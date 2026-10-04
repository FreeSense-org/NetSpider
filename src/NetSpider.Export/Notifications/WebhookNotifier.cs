using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Export.Json;

namespace NetSpider.Export.Notifications;

/// <summary>
/// Posts alerts to Discord, Slack or generic JSON webhooks. Each webhook gets at most one message per <see cref="MinInterval"/>;
/// alerts arriving faster are collapsed into a single summary message.
/// </summary>
public sealed class WebhookNotifier : INotifier, IDisposable
{
    public const int MaxBatch = 10;

    private readonly ISettingsStore _settings;
    private readonly ILogger<WebhookNotifier> _log;
    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<string, Throttle> _throttles = new(StringComparer.OrdinalIgnoreCase);

    public WebhookNotifier(ISettingsStore settings, ILogger<WebhookNotifier> log) : this(settings, log, null) { }

    /// <param name="handler">Optional handler (tests); when null a default <see cref="SocketsHttpHandler"/> is used.</param>
    public WebhookNotifier(ISettingsStore settings, ILogger<WebhookNotifier> log, HttpMessageHandler? handler)
    {
        _settings = settings;
        _log = log;
        _http = new HttpClient(handler ?? new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) }, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"NetSpider/{ExportText.AppVersion}");
    }

    /// <summary>Minimum spacing between two messages to the same webhook.</summary>
    public TimeSpan MinInterval { get; set; } = TimeSpan.FromSeconds(2);

    public async Task NotifyAsync(Alert alert, CancellationToken ct = default)
    {
        var hooks = _settings.Settings.Webhooks.Where(h => h.Enabled && Uri.TryCreate(h.Url, UriKind.Absolute, out var u) && u.Scheme is "http" or "https").ToList();
        if (hooks.Count == 0) return;
        await Task.WhenAll(hooks.Select(h => EnqueueAsync(h, alert, ct))).ConfigureAwait(false);
    }

    private Task EnqueueAsync(WebhookConfig hook, Alert alert, CancellationToken ct)
    {
        var t = _throttles.GetOrAdd(hook.Url, _ => new Throttle());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        lock (t)
        {
            t.Pending.Add(alert);
            if (t.FlushScheduled) return Task.CompletedTask; // collapsed into the scheduled message
            t.FlushScheduled = true;
            var wait = t.LastSent + MinInterval - now;
            if (wait > TimeSpan.Zero)
            {
                _ = Task.Run(async () =>
                {
                    try { await Task.Delay(wait, CancellationToken.None).ConfigureAwait(false); } catch { }
                    await FlushAsync(hook, t, CancellationToken.None).ConfigureAwait(false);
                }, CancellationToken.None);
                return Task.CompletedTask;
            }
        }
        return FlushAsync(hook, t, ct);
    }

    private async Task FlushAsync(WebhookConfig hook, Throttle t, CancellationToken ct)
    {
        List<Alert> batch;
        lock (t)
        {
            batch = [.. t.Pending];
            t.Pending.Clear();
            t.FlushScheduled = false;
            t.LastSent = DateTimeOffset.UtcNow;
        }
        if (batch.Count == 0) return;
        try
        {
            var payload = BuildPayload(hook.Kind, batch);
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(hook.Url, content, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                _log.LogWarning("Webhook {Name} returned {Status} {Reason}", Name(hook), (int)resp.StatusCode, resp.ReasonPhrase);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.LogWarning("Webhook {Name} failed: {Message}", Name(hook), ex.Message);
        }
    }

    private static string Name(WebhookConfig h) => string.IsNullOrWhiteSpace(h.Name) ? new Uri(h.Url).Host : h.Name;

    private sealed class Throttle
    {
        public readonly List<Alert> Pending = new();
        public bool FlushScheduled;
        public DateTimeOffset LastSent = DateTimeOffset.MinValue;
    }

    // ------------------------------------------------------------------ payloads

    public static string BuildPayload(string kind, IReadOnlyList<Alert> alerts) => kind.Trim().ToLowerInvariant() switch
    {
        "discord" => BuildDiscordPayload(alerts),
        "slack" => BuildSlackPayload(alerts),
        _ => BuildJsonPayload(alerts),
    };

    public static int DiscordColor(AlertSeverity s) => s switch
    {
        AlertSeverity.Critical => 0xFF4D6D,
        AlertSeverity.Warning => 0xFFB547,
        _ => 0x22D3EE,
    };

    /// <summary>{"username":"NetSpider","embeds":[{title, description, color, timestamp, fields}]} (one embed per alert, max 10).</summary>
    public static string BuildDiscordPayload(IReadOnlyList<Alert> alerts)
    {
        var embeds = new JsonArray();
        foreach (var a in alerts.Take(MaxBatch))
        {
            var fields = new JsonArray
            {
                Field("Severity", a.Severity.ToString(), true),
                Field("Kind", a.Kind.ToString(), true),
            };
            if (a.Source is { } src) fields.Add(Field("Source", src.ToString(), true));
            if (a.Rate is { } rate) fields.Add(Field("Rate", rate.ToString("0.##", CultureInfo.InvariantCulture), true));
            embeds.Add(new JsonObject
            {
                ["title"] = ExportText.Truncate(a.Title, 256),
                ["description"] = ExportText.Truncate(a.Details, 4000),
                ["color"] = DiscordColor(a.Severity),
                ["timestamp"] = a.Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
                ["fields"] = fields,
                ["footer"] = new JsonObject { ["text"] = "NetSpider" },
            });
        }
        var root = new JsonObject { ["username"] = "NetSpider", ["embeds"] = embeds };
        if (alerts.Count > MaxBatch) root["content"] = $"{alerts.Count} alerts in a burst; showing the first {MaxBatch}.";
        return root.ToJsonString(ExportJson.Compact);

        static JsonObject Field(string name, string value, bool inline) =>
            new() { ["name"] = name, ["value"] = ExportText.Truncate(value, 1024), ["inline"] = inline };
    }

    /// <summary>{"text": fallback, "blocks": [header, section, context, divider...]}.</summary>
    public static string BuildSlackPayload(IReadOnlyList<Alert> alerts)
    {
        var blocks = new JsonArray();
        string text = alerts.Count == 1
            ? $"[{alerts[0].Severity}] {alerts[0].Title}"
            : $"NetSpider: {alerts.Count} alerts ({string.Join(", ", alerts.GroupBy(a => a.Severity).OrderByDescending(g => g.Key).Select(g => $"{g.Count()} {g.Key}"))})";
        if (alerts.Count > 1)
            blocks.Add(new JsonObject { ["type"] = "header", ["text"] = Plain(ExportText.Truncate(text, 150)) });
        foreach (var a in alerts.Take(MaxBatch))
        {
            if (alerts.Count == 1) blocks.Add(new JsonObject { ["type"] = "header", ["text"] = Plain(ExportText.Truncate($"{Emoji(a.Severity)} {a.Title}", 150)) });
            else blocks.Add(new JsonObject { ["type"] = "section", ["text"] = Mrkdwn($"{Emoji(a.Severity)} *{SlackEscape(ExportText.Truncate(a.Title, 200))}*") });
            if (!string.IsNullOrWhiteSpace(a.Details))
                blocks.Add(new JsonObject { ["type"] = "section", ["text"] = Mrkdwn(SlackEscape(ExportText.Truncate(a.Details, 2900))) });
            var ctx = $"*Severity:* {a.Severity}  |  *Kind:* {a.Kind}" + (a.Source is { } s ? $"  |  *Source:* `{s}`" : "")
                + $"  |  <!date^{a.Time.ToUnixTimeSeconds()}^{{date_short_pretty}} {{time_secs}}|{a.Time.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC>";
            blocks.Add(new JsonObject { ["type"] = "context", ["elements"] = new JsonArray { Mrkdwn(ctx) } });
            if (alerts.Count > 1) blocks.Add(new JsonObject { ["type"] = "divider" });
        }
        if (alerts.Count > MaxBatch)
            blocks.Add(new JsonObject { ["type"] = "context", ["elements"] = new JsonArray { Mrkdwn($"…and {alerts.Count - MaxBatch} more") } });
        return new JsonObject { ["text"] = text, ["blocks"] = blocks }.ToJsonString(ExportJson.Compact);

        static JsonObject Plain(string t) => new() { ["type"] = "plain_text", ["text"] = t, ["emoji"] = true };
        static JsonObject Mrkdwn(string t) => new() { ["type"] = "mrkdwn", ["text"] = t };
        static string Emoji(AlertSeverity s) => s switch { AlertSeverity.Critical => ":rotating_light:", AlertSeverity.Warning => ":warning:", _ => ":information_source:" };
    }

    /// <summary>Raw alert JSON; a collapsed burst is sent as {"alerts":[...]} instead.</summary>
    public static string BuildJsonPayload(IReadOnlyList<Alert> alerts) =>
        alerts.Count == 1
            ? JsonSerializer.Serialize(alerts[0], ExportJson.Compact)
            : JsonSerializer.Serialize(new { source = "NetSpider", count = alerts.Count, alerts }, ExportJson.Compact);

    /// <summary>Slack mrkdwn requires &amp;, &lt; and &gt; to be escaped.</summary>
    public static string SlackEscape(string s) => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    public void Dispose() => _http.Dispose();
}
