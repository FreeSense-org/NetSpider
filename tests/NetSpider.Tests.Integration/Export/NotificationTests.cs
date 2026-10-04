using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Notifications;

namespace NetSpider.Tests.Integration.Export;

public sealed class NotificationTests
{
    private static readonly Alert Storm = Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "Broadcast storm", "812 pps <broadcast> & more", TestData.RouterMac, 812.5);
    private static readonly Alert Rogue = Alert.Create(AlertSeverity.Critical, AlertKind.RogueDhcp, "Rogue DHCP", "192.168.1.66", TestData.EvilMac);

    private static (WebhookNotifier Notifier, RecordingHandler Handler) Create(params WebhookConfig[] hooks)
    {
        var settings = new AppSettings { Webhooks = hooks.ToList() };
        var handler = new RecordingHandler();
        return (new WebhookNotifier(new FakeSettingsStore(settings), NullLogger<WebhookNotifier>.Instance, handler), handler);
    }

    private static async Task<bool> WaitFor(Func<bool> cond, int ms = 3000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until) { if (cond()) return true; await Task.Delay(20); }
        return cond();
    }

    [Fact]
    public async Task Discord_payload_shape()
    {
        var (n, h) = Create(new WebhookConfig { Name = "d", Kind = "Discord", Url = "https://discord.example/api/webhooks/1/x" });
        using (n) await n.NotifyAsync(Storm);

        var req = Assert.Single(h.Requests);
        Assert.Equal("application/json", req.MediaType);
        using var doc = JsonDocument.Parse(req.Body);
        var root = doc.RootElement;
        Assert.Equal("NetSpider", root.GetProperty("username").GetString());
        var embed = Assert.Single(root.GetProperty("embeds").EnumerateArray());
        Assert.Equal("Broadcast storm", embed.GetProperty("title").GetString());
        Assert.Equal("812 pps <broadcast> & more", embed.GetProperty("description").GetString());
        Assert.Equal(WebhookNotifier.DiscordColor(AlertSeverity.Warning), embed.GetProperty("color").GetInt32());
        Assert.True(DateTimeOffset.TryParse(embed.GetProperty("timestamp").GetString(), out var ts));
        Assert.Equal(Storm.Time.ToUnixTimeSeconds(), ts.ToUnixTimeSeconds());
        var fields = embed.GetProperty("fields").EnumerateArray().ToDictionary(f => f.GetProperty("name").GetString()!, f => f.GetProperty("value").GetString());
        Assert.Equal("Warning", fields["Severity"]);
        Assert.Equal("BroadcastStorm", fields["Kind"]);
        Assert.Equal(TestData.RouterMac.ToString(), fields["Source"]);
        Assert.Equal("812.5", fields["Rate"]);
    }

    [Fact]
    public async Task Slack_payload_shape()
    {
        var (n, h) = Create(new WebhookConfig { Kind = "Slack", Url = "https://hooks.slack.example/services/T/B/x" });
        using (n) await n.NotifyAsync(Rogue);

        using var doc = JsonDocument.Parse(Assert.Single(h.Requests).Body);
        var root = doc.RootElement;
        Assert.Contains("Rogue DHCP", root.GetProperty("text").GetString());
        var blocks = root.GetProperty("blocks").EnumerateArray().ToList();
        Assert.Equal("header", blocks[0].GetProperty("type").GetString());
        Assert.Equal("plain_text", blocks[0].GetProperty("text").GetProperty("type").GetString());
        Assert.All(blocks, b => Assert.True(b.TryGetProperty("type", out _)));
        Assert.Contains(blocks, b => b.GetProperty("type").GetString() == "section" && b.GetProperty("text").GetProperty("type").GetString() == "mrkdwn");
        Assert.Contains(blocks, b => b.GetProperty("type").GetString() == "context");
    }

    [Fact]
    public void Slack_escapes_control_characters() =>
        Assert.Contains("812 pps &lt;broadcast&gt; &amp; more", WebhookNotifier.BuildSlackPayload([Storm]));

    [Fact]
    public async Task Json_payload_is_raw_alert()
    {
        var (n, h) = Create(new WebhookConfig { Kind = "Json", Url = "http://127.0.0.1:9/hook" });
        using (n) await n.NotifyAsync(Storm);

        using var doc = JsonDocument.Parse(Assert.Single(h.Requests).Body);
        var root = doc.RootElement;
        Assert.Equal(Storm.Id, root.GetProperty("id").GetGuid());
        Assert.Equal("Warning", root.GetProperty("severity").GetString());
        Assert.Equal("BroadcastStorm", root.GetProperty("kind").GetString());
        Assert.Equal(TestData.RouterMac.ToString(), root.GetProperty("source").GetString());
        Assert.Equal(812.5, root.GetProperty("rate").GetDouble());
    }

    [Fact]
    public async Task Disabled_and_invalid_webhooks_are_skipped()
    {
        var (n, h) = Create(
            new WebhookConfig { Kind = "Json", Url = "https://a.example/x", Enabled = false },
            new WebhookConfig { Kind = "Json", Url = "not a url" },
            new WebhookConfig { Kind = "Json", Url = "ftp://b.example/x" });
        using (n) await n.NotifyAsync(Storm);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Bursts_are_rate_limited_and_collapsed_per_webhook()
    {
        var (n, h) = Create(
            new WebhookConfig { Kind = "Discord", Url = "https://one.example/x" },
            new WebhookConfig { Kind = "Json", Url = "https://two.example/x" });
        n.MinInterval = TimeSpan.FromMilliseconds(400);
        using (n)
        {
            await n.NotifyAsync(Storm);
            await n.NotifyAsync(Rogue);
            await n.NotifyAsync(Storm with { Id = Guid.NewGuid() });
            Assert.Equal(2, h.Count); // one immediate message per webhook

            Assert.True(await WaitFor(() => h.Count == 4));
            await Task.Delay(500);
            Assert.Equal(4, h.Count); // the burst collapsed into one more message per webhook
        }

        var one = h.Requests.Where(r => r.Uri.Host == "one.example").ToList();
        Assert.True(one[1].At - one[0].At >= TimeSpan.FromMilliseconds(350));
        using var discord = JsonDocument.Parse(one[1].Body);
        Assert.Equal(2, discord.RootElement.GetProperty("embeds").GetArrayLength());

        using var json = JsonDocument.Parse(h.Requests.Where(r => r.Uri.Host == "two.example").ToList()[1].Body);
        Assert.Equal(2, json.RootElement.GetProperty("count").GetInt32());
        Assert.Equal(2, json.RootElement.GetProperty("alerts").GetArrayLength());
    }

    [Fact]
    public void Syslog_rfc5424_format()
    {
        var msg = SyslogNotifier.Format(Rogue with { Details = "line1\nline2 \"q\"" }, "my host", 4242);
        Assert.StartsWith("<130>1 ", msg); // local0 (16) * 8 + crit (2)
        var parts = msg.Split(' ', 7);
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$", parts[1]);
        Assert.Equal("myhost", parts[2]);
        Assert.Equal("NetSpider", parts[3]);
        Assert.Equal("4242", parts[4]);
        Assert.Equal("RogueDhcp", parts[5]);
        Assert.StartsWith("[netspider@32473 id=\"", parts[6]);
        Assert.Contains($"source=\"{TestData.EvilMac}\"", parts[6]);
        Assert.Contains("] ﻿Rogue DHCP: line1 line2 \"q\"", parts[6]);
        Assert.DoesNotContain('\n', msg);

        Assert.Equal(4, SyslogNotifier.Severity(AlertSeverity.Warning));
        Assert.Equal(6, SyslogNotifier.Severity(AlertSeverity.Info));
        Assert.Equal("a\\\"b\\]c\\\\", SyslogNotifier.SdEscape("a\"b]c\\"));
    }

    [Fact]
    public async Task Syslog_sends_udp_datagram()
    {
        using var server = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = ((System.Net.IPEndPoint)server.Client.LocalEndPoint!).Port;
        var settings = new AppSettings { SyslogServer = "127.0.0.1", SyslogPort = port };
        using var n = new SyslogNotifier(new FakeSettingsStore(settings), NullLogger<SyslogNotifier>.Instance);
        await n.NotifyAsync(Storm);

        var recv = await server.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));
        var text = System.Text.Encoding.UTF8.GetString(recv.Buffer);
        Assert.StartsWith("<132>1 ", text); // local0 warning
        Assert.Contains("BroadcastStorm", text);
    }

    [Fact]
    public async Task Notification_service_persists_all_and_forwards_by_severity()
    {
        var alerts = new AlertService();
        var repo = new FakeRepository();
        var ok = new FakeNotifier();
        var failing = new FakeNotifier { Throw = true };
        var settings = new AppSettings { NotifyMinSeverity = AlertSeverity.Warning };
        using var svc = new NotificationService(alerts, repo, [failing, ok], new FakeSettingsStore(settings), NullLogger<NotificationService>.Instance);
        svc.Start();

        alerts.Raise(Alert.Create(AlertSeverity.Info, AlertKind.NewDevice, "new", "x"));
        alerts.Raise(Storm);
        alerts.Raise(Rogue);

        Assert.True(await WaitFor(() => repo.Alerts.Count == 3 && svc.InFlight == 0));
        Assert.Equal(2, ok.Received.Count);
        Assert.DoesNotContain(ok.Received, a => a.Severity == AlertSeverity.Info);
        Assert.Equal(2, failing.Received.Count); // a throwing notifier does not stop the others
    }
}
