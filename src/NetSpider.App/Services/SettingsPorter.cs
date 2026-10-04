using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetSpider.Core;
using NetSpider.Core.Model;

namespace NetSpider.App.Services;

/// <summary>
/// Settings export / import / reset (Settings → Application). Pure and unit tested: the live <see cref="AppSettings"/> instance
/// is shared by every service, so imports and resets copy values <i>into</i> it instead of replacing it.
/// </summary>
public static class SettingsPorter
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    /// <summary>Machine-/install-specific values that an import or reset never overwrites.</summary>
    public static readonly IReadOnlySet<string> LocalOnly = new HashSet<string>
    {
        nameof(AppSettings.Window), nameof(AppSettings.LastAdapterId), nameof(AppSettings.WelcomeShown),
        nameof(AppSettings.StartWithWindows), nameof(AppSettings.SkippedVersion), nameof(AppSettings.LastUpdateCheck),
        nameof(AppSettings.LastUpdateResult), nameof(AppSettings.LastSeenVersion),
    };

    /// <summary>Settings only read at startup: changing them needs a restart.</summary>
    public static readonly IReadOnlyDictionary<string, string> RestartRequired = new Dictionary<string, string>
    {
        [nameof(AppSettings.UpdateChannel)] = "Update channel",
        [nameof(AppSettings.UpdateCheckHours)] = "Update check interval",
        [nameof(AppSettings.StartMinimizedToTray)] = "Start minimized to tray",
    };

    public sealed record ImportResult(bool Success, string Message, AppSettings? Settings, IReadOnlyList<string> Warnings);

    private static IEnumerable<PropertyInfo> Properties =>
        typeof(AppSettings).GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p is { CanRead: true, CanWrite: true });

    /// <summary>Settings as JSON with a small header (product, version, export time).</summary>
    public static string Export(AppSettings settings)
    {
        var node = JsonSerializer.SerializeToNode(settings, Json)!.AsObject();
        foreach (var k in LocalOnly) node.Remove(k);
        var root = new JsonObject
        {
            ["$product"] = AppInfo.ProductName,
            ["$version"] = AppInfo.Version,
            ["$exported"] = DateTimeOffset.Now.ToString("O"),
        };
        foreach (var kv in node.ToList())
        {
            node.Remove(kv.Key);
            root[kv.Key] = kv.Value;
        }
        return root.ToJsonString(Json);
    }

    /// <summary>Parses and validates an exported file. Unknown keys are ignored; out-of-range values are clamped (listed as warnings).</summary>
    public static ImportResult Parse(string json)
    {
        JsonNode? node;
        try { node = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }); }
        catch (JsonException ex) { return new ImportResult(false, "Not a valid JSON file: " + ex.Message, null, []); }
        if (node is not JsonObject obj) return new ImportResult(false, "Not a NetSpider settings file (expected a JSON object).", null, []);

        var known = Properties.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        int matches = obj.Count(kv => known.Contains(kv.Key));
        if (matches == 0) return new ImportResult(false, "Not a NetSpider settings file (no known settings found).", null, []);

        AppSettings? s;
        try { s = obj.Deserialize<AppSettings>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException or FormatException)
        {
            return new ImportResult(false, "The settings file contains invalid values: " + ex.Message, null, []);
        }
        if (s is null) return new ImportResult(false, "The settings file is empty.", null, []);
        var warnings = Sanitize(s);
        return new ImportResult(true, $"{matches} settings read", s, warnings);
    }

    /// <summary>Clamps values to the ranges the UI allows. Returns a description of every fix.</summary>
    public static List<string> Sanitize(AppSettings s)
    {
        var w = new List<string>();
        int ClampI(string name, int v, int min, int max) { if (v < min || v > max) { w.Add($"{name} {v} out of range, set to {Math.Clamp(v, min, max)}"); return Math.Clamp(v, min, max); } return v; }
        double ClampD(string name, double v, double min, double max)
        {
            if (double.IsNaN(v) || v < min || v > max) { var c = double.IsNaN(v) ? min : Math.Clamp(v, min, max); w.Add($"{name} {v} out of range, set to {c}"); return c; }
            return v;
        }
        s.MinSweepPrefix = ClampI(nameof(s.MinSweepPrefix), s.MinSweepPrefix, 8, 30);
        s.MaxInjectPps = ClampI(nameof(s.MaxInjectPps), s.MaxInjectPps, 10, 20000);
        s.SnmpTimeoutMs = ClampI(nameof(s.SnmpTimeoutMs), s.SnmpTimeoutMs, 200, 10000);
        s.SnmpPollMinutes = ClampI(nameof(s.SnmpPollMinutes), s.SnmpPollMinutes, 1, 1440);
        s.LatencyIntervalSeconds = ClampI(nameof(s.LatencyIntervalSeconds), s.LatencyIntervalSeconds, 1, 10);
        s.InternetIntervalSeconds = ClampI(nameof(s.InternetIntervalSeconds), s.InternetIntervalSeconds, 1, 3600);
        s.InternetOutageRounds = ClampI(nameof(s.InternetOutageRounds), s.InternetOutageRounds, 1, 60);
        s.PathIntervalSeconds = ClampI(nameof(s.PathIntervalSeconds), s.PathIntervalSeconds, 1, 60);
        s.HopDownRounds = ClampI(nameof(s.HopDownRounds), s.HopDownRounds, 1, 30);
        s.PortCounterPollSeconds = ClampI(nameof(s.PortCounterPollSeconds), s.PortCounterPollSeconds, 10, 3600);
        s.WifiWeakRssiDbm = ClampI(nameof(s.WifiWeakRssiDbm), s.WifiWeakRssiDbm, -95, -40);
        s.ProbeAgentPort = ClampI(nameof(s.ProbeAgentPort), s.ProbeAgentPort, 1024, 65535);
        s.SyslogPort = ClampI(nameof(s.SyslogPort), s.SyslogPort, 1, 65535);
        s.MacFlapThreshold = ClampI(nameof(s.MacFlapThreshold), s.MacFlapThreshold, 1, 100);
        s.UpdateCheckHours = ClampI(nameof(s.UpdateCheckHours), s.UpdateCheckHours, 0, 168);
        s.CaptureFolderMaxMb = ClampI(nameof(s.CaptureFolderMaxMb), s.CaptureFolderMaxMb, 100, 1024 * 1024);
        s.StormBroadcastRatio = ClampD(nameof(s.StormBroadcastRatio), s.StormBroadcastRatio, 0.01, 1);
        s.LatencyGoodMs = ClampD(nameof(s.LatencyGoodMs), s.LatencyGoodMs, 0.1, 100);
        s.LatencyWarnMs = ClampD(nameof(s.LatencyWarnMs), s.LatencyWarnMs, 0.5, 500);
        s.LatencyBadMs = ClampD(nameof(s.LatencyBadMs), s.LatencyBadMs, 1, 2000);
        if (s.LogLevel is not ("Information" or "Debug")) { w.Add($"LogLevel \"{s.LogLevel}\" unknown, set to Information"); s.LogLevel = "Information"; }
        // null = follow the installer's channel; legacy "stable"/"beta" map to release/prerelease
        if (s.UpdateChannel is "stable") s.UpdateChannel = UpdateLogic.ReleaseChannel;
        if (s.UpdateChannel is "beta") s.UpdateChannel = UpdateLogic.PrereleaseChannel;
        if (s.UpdateChannel is not (null or UpdateLogic.ReleaseChannel or UpdateLogic.PrereleaseChannel)) { w.Add($"UpdateChannel \"{s.UpdateChannel}\" unknown, following the installer channel"); s.UpdateChannel = null; }
        if (!Enum.IsDefined(s.ToastMinSeverity)) { w.Add("ToastMinSeverity unknown, set to Warning"); s.ToastMinSeverity = AlertSeverity.Warning; }
        if (!Enum.IsDefined(s.NotifyMinSeverity)) { w.Add("NotifyMinSeverity unknown, set to Warning"); s.NotifyMinSeverity = AlertSeverity.Warning; }
        if (!Enum.IsDefined(s.UpdateAction)) { w.Add("UpdateAction unknown, set to DownloadAndAsk"); s.UpdateAction = UpdateAction.DownloadAndAsk; }
        s.SnmpCommunities ??= [];
        s.Webhooks ??= [];
        s.InternetTargets ??= [];
        s.ExtraPorts ??= "";
        return w;
    }

    /// <summary>
    /// Copies every setting except <see cref="LocalOnly"/> from <paramref name="source"/> into <paramref name="target"/>.
    /// Returns the names of the properties whose value changed.
    /// </summary>
    public static List<string> CopyInto(AppSettings source, AppSettings target)
    {
        var changed = new List<string>();
        foreach (var p in Properties)
        {
            if (LocalOnly.Contains(p.Name)) continue;
            var before = p.GetValue(target);
            var after = p.GetValue(source);
            if (!SameJson(before, after)) changed.Add(p.Name);
            p.SetValue(target, after);
        }
        return changed;
    }

    /// <summary>Human-readable names of the changed settings that only apply after a restart.</summary>
    public static List<string> NeedsRestart(IEnumerable<string> changed) =>
        changed.Where(RestartRequired.ContainsKey).Select(c => RestartRequired[c]).ToList();

    private static bool SameJson(object? a, object? b) =>
        ReferenceEquals(a, b) || JsonSerializer.Serialize(a) == JsonSerializer.Serialize(b);
}
