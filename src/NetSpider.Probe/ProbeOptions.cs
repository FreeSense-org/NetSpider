using System.Globalization;
using System.Net;
using System.Text.Json;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Probe;

/// <summary>Agent configuration from <c>probe.json</c> (next to the exe or <c>--config</c>) overridden by the command line.</summary>
public sealed class ProbeOptions
{
    public const string ConfigFileName = "probe.json";
    public const string KeyEnvironmentVariable = "NETSPIDER_PROBE_KEY";
    public static readonly string[] DefaultTargets = ["gw", "hub", "1.1.1.1"];

    public string? HubHost { get; set; }
    public int HubPort { get; set; } = AgentProtocol.DefaultPort;
    public string? Key { get; set; }
    public List<string> Targets { get; set; } = [.. DefaultTargets];
    public double IntervalSeconds { get; set; } = 2;
    /// <summary>Number of pings per target the loss/average window covers.</summary>
    public int Window { get; set; } = 10;
    public string Id { get; set; } = Environment.MachineName;
    public bool Once { get; set; }
    public bool Quiet { get; set; }
    public bool Help { get; set; }
    public string? ConfigPath { get; set; }

    public static string Usage => """
        netspider-probe - NetSpider probe agent (second vantage point)

        Usage:
          netspider-probe --key <base64> [--hub <ip|host>[:port]] [--targets gw,hub,1.1.1.1,10.0.0.15]
                          [--interval 2] [--window 10] [--id NAME] [--once] [--quiet] [--config probe.json]

          --hub       hub (NetSpider PC) address; omitted = discover it via authenticated broadcast on UDP 47811
          --key       shared key from NetSpider settings (or env NETSPIDER_PROBE_KEY, or "key" in probe.json)
          --targets   comma separated; "gw" = default gateway, "hub" = the hub host. Default: gw,hub,1.1.1.1
          --interval  seconds between rounds (default 2)
          --window    pings per target used for loss/average (default 10)
          --id        agent name shown in NetSpider (default: machine name)
          --once      run one round, send one report and exit (testing)
          --quiet     only log changes and errors
          --config    alternative config file (default: probe.json next to the executable)
        """;

    /// <summary>Loads probe.json (if present) then applies the arguments. Returns null and an error on invalid input.</summary>
    public static ProbeOptions? Load(string[] args, out string? error)
    {
        var o = new ProbeOptions();
        error = null;

        // pass 1: locate a config file
        string? config = null;
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] is "--config" or "-c") config = args[i + 1];
        var path = config ?? Path.Combine(AppContext.BaseDirectory, ConfigFileName);
        if (File.Exists(path))
        {
            if (!o.ApplyConfigFile(path, out error)) return null;
            o.ConfigPath = path;
        }
        else if (config is not null) { error = $"config file not found: {config}"; return null; }

        if (string.IsNullOrWhiteSpace(o.Key) && Environment.GetEnvironmentVariable(KeyEnvironmentVariable) is { Length: > 0 } envKey) o.Key = envKey;

        // pass 2: arguments
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            switch (a)
            {
                case "--help" or "-h" or "-?" or "/?": o.Help = true; break;
                case "--once": o.Once = true; break;
                case "--quiet" or "-q": o.Quiet = true; break;
                case "--config" or "-c": Next(); break;
                case "--hub": if (!o.SetHub(Next(), out error)) return null; break;
                case "--key" or "-k": o.Key = Next(); break;
                case "--targets" or "-t": o.Targets = SplitTargets(Next()); break;
                case "--id": o.Id = Next() ?? o.Id; break;
                case "--interval" or "-i":
                    if (!double.TryParse(Next(), NumberStyles.Float, CultureInfo.InvariantCulture, out var iv)) { error = "--interval needs seconds"; return null; }
                    o.IntervalSeconds = iv; break;
                case "--window" or "-w":
                    if (!int.TryParse(Next(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var w)) { error = "--window needs a count"; return null; }
                    o.Window = w; break;
                default: error = $"unknown argument: {a}"; return null;
            }
        }
        if (o.Help) return o;

        o.IntervalSeconds = Math.Clamp(o.IntervalSeconds, 0.5, 300);
        o.Window = Math.Clamp(o.Window, 1, 300);
        o.Id = string.IsNullOrWhiteSpace(o.Id) ? Environment.MachineName : o.Id.Trim();
        if (o.Id.Length > 64) o.Id = o.Id[..64];
        if (o.Targets.Count == 0) o.Targets = [.. DefaultTargets];
        if (!AgentProtocol.TryParseKey(o.Key, out _)) { error = "a valid --key (base64, from NetSpider settings) is required"; return null; }
        return o;
    }

    public static List<string> SplitTargets(string? s) =>
        (s ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Accepts "10.0.0.5", "10.0.0.5:47810", "[fe80::1]:47810", "nas.local", "nas.local:47810".</summary>
    public bool SetHub(string? value, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(value)) { error = "--hub needs an address"; return false; }
        value = value.Trim();
        if (IPAddress.TryParse(value, out var ipOnly)) { HubHost = ipOnly.ToString(); return true; }
        if (IPEndPoint.TryParse(value, out var ep) && ep.Port != 0) { HubHost = ep.Address.ToString(); HubPort = ep.Port; return true; }
        int colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon)
        {
            if (!int.TryParse(value[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p is < 1 or > 65535) { error = $"invalid hub port in '{value}'"; return false; }
            HubHost = value[..colon];
            HubPort = p;
            return true;
        }
        HubHost = value;
        return true;
    }

    private bool ApplyConfigFile(string path, out string? error)
    {
        error = null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                switch (p.Name.ToLowerInvariant())
                {
                    case "hub": if (p.Value.GetString() is { Length: > 0 } h && !SetHub(h, out error)) return false; break;
                    case "hubport": HubPort = p.Value.GetInt32(); break;
                    case "key": Key = p.Value.GetString(); break;
                    case "id": Id = p.Value.GetString() ?? Id; break;
                    case "interval": IntervalSeconds = p.Value.GetDouble(); break;
                    case "window": Window = p.Value.GetInt32(); break;
                    case "quiet": Quiet = p.Value.GetBoolean(); break;
                    case "targets":
                        Targets = p.Value.ValueKind == JsonValueKind.Array
                            ? p.Value.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToList()
                            : SplitTargets(p.Value.GetString());
                        break;
                }
            }
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or IOException or UnauthorizedAccessException)
        {
            error = $"cannot read {path}: {ex.Message}";
            return false;
        }
    }
}
