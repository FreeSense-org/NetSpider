using NetSpider.Core.Model;
using NetSpider.Diagnostics.Anomaly;

namespace NetSpider.Diagnostics.Storm;

/// <summary>
/// Loop heuristics. Combines evidence into <see cref="LoopSuspect"/>s with a confidence:
/// <list type="bullet">
/// <item>the anomaly engine's duplicate-frame bursts and STP topology-change bursts (network-wide, no port),</item>
/// <item>MAC flapping between ports (anomaly engine FDB tracking),</item>
/// <item>the same MAC learned on 2+ ports of the same switch in FDB snapshots over time (simultaneously, or alternating),</item>
/// <item>two ports of the same switch with simultaneous high broadcast ingress (SNMP port counters).</item>
/// </list>
/// Per-switch evidence pinpoints ports; network-wide evidence raises the confidence of those, or produces a generic suspect.
/// Thread-safe.
/// </summary>
public sealed class LoopFinder
{
    public static readonly TimeSpan FdbWindow = TimeSpan.FromMinutes(10);
    /// <summary>Broadcast ingress (pps) at which two ports of one switch count as "both flooded".</summary>
    public const double MinIngressPps = 200;
    /// <summary>Rates of the two ports must be within this factor of each other (a loop circulates the same flood).</summary>
    public const double IngressSimilarity = 0.3;
    public static readonly TimeSpan LoopEvidenceWindow = TimeSpan.FromSeconds(30);

    private readonly object _sync = new();
    private readonly Dictionary<(Mac Sw, Mac Mac), MacPorts> _fdb = new();

    private sealed class MacPorts
    {
        public readonly Dictionary<string, DateTimeOffset> Ports = new(StringComparer.OrdinalIgnoreCase);
        public string? LastPort;
        public readonly List<DateTimeOffset> Changes = new();
        public DateTimeOffset? Simultaneous;
    }

    /// <summary>Feeds an FDB snapshot. <paramref name="portName"/> maps an entry to the port label used in the output.</summary>
    public void ObserveFdb(IReadOnlyList<FdbEntry> fdb, DateTimeOffset now, Func<FdbEntry, string>? portName = null)
    {
        portName ??= e => e.Port;
        lock (_sync)
        {
            foreach (var g in fdb.Where(e => !e.Mac.IsMulticast).GroupBy(e => (e.Switch, e.Mac)))
            {
                if (!_fdb.TryGetValue(g.Key, out var mp)) _fdb[g.Key] = mp = new MacPorts();
                // the same MAC on two ports in the same VLAN at the same time cannot happen on a loop-free bridge
                var simultaneous = g.GroupBy(e => e.Vlan).Any(v => v.Select(portName).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2);
                if (simultaneous) mp.Simultaneous = now;
                foreach (var e in g)
                {
                    var p = portName(e);
                    mp.Ports[p] = now;
                    if (mp.LastPort is not null && !string.Equals(mp.LastPort, p, StringComparison.OrdinalIgnoreCase)) mp.Changes.Add(now);
                    mp.LastPort = p;
                }
                foreach (var stale in mp.Ports.Where(kv => now - kv.Value > FdbWindow).Select(kv => kv.Key).ToList()) mp.Ports.Remove(stale);
                mp.Changes.RemoveAll(x => now - x > FdbWindow);
                if (mp.Simultaneous is { } s && now - s > FdbWindow) mp.Simultaneous = null;
            }
            if (_fdb.Count > 200_000) _fdb.Clear();
        }
    }

    /// <summary>(switch, MAC) pairs seen on 2+ ports within <see cref="FdbWindow"/> that alternated or appeared simultaneously.</summary>
    public IReadOnlyList<(Mac Switch, Mac Mac, IReadOnlyList<string> Ports, bool Simultaneous)> MultiPortMacs()
    {
        lock (_sync)
        {
            return _fdb
                .Where(kv => kv.Value.Ports.Count >= 2 && (kv.Value.Simultaneous is not null || kv.Value.Changes.Count >= 2))
                .Select(kv => (kv.Key.Sw, kv.Key.Mac, (IReadOnlyList<string>)kv.Value.Ports.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray(), kv.Value.Simultaneous is not null))
                .ToList();
        }
    }

    public IReadOnlyList<LoopSuspect> Evaluate(AnomalyState anomaly, IReadOnlyList<PortHealth> ports, Func<Mac, string> switchName, DateTimeOffset now, double minIngressPps = MinIngressPps)
    {
        var perSwitch = new Dictionary<Mac, SwitchEvidence>();
        SwitchEvidence Ev(Mac sw) => perSwitch.TryGetValue(sw, out var e) ? e : perSwitch[sw] = new SwitchEvidence();

        // ---- MAC flapping (anomaly engine) ----
        var seen = new HashSet<(Mac, Mac)>();
        foreach (var f in anomaly.FlappingMacs)
        {
            if (f.Ports.Count < 2) continue;
            var ev = Ev(f.Switch);
            foreach (var p in f.Ports) ev.Ports.Add(p);
            ev.Macs.Add(f.Mac);
            ev.Add(f.Moves >= 3 ? 0.6 : 0.4, $"MAC {f.Mac} flapping between ports {Join(f.Ports)}");
            seen.Add((f.Switch, f.Mac));
        }

        // ---- same MAC on 2+ ports (FDB snapshots over time) ----
        foreach (var (sw, mac, macPorts, simultaneous) in MultiPortMacs())
        {
            if (!seen.Add((sw, mac))) continue;
            var ev = Ev(sw);
            foreach (var p in macPorts) ev.Ports.Add(p);
            ev.Macs.Add(mac);
            ev.Add(simultaneous ? 0.5 : 0.4, $"MAC {mac} learned on ports {Join(macPorts)}");
        }

        // ---- two ports of one switch flooded at the same time ----
        foreach (var g in ports.Where(p => p.OperUp && p.BroadcastPps >= minIngressPps).GroupBy(p => p.Switch))
        {
            var top = g.OrderByDescending(p => p.BroadcastPps).Take(2).ToList();
            if (top.Count < 2 || top[1].BroadcastPps / top[0].BroadcastPps < IngressSimilarity) continue;
            var ev = Ev(g.Key);
            ev.Ports.Add(top[0].Name);
            ev.Ports.Add(top[1].Name);
            ev.Add(0.4, $"both ports ingest {Pps(Math.Min(top[0].BroadcastPps, top[1].BroadcastPps))} broadcast pps");
            ev.IngressPorts.Add(top[0].Name);
            ev.IngressPorts.Add(top[1].Name);
        }

        // ---- network-wide evidence ----
        double global = 0;
        var globalReasons = new List<string>();
        var nowUtc = now.UtcDateTime;
        if (anomaly.LoopBursts5s >= 2 && anomaly.LastLoopTimeUtc is { } lt && (nowUtc - lt).Duration() <= LoopEvidenceWindow)
        {
            global = 1 - (1 - global) * (1 - (anomaly.LoopBursts5s >= 20 ? 0.6 : 0.4));
            globalReasons.Add($"{anomaly.LoopBursts5s} duplicate-frame bursts in 5 s");
        }
        if (anomaly.TcEventsInWindow >= AnomalyEngine.TcBurstCount && anomaly.LastTcTimeUtc is { } tt && (nowUtc - tt).Duration() <= AnomalyEngine.TcBurstWindow)
        {
            global = 1 - (1 - global) * 0.7;
            globalReasons.Add($"{anomaly.TcEventsInWindow} STP topology changes in {AnomalyEngine.TcBurstWindow.TotalSeconds:0} s");
        }

        var result = new List<LoopSuspect>();
        foreach (var (sw, ev) in perSwitch)
        {
            double conf = ev.Confidence;
            var reasons = ev.Reasons.ToList();
            if (global > 0)
            {
                conf = 1 - (1 - conf) * (1 - global * 0.5);
                reasons.AddRange(globalReasons);
            }
            conf = Math.Min(0.95, conf);
            // prefer the ports that carry both kinds of evidence, then the rest
            var portList = ev.Ports.OrderByDescending(p => ev.IngressPorts.Contains(p)).ThenBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
            string where = portList.Count switch
            {
                0 => $"on {switchName(sw)}",
                1 => $"on {switchName(sw)} port {portList[0]}",
                2 => $"between {switchName(sw)} port {portList[0]} and port {portList[1]}",
                _ => $"between {switchName(sw)} ports {string.Join(", ", portList.Take(portList.Count - 1))} and {portList[^1]}",
            };
            result.Add(new LoopSuspect($"Loop suspected {where} ({string.Join(", ", reasons)})", sw, portList, ev.Macs.ToList(), conf, now));
        }
        if (result.Count == 0 && global > 0)
        {
            result.Add(new LoopSuspect($"Possible layer-2 loop: {string.Join(", ", globalReasons)}; no switch FDB/counters to pinpoint the ports",
                null, [], anomaly.LastLoopSource is { } m ? [m] : [], Math.Min(0.95, global), now));
        }
        return result.OrderByDescending(l => l.Confidence).ToList();
    }

    private sealed class SwitchEvidence
    {
        public readonly HashSet<string> Ports = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> IngressPorts = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<Mac> Macs = new();
        public readonly List<string> Reasons = new();
        public double Confidence;
        public void Add(double c, string reason)
        {
            Confidence = 1 - (1 - Confidence) * (1 - c);
            Reasons.Add(reason);
        }
    }

    private static string Join(IReadOnlyList<string> ports) => ports.Count <= 2 ? string.Join(" and ", ports) : string.Join(", ", ports);

    public static string Pps(double v) => v >= 1000 ? $"{v / 1000:0.#}k" : $"{v:0}";
}
