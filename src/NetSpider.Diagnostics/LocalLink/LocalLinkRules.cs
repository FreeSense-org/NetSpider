using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.LocalLink;

/// <summary>Pure diff between two snapshots of this host's NIC → diagnostic signals.</summary>
public static class LocalLinkRules
{
    public const string Source = "local-link";

    /// <param name="prev">Previous snapshot (null on the first poll: no signals except an initial "down").</param>
    public static IReadOnlyList<DiagnosticSignal> Diff(LocalLinkState? prev, LocalLinkState? cur, DateTimeOffset now)
    {
        var list = new List<DiagnosticSignal>();
        if (cur is null) return list;
        Mac? dev = cur.Mac.IsZero ? null : cur.Mac;
        DiagnosticSignal Sig(SignalKind k, string summary, double weight) => new(now, k, Source, summary, dev, cur.Name, weight);

        if (prev is null)
        {
            if (!cur.Up) list.Add(Sig(SignalKind.LocalLinkDown, DownText(cur), 1.0));
            return list;
        }

        if (prev.Id != cur.Id)
        {
            // switched to another adapter (e.g. Ethernet unplugged, Wi-Fi took over)
            if (cur.Up) list.Add(Sig(SignalKind.LocalLinkUp, $"Now using {Kind(cur)} adapter {cur.Name} ({Ips(cur)}) instead of {prev.Name}", 0.3));
            else list.Add(Sig(SignalKind.LocalLinkDown, DownText(cur), 1.0));
            return list;
        }

        if (prev.Up && !cur.Up) { list.Add(Sig(SignalKind.LocalLinkDown, DownText(cur), 1.0)); return list; }
        if (!prev.Up && cur.Up)
            list.Add(Sig(SignalKind.LocalLinkUp, $"Link restored on {cur.Name}{(cur.IsWireless || cur.SpeedMbps <= 0 ? "" : $" at {FormatSpeed(cur.SpeedMbps)}")}", 0.3));
        if (!cur.Up) return list;

        // Wi-Fi rates change all the time (rate adaptation); only wired speed changes are meaningful
        if (!cur.IsWireless && prev.Up && prev.SpeedMbps > 0 && cur.SpeedMbps > 0 && prev.SpeedMbps != cur.SpeedMbps)
        {
            bool down = cur.SpeedMbps < prev.SpeedMbps;
            list.Add(Sig(SignalKind.LocalSpeedChanged,
                down ? $"Link speed on {cur.Name} dropped {FormatSpeed(prev.SpeedMbps)} → {FormatSpeed(cur.SpeedMbps)} — possible bad cable or port"
                     : $"Link speed on {cur.Name} changed {FormatSpeed(prev.SpeedMbps)} → {FormatSpeed(cur.SpeedMbps)}",
                down ? 0.7 : 0.2));
        }

        if (cur.HasApipa && !cur.HasRoutableV4 && !(prev.HasApipa && !prev.HasRoutableV4))
            list.Add(Sig(SignalKind.DhcpLeaseLost, $"{cur.Name} fell back to an APIPA address ({Ips(cur)}) — DHCP lease lost / no DHCP server reachable", 0.8));
        else if (!SameIps(prev, cur) && cur.IPv4.Count > 0)
            list.Add(Sig(SignalKind.LocalIpChanged, $"IP address of {cur.Name} changed {Ips(prev)} → {Ips(cur)}", 0.3));

        if (!Equals(prev.Gateway, cur.Gateway) && (prev.Gateway is not null || cur.Gateway is not null))
        {
            string text = cur.Gateway is null ? $"Default gateway {prev.Gateway} disappeared on {cur.Name}"
                : prev.Gateway is null ? $"Default gateway on {cur.Name} is now {cur.Gateway}"
                : $"Default gateway on {cur.Name} changed {prev.Gateway} → {cur.Gateway}";
            list.Add(Sig(SignalKind.LocalGatewayChanged, text, cur.Gateway is null ? 0.6 : 0.3));
        }
        return list;
    }

    public static string DownText(LocalLinkState s) =>
        s.IsWireless ? $"Wi-Fi disconnected on {s.Name}" : $"Cable unplugged or switch port down on {s.Name}";

    public static string FormatSpeed(long mbps) => mbps >= 1000 && mbps % 1000 == 0 ? $"{mbps / 1000} Gbps" : $"{mbps} Mbps";

    private static string Kind(LocalLinkState s) => s.IsWireless ? "Wi-Fi" : "wired";

    private static string Ips(LocalLinkState s) => s.IPv4.Count == 0 ? "no IPv4" : string.Join(", ", s.IPv4.Select(a => a.ToString()));

    private static bool SameIps(LocalLinkState a, LocalLinkState b) =>
        a.IPv4.Select(x => x.ToString()).OrderBy(x => x, StringComparer.Ordinal)
            .SequenceEqual(b.IPv4.Select(x => x.ToString()).OrderBy(x => x, StringComparer.Ordinal));
}
