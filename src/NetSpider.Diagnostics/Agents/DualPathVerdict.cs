using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

public enum DualPathSuspect { Ok, WiredSide, WifiSide, ApLanBridge, Upstream, Inconclusive }

public sealed record DualPathVerdictResult(DualPathSuspect Suspect, string Sentence);

/// <summary>
/// Compares what this PC's wired and Wi-Fi adapters can reach (local vantages) and names the failing side.
/// Results use the target names written by <see cref="LocalVantageMonitor"/>: <c>gw</c> (own gateway),
/// <c>gw:&lt;other adapter&gt;</c>, <c>internet</c> and <c>peer:&lt;other adapter&gt;</c> (the other adapter's own IP).
/// </summary>
public static class DualPathVerdict
{
    public const string Gateway = "gw";
    public const string Internet = "internet";
    public const string PeerPrefix = "peer:";
    public const string PeerGatewayPrefix = "gw:";

    public static DualPathVerdictResult Evaluate(IReadOnlyList<ProbeTargetResult> wired, IReadOnlyList<ProbeTargetResult> wifi,
        string? wiredIp = null, string? wifiIp = null)
    {
        var wiredName = wiredIp is null ? "wired adapter" : $"wired adapter ({wiredIp})";
        var wifiName = wifiIp is null ? "Wi-Fi adapter" : $"Wi-Fi adapter ({wifiIp})";

        var wGw = State(Find(wired, Gateway));
        var fGw = State(Find(wifi, Gateway));
        var wNet = State(Find(wired, Internet));
        var fNet = State(Find(wifi, Internet));
        var wPeer = State(wired.FirstOrDefault(r => r.Target.StartsWith(PeerPrefix, StringComparison.OrdinalIgnoreCase)));
        var fPeer = State(wifi.FirstOrDefault(r => r.Target.StartsWith(PeerPrefix, StringComparison.OrdinalIgnoreCase)));
        string Gw(IReadOnlyList<ProbeTargetResult> rs) => Find(rs, Gateway)?.Ip is { } ip ? $"gateway {ip}" : "its gateway";

        if (wGw == Reach.Unknown && fGw == Reach.Unknown)
            return new(DualPathSuspect.Inconclusive, "not enough samples from both adapters yet");

        // gateway layer first
        if (wGw == Reach.Down && fGw == Reach.Down)
            return new(DualPathSuspect.Upstream, $"neither the {wiredName} nor the {wifiName} reaches its gateway → gateway/router or the common core switch");
        if (fGw == Reach.Down && wGw == Reach.Up)
            return new(DualPathSuspect.WifiSide, $"{Cap(wifiName)} cannot reach {Gw(wifi)}, wired adapter can → problem on the Wi-Fi side (AP/radio or AP uplink)");
        if (wGw == Reach.Down && fGw == Reach.Up)
            return new(DualPathSuspect.WiredSide, $"{Cap(wiredName)} cannot reach {Gw(wired)}, Wi-Fi adapter can → problem on the wired side (cable, switch port or access switch)");

        // both reach the gateway: crossover path between the two adapters
        if (wGw == Reach.Up && fGw == Reach.Up && (wPeer == Reach.Down || fPeer == Reach.Down))
        {
            var dir = (wPeer, fPeer) switch
            {
                (Reach.Down, Reach.Down) => "wired ↔ own Wi-Fi IP fails in both directions",
                (Reach.Down, _) => "wired → own Wi-Fi IP fails",
                _ => "Wi-Fi → own wired IP fails",
            };
            return new(DualPathSuspect.ApLanBridge, $"{dir} but both reach the gateway → AP/LAN bridging or client isolation");
        }

        // internet layer
        if (wNet == Reach.Down && fNet == Reach.Down && wGw == Reach.Up && fGw == Reach.Up)
            return new(DualPathSuspect.Upstream, "both adapters reach their gateway but not the internet → router WAN, modem or ISP");
        if (fNet == Reach.Down && wNet == Reach.Up)
            return new(DualPathSuspect.WifiSide, $"{Cap(wifiName)} reaches its gateway but not the internet, wired adapter does → Wi-Fi network routing/firewall (guest VLAN?)");
        if (wNet == Reach.Down && fNet == Reach.Up)
            return new(DualPathSuspect.WiredSide, $"{Cap(wiredName)} reaches its gateway but not the internet, Wi-Fi adapter does → wired network routing/firewall");

        if (wGw == Reach.Up && fGw == Reach.Up)
            return new(DualPathSuspect.Ok, "wired and Wi-Fi adapters both reach the gateway" + (wNet == Reach.Up && fNet == Reach.Up ? " and the internet" : "") +
                (wPeer == Reach.Up && fPeer == Reach.Up ? "; the LAN ↔ Wi-Fi crossover works both ways" : ""));
        return new(DualPathSuspect.Inconclusive, "waiting for more samples");
    }

    private enum Reach { Unknown, Up, Down }

    private static ProbeTargetResult? Find(IReadOnlyList<ProbeTargetResult> rs, string target) =>
        rs.FirstOrDefault(r => r.Target.Equals(target, StringComparison.OrdinalIgnoreCase));

    private static Reach State(ProbeTargetResult? r) =>
        r is null || r.Sent == 0 ? Reach.Unknown
        : r.LossPercent >= AgentSignalLogic.FailLossPercent ? Reach.Down
        : r.RttMs is not null || r.LossPercent < AgentSignalLogic.FailLossPercent ? Reach.Up : Reach.Unknown;

    private static string Cap(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
