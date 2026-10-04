using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Wifi;

/// <summary>Everything the AP diagnosis rules look at for one access point (one monitor cycle).</summary>
/// <param name="MgmtUp">Management IP answered ICMP or ARP; null when the AP has no known management IP.</param>
/// <param name="UpstreamUp">The AP's upstream switch answers; null when unknown (no upstream, or no way to probe it).</param>
/// <param name="ClientsSeen">Recently-seen wireless clients being tracked.</param>
/// <param name="ClientsUnreachable">Clients failing the 2-of-N rule (their last ≥2 probes failed).</param>
/// <param name="ClientsReachable">Clients whose recent probes succeed (the rest are undecided, e.g. a single missed probe).</param>
/// <param name="ClientOutageFor">How long the "≥ outage fraction unreachable" condition has held continuously.</param>
/// <param name="ClientLossPercent">Probe loss over clients that are still reachable.</param>
/// <param name="ChannelOtherBss">Other BSSIDs (not this AP's) seen on the AP's channel by the Wi-Fi scan.</param>
/// <param name="HostOnThisAp">This host is associated to this AP over Wi-Fi.</param>
/// <param name="HostRadioOk">This host's radio hop is healthy (connected, signal OK, AP answers).</param>
/// <param name="HostGatewayOk">This host reaches the gateway over Wi-Fi; false = recently failing although it normally answers.</param>
public sealed record ApObservation(
    string ApName,
    bool? MgmtUp,
    double? MgmtRttMs,
    bool? UpstreamUp,
    string? UpstreamName,
    string? UpstreamPort,
    int ClientsSeen,
    int ClientsUnreachable,
    int ClientsReachable,
    TimeSpan ClientOutageFor,
    double ClientLossPercent,
    double? ClientJitterMs,
    double? AvgClientRttMs,
    int? Channel,
    int ChannelOtherBss,
    bool HostOnThisAp = false,
    bool? HostRadioOk = null,
    bool? HostGatewayOk = null);

public sealed record ApDiagnosisOptions
{
    public static readonly ApDiagnosisOptions Default = new();

    /// <summary>Fraction of recently-seen clients that must be unreachable to call a radio/SSID problem.</summary>
    public double OutageFraction { get; init; } = 0.7;
    public TimeSpan OutageHold { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Phones sleep: never call a radio outage from fewer clients than this.</summary>
    public int MinClientsForOutage { get; init; } = 2;
    public double LossDegradedPercent { get; init; } = 25;
    public double JitterDegradedMs { get; init; } = 60;
    /// <summary>Other BSSIDs on the same channel from which the channel is called congested.</summary>
    public int CongestedChannelBss { get; init; } = 5;
}

public sealed record ApVerdict(HopHealth Health, string? Diagnosis, SignalKind? Signal, double Weight = 0.5);

/// <summary>Pure rules turning an <see cref="ApObservation"/> into health, a diagnosis sentence and an optional signal.</summary>
public static class ApDiagnosis
{
    public static ApVerdict Evaluate(ApObservation o, ApDiagnosisOptions? options = null)
    {
        var opt = options ?? ApDiagnosisOptions.Default;
        int reachable = o.ClientsReachable;

        // 1. management IP silent
        if (o.MgmtUp == false)
        {
            if (o.ClientsSeen > 0 && reachable > 0)
                return new(HopHealth.Up, $"Management IP does not answer, but {reachable} of {o.ClientsSeen} clients are reachable through the AP (management may filter ping)", null);
            if (o.UpstreamUp == false)
                return new(HopHealth.Down, $"AP unreachable — its upstream {o.UpstreamName ?? "switch"} is down too (fault is upstream of the AP)", null);
            string where = o.UpstreamName is null ? "its switch port"
                : o.UpstreamPort is null ? $"its port on {o.UpstreamName}" : $"its switch port {o.UpstreamName} {o.UpstreamPort}";
            return new(HopHealth.Down, $"AP down — check AP power/PoE or {where}", SignalKind.ApDown, o.UpstreamUp == true ? 0.85 : 0.6);
        }

        // 2. this host's radio hop fine, but nothing beyond the AP
        if (o.HostOnThisAp && o.HostRadioOk == true && o.HostGatewayOk == false)
            return new(HopHealth.Degraded, "Wireless OK, backhaul from AP to router failing", SignalKind.ApDegraded, 0.7);

        // 3. most recently-seen clients unreachable for a while
        if (o.ClientsSeen >= opt.MinClientsForOutage
            && o.ClientsUnreachable >= Math.Ceiling(o.ClientsSeen * opt.OutageFraction - 1e-9)
            && o.ClientOutageFor >= opt.OutageHold)
        {
            string count = $"{o.ClientsUnreachable} of {o.ClientsSeen} wireless clients unreachable for {o.ClientOutageFor.TotalSeconds:0} s";
            return o.MgmtUp == true
                ? new(HopHealth.Down, $"AP radio/SSID problem — wired side OK ({count})", SignalKind.ApClientsUnreachable, 0.8)
                : new(HopHealth.Down, $"AP radio/SSID problem likely ({count}; no management IP to confirm the wired side)", SignalKind.ApClientsUnreachable, 0.6);
        }

        // 4. reachable but lossy / jittery
        bool lossy = reachable > 0 && o.ClientLossPercent >= opt.LossDegradedPercent;
        bool jittery = o.ClientJitterMs >= opt.JitterDegradedMs;
        if (lossy || jittery)
        {
            var parts = new List<string>();
            if (lossy) parts.Add($"{o.ClientLossPercent:0}% client loss");
            if (jittery) parts.Add($"{o.ClientJitterMs:0} ms jitter");
            if (o.Channel is { } ch)
            {
                string congestion = o.ChannelOtherBss >= opt.CongestedChannelBss ? " (congested)" : "";
                parts.Add(o.ChannelOtherBss == 0 ? $"channel {ch} has no other BSSIDs (congestion unlikely)" : $"channel {ch} shared with {o.ChannelOtherBss} other BSSIDs{congestion}");
            }
            return new(HopHealth.Degraded, $"RF/interference or congestion: {string.Join(", ", parts)}", SignalKind.ApDegraded, 0.5);
        }

        if (o.MgmtUp is null && o.ClientsSeen == 0)
            return new(HopHealth.Unknown, "No management IP or wireless clients to probe", null);
        if (o.MgmtUp is null && reachable == 0)
            return new(HopHealth.Unknown, $"No management IP; {o.ClientsUnreachable} client(s) not answering (may be asleep)", null);
        return new(HopHealth.Up, null, null);
    }
}
