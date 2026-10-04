using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>Probes one target IP (ARP when allowed, plus ICMP). Separate so the monitor can be tested without a network.</summary>
public interface IHopProber
{
    Task<HopProbeResult> ProbeAsync(IPAddress ip, bool arp, TimeSpan timeout, CancellationToken ct);
}

/// <summary>
/// ICMP through <see cref="ILatencyProber"/> when registered (plain <see cref="Ping"/> otherwise); ARP through the prober
/// only while capture runs. ARP failing because capture is unavailable is reported as "not attempted" (null), so the hop
/// degrades gracefully to ICMP-only.
/// </summary>
public sealed class HopProber : IHopProber
{
    private readonly ILatencyProber? _prober;
    private readonly IFrameSource? _frames;
    private readonly ILogger<HopProber> _log;

    public HopProber(ILogger<HopProber> log, ILatencyProber? prober = null, IFrameSource? frames = null)
    {
        _log = log;
        _prober = prober;
        _frames = frames;
    }

    public async Task<HopProbeResult> ProbeAsync(IPAddress ip, bool arp, TimeSpan timeout, CancellationToken ct)
    {
        bool canArp = arp && _prober is not null && _frames is { IsRunning: true } && ip.AddressFamily == AddressFamily.InterNetwork;
        var icmpTask = IcmpAsync(ip, timeout, ct);
        Task<(double? Ms, Mac? Mac)>? arpTask = canArp ? SafeArpAsync(ip, timeout, ct) : null;
        var icmp = await icmpTask.ConfigureAwait(false);
        bool? arpOk = null;
        double? arpMs = null;
        if (arpTask is not null)
        {
            var (ms, _) = await arpTask.ConfigureAwait(false);
            arpOk = ms is not null;
            arpMs = ms;
        }
        return new HopProbeResult(arpOk, icmp is not null, icmp ?? arpMs);
    }

    private async Task<(double? Ms, Mac? Mac)> SafeArpAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        try { return await _prober!.ArpPingAsync(ip, timeout, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "ARP probe {Ip} failed", ip); return (null, null); }
    }

    private async Task<double?> IcmpAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            if (_prober is not null) return await _prober.IcmpPingAsync(ip, timeout, ct).ConfigureAwait(false);
            using var ping = new Ping();
            long t0 = Stopwatch.GetTimestamp();
            var reply = await ping.SendPingAsync(ip, timeout, new byte[32], new PingOptions(128, false), ct).ConfigureAwait(false);
            if (reply.Status != IPStatus.Success) return null;
            double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
            return reply.RoundtripTime > 0 && ms > reply.RoundtripTime + 1 ? reply.RoundtripTime : ms;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "ICMP probe {Ip} failed", ip); return null; }
    }
}
