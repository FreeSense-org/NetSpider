using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L3;

/// <summary>
/// ICMP traceroute using <see cref="Ping"/> with a TTL ramp (3 probes per hop). All TTLs are probed concurrently and the
/// path is cut at the first hop that answers from the target; reverse DNS runs per hop with a short timeout.
/// </summary>
public sealed class Tracerouter : ITracerouter
{
    public const int ProbesPerHop = 3;
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(1500);
    private static readonly TimeSpan DnsTimeout = TimeSpan.FromMilliseconds(800);

    private readonly ILogger<Tracerouter> _log;
    private readonly IDeviceStore _store;

    public Tracerouter(ILogger<Tracerouter> log, IDeviceStore store)
    {
        _log = log;
        _store = store;
    }

    public async Task<IReadOnlyList<TracerouteHop>> TraceAsync(IPAddress target, int maxHops, CancellationToken ct)
    {
        maxHops = Math.Clamp(maxHops, 1, 64);
        try
        {
            var reach = new ReachMarker();
            var hops = await Task.WhenAll(Enumerable.Range(1, maxHops).Select(ttl => ProbeHopAsync(target, ttl, reach, ct))).ConfigureAwait(false);
            int last = Array.FindIndex(hops, h => h.Reached);
            var path = (last >= 0 ? hops.Take(last + 1) : TrimTrailingSilence(hops)).ToList();

            var names = await Task.WhenAll(path.Select(h => h.Address is null ? Task.FromResult<string?>(null) : ReverseDnsAsync(h.Address, ct))).ConfigureAwait(false);
            var result = new List<TracerouteHop>(path.Count);
            for (int i = 0; i < path.Count; i++)
            {
                var h = path[i];
                Mac? mac = h.Address is null ? null : _store.FindByIp(h.Address)?.Mac;
                result.Add(new TracerouteHop(h.Ttl, h.Address, h.RttMs, names[i], mac));
            }
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Traceroute to {Target} failed", target);
            return [];
        }
    }

    private static IEnumerable<HopResult> TrimTrailingSilence(HopResult[] hops)
    {
        int lastAnswered = Array.FindLastIndex(hops, h => h.Address is not null);
        return hops.Take(lastAnswered + 1);
    }

    private readonly record struct HopResult(int Ttl, IPAddress? Address, double? RttMs, bool Reached);

    /// <summary>Lowest TTL known to reach the target; probes for deeper TTLs stop early.</summary>
    private sealed class ReachMarker { public int Ttl = int.MaxValue; }

    private async Task<HopResult> ProbeHopAsync(IPAddress target, int ttl, ReachMarker reach, CancellationToken ct)
    {
        IPAddress? addr = null;
        double? best = null;
        bool reached = false;
        var buffer = new byte[32];
        for (int i = 0; i < ProbesPerHop; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (ttl > Volatile.Read(ref reach.Ttl)) break;
            try
            {
                using var ping = new Ping();
                long t0 = Stopwatch.GetTimestamp();
                var reply = await ping.SendPingAsync(target, ProbeTimeout, buffer, new PingOptions(ttl, dontFragment: true), ct).ConfigureAwait(false);
                double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                if (reply.Status is IPStatus.TtlExpired or IPStatus.TimeExceeded or IPStatus.Success)
                {
                    addr ??= reply.Address;
                    if (reply.Status == IPStatus.Success) { reached = true; InterlockedMin(ref reach.Ttl, ttl); if (reply.RoundtripTime > 0 && ms > reply.RoundtripTime + 1) ms = reply.RoundtripTime; }
                    best = best is null ? ms : Math.Min(best.Value, ms);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _log.LogDebug(ex, "Traceroute probe ttl {Ttl}", ttl); }
        }
        return new HopResult(ttl, addr, best, reached);
    }

    private static void InterlockedMin(ref int location, int value)
    {
        int cur;
        while (value < (cur = Volatile.Read(ref location)) && Interlocked.CompareExchange(ref location, value, cur) != cur) { }
    }

    private async Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            // Dns honours cancellation only before the OS lookup starts; observe a late fault so it is not "unobserved".
            var lookup = Dns.GetHostEntryAsync(ip);
            _ = lookup.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            var entry = await lookup.WaitAsync(DnsTimeout, ct).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(entry.HostName) || entry.HostName == ip.ToString() ? null : entry.HostName;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }
}
