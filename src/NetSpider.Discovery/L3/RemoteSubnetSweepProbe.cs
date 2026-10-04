using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Discovery.L2;

namespace NetSpider.Discovery.L3;

/// <summary>
/// Scan stage 120: concurrent ICMP sweep (≤64 in flight) of every non-local segment with <c>ScanEnabled</c>. Hosts that
/// answer become devices keyed by <see cref="SyntheticNodes.RemoteHost"/> (their real MAC is behind a router), flagged
/// <see cref="DeviceFlags.OffSubnet"/>, with an ICMP latency sample and TTL evidence.
/// </summary>
public sealed class RemoteSubnetSweepProbe : IActiveProbe
{
    private const int MaxInFlight = 64;
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(1000);

    private readonly ILogger<RemoteSubnetSweepProbe> _log;
    private readonly IDeviceStore _store;
    private readonly DiscoveryContext _dctx;

    public RemoteSubnetSweepProbe(ILogger<RemoteSubnetSweepProbe> log, IDeviceStore store, DiscoveryContext dctx)
    {
        _log = log;
        _store = store;
        _dctx = dctx;
    }

    public string Name => "Remote subnet ICMP sweep";
    public ProbeLayer Layer => ProbeLayer.L3;
    public int Order => 120;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        if (!ctx.Settings.ScanOtherSubnets) return;
        var segments = _dctx.AllSegments(ctx)
            .Where(s => !s.IsLocal && s.ScanEnabled && s.Network.AddressFamily == AddressFamily.InterNetwork && !_dctx.InLocalSegment(s.Network))
            .ToList();
        if (segments.Count == 0) return;

        var work = segments.SelectMany(s => L2.ArpSweepProbe.SweepTargets(s.Network, s.PrefixLength, ctx.Settings.MinSweepPrefix, null).Select(ip => (Seg: s, Ip: ip)))
            .Where(w => !_dctx.IsLocalIp(w.Ip))
            .ToList();
        _log.LogInformation("ICMP sweep of {Count} addresses in {Segments}", work.Count, string.Join(", ", segments.Select(s => s.Cidr)));

        int done = 0;
        var hits = new Dictionary<NetworkSegment, int>();
        foreach (var s in segments) hits[s] = 0;
        try
        {
            await Parallel.ForEachAsync(work, new ParallelOptions { MaxDegreeOfParallelism = MaxInFlight, CancellationToken = ct }, async (w, token) =>
            {
                try
                {
                    var (ms, ttl) = await PingAsync(w.Ip, token).ConfigureAwait(false);
                    if (ms is { } rtt)
                    {
                        Record(w.Ip, rtt, ttl);
                        lock (hits) hits[w.Seg]++;
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogDebug(ex, "ICMP sweep {Ip}", w.Ip); }
                int n = Interlocked.Increment(ref done);
                if (n % 32 == 0 || n == work.Count) progress?.Report(new ScanProgress(Name, (double)n / work.Count, $"{n}/{work.Count}"));
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "Remote sweep failed"); }

        foreach (var s in segments)
        {
            s.HostsFound = hits[s];
            s.LastScanned = DateTimeOffset.Now;
        }
    }

    private static async Task<(double? Ms, int? Ttl)> PingAsync(IPAddress ip, CancellationToken ct)
    {
        using var ping = new Ping();
        long t0 = Stopwatch.GetTimestamp();
        var reply = await ping.SendPingAsync(ip, Timeout, new byte[32], new PingOptions(128, false), ct).ConfigureAwait(false);
        if (reply.Status != IPStatus.Success) return (null, null);
        double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        if (reply.RoundtripTime > 0 && ms > reply.RoundtripTime + 1) ms = reply.RoundtripTime;
        return (ms, reply.Options?.Ttl);
    }

    private void Record(IPAddress ip, double ms, int? ttl)
    {
        var d = _store.FindByIp(ip) ?? _store.Observe(SyntheticNodes.RemoteHost(ip), ip, "icmp");
        d.Touch();
        if (SyntheticNodes.IsSynthetic(d.Mac) || !_dctx.InLocalSegment(ip)) d.SetFlag(DeviceFlags.OffSubnet);
        d.Latency.Add(LatencyKind.Icmp, ms);
        if (ttl is int t and > 0)
        {
            d.Ttl = t;
            d.AddEvidence("icmp", Fields.Ttl, t.ToString(CultureInfo.InvariantCulture), Confidence.Ttl);
        }
        _store.NotifyChanged(d, "icmp-sweep");
    }
}
