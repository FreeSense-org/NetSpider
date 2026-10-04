using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Scan stage 20: IPv6 neighbor discovery. Pings the all-nodes group ff02::1 (from our link-local and, if present, our
/// global address), collects echo replies and neighbor advertisements, then sends Neighbor Solicitations to every known
/// IPv6 address to measure the NS→NA L2 round trip.
/// </summary>
public sealed class NdpSweepProbe : IActiveProbe
{
    private static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");
    private static readonly TimeSpan CollectFor = TimeSpan.FromSeconds(3);

    private readonly ILogger<NdpSweepProbe> _log;
    private readonly IFrameSource _frames;
    private readonly IDeviceStore _store;
    private readonly LatencyProber _prober;
    private readonly DiscoveryContext _dctx;

    public NdpSweepProbe(ILogger<NdpSweepProbe> log, IFrameSource frames, IDeviceStore store, LatencyProber prober, DiscoveryContext dctx)
    {
        _log = log;
        _frames = frames;
        _store = store;
        _prober = prober;
        _dctx = dctx;
    }

    public string Name => "IPv6 neighbor discovery";
    public ProbeLayer Layer => ProbeLayer.L2;
    public int Order => 20;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        var adapter = ctx.Adapter;
        if (!_frames.IsRunning || adapter.LinkLocalV6 is null) { _log.LogDebug("NDP sweep skipped (no capture or no IPv6 link-local)"); return; }
        try
        {
            var local = adapter.Mac;
            ushort id = (ushort)Random.Shared.Next(1, 0xFFFF);
            var collector = new EchoCollector(id, local);
            using (_frames.Subscribe(collector))
            {
                var sources = new List<IPAddress> { DeviceHints.Normalize(adapter.LinkLocalV6) };
                var global = adapter.IPv6.FirstOrDefault(a => !a.IsIPv6LinkLocal && !a.IsIPv6Multicast && !a.IsIPv6SiteLocal);
                if (global is not null) sources.Add(DeviceHints.Normalize(global));
                ushort seq = 1;
                for (int round = 0; round < 2; round++)
                    foreach (var src in sources)
                        await _frames.SendPacedAsync(FrameBuilder.Icmp6Echo(local, src, AllNodes, IpUtil.MulticastMac(AllNodes), id, seq++), ct).ConfigureAwait(false);
                progress?.Report(new ScanProgress(Name, 0.1, "pinging ff02::1"));
                await Task.Delay(CollectFor, ct).ConfigureAwait(false);
            }

            int learned = 0;
            foreach (var (mac, ip) in collector.Results)
            {
                if (mac == local) continue;
                var d = _store.Observe(mac, ip, "ndp");
                d.AddIp(ip);
                learned++;
            }
            progress?.Report(new ScanProgress(Name, 0.4, $"{learned} IPv6 replies"));

            // NS → NA round trip for every known IPv6 neighbor.
            var targets = _store.All
                .Where(d => d.Mac != local && !Core.Services.SyntheticNodes.IsSynthetic(d.Mac))
                .SelectMany(d => d.IPv6.Where(x => x.Kind is Ipv6Kind.LinkLocal or Ipv6Kind.GlobalUnicast or Ipv6Kind.UniqueLocal).Select(x => (Device: d, x.Address)))
                .ToList();
            int done = 0;
            var tasks = targets.Select(async t =>
            {
                try
                {
                    var ms = await _prober.NdpPingCoreAsync(t.Address, t.Device.Mac, TimeSpan.FromMilliseconds(1500), paced: true, ct).ConfigureAwait(false);
                    if (ms is { } v) { t.Device.Latency.Add(LatencyKind.Ndp, v); _store.NotifyChanged(t.Device, "ndp-rtt"); }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogDebug(ex, "NS {Ip}", t.Address); }
                finally
                {
                    int n = Interlocked.Increment(ref done);
                    if (n % 8 == 0 || n == targets.Count) progress?.Report(new ScanProgress(Name, 0.4 + 0.6 * n / Math.Max(1, targets.Count), $"NS {n}/{targets.Count}"));
                }
            }).ToList();
            await Task.WhenAll(tasks).ConfigureAwait(false);
            progress?.Report(new ScanProgress(Name, 1, $"{learned} IPv6 hosts"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "NDP sweep failed"); }
    }

    /// <summary>Collects echo replies matching our identifier and any neighbor advertisements while the sweep runs.</summary>
    internal sealed class EchoCollector(ushort id, Mac local) : IFrameHandler
    {
        private readonly ConcurrentDictionary<IPAddress, Mac> _found = new();
        public IEnumerable<(Mac Mac, IPAddress Ip)> Results => _found.Select(kv => (kv.Value, kv.Key));

        public void OnFrame(CapturedFrame frame)
        {
            if (frame.IsOutbound || frame.Eth.EtherType != EthernetView.Ipv6 || frame.Eth.Source == local) return;
            try
            {
                var p = frame.Payload;
                if (!IpView.TryParse(p, EthernetView.Ipv6, out var ip) || ip.Protocol != IpView.Icmp6) return;
                var icmp = ip.L4(p);
                if (icmp.Length < 8) return;
                var src = ip.Source(p);
                if (src.Equals(IPAddress.IPv6Any)) return;
                if (icmp[0] == NdpParser.EchoReply && BinaryPrimitives.ReadUInt16BigEndian(icmp[4..]) == id)
                    _found[src] = frame.Eth.Source;
                else if (icmp[0] == NdpParser.NeighborAdvertisement && NdpParser.ParseNeighbor(icmp) is { } na)
                    _found[na.Target] = na.LinkLayer ?? frame.Eth.Source;
            }
            catch { /* never break the dispatch loop */ }
        }
    }
}
