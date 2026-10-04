using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;
using NetSpider.Discovery.L3;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Collects DHCP OFFERs whose xid belongs to one of our DISCOVERs. Subscribed to the frame source only while a probe
/// is waiting, so it costs nothing otherwise.
/// </summary>
internal sealed class DhcpOfferCollector(ICollection<uint> xids) : IFrameHandler
{
    public ConcurrentQueue<(DhcpPacket Offer, Mac ServerMac, IPAddress SourceIp, int? FrameVlan)> Offers { get; } = new();

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound || frame.Eth.EtherType != EthernetView.Ipv4) return;
        try
        {
            if (!DhcpBuilder.TryExtract(frame, out var p, out _, out var src)) return;
            if (p.IsBootRequest || p.MessageType != DhcpPacket.Offer || !xids.Contains(p.Xid)) return;
            Offers.Enqueue((p, frame.Eth.Source, src, frame.Eth.VlanId));
        }
        catch { /* never break the dispatch loop */ }
    }
}

/// <summary>
/// Scan stage 40: sends ONE broadcast DHCPDISCOVER with a random xid and collects every OFFER for 3 s. This finds all
/// DHCP servers on the segment, including rogue ones (judged by <see cref="DhcpMonitor"/>, which sees the same OFFERs).
/// Option 121/249 classless static routes are added as candidate segments ("dhcp-121").
/// A DHCPREQUEST is NEVER sent, so no lease is taken and no address is consumed beyond the server's short offer hold.
/// </summary>
public sealed class DhcpDiscoverProbe : IActiveProbe
{
    public static readonly TimeSpan CollectFor = TimeSpan.FromSeconds(3);

    private readonly ILogger<DhcpDiscoverProbe> _log;
    private readonly IFrameSource _frames;
    private readonly DhcpProbeRegistry _registry;
    private readonly SubnetDiscoverer _subnets;
    private readonly DiscoveryContext _dctx;
    private readonly IDeviceStore _store;

    public DhcpDiscoverProbe(ILogger<DhcpDiscoverProbe> log, IFrameSource frames, DhcpProbeRegistry registry, SubnetDiscoverer subnets,
        DiscoveryContext dctx, IDeviceStore store)
    {
        _log = log;
        _frames = frames;
        _registry = registry;
        _subnets = subnets;
        _dctx = dctx;
        _store = store;
    }

    public string Name => "DHCP server discovery";
    public ProbeLayer Layer => ProbeLayer.L2;
    public int Order => 40;

    /// <summary>Offers received by the last run (for diagnostics and tests).</summary>
    public IReadOnlyList<DhcpPacket> LastOffers { get; private set; } = [];

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        if (!ctx.Settings.ActiveDhcpDiscover || !_frames.IsRunning) return;
        uint xid = _registry.NewXid(null);
        var collector = new DhcpOfferCollector(new HashSet<uint> { xid });
        try
        {
            using (_frames.Subscribe(collector))
            {
                _frames.Send(DhcpBuilder.DiscoverFrame(ctx.LocalMac, xid));
                progress?.Report(new ScanProgress(Name, 0.1, "DHCPDISCOVER sent"));
                await Task.Delay(CollectFor, ct).ConfigureAwait(false);
            }
            var offers = collector.Offers.ToArray();
            LastOffers = offers.Select(o => o.Offer).ToList();
            foreach (var (offer, serverMac, _, _) in offers)
            {
                _log.LogInformation("DHCP OFFER from {Server} ({Mac}): {Ip}/{Mask} router {Router}", offer.ServerIdentifier, serverMac, offer.YourIp, offer.SubnetMask, offer.Routers.FirstOrDefault());
                foreach (var route in offer.ClasslessRoutes)
                {
                    if (route.PrefixLength == 0) continue; // default route
                    _subnets.AddCandidate(route.Network, route.PrefixLength, "dhcp-121", route.Router);
                }
                if (offer.ClasslessRoutes.Count > 0 && _store.TryGet(serverMac, out var srv) &&
                    srv.SetProperty("dhcp.classlessRoutes", string.Join("; ", offer.ClasslessRoutes)))
                    _store.NotifyChanged(srv, "dhcp-121");
            }
            progress?.Report(new ScanProgress(Name, 1, $"{offers.Select(o => o.Offer.ServerIdentifier?.ToString() ?? o.ServerMac.ToString()).Distinct().Count()} DHCP server(s)"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "DHCP discover failed"); }
        finally { _registry.Release(xid); }
    }
}
