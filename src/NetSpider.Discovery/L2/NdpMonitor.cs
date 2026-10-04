using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive IPv6 neighbor-discovery listener. Router Advertisements give the sender the <see cref="DeviceType.Router"/>
/// hint and RA properties (prefixes, flags, RDNSS, MTU). When more than one RA source is active, every source that is not
/// the gateway gets a <see cref="AlertKind.RogueRouterAdvert"/> alert and flag. Neighbor solicitations/advertisements
/// teach IPv6 addresses.
/// </summary>
public sealed class NdpMonitor : IFrameHandler
{
    private static readonly TimeSpan SourceWindow = TimeSpan.FromMinutes(30);

    private readonly ILogger<NdpMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly IAlertService _alerts;
    private readonly DiscoveryContext _ctx;
    private readonly ActivityPublisher _activity;
    private readonly Dictionary<Mac, DateTimeOffset> _raSources = new();

    public NdpMonitor(ILogger<NdpMonitor> log, IDeviceStore store, IAlertService alerts, DiscoveryContext ctx, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _alerts = alerts;
        _ctx = ctx;
        _activity = activity;
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound || frame.Eth.EtherType != EthernetView.Ipv6) return;
        try
        {
            var p = frame.Payload;
            if (!IpView.TryParse(p, EthernetView.Ipv6, out var ip) || ip.Protocol != IpView.Icmp6) return;
            var icmp = ip.L4(p);
            if (icmp.Length < 4) return;
            switch (icmp[0])
            {
                case NdpParser.RouterAdvertisement:
                    if (NdpParser.ParseRa(icmp) is { } ra) ApplyRa(ra, frame.Eth.Source, ip.Source(p));
                    break;
                case NdpParser.NeighborSolicitation:
                case NdpParser.NeighborAdvertisement:
                    if (NdpParser.ParseNeighbor(icmp) is { } nm) ApplyNeighbor(nm, frame.Eth.Source, ip.Source(p));
                    break;
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "NDP frame from {Mac}", frame.Eth.Source); }
    }

    internal void ApplyNeighbor(NeighborMessage m, Mac ethSrc, IPAddress src)
    {
        _activity.Publish(ethSrc, "NDP");
        if (m.IsAdvertisement)
        {
            var mac = m.LinkLayer ?? ethSrc;
            if (mac.IsMulticast || mac.IsZero) return;
            _store.Observe(mac, m.Target, "ndp");
        }
        else if (!src.Equals(IPAddress.IPv6Any) && m.LinkLayer is { } sll && !sll.IsMulticast)
        {
            _store.Observe(sll, src, "ndp"); // DAD probes (src ::) carry no usable address
        }
    }

    internal Device ApplyRa(RouterAdvert ra, Mac ethSrc, IPAddress src)
    {
        _activity.Publish(ethSrc, "NDP");
        var mac = ra.SourceLinkLayer is { } sll && !sll.IsMulticast ? sll : ethSrc;
        var d = _store.Observe(mac, src, "ndp");
        bool ch = DeviceHints.HintType(d, "ndp", DeviceType.Router, 0.7);
        ch |= d.AddEvidence("ndp", Fields.Capabilities, "IPv6 Router", 0.8);
        if (!d.Has(DeviceFlags.Infrastructure)) { d.SetFlag(DeviceFlags.Infrastructure); ch = true; }
        ch |= d.SetProperty("ra.prefixes", ra.Prefixes.Count == 0 ? null : string.Join(",", ra.Prefixes));
        ch |= d.SetProperty("ra.routerLifetime", ((int)ra.RouterLifetime.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture));
        ch |= d.SetProperty("ra.flags", $"M={(ra.Managed ? 1 : 0)} O={(ra.OtherConfig ? 1 : 0)} pref={ra.Preference}");
        if (ra.Mtu is { } mtu) ch |= d.SetProperty("ra.mtu", mtu.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (ra.Rdnss.Count > 0) ch |= d.SetProperty("ra.rdnss", string.Join(",", ra.Rdnss));
        if (ra.RouteInfo.Count > 0) ch |= d.SetProperty("ra.routes", string.Join(",", ra.RouteInfo));
        if (ch) _store.NotifyChanged(d, "ra");

        CheckRogue(d, src);
        return d;
    }

    private void CheckRogue(Device sender, IPAddress src)
    {
        var now = DateTimeOffset.Now;
        List<Mac> active;
        lock (_raSources)
        {
            _raSources[sender.Mac] = now;
            foreach (var stale in _raSources.Where(kv => now - kv.Value > SourceWindow).Select(kv => kv.Key).ToList()) _raSources.Remove(stale);
            active = _raSources.Keys.ToList();
        }
        if (active.Count < 2) return;

        var gwMac = _ctx.Gateway is { } gw ? _store.FindByIp(gw)?.Mac : null;
        var gw6 = _ctx.GatewayV6;
        if (gwMac is null && gw6 is null) return; // cannot tell which router is legitimate
        foreach (var mac in active)
        {
            if (!_store.TryGet(mac, out var d)) continue;
            bool isGateway = d.Has(DeviceFlags.Gateway) || mac == gwMac || (gw6 is not null && d.HasIp(DeviceHints.Normalize(gw6)));
            if (isGateway || d.Has(DeviceFlags.RogueRouterAdvert)) continue;
            d.SetFlag(DeviceFlags.RogueRouterAdvert);
            _store.NotifyChanged(d, "rogue-ra");
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.RogueRouterAdvert,
                $"Rogue IPv6 router advertisement from {d.DisplayName}",
                $"{mac} sends IPv6 Router Advertisements ({d.GetProperty("ra.prefixes") ?? "no prefixes"}) but is not the gateway; " +
                $"{active.Count} RA sources are active. Hosts may route IPv6 traffic through it.",
                mac), TimeSpan.FromMinutes(10));
        }
    }
}
