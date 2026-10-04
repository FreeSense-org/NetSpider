using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>Transaction ids of our own DHCPDISCOVERs, so the passive monitor knows which OFFERs answer an active probe.</summary>
public sealed class DhcpProbeRegistry
{
    private readonly ConcurrentDictionary<uint, int?> _xids = new();

    /// <summary>Registers a fresh random xid; <paramref name="vlanId"/> is the 802.1Q VLAN the DISCOVER was sent on (null = untagged).</summary>
    public uint NewXid(int? vlanId)
    {
        while (true)
        {
            uint xid = (uint)Random.Shared.NextInt64(1, uint.MaxValue);
            if (_xids.TryAdd(xid, vlanId)) return xid;
        }
    }

    public bool TryGet(uint xid, out int? vlanId) => _xids.TryGetValue(xid, out vlanId);
    public void Release(uint xid) => _xids.TryRemove(xid, out _);
}

/// <summary>
/// Passive DHCPv4 listener (UDP 67/68).
/// <list type="bullet">
/// <item>Client messages: option 55 order → <see cref="Fields.DhcpFingerprint"/>, option 60 → <see cref="Fields.DhcpVendorClass"/>,
/// option 12/81 → hostname.</item>
/// <item>Server OFFER/ACK: <see cref="INetworkState.AddDhcpServer"/> and <see cref="DeviceFlags.DhcpServer"/>. A server that is
/// neither the gateway nor the adapter's configured DHCP server is a rogue: Warning <see cref="AlertKind.RogueDhcp"/> and
/// <see cref="DeviceFlags.RogueDhcp"/>. OFFERs answering our tagged VLAN probes are never judged rogue.</item>
/// </list>
/// </summary>
public sealed class DhcpMonitor : IFrameHandler
{
    private const string Src = "dhcp";
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private readonly ILogger<DhcpMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly IAlertService _alerts;
    private readonly DiscoveryContext _ctx;
    private readonly DhcpProbeRegistry _registry;
    private readonly ActivityPublisher _activity;

    public DhcpMonitor(ILogger<DhcpMonitor> log, IDeviceStore store, INetworkState network, IAlertService alerts, DiscoveryContext ctx,
        DhcpProbeRegistry registry, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _network = network;
        _alerts = alerts;
        _ctx = ctx;
        _registry = registry;
        _activity = activity;
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound || frame.Eth.EtherType != EthernetView.Ipv4) return;
        try
        {
            if (!DhcpBuilder.TryExtract(frame, out var pkt, out _, out var srcIp)) return;
            if (pkt.IsBootRequest) ApplyClient(pkt, frame.Eth.Source);
            else ApplyServer(pkt, frame.Eth.Source, srcIp, frame.Eth.VlanId);
        }
        catch (Exception ex) { _log.LogDebug(ex, "DHCP frame from {Mac}", frame.Eth.Source); }
    }

    internal Device? ApplyClient(DhcpPacket p, Mac ethSrc)
    {
        var mac = !p.ClientMac.IsZero && !p.ClientMac.IsMulticast ? p.ClientMac : ethSrc;
        if (mac == _ctx.LocalMac) return null;
        _activity.Publish(ethSrc, "DHCP");
        var ciaddr = p.ClientIp.Equals(IPAddress.Any) ? null : p.ClientIp;
        var d = _store.Observe(mac, ciaddr, Src);
        bool ch = false;
        double conf = Confidence.Dhcp;

        ch |= d.AddEvidence(Src, Fields.DhcpFingerprint, p.Fingerprint, conf);
        ch |= d.AddEvidence(Src, Fields.DhcpVendorClass, p.VendorClass, conf);
        var host = p.Hostname;
        var fqdn = p.ClientFqdn;
        if (host is not null)
        {
            ch |= d.SetHostname(Src, host);
            ch |= d.AddEvidence(Src, Fields.Hostname, host, conf);
        }
        else if (fqdn is not null)
        {
            ch |= d.SetHostname(Src, fqdn);
            ch |= d.AddEvidence(Src, Fields.Hostname, fqdn, conf);
        }
        if (fqdn is not null)
        {
            ch |= d.SetProperty("dhcp.fqdn", fqdn);
            int dot = fqdn.IndexOf('.');
            if (dot > 0 && dot < fqdn.Length - 1) ch |= d.AddEvidence(Src, Fields.Domain, fqdn[(dot + 1)..], conf);
        }
        ch |= d.SetProperty("dhcp.fingerprint", p.Fingerprint);
        ch |= d.SetProperty("dhcp.vendorClass", p.VendorClass);
        ch |= d.SetProperty("dhcp.optionOrder", string.Join(",", p.OptionOrder));
        if (p.MaxMessageSize is { } mms) ch |= d.SetProperty("dhcp.maxMessageSize", mms.ToString(Inv));
        ch |= d.SetProperty("dhcp.clientId", p.ClientIdentifier);
        ch |= d.SetProperty("dhcp.userClass", p.UserClass);
        if (p.RequestedIp is { } rq) ch |= d.SetProperty("dhcp.requestedIp", rq.ToString());
        ch |= d.SetProperty("dhcp.lastMessage", p.MessageTypeName);
        if (ch) _store.NotifyChanged(d, Src);
        return d;
    }

    internal DhcpServerInfo? ApplyServer(DhcpPacket p, Mac ethSrc, IPAddress srcIp, int? frameVlan)
    {
        if (p.MessageType is not (DhcpPacket.Offer or DhcpPacket.Ack)) return null;
        _activity.Publish(ethSrc, "DHCP");
        var serverId = p.ServerIdentifier ?? srcIp;
        bool relayed = !p.RelayIp.Equals(IPAddress.Any) && !srcIp.Equals(serverId);

        // A client just got a lease: bind it.
        if (p.MessageType == DhcpPacket.Ack && !p.YourIp.Equals(IPAddress.Any) && !p.ClientMac.IsZero && p.ClientMac != _ctx.LocalMac)
        {
            var client = _store.Observe(p.ClientMac, p.YourIp, Src);
            if (p.LeaseTime is { } lt && client.SetProperty("dhcp.lease", lt.ToString())) _store.NotifyChanged(client, Src);
        }

        bool probeVlan = _registry.TryGet(p.Xid, out var probedVlan) && probedVlan is not null;
        int? nativeVlan = _store.TryGet(_ctx.LocalMac, out var me) ? me.NativeVlan : null;
        bool otherVlan = probeVlan || (frameVlan is { } fv && fv != 0 && fv != nativeVlan);

        var gw = _ctx.Gateway;
        var adapterDhcp = _ctx.AdapterDhcpServer;
        var gwMac = gw is null ? (Mac?)null : _store.FindByIp(gw)?.Mac;
        bool canJudge = gw is not null || adapterDhcp is not null;
        bool legit = (gw is not null && (serverId.Equals(gw) || srcIp.Equals(gw)))
                     || (gwMac is { } gm && gm == ethSrc)
                     || (adapterDhcp is not null && (serverId.Equals(adapterDhcp) || srcIp.Equals(adapterDhcp)));
        bool rogue = canJudge && !legit && !otherVlan;

        var info = new DhcpServerInfo(serverId, ethSrc, p.YourIp.Equals(IPAddress.Any) ? null : p.YourIp, p.Routers.FirstOrDefault(),
            p.DnsServers, p.SubnetMask, p.LeaseTime, DateTimeOffset.Now, rogue);
        _network.AddDhcpServer(info);

        var d = _store.Observe(ethSrc, srcIp, Src);
        bool ch = false;
        if (!relayed && !d.Has(DeviceFlags.DhcpServer)) { d.SetFlag(DeviceFlags.DhcpServer); ch = true; }
        if (relayed) ch |= d.SetProperty("dhcp.relayFor", serverId.ToString());
        ch |= d.SetProperty("dhcp.server", $"{serverId}{(p.SubnetMask is { } m ? $" mask {m}" : "")}{(p.Routers.Count > 0 ? $" router {p.Routers[0]}" : "")}");
        ch |= d.SetProperty("dhcp.domain", p.DomainName);
        if (rogue && !d.Has(DeviceFlags.RogueDhcp)) { d.SetFlag(DeviceFlags.RogueDhcp); ch = true; }
        if (ch) _store.NotifyChanged(d, "dhcp-server");

        if (rogue)
        {
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.RogueDhcp,
                $"Rogue DHCP server {serverId}",
                $"DHCP {p.MessageTypeName} from {serverId} ({ethSrc}) offering {p.YourIp}" +
                $"{(p.Routers.Count > 0 ? $" with router {p.Routers[0]}" : "")}{(p.DnsServers.Count > 0 ? $" and DNS {string.Join(", ", p.DnsServers)}" : "")}. " +
                $"Expected gateway {gw?.ToString() ?? "-"} / configured DHCP server {adapterDhcp?.ToString() ?? "-"}.",
                ethSrc), TimeSpan.FromMinutes(10));
        }
        return info;
    }
}
