using System.Globalization;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive listener for the remaining L2 signals: DTP and VTP (Cisco trunking/VLAN domain), 802.1Q tags on any frame
/// (proves the NIC passes tags and reveals VLAN ids), LACP and EAPOL (802.1X). DTP/VTP/LACP/EAPOL only write properties.
/// </summary>
public sealed class L2SignalMonitor : IFrameHandler
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private readonly ILogger<L2SignalMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly DiscoveryContext _ctx;
    private readonly ActivityPublisher _activity;
    private readonly HashSet<int> _seenVlans = new();
    private readonly HashSet<(Mac, int)> _seenDeviceVlans = new();
    private volatile bool _tagsSeen;

    public L2SignalMonitor(ILogger<L2SignalMonitor> log, IDeviceStore store, INetworkState network, DiscoveryContext ctx, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _network = network;
        _ctx = ctx;
        _activity = activity;
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound) return;
        var eth = frame.Eth;
        if (!eth.Valid) return;
        try
        {
            if (eth.VlanId is { } vid) OnTagged(eth.Source, vid, eth.OuterVlanId);
            if (eth.IsDtp) { if (L2SignalParsers.ParseDtp(frame.Payload) is { } dtp) ApplyDtp(dtp, eth.Source); }
            else if (eth.IsVtp) { if (L2SignalParsers.ParseVtp(frame.Payload) is { } vtp) ApplyVtp(vtp, eth.Source); }
            else if (eth.EtherType == EthernetView.Slow && !eth.IsLlc) { if (L2SignalParsers.ParseLacp(frame.Payload) is { } lacp) ApplyLacp(lacp, eth.Source); }
            else if (eth.EtherType == EthernetView.Eapol && !eth.IsLlc) { if (L2SignalParsers.ParseEapol(frame.Payload) is { } eap) ApplyEapol(eap, eth.Source); }
        }
        catch (Exception ex) { _log.LogDebug(ex, "L2 signal frame from {Mac}", eth.Source); }
    }

    internal void OnTagged(Mac src, int vid, int? outer)
    {
        if (!_tagsSeen)
        {
            _tagsSeen = true;
            if (_network.NicPassesVlanTags != true) _network.NicPassesVlanTags = true;
            _log.LogInformation("802.1Q tagged frames are visible: the NIC passes VLAN tags");
        }
        int[] vids = outer is { } o ? [vid, o] : [vid];
        foreach (var v in vids)
        {
            if (v is <= 0 or >= 4095) continue; // VLAN 0 = priority tag only
            bool newVlan;
            lock (_seenVlans) newVlan = _seenVlans.Add(v);
            if (newVlan) _network.AddVlan(new VlanInfo(v, null, "802.1Q", Native: false, Voice: false));
            if (src.IsMulticast || src.IsZero) continue;
            bool newPair;
            lock (_seenDeviceVlans)
            {
                if (_seenDeviceVlans.Count > 100_000) _seenDeviceVlans.Clear();
                newPair = _seenDeviceVlans.Add((src, v));
            }
            if (newPair)
            {
                var d = _store.GetOrAdd(src);
                if (d.AddVlan(v)) _store.NotifyChanged(d, "vlan");
            }
        }
    }

    internal void ApplyDtp(DtpInfo dtp, Mac src)
    {
        _activity.Publish(src, "DTP");
        var d = Get(src);
        bool ch = !d.Has(DeviceFlags.Infrastructure);
        d.SetFlag(DeviceFlags.Infrastructure);
        ch |= d.SetProperty("dtp.domain", dtp.Domain);
        if (dtp.Trunking is { } t) ch |= d.SetProperty("dtp.trunkStatus", t ? "trunk" : "access");
        ch |= d.SetProperty("dtp.adminMode", dtp.AdminMode);
        ch |= d.SetProperty("dtp.encapsulation", dtp.Encapsulation);
        if (dtp.AdminMode is "desirable" or "auto")
            ch |= d.SetProperty("dtp.risk", "Port negotiates trunking (DTP " + dtp.AdminMode + "): a host could form a trunk (VLAN hopping)");
        if (ch) _store.NotifyChanged(d, "dtp");
    }

    internal void ApplyVtp(VtpInfo vtp, Mac src)
    {
        _activity.Publish(src, "VTP");
        var d = Get(src);
        bool ch = !d.Has(DeviceFlags.Infrastructure);
        d.SetFlag(DeviceFlags.Infrastructure);
        ch |= d.SetProperty("vtp.domain", vtp.Domain);
        ch |= d.SetProperty("vtp.version", vtp.Version.ToString(Inv));
        if (vtp.ConfigRevision is { } rev) ch |= d.SetProperty("vtp.revision", rev.ToString(Inv));
        if (vtp.Updater is { } up && !up.Equals(System.Net.IPAddress.Any)) ch |= d.SetProperty("vtp.updater", up.ToString());
        ch |= d.AddEvidence("vtp", Fields.Domain, vtp.Domain, 0.5);
        foreach (var (id, name, _) in vtp.Vlans)
        {
            if (id is <= 0 or >= 4095) continue;
            _network.AddVlan(new VlanInfo(id, string.IsNullOrEmpty(name) ? null : name, "vtp", Native: false, Voice: false));
        }
        if (ch) _store.NotifyChanged(d, "vtp");
    }

    internal void ApplyLacp(LacpInfo lacp, Mac src)
    {
        _activity.Publish(src, "LACP");
        var d = Get(src);
        bool ch = false;
        ch |= d.SetProperty("lacp.actorSystem", $"{lacp.ActorSystemPriority}/{lacp.ActorSystem}");
        ch |= d.SetProperty("lacp.actorKey", lacp.ActorKey.ToString(Inv));
        ch |= d.SetProperty("lacp.actorPort", lacp.ActorPort.ToString(Inv));
        ch |= d.SetProperty("lacp.state", lacp.StateText);
        if (!lacp.PartnerSystem.IsZero) ch |= d.SetProperty("lacp.partner", $"{lacp.PartnerSystem} key {lacp.PartnerKey} port {lacp.PartnerPort}");
        ch |= d.SetProperty("802.3ad", "LACP present");
        if (ch) _store.NotifyChanged(d, "lacp");
    }

    internal void ApplyEapol(EapolInfo eap, Mac src)
    {
        _activity.Publish(src, "EAPOL");
        var d = Get(src);
        bool ch = d.SetProperty("802.1X", "802.1X present");
        ch |= d.SetProperty("eapol.last", eap.TypeName + (eap.EapCode is { } c ? $" (EAP code {c}{(eap.EapType is { } t ? $", type {t}" : "")})" : ""));
        if (eap.IsAuthenticatorRequest) ch |= d.SetProperty("802.1X.role", "authenticator");
        if (ch) _store.NotifyChanged(d, "eapol");
        var local = _ctx.LocalMac;
        if (!local.IsZero && eap.IsAuthenticatorRequest)
        {
            var me = _store.GetOrAdd(local);
            if (me.SetProperty("802.1X", "802.1X present (port authentication requested)")) _store.NotifyChanged(me, "eapol");
        }
    }

    private Device Get(Mac mac)
    {
        var d = _store.GetOrAdd(mac);
        d.Touch();
        return d;
    }
}
