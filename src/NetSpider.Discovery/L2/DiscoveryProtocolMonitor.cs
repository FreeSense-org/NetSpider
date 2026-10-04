using System.Globalization;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;
using NetSpider.Discovery.L3;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive LLDP (0x88CC) and CDP (SNAP 00000C/2000) listener. Writes identity evidence, capabilities, VLANs, PoE and link
/// facts to the advertising device and records a <see cref="NeighborEntry"/> (Reporter = advertiser, Neighbor = this host).
/// <para>Device identity: LLDP uses the chassis MAC when the chassis id is a MAC (matching the switch's base/ARP MAC);
/// otherwise, and for CDP, the frame's source MAC. The port MAC is kept as property "srcMac".</para>
/// </summary>
public sealed class DiscoveryProtocolMonitor : IFrameHandler
{
    private const string Lldp = "lldp", Cdp = "cdp";
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private readonly ILogger<DiscoveryProtocolMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly DiscoveryContext _ctx;
    private readonly ActivityPublisher _activity;
    private readonly SubnetDiscoverer _subnets;

    public DiscoveryProtocolMonitor(ILogger<DiscoveryProtocolMonitor> log, IDeviceStore store, INetworkState network, DiscoveryContext ctx,
        ActivityPublisher activity, SubnetDiscoverer subnets)
    {
        _log = log;
        _store = store;
        _network = network;
        _ctx = ctx;
        _activity = activity;
        _subnets = subnets;
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound) return;
        var eth = frame.Eth;
        try
        {
            if (eth.EtherType == EthernetView.Lldp && !eth.IsLlc)
            {
                if (LldpParser.Parse(frame.Payload) is { } l) ApplyLldp(l, eth.Source);
            }
            else if (eth.IsCdp)
            {
                if (CdpParser.Parse(frame.Payload) is { } c) ApplyCdp(c, eth.Source);
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "LLDP/CDP frame from {Mac}", eth.Source); }
    }

    // ================================================================== LLDP

    internal Device? ApplyLldp(LldpInfo l, Mac src)
    {
        _activity.Publish(src, "LLDP");
        if (l.IsShutdown) return null;
        var mac = l.ChassisMac is { } cm && !cm.IsZero && !cm.IsMulticast ? cm : src;
        var local = _ctx.LocalMac;
        if (mac == local || src == local) return null;

        var d = _store.GetOrAdd(mac);
        d.Touch();
        bool ch = false;
        double conf = Confidence.Lldp;

        if (src != mac) ch |= d.SetProperty("srcMac", src.ToString());
        ch |= d.SetProperty("lldp.chassisId", l.ChassisId);
        ch |= d.SetProperty("lldp.chassisIdSubtype", l.ChassisIdSubtype.ToString(Inv));
        ch |= d.SetProperty("lldp.portId", l.PortId);
        ch |= d.SetProperty("lldp.portDescription", l.PortDescription);
        if (l.Ttl is { } ttl) ch |= d.SetProperty("lldp.ttl", ttl.ToString(Inv));

        if (l.SystemName is { } name)
        {
            ch |= d.SetHostname(Lldp, name);
            ch |= d.AddEvidence(Lldp, Fields.Hostname, name, conf);
        }
        ch |= d.AddEvidence(Lldp, Fields.Description, l.SystemDescription, conf);

        // ---- capabilities → type hint ----
        var caps = l.EnabledCapabilities ?? l.SystemCapabilities ?? 0;
        if (l.SystemCapabilities is not null)
        {
            ch |= d.SetProperty("lldp.capabilities", string.Join(",", LldpParser.CapabilityNames(l.SystemCapabilities.Value)));
            ch |= d.SetProperty("lldp.enabledCapabilities", string.Join(",", l.EnabledCapabilityNames));
            ch |= d.AddEvidence(Lldp, Fields.Capabilities, string.Join(",", l.EnabledCapabilityNames), conf);
        }
        var hint = TypeFromLldp(caps, l.MedDeviceClass);
        if (hint is { } h) ch |= DeviceHints.HintType(d, Lldp, h.Type, h.Confidence);
        if ((caps & (LldpParser.CapBridge | LldpParser.CapRouter | LldpParser.CapWlanAp)) != 0 && !d.Has(DeviceFlags.Infrastructure))
        {
            d.SetFlag(DeviceFlags.Infrastructure);
            ch = true;
        }

        // ---- management addresses ----
        foreach (var ip in l.ManagementAddresses)
        {
            ch |= DeviceHints.AddManagementIp(_store, _ctx, d, ip, Lldp);
            _subnets.ConsiderAddress(ip, "lldp-mgmt");
        }
        if (l.ManagementAddresses.Count > 0) ch |= d.SetProperty("lldp.mgmtIp", string.Join(",", l.ManagementAddresses));

        // ---- 802.1 VLANs ----
        if (l.PortVlanId is { } pvid)
        {
            var pname = l.VlanNames.FirstOrDefault(v => v.Vlan == pvid).Name;
            _network.AddVlan(new VlanInfo(pvid, string.IsNullOrEmpty(pname) ? null : pname, Lldp, Native: true, Voice: false));
            ch |= d.AddVlan(pvid);
            if (d.NativeVlan != pvid) { d.NativeVlan = pvid; ch = true; }
            SetLocalNativeVlan(local, pvid);
            ch |= d.SetProperty("lldp.pvid", pvid.ToString(Inv));
        }
        foreach (var (vid, vname) in l.VlanNames)
        {
            _network.AddVlan(new VlanInfo(vid, string.IsNullOrEmpty(vname) ? null : vname, Lldp, Native: false, Voice: false));
            ch |= d.AddVlan(vid);
        }
        foreach (var (vid, _, enabled) in l.ProtocolVlans)
        {
            if (!enabled || vid <= 0) continue;
            _network.AddVlan(new VlanInfo(vid, null, Lldp, Native: false, Voice: false));
            ch |= d.AddVlan(vid);
        }
        if (l.VoiceVlan is { } voice)
        {
            _network.AddVlan(new VlanInfo(voice, null, "lldp-med", Native: false, Voice: true));
            ch |= d.AddVlan(voice);
            ch |= d.SetProperty("voiceVlan", voice.ToString(Inv));
        }
        foreach (var pol in l.NetworkPolicies)
            ch |= d.SetProperty($"lldp.med.policy.{pol.AppName}", pol.UnknownPolicy ? "unknown" : $"vlan {pol.VlanId}{(pol.Tagged ? " tagged" : " untagged")}, L2 prio {pol.Priority}, DSCP {pol.Dscp}");

        // ---- 802.3 link facts ----
        if (l.SpeedMbps is { } speed) ch |= d.SetProperty("lldp.port.speedMbps", speed.ToString(Inv));
        if (l.Duplex is { } duplex) ch |= d.SetProperty("lldp.port.duplex", duplex);
        if (l.MauType is { } mau) ch |= d.SetProperty("lldp.port.mauType", mau.ToString(Inv));
        if (l.AutonegSupported is { } ans) ch |= d.SetProperty("lldp.port.autoneg", ans ? (l.AutonegEnabled == true ? "enabled" : "supported, disabled") : "not supported");
        if (l.MaxFrameSize is { } mfs) ch |= d.SetProperty("lldp.port.maxFrameSize", mfs.ToString(Inv));
        if (l.LagCapable is { } lagc) ch |= d.SetProperty("lldp.port.linkAggregation", l.LagEnabled == true ? $"aggregated (port {l.LagPortId})" : lagc ? "capable" : "not capable");
        if (l.PoePortClass is { } pclass)
        {
            ch |= d.SetProperty("poe.portClass", pclass);
            ch |= d.SetProperty("poe.supported", l.PoeSupported == true ? "yes" : "no");
            if (l.PoeClass is { } pc) ch |= d.SetProperty("poe.class", pc.ToString(Inv));
            if (l.PoeType is { } pt) ch |= d.SetProperty("poe.type", pt);
            if (l.PoeAllocatedWatts is { } aw) ch |= d.SetProperty("poe.allocatedW", aw.ToString("0.0", Inv));
            if (l.PoeRequestedWatts is { } rw) ch |= d.SetProperty("poe.requestedW", rw.ToString("0.0", Inv));
        }
        if (l.MedPowerWatts is { } mw)
        {
            ch |= d.SetProperty("poe.medPowerW", mw.ToString("0.0", Inv));
            ch |= d.SetProperty("poe.medPowerType", l.MedPowerType);
            ch |= d.SetProperty("poe.medPowerSource", l.MedPowerSource);
        }
        if ((l.PoePortClass == "PD" || l.MedPowerType == "PD") && !d.Has(DeviceFlags.PoePowered)) { d.SetFlag(DeviceFlags.PoePowered); ch = true; }

        // ---- LLDP-MED inventory ----
        ch |= d.SetProperty("lldp.med.deviceClass", l.MedDeviceClassName);
        ch |= d.AddEvidence(Lldp, Fields.Brand, l.Manufacturer, conf);
        ch |= d.AddEvidence(Lldp, Fields.Model, l.ModelName, conf);
        ch |= d.AddEvidence(Lldp, Fields.Firmware, l.SoftwareRevision ?? l.FirmwareRevision, conf);
        ch |= d.AddEvidence(Lldp, Fields.Serial, l.SerialNumber, conf);
        ch |= d.SetProperty("lldp.med.hardwareRevision", l.HardwareRevision);
        ch |= d.SetProperty("lldp.med.firmwareRevision", l.FirmwareRevision);
        ch |= d.SetProperty("lldp.med.softwareRevision", l.SoftwareRevision);
        ch |= d.SetProperty("lldp.med.assetId", l.AssetId);
        ch |= d.SetProperty("lldp.med.location", l.Location);

        _network.AddNeighbor(new NeighborEntry(
            Reporter: mac, ReporterPort: l.DisplayPort,
            NeighborMac: local, NeighborChassisId: local.ToString(), NeighborPort: null, NeighborName: Environment.MachineName,
            NeighborMgmtIp: _ctx.LocalIPv4, NeighborDescription: l.PortDescription, NeighborCapabilities: "Station",
            Protocol: "LLDP", Seen: DateTimeOffset.Now));

        if (ch) _store.NotifyChanged(d, Lldp);
        return d;
    }

    internal static (DeviceType Type, double Confidence)? TypeFromLldp(ushort caps, int? medClass)
    {
        if ((caps & LldpParser.CapTelephone) != 0 || medClass == 3) return (DeviceType.VoipPhone, 0.9);
        if ((caps & LldpParser.CapWlanAp) != 0) return (DeviceType.AccessPoint, 0.85);
        bool bridge = (caps & LldpParser.CapBridge) != 0, router = (caps & LldpParser.CapRouter) != 0;
        if (bridge && router) return (DeviceType.CoreSwitch, 0.6);
        if (bridge) return (DeviceType.AccessSwitch, 0.8);
        if (router) return (DeviceType.Router, 0.8);
        if ((caps & LldpParser.CapDocsis) != 0) return (DeviceType.Router, 0.6);
        return null;
    }

    // ================================================================== CDP

    internal Device? ApplyCdp(CdpInfo c, Mac src)
    {
        _activity.Publish(src, "CDP");
        var local = _ctx.LocalMac;
        if (src == local || src.IsMulticast || src.IsZero) return null;
        var d = _store.GetOrAdd(src);
        d.Touch();
        bool ch = false;
        double conf = Confidence.Lldp;

        ch |= d.SetProperty("cdp.version", c.Version.ToString(Inv));
        ch |= d.SetProperty("cdp.portId", c.PortId);
        if (c.DeviceId is { } id)
        {
            ch |= d.SetHostname(Cdp, id);
            ch |= d.AddEvidence(Cdp, Fields.Hostname, id, conf);
        }
        if (c.SystemName is { } sn) ch |= d.SetProperty("cdp.systemName", sn);

        if (c.Platform is { } platform)
        {
            ch |= d.SetProperty("cdp.platform", platform);
            var model = platform;
            if (platform.StartsWith("cisco ", StringComparison.OrdinalIgnoreCase))
            {
                model = platform[6..].Trim();
                ch |= d.AddEvidence(Cdp, Fields.Brand, "Cisco", 0.9);
            }
            ch |= d.AddEvidence(Cdp, Fields.Model, model, conf);
        }
        if (c.SoftwareVersion is { } sw)
        {
            ch |= d.AddEvidence(Cdp, Fields.Description, sw, conf);
            ch |= d.AddEvidence(Cdp, Fields.Firmware, c.SoftwareVersionShort, conf);
            ch |= d.AddEvidence(Cdp, Fields.Os, sw.Contains("IOS", StringComparison.OrdinalIgnoreCase) ? c.SoftwareVersionShort : null, conf);
        }
        if (c.Capabilities is { } caps)
        {
            var capText = string.Join(",", c.CapabilityNames);
            ch |= d.SetProperty("cdp.capabilities", capText);
            ch |= d.AddEvidence(Cdp, Fields.Capabilities, capText, conf);
            if (TypeFromCdp(caps) is { } h) ch |= DeviceHints.HintType(d, Cdp, h.Type, h.Confidence);
            if ((caps & (CdpInfo.CapRouter | CdpInfo.CapSwitch | CdpInfo.CapTransBridge | CdpInfo.CapSrBridge)) != 0 && !d.Has(DeviceFlags.Infrastructure))
            {
                d.SetFlag(DeviceFlags.Infrastructure);
                ch = true;
            }
        }

        foreach (var ip in c.Addresses.Concat(c.ManagementAddresses).Distinct())
        {
            ch |= DeviceHints.AddManagementIp(_store, _ctx, d, ip, Cdp);
            _subnets.ConsiderAddress(ip, "cdp-mgmt");
        }
        if (c.Addresses.Count > 0) ch |= d.SetProperty("cdp.addresses", string.Join(",", c.Addresses));
        if (c.IpPrefixes.Count > 0) ch |= d.SetProperty("cdp.ipPrefixes", string.Join(",", c.IpPrefixes));

        if (c.VtpDomain is { } vtp)
        {
            ch |= d.SetProperty("vtp.domain", vtp);
            ch |= d.AddEvidence(Cdp, Fields.Domain, vtp, 0.5);
        }
        if (c.NativeVlan is { } nv && nv > 0)
        {
            _network.AddVlan(new VlanInfo(nv, null, Cdp, Native: true, Voice: false));
            ch |= d.AddVlan(nv);
            if (d.NativeVlan != nv) { d.NativeVlan = nv; ch = true; }
            SetLocalNativeVlan(local, nv);
        }
        if (c.VoiceVlan is { } vv && vv is > 0 and < 4095)
        {
            _network.AddVlan(new VlanInfo(vv, null, Cdp, Native: false, Voice: true));
            ch |= d.AddVlan(vv);
            ch |= d.SetProperty("voiceVlan", vv.ToString(Inv));
        }
        if (c.FullDuplex is { } fd) ch |= d.SetProperty("cdp.port.duplex", fd ? "full" : "half");
        if (c.PowerMilliwatts is { } mw) ch |= d.SetProperty("poe.consumptionW", (mw / 1000.0).ToString("0.0", Inv));
        if (c.PowerAvailableMilliwatts is { } pa) ch |= d.SetProperty("poe.availableW", (pa / 1000.0).ToString("0.0", Inv));
        if (c.Mtu is { } mtu) ch |= d.SetProperty("cdp.mtu", mtu.ToString(Inv));
        ch |= d.SetProperty("cdp.location", c.Location);

        _network.AddNeighbor(new NeighborEntry(
            Reporter: src, ReporterPort: c.PortId,
            NeighborMac: local, NeighborChassisId: local.ToString(), NeighborPort: null, NeighborName: Environment.MachineName,
            NeighborMgmtIp: _ctx.LocalIPv4, NeighborDescription: null, NeighborCapabilities: "Host",
            Protocol: "CDP", Seen: DateTimeOffset.Now));

        if (ch) _store.NotifyChanged(d, Cdp);
        return d;
    }

    /// <summary>The advertised port VLAN is the access VLAN this host sits in.</summary>
    private void SetLocalNativeVlan(Mac local, int vlan)
    {
        if (local.IsZero) return;
        var me = _store.GetOrAdd(local);
        if (me.NativeVlan == vlan) return;
        me.NativeVlan = vlan;
        me.AddVlan(vlan);
        _store.NotifyChanged(me, "native-vlan");
    }

    internal static (DeviceType Type, double Confidence)? TypeFromCdp(uint caps)
    {
        if ((caps & CdpInfo.CapPhone) != 0) return (DeviceType.VoipPhone, 0.9);
        bool sw = (caps & CdpInfo.CapSwitch) != 0, router = (caps & CdpInfo.CapRouter) != 0;
        if (sw && router) return (DeviceType.CoreSwitch, 0.6);
        if (sw) return (DeviceType.AccessSwitch, 0.8);
        if (router) return (DeviceType.Router, 0.8);
        if ((caps & CdpInfo.CapTransBridge) != 0) return (DeviceType.AccessPoint, 0.5);
        return null;
    }
}
