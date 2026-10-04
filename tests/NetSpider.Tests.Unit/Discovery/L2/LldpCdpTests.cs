using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class LldpCdpTests
{
    private static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    private static readonly Mac ChassisMac = Mac.Parse("00:1B:54:AA:BB:00");
    private static readonly Mac PortMac = Mac.Parse("00:1B:54:AA:BB:05");

    /// <summary>A Catalyst-style LLDPDU with basic, 802.1, 802.3 and LLDP-MED TLVs (hand-assembled per IEEE 802.1AB / TIA-1057).</summary>
    public static byte[] SwitchLldpdu() =>
    [
        .. Hex("02 07 04 00 1b 54 aa bb 00"),                       // chassis id: MAC
        .. Hex("04 08 05"), .. A("Gi1/0/5"),                        // port id: interface name
        .. Hex("06 02 00 78"),                                      // TTL 120
        .. Hex("08 14"), .. A("GigabitEthernet1/0/5"),              // port description
        .. Hex("0a 0c"), .. A("sw-access-01"),                      // system name
        .. Hex("0c 23"), .. A("Cisco IOS Software, C2960X Software"),// system description (35)
        .. Hex("0e 04 00 14 00 04"),                                // caps: bridge+router, enabled bridge
        .. Hex("10 0c 05 01 0a 00 00 02 02 00 00 00 01 00"),        // mgmt address 10.0.0.2, ifIndex 1
        .. Hex("fe 06 00 80 c2 01 00 0a"),                          // 802.1 port VLAN id 10
        .. Hex("fe 07 00 80 c2 02 06 00 0a"),                       // 802.1 port & protocol VLAN 10 (supported, enabled)
        .. Hex("fe 0c 00 80 c2 03 00 0a 05"), .. A("USERS"),        // 802.1 VLAN name 10 = USERS
        .. Hex("fe 09 00 12 0f 01 03 6c 03 00 1e"),                 // 802.3 MAC/PHY: autoneg on, MAU 30 = 1000BASE-T FD
        .. Hex("fe 0c 00 12 0f 02 07 01 05 11 00 82 00 96"),        // 802.3 power via MDI: PSE, class 4, req 13.0 W, alloc 15.0 W
        .. Hex("fe 09 00 12 0f 03 01 00 00 00 00"),                 // 802.3 link aggregation: capable, not aggregated
        .. Hex("fe 06 00 12 0f 04 05 f2"),                          // 802.3 max frame size 1522
        .. Hex("fe 07 00 12 bb 01 00 3f 04"),                       // MED capabilities, class Network Connectivity
        .. Hex("fe 08 00 12 bb 02 01 40 29 6e"),                    // MED network policy: voice, tagged, VLAN 20, prio 5, DSCP 46
        .. Hex("fe 0d 00 12 bb 07"), .. A("15.2(7)E3"),             // MED software revision
        .. Hex("fe 0f 00 12 bb 08"), .. A("FOC1234X0AB"),           // MED serial
        .. Hex("fe 09 00 12 bb 09"), .. A("Cisco"),                 // MED manufacturer
        .. Hex("fe 14 00 12 bb 0a"), .. A("WS-C2960X-24PS-L"),      // MED model
        .. Hex("00 00"),                                            // end
    ];

    [Fact]
    public void Lldp_parses_all_tlv_families()
    {
        var l = LldpParser.Parse(SwitchLldpdu());
        Assert.NotNull(l);
        Assert.Equal(4, l.ChassisIdSubtype);
        Assert.Equal(ChassisMac, l.ChassisMac);
        Assert.Equal("Gi1/0/5", l.PortId);
        Assert.Equal(5, l.PortIdSubtype);
        Assert.Equal(120, l.Ttl);
        Assert.Equal("GigabitEthernet1/0/5", l.PortDescription);
        Assert.Equal("sw-access-01", l.SystemName);
        Assert.Equal("Cisco IOS Software, C2960X Software", l.SystemDescription);
        Assert.Equal((ushort)0x14, l.SystemCapabilities);
        Assert.Equal(["Bridge"], l.EnabledCapabilityNames);
        Assert.Equal([IPAddress.Parse("10.0.0.2")], l.ManagementAddresses);

        Assert.Equal(10, l.PortVlanId);
        Assert.Contains((10, true, true), l.ProtocolVlans);
        Assert.Contains((10, "USERS"), l.VlanNames);

        Assert.True(l.AutonegSupported);
        Assert.True(l.AutonegEnabled);
        Assert.Equal(30, l.MauType);
        Assert.Equal(1000, l.SpeedMbps);
        Assert.Equal("full", l.Duplex);
        Assert.Equal("PSE", l.PoePortClass);
        Assert.True(l.PoeSupported);
        Assert.True(l.PoeEnabled);
        Assert.Equal(4, l.PoeClass);
        Assert.Equal("Type 2 PSE", l.PoeType);
        Assert.Equal(13.0, l.PoeRequestedWatts);
        Assert.Equal(15.0, l.PoeAllocatedWatts);
        Assert.True(l.LagCapable);
        Assert.False(l.LagEnabled);
        Assert.Equal(1522, l.MaxFrameSize);

        Assert.Equal(4, l.MedDeviceClass);
        Assert.Equal("Network Connectivity", l.MedDeviceClassName);
        var voice = Assert.Single(l.NetworkPolicies);
        Assert.Equal("Voice", voice.AppName);
        Assert.True(voice.Tagged);
        Assert.False(voice.UnknownPolicy);
        Assert.Equal(20, voice.VlanId);
        Assert.Equal(5, voice.Priority);
        Assert.Equal(46, voice.Dscp);
        Assert.Equal(20, l.VoiceVlan);
        Assert.Equal("15.2(7)E3", l.SoftwareRevision);
        Assert.Equal("FOC1234X0AB", l.SerialNumber);
        Assert.Equal("Cisco", l.Manufacturer);
        Assert.Equal("WS-C2960X-24PS-L", l.ModelName);
        Assert.Empty(l.UnknownTlvs);
    }

    [Fact]
    public void Lldp_truncated_frame_does_not_throw()
    {
        var full = SwitchLldpdu();
        for (int cut = 0; cut < full.Length; cut += 7)
        {
            var l = LldpParser.Parse(full.AsSpan(0, cut));
            if (cut >= 9) Assert.NotNull(l);
        }
    }

    [Theory]
    [InlineData(16, 100L, "full")]
    [InlineData(15, 100L, "half")]
    [InlineData(11, 10L, "full")]
    [InlineData(30, 1000L, "full")]
    [InlineData(54, 10000L, "full")]
    public void Mau_types_map_to_speed(int mau, long speed, string duplex)
    {
        var (s, d) = LldpParser.MauTypeToSpeed(mau);
        Assert.Equal(speed, s);
        Assert.Equal(duplex, d);
    }

    [Fact]
    public void Lldp_monitor_writes_device_vlans_neighbor_and_mgmt_subnet()
    {
        var kit = new L2TestKit();
        var mon = new DiscoveryProtocolMonitor(NullLogger<DiscoveryProtocolMonitor>.Instance, kit.Store, kit.Network, kit.Ctx, kit.Activity, kit.Subnets);
        var frame = Eth(Mac.Parse("01:80:C2:00:00:0E"), PortMac, EthernetView.Lldp, SwitchLldpdu());
        var activity = new List<PacketActivity>();
        using var sub = kit.Bus.Subscribe<PacketActivity>(activity.Add);

        mon.OnFrame(Frame(frame));

        Assert.True(kit.Store.TryGet(ChassisMac, out var d));
        Assert.False(kit.Store.TryGet(PortMac, out _));
        Assert.Equal("sw-access-01", d.Hostname);
        Assert.Equal(DeviceType.AccessSwitch, d.Type);
        Assert.True(d.Has(DeviceFlags.Infrastructure));
        Assert.Equal(10, d.NativeVlan);
        Assert.Contains(10, d.Vlans);
        Assert.Contains(20, d.Vlans);
        Assert.Equal(PortMac.ToString(), d.GetProperty("srcMac"));
        Assert.Equal("1000", d.GetProperty("lldp.port.speedMbps"));
        Assert.Equal("full", d.GetProperty("lldp.port.duplex"));
        Assert.Equal("15.0", d.GetProperty("poe.allocatedW"));
        Assert.Equal("20", d.GetProperty("voiceVlan"));

        var ev = d.Evidence;
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Hostname && e.Value == "sw-access-01" && e.Confidence == Confidence.Lldp);
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Model && e.Value == "WS-C2960X-24PS-L");
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Brand && e.Value == "Cisco");
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Serial && e.Value == "FOC1234X0AB");
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Firmware && e.Value == "15.2(7)E3");
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.DeviceType && e.Value == nameof(DeviceType.AccessSwitch));
        Assert.Contains(ev, e => e.Source == "lldp" && e.Field == Fields.Description);

        // off-subnet management IP is indexed and its /24 becomes a candidate segment
        Assert.Same(d, kit.Store.FindByIp(IPAddress.Parse("10.0.0.2")));
        Assert.Contains(kit.Network.Segments, s => s.Cidr == "10.0.0.0/24" && s.Source == "lldp-mgmt" && !s.IsLocal);

        var vlans = kit.Network.Vlans;
        Assert.Contains(vlans, v => v.Id == 10 && v.Native && v.Name == "USERS");
        Assert.Contains(vlans, v => v.Id == 20 && v.Voice);

        var n = Assert.Single(kit.Network.Neighbors);
        Assert.Equal(ChassisMac, n.Reporter);
        Assert.Equal("Gi1/0/5", n.ReporterPort);
        Assert.Equal(LocalMac, n.NeighborMac);
        Assert.Equal("LLDP", n.Protocol);

        Assert.True(kit.Store.TryGet(LocalMac, out var me));
        Assert.Equal(10, me.NativeVlan);
        Assert.Contains(activity, a => a.Source == PortMac && a.Protocol == "LLDP");
    }

    [Fact]
    public void Lldp_phone_gets_voip_type_and_poe_flag()
    {
        byte[] phone =
        [
            .. Hex("02 07 04 00 04 f2 11 22 33"),
            .. Hex("04 07 03 00 04 f2 11 22 33"),                    // port id: MAC subtype
            .. Hex("06 02 00 b4"),
            .. Hex("0a 0b"), .. A("SEP0004F211"),
            .. Hex("0e 04 00 24 00 24"),                            // bridge + telephone
            .. Hex("fe 07 00 12 bb 01 00 33 03"),                   // MED class III
            .. Hex("fe 07 00 12 bb 04 51 00 41"),                   // ext power: PD, primary, 6.5 W
            .. Hex("00 00"),
        ];
        var kit = new L2TestKit();
        var mon = new DiscoveryProtocolMonitor(NullLogger<DiscoveryProtocolMonitor>.Instance, kit.Store, kit.Network, kit.Ctx, kit.Activity, kit.Subnets);
        var d = mon.ApplyLldp(LldpParser.Parse(phone)!, Mac.Parse("00:04:F2:11:22:33"));
        Assert.NotNull(d);
        Assert.Equal(DeviceType.VoipPhone, d.Type);
        Assert.True(d.Has(DeviceFlags.PoePowered));
        Assert.Equal("6.5", d.GetProperty("poe.medPowerW"));
        Assert.Equal("PD", d.GetProperty("poe.medPowerType"));
    }

    // ----------------------------------------------------------------------------------------------- CDP

    private static byte[] CdpTlv(int type, byte[] value) => [(byte)(type >> 8), (byte)type, (byte)((value.Length + 4) >> 8), (byte)(value.Length + 4), .. value];

    public static byte[] SwitchCdp() =>
    [
        0x02, 0xB4, 0x00, 0x00,                                     // version 2, TTL 180, checksum (not verified)
        .. CdpTlv(0x0001, A("core-sw.corp.local")),
        .. CdpTlv(0x0002, Hex("00 00 00 01 01 01 cc 00 04 0a 00 00 01")),
        .. CdpTlv(0x0003, A("GigabitEthernet1/0/24")),
        .. CdpTlv(0x0004, Hex("00 00 00 29")),                       // router + switch + IGMP
        .. CdpTlv(0x0005, A("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.0(2)SE11\nTechnical Support: http://www.cisco.com/techsupport")),
        .. CdpTlv(0x0006, A("cisco WS-C3750X-48P")),
        .. CdpTlv(0x0009, A("CORP")),
        .. CdpTlv(0x000A, Hex("00 01")),
        .. CdpTlv(0x000B, Hex("01")),
        .. CdpTlv(0x000E, Hex("01 00 64")),                          // appliance (voice) VLAN 100
        .. CdpTlv(0x0011, Hex("00 00 05 dc")),
        .. CdpTlv(0x0014, A("core-sw")),
        .. CdpTlv(0x0016, Hex("00 00 00 01 01 01 cc 00 04 0a 00 00 01")),
    ];

    [Fact]
    public void Cdp_parses_v2_tlvs()
    {
        var c = CdpParser.Parse(SwitchCdp());
        Assert.NotNull(c);
        Assert.Equal(2, c.Version);
        Assert.Equal(180, c.Ttl);
        Assert.Equal("core-sw.corp.local", c.DeviceId);
        Assert.Equal([IPAddress.Parse("10.0.0.1")], c.Addresses);
        Assert.Equal([IPAddress.Parse("10.0.0.1")], c.ManagementAddresses);
        Assert.Equal("GigabitEthernet1/0/24", c.PortId);
        Assert.Equal(["Router", "Switch", "IGMP"], c.CapabilityNames);
        Assert.Equal("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.0(2)SE11", c.SoftwareVersionShort);
        Assert.Equal("cisco WS-C3750X-48P", c.Platform);
        Assert.Equal("CORP", c.VtpDomain);
        Assert.Equal(1, c.NativeVlan);
        Assert.True(c.FullDuplex);
        Assert.Equal(100, c.VoiceVlan);
        Assert.Equal(1500, c.Mtu);
        Assert.Equal("core-sw", c.SystemName);
    }

    [Fact]
    public void Cdp_monitor_writes_identity_and_vlans_via_snap_frame()
    {
        var kit = new L2TestKit();
        var mon = new DiscoveryProtocolMonitor(NullLogger<DiscoveryProtocolMonitor>.Instance, kit.Store, kit.Network, kit.Ctx, kit.Activity, kit.Subnets);
        var src = Mac.Parse("00:24:13:AB:CD:18");
        var frame = Llc(Mac.Parse("01:00:0C:CC:CC:CC"), src, Snap(0x00000C, 0x2000, SwitchCdp()));
        var f = Frame(frame);
        Assert.True(f.Eth.IsCdp);

        mon.OnFrame(f);

        Assert.True(kit.Store.TryGet(src, out var d));
        Assert.Equal("core-sw.corp.local", d.Hostname);
        Assert.Equal(DeviceType.CoreSwitch, d.Type);
        Assert.True(d.Has(DeviceFlags.Infrastructure));
        Assert.Equal(1, d.NativeVlan);
        Assert.Contains(100, d.Vlans);
        Assert.Equal("CORP", d.GetProperty("vtp.domain"));
        Assert.Equal("full", d.GetProperty("cdp.port.duplex"));
        var ev = d.Evidence;
        Assert.Contains(ev, e => e.Source == "cdp" && e.Field == Fields.Brand && e.Value == "Cisco");
        Assert.Contains(ev, e => e.Source == "cdp" && e.Field == Fields.Model && e.Value == "WS-C3750X-48P");
        Assert.Contains(ev, e => e.Source == "cdp" && e.Field == Fields.Firmware && e.Value!.Contains("15.0(2)SE11"));
        Assert.Contains(ev, e => e.Source == "cdp" && e.Field == Fields.Domain && e.Value == "CORP");
        Assert.Contains(kit.Network.Vlans, v => v.Id == 100 && v.Voice);
        Assert.Contains(kit.Network.Vlans, v => v.Id == 1 && v.Native);
        var n = Assert.Single(kit.Network.Neighbors);
        Assert.Equal(src, n.Reporter);
        Assert.Equal("GigabitEthernet1/0/24", n.ReporterPort);
        Assert.Equal("CDP", n.Protocol);
    }

    [Fact]
    public void Cdp_garbage_returns_null_or_partial_without_throwing()
    {
        Assert.Null(CdpParser.Parse(Hex("07 b4 00 00")));
        var partial = CdpParser.Parse([.. SwitchCdp().AsSpan(0, 40)]);
        Assert.NotNull(partial);
        Assert.Equal("core-sw.corp.local", partial.DeviceId);
    }
}
