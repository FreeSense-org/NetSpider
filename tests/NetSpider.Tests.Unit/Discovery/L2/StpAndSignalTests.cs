using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class StpAndSignalTests
{
    private static readonly Mac StpDst = Mac.Parse("01:80:C2:00:00:00");

    // RSTP BPDU: designated port, root 8000.00:1c:0e:87:78:00 cost 4, bridge 8000.00:1c:0e:87:85:00, port 0x8004.
    private const string Rstp = "00 00 02 02 3c 80 00 00 1c 0e 87 78 00 00 00 00 04 80 00 00 1c 0e 87 85 00 80 04 01 00 14 00 02 00 0f 00 00";
    // 802.1D config BPDU from the root itself (priority 32769 = 32768 + VLAN 1) with the TC flag set.
    private const string StpRootTc = "00 00 00 00 01 80 01 00 11 22 33 44 55 00 00 00 00 80 01 00 11 22 33 44 55 80 02 00 00 14 00 02 00 0f 00";

    [Fact]
    public void Rstp_bpdu_parses()
    {
        var b = StpParser.Parse(Hex(Rstp));
        Assert.NotNull(b);
        Assert.Equal("RSTP", b.Protocol);
        Assert.Equal("Designated", b.PortRole);
        Assert.Equal(32768, b.RootPriority);
        Assert.Equal(Mac.Parse("00:1C:0E:87:78:00"), b.RootMac);
        Assert.Equal(4, b.RootPathCost);
        Assert.Equal(Mac.Parse("00:1C:0E:87:85:00"), b.BridgeMac);
        Assert.Equal(0x8004, b.PortId);
        Assert.Equal(1.0, b.MessageAge);
        Assert.Equal(20.0, b.MaxAge);
        Assert.Equal(2.0, b.HelloTime);
        Assert.Equal(15.0, b.ForwardDelay);
        Assert.False(b.TopologyChange);
        Assert.False(b.IsRoot);
        Assert.Equal("32768.00:1C:0E:87:78:00", b.RootId);
    }

    [Fact]
    public void Stp_config_bpdu_from_root_with_tc()
    {
        var b = StpParser.Parse(Hex(StpRootTc))!;
        Assert.Equal("STP", b.Protocol);
        Assert.True(b.TopologyChange);
        Assert.True(b.IsRoot);
        Assert.Equal(32769, b.RootPriority);
        Assert.Null(b.PortRole);
    }

    [Fact]
    public void Tcn_bpdu_parses()
    {
        var b = StpParser.Parse(Hex("00 00 00 80"))!;
        Assert.True(b.IsTcn);
        Assert.True(b.TopologyChange);
    }

    [Fact]
    public void Pvst_bpdu_carries_originating_vlan()
    {
        var b = StpParser.Parse(Hex(Rstp + " 00 00 00 02 00 14"), pvst: true)!;
        Assert.Equal("Rapid-PVST+", b.Protocol);
        Assert.Equal(20, b.PvstVlan);
    }

    [Fact]
    public void Mstp_bpdu_uses_cist_bridge_id()
    {
        var name = new byte[32];
        Encoding.ASCII.GetBytes("REGION1").CopyTo(name, 0);
        byte[] mst =
        [
            .. Hex("00 00 03 02 3c 80 00 00 1c 0e 87 78 00 00 00 00 04 80 00 00 1c 0e 87 78 00 80 04 01 00 14 00 02 00 0f 00 00"),
            .. Hex("00 40 00"), .. name, .. Hex("00 01"), .. new byte[16],
            .. Hex("00 00 00 00 70 00 00 aa bb cc dd ee 14"),
        ];
        var b = StpParser.Parse(mst)!;
        Assert.Equal("MSTP", b.Protocol);
        Assert.Equal("REGION1", b.MstConfigName);
        Assert.Equal(1, b.MstRevision);
        Assert.Equal(Mac.Parse("00:AA:BB:CC:DD:EE"), b.BridgeMac);
        Assert.Equal(0x7000, b.BridgePriority);
    }

    [Fact]
    public void Stp_monitor_records_bridge_flags_root_and_raises_bpdu_event()
    {
        var kit = new L2TestKit();
        var mon = new StpMonitor(NullLogger<StpMonitor>.Instance, kit.Store, kit.Network, kit.Activity);
        var seen = new List<(Mac, bool)>();
        mon.BpduSeen += (m, tc) => seen.Add((m, tc));

        var portMac = Mac.Parse("00:11:22:33:44:57");
        var f = Frame(Llc(StpDst, portMac, [0x42, 0x42, 0x03, .. Hex(StpRootTc)]));
        Assert.True(f.Eth.IsStp);
        mon.OnFrame(f);

        var bridge = Mac.Parse("00:11:22:33:44:55");
        Assert.True(kit.Store.TryGet(bridge, out var d));
        Assert.True(d.Has(DeviceFlags.Infrastructure));
        Assert.True(d.Has(DeviceFlags.StpRoot));
        Assert.Equal(portMac.ToString(), d.GetProperty("srcMac"));
        Assert.Equal("STP", d.GetProperty("stp.protocol"));
        Assert.Contains(d.Evidence, e => e.Source == "stp" && e.Field == Fields.DeviceType);
        var stp = Assert.Single(kit.Network.StpBridges);
        Assert.Equal(bridge, stp.SenderMac);
        Assert.Equal(bridge, stp.RootMac);
        Assert.Equal(32769, stp.RootPriority);
        Assert.Equal("STP", stp.Protocol);
        Assert.Equal([(bridge, true)], seen);
        Assert.Equal(1, mon.TopologyChangeCount);

        // TCN from the same port maps back to the bridge
        mon.OnFrame(Frame(Llc(StpDst, portMac, [0x42, 0x42, 0x03, .. Hex("00 00 00 80")])));
        Assert.Equal((bridge, true), seen[^1]);
        Assert.Equal(2, mon.TopologyChangeCount);
    }

    [Fact]
    public void Stp_monitor_handles_pvst_snap_frame()
    {
        var kit = new L2TestKit();
        var mon = new StpMonitor(NullLogger<StpMonitor>.Instance, kit.Store, kit.Network, kit.Activity);
        var f = Frame(Llc(Mac.Parse("01:00:0C:CC:CC:CD"), Mac.Parse("00:1C:0E:87:85:04"), Snap(0x00000C, 0x010B, Hex(Rstp + " 00 00 00 02 00 14"))));
        Assert.True(f.Eth.IsPvst);
        mon.OnFrame(f);
        Assert.True(kit.Store.TryGet(Mac.Parse("00:1C:0E:87:85:00"), out var d));
        Assert.Contains(20, d.Vlans);
        Assert.Contains(kit.Network.Vlans, v => v.Id == 20 && v.Source == "stp");
        Assert.Contains("VLAN 20", Assert.Single(kit.Network.StpBridges).Protocol);
        Assert.False(d.Has(DeviceFlags.StpRoot));
    }

    // ----------------------------------------------------------------------------------- DTP / VTP / LACP / EAPOL / 802.1Q

    [Fact]
    public void Dtp_parses_domain_and_status()
    {
        var dtp = L2SignalParsers.ParseDtp(Hex("01 00 01 00 09 43 4f 52 50 00 00 02 00 05 03 00 03 00 05 a5 00 04 00 0a 00 24 13 ab cd 18"))!;
        Assert.Equal("CORP", dtp.Domain);
        Assert.False(dtp.Trunking);
        Assert.Equal("desirable", dtp.AdminMode);
        Assert.Equal("802.1q", dtp.Encapsulation);
        Assert.Equal(Mac.Parse("00:24:13:AB:CD:18"), dtp.Neighbor);
    }

    [Fact]
    public void Vtp_subset_lists_vlans()
    {
        var domain = new byte[32];
        Encoding.ASCII.GetBytes("CORP").CopyTo(domain, 0);
        byte[] vlan10 = [.. Hex("14 00 01 05 00 0a 05 dc 00 01 86 aa"), .. Encoding.ASCII.GetBytes("VOICE"), 0, 0, 0];
        byte[] vtp = [.. Hex("02 02 01 04"), .. domain, .. Hex("00 00 00 2a"), .. vlan10];
        var info = L2SignalParsers.ParseVtp(vtp)!;
        Assert.Equal("Subset", info.CodeName);
        Assert.Equal("CORP", info.Domain);
        Assert.Equal(42u, info.ConfigRevision);
        var v = Assert.Single(info.Vlans);
        Assert.Equal((10, "VOICE", true), v);
    }

    [Fact]
    public void Lacp_and_eapol_parse()
    {
        var lacp = L2SignalParsers.ParseLacp(Hex(
            "01 01 01 14 80 00 00 1b 54 aa bb 00 00 0d 80 00 00 05 3d 00 00 00 " +
            "02 14 80 00 3c 52 82 11 22 33 00 01 80 00 00 01 3f 00 00 00 03 10 00 00 00 00 00 00 00"))!;
        Assert.Equal(Mac.Parse("00:1B:54:AA:BB:00"), lacp.ActorSystem);
        Assert.Equal(13, lacp.ActorKey);
        Assert.Equal(5, lacp.ActorPort);
        Assert.True(lacp.Active && lacp.Aggregating && lacp.Synchronized);

        var eap = L2SignalParsers.ParseEapol(Hex("01 00 00 05 01 01 00 05 01"))!;
        Assert.Equal("EAP-Packet", eap.TypeName);
        Assert.True(eap.IsAuthenticatorRequest);
        Assert.Equal(1, eap.EapType);
    }

    [Fact]
    public void Signal_monitor_sees_tags_lacp_and_eapol()
    {
        var kit = new L2TestKit();
        var mon = new L2SignalMonitor(NullLogger<L2SignalMonitor>.Instance, kit.Store, kit.Network, kit.Ctx, kit.Activity);
        var host = Mac.Parse("00:50:56:01:02:03");
        var tagged = FrameBuilder.ArpRequest(host, System.Net.IPAddress.Parse("10.30.0.5"), System.Net.IPAddress.Parse("10.30.0.1"), vlanId: 30);
        mon.OnFrame(Frame(tagged));
        Assert.True(kit.Network.NicPassesVlanTags);
        Assert.Contains(kit.Network.Vlans, v => v.Id == 30 && v.Source == "802.1Q");
        Assert.True(kit.Store.TryGet(host, out var hd));
        Assert.Contains(30, hd.Vlans);

        // our own (looped back) tagged frames prove nothing
        var kit2 = new L2TestKit();
        var mon2 = new L2SignalMonitor(NullLogger<L2SignalMonitor>.Instance, kit2.Store, kit2.Network, kit2.Ctx, kit2.Activity);
        mon2.OnFrame(Frame(tagged, outbound: true));
        Assert.Null(kit2.Network.NicPassesVlanTags);

        var sw = Mac.Parse("00:1B:54:AA:BB:05");
        mon.OnFrame(Frame(Eth(Mac.Parse("01:80:C2:00:00:03"), sw, EthernetView.Eapol, Hex("01 00 00 05 01 01 00 05 01"))));
        Assert.True(kit.Store.TryGet(sw, out var swd));
        Assert.Equal("802.1X present", swd.GetProperty("802.1X"));
        Assert.Equal("authenticator", swd.GetProperty("802.1X.role"));
        Assert.True(kit.Store.TryGet(LocalMac, out var me));
        Assert.StartsWith("802.1X present", me.GetProperty("802.1X"));
    }
}
