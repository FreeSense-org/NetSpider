using System.Buffers.Binary;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class DhcpTests
{
    private static readonly Mac Client = Mac.Parse("D4:5D:64:AA:01:02");
    private static readonly Mac RogueMac = Mac.Parse("B8:27:EB:66:66:66");
    private static readonly Mac GatewayMac = Mac.Parse("74:AC:B9:00:00:01");

    private static byte[] Opt(byte code, params byte[] v) => [code, (byte)v.Length, .. v];
    private static byte[] OptS(byte code, string s) => Opt(code, Encoding.ASCII.GetBytes(s));
    private static byte[] OptIp(byte code, params string[] ips) => Opt(code, ips.SelectMany(i => IPAddress.Parse(i).GetAddressBytes()).ToArray());

    /// <summary>BOOTP fixed header + magic cookie + options + end.</summary>
    private static byte[] Bootp(byte op, uint xid, Mac chaddr, IPAddress? yiaddr, bool broadcast, params byte[][] options)
    {
        var b = new byte[240];
        b[0] = op; b[1] = 1; b[2] = 6;
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), xid);
        if (broadcast) b[10] = 0x80;
        (yiaddr ?? IPAddress.Any).TryWriteBytes(b.AsSpan(16), out _);
        chaddr.WriteTo(b.AsSpan(28));
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(236), 0x63825363);
        return [.. b, .. options.SelectMany(o => o), 255];
    }

    /// <summary>Windows 10 style DHCPDISCOVER.</summary>
    public static byte[] Win10Discover() => Bootp(1, 0x3903F326, Client, null, false,
        Opt(53, 1),
        Opt(61, 1, 0xD4, 0x5D, 0x64, 0xAA, 0x01, 0x02),
        OptIp(50, "192.168.1.77"),
        OptS(12, "DESKTOP-7K2M"),
        [81, 15, 0, 0, 0, .. Encoding.ASCII.GetBytes("DESKTOP-7K2M")],
        OptS(60, "MSFT 5.0"),
        Opt(55, 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252));

    public static byte[] Offer(uint xid, string server, string yiaddr, string router, byte[]? routes121 = null)
    {
        var opts = new List<byte[]>
        {
            Opt(53, 2), OptIp(54, server), OptIp(1, "255.255.255.0"), OptIp(3, router), OptIp(6, "8.8.8.8", "1.1.1.1"),
            Opt(51, 0, 1, 0x51, 0x80),
        };
        if (routes121 is not null) opts.Add(Opt(121, routes121));
        return Bootp(2, xid, LocalMac, IPAddress.Parse(yiaddr), true, [.. opts]);
    }

    private static readonly byte[] Routes121 = [24, 10, 20, 30, 192, 168, 1, 254, 16, 172, 20, 192, 168, 1, 254, 0, 192, 168, 1, 1];

    [Fact]
    public void Discover_options_give_fingerprint_vendor_class_and_names()
    {
        var p = DhcpPacket.Parse(Win10Discover())!;
        Assert.True(p.IsBootRequest);
        Assert.Equal(DhcpPacket.Discover, p.MessageType);
        Assert.Equal(Client, p.ClientMac);
        Assert.Equal("1,3,6,15,31,33,43,44,46,47,119,121,249,252", p.Fingerprint);
        Assert.Equal("MSFT 5.0", p.VendorClass);
        Assert.Equal("DESKTOP-7K2M", p.Hostname);
        Assert.Equal("DESKTOP-7K2M", p.ClientFqdn);
        Assert.Equal(IPAddress.Parse("192.168.1.77"), p.RequestedIp);
        Assert.Equal([53, 61, 50, 12, 81, 60, 55], p.OptionOrder.Select(x => (int)x));
    }

    [Fact]
    public void Fqdn_option_in_wire_format()
    {
        var pkt = DhcpPacket.Parse(Bootp(1, 1, Client, null, false, Opt(53, 3), [81, 3 + 17, 0x05, 0, 0, 6, .. "laptop"u8, 4, .. "corp"u8, 3, .. "lan"u8, 0]))!;
        Assert.Equal("laptop.corp.lan", pkt.ClientFqdn);
    }

    [Fact]
    public void Classless_routes_option_121()
    {
        var routes = DhcpPacket.ParseClasslessRoutes(Routes121);
        Assert.Equal(3, routes.Count);
        Assert.Equal(new ClasslessRoute(IPAddress.Parse("10.20.30.0"), 24, IPAddress.Parse("192.168.1.254")), routes[0]);
        Assert.Equal(new ClasslessRoute(IPAddress.Parse("172.20.0.0"), 16, IPAddress.Parse("192.168.1.254")), routes[1]);
        Assert.Equal(new ClasslessRoute(IPAddress.Any, 0, IPAddress.Parse("192.168.1.1")), routes[2]);
    }

    [Fact]
    public void Discover_frame_is_broadcast_with_valid_checksums_and_tag()
    {
        var frame = DhcpBuilder.DiscoverFrame(LocalMac, 0xDEADBEEF, vlanId: 42);
        var f = Frame(frame);
        Assert.Equal(42, f.Eth.VlanId);
        Assert.Equal(Mac.Broadcast, f.Eth.Destination);
        var ip = f.Payload;
        Assert.Equal(0, FrameBuilder.Checksum(ip[..20]));
        int len = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
        var udp = ip[20..len];
        Assert.Equal(0, FrameBuilder.PseudoChecksum4(IPAddress.Any, IPAddress.Broadcast, 17, udp));
        Assert.True(DhcpBuilder.TryExtract(f, out var p, out _, out _));
        Assert.Equal(DhcpPacket.Discover, p.MessageType);
        Assert.True(p.Broadcast);
        Assert.Equal(0xDEADBEEFu, p.Xid);
        Assert.Null(p.RequestedIp);
        Assert.Contains((byte)121, p.ParameterRequestList!);
    }

    private static DhcpMonitor Monitor(L2TestKit kit) =>
        new(NullLogger<DhcpMonitor>.Instance, kit.Store, kit.Network, kit.Alerts, kit.Ctx, new DhcpProbeRegistry(), kit.Activity);

    [Fact]
    public void Passive_client_fingerprinting()
    {
        var kit = new L2TestKit();
        var frame = FrameBuilder.Udp4(Client, Mac.Broadcast, IPAddress.Any, IPAddress.Broadcast, 68, 67, Win10Discover());
        Monitor(kit).OnFrame(Frame(frame));

        Assert.True(kit.Store.TryGet(Client, out var d));
        Assert.Equal("DESKTOP-7K2M", d.Hostname);
        Assert.Contains(d.Evidence, e => e.Source == "dhcp" && e.Field == Fields.DhcpFingerprint && e.Value == "1,3,6,15,31,33,43,44,46,47,119,121,249,252" && e.Confidence == Confidence.Dhcp);
        Assert.Contains(d.Evidence, e => e.Source == "dhcp" && e.Field == Fields.DhcpVendorClass && e.Value == "MSFT 5.0");
        Assert.Contains(d.Evidence, e => e.Source == "dhcp" && e.Field == Fields.Hostname && e.Value == "DESKTOP-7K2M");
        Assert.Equal("DISCOVER", d.GetProperty("dhcp.lastMessage"));
    }

    [Fact]
    public void Rogue_offer_raises_alert_and_legit_offer_does_not()
    {
        var kit = new L2TestKit();
        kit.Store.Observe(GatewayMac, GatewayIp, "arp");
        var mon = Monitor(kit);

        var legit = FrameBuilder.Udp4(GatewayMac, Mac.Broadcast, GatewayIp, IPAddress.Broadcast, 67, 68, Offer(7, "192.168.1.1", "192.168.1.50", "192.168.1.1"));
        mon.OnFrame(Frame(legit));
        Assert.Empty(kit.Alerts.Alerts);
        Assert.True(kit.Store.TryGet(GatewayMac, out var gw));
        Assert.True(gw.Has(DeviceFlags.DhcpServer));
        Assert.False(gw.Has(DeviceFlags.RogueDhcp));

        var rogueIp = IPAddress.Parse("192.168.1.66");
        var rogue = FrameBuilder.Udp4(RogueMac, Mac.Broadcast, rogueIp, IPAddress.Broadcast, 67, 68, Offer(8, "192.168.1.66", "192.168.1.120", "192.168.1.66", Routes121));
        mon.OnFrame(Frame(rogue));

        var alert = Assert.Single(kit.Alerts.Alerts);
        Assert.Equal(AlertKind.RogueDhcp, alert.Kind);
        Assert.Equal(AlertSeverity.Warning, alert.Severity);
        Assert.Equal(RogueMac, alert.Source);
        Assert.True(kit.Store.TryGet(RogueMac, out var r));
        Assert.True(r.Has(DeviceFlags.RogueDhcp));
        Assert.True(r.Has(DeviceFlags.DhcpServer));
        Assert.Contains(rogueIp, r.IPv4);
        var servers = kit.Network.DhcpServers;
        Assert.Equal(2, servers.Count);
        var rs = servers.Single(s => s.ServerIp.Equals(rogueIp));
        Assert.True(rs.IsRogue);
        Assert.Equal(IPAddress.Parse("255.255.255.0"), rs.SubnetMask);
        Assert.Equal(TimeSpan.FromSeconds(86400), rs.Lease);
        Assert.False(servers.Single(s => s.ServerIp.Equals(GatewayIp)).IsRogue);
    }

    [Fact]
    public void Offer_answering_a_vlan_probe_is_never_rogue()
    {
        var kit = new L2TestKit();
        var reg = new DhcpProbeRegistry();
        var mon = new DhcpMonitor(NullLogger<DhcpMonitor>.Instance, kit.Store, kit.Network, kit.Alerts, kit.Ctx, reg, kit.Activity);
        uint xid = reg.NewXid(30);
        var other = FrameBuilder.Udp4(RogueMac, Mac.Broadcast, IPAddress.Parse("10.30.0.1"), IPAddress.Broadcast, 67, 68, Offer(xid, "10.30.0.1", "10.30.0.99", "10.30.0.1"));
        mon.OnFrame(Frame(other));
        Assert.Empty(kit.Alerts.Alerts);
        Assert.False(Assert.Single(kit.Network.DhcpServers).IsRogue);
    }

    [Fact]
    public async Task Active_discover_sends_one_discover_and_learns_option_121_subnets()
    {
        var kit = new L2TestKit();
        var reg = new DhcpProbeRegistry();
        var probe = new DhcpDiscoverProbe(NullLogger<DhcpDiscoverProbe>.Instance, kit.Frames, reg, kit.Subnets, kit.Ctx, kit.Store);
        kit.Frames.OnSend = (frame, ticks) =>
        {
            Assert.True(DhcpBuilder.TryExtract(Frame(frame), out var d, out _, out _));
            Assert.Equal(DhcpPacket.Discover, d.MessageType);
            var offer = FrameBuilder.Udp4(GatewayMac, Mac.Broadcast, GatewayIp, IPAddress.Broadcast, 67, 68, Offer(d.Xid, "192.168.1.1", "192.168.1.50", "192.168.1.1", Routes121));
            Task.Run(() => kit.Frames.Deliver(Frame(offer)));
        };

        await probe.RunAsync(kit.ScanContext(), null, CancellationToken.None);

        Assert.Single(kit.Frames.Sent);
        Assert.Single(probe.LastOffers);
        var seg = Assert.Single(kit.Network.Segments, s => s.Cidr == "10.20.30.0/24");
        Assert.Equal("dhcp-121", seg.Source);
        Assert.False(seg.IsLocal);
        Assert.Equal(kit.Settings.ScanOtherSubnets, seg.ScanEnabled);
        Assert.Equal(IPAddress.Parse("192.168.1.254"), seg.Gateway);
        Assert.Contains(kit.Network.Segments, s => s.Cidr == "172.20.0.0/16");
        Assert.DoesNotContain(kit.Network.Segments, s => s.PrefixLength == 0);
        Assert.DoesNotContain(kit.Frames.Sent, f => DhcpBuilder.TryExtract(Frame(f), out var p, out _, out _) && p.MessageType == DhcpPacket.Request);
    }

    [Fact]
    public async Task Vlan_prober_maps_offer_to_vlan_segment()
    {
        var kit = new L2TestKit();
        kit.Network.AddVlan(new VlanInfo(10, "USERS", "lldp", Native: true, Voice: false));
        kit.Network.AddVlan(new VlanInfo(30, "LAB", "lldp", Native: false, Voice: false));
        var reg = new DhcpProbeRegistry();
        var probe = new VlanProber(NullLogger<VlanProber>.Instance, kit.Frames, kit.Network, kit.Store, reg, kit.Ctx);
        kit.Frames.OnSend = (frame, ticks) =>
        {
            var f = Frame(frame);
            Assert.Equal(30, f.Eth.VlanId);
            Assert.True(DhcpBuilder.TryExtract(f, out var d, out _, out _));
            var offer = FrameBuilder.Udp4(RogueMac, Mac.Broadcast, IPAddress.Parse("10.30.0.1"), IPAddress.Broadcast, 67, 68, Offer(d.Xid, "10.30.0.1", "10.30.0.99", "10.30.0.1"), vlanId: 30);
            Task.Run(() => kit.Frames.Deliver(Frame(offer)));
        };
        await probe.RunAsync(kit.ScanContext(), null, CancellationToken.None);

        Assert.Single(kit.Frames.Sent);
        var seg = Assert.Single(kit.Network.Segments, s => s.Cidr == "10.30.0.0/24");
        Assert.Equal(30, seg.VlanId);
        Assert.False(seg.IsLocal);
        Assert.Equal(IPAddress.Parse("10.30.0.1"), seg.Gateway);
    }

    [Fact]
    public async Task Vlan_prober_skips_when_nic_strips_tags()
    {
        var kit = new L2TestKit();
        kit.Network.AddVlan(new VlanInfo(30, null, "lldp", false, false));
        kit.Network.NicPassesVlanTags = false;
        var probe = new VlanProber(NullLogger<VlanProber>.Instance, kit.Frames, kit.Network, kit.Store, new DhcpProbeRegistry(), kit.Ctx);
        await probe.RunAsync(kit.ScanContext(), null, CancellationToken.None);
        Assert.Empty(kit.Frames.Sent);
    }
}
