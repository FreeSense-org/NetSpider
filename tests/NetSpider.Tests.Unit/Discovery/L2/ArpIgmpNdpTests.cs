using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class ArpIgmpNdpTests
{
    private static readonly Mac GatewayMac = Mac.Parse("74:AC:B9:00:00:01");
    private static readonly Mac Attacker = Mac.Parse("02:BA:D0:00:00:66");
    private static readonly Mac HostA = Mac.Parse("00:0C:29:AA:00:01");
    private static readonly Mac HostB = Mac.Parse("00:0C:29:BB:00:02");

    // ------------------------------------------------------------------------------------------ ARP / FrameBuilder

    [Fact]
    public void Arp_request_bytes_match_rfc826_layout()
    {
        var f = FrameBuilder.ArpRequest(LocalMac, LocalIp, GatewayIp);
        Assert.Equal(60, f.Length);
        Assert.Equal(Hex("ff ff ff ff ff ff 3c 52 82 11 22 33 08 06 00 01 08 00 06 04 00 01 3c 52 82 11 22 33 c0 a8 01 32 00 00 00 00 00 00 c0 a8 01 01"), f[..42]);
        var arp = ArpPacket.Parse(Frame(f).Payload)!;
        Assert.Equal(ArpPacket.Request, arp.Op);
        Assert.Equal(LocalMac, arp.SenderMac);
        Assert.Equal(GatewayIp, arp.TargetIp);
    }

    [Fact]
    public void Arp_reply_hex_sample_parses()
    {
        // 74:ac:b9:00:00:01 is-at, 192.168.1.1 → 192.168.1.50
        var frame = Hex("3c 52 82 11 22 33 74 ac b9 00 00 01 08 06 00 01 08 00 06 04 00 02 74 ac b9 00 00 01 c0 a8 01 01 3c 52 82 11 22 33 c0 a8 01 32" + string.Concat(Enumerable.Repeat(" 00", 18)));
        var arp = ArpPacket.Parse(Frame(frame).Payload)!;
        Assert.Equal(ArpPacket.Reply, arp.Op);
        Assert.Equal(GatewayMac, arp.SenderMac);
        Assert.Equal(GatewayIp, arp.SenderIp);
        Assert.Equal(LocalMac, arp.TargetMac);
        Assert.False(arp.IsGratuitous);
        Assert.Null(ArpPacket.Parse(Hex("00 06 08 00 06 04")));
    }

    [Fact]
    public void Neighbor_solicitation_has_valid_checksum_and_solicited_node_destination()
    {
        var target = IPAddress.Parse("fe80::1234:56ff:fe78:9abc");
        var f = FrameBuilder.NeighborSolicitation(LocalMac, LocalLinkLocal, target);
        var frame = Frame(f);
        Assert.Equal(Mac.Parse("33:33:FF:78:9A:BC"), frame.Eth.Destination);
        Assert.True(IpView.TryParse(frame.Payload, EthernetView.Ipv6, out var ip));
        Assert.Equal(IpView.Icmp6, ip.Protocol);
        Assert.Equal(IPAddress.Parse("ff02::1:ff78:9abc"), ip.Destination(frame.Payload));
        var icmp = ip.L4(frame.Payload);
        Assert.Equal(0, FrameBuilder.PseudoChecksum6(LocalLinkLocal, IpUtil.SolicitedNode(target), 58, icmp));
        var ns = NdpParser.ParseNeighbor(icmp)!;
        Assert.False(ns.IsAdvertisement);
        Assert.Equal(target, ns.Target);
        Assert.Equal(LocalMac, ns.LinkLayer);
    }

    [Fact]
    public void Udp_and_ipv4_checksums_are_valid()
    {
        var f = FrameBuilder.Udp4(LocalMac, Mac.Broadcast, LocalIp, IPAddress.Parse("192.168.1.255"), 5353, 5353, "hello"u8);
        var p = Frame(f).Payload;
        Assert.Equal(0, FrameBuilder.Checksum(p[..20]));
        Assert.Equal(0, FrameBuilder.PseudoChecksum4(LocalIp, IPAddress.Parse("192.168.1.255"), 17, p[20..33]));
    }

    private static ArpWatcher Watcher(L2TestKit kit) => new(NullLogger<ArpWatcher>.Instance, kit.Store, kit.Alerts, kit.Ctx, kit.Activity);

    private static CapturedFrame ArpReplyFrame(Mac sender, IPAddress senderIp) =>
        Frame(FrameBuilder.ArpReply(sender, senderIp, LocalMac, LocalIp));

    [Fact]
    public void Gateway_mac_change_is_critical()
    {
        var kit = new L2TestKit();
        var w = Watcher(kit);
        w.OnFrame(ArpReplyFrame(GatewayMac, GatewayIp));
        Assert.True(kit.Store.TryGet(GatewayMac, out var gw));
        Assert.True(gw.Has(DeviceFlags.Gateway));
        Assert.Empty(kit.Alerts.Alerts);

        w.OnFrame(ArpReplyFrame(Attacker, GatewayIp));
        var crit = Assert.Single(kit.Alerts.Alerts, a => a.Kind == AlertKind.GatewayMacChanged);
        Assert.Equal(AlertSeverity.Critical, crit.Severity);
        Assert.Equal(Attacker, crit.Source);
        Assert.Contains(kit.Alerts.Alerts, a => a.Kind == AlertKind.ArpSpoofing);
        Assert.True(gw.Has(DeviceFlags.IpConflict));
        Assert.True(kit.Store.TryGet(Attacker, out var att));
        Assert.True(att.Has(DeviceFlags.IpConflict));
        Assert.True(att.Has(DeviceFlags.Gateway));
        Assert.False(gw.Has(DeviceFlags.Gateway));
    }

    [Fact]
    public void Duplicate_ip_then_flip_back_is_arp_spoofing()
    {
        var kit = new L2TestKit();
        var w = Watcher(kit);
        var ip = IPAddress.Parse("192.168.1.20");
        w.OnFrame(ArpReplyFrame(HostA, ip));
        w.OnFrame(ArpReplyFrame(HostB, ip));
        var dup = Assert.Single(kit.Alerts.Alerts);
        Assert.Equal(AlertKind.DuplicateIp, dup.Kind);
        Assert.Equal(AlertSeverity.Warning, dup.Severity);

        w.OnFrame(ArpReplyFrame(HostA, ip));
        Assert.Contains(kit.Alerts.Alerts, a => a.Kind == AlertKind.ArpSpoofing);
    }

    [Fact]
    public void Dhcp_renewal_like_change_is_ignored()
    {
        var kit = new L2TestKit();
        var w = Watcher(kit);
        var ip = IPAddress.Parse("192.168.1.21");
        w.OnFrame(ArpReplyFrame(HostA, ip));
        Assert.True(kit.Store.TryGet(HostA, out var a));
        a.LastSeen = DateTimeOffset.Now - TimeSpan.FromMinutes(6);
        a.State = DeviceState.Offline;

        w.OnFrame(ArpReplyFrame(HostB, ip));
        Assert.Empty(kit.Alerts.Alerts);
        Assert.Equal(HostB, kit.Store.FindByIp(ip)!.Mac);
        Assert.False(a.Has(DeviceFlags.IpConflict));
    }

    [Fact]
    public void Gratuitous_arp_and_probe_are_observed()
    {
        var kit = new L2TestKit();
        var w = Watcher(kit);
        var ip = IPAddress.Parse("192.168.1.30");
        w.OnFrame(Frame(FrameBuilder.ArpRequest(HostA, ip, ip)));
        Assert.True(kit.Store.TryGet(HostA, out var d));
        Assert.Contains(ip, d.IPv4);
        Assert.Equal("seen", d.GetProperty("arp.gratuitous"));

        w.OnFrame(Frame(FrameBuilder.ArpRequest(HostB, IPAddress.Any, ip)));
        Assert.True(kit.Store.TryGet(HostB, out var probe));
        Assert.Empty(probe.IPv4);
        Assert.Empty(kit.Alerts.Alerts);
    }

    [Fact]
    public void Fhrp_virtual_macs_are_recognised()
    {
        Assert.True(ArpWatcher.IsFhrpVirtual(Mac.Parse("00:00:5E:00:01:0A")));
        Assert.True(ArpWatcher.IsFhrpVirtual(Mac.Parse("00:00:0C:07:AC:01")));
        Assert.False(ArpWatcher.IsFhrpVirtual(GatewayMac));
    }

    // ------------------------------------------------------------------------------------------ IGMP / MLD

    private static readonly byte[] RouterAlert = [0x94, 0x04, 0x00, 0x00];

    /// <summary>IGMPv3 report: TO_EX(239.255.255.250) join + TO_IN{}(224.0.0.251) leave.</summary>
    public static byte[] IgmpV3Report()
    {
        var m = Hex("22 00 00 00 00 00 00 02 04 00 00 00 ef ff ff fa 03 00 00 00 e0 00 00 fb");
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(2), FrameBuilder.Checksum(m));
        return m;
    }

    [Fact]
    public void Igmpv3_report_parses_joins_and_leaves()
    {
        var msg = IgmpParser.ParseIgmp(IgmpV3Report())!;
        Assert.Equal(3, msg.Version);
        Assert.Equal([IPAddress.Parse("239.255.255.250")], msg.Joined);
        Assert.Equal([IPAddress.Parse("224.0.0.251")], msg.Left);
        Assert.Equal(0, FrameBuilder.Checksum(IgmpV3Report()));
    }

    [Fact]
    public void Igmp_monitor_tracks_groups_and_querier()
    {
        var kit = new L2TestKit();
        var mon = new IgmpMonitor(NullLogger<IgmpMonitor>.Instance, kit.Store, kit.Network, kit.Activity);
        var hostIp = IPAddress.Parse("192.168.1.77");
        var mdns = IPAddress.Parse("224.0.0.251");

        var v2 = Hex("16 00 00 00 e0 00 00 fb");
        BinaryPrimitives.WriteUInt16BigEndian(v2.AsSpan(2), FrameBuilder.Checksum(v2));
        mon.OnFrame(Frame(Eth(IpUtil.MulticastMac(mdns), HostA, EthernetView.Ipv4, Ip4(hostIp, mdns, 2, v2, 1, RouterAlert))));
        Assert.True(kit.Store.TryGet(HostA, out var d));
        Assert.Contains(mdns, d.MulticastGroups);
        Assert.True(d.Has(DeviceFlags.MulticastSource));

        var v3dst = IPAddress.Parse("224.0.0.22");
        mon.OnFrame(Frame(Eth(IpUtil.MulticastMac(v3dst), HostA, EthernetView.Ipv4, Ip4(hostIp, v3dst, 2, IgmpV3Report(), 1, RouterAlert))));
        Assert.Contains(IPAddress.Parse("239.255.255.250"), d.MulticastGroups);
        Assert.DoesNotContain(mdns, d.MulticastGroups);

        Assert.Null(kit.Network.IgmpQuerier);
        var query = IgmpQueryProbe.BuildQueryFrame(GatewayMac, GatewayIp, 100);
        mon.OnFrame(Frame(query, outbound: true));
        Assert.Null(kit.Network.IgmpQuerier); // our own looped-back query does not count
        mon.OnFrame(Frame(query));
        Assert.Equal(GatewayMac, kit.Network.IgmpQuerier);
        Assert.True(kit.Store.TryGet(GatewayMac, out var q));
        Assert.True(q.Has(DeviceFlags.IgmpQuerier));
        Assert.NotNull(mon.SinceLastQuery);
    }

    [Fact]
    public void Igmp_query_frame_is_well_formed()
    {
        var f = Frame(IgmpQueryProbe.BuildQueryFrame(LocalMac, LocalIp, 10));
        Assert.Equal(Mac.Parse("01:00:5E:00:00:01"), f.Eth.Destination);
        Assert.True(IpView.TryParse(f.Payload, EthernetView.Ipv4, out var ip));
        Assert.Equal(1, ip.Ttl);
        Assert.Equal(24, ip.L4Offset);
        Assert.Equal(0, FrameBuilder.Checksum(f.Payload[..24]));
        var igmp = ip.L4(f.Payload);
        Assert.Equal(8, igmp.Length);
        Assert.Equal(0, FrameBuilder.Checksum(igmp));
        var msg = IgmpParser.ParseIgmp(igmp)!;
        Assert.Equal(GroupMessageKind.Query, msg.Kind);
        Assert.Equal(2, msg.Version);
        Assert.True(msg.IsGeneralQuery);
        Assert.Equal(1.0, msg.MaxResponseSeconds);
    }

    [Fact]
    public void Mldv2_report_through_hop_by_hop_header()
    {
        var kit = new L2TestKit();
        var mon = new IgmpMonitor(NullLogger<IgmpMonitor>.Instance, kit.Store, kit.Network, kit.Activity);
        var src = IPAddress.Parse("fe80::20c:29ff:feaa:1");
        var dst = IPAddress.Parse("ff02::16");
        var group = IPAddress.Parse("ff02::fb");
        var solicited = IPAddress.Parse("ff02::1:ffaa:1");
        byte[] mld = [143, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, .. group.GetAddressBytes(), 4, 0, 0, 0, .. solicited.GetAddressBytes()];
        BinaryPrimitives.WriteUInt16BigEndian(mld.AsSpan(2), FrameBuilder.PseudoChecksum6(src, dst, 58, mld));
        byte[] hbh = [58, 0, 5, 2, 0, 0, 1, 0]; // next=ICMPv6, len 0, router alert (MLD), PadN
        var frame = FrameBuilder.Ip6Frame(HostA, IpUtil.MulticastMac(dst), src, dst, 0, [.. hbh, .. mld], hopLimit: 1);
        mon.OnFrame(Frame(frame));

        Assert.True(kit.Store.TryGet(HostA, out var d));
        Assert.Contains(group, d.MulticastGroups);
        Assert.DoesNotContain(solicited, d.MulticastGroups); // solicited-node groups are noise
        Assert.Contains(src, d.IPv6.Select(x => x.Address));
    }

    // ------------------------------------------------------------------------------------------ IPv6 RA

    private static byte[] RaFrame(Mac router, IPAddress src)
    {
        byte[] body =
        [
            64, 0x08, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,                  // hop limit 64, pref high, lifetime 1800, reachable, retrans
            1, 1, .. router.ToBytes(),                                     // source link-layer
            3, 4, 64, 0xC0, 0, 0, 0x0e, 0x10, 0, 0, 0x07, 0x08, 0, 0, 0, 0, // prefix info /64 L+A
            .. IPAddress.Parse("2001:db8:1::").GetAddressBytes(),
            5, 1, 0, 0, 0, 0, 0x05, 0xdc,                                  // MTU 1500
        ];
        return FrameBuilder.Icmp6Frame(router, Mac.Parse("33:33:00:00:00:01"), src, IPAddress.Parse("ff02::1"), 134, 0, body);
    }

    [Fact]
    public void Router_advertisement_parses()
    {
        var f = Frame(RaFrame(GatewayMac, IPAddress.Parse("fe80::1")));
        Assert.True(IpView.TryParse(f.Payload, EthernetView.Ipv6, out var ip));
        var ra = NdpParser.ParseRa(ip.L4(f.Payload))!;
        Assert.Equal(TimeSpan.FromSeconds(1800), ra.RouterLifetime);
        Assert.Equal("High", ra.Preference);
        Assert.Equal(GatewayMac, ra.SourceLinkLayer);
        Assert.Equal(1500, ra.Mtu);
        var p = Assert.Single(ra.Prefixes);
        Assert.Equal("2001:db8:1::/64", p.ToString());
        Assert.True(p.Autonomous);
    }

    [Fact]
    public void Second_ra_source_that_is_not_the_gateway_is_rogue()
    {
        var kit = new L2TestKit();
        var gw = kit.Store.Observe(GatewayMac, GatewayIp, "arp");
        gw.SetFlag(DeviceFlags.Gateway);
        var mon = new NdpMonitor(NullLogger<NdpMonitor>.Instance, kit.Store, kit.Alerts, kit.Ctx, kit.Activity);

        mon.OnFrame(Frame(RaFrame(GatewayMac, IPAddress.Parse("fe80::1"))));
        Assert.Equal(DeviceType.Router, gw.Type);
        Assert.Empty(kit.Alerts.Alerts);

        mon.OnFrame(Frame(RaFrame(Attacker, IPAddress.Parse("fe80::bad"))));
        var alert = Assert.Single(kit.Alerts.Alerts);
        Assert.Equal(AlertKind.RogueRouterAdvert, alert.Kind);
        Assert.Equal(Attacker, alert.Source);
        Assert.True(kit.Store.TryGet(Attacker, out var rogue));
        Assert.True(rogue.Has(DeviceFlags.RogueRouterAdvert));
        Assert.False(gw.Has(DeviceFlags.RogueRouterAdvert));
    }
}
