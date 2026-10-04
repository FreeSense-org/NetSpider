using System.Net;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Tests.Unit.Core;

public class MacTests
{
    [Theory]
    [InlineData("00:0E:58:12:34:56")]
    [InlineData("00-0e-58-12-34-56")]
    [InlineData("000e.5812.3456")]
    [InlineData("000E58123456")]
    public void Parse_accepts_common_formats(string s)
    {
        Assert.True(Mac.TryParse(s, out var mac));
        Assert.Equal("00:0E:58:12:34:56", mac.ToString());
        Assert.Equal(0x000E58u, mac.Oui24);
    }

    [Theory]
    [InlineData("")]
    [InlineData("00:0E:58:12:34")]
    [InlineData("00:0E:58:12:34:56:78")]
    [InlineData("zz:0E:58:12:34:56")]
    public void Parse_rejects_garbage(string s) => Assert.False(Mac.TryParse(s, out _));

    [Fact]
    public void Bits_are_decoded()
    {
        Assert.True(Mac.Broadcast.IsBroadcast);
        Assert.True(Mac.Parse("01:00:5E:00:00:FB").IsMulticast);
        var random = Mac.Parse("DA:A1:19:00:00:01");
        Assert.True(random.IsLocallyAdministered);
        Assert.True(random.IsRandomized);
        Assert.False(Mac.Parse("00:0E:58:12:34:56").IsRandomized);
    }

    [Fact]
    public void Bytes_roundtrip()
    {
        var mac = Mac.Parse("AC:DE:48:00:11:22");
        Assert.Equal(mac, Mac.FromBytes(mac.ToBytes()));
        Assert.Equal(0x22, mac[5]);
        Assert.Equal(Mac.Parse("AC:DE:48:00:11:23"), mac.Offset(1));
    }
}

public class IpUtilTests
{
    [Fact]
    public void Subnet_math()
    {
        var net = IpUtil.NetworkAddress(IPAddress.Parse("192.168.1.77"), 24);
        Assert.Equal(IPAddress.Parse("192.168.1.0"), net);
        Assert.True(IpUtil.InSubnet(IPAddress.Parse("192.168.1.200"), net, 24));
        Assert.False(IpUtil.InSubnet(IPAddress.Parse("192.168.2.1"), net, 24));
        Assert.Equal(254, IpUtil.Hosts(net, 24).Count());
        Assert.Equal(2, IpUtil.Hosts(IPAddress.Parse("10.0.0.0"), 31).Count());
        Assert.Equal(24, IpUtil.PrefixFromMask(IPAddress.Parse("255.255.255.0")));
    }

    [Fact]
    public void Multicast_macs()
    {
        Assert.Equal(Mac.Parse("01:00:5E:00:00:FB"), IpUtil.MulticastMac(IPAddress.Parse("224.0.0.251")));
        Assert.Equal(Mac.Parse("01:00:5E:7F:FF:FA"), IpUtil.MulticastMac(IPAddress.Parse("239.255.255.250")));
        Assert.Equal(Mac.Parse("33:33:00:00:00:FB"), IpUtil.MulticastMac(IPAddress.Parse("ff02::fb")));
    }

    [Fact]
    public void Solicited_node_address()
    {
        var sn = IpUtil.SolicitedNode(IPAddress.Parse("fe80::1234:5678:9abc:def0"));
        Assert.Equal(IPAddress.Parse("ff02::1:ffbc:def0"), sn);
    }

    [Fact]
    public void Ports_and_cidr_parse()
    {
        Assert.Equal([22, 80, 8000, 8001, 8002], IpUtil.ParsePorts("22, 80,8000-8002").ToArray());
        Assert.True(IpUtil.TryParseCidr("10.20.30.40/16", out var n, out var p));
        Assert.Equal(IPAddress.Parse("10.20.0.0"), n);
        Assert.Equal(16, p);
        Assert.True(IpUtil.IsPrivate(IPAddress.Parse("172.20.1.1")));
        Assert.False(IpUtil.IsPrivate(IPAddress.Parse("8.8.8.8")));
    }
}

public class EthernetViewTests
{
    [Fact]
    public void Parses_plain_ethernet()
    {
        var f = FrameBuilder.ArpRequest(Mac.Parse("00:11:22:33:44:55"), IPAddress.Parse("192.168.1.10"), IPAddress.Parse("192.168.1.1"));
        var e = EthernetView.Parse(f);
        Assert.True(e.Valid);
        Assert.Equal(Mac.Broadcast, e.Destination);
        Assert.Equal(EthernetView.Arp, e.EtherType);
        Assert.Null(e.VlanId);
        Assert.Equal(14, e.PayloadOffset);
    }

    [Fact]
    public void Parses_vlan_tag()
    {
        var f = FrameBuilder.ArpRequest(Mac.Parse("00:11:22:33:44:55"), IPAddress.Parse("10.0.20.10"), IPAddress.Parse("10.0.20.1"), vlanId: 20);
        var e = EthernetView.Parse(f);
        Assert.Equal(20, e.VlanId);
        Assert.Equal(EthernetView.Arp, e.EtherType);
        Assert.Equal(18, e.PayloadOffset);
    }

    [Fact]
    public void Recognizes_stp_and_cdp_llc()
    {
        // 802.3 frame to 01:80:C2:00:00:00 with LLC 42 42 03 (STP)
        var stp = new byte[60];
        Mac.Parse("01:80:C2:00:00:00").WriteTo(stp);
        Mac.Parse("00:1B:2C:3D:4E:5F").WriteTo(stp.AsSpan(6));
        stp[12] = 0x00; stp[13] = 0x26;
        stp[14] = 0x42; stp[15] = 0x42; stp[16] = 0x03;
        Assert.True(EthernetView.Parse(stp).IsStp);

        // CDP: SNAP AA AA 03 00 00 0C 20 00
        var cdp = new byte[60];
        Mac.Parse("01:00:0C:CC:CC:CC").WriteTo(cdp);
        Mac.Parse("00:1B:2C:3D:4E:5F").WriteTo(cdp.AsSpan(6));
        cdp[12] = 0x00; cdp[13] = 0x30;
        byte[] snap = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];
        snap.CopyTo(cdp.AsSpan(14));
        var e = EthernetView.Parse(cdp);
        Assert.True(e.IsCdp);
        Assert.Equal(22, e.PayloadOffset);
    }
}

public class FrameBuilderTests
{
    [Fact]
    public void Ipv4_header_checksum_verifies()
    {
        var f = FrameBuilder.Udp4(Mac.Parse("00:11:22:33:44:55"), Mac.Broadcast, IPAddress.Parse("192.168.1.10"), IPAddress.Parse("255.255.255.255"), 68, 67, new byte[20]);
        // Checksum over a header including its checksum field must be zero.
        Assert.Equal(0, FrameBuilder.Checksum(f.AsSpan(14, 20)));
        // UDP checksum verifies with pseudo header.
        int udpLen = f[14 + 24] << 8 | f[14 + 25];
        Assert.Equal(0, FrameBuilder.PseudoChecksum4(IPAddress.Parse("192.168.1.10"), IPAddress.Parse("255.255.255.255"), 17, f.AsSpan(34, udpLen)));
    }

    [Fact]
    public void Icmpv6_checksum_verifies()
    {
        var src = IPAddress.Parse("fe80::211:22ff:fe33:4455");
        var target = IPAddress.Parse("fe80::1");
        var f = FrameBuilder.NeighborSolicitation(Mac.Parse("00:11:22:33:44:55"), src, target);
        var dst = IpUtil.SolicitedNode(target);
        int payloadLen = f[14 + 4] << 8 | f[14 + 5];
        Assert.Equal(0, FrameBuilder.PseudoChecksum6(src, dst, 58, f.AsSpan(54, payloadLen)));
        Assert.Equal(IpUtil.MulticastMac(dst), Mac.FromBytes(f));
    }

    [Fact]
    public void Magic_packet_has_sync_and_16_repeats()
    {
        var mac = Mac.Parse("AA:BB:CC:DD:EE:FF");
        var p = FrameBuilder.MagicPacket(mac);
        Assert.Equal(102, p.Length);
        Assert.All(p.Take(6), b => Assert.Equal(0xFF, b));
        for (int i = 0; i < 16; i++) Assert.Equal(mac, Mac.FromBytes(p.AsSpan(6 + i * 6)));
    }
}

public class StoreTests
{
    [Fact]
    public void Observe_indexes_ips_and_raises_events()
    {
        var store = new DeviceStore();
        int added = 0, changed = 0;
        store.DeviceAdded += _ => added++;
        store.DeviceChanged += (_, _) => changed++;
        var mac = Mac.Parse("00:0E:58:00:00:01");
        var d = store.Observe(mac, IPAddress.Parse("192.168.1.20"), "arp");
        store.Observe(mac, IPAddress.Parse("192.168.1.20"), "arp");
        Assert.Equal(1, added);
        Assert.Equal(1, changed);
        Assert.Same(d, store.FindByIp(IPAddress.Parse("192.168.1.20")));
    }

    [Fact]
    public void Ip_moving_to_new_mac_updates_index()
    {
        var store = new DeviceStore();
        var ip = IPAddress.Parse("192.168.1.50");
        store.Observe(Mac.Parse("00:00:00:00:00:01"), ip, "arp");
        store.Observe(Mac.Parse("00:00:00:00:00:02"), ip, "arp");
        Assert.Equal(Mac.Parse("00:00:00:00:00:02"), store.FindByIp(ip)!.Mac);
    }

    [Fact]
    public void Links_are_undirected()
    {
        var topo = new TopologyStore();
        var a = Mac.Parse("00:00:00:00:00:01");
        var b = Mac.Parse("00:00:00:00:00:02");
        topo.Upsert(a, b, LinkKind.LldpCdp, l => l.SetPort(a, "Gi0/1"));
        topo.Upsert(b, a, LinkKind.LldpCdp);
        var link = Assert.Single(topo.Links);
        Assert.Equal("Gi0/1", link.PortOf(a));
        topo.SetPairLatency(new PairLatency(b, a, 0.5, LatencyOrigin.Measured, "test", DateTimeOffset.Now));
        Assert.Equal(0.5, topo.GetPairLatency(a, b)!.Ms);
    }

    [Fact]
    public void Alerts_respect_cooldown()
    {
        var alerts = new AlertService();
        var src = Mac.Parse("00:00:00:00:00:09");
        Assert.True(alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "storm", "x", src)));
        Assert.False(alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "storm", "x", src)));
        Assert.True(alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "storm", "x", src), TimeSpan.Zero));
        Assert.Equal(2, alerts.Alerts.Count);
    }

    [Fact]
    public void Device_evidence_replaces_same_source_field()
    {
        var d = new Device(Mac.Parse("00:0E:58:00:00:01"));
        Assert.True(d.AddEvidence("mdns", Fields.Model, "Sonos One", Confidence.Mdns));
        Assert.False(d.AddEvidence("mdns", Fields.Model, "Sonos One", Confidence.Mdns));
        Assert.True(d.AddEvidence("mdns", Fields.Model, "Sonos Era 100", Confidence.Mdns));
        Assert.Single(d.Evidence);
        d.SetHostname("dns", "living-room.lan");
        d.SetHostname("mdns", "Living-Room.local");
        Assert.Equal("Living-Room.local", d.Hostname);
    }

    [Fact]
    public void Latency_summary()
    {
        var s = new LatencyStats();
        foreach (var v in new double?[] { 1, 2, null, 3 }) s.Add(LatencyKind.Arp, v);
        var sum = s.Summarize(LatencyKind.Arp);
        Assert.Equal(25, sum.LossPercent);
        Assert.Equal(1, sum.Min);
        Assert.Equal(3, sum.Max);
        Assert.Equal(2, sum.Avg);
        Assert.Equal(3, s.BestLast);
    }

    [Fact]
    public void Eui64_ipv6_detected()
    {
        var mac = Mac.Parse("00:11:22:33:44:55");
        Assert.Equal(Ipv6InterfaceIdKind.Eui64, Ipv6Classifier.InterfaceId(IPAddress.Parse("fe80::211:22ff:fe33:4455"), mac));
        Assert.Equal(Ipv6Kind.LinkLocal, Ipv6Classifier.Kind(IPAddress.Parse("fe80::1")));
        Assert.Equal(Ipv6Kind.UniqueLocal, Ipv6Classifier.Kind(IPAddress.Parse("fd00::1")));
        Assert.Equal(Ipv6Kind.GlobalUnicast, Ipv6Classifier.Kind(IPAddress.Parse("2001:db8::1")));
    }
}
