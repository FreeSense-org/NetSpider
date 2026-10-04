using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace NetSpider.Core.Model;

/// <summary>Helpers to craft raw Ethernet frames for injection. All multi-byte fields are big-endian.</summary>
public static class FrameBuilder
{
    public static int WriteEthernet(Span<byte> buf, Mac dst, Mac src, ushort etherType, int? vlanId = null)
    {
        dst.WriteTo(buf);
        src.WriteTo(buf[6..]);
        int off = 12;
        if (vlanId is { } v)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buf[off..], EthernetView.Vlan);
            BinaryPrimitives.WriteUInt16BigEndian(buf[(off + 2)..], (ushort)(v & 0x0FFF));
            off += 4;
        }
        BinaryPrimitives.WriteUInt16BigEndian(buf[off..], etherType);
        return off + 2;
    }

    /// <summary>ARP request (who-has <paramref name="targetIp"/>, tell <paramref name="senderIp"/>), padded to 60 bytes.</summary>
    public static byte[] ArpRequest(Mac srcMac, IPAddress senderIp, IPAddress targetIp, int? vlanId = null, Mac? dstMac = null)
    {
        var buf = new byte[vlanId is null ? 60 : 64];
        int o = WriteEthernet(buf, dstMac ?? Mac.Broadcast, srcMac, EthernetView.Arp, vlanId);
        WriteArp(buf.AsSpan(o), 1, srcMac, senderIp, Mac.Zero, targetIp);
        return buf;
    }

    public static byte[] ArpReply(Mac srcMac, IPAddress senderIp, Mac dstMac, IPAddress targetIp)
    {
        var buf = new byte[60];
        int o = WriteEthernet(buf, dstMac, srcMac, EthernetView.Arp);
        WriteArp(buf.AsSpan(o), 2, srcMac, senderIp, dstMac, targetIp);
        return buf;
    }

    private static void WriteArp(Span<byte> a, ushort op, Mac sha, IPAddress spa, Mac tha, IPAddress tpa)
    {
        BinaryPrimitives.WriteUInt16BigEndian(a, 1);          // HTYPE Ethernet
        BinaryPrimitives.WriteUInt16BigEndian(a[2..], 0x0800); // PTYPE IPv4
        a[4] = 6; a[5] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(a[6..], op);
        sha.WriteTo(a[8..]);
        spa.TryWriteBytes(a[14..], out _);
        tha.WriteTo(a[18..]);
        tpa.TryWriteBytes(a[24..], out _);
    }

    /// <summary>IPv4 header (20 bytes, no options) followed by <paramref name="payload"/>.</summary>
    public static int WriteIpv4(Span<byte> buf, IPAddress src, IPAddress dst, byte protocol, ReadOnlySpan<byte> payload, byte ttl = 64, ushort id = 0, bool dontFragment = false, byte tos = 0)
    {
        int total = 20 + payload.Length;
        buf[0] = 0x45; buf[1] = tos;
        BinaryPrimitives.WriteUInt16BigEndian(buf[2..], (ushort)total);
        BinaryPrimitives.WriteUInt16BigEndian(buf[4..], id);
        BinaryPrimitives.WriteUInt16BigEndian(buf[6..], (ushort)(dontFragment ? 0x4000 : 0));
        buf[8] = ttl; buf[9] = protocol;
        buf[10] = buf[11] = 0;
        src.TryWriteBytes(buf[12..], out _);
        dst.TryWriteBytes(buf[16..], out _);
        BinaryPrimitives.WriteUInt16BigEndian(buf[10..], Checksum(buf[..20]));
        payload.CopyTo(buf[20..]);
        return total;
    }

    /// <summary>Builds Ethernet + IPv4 + UDP with a correct UDP checksum.</summary>
    public static byte[] Udp4(Mac srcMac, Mac dstMac, IPAddress srcIp, IPAddress dstIp, int srcPort, int dstPort, ReadOnlySpan<byte> data, byte ttl = 64, int? vlanId = null)
    {
        var udp = new byte[8 + data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(udp, (ushort)srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2), (ushort)dstPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4), (ushort)udp.Length);
        data.CopyTo(udp.AsSpan(8));
        var cs = PseudoChecksum4(srcIp, dstIp, 17, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(6), cs == 0 ? (ushort)0xFFFF : cs);
        return Ip4Frame(srcMac, dstMac, srcIp, dstIp, 17, udp, ttl, vlanId);
    }

    public static byte[] Ip4Frame(Mac srcMac, Mac dstMac, IPAddress srcIp, IPAddress dstIp, byte protocol, ReadOnlySpan<byte> l4, byte ttl = 64, int? vlanId = null, bool dontFragment = false, byte tos = 0)
    {
        int ethLen = vlanId is null ? 14 : 18;
        var buf = new byte[Math.Max(60, ethLen + 20 + l4.Length)];
        int o = WriteEthernet(buf, dstMac, srcMac, EthernetView.Ipv4, vlanId);
        WriteIpv4(buf.AsSpan(o), srcIp, dstIp, protocol, l4, ttl, (ushort)Random.Shared.Next(1, 65535), dontFragment, tos);
        return buf;
    }

    /// <summary>IPv6 header (40 bytes) + payload with next header <paramref name="nextHeader"/>.</summary>
    public static byte[] Ip6Frame(Mac srcMac, Mac dstMac, IPAddress src, IPAddress dst, byte nextHeader, ReadOnlySpan<byte> payload, byte hopLimit = 255)
    {
        var buf = new byte[Math.Max(60, 14 + 40 + payload.Length)];
        int o = WriteEthernet(buf, dstMac, srcMac, EthernetView.Ipv6);
        var ip = buf.AsSpan(o);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)payload.Length);
        ip[6] = nextHeader; ip[7] = hopLimit;
        src.TryWriteBytes(ip[8..], out _);
        dst.TryWriteBytes(ip[24..], out _);
        payload.CopyTo(ip[40..]);
        return buf;
    }

    /// <summary>ICMPv6 message (type/code/body) with checksum computed over the IPv6 pseudo header.</summary>
    public static byte[] Icmp6Frame(Mac srcMac, Mac dstMac, IPAddress src, IPAddress dst, byte type, byte code, ReadOnlySpan<byte> body, byte hopLimit = 255)
    {
        var icmp = new byte[4 + body.Length];
        icmp[0] = type; icmp[1] = code;
        body.CopyTo(icmp.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2), PseudoChecksum6(src, dst, 58, icmp));
        return Ip6Frame(srcMac, dstMac, src, dst, 58, icmp, hopLimit);
    }

    /// <summary>ICMPv6 Neighbor Solicitation for <paramref name="target"/> (to its solicited-node group unless a unicast MAC is known).</summary>
    public static byte[] NeighborSolicitation(Mac srcMac, IPAddress srcIp, IPAddress target, Mac? knownTargetMac = null)
    {
        var body = new byte[4 + 16 + 8];
        target.TryWriteBytes(body.AsSpan(4), out _);
        body[20] = 1; body[21] = 1; // source link-layer address option
        srcMac.WriteTo(body.AsSpan(22));
        var dstIp = knownTargetMac is null ? IpUtil.SolicitedNode(target) : target;
        var dstMac = knownTargetMac ?? IpUtil.MulticastMac(dstIp);
        return Icmp6Frame(srcMac, dstMac, srcIp, dstIp, 135, 0, body);
    }

    /// <summary>ICMPv6 Echo Request (e.g. to ff02::1 to enumerate all IPv6 nodes).</summary>
    public static byte[] Icmp6Echo(Mac srcMac, IPAddress srcIp, IPAddress dst, Mac dstMac, ushort id, ushort seq, int payload = 16)
    {
        var body = new byte[4 + payload];
        BinaryPrimitives.WriteUInt16BigEndian(body, id);
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(2), seq);
        return Icmp6Frame(srcMac, dstMac, srcIp, dst, 128, 0, body, hopLimit: 255);
    }

    /// <summary>Wake-on-LAN magic packet as raw EtherType 0x0842 frame.</summary>
    public static byte[] WakeOnLan(Mac src, Mac target)
    {
        var payload = MagicPacket(target);
        var buf = new byte[14 + payload.Length];
        int o = WriteEthernet(buf, Mac.Broadcast, src, EthernetView.WakeOnLan);
        payload.CopyTo(buf.AsSpan(o));
        return buf;
    }

    public static byte[] MagicPacket(Mac target)
    {
        var p = new byte[6 + 16 * 6];
        for (int i = 0; i < 6; i++) p[i] = 0xFF;
        for (int r = 0; r < 16; r++) target.WriteTo(p.AsSpan(6 + r * 6));
        return p;
    }

    // ---- checksums ----

    public static ushort Checksum(ReadOnlySpan<byte> data, uint initial = 0)
    {
        uint sum = initial;
        int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += (uint)(data[i] << 8 | data[i + 1]);
        if (i < data.Length) sum += (uint)(data[i] << 8);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static ushort PseudoChecksum4(IPAddress src, IPAddress dst, byte proto, ReadOnlySpan<byte> l4)
    {
        Span<byte> ph = stackalloc byte[12];
        src.TryWriteBytes(ph, out _);
        dst.TryWriteBytes(ph[4..], out _);
        ph[8] = 0; ph[9] = proto;
        BinaryPrimitives.WriteUInt16BigEndian(ph[10..], (ushort)l4.Length);
        return Checksum(l4, Sum(ph));
    }

    public static ushort PseudoChecksum6(IPAddress src, IPAddress dst, byte next, ReadOnlySpan<byte> l4)
    {
        Span<byte> ph = stackalloc byte[40];
        src.TryWriteBytes(ph, out _);
        dst.TryWriteBytes(ph[16..], out _);
        BinaryPrimitives.WriteUInt32BigEndian(ph[32..], (uint)l4.Length);
        ph[39] = next;
        return Checksum(l4, Sum(ph));
    }

    private static uint Sum(ReadOnlySpan<byte> d)
    {
        uint s = 0;
        for (int i = 0; i + 1 < d.Length; i += 2) s += (uint)(d[i] << 8 | d[i + 1]);
        return s;
    }

    public static IPAddress ReadIp4(ReadOnlySpan<byte> b) => new(b[..4]);
    public static IPAddress ReadIp6(ReadOnlySpan<byte> b) => new(b[..16]);
    public static bool IsV4(IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetwork;
}
