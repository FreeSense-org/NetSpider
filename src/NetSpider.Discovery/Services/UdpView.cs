using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services;

/// <summary>Lightweight UDP-over-IPv4/IPv6 extraction from a captured Ethernet frame. No allocation on the fast path.</summary>
internal readonly ref struct UdpView
{
    public bool Valid { get; init; }
    public int SrcPort { get; init; }
    public int DstPort { get; init; }
    public IPAddress? SrcIp { get; init; }
    public IPAddress? DstIp { get; init; }
    public ReadOnlySpan<byte> Payload { get; init; }

    public static UdpView TryParse(CapturedFrame frame)
    {
        var eth = frame.Eth;
        if (!eth.Valid) return default;
        var payload = frame.Payload;
        if (eth.EtherType == EthernetView.Ipv4) return ParseV4(payload);
        if (eth.EtherType == EthernetView.Ipv6) return ParseV6(payload);
        return default;
    }

    private static UdpView ParseV4(ReadOnlySpan<byte> ip)
    {
        if (ip.Length < 20) return default;
        int ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || ip.Length < ihl + 8) return default;
        if (ip[9] != 17) return default; // UDP
        var src = new IPAddress(ip.Slice(12, 4).ToArray());
        var dst = new IPAddress(ip.Slice(16, 4).ToArray());
        var udp = ip[ihl..];
        return ReadUdp(udp, src, dst);
    }

    private static UdpView ParseV6(ReadOnlySpan<byte> ip)
    {
        if (ip.Length < 40) return default;
        byte next = ip[6];
        int offset = 40;
        // Skip a couple of common extension headers to reach UDP.
        int guard = 0;
        while (next is 0 or 43 or 60 && ip.Length >= offset + 2 && guard++ < 8)
        {
            next = ip[offset];
            int hlen = (ip[offset + 1] + 1) * 8;
            offset += hlen;
        }
        if (next != 17 || ip.Length < offset + 8) return default;
        var src = new IPAddress(ip.Slice(8, 16).ToArray());
        var dst = new IPAddress(ip.Slice(24, 16).ToArray());
        return ReadUdp(ip[offset..], src, dst);
    }

    private static UdpView ReadUdp(ReadOnlySpan<byte> udp, IPAddress src, IPAddress dst)
    {
        if (udp.Length < 8) return default;
        int sp = BinaryPrimitives.ReadUInt16BigEndian(udp);
        int dp = BinaryPrimitives.ReadUInt16BigEndian(udp[2..]);
        int len = BinaryPrimitives.ReadUInt16BigEndian(udp[4..]);
        int end = Math.Min(udp.Length, Math.Max(8, len));
        return new UdpView { Valid = true, SrcPort = sp, DstPort = dp, SrcIp = src, DstIp = dst, Payload = udp[8..end] };
    }
}
