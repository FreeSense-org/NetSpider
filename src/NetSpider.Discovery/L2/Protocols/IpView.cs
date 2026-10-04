using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>
/// Allocation-free view over an IPv4/IPv6 header inside an Ethernet payload. All offsets are relative to the span that
/// was passed to <see cref="TryParse"/>. For IPv6 the extension-header chain (hop-by-hop, routing, destination options,
/// fragment, AH) is walked so <see cref="Protocol"/> is the upper-layer protocol.
/// </summary>
public readonly record struct IpView(int Version, byte Protocol, byte Ttl, int L4Offset, int L4Length, bool FirstFragment)
{
    public const byte Icmp = 1, Igmp = 2, Tcp = 6, Udp = 17, Icmp6 = 58;

    public bool IsV4 => Version == 4;

    public IPAddress Source(ReadOnlySpan<byte> p) => IsV4 ? new IPAddress(p.Slice(12, 4)) : new IPAddress(p.Slice(8, 16));
    public IPAddress Destination(ReadOnlySpan<byte> p) => IsV4 ? new IPAddress(p.Slice(16, 4)) : new IPAddress(p.Slice(24, 16));
    public uint SourceV4Raw(ReadOnlySpan<byte> p) => BinaryPrimitives.ReadUInt32BigEndian(p[12..]);
    public uint DestinationV4Raw(ReadOnlySpan<byte> p) => BinaryPrimitives.ReadUInt32BigEndian(p[16..]);

    public ReadOnlySpan<byte> L4(ReadOnlySpan<byte> p) => p.Slice(L4Offset, L4Length);

    public static bool TryParse(ReadOnlySpan<byte> p, ushort etherType, out IpView view)
    {
        view = default;
        try
        {
            if (etherType == EthernetView.Ipv4)
            {
                if (p.Length < 20 || p[0] >> 4 != 4) return false;
                int ihl = (p[0] & 0x0F) * 4;
                if (ihl < 20 || p.Length < ihl) return false;
                int total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
                if (total < ihl) total = p.Length; // TSO / bogus length: trust the capture
                int end = Math.Min(total, p.Length);
                ushort frag = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
                bool first = (frag & 0x1FFF) == 0;
                view = new IpView(4, p[9], p[8], ihl, end - ihl, first);
                return true;
            }
            if (etherType == EthernetView.Ipv6)
            {
                if (p.Length < 40 || p[0] >> 4 != 6) return false;
                int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
                int end = Math.Min(40 + payloadLen, p.Length);
                byte next = p[6];
                int off = 40;
                bool first = true;
                for (int guard = 0; guard < 8; guard++)
                {
                    if (next is 0 or 43 or 60)
                    {
                        if (off + 2 > end) return false;
                        byte nh = p[off];
                        off += (p[off + 1] + 1) * 8;
                        next = nh;
                    }
                    else if (next == 44)
                    {
                        if (off + 8 > end) return false;
                        byte nh = p[off];
                        first = (BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]) & 0xFFF8) == 0;
                        off += 8;
                        next = nh;
                    }
                    else if (next == 51)
                    {
                        if (off + 2 > end) return false;
                        byte nh = p[off];
                        off += (p[off + 1] + 2) * 4;
                        next = nh;
                    }
                    else break;
                }
                if (off > end) return false;
                view = new IpView(6, next, p[7], off, end - off, first);
                return true;
            }
        }
        catch (ArgumentOutOfRangeException) { }
        return false;
    }
}

/// <summary>UDP header helper.</summary>
public readonly record struct UdpView(int SourcePort, int DestinationPort, int PayloadOffset, int PayloadLength)
{
    public static bool TryParse(ReadOnlySpan<byte> l4, out UdpView v)
    {
        v = default;
        if (l4.Length < 8) return false;
        int len = BinaryPrimitives.ReadUInt16BigEndian(l4[4..]);
        int payload = Math.Min(len >= 8 ? len - 8 : l4.Length - 8, l4.Length - 8);
        v = new UdpView(BinaryPrimitives.ReadUInt16BigEndian(l4), BinaryPrimitives.ReadUInt16BigEndian(l4[2..]), 8, payload);
        return true;
    }
}

internal static class TextUtil
{
    /// <summary>Decodes a TLV string: UTF-8, trailing NULs/whitespace trimmed; null when empty.</summary>
    public static string? Str(ReadOnlySpan<byte> b)
    {
        if (b.IsEmpty) return null;
        var s = System.Text.Encoding.UTF8.GetString(b).TrimEnd('\0', ' ', '\r', '\n', '\t');
        int nul = s.IndexOf('\0');
        if (nul >= 0) s = s[..nul];
        return s.Length == 0 ? null : s;
    }

    public static bool IsPrintable(ReadOnlySpan<byte> b)
    {
        foreach (var c in b) if (c < 0x20 || c > 0x7E) return false;
        return !b.IsEmpty;
    }

    public static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}
