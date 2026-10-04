using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

public sealed record RaPrefix(IPAddress Prefix, int Length, bool OnLink, bool Autonomous, TimeSpan Valid, TimeSpan Preferred)
{
    public override string ToString() => $"{Prefix}/{Length}";
}

/// <summary>Decoded ICMPv6 Router Advertisement (type 134).</summary>
public sealed record RouterAdvert(int CurHopLimit, bool Managed, bool OtherConfig, string Preference, TimeSpan RouterLifetime,
    Mac? SourceLinkLayer, int? Mtu, IReadOnlyList<RaPrefix> Prefixes, IReadOnlyList<IPAddress> Rdnss, IReadOnlyList<string> RouteInfo);

/// <summary>Decoded Neighbor Solicitation (135) or Advertisement (136).</summary>
public sealed record NeighborMessage(int Type, IPAddress Target, Mac? LinkLayer, bool Router, bool Solicited, bool Override)
{
    public bool IsAdvertisement => Type == 136;
}

/// <summary>Manual parsers for the ICMPv6 Neighbor Discovery messages NetSpider cares about.</summary>
public static class NdpParser
{
    public const byte RouterSolicitation = 133, RouterAdvertisement = 134, NeighborSolicitation = 135, NeighborAdvertisement = 136, EchoRequest = 128, EchoReply = 129;

    /// <param name="p">ICMPv6 message starting at the type byte.</param>
    public static RouterAdvert? ParseRa(ReadOnlySpan<byte> p)
    {
        if (p.Length < 16 || p[0] != RouterAdvertisement) return null;
        int hop = p[4];
        byte flags = p[5];
        string pref = ((flags >> 3) & 0x03) switch { 1 => "High", 3 => "Low", 2 => "Reserved", _ => "Medium" };
        var lifetime = TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt16BigEndian(p[6..]));
        Mac? sll = null; int? mtu = null;
        var prefixes = new List<RaPrefix>();
        var rdnss = new List<IPAddress>();
        var routes = new List<string>();
        foreach (var (type, arr) in Options(p[16..]))
        {
            ReadOnlySpan<byte> v = arr;
            switch (type)
            {
                case 1: if (v.Length >= 6) sll = Mac.FromBytes(v); break;
                case 3:
                    if (v.Length >= 30)
                        prefixes.Add(new RaPrefix(new IPAddress(v.Slice(14, 16)), v[0], (v[1] & 0x80) != 0, (v[1] & 0x40) != 0,
                            TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(v[2..])), TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(v[6..]))));
                    break;
                case 5: if (v.Length >= 6) mtu = (int)BinaryPrimitives.ReadUInt32BigEndian(v[2..]); break;
                case 24:
                    if (v.Length >= 6)
                    {
                        int plen = v[0];
                        var pb = new byte[16];
                        v[6..].Slice(0, Math.Min(16, v.Length - 6)).CopyTo(pb);
                        routes.Add($"{new IPAddress(pb)}/{plen}");
                    }
                    break;
                case 25:
                    for (int i = 6; i + 16 <= v.Length; i += 16) rdnss.Add(new IPAddress(v.Slice(i, 16)));
                    break;
            }
        }
        return new RouterAdvert(hop, (flags & 0x80) != 0, (flags & 0x40) != 0, pref, lifetime, sll, mtu, prefixes, rdnss, routes);
    }

    /// <param name="p">ICMPv6 message starting at the type byte.</param>
    public static NeighborMessage? ParseNeighbor(ReadOnlySpan<byte> p)
    {
        if (p.Length < 24 || p[0] is not (NeighborSolicitation or NeighborAdvertisement)) return null;
        var target = new IPAddress(p.Slice(8, 16));
        byte flags = p[4];
        Mac? ll = null;
        foreach (var (type, v) in Options(p[24..]))
            if ((type == 1 || type == 2) && v.Length >= 6) { ll = Mac.FromBytes(v); break; }
        return new NeighborMessage(p[0], target, ll, (flags & 0x80) != 0, (flags & 0x40) != 0, (flags & 0x20) != 0);
    }

    /// <summary>Enumerates ND options as (type, value-without-type-and-length).</summary>
    private static List<(byte Type, byte[] Value)> Options(ReadOnlySpan<byte> o)
    {
        var list = new List<(byte, byte[])>();
        int off = 0;
        while (off + 2 <= o.Length)
        {
            int len = o[off + 1] * 8;
            if (len == 0 || off + len > o.Length) break;
            list.Add((o[off], o.Slice(off + 2, len - 2).ToArray()));
            off += len;
        }
        return list;
    }
}
