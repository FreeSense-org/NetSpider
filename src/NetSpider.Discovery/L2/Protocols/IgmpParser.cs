using System.Buffers.Binary;
using System.Net;

namespace NetSpider.Discovery.L2.Protocols;

public enum GroupMessageKind { Query, Report, Leave }

/// <summary>A decoded IGMP (v1/v2/v3) or MLD (v1/v2) message, normalized to joins/leaves.</summary>
public sealed record GroupMessage(GroupMessageKind Kind, string Protocol, int Version, IPAddress? QueryGroup, double? MaxResponseSeconds,
    IReadOnlyList<IPAddress> Joined, IReadOnlyList<IPAddress> Left)
{
    public bool IsGeneralQuery => Kind == GroupMessageKind.Query && (QueryGroup is null || QueryGroup.Equals(IPAddress.Any) || QueryGroup.Equals(IPAddress.IPv6Any));
}

/// <summary>Manual parsers for IGMP (IPv4 protocol 2) and MLD (ICMPv6 130/131/132/143).</summary>
public static class IgmpParser
{
    /// <param name="p">IGMP message (IP payload).</param>
    public static GroupMessage? ParseIgmp(ReadOnlySpan<byte> p)
    {
        if (p.Length < 8) return null;
        byte type = p[0];
        var group = new IPAddress(p.Slice(4, 4));
        switch (type)
        {
            case 0x11:
                {
                    int version = p.Length >= 12 ? 3 : p[1] == 0 ? 1 : 2;
                    double mrt = version == 3 ? DecodeIgmpV3Code(p[1]) / 10.0 : p[1] / 10.0;
                    return new GroupMessage(GroupMessageKind.Query, "IGMP", version, group, mrt, [], []);
                }
            case 0x12: return new GroupMessage(GroupMessageKind.Report, "IGMP", 1, null, null, [group], []);
            case 0x16: return new GroupMessage(GroupMessageKind.Report, "IGMP", 2, null, null, [group], []);
            case 0x17: return new GroupMessage(GroupMessageKind.Leave, "IGMP", 2, null, null, [], [group]);
            case 0x22:
                {
                    int n = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
                    var (joined, left) = ParseRecords(p[8..], n, 4);
                    return new GroupMessage(left.Count > 0 && joined.Count == 0 ? GroupMessageKind.Leave : GroupMessageKind.Report, "IGMP", 3, null, null, joined, left);
                }
        }
        return null;
    }

    /// <param name="p">ICMPv6 message (type, code, checksum, body).</param>
    public static GroupMessage? ParseMld(ReadOnlySpan<byte> p)
    {
        if (p.Length < 8) return null;
        byte type = p[0];
        switch (type)
        {
            case 130:
                {
                    if (p.Length < 24) return null;
                    int version = p.Length >= 28 ? 2 : 1;
                    var group = new IPAddress(p.Slice(8, 16));
                    double mrt = BinaryPrimitives.ReadUInt16BigEndian(p[4..]) / 1000.0;
                    return new GroupMessage(GroupMessageKind.Query, "MLD", version, group, mrt, [], []);
                }
            case 131:
                if (p.Length < 24) return null;
                return new GroupMessage(GroupMessageKind.Report, "MLD", 1, null, null, [new IPAddress(p.Slice(8, 16))], []);
            case 132:
                if (p.Length < 24) return null;
                return new GroupMessage(GroupMessageKind.Leave, "MLD", 1, null, null, [], [new IPAddress(p.Slice(8, 16))]);
            case 143:
                {
                    int n = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
                    var (joined, left) = ParseRecords(p[8..], n, 16);
                    return new GroupMessage(left.Count > 0 && joined.Count == 0 ? GroupMessageKind.Leave : GroupMessageKind.Report, "MLD", 2, null, null, joined, left);
                }
        }
        return null;
    }

    /// <summary>IGMPv3/MLDv2 group records. Exclude-mode (or include with sources) means member; TO_IN{} / BLOCK-all means leave.</summary>
    private static (List<IPAddress> Joined, List<IPAddress> Left) ParseRecords(ReadOnlySpan<byte> r, int count, int addrLen)
    {
        var joined = new List<IPAddress>();
        var left = new List<IPAddress>();
        int off = 0;
        for (int i = 0; i < count && off + 4 + addrLen <= r.Length; i++)
        {
            byte recType = r[off];
            int auxWords = r[off + 1];
            int nsrc = BinaryPrimitives.ReadUInt16BigEndian(r[(off + 2)..]);
            var group = new IPAddress(r.Slice(off + 4, addrLen));
            off += 4 + addrLen + nsrc * addrLen + auxWords * 4;
            switch (recType)
            {
                case 2: // MODE_IS_EXCLUDE
                case 4: // CHANGE_TO_EXCLUDE_MODE
                    joined.Add(group); break;
                case 1: // MODE_IS_INCLUDE
                case 5: // ALLOW_NEW_SOURCES
                    if (nsrc > 0) joined.Add(group); break;
                case 3: // CHANGE_TO_INCLUDE_MODE
                    if (nsrc == 0) left.Add(group); else joined.Add(group);
                    break;
                case 6: // BLOCK_OLD_SOURCES: still a member for other sources
                    break;
            }
        }
        return (joined, left);
    }

    private static int DecodeIgmpV3Code(byte code) =>
        code < 128 ? code : ((code & 0x0F) | 0x10) << (((code >> 4) & 0x07) + 3);

    /// <summary>IGMPv2 general query message (8 bytes) with checksum.</summary>
    public static byte[] BuildV2GeneralQuery(byte maxRespTenths)
    {
        var m = new byte[8];
        m[0] = 0x11; m[1] = maxRespTenths;
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(2), NetSpider.Core.Model.FrameBuilder.Checksum(m));
        return m;
    }
}
