using System.Buffers.Binary;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>Decoded STP / RSTP / MSTP / PVST+ BPDU.</summary>
public sealed record BpduInfo
{
    public required string Protocol { get; init; }
    public int Version { get; init; }
    public int Type { get; init; }
    public int Flags { get; init; }
    public bool IsTcn => Type == 0x80;
    /// <summary>Topology change flag set (or a TCN BPDU).</summary>
    public bool TopologyChange => IsTcn || (Flags & 0x01) != 0;
    public bool TopologyChangeAck => (Flags & 0x80) != 0;
    public int RootPriority { get; init; }
    public Mac RootMac { get; init; }
    public int RootPathCost { get; init; }
    public int BridgePriority { get; init; }
    public Mac BridgeMac { get; init; }
    public int PortId { get; init; }
    public double MessageAge { get; init; }
    public double MaxAge { get; init; }
    public double HelloTime { get; init; }
    public double ForwardDelay { get; init; }
    /// <summary>RSTP port role: Unknown, Alternate/Backup, Root, Designated.</summary>
    public string? PortRole { get; init; }
    public string? MstConfigName { get; init; }
    public int? MstRevision { get; init; }
    public int? MstiCount { get; init; }
    /// <summary>Originating VLAN from a PVST+ BPDU.</summary>
    public int? PvstVlan { get; init; }

    public string RootId => FormatId(RootPriority, RootMac);
    public string BridgeId => FormatId(BridgePriority, BridgeMac);
    /// <summary>The sending bridge is the (CIST) root.</summary>
    public bool IsRoot => !IsTcn && RootMac == BridgeMac && RootPriority == BridgePriority;

    /// <summary>"32769.00:11:22:33:44:55" (priority incl. system-id extension, then MAC).</summary>
    public static string FormatId(int priority, Mac mac) => $"{priority}.{mac}";
}

/// <summary>Manual parser for 802.1D/802.1w/802.1s BPDUs (LLC 42/42) and Cisco PVST+ (SNAP 00000C/010B).</summary>
public static class StpParser
{
    private static double T(ReadOnlySpan<byte> p, int o) => BinaryPrimitives.ReadUInt16BigEndian(p[o..]) / 256.0;

    /// <param name="p">Payload after the LLC (or SNAP) header, starting with the 2-byte protocol identifier.</param>
    public static BpduInfo? Parse(ReadOnlySpan<byte> p, bool pvst = false)
    {
        if (p.Length < 4 || BinaryPrimitives.ReadUInt16BigEndian(p) != 0) return null;
        int version = p[2], type = p[3];
        if (type == 0x80)
            return new BpduInfo { Protocol = pvst ? "PVST+" : "STP", Version = version, Type = type };
        if (p.Length < 35 || type is not (0x00 or 0x02)) return null;

        int flags = p[4];
        ushort rootPrio = BinaryPrimitives.ReadUInt16BigEndian(p[5..]);
        var rootMac = Mac.FromBytes(p.Slice(7, 6));
        int cost = (int)BinaryPrimitives.ReadUInt32BigEndian(p[13..]);
        ushort bridgePrio = BinaryPrimitives.ReadUInt16BigEndian(p[17..]);
        var bridgeMac = Mac.FromBytes(p.Slice(19, 6));
        int portId = BinaryPrimitives.ReadUInt16BigEndian(p[25..]);

        string protocol = version switch { 0 => "STP", 2 => "RSTP", >= 3 => "MSTP", _ => $"STP v{version}" };
        if (pvst) protocol = version >= 2 ? "Rapid-PVST+" : "PVST+";

        string? role = null;
        if (version >= 2)
            role = ((flags >> 2) & 0x03) switch { 1 => "Alternate/Backup", 2 => "Root", 3 => "Designated", _ => "Unknown" };

        string? mstName = null; int? mstRev = null, msti = null;
        int baseLen = version >= 2 ? 36 : 35;
        if (version >= 3 && !pvst && p.Length >= 102)
        {
            // MSTP: the field at the "bridge id" position is the CIST regional root; the transmitting bridge is the CIST bridge id.
            int v3Len = BinaryPrimitives.ReadUInt16BigEndian(p[36..]);
            mstName = TextUtil.Str(p.Slice(39, 32));
            mstRev = BinaryPrimitives.ReadUInt16BigEndian(p[71..]);
            bridgePrio = BinaryPrimitives.ReadUInt16BigEndian(p[93..]);
            bridgeMac = Mac.FromBytes(p.Slice(95, 6));
            msti = Math.Max(0, (v3Len - 64) / 16);
        }

        int? pvid = null;
        if (pvst)
        {
            // Originating VLAN TLV: type 0x0000, length 0x0002, VLAN id (a pad byte may precede it).
            for (int o = baseLen; o + 6 <= p.Length && o <= baseLen + 3; o++)
                if (p[o] == 0 && p[o + 1] == 0 && p[o + 2] == 0 && p[o + 3] == 2) { pvid = BinaryPrimitives.ReadUInt16BigEndian(p[(o + 4)..]); break; }
        }

        return new BpduInfo
        {
            Protocol = protocol, Version = version, Type = type, Flags = flags,
            RootPriority = rootPrio, RootMac = rootMac, RootPathCost = cost,
            BridgePriority = bridgePrio, BridgeMac = bridgeMac, PortId = portId,
            MessageAge = T(p, 27), MaxAge = T(p, 29), HelloTime = T(p, 31), ForwardDelay = T(p, 33),
            PortRole = role, MstConfigName = mstName, MstRevision = mstRev, MstiCount = msti, PvstVlan = pvid,
        };
    }
}
