using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>Cisco Dynamic Trunking Protocol (SNAP 00000C/2004).</summary>
public sealed record DtpInfo(string? Domain, bool? Trunking, string? AdminMode, string? Encapsulation, Mac? Neighbor);

/// <summary>Cisco VLAN Trunking Protocol (SNAP 00000C/2003).</summary>
public sealed record VtpInfo(int Version, int Code, string CodeName, string? Domain, uint? ConfigRevision, IPAddress? Updater, IReadOnlyList<(int Id, string Name, bool Active)> Vlans);

/// <summary>802.3ad LACPDU (slow protocols 0x8809 subtype 1).</summary>
public sealed record LacpInfo(int ActorSystemPriority, Mac ActorSystem, int ActorKey, int ActorPort, byte ActorState,
    Mac PartnerSystem, int PartnerKey, int PartnerPort, byte PartnerState)
{
    public bool Aggregating => (ActorState & 0x04) != 0;
    public bool Synchronized => (ActorState & 0x08) != 0;
    public bool Active => (ActorState & 0x01) != 0;
    public string StateText => $"{(Active ? "active" : "passive")},{(Aggregating ? "aggregatable" : "individual")}{(Synchronized ? ",in-sync" : "")}{((ActorState & 0x20) != 0 ? ",distributing" : "")}";
}

/// <summary>EAPOL frame (0x888E).</summary>
public sealed record EapolInfo(int Version, int Type, string TypeName, int? EapCode, int? EapType)
{
    public bool IsAuthenticatorRequest => Type == 0 && EapCode == 1;
}

public static class L2SignalParsers
{
    /// <param name="p">Payload after the SNAP header.</param>
    public static DtpInfo? ParseDtp(ReadOnlySpan<byte> p)
    {
        if (p.Length < 1) return null;
        string? domain = null, admin = null, encap = null; bool? trunk = null; Mac? neighbor = null;
        int off = 1;
        while (off + 4 <= p.Length)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(p[off..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]);
            if (len < 4 || off + len > p.Length) break;
            var v = p.Slice(off + 4, len - 4);
            off += len;
            switch (type)
            {
                case 1: domain = TextUtil.Str(v); break;
                case 2:
                    if (v.Length >= 1)
                    {
                        trunk = (v[0] & 0x80) != 0;
                        admin = (v[0] & 0x07) switch { 1 => "on", 2 => "off", 3 => "desirable", 4 => "auto", _ => $"0x{v[0]:X2}" };
                    }
                    break;
                case 3:
                    if (v.Length >= 1) encap = (v[0] & 0x07) switch { 0 => "negotiate", 1 => "native", 2 => "isl", 5 => "802.1q", _ => $"0x{v[0]:X2}" };
                    break;
                case 4: if (v.Length >= 6) neighbor = Mac.FromBytes(v); break;
            }
        }
        return new DtpInfo(domain, trunk, admin, encap, neighbor);
    }

    /// <param name="p">Payload after the SNAP header.</param>
    public static VtpInfo? ParseVtp(ReadOnlySpan<byte> p)
    {
        if (p.Length < 36) return null;
        int version = p[0], code = p[1];
        int dlen = Math.Min(p[3], (byte)32);
        string? domain = TextUtil.Str(p.Slice(4, dlen));
        string codeName = code switch { 1 => "Summary", 2 => "Subset", 3 => "Request", 4 => "Join", _ => $"code {code}" };
        uint? rev = null; IPAddress? updater = null;
        var vlans = new List<(int, string, bool)>();
        if ((code == 1 || code == 2) && p.Length >= 40) rev = BinaryPrimitives.ReadUInt32BigEndian(p[36..]);
        if (code == 1 && p.Length >= 44) updater = new IPAddress(p.Slice(40, 4));
        if (code == 2)
        {
            int off = 40;
            while (off + 12 <= p.Length)
            {
                int infoLen = p[off];
                if (infoLen < 12 || off + infoLen > p.Length) break;
                byte status = p[off + 1];
                int nameLen = p[off + 3];
                int id = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 4)..]);
                string name = off + 12 + nameLen <= p.Length ? TextUtil.Str(p.Slice(off + 12, nameLen)) ?? "" : "";
                vlans.Add((id, name, status == 0));
                off += infoLen;
            }
        }
        return new VtpInfo(version, code, codeName, domain, rev, updater, vlans);
    }

    /// <param name="p">Payload of a 0x8809 frame.</param>
    public static LacpInfo? ParseLacp(ReadOnlySpan<byte> p)
    {
        if (p.Length < 40 || p[0] != 1 || p[2] != 1) return null;
        return new LacpInfo(
            BinaryPrimitives.ReadUInt16BigEndian(p[4..]), Mac.FromBytes(p.Slice(6, 6)), BinaryPrimitives.ReadUInt16BigEndian(p[12..]),
            BinaryPrimitives.ReadUInt16BigEndian(p[16..]), p[18],
            Mac.FromBytes(p.Slice(26, 6)), BinaryPrimitives.ReadUInt16BigEndian(p[32..]), BinaryPrimitives.ReadUInt16BigEndian(p[36..]), p[38]);
    }

    /// <param name="p">Payload of a 0x888E frame.</param>
    public static EapolInfo? ParseEapol(ReadOnlySpan<byte> p)
    {
        if (p.Length < 4) return null;
        int type = p[1];
        string name = type switch { 0 => "EAP-Packet", 1 => "EAPOL-Start", 2 => "EAPOL-Logoff", 3 => "EAPOL-Key", 4 => "EAPOL-ASF-Alert", 5 => "EAPOL-MKA", _ => $"type {type}" };
        int? code = null, eapType = null;
        if (type == 0 && p.Length >= 8)
        {
            code = p[4];
            if (p.Length >= 9 && code is 1 or 2) eapType = p[8];
        }
        return new EapolInfo(p[0], type, name, code, eapType);
    }
}
