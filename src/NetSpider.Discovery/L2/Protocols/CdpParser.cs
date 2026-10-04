using System.Buffers.Binary;
using System.Net;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>Decoded Cisco Discovery Protocol v1/v2 packet.</summary>
public sealed class CdpInfo
{
    public int Version { get; set; }
    public int Ttl { get; set; }
    public string? DeviceId { get; set; }
    public List<IPAddress> Addresses { get; } = [];
    public List<IPAddress> ManagementAddresses { get; } = [];
    public string? PortId { get; set; }
    public uint? Capabilities { get; set; }
    public string? SoftwareVersion { get; set; }
    public string? Platform { get; set; }
    public List<string> IpPrefixes { get; } = [];
    public string? VtpDomain { get; set; }
    public int? NativeVlan { get; set; }
    /// <summary>true = full duplex, false = half.</summary>
    public bool? FullDuplex { get; set; }
    public int? VoiceVlan { get; set; }
    public int? PowerMilliwatts { get; set; }
    public int? PowerAvailableMilliwatts { get; set; }
    public int? Mtu { get; set; }
    public string? SystemName { get; set; }
    public string? Location { get; set; }

    public const uint CapRouter = 0x01, CapTransBridge = 0x02, CapSrBridge = 0x04, CapSwitch = 0x08, CapHost = 0x10, CapIgmp = 0x20,
        CapRepeater = 0x40, CapPhone = 0x80, CapRemote = 0x100, CapCvta = 0x200, CapMacRelay = 0x400;

    public IEnumerable<string> CapabilityNames
    {
        get
        {
            uint c = Capabilities ?? 0;
            if ((c & CapRouter) != 0) yield return "Router";
            if ((c & CapTransBridge) != 0) yield return "Trans-Bridge";
            if ((c & CapSrBridge) != 0) yield return "Source-Route-Bridge";
            if ((c & CapSwitch) != 0) yield return "Switch";
            if ((c & CapHost) != 0) yield return "Host";
            if ((c & CapIgmp) != 0) yield return "IGMP";
            if ((c & CapRepeater) != 0) yield return "Repeater";
            if ((c & CapPhone) != 0) yield return "Phone";
            if ((c & CapRemote) != 0) yield return "Remotely-Managed";
            if ((c & CapCvta) != 0) yield return "CVTA";
            if ((c & CapMacRelay) != 0) yield return "Two-port-MAC-Relay";
        }
    }

    /// <summary>First line of the software version (the full string is usually a multi-line IOS banner).</summary>
    public string? SoftwareVersionShort => SoftwareVersion?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
}

/// <summary>Manual parser for CDP (SNAP 00000C / 0x2000).</summary>
public static class CdpParser
{
    /// <param name="p">Payload after the LLC/SNAP header (starts with the CDP version byte).</param>
    public static CdpInfo? Parse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 4 || p[0] is not (1 or 2)) return null;
        var info = new CdpInfo { Version = p[0], Ttl = p[1] };
        int off = 4;
        try
        {
            while (off + 4 <= p.Length)
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(p[off..]);
                int len = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]);
                if (len < 4 || off + len > p.Length) break;
                var v = p.Slice(off + 4, len - 4);
                off += len;
                switch (type)
                {
                    case 0x0001: info.DeviceId = TextUtil.Str(v); break;
                    case 0x0002: ParseAddresses(v, info.Addresses); break;
                    case 0x0003: info.PortId = TextUtil.Str(v); break;
                    case 0x0004: if (v.Length >= 4) info.Capabilities = BinaryPrimitives.ReadUInt32BigEndian(v); break;
                    case 0x0005: info.SoftwareVersion = TextUtil.Str(v); break;
                    case 0x0006: info.Platform = TextUtil.Str(v); break;
                    case 0x0007:
                        for (int i = 0; i + 5 <= v.Length; i += 5) info.IpPrefixes.Add($"{new IPAddress(v.Slice(i, 4))}/{v[i + 4]}");
                        break;
                    case 0x0009: info.VtpDomain = TextUtil.Str(v); break;
                    case 0x000A: if (v.Length >= 2) info.NativeVlan = BinaryPrimitives.ReadUInt16BigEndian(v); break;
                    case 0x000B: if (v.Length >= 1) info.FullDuplex = v[0] != 0; break;
                    case 0x000E: // VoIP VLAN reply (appliance VLAN): appliance id (1) + vlan (2)
                        if (v.Length >= 3) info.VoiceVlan = BinaryPrimitives.ReadUInt16BigEndian(v[1..]);
                        break;
                    case 0x0010: if (v.Length >= 2) info.PowerMilliwatts = BinaryPrimitives.ReadUInt16BigEndian(v); break;
                    case 0x0011: if (v.Length >= 4) info.Mtu = (int)BinaryPrimitives.ReadUInt32BigEndian(v); break;
                    case 0x0014: info.SystemName = TextUtil.Str(v); break;
                    case 0x0016: ParseAddresses(v, info.ManagementAddresses); break;
                    case 0x0017: if (v.Length > 1) info.Location = TextUtil.Str(v[1..]); break;
                    case 0x001A: // power available: request id(2) mgmt id(2) available(4) max(4)
                        if (v.Length >= 8) info.PowerAvailableMilliwatts = (int)BinaryPrimitives.ReadUInt32BigEndian(v[4..]);
                        break;
                }
            }
        }
        catch (ArgumentOutOfRangeException) { }
        return info;
    }

    private static void ParseAddresses(ReadOnlySpan<byte> v, List<IPAddress> into)
    {
        if (v.Length < 4) return;
        uint count = BinaryPrimitives.ReadUInt32BigEndian(v);
        int off = 4;
        for (uint i = 0; i < count && off + 2 <= v.Length; i++)
        {
            byte protoType = v[off];
            int protoLen = v[off + 1];
            off += 2;
            if (off + protoLen + 2 > v.Length) return;
            var proto = v.Slice(off, protoLen);
            off += protoLen;
            int addrLen = BinaryPrimitives.ReadUInt16BigEndian(v[off..]);
            off += 2;
            if (off + addrLen > v.Length) return;
            var addr = v.Slice(off, addrLen);
            off += addrLen;
            if (protoType == 1 && protoLen == 1 && proto[0] == 0xCC && addrLen == 4) into.Add(new IPAddress(addr));
            else if (protoType == 2 && protoLen == 8 && proto[6] == 0x86 && proto[7] == 0xDD && addrLen == 16) into.Add(new IPAddress(addr));
        }
    }
}
