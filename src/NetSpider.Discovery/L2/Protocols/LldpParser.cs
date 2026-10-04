using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>LLDP-MED network policy (voice VLAN etc.).</summary>
public sealed record LldpNetworkPolicy(int AppType, string AppName, bool UnknownPolicy, bool Tagged, int VlanId, int Priority, int Dscp);

/// <summary>Decoded LLDPDU (IEEE 802.1AB) including 802.1, 802.3 and LLDP-MED organizationally specific TLVs.</summary>
public sealed class LldpInfo
{
    public int ChassisIdSubtype { get; set; }
    public string? ChassisId { get; set; }
    /// <summary>Set when the chassis id is a MAC address (subtype 4).</summary>
    public Mac? ChassisMac { get; set; }
    public int PortIdSubtype { get; set; }
    public string? PortId { get; set; }
    public Mac? PortMac { get; set; }
    public int? Ttl { get; set; }
    public string? PortDescription { get; set; }
    public string? SystemName { get; set; }
    public string? SystemDescription { get; set; }
    public ushort? SystemCapabilities { get; set; }
    public ushort? EnabledCapabilities { get; set; }
    public List<IPAddress> ManagementAddresses { get; } = [];
    public List<Mac> ManagementMacs { get; } = [];

    // ---- IEEE 802.1 (00-80-C2) ----
    public int? PortVlanId { get; set; }
    public List<(int Vlan, string Name)> VlanNames { get; } = [];
    public List<(int Vlan, bool Supported, bool Enabled)> ProtocolVlans { get; } = [];
    public List<string> ProtocolIdentities { get; } = [];

    // ---- IEEE 802.3 (00-12-0F) ----
    public bool? AutonegSupported { get; set; }
    public bool? AutonegEnabled { get; set; }
    public ushort? AutonegAdvertised { get; set; }
    public int? MauType { get; set; }
    public long? SpeedMbps { get; set; }
    public string? Duplex { get; set; }
    /// <summary>"PSE" or "PD" from the MDI power support field.</summary>
    public string? PoePortClass { get; set; }
    public bool? PoeSupported { get; set; }
    public bool? PoeEnabled { get; set; }
    public int? PoePowerPair { get; set; }
    /// <summary>802.3 power class 0-4 (encoded as class+1 on the wire).</summary>
    public int? PoeClass { get; set; }
    public string? PoeType { get; set; }
    public double? PoeRequestedWatts { get; set; }
    public double? PoeAllocatedWatts { get; set; }
    public bool? LagCapable { get; set; }
    public bool? LagEnabled { get; set; }
    public uint? LagPortId { get; set; }
    public int? MaxFrameSize { get; set; }

    // ---- LLDP-MED (00-12-BB) ----
    public ushort? MedCapabilities { get; set; }
    public int? MedDeviceClass { get; set; }
    public List<LldpNetworkPolicy> NetworkPolicies { get; } = [];
    public string? MedPowerType { get; set; }
    public string? MedPowerSource { get; set; }
    public double? MedPowerWatts { get; set; }
    public string? HardwareRevision { get; set; }
    public string? FirmwareRevision { get; set; }
    public string? SoftwareRevision { get; set; }
    public string? SerialNumber { get; set; }
    public string? Manufacturer { get; set; }
    public string? ModelName { get; set; }
    public string? AssetId { get; set; }
    public string? Location { get; set; }

    public List<string> UnknownTlvs { get; } = [];

    public bool IsShutdown => Ttl == 0;
    public int? VoiceVlan => NetworkPolicies.FirstOrDefault(p => p.AppType == 1 && !p.UnknownPolicy && p.VlanId > 0)?.VlanId;

    public string? MedDeviceClassName => MedDeviceClass switch
    {
        1 => "Endpoint Class I",
        2 => "Endpoint Class II",
        3 => "Endpoint Class III",
        4 => "Network Connectivity",
        _ => null,
    };

    public IEnumerable<string> EnabledCapabilityNames => LldpParser.CapabilityNames(EnabledCapabilities ?? SystemCapabilities ?? 0);

    /// <summary>Port name for display: interface names stay, MAC-subtype port ids fall back to the description.</summary>
    public string? DisplayPort => PortIdSubtype == 3 ? PortDescription ?? PortId : PortId ?? PortDescription;
}

/// <summary>Manual byte parser for LLDP (EtherType 0x88CC).</summary>
public static class LldpParser
{
    public const uint Oui8021 = 0x0080C2, Oui8023 = 0x00120F, OuiMed = 0x0012BB;

    private static readonly string[] CapNames = ["Other", "Repeater", "Bridge", "WLAN AP", "Router", "Telephone", "DOCSIS", "Station", "C-VLAN", "S-VLAN", "TPMR"];

    public static IEnumerable<string> CapabilityNames(ushort caps)
    {
        for (int i = 0; i < CapNames.Length; i++) if ((caps & (1 << i)) != 0) yield return CapNames[i];
    }

    public const ushort CapBridge = 1 << 2, CapWlanAp = 1 << 3, CapRouter = 1 << 4, CapTelephone = 1 << 5, CapDocsis = 1 << 6, CapStation = 1 << 7;

    /// <param name="p">Ethernet payload (the LLDPDU).</param>
    public static LldpInfo? Parse(ReadOnlySpan<byte> p)
    {
        var info = new LldpInfo();
        int off = 0;
        bool sawChassis = false;
        try
        {
            while (off + 2 <= p.Length)
            {
                ushort hdr = BinaryPrimitives.ReadUInt16BigEndian(p[off..]);
                int type = hdr >> 9, len = hdr & 0x1FF;
                off += 2;
                if (type == 0) break;
                if (off + len > p.Length) break;
                var v = p.Slice(off, len);
                off += len;
                switch (type)
                {
                    case 1:
                        if (len < 2) break;
                        sawChassis = true;
                        info.ChassisIdSubtype = v[0];
                        info.ChassisId = FormatId(v[0], v[1..], isChassis: true, out var cm);
                        info.ChassisMac = cm;
                        break;
                    case 2:
                        if (len < 2) break;
                        info.PortIdSubtype = v[0];
                        info.PortId = FormatId(v[0], v[1..], isChassis: false, out var pm);
                        info.PortMac = pm;
                        break;
                    case 3:
                        if (len >= 2) info.Ttl = BinaryPrimitives.ReadUInt16BigEndian(v);
                        break;
                    case 4: info.PortDescription = TextUtil.Str(v); break;
                    case 5: info.SystemName = TextUtil.Str(v); break;
                    case 6: info.SystemDescription = TextUtil.Str(v); break;
                    case 7:
                        if (len >= 4)
                        {
                            info.SystemCapabilities = BinaryPrimitives.ReadUInt16BigEndian(v);
                            info.EnabledCapabilities = BinaryPrimitives.ReadUInt16BigEndian(v[2..]);
                        }
                        break;
                    case 8: ParseMgmtAddress(v, info); break;
                    case 127:
                        if (len < 4) break;
                        ParseOrgSpecific((uint)(v[0] << 16 | v[1] << 8 | v[2]), v[3], v[4..], info);
                        break;
                    default:
                        info.UnknownTlvs.Add($"type{type}");
                        break;
                }
            }
        }
        catch (ArgumentOutOfRangeException) { /* truncated TLV: keep what we have */ }
        return sawChassis ? info : null;
    }

    private static string? FormatId(byte subtype, ReadOnlySpan<byte> v, bool isChassis, out Mac? mac)
    {
        mac = null;
        int macSubtype = isChassis ? 4 : 3;
        int netSubtype = isChassis ? 5 : 4;
        if (subtype == macSubtype && v.Length >= 6)
        {
            mac = Mac.FromBytes(v);
            return mac.ToString();
        }
        if (subtype == netSubtype && v.Length >= 2)
        {
            if (v[0] == 1 && v.Length >= 5) return new IPAddress(v.Slice(1, 4)).ToString();
            if (v[0] == 2 && v.Length >= 17) return new IPAddress(v.Slice(1, 16)).ToString();
            return TextUtil.Hex(v);
        }
        return TextUtil.IsPrintable(v.TrimEnd((byte)0)) ? TextUtil.Str(v) : TextUtil.Hex(v);
    }

    private static void ParseMgmtAddress(ReadOnlySpan<byte> v, LldpInfo info)
    {
        if (v.Length < 2) return;
        int strLen = v[0];
        if (strLen < 2 || 1 + strLen > v.Length) return;
        byte family = v[1];
        var addr = v.Slice(2, strLen - 1);
        if (family == 1 && addr.Length == 4) info.ManagementAddresses.Add(new IPAddress(addr));
        else if (family == 2 && addr.Length == 16) info.ManagementAddresses.Add(new IPAddress(addr));
        else if (family == 6 && addr.Length == 6) info.ManagementMacs.Add(Mac.FromBytes(addr));
    }

    private static void ParseOrgSpecific(uint oui, byte subtype, ReadOnlySpan<byte> v, LldpInfo info)
    {
        switch (oui)
        {
            case Oui8021: Parse8021(subtype, v, info); break;
            case Oui8023: Parse8023(subtype, v, info); break;
            case OuiMed: ParseMed(subtype, v, info); break;
            default: info.UnknownTlvs.Add($"org {oui:X6}/{subtype}"); break;
        }
    }

    private static void Parse8021(byte subtype, ReadOnlySpan<byte> v, LldpInfo info)
    {
        switch (subtype)
        {
            case 1: // Port VLAN ID
                if (v.Length >= 2) { int pvid = BinaryPrimitives.ReadUInt16BigEndian(v); if (pvid > 0) info.PortVlanId = pvid; }
                break;
            case 2: // Port and protocol VLAN ID
                if (v.Length >= 3) info.ProtocolVlans.Add((BinaryPrimitives.ReadUInt16BigEndian(v[1..]), (v[0] & 0x02) != 0, (v[0] & 0x04) != 0));
                break;
            case 3: // VLAN name
                if (v.Length >= 3)
                {
                    int vid = BinaryPrimitives.ReadUInt16BigEndian(v);
                    int nlen = Math.Min(v[2], v.Length - 3);
                    info.VlanNames.Add((vid, TextUtil.Str(v.Slice(3, nlen)) ?? ""));
                }
                break;
            case 4: // Protocol identity
                if (v.Length >= 1) info.ProtocolIdentities.Add(TextUtil.Hex(v.Slice(1, Math.Min(v[0], v.Length - 1))));
                break;
            case 7: // Link aggregation (802.1AB-2009 location)
                ParseLag(v, info);
                break;
        }
    }

    private static void ParseLag(ReadOnlySpan<byte> v, LldpInfo info)
    {
        if (v.Length < 5) return;
        info.LagCapable = (v[0] & 0x01) != 0;
        info.LagEnabled = (v[0] & 0x02) != 0;
        info.LagPortId = BinaryPrimitives.ReadUInt32BigEndian(v[1..]);
    }

    private static void Parse8023(byte subtype, ReadOnlySpan<byte> v, LldpInfo info)
    {
        switch (subtype)
        {
            case 1: // MAC/PHY configuration/status
                if (v.Length < 5) break;
                info.AutonegSupported = (v[0] & 0x01) != 0;
                info.AutonegEnabled = (v[0] & 0x02) != 0;
                info.AutonegAdvertised = BinaryPrimitives.ReadUInt16BigEndian(v[1..]);
                int mau = BinaryPrimitives.ReadUInt16BigEndian(v[3..]);
                info.MauType = mau;
                (info.SpeedMbps, info.Duplex) = MauTypeToSpeed(mau);
                break;
            case 2: // Power via MDI
                if (v.Length < 3) break;
                info.PoePortClass = (v[0] & 0x01) != 0 ? "PSE" : "PD";
                info.PoeSupported = (v[0] & 0x02) != 0;
                info.PoeEnabled = (v[0] & 0x04) != 0;
                info.PoePowerPair = v[1];
                if (v[2] > 0) info.PoeClass = v[2] - 1;
                if (v.Length >= 8)
                {
                    info.PoeType = (v[3] >> 6) switch { 0 => "Type 2 PSE", 1 => "Type 2 PD", 2 => "Type 1 PSE", _ => "Type 1 PD" };
                    info.PoeRequestedWatts = BinaryPrimitives.ReadUInt16BigEndian(v[4..]) / 10.0;
                    info.PoeAllocatedWatts = BinaryPrimitives.ReadUInt16BigEndian(v[6..]) / 10.0;
                }
                break;
            case 3: // Link aggregation (legacy 802.3 location)
                ParseLag(v, info);
                break;
            case 4: // Maximum frame size
                if (v.Length >= 2) info.MaxFrameSize = BinaryPrimitives.ReadUInt16BigEndian(v);
                break;
        }
    }

    private static readonly string[] MedApps = ["Reserved", "Voice", "Voice Signaling", "Guest Voice", "Guest Voice Signaling", "Softphone Voice", "Video Conferencing", "Streaming Video", "Video Signaling"];

    private static void ParseMed(byte subtype, ReadOnlySpan<byte> v, LldpInfo info)
    {
        switch (subtype)
        {
            case 1: // capabilities
                if (v.Length >= 3) { info.MedCapabilities = BinaryPrimitives.ReadUInt16BigEndian(v); info.MedDeviceClass = v[2]; }
                break;
            case 2: // network policy
                if (v.Length >= 4)
                {
                    int app = v[0];
                    uint bits = (uint)(v[1] << 16 | v[2] << 8 | v[3]);
                    info.NetworkPolicies.Add(new LldpNetworkPolicy(app, app < MedApps.Length ? MedApps[app] : $"App {app}",
                        UnknownPolicy: (bits & 0x800000) != 0, Tagged: (bits & 0x400000) != 0,
                        VlanId: (int)((bits >> 9) & 0x0FFF), Priority: (int)((bits >> 6) & 0x07), Dscp: (int)(bits & 0x3F)));
                }
                break;
            case 3: // location identification
                if (v.Length >= 1) info.Location = v[0] == 3 ? TextUtil.Str(v[1..]) : $"format {v[0]}: {TextUtil.Hex(v[1..])}";
                break;
            case 4: // extended power via MDI
                if (v.Length >= 3)
                {
                    info.MedPowerType = (v[0] >> 6) switch { 0 => "PSE", 1 => "PD", _ => "Reserved" };
                    info.MedPowerSource = ((v[0] >> 4) & 0x03) switch { 0 => "Unknown", 1 => "Primary", 2 => "Backup", _ => "Reserved" };
                    info.MedPowerWatts = BinaryPrimitives.ReadUInt16BigEndian(v[1..]) / 10.0;
                }
                break;
            case 5: info.HardwareRevision = TextUtil.Str(v); break;
            case 6: info.FirmwareRevision = TextUtil.Str(v); break;
            case 7: info.SoftwareRevision = TextUtil.Str(v); break;
            case 8: info.SerialNumber = TextUtil.Str(v); break;
            case 9: info.Manufacturer = TextUtil.Str(v); break;
            case 10: info.ModelName = TextUtil.Str(v); break;
            case 11: info.AssetId = TextUtil.Str(v); break;
        }
    }

    /// <summary>Maps an IANA MAU type (RFC 4836 dot3MauType) to speed and duplex.</summary>
    public static (long? SpeedMbps, string? Duplex) MauTypeToSpeed(int mau)
    {
        long? speed = mau switch
        {
            >= 2 and <= 13 => 10,
            >= 14 and <= 20 => 100,
            >= 21 and <= 30 => 1000,
            >= 31 and <= 41 => 10_000,
            >= 44 and <= 46 => 100,
            >= 47 and <= 53 => 1000,
            54 or 55 or 57 or 58 => 10_000,
            56 => 1000,
            _ => null,
        };
        string? duplex = mau switch
        {
            10 or 12 or 15 or 17 or 19 or 21 or 23 or 25 or 27 or 29 => "half",
            11 or 13 or 16 or 18 or 20 or 22 or 24 or 26 or 28 or 30 => "full",
            >= 31 and <= 58 => "full",
            _ => null,
        };
        return (speed, duplex);
    }
}
