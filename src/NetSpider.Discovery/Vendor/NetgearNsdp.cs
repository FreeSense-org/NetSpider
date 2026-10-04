using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

public sealed record NsdpInfo
{
    public string? Model { get; init; }
    public string? Name { get; init; }
    public Mac? Mac { get; init; }
    public IPAddress? Ip { get; init; }
    public IPAddress? Netmask { get; init; }
    public IPAddress? Gateway { get; init; }
    public string? Firmware { get; init; }
    public bool? DhcpEnabled { get; init; }
    public int? PortCount { get; init; }
}

/// <summary>Netgear Switch Discovery Protocol (NSDP) request builder and response parser (UDP 63322/63324).</summary>
public static class NetgearNsdp
{
    private const int HeaderLen = 32;
    private static readonly byte[] Signature = Encoding.ASCII.GetBytes("NSDP");

    // requested TLV types for a read
    public static readonly ushort[] ReadTypes = { 0x0001, 0x0003, 0x0004, 0x0006, 0x0007, 0x0008, 0x000D, 0x000B, 0x6000 };

    /// <summary>Builds an NSDP read request (operation 0x01) from our MAC, asking for the standard TLV set.</summary>
    public static byte[] BuildReadRequest(Mac hostMac, uint sequence)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write((byte)1);  // version
        w.Write((byte)1);  // operation: read request
        w.Write((ushort)0); // status
        w.Write((uint)0);   // reserved
        var hm = hostMac.ToBytes(); w.Write(hm);
        w.Write(new byte[6]); // device mac = broadcast
        w.Write((ushort)0);   // reserved
        Span<byte> seq = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(seq, (ushort)(sequence & 0xFFFF));
        w.Write(seq);
        w.Write(Signature);
        w.Write((uint)0);     // reserved
        Span<byte> tlv = stackalloc byte[4];
        foreach (var t in ReadTypes)
        {
            BinaryPrimitives.WriteUInt16BigEndian(tlv, t);
            BinaryPrimitives.WriteUInt16BigEndian(tlv[2..], 0);
            w.Write(tlv);
        }
        Span<byte> end = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(end, 0xFFFF);
        BinaryPrimitives.WriteUInt16BigEndian(end[2..], 0);
        w.Write(end);
        return ms.ToArray();
    }

    public static NsdpInfo? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderLen + 4) return null;
        if (!data.Slice(24, 4).SequenceEqual(Signature)) return null;
        int pos = HeaderLen;
        var info = new NsdpInfo();
        bool any = false;
        while (pos + 4 <= data.Length)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            ushort len = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            pos += 4;
            if (type == 0xFFFF) break;
            if (pos + len > data.Length) break;
            var val = data.Slice(pos, len);
            info = Apply(info, type, val, ref any);
            pos += len;
        }
        return any ? info : null;
    }

    private static NsdpInfo Apply(NsdpInfo info, ushort type, ReadOnlySpan<byte> val, ref bool any)
    {
        any = true;
        switch (type)
        {
            case 0x0001: info = info with { Model = Str(val) }; break;
            case 0x0003: info = info with { Name = Str(val) }; break;
            case 0x0004: if (val.Length >= 6) info = info with { Mac = Mac.FromBytes(val[..6]) }; break;
            case 0x0006: if (val.Length >= 4) info = info with { Ip = new IPAddress(val[..4].ToArray()) }; break;
            case 0x0007: if (val.Length >= 4) info = info with { Netmask = new IPAddress(val[..4].ToArray()) }; break;
            case 0x0008: if (val.Length >= 4) info = info with { Gateway = new IPAddress(val[..4].ToArray()) }; break;
            case 0x000D: info = info with { Firmware = Str(val) }; break;
            case 0x000B: if (val.Length >= 1) info = info with { DhcpEnabled = val[0] != 0 }; break;
            case 0x6000: info = info with { PortCount = val.Length }; break;
            default: break;
        }
        return info;
    }

    private static string Str(ReadOnlySpan<byte> v) => Encoding.UTF8.GetString(v).Trim('\0', ' ');

    public static bool Apply(Device device, NsdpInfo info)
    {
        bool changed = device.AddEvidence("vendor:netgear", Fields.Brand, "Netgear", Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Model)) changed |= device.AddEvidence("vendor:netgear", Fields.Model, info.Model, Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Name)) changed |= device.SetHostname("vendor", info.Name);
        if (!string.IsNullOrWhiteSpace(info.Firmware)) { changed |= device.AddEvidence("vendor:netgear", Fields.Firmware, info.Firmware, Confidence.VendorProtocol); device.Firmware ??= info.Firmware; }
        if (info.Ip is not null) changed |= device.AddIp(info.Ip);
        if (info.DhcpEnabled is { } dh) changed |= device.SetProperty("nsdp.dhcp", dh ? "on" : "off");
        if (info.PortCount is { } pc) changed |= device.SetProperty("nsdp.ports", pc.ToString());
        changed |= device.AddEvidence("vendor:netgear", Fields.DeviceType, nameof(DeviceType.AccessSwitch), Confidence.Port);
        return changed;
    }
}
