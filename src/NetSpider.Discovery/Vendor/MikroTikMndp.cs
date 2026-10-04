using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

public sealed record MndpInfo
{
    public Mac? Mac { get; init; }
    public string? Identity { get; init; }
    public string? Version { get; init; }
    public string? Platform { get; init; }
    public uint? Uptime { get; init; }
    public string? SoftwareId { get; init; }
    public string? Board { get; init; }
    public string? InterfaceName { get; init; }
    public IPAddress? IPv4 { get; init; }
    public IPAddress? IPv6 { get; init; }
}

/// <summary>Parses the MikroTik Neighbor Discovery Protocol (MNDP, UDP 5678) TLV payload.</summary>
public static class MikroTikMndp
{
    /// <summary>An empty 4-byte request elicits MNDP replies.</summary>
    public static readonly byte[] Request = { 0x00, 0x00, 0x00, 0x00 };

    public static MndpInfo? Parse(ReadOnlySpan<byte> data)
    {
        // 4-byte header (seq/type) then TLVs: type(2 BE), len(2 BE), value.
        if (data.Length < 4) return null;
        int pos = 4;
        var info = new MndpInfo();
        bool any = false;
        while (pos + 4 <= data.Length)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            ushort len = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            pos += 4;
            if (pos + len > data.Length) break;
            var val = data.Slice(pos, len);
            info = Apply(info, type, val, ref any);
            pos += len;
        }
        return any ? info : null;
    }

    private static MndpInfo Apply(MndpInfo info, ushort type, ReadOnlySpan<byte> val, ref bool any)
    {
        any = true;
        switch (type)
        {
            case 1: if (val.Length >= 6) info = info with { Mac = Mac.FromBytes(val[..6]) }; break;
            case 5: info = info with { Identity = Str(val) }; break;
            case 7: info = info with { Version = Str(val) }; break;
            case 8: info = info with { Platform = Str(val) }; break;
            case 10: if (val.Length >= 4) info = info with { Uptime = BinaryPrimitives.ReadUInt32LittleEndian(val) }; break;
            case 11: info = info with { SoftwareId = Str(val) }; break;
            case 12: info = info with { Board = Str(val) }; break;
            case 15: if (val.Length >= 16) info = info with { IPv6 = new IPAddress(val[..16].ToArray()) }; break;
            case 16: info = info with { InterfaceName = Str(val) }; break;
            case 17: if (val.Length >= 4) info = info with { IPv4 = new IPAddress(val[..4].ToArray()) }; break;
            default: any = any || true; break;
        }
        return info;
    }

    private static string Str(ReadOnlySpan<byte> v) => System.Text.Encoding.UTF8.GetString(v).Trim('\0', ' ');

    public static bool Apply(Device device, MndpInfo info)
    {
        bool changed = device.AddEvidence("vendor:mikrotik", Fields.Brand, "MikroTik", Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Identity)) changed |= device.SetHostname("vendor", info.Identity);
        if (!string.IsNullOrWhiteSpace(info.Board)) changed |= device.AddEvidence("vendor:mikrotik", Fields.Model, info.Board, Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Platform)) changed |= device.SetProperty("mndp.platform", info.Platform!);
        if (!string.IsNullOrWhiteSpace(info.Version)) { changed |= device.AddEvidence("vendor:mikrotik", Fields.Firmware, info.Version, Confidence.VendorProtocol); device.Firmware ??= info.Version; }
        if (!string.IsNullOrWhiteSpace(info.SoftwareId)) changed |= device.SetProperty("mndp.softwareId", info.SoftwareId!);
        if (!string.IsNullOrWhiteSpace(info.InterfaceName)) changed |= device.SetProperty("mndp.interface", info.InterfaceName!);
        if (info.Uptime is { } up) changed |= device.SetProperty("mndp.uptime", up.ToString());
        if (info.IPv4 is not null) changed |= device.AddIp(info.IPv4);
        if (info.IPv6 is not null) changed |= device.AddIp(info.IPv6);
        changed |= device.AddEvidence("vendor:mikrotik", Fields.DeviceType, nameof(DeviceType.Router), Confidence.Port);
        return changed;
    }
}
