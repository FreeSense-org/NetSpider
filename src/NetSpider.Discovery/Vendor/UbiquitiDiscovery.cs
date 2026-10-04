using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

public sealed record UbiquitiInfo
{
    public Mac? Hwaddr { get; init; }
    public IPAddress? IpAddress { get; init; }
    public string? Firmware { get; init; }
    public string? Hostname { get; init; }
    public string? PlatformShort { get; init; }
    public string? Essid { get; init; }
    public string? Model { get; init; }
    public string? ModelDisplay { get; init; }
    public uint? Uptime { get; init; }
}

/// <summary>Parses the Ubiquiti device-discovery (UDP 10001) v1 response TLV stream.</summary>
public static class UbiquitiDiscovery
{
    /// <summary>The v1 discovery request payload.</summary>
    public static readonly byte[] Request = { 0x01, 0x00, 0x00, 0x00 };

    public static UbiquitiInfo? Parse(ReadOnlySpan<byte> data)
    {
        // Header: version(1) cmd(1) length(2). We tolerate a 4-byte header then TLVs.
        if (data.Length < 4) return null;
        int pos = 4;
        var info = new UbiquitiInfo();
        while (pos + 3 <= data.Length)
        {
            byte type = data[pos];
            int len = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 1)..]);
            pos += 3;
            if (pos + len > data.Length) break;
            var val = data.Slice(pos, len);
            info = Apply(info, type, val);
            pos += len;
        }
        return info.Hwaddr is not null || info.Model is not null || info.Hostname is not null ? info : null;
    }

    private static UbiquitiInfo Apply(UbiquitiInfo info, byte type, ReadOnlySpan<byte> val)
    {
        switch (type)
        {
            case 0x01: // hwaddr (MAC)
                if (val.Length >= 6) info = info with { Hwaddr = Mac.FromBytes(val[..6]) };
                break;
            case 0x02: // hwaddr + ip
                if (val.Length >= 10)
                {
                    info = info with { Hwaddr = Mac.FromBytes(val[..6]), IpAddress = new IPAddress(val.Slice(6, 4).ToArray()) };
                }
                break;
            case 0x03: info = info with { Firmware = Ascii(val) }; break;
            case 0x0A: if (val.Length >= 4) info = info with { Uptime = BinaryPrimitives.ReadUInt32BigEndian(val) }; break;
            case 0x0B: info = info with { Hostname = Ascii(val) }; break;
            case 0x0C: info = info with { PlatformShort = Ascii(val) }; break;
            case 0x0D: info = info with { Essid = Ascii(val) }; break;
            case 0x14: info = info with { Model = Ascii(val) }; break;
            case 0x15: info = info with { ModelDisplay = Ascii(val) }; break;
        }
        return info;
    }

    private static string Ascii(ReadOnlySpan<byte> v) => System.Text.Encoding.UTF8.GetString(v).Trim('\0', ' ');

    /// <summary>Applies parsed info to a device as evidence/hostname/properties.</summary>
    public static bool Apply(Device device, UbiquitiInfo info)
    {
        bool changed = device.AddEvidence("vendor:ubiquiti", Fields.Brand, "Ubiquiti", Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Hostname)) changed |= device.SetHostname("vendor", info.Hostname);
        if (!string.IsNullOrWhiteSpace(info.ModelDisplay)) changed |= device.AddEvidence("vendor:ubiquiti", Fields.Model, info.ModelDisplay, Confidence.VendorProtocol);
        else if (!string.IsNullOrWhiteSpace(info.Model)) changed |= device.AddEvidence("vendor:ubiquiti", Fields.Model, info.Model, Confidence.VendorProtocol);
        if (!string.IsNullOrWhiteSpace(info.Firmware)) { changed |= device.AddEvidence("vendor:ubiquiti", Fields.Firmware, info.Firmware, Confidence.VendorProtocol); device.Firmware ??= info.Firmware; }
        if (!string.IsNullOrWhiteSpace(info.Essid)) changed |= device.SetProperty("ubnt.essid", info.Essid!);
        if (info.Uptime is { } up) changed |= device.SetProperty("ubnt.uptime", up.ToString());
        if (info.IpAddress is not null) changed |= device.AddIp(info.IpAddress);
        changed |= device.AddEvidence("vendor:ubiquiti", Fields.DeviceType, nameof(DeviceType.AccessPoint), Confidence.Port);
        return changed;
    }
}
