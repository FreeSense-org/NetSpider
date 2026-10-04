using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Dns;

namespace NetSpider.Discovery.Services.Mdns;

/// <summary>
/// Applies the facts in an mDNS/DNS-SD message to a device: hostnames (.local A/AAAA owners), service instances
/// (PTR/SRV/TXT) and the vendor/model hints carried in well-known TXT keys.
/// </summary>
internal static class MdnsInterpreter
{
    private const string Source = "mdns";

    /// <summary>Interprets a parsed message against a known device (source MAC or IP already resolved).</summary>
    public static bool Apply(Device device, byte[] packet, DnsMessage msg)
    {
        bool changed = false;

        // Hostnames from queries (QM carries the asker's hostname in the question) and from A/AAAA owner names.
        foreach (var q in msg.Questions)
            if (IsLocalHost(q.Name))
                changed |= device.SetHostname(Source, StripLocal(q.Name));

        foreach (var rr in msg.AllRecords)
        {
            switch (rr.Type)
            {
                case DnsType.A or DnsType.Aaaa:
                    if (IsLocalHost(rr.Name))
                        changed |= device.SetHostname(Source, StripLocal(rr.Name));
                    if (rr.AsAddress() is { } ip) changed |= device.AddIp(ip);
                    break;

                case DnsType.Ptr:
                    var target = DnsCodec.ParseName(packet, rr);
                    if (!string.IsNullOrEmpty(target) && rr.Name.Contains("._", StringComparison.Ordinal))
                        changed |= ApplyServiceType(device, rr.Name, target);
                    break;

                case DnsType.Srv:
                    var srv = DnsCodec.ParseSrv(packet, rr);
                    if (srv is not null)
                    {
                        changed |= device.AddService(new ServiceInfo("tcp", srv.Port, rr.Name, ServiceTypeOf(rr.Name)));
                        if (IsLocalHost(srv.Target)) changed |= device.SetHostname(Source, StripLocal(srv.Target));
                    }
                    break;

                case DnsType.Txt:
                    var txt = DnsCodec.ParseTxt(rr.RData.Span);
                    if (txt.Count > 0) changed |= ApplyTxt(device, rr.Name, txt);
                    break;
            }
        }
        return changed;
    }

    private static bool ApplyServiceType(Device device, string owner, string instance)
    {
        // owner is e.g. "_googlecast._tcp.local"; record that the service type exists on the device.
        var type = ServiceTypeOf(owner);
        bool changed = device.AddService(new ServiceInfo("mdns", 0, instance, type));
        changed |= HintFromServiceType(device, owner);
        return changed;
    }

    private static string ServiceTypeOf(string name)
    {
        // Return the "_xxx._tcp" portion.
        int i = name.IndexOf("._", StringComparison.Ordinal);
        return i >= 0 ? name[i..].TrimEnd('.').Replace(".local", "") : name;
    }

    private static bool HintFromServiceType(Device device, string owner)
    {
        var t = owner.ToLowerInvariant();
        bool changed = false;
        if (t.Contains("_googlecast")) changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.MediaStreamer), Confidence.Mdns);
        else if (t.Contains("_spotify-connect")) changed |= device.AddEvidence(Source, Fields.Service, "Spotify Connect", Confidence.Mdns);
        else if (t.Contains("_airplay") || t.Contains("_raop")) { changed |= device.AddEvidence(Source, Fields.Service, "AirPlay", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.AudioStreamer), Confidence.Mdns); }
        else if (t.Contains("_sonos")) { changed |= device.AddEvidence(Source, Fields.Brand, "Sonos", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.AudioStreamer), Confidence.Mdns); }
        else if (t.Contains("_ipp") || t.Contains("_ipps") || t.Contains("_printer") || t.Contains("_pdl-datastream")) changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Printer), Confidence.Mdns);
        else if (t.Contains("_hap")) changed |= device.AddEvidence(Source, Fields.Service, "HomeKit", Confidence.Mdns);
        else if (t.Contains("_matter") || t.Contains("_matterc")) { changed |= device.AddEvidence(Source, Fields.Service, "Matter", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.IoT), Confidence.Mdns); }
        else if (t.Contains("_esphomelib")) { changed |= device.AddEvidence(Source, Fields.Brand, "ESPHome", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.IoT), Confidence.Mdns); }
        else if (t.Contains("_hue")) { changed |= device.AddEvidence(Source, Fields.Brand, "Philips Hue", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.SmartHomeHub), Confidence.Mdns); }
        else if (t.Contains("_elg")) changed |= device.AddEvidence(Source, Fields.Brand, "Elgato", Confidence.Mdns);
        else if (t.Contains("_shelly")) { changed |= device.AddEvidence(Source, Fields.Brand, "Shelly", Confidence.Mdns); changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.IoT), Confidence.Mdns); }
        else if (t.Contains("_smb") || t.Contains("_afpovertcp")) changed |= device.AddEvidence(Source, Fields.Service, "File sharing", Confidence.Mdns);
        return changed;
    }

    private static bool ApplyTxt(Device device, string owner, Dictionary<string, string> txt)
    {
        bool changed = false;
        foreach (var (k, v) in txt)
        {
            if (string.IsNullOrWhiteSpace(v)) continue;
            switch (k.ToLowerInvariant())
            {
                case "md": // Apple / Cast model code
                    changed |= device.AddEvidence(Source, Fields.Model, v, Confidence.Mdns);
                    if (v.Contains("Chromecast", StringComparison.OrdinalIgnoreCase) || owner.Contains("_googlecast", StringComparison.OrdinalIgnoreCase))
                        changed |= device.AddEvidence(Source, Fields.Brand, "Google", Confidence.Mdns);
                    break;
                case "model": case "mn": case "rpmd":
                    changed |= device.AddEvidence(Source, Fields.Model, v, Confidence.Mdns); break;
                case "am": // AirPlay model identifier, e.g. AppleTV6,2
                    changed |= device.AddEvidence(Source, Fields.Model, v, Confidence.Mdns);
                    changed |= device.AddEvidence(Source, Fields.Brand, "Apple", Confidence.Mdns);
                    break;
                case "ty": case "product": // printer friendly model
                    changed |= device.AddEvidence(Source, Fields.Model, v.Trim('(', ')'), Confidence.Mdns);
                    changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Printer), Confidence.Mdns);
                    break;
                case "usb_mfg": case "mfg": case "manufacturer":
                    changed |= device.AddEvidence(Source, Fields.Vendor, v, Confidence.Mdns); break;
                case "fn": // HomeKit / friendly name
                    changed |= device.SetHostname(Source, v); break;
                case "osxvers":
                    changed |= device.AddEvidence(Source, Fields.Os, "macOS (Darwin " + v + ")", Confidence.Mdns); break;
                case "srcvers": case "vs": case "fw": case "swversion":
                    changed |= device.SetProperty("mdns.firmware", v); break;
                case "deviceid":
                    changed |= device.SetProperty("mdns.deviceid", v); break;
                case "ci": // HomeKit accessory category id
                    var type = HomeKitCategory(v);
                    if (type is not null) changed |= device.AddEvidence(Source, Fields.DeviceType, type, Confidence.Mdns);
                    break;
            }
        }
        return changed;
    }

    private static string? HomeKitCategory(string ci) => ci switch
    {
        "2" => nameof(DeviceType.SmartHomeHub),   // bridge
        "3" => nameof(DeviceType.SmartPlug),       // fan/outlet-ish
        "5" => nameof(DeviceType.Light),
        "7" => nameof(DeviceType.SmartPlug),       // outlet
        "17" => nameof(DeviceType.Camera),         // IP camera
        "18" => nameof(DeviceType.Camera),         // video doorbell
        "26" => nameof(DeviceType.Tv),
        "28" => nameof(DeviceType.AudioStreamer),  // speaker
        _ => nameof(DeviceType.IoT),
    };

    private static bool IsLocalHost(string name) =>
        name.EndsWith(".local", StringComparison.OrdinalIgnoreCase) && !name.Contains("._", StringComparison.Ordinal);

    private static string StripLocal(string name) =>
        name.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? name[..^6] : name;
}
