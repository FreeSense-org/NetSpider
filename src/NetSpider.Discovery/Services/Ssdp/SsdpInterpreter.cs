using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Ssdp;

internal static class SsdpInterpreter
{
    private const string Source = "ssdp";

    /// <summary>Parses the HTTP-like headers of an SSDP NOTIFY or M-SEARCH response into a case-insensitive map.</summary>
    public static Dictionary<string, string> ParseHeaders(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n'))
        {
            var l = line.TrimEnd('\r');
            int c = l.IndexOf(':');
            if (c <= 0) continue;
            var key = l[..c].Trim();
            var val = l[(c + 1)..].Trim();
            if (key.Length > 0 && !map.ContainsKey(key)) map[key] = val;
        }
        return map;
    }

    /// <summary>Records SERVER/USN hints from an SSDP advertisement header block.</summary>
    public static bool ApplyHeaders(Device device, Dictionary<string, string> headers)
    {
        bool changed = false;
        if (headers.TryGetValue("SERVER", out var server) && !string.IsNullOrWhiteSpace(server))
        {
            changed |= device.SetProperty("ssdp.server", server);
            var os = OsFromServer(server);
            if (os is not null) changed |= device.AddEvidence(Source, Fields.Os, os, Confidence.Ssdp);
        }
        if (headers.TryGetValue("USN", out var usn)) changed |= device.SetProperty("ssdp.usn", usn);
        return changed;
    }

    public static string? OsFromServer(string server)
    {
        // SSDP SERVER is "OS/version UPnP/1.1 product/version".
        var first = server.Split(' ').FirstOrDefault();
        if (string.IsNullOrWhiteSpace(first) || first.StartsWith("UPnP", StringComparison.OrdinalIgnoreCase)) return null;
        return first;
    }

    /// <summary>Applies a parsed UPnP description device tree to a NetSpider device.</summary>
    public static bool Apply(Device device, SsdpDescription desc)
    {
        bool changed = ApplyHeadersFromDesc(device, desc);
        foreach (var d in desc.AllDevices())
            changed |= ApplyDevice(device, d);
        return changed;
    }

    private static bool ApplyHeadersFromDesc(Device device, SsdpDescription desc)
    {
        bool changed = device.SetProperty("ssdp.location", desc.Location.AbsoluteUri);
        if (!string.IsNullOrWhiteSpace(desc.Server))
        {
            changed |= device.SetProperty("ssdp.server", desc.Server);
            var os = OsFromServer(desc.Server!);
            if (os is not null) changed |= device.AddEvidence(Source, Fields.Os, os, Confidence.Ssdp);
        }
        return changed;
    }

    private static bool ApplyDevice(Device device, UpnpDevice d)
    {
        bool changed = false;
        if (!string.IsNullOrWhiteSpace(d.FriendlyName)) changed |= device.SetHostname(Source, d.FriendlyName);
        if (!string.IsNullOrWhiteSpace(d.Manufacturer)) changed |= device.AddEvidence(Source, Fields.Vendor, d.Manufacturer, Confidence.Ssdp);
        if (!string.IsNullOrWhiteSpace(d.ModelName)) changed |= device.AddEvidence(Source, Fields.Model, d.ModelName, Confidence.Ssdp);
        if (!string.IsNullOrWhiteSpace(d.ModelNumber)) changed |= device.AddEvidence(Source, Fields.ModelNumber, d.ModelNumber, Confidence.Ssdp);
        if (!string.IsNullOrWhiteSpace(d.ModelDescription)) changed |= device.AddEvidence(Source, Fields.Description, d.ModelDescription, Confidence.Ssdp);
        if (!string.IsNullOrWhiteSpace(d.SerialNumber)) changed |= device.AddEvidence(Source, Fields.Serial, d.SerialNumber, Confidence.Ssdp);
        if (!string.IsNullOrWhiteSpace(d.PresentationUrl)) { changed |= device.AddEvidence(Source, Fields.PresentationUrl, d.PresentationUrl, Confidence.Ssdp); changed |= device.SetProperty("upnp.presentationUrl", d.PresentationUrl!); }
        if (!string.IsNullOrWhiteSpace(d.ManufacturerUrl)) changed |= device.SetProperty("upnp.manufacturerUrl", d.ManufacturerUrl!);
        if (!string.IsNullOrWhiteSpace(d.Udn)) changed |= device.SetProperty("upnp.udn", d.Udn!);
        if (!string.IsNullOrWhiteSpace(d.IconUrl))
        {
            device.IconUrl ??= d.IconUrl;
            changed |= device.AddEvidence(Source, Fields.IconUrl, d.IconUrl, Confidence.Ssdp);
        }
        var type = TypeFromDeviceType(d.DeviceType);
        if (type is not null) changed |= device.AddEvidence(Source, Fields.DeviceType, type, Confidence.Ssdp);
        return changed;
    }

    public static string? TypeFromDeviceType(string? deviceType)
    {
        if (string.IsNullOrWhiteSpace(deviceType)) return null;
        var t = deviceType.ToLowerInvariant();
        if (t.Contains("internetgatewaydevice")) return nameof(DeviceType.Router);
        if (t.Contains("wandevice") || t.Contains("wanconnectiondevice")) return nameof(DeviceType.Router);
        if (t.Contains("mediarenderer") || t.Contains("zoneplayer")) return nameof(DeviceType.AudioStreamer);
        if (t.Contains("mediaserver")) return nameof(DeviceType.Server);
        if (t.Contains("printer")) return nameof(DeviceType.Printer);
        if (t.Contains("digitalsecuritycamera") || t.Contains("camera")) return nameof(DeviceType.Camera);
        if (t.Contains("basic")) return null;
        return null;
    }
}
