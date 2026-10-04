using System.Net.Http;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

/// <summary>
/// Queries well-known HTTP device APIs (Sonos, Hue, Chromecast, Shelly, Tasmota, Home Assistant, Synology, UniFi,
/// Fritz!Box, Plex) when the matching port is open or an mDNS/SSDP hint suggests the device.
/// </summary>
public sealed class HttpDeviceProbe : IDeviceProbe
{
    private readonly IDeviceStore _store;
    private readonly ILogger<HttpDeviceProbe> _log;

    public HttpDeviceProbe(IDeviceStore store, ILogger<HttpDeviceProbe> log) { _store = store; _log = log; }

    public string Name => "HTTP device APIs";
    public int Order => 350;

    public bool AppliesTo(Device device, ScanContext ctx) => device.PrimaryIPv4 is not null && OpenPorts(device).Count > 0;

    private static HashSet<int> OpenPorts(Device device) =>
        device.Ports.Where(p => p.State == PortState.Open).Select(p => p.Port).ToHashSet();

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        var open = OpenPorts(device);
        var host = ip.ToString();
        using var http = Client(false);
        using var https = Client(true);
        bool changed = false;

        if (open.Contains(1400)) changed |= await Sonos(device, http, host, ct).ConfigureAwait(false);
        if (open.Contains(80) || open.Contains(443)) changed |= await Hue(device, open.Contains(443) ? https : http, host, open.Contains(443) ? 443 : 80, ct).ConfigureAwait(false);
        if (open.Contains(8008)) changed |= await Chromecast(device, http, host, ct).ConfigureAwait(false);
        if (open.Contains(80)) changed |= await Shelly(device, http, host, ct).ConfigureAwait(false);
        if (open.Contains(80)) changed |= await Tasmota(device, http, host, ct).ConfigureAwait(false);
        if (open.Contains(8123)) changed |= await HomeAssistant(device, http, host, ct).ConfigureAwait(false);
        if (open.Contains(5000) || open.Contains(5001)) changed |= await Synology(device, open.Contains(5001) ? https : http, host, open.Contains(5001) ? 5001 : 5000, ct).ConfigureAwait(false);
        if (open.Contains(443) || open.Contains(80)) changed |= await UniFiOs(device, open.Contains(443) ? https : http, host, open.Contains(443) ? 443 : 80, ct).ConfigureAwait(false);
        if (open.Contains(80) || open.Contains(443)) changed |= await FritzBox(device, open.Contains(443) ? https : http, host, open.Contains(443) ? 443 : 80, ct).ConfigureAwait(false);
        if (open.Contains(32400)) changed |= await Plex(device, http, host, ct).ConfigureAwait(false);

        if (changed) _store.NotifyChanged(device, "http");
    }

    private static HttpClient Client(bool https)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
    }

    private async Task<string?> GetAsync(HttpClient http, string url, CancellationToken ct)
    {
        try
        {
            using var resp = await http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex) { _log.LogDebug(ex, "GET {Url}", url); return null; }
    }

    private async Task<bool> Sonos(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var xml = await GetAsync(http, $"http://{host}:1400/xml/device_description.xml", ct).ConfigureAwait(false);
        if (xml is null) return false;
        bool changed = d.AddEvidence("vendor:sonos", Fields.Brand, "Sonos", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:sonos", Fields.DeviceType, nameof(DeviceType.AudioStreamer), Confidence.VendorProtocol);
        var root = TryXml(xml);
        if (root is not null)
        {
            var model = XmlVal(root, "modelName"); var room = XmlVal(root, "roomName"); var sw = XmlVal(root, "softwareVersion");
            if (model is not null) changed |= d.AddEvidence("vendor:sonos", Fields.Model, model, Confidence.VendorProtocol);
            if (room is not null) changed |= d.SetHostname("vendor", room);
            if (sw is not null) { changed |= d.AddEvidence("vendor:sonos", Fields.Firmware, sw, Confidence.VendorProtocol); d.Firmware ??= sw; }
        }
        return changed;
    }

    private async Task<bool> Hue(Device d, HttpClient http, string host, int port, CancellationToken ct)
    {
        var scheme = port == 443 ? "https" : "http";
        var json = await GetAsync(http, $"{scheme}://{host}/api/config", ct).ConfigureAwait(false);
        if (json is null || !json.TrimStart().StartsWith("{")) return false;
        var doc = TryJson(json);
        if (doc is null || !doc.Value.TryGetProperty("bridgeid", out _)) return false;
        bool changed = d.AddEvidence("vendor:hue", Fields.Brand, "Philips Hue", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:hue", Fields.DeviceType, nameof(DeviceType.SmartHomeHub), Confidence.VendorProtocol);
        changed |= ApplyJson(d, doc.Value, "vendor:hue", ("name", Fields.Hostname), ("modelid", Fields.Model), ("swversion", Fields.Firmware));
        return changed;
    }

    private async Task<bool> Chromecast(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var json = await GetAsync(http, $"http://{host}:8008/setup/eureka_info?params=name,device_info", ct).ConfigureAwait(false);
        if (json is null) return false;
        var doc = TryJson(json);
        if (doc is null) return false;
        bool changed = d.AddEvidence("vendor:chromecast", Fields.Brand, "Google", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:chromecast", Fields.DeviceType, nameof(DeviceType.MediaStreamer), Confidence.VendorProtocol);
        if (doc.Value.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String) changed |= d.SetHostname("vendor", name.GetString());
        if (doc.Value.TryGetProperty("device_info", out var di) && di.ValueKind == JsonValueKind.Object)
            changed |= ApplyJson(d, di, "vendor:chromecast", ("model_name", Fields.Model), ("manufacturer", Fields.Vendor));
        return changed;
    }

    private async Task<bool> Shelly(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var json = await GetAsync(http, $"http://{host}/shelly", ct).ConfigureAwait(false);
        if (json is null) return false;
        var doc = TryJson(json);
        if (doc is null) return false;
        if (!doc.Value.TryGetProperty("type", out _) && !doc.Value.TryGetProperty("model", out _) && !doc.Value.TryGetProperty("mac", out _)) return false;
        bool changed = d.AddEvidence("vendor:shelly", Fields.Brand, "Shelly", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:shelly", Fields.DeviceType, nameof(DeviceType.IoT), Confidence.VendorProtocol);
        changed |= ApplyJson(d, doc.Value, "vendor:shelly", ("type", Fields.Model), ("model", Fields.Model), ("fw", Fields.Firmware));
        return changed;
    }

    private async Task<bool> Tasmota(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var json = await GetAsync(http, $"http://{host}/cm?cmnd=Status%200", ct).ConfigureAwait(false);
        if (json is null || !json.Contains("Status", StringComparison.OrdinalIgnoreCase)) return false;
        var doc = TryJson(json);
        if (doc is null) return false;
        bool changed = d.AddEvidence("vendor:tasmota", Fields.Brand, "Tasmota", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:tasmota", Fields.DeviceType, nameof(DeviceType.IoT), Confidence.VendorProtocol);
        if (doc.Value.TryGetProperty("Status", out var st) && st.ValueKind == JsonValueKind.Object)
        {
            if (st.TryGetProperty("DeviceName", out var dn) && dn.ValueKind == JsonValueKind.String) changed |= d.SetHostname("vendor", dn.GetString());
            if (st.TryGetProperty("Module", out var mod)) changed |= d.SetProperty("tasmota.module", mod.ToString());
        }
        return changed;
    }

    private async Task<bool> HomeAssistant(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var json = await GetAsync(http, $"http://{host}:8123/manifest.json", ct).ConfigureAwait(false);
        if (json is null || !json.Contains("Home Assistant", StringComparison.OrdinalIgnoreCase)) return false;
        bool changed = d.AddEvidence("vendor:homeassistant", Fields.Brand, "Home Assistant", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:homeassistant", Fields.DeviceType, nameof(DeviceType.SmartHomeHub), Confidence.VendorProtocol);
        return changed;
    }

    private async Task<bool> Synology(Device d, HttpClient http, string host, int port, CancellationToken ct)
    {
        var scheme = port == 5001 ? "https" : "http";
        var json = await GetAsync(http, $"{scheme}://{host}:{port}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query", ct).ConfigureAwait(false);
        var title = await GetAsync(http, $"{scheme}://{host}:{port}/", ct).ConfigureAwait(false);
        bool isSyno = (json?.Contains("SYNO.API", StringComparison.OrdinalIgnoreCase) ?? false) || (title?.Contains("Synology", StringComparison.OrdinalIgnoreCase) ?? false);
        if (!isSyno) return false;
        bool changed = d.AddEvidence("vendor:synology", Fields.Brand, "Synology", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:synology", Fields.DeviceType, nameof(DeviceType.Nas), Confidence.VendorProtocol);
        return changed;
    }

    private async Task<bool> UniFiOs(Device d, HttpClient http, string host, int port, CancellationToken ct)
    {
        var scheme = port == 443 ? "https" : "http";
        var json = await GetAsync(http, $"{scheme}://{host}/api/system", ct).ConfigureAwait(false);
        if (json is null || !json.TrimStart().StartsWith("{")) return false;
        var doc = TryJson(json);
        if (doc is null) return false;
        bool changed = d.AddEvidence("vendor:ubiquiti", Fields.Brand, "Ubiquiti", Confidence.VendorProtocol);
        changed |= ApplyJson(d, doc.Value, "vendor:ubiquiti", ("name", Fields.Hostname), ("hardware", Fields.Model), ("version", Fields.Firmware));
        return changed;
    }

    private async Task<bool> FritzBox(Device d, HttpClient http, string host, int port, CancellationToken ct)
    {
        var scheme = port == 443 ? "https" : "http";
        var xml = await GetAsync(http, $"{scheme}://{host}/jason_boxinfo.xml", ct).ConfigureAwait(false);
        if (xml is null || !xml.Contains("boxinfo", StringComparison.OrdinalIgnoreCase)) return false;
        bool changed = d.AddEvidence("vendor:avm", Fields.Brand, "AVM", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:avm", Fields.DeviceType, nameof(DeviceType.Router), Confidence.VendorProtocol);
        var root = TryXml(xml);
        if (root is not null)
        {
            var name = XmlVal(root, "Name"); var fw = XmlVal(root, "Version");
            if (name is not null) changed |= d.AddEvidence("vendor:avm", Fields.Model, name, Confidence.VendorProtocol);
            if (fw is not null) { changed |= d.AddEvidence("vendor:avm", Fields.Firmware, fw, Confidence.VendorProtocol); d.Firmware ??= fw; }
        }
        return changed;
    }

    private async Task<bool> Plex(Device d, HttpClient http, string host, CancellationToken ct)
    {
        var xml = await GetAsync(http, $"http://{host}:32400/identity", ct).ConfigureAwait(false);
        if (xml is null || !xml.Contains("MediaContainer", StringComparison.OrdinalIgnoreCase)) return false;
        bool changed = d.AddEvidence("vendor:plex", Fields.Brand, "Plex", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:plex", Fields.Service, "Plex Media Server", Confidence.VendorProtocol);
        changed |= d.AddEvidence("vendor:plex", Fields.DeviceType, nameof(DeviceType.Server), Confidence.Port);
        return changed;
    }

    // ---- parse helpers ----
    private static JsonElement? TryJson(string s)
    {
        try { using var doc = JsonDocument.Parse(s); return doc.RootElement.Clone(); } catch { return null; }
    }

    private static XElement? TryXml(string s) { try { return XDocument.Parse(s).Root; } catch { return null; } }

    private static string? XmlVal(XElement root, string local) =>
        root.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase))?.Value?.Trim();

    private static bool ApplyJson(Device d, JsonElement obj, string source, params (string Key, string Field)[] map)
    {
        bool changed = false;
        foreach (var (key, field) in map)
            if (obj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()))
            {
                var value = v.GetString()!;
                if (field == Fields.Hostname) changed |= d.SetHostname("vendor", value);
                else changed |= d.AddEvidence(source, field, value, Confidence.VendorProtocol);
            }
        return changed;
    }
}
