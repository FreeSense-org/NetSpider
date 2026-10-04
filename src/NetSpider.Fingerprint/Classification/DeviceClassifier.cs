using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Fingerprint.Classification;

/// <summary>
/// Evidence-scoring classifier. Every fact about a device (evidence, hostnames, services, mDNS types/TXT, ports, TTL,
/// DHCP, SNMP, certificates, OUI, flags, LLDP capabilities) becomes a weighted <see cref="Signal"/>; rules from
/// <see cref="ClassifierRules"/> turn signals into votes, and votes for the same value are combined with noisy-OR so that
/// independent agreeing sources reinforce each other while a single strong source beats many weak ones.
/// </summary>
public sealed class DeviceClassifier : IDeviceClassifier
{
    private readonly ILogger<DeviceClassifier> _log;
    private readonly IOuiLookup? _oui;

    public DeviceClassifier(ILogger<DeviceClassifier> log, IOuiLookup? oui = null)
    {
        _log = log;
        _oui = oui;
    }

    public readonly record struct Signal(Channel Channel, string Text, double Confidence);

    /// <summary>The full scoring result (exposed for the inspector/tests).</summary>
    public sealed record Result(string? Brand, double BrandScore, string? Model, double ModelScore, string? Firmware, string? Os, double OsScore,
        DeviceType Type, double TypeScore, double IdentityConfidence);

    private static readonly Regex AppleModelCode = new(@"^(?<fam>iPhone|iPad|iPod|AppleTV|AudioAccessory|MacBookPro|MacBookAir|MacBook|iMacPro|iMac|Macmini|MacPro|Mac|Watch)(?<maj>\d+),(?<min>\d+)$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex AndroidDhcp = new(@"android-dhcp-(?<v>\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex OidEnterprise = new(@"^\.?1\.3\.6\.1\.4\.1\.(?<n>\d+)", RegexOptions.Compiled);

    private static readonly HashSet<string> ModelTxtKeys = new(StringComparer.OrdinalIgnoreCase) { "model", "md", "am", "ty", "product", "usb_MDL", "modelName", "rpMd", "mdl" };
    private static readonly HashSet<string> VendorTxtKeys = new(StringComparer.OrdinalIgnoreCase) { "manufacturer", "usb_MFG", "mfg", "vendor", "brand" };
    private static readonly HashSet<string> FirmwareTxtKeys = new(StringComparer.OrdinalIgnoreCase) { "fv", "fw", "firmware", "fwversion", "osvers", "version" };

    private static readonly string[] FirewallBrands = ["Fortinet", "Netgate", "OPNsense", "SonicWall", "WatchGuard", "Sophos", "Palo Alto"];

    public bool Classify(Device device)
    {
        try
        {
            if (SyntheticNodes.IsGraphOnly(device.Mac)) return false;
            var r = Evaluate(device);
            return Apply(device, r);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Classification failed for {Mac}", device.Mac);
            return false;
        }
    }

    private static bool Apply(Device d, Result r)
    {
        bool changed = false;
        void Set<T>(T current, T value, Action<T> setter)
        {
            if (!EqualityComparer<T>.Default.Equals(current, value)) { setter(value); changed = true; }
        }
        if (r.Brand is not null) Set(d.Brand, r.Brand, v => d.Brand = v);
        if (r.Model is not null) Set(d.Model, r.Model, v => d.Model = v);
        if (r.Firmware is not null) Set(d.Firmware, r.Firmware, v => d.Firmware = v);
        if (r.Os is not null) Set(d.OsGuess, r.Os, v => d.OsGuess = v);
        if (r.Type != DeviceType.Unknown || d.Type == DeviceType.Unknown)
        {
            Set(d.Type, r.Type, v => d.Type = v);
            Set(Math.Round(d.TypeConfidence, 3), Math.Round(r.TypeScore, 3), v => d.TypeConfidence = v);
        }
        Set(Math.Round(d.IdentityConfidence, 3), Math.Round(r.IdentityConfidence, 3), v => d.IdentityConfidence = v);
        return changed;
    }

    /// <summary>Scores everything known about the device without mutating it.</summary>
    public Result Evaluate(Device d)
    {
        var signals = CollectSignals(d);
        var brand = new Votes();
        var type = new Votes();
        var os = new Votes();
        var model = new Votes();
        var firmware = new Votes();

        // ---- explicit evidence fields ----
        foreach (var e in d.Evidence)
        {
            switch (e.Field)
            {
                case Fields.Brand:
                case Fields.Vendor:
                    if (BrandNormalizer.Normalize(e.Value) is { } b) brand.Add(b, e.Field == Fields.Brand ? e.Confidence : e.Confidence * 0.9);
                    break;
                case Fields.Model:
                    model.Add(CleanModel(e.Value), e.Confidence);
                    break;
                case Fields.ModelNumber:
                    model.Add(CleanModel(e.Value), e.Confidence * 0.8);
                    break;
                case Fields.Firmware:
                    firmware.Add(e.Value.Trim(), e.Confidence);
                    break;
                case Fields.Os:
                    os.Add(e.Value.Trim(), e.Confidence);
                    break;
                case Fields.DeviceType:
                    if (ParseType(e.Value) is { } t) type.Add(t.ToString(), e.Confidence);
                    break;
                case Fields.Capabilities:
                    AddCapabilities(e.Value, e.Confidence, type);
                    break;
                case Fields.Ttl:
                    if (int.TryParse(e.Value, out var ttl)) AddTtl(ttl, e.Confidence, os);
                    break;
            }
        }
        if (d.Ttl is { } devTtl) AddTtl(devTtl, Confidence.Ttl, os);
        if ((d.GetProperty("lldp.capabilities") ?? d.GetProperty("capabilities")) is { } caps) AddCapabilities(caps, Confidence.Lldp, type);

        // ---- OUI ----
        var ouiVendor = d.OuiVendor ?? (_oui?.Lookup(d.Mac));
        if (ouiVendor is not null)
        {
            var ob = BrandNormalizer.Normalize(ouiVendor) ?? ouiVendor;
            brand.Add(ob, ClassifierRules.ChipsetVendors.Contains(ob) ? 0.15 : Confidence.Oui);
        }
        AddVirtualOui(d.Mac, type, brand);

        // ---- pass 1: brand rules ----
        foreach (var rule in ClassifierRules.Brand) ApplyRule(rule, signals, brand, type, os, model);

        // ---- Apple model codes (mDNS model=AppleTV11,1 etc.) and direct model strings (TXT model/md/ty, ...) ----
        foreach (var s in signals)
        {
            if (s.Channel == Channel.Model && AppleModelCode.IsMatch(s.Text.Trim()) is false && s.Text.Length <= 64)
                model.Add(CleanModel(s.Text), s.Confidence * 0.85);
            if ((s.Channel & (Channel.Model | Channel.Text)) == 0) continue;
            if (AppleModel(s.Text.Trim()) is { } am)
            {
                brand.Add("Apple", s.Confidence);
                type.Add(am.Type.ToString(), s.Confidence);
                model.Add(am.Name, s.Confidence * 1.02);
                os.Add(am.Os, s.Confidence * 0.9);
            }
        }

        // ---- SNMP sysObjectID ----
        foreach (var s in signals.Where(s => s.Channel == Channel.Oid))
        {
            var m = OidEnterprise.Match(s.Text.Trim());
            if (m.Success && int.TryParse(m.Groups["n"].Value, out var ent) && ClassifierRules.Enterprises.TryGetValue(ent, out var info))
            {
                if (info.Brand.Length > 0) brand.Add(info.Brand, s.Confidence);
                if (info.Type is { } t) type.Add(t.ToString(), s.Confidence * 0.7);
                if (ent is 8072 or 2021) os.Add("Linux", s.Confidence * 0.6);
            }
        }

        // ---- DHCP ----
        foreach (var s in signals.Where(s => s.Channel == Channel.Dhcp)) AddDhcp(s, os, type, brand);

        // ---- ports ----
        AddPorts(d, type, os, brand);

        // ---- flags ----
        var flags = d.Flags;
        if (flags.HasFlag(DeviceFlags.DhcpServer)) type.Add(nameof(DeviceType.Router), 0.4);
        if (flags.HasFlag(DeviceFlags.StpRoot)) type.Add(nameof(DeviceType.CoreSwitch), 0.55);
        if (flags.HasFlag(DeviceFlags.Infrastructure)) type.Add(nameof(DeviceType.AccessSwitch), 0.35);
        if (flags.HasFlag(DeviceFlags.Virtual)) type.Add(nameof(DeviceType.VirtualMachine), 0.5);
        if (flags.HasFlag(DeviceFlags.Gateway)) type.Add(nameof(DeviceType.Router), 0.6);

        // ---- choose brand, then product-line rules for that brand ----
        var (bestBrand, brandScore) = brand.Best();
        if (bestBrand is not null)
        {
            foreach (var rule in ClassifierRules.ProductLines)
                if (string.Equals(rule.RequireBrand, bestBrand, StringComparison.OrdinalIgnoreCase))
                    ApplyRule(rule, signals, brand, type, os, model);
        }

        // Apple/iOS phones with port 62078 and no other info
        var (bestType, typeScore) = type.Best();
        var t2 = bestType is null ? DeviceType.Unknown : Enum.Parse<DeviceType>(bestType);

        // ---- gateway / this host overrides ----
        if (flags.HasFlag(DeviceFlags.ThisHost)) { t2 = DeviceType.ThisComputer; typeScore = 1.0; }
        else if (flags.HasFlag(DeviceFlags.Gateway))
        {
            double fw = type.Score(nameof(DeviceType.Firewall));
            bool firewallBrand = bestBrand is not null && FirewallBrands.Contains(bestBrand, StringComparer.OrdinalIgnoreCase);
            if (fw >= 0.6 || (firewallBrand && fw >= 0.3)) { t2 = DeviceType.Firewall; typeScore = Math.Max(fw, 0.8); }
            else { t2 = DeviceType.Router; typeScore = Math.Max(type.Score(nameof(DeviceType.Router)), 0.8); }
        }

        var (bestModel, modelScore) = model.Best();
        var (bestOs, osScore) = os.Best();
        var (bestFw, _) = firmware.Best();
        // A brand that is only a chipset vendor with nothing better should stay weak.
        double identity = Math.Clamp(Math.Max(brandScore, bestModel is null ? 0 : (brandScore + modelScore) / 2 + 0.1 * modelScore), 0, 1);
        return new Result(bestBrand, brandScore, bestModel, modelScore, bestFw, bestOs, osScore, t2, Math.Clamp(typeScore, 0, 1), identity);
    }

    // ------------------------------------------------------------------------------------------------

    private static void ApplyRule(ClassifierRule rule, List<Signal> signals, Votes brand, Votes type, Votes os, Votes model)
    {
        foreach (var s in signals)
        {
            if ((s.Channel & rule.Channels) == 0) continue;
            var m = rule.Pattern.Match(s.Text);
            if (!m.Success) continue;
            double c = Math.Clamp(s.Confidence * rule.Weight, 0, 1);
            if (s.Channel == Channel.Oui)
            {
                // the OUI already voted for its brand directly; here it only hints at the product category
                if (rule.Type is { } ot) type.Add(ot.ToString(), c);
                continue;
            }
            if (rule.Brand is not null) brand.Add(rule.Brand, c);
            if (rule.Type is { } t) type.Add(t.ToString(), c);
            if (rule.Os is not null) os.Add(rule.Os, c * 0.9);
            var g = m.Groups["model"];
            if (g.Success && g.Value.Length > 1) model.Add(CleanModel(g.Value), c * 0.9);
            else if (rule.Model is not null) model.Add(rule.Model, c * 0.8);
        }
    }

    internal static List<Signal> CollectSignals(Device d)
    {
        var list = new List<Signal>(32);
        void Add(Channel ch, string? text, double conf)
        {
            if (!string.IsNullOrWhiteSpace(text)) list.Add(new Signal(ch, text.Trim(), conf));
        }

        foreach (var e in d.Evidence)
        {
            var ch = e.Field switch
            {
                Fields.Hostname => Channel.Host,
                Fields.Model or Fields.ModelNumber => Channel.Model,
                Fields.DeviceType => Channel.Kind,
                Fields.Service => e.Value.StartsWith('_') ? Channel.Service : Channel.Text,
                Fields.DhcpFingerprint or Fields.DhcpVendorClass => Channel.Dhcp,
                Fields.Serial or Fields.Ttl or Fields.Capabilities or Fields.Firmware or Fields.IconUrl => Channel.None,
                _ when e.Field.Contains("objectid", StringComparison.OrdinalIgnoreCase) || e.Field.Equals("sysObjectID", StringComparison.OrdinalIgnoreCase) => Channel.Oid,
                _ => Channel.Text,
            };
            if (ch != Channel.None) Add(ch, e.Value, e.Confidence);
            // a DHCP vendor class string like "dhcpcd-9.4.1:Linux..." also helps text rules
            if (ch == Channel.Dhcp) Add(Channel.Text, e.Value, e.Confidence * 0.5);
        }

        foreach (var (src, name) in d.Hostnames) Add(Channel.Host, name, HostnameConfidence(src));

        foreach (var s in d.Services)
        {
            bool mdns = s.Type is not null && s.Type.StartsWith('_');
            if (mdns) Add(Channel.Service, s.Type, Confidence.Mdns);
            Add(Channel.Text, s.Banner, Confidence.Http);
            if (s.Txt is { } txt)
            {
                foreach (var (k, v) in txt)
                {
                    if (ModelTxtKeys.Contains(k)) Add(Channel.Model, v, Confidence.Mdns);
                    else if (VendorTxtKeys.Contains(k)) Add(Channel.Text, v, Confidence.Mdns);
                }
            }
            // instance names like "Living Room Sonos" or "[TV] Samsung Q80"
            if (mdns || s.Protocol.Equals("ssdp", StringComparison.OrdinalIgnoreCase)) Add(Channel.Host, s.Name, Confidence.Mdns * 0.8);
        }

        foreach (var (k, v) in d.Properties)
        {
            if (k.Contains("objectid", StringComparison.OrdinalIgnoreCase) || k.EndsWith("oid", StringComparison.OrdinalIgnoreCase)) Add(Channel.Oid, v, Confidence.Snmp);
            else if (k.Contains("sysdescr", StringComparison.OrdinalIgnoreCase)) Add(Channel.Text, v, Confidence.Snmp);
            else if (k.Contains("sysname", StringComparison.OrdinalIgnoreCase)) Add(Channel.Host, v, Confidence.Snmp * 0.9);
            else if (k.Contains("model", StringComparison.OrdinalIgnoreCase)) Add(Channel.Model, v, Confidence.Http);
            else if (k.Contains("descr", StringComparison.OrdinalIgnoreCase) || k.Contains("title", StringComparison.OrdinalIgnoreCase) ||
                     k.Contains("server", StringComparison.OrdinalIgnoreCase) || k.Contains("banner", StringComparison.OrdinalIgnoreCase) ||
                     k.Contains("manufacturer", StringComparison.OrdinalIgnoreCase) || k.Contains("vendor", StringComparison.OrdinalIgnoreCase) ||
                     k.Contains("platform", StringComparison.OrdinalIgnoreCase))
                Add(Channel.Text, v, Confidence.Http);
            else if (k.Contains("dhcp", StringComparison.OrdinalIgnoreCase)) Add(Channel.Dhcp, v, Confidence.Dhcp);
        }

        foreach (var c in d.Certificates)
        {
            Add(Channel.Text, c.CommonName, Confidence.Tls);
            Add(Channel.Text, c.IssuerOrganization, Confidence.Tls * 0.8);
            Add(Channel.Text, c.Subject, Confidence.Tls * 0.9);
            foreach (var san in c.SubjectAltNames.Take(8)) Add(Channel.Host, san, Confidence.Tls * 0.8);
        }

        if (d.OuiVendor is { } oui) Add(Channel.Oui, oui, Confidence.Oui);
        return list;
    }

    private static double HostnameConfidence(string source) => source.ToLowerInvariant() switch
    {
        "user" => Confidence.User,
        "snmp" or "lldp" or "cdp" => Confidence.Snmp,
        "mdns" => Confidence.Mdns,
        "ssdp" => Confidence.Ssdp,
        "netbios" or "smb" or "llmnr" => Confidence.NetBios,
        "dhcp" => Confidence.Dhcp,
        "tls" => 0.75,
        _ => 0.6,
    };

    private static void AddTtl(int ttl, double conf, Votes os)
    {
        if (ttl <= 0) return;
        if (ttl <= 64) os.Add("Linux/macOS/iOS/Android", conf);
        else if (ttl <= 128) os.Add("Windows", conf);
        else os.Add("Network OS", conf);
    }

    private static void AddCapabilities(string caps, double conf, Votes type)
    {
        var c = caps.ToLowerInvariant();
        bool bridge = c.Contains("bridge") || c.Contains("switch");
        bool router = c.Contains("router");
        if (c.Contains("wlan") || c.Contains("access point") || c.Contains("ap")) type.Add(nameof(DeviceType.AccessPoint), conf * 0.8);
        if (c.Contains("telephone") || c.Contains("phone")) type.Add(nameof(DeviceType.VoipPhone), conf * 0.8);
        if (bridge && router) type.Add(nameof(DeviceType.CoreSwitch), conf * 0.6);
        else if (bridge) type.Add(nameof(DeviceType.AccessSwitch), conf * 0.7);
        else if (router) type.Add(nameof(DeviceType.Router), conf * 0.6);
        if (c.Contains("docsis") || c.Contains("cable")) type.Add(nameof(DeviceType.Router), conf * 0.5);
    }

    private static void AddDhcp(Signal s, Votes os, Votes type, Votes brand)
    {
        var t = s.Text;
        double c = s.Confidence;
        if (t.Contains("MSFT 5.0", StringComparison.OrdinalIgnoreCase) || t.StartsWith("MSFT", StringComparison.OrdinalIgnoreCase)) os.Add("Windows", c);
        var am = AndroidDhcp.Match(t);
        if (am.Success) { os.Add($"Android {am.Groups["v"].Value}", c); type.Add(nameof(DeviceType.Phone), c * 0.6); }
        else if (t.Contains("android", StringComparison.OrdinalIgnoreCase)) { os.Add("Android", c); type.Add(nameof(DeviceType.Phone), c * 0.6); }
        if (t.Contains("udhcp", StringComparison.OrdinalIgnoreCase)) { os.Add("Embedded Linux", c * 0.8); type.Add(nameof(DeviceType.IoT), c * 0.3); }
        if (t.Contains("dhcpcd", StringComparison.OrdinalIgnoreCase)) os.Add("Linux", c * 0.8);
        if (t.Contains("Cisco Systems", StringComparison.OrdinalIgnoreCase)) brand.Add("Cisco", c * 0.8);
        if (t.Contains("ubnt", StringComparison.OrdinalIgnoreCase)) brand.Add("Ubiquiti", c * 0.8);
        if (t.Contains("Mikrotik", StringComparison.OrdinalIgnoreCase)) brand.Add("MikroTik", c * 0.8);

        // parameter-request-list fingerprints (option 55)
        var digits = Regex.Replace(t, @"\s", "");
        if (Regex.IsMatch(digits, @"^\d+(,\d+)+$"))
        {
            switch (digits)
            {
                case "1,121,3,6,15,108,114,119,252,95,44,46":
                case "1,121,3,6,15,119,252,95,44,46":
                case "1,121,3,6,15,114,119,252,95,44,46":
                case "1,3,6,15,119,252":
                    os.Add("macOS/iOS", c); brand.Add("Apple", c * 0.6); break;
                case "1,3,6,15,31,33,43,44,46,47,119,121,249,252":
                case "1,3,6,15,31,33,43,44,46,47,121,249,252":
                case "1,15,3,6,44,46,47,31,33,121,249,43":
                    os.Add("Windows", c); break;
                case "1,3,6,15,26,28,51,58,59,43":
                case "1,3,6,28,33,51,58,59,121":
                    os.Add("Android", c * 0.9); break;
                case "1,28,2,3,15,6,119,12,44,47,26,121,42":
                case "1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42":
                    os.Add("Linux", c * 0.9); break;
                case "1,3,28,6":
                case "1,3,6,12,15,28,42":
                    os.Add("Embedded Linux", c * 0.6); break;
            }
        }
    }

    private static readonly int[] PrinterPorts = [9100, 515, 631];

    private static void AddPorts(Device d, Votes type, Votes os, Votes brand)
    {
        var open = new HashSet<int>(d.Ports.Where(p => p.State == PortState.Open).Select(p => p.Port));
        foreach (var s in d.Services) if (s.Port > 0 && !s.Protocol.Equals("mdns", StringComparison.OrdinalIgnoreCase)) open.Add(s.Port);
        if (open.Count == 0) return;
        bool onvif = d.Services.Any(s => (s.Type ?? s.Name).Contains("onvif", StringComparison.OrdinalIgnoreCase)) ||
                     d.Evidence.Any(e => e.Value.Contains("onvif", StringComparison.OrdinalIgnoreCase));
        double c = Confidence.Port;

        if (open.Contains(9100)) type.Add(nameof(DeviceType.Printer), c * 1.2);
        if (open.Contains(515)) type.Add(nameof(DeviceType.Printer), c);
        if (open.Contains(631) && !open.Contains(22) && !open.Contains(445)) type.Add(nameof(DeviceType.Printer), c * 0.7);
        if (open.Contains(554)) type.Add(nameof(DeviceType.Camera), onvif ? 0.75 : c * 0.8);
        if (open.Contains(3389) && open.Contains(445)) { type.Add(nameof(DeviceType.Desktop), c * 1.1); os.Add("Windows", 0.6); }
        else if (open.Contains(445) && (open.Contains(135) || open.Contains(139))) os.Add("Windows", c);
        if (open.Contains(62078)) { type.Add(nameof(DeviceType.Phone), c * 1.2); brand.Add("Apple", c * 1.2); os.Add("iOS", c); }
        if ((open.Contains(5000) || open.Contains(5001)) && brand.Score("Synology") > 0.2) type.Add(nameof(DeviceType.Nas), 0.8);
        if (open.Contains(8006)) { type.Add(nameof(DeviceType.Hypervisor), 0.7); os.Add("Proxmox VE", 0.6); }
        if (open.Contains(902) && open.Contains(443)) type.Add(nameof(DeviceType.Hypervisor), c);
        if (open.Contains(1400) && (open.Contains(1443) || open.Count < 12)) { brand.Add("Sonos", 0.6); type.Add(nameof(DeviceType.AudioStreamer), 0.6); }
        if (open.Contains(8008) && open.Contains(8009)) type.Add(nameof(DeviceType.MediaStreamer), c);
        if (open.Contains(32400)) type.Add(nameof(DeviceType.Server), c);
        if (open.Contains(8123)) { brand.Add("Home Assistant", c); type.Add(nameof(DeviceType.SmartHomeHub), c * 1.1); }
        if (open.Contains(623)) type.Add(nameof(DeviceType.Server), c);
        if (open.Contains(5060)) type.Add(nameof(DeviceType.VoipPhone), c * 0.5);
        if (open.Contains(2049) || open.Contains(548)) type.Add(nameof(DeviceType.Nas), c * 0.6);
        if (open.Contains(53) && (open.Contains(80) || open.Contains(443))) type.Add(nameof(DeviceType.Router), c * 0.5);
        if (open.Contains(10001) && brand.Score("Ubiquiti") > 0) type.Add(nameof(DeviceType.AccessPoint), c * 0.4);
        if (open.Contains(8291)) { brand.Add("MikroTik", 0.8); type.Add(nameof(DeviceType.Router), c); } // Winbox
        if (open.Contains(1883) || open.Contains(8883)) type.Add(nameof(DeviceType.IoT), c * 0.3);
        if (open.Contains(22) && !open.Contains(445) && !open.Contains(3389)) os.Add("Linux", c * 0.4);
        _ = PrinterPorts;
    }

    private static void AddVirtualOui(Mac mac, Votes type, Votes brand)
    {
        uint oui = mac.Oui24;
        switch (oui)
        {
            case 0x00155D: type.Add(nameof(DeviceType.VirtualMachine), 0.75); brand.Add("Microsoft", 0.3); break; // Hyper-V
            case 0x005056: case 0x000C29: case 0x000569: case 0x001C14: type.Add(nameof(DeviceType.VirtualMachine), 0.75); break; // VMware
            case 0x080027: case 0x0A0027: type.Add(nameof(DeviceType.VirtualMachine), 0.75); break; // VirtualBox
            case 0x525400: type.Add(nameof(DeviceType.VirtualMachine), 0.7); break; // QEMU/KVM
            case 0x00163E: type.Add(nameof(DeviceType.VirtualMachine), 0.7); break; // Xen
            case 0xBC2411: type.Add(nameof(DeviceType.VirtualMachine), 0.6); brand.Add("Proxmox", 0.3); break; // Proxmox
        }
        if (mac[0] == 0x02 && mac[1] == 0x42) type.Add(nameof(DeviceType.VirtualMachine), 0.6); // Docker
    }

    internal static DeviceType? ParseType(string v)
    {
        var s = v.Trim();
        if (Enum.TryParse<DeviceType>(s, true, out var t) && t != DeviceType.Unknown && !int.TryParse(s, out _)) return t;
        var l = s.ToLowerInvariant();
        if (l.Contains("internetgatewaydevice") || l == "gateway" || l.Contains("router")) return DeviceType.Router;
        if (l.Contains("firewall")) return DeviceType.Firewall;
        if (l.Contains("access point") || l.Contains("accesspoint") || l == "ap" || l.Contains("wlanaccesspoint")) return DeviceType.AccessPoint;
        if (l.Contains("switch")) return DeviceType.AccessSwitch;
        if (l.Contains("printer")) return DeviceType.Printer;
        if (l.Contains("camera") || l.Contains("networkvideotransmitter")) return DeviceType.Camera;
        if (l.Contains("nas") || l.Contains("storage")) return DeviceType.Nas;
        if (l.Contains("zoneplayer") || l.Contains("speaker")) return DeviceType.AudioStreamer;
        if (l.Contains("television") || l is "tv") return DeviceType.Tv;
        if (l.Contains("phone")) return DeviceType.Phone;
        if (l.Contains("tablet")) return DeviceType.Tablet;
        if (l.Contains("laptop") || l.Contains("notebook")) return DeviceType.Laptop;
        if (l.Contains("desktop") || l.Contains("workstation")) return DeviceType.Desktop;
        if (l.Contains("server")) return DeviceType.Server;
        if (l.Contains("ups")) return DeviceType.Ups;
        return null;
    }

    private static string CleanModel(string v) => Regex.Replace(v.Trim(), @"\s+", " ");

    public sealed record AppleModelInfo(string Name, DeviceType Type, string Os);

    /// <summary>Maps an Apple hardware model identifier ("AppleTV11,1", "iPhone15,2") to a family, type and OS.</summary>
    public static AppleModelInfo? AppleModel(string code)
    {
        var m = AppleModelCode.Match(code);
        if (!m.Success) return null;
        var fam = m.Groups["fam"].Value;
        int maj = int.Parse(m.Groups["maj"].Value), min = int.Parse(m.Groups["min"].Value);
        return fam switch
        {
            "iPhone" => new($"iPhone ({code})", DeviceType.Phone, "iOS"),
            "iPad" => new($"iPad ({code})", DeviceType.Tablet, "iPadOS"),
            "iPod" => new($"iPod touch ({code})", DeviceType.Phone, "iOS"),
            "AppleTV" => new(maj switch { >= 11 => "Apple TV 4K (3rd gen)", 6 when min == 2 => "Apple TV 4K", 6 => "Apple TV 4K", 5 => "Apple TV HD", _ when maj >= 14 => "Apple TV 4K", _ => "Apple TV" }, DeviceType.MediaStreamer, "tvOS"),
            "AudioAccessory" => new(maj switch { 1 => "HomePod", 5 => "HomePod mini", 6 => "HomePod (2nd gen)", _ => "HomePod" }, DeviceType.AudioStreamer, "audioOS"),
            "MacBookPro" => new($"MacBook Pro ({code})", DeviceType.Laptop, "macOS"),
            "MacBookAir" => new($"MacBook Air ({code})", DeviceType.Laptop, "macOS"),
            "MacBook" => new($"MacBook ({code})", DeviceType.Laptop, "macOS"),
            "iMac" or "iMacPro" => new($"iMac ({code})", DeviceType.Desktop, "macOS"),
            "Macmini" => new($"Mac mini ({code})", DeviceType.Desktop, "macOS"),
            "MacPro" => new($"Mac Pro ({code})", DeviceType.Desktop, "macOS"),
            "Watch" => new($"Apple Watch ({code})", DeviceType.IoT, "watchOS"),
            "Mac" => MacGeneric(code),
            _ => null,
        };
    }

    // Apple Silicon "MacNN,N" identifiers mix laptops and desktops.
    private static readonly Dictionary<string, string> MacCodes = new()
    {
        ["Mac13,1"] = "Mac Studio", ["Mac13,2"] = "Mac Studio", ["Mac14,2"] = "MacBook Air", ["Mac14,3"] = "Mac mini", ["Mac14,5"] = "MacBook Pro",
        ["Mac14,6"] = "MacBook Pro", ["Mac14,7"] = "MacBook Pro", ["Mac14,8"] = "Mac Pro", ["Mac14,9"] = "MacBook Pro", ["Mac14,10"] = "MacBook Pro",
        ["Mac14,12"] = "Mac mini", ["Mac14,13"] = "Mac Studio", ["Mac14,14"] = "Mac Studio", ["Mac14,15"] = "MacBook Air", ["Mac15,3"] = "MacBook Pro",
        ["Mac15,4"] = "iMac", ["Mac15,5"] = "iMac", ["Mac15,6"] = "MacBook Pro", ["Mac15,7"] = "MacBook Pro", ["Mac15,8"] = "MacBook Pro",
        ["Mac15,9"] = "MacBook Pro", ["Mac15,10"] = "MacBook Pro", ["Mac15,11"] = "MacBook Pro", ["Mac15,12"] = "MacBook Air", ["Mac15,13"] = "MacBook Air",
        ["Mac15,14"] = "Mac Studio", ["Mac16,1"] = "MacBook Pro", ["Mac16,2"] = "iMac", ["Mac16,3"] = "iMac", ["Mac16,5"] = "MacBook Pro",
        ["Mac16,6"] = "MacBook Pro", ["Mac16,7"] = "MacBook Pro", ["Mac16,8"] = "MacBook Pro", ["Mac16,9"] = "Mac Studio", ["Mac16,10"] = "Mac mini",
        ["Mac16,11"] = "Mac mini", ["Mac16,12"] = "MacBook Air", ["Mac16,13"] = "MacBook Air", ["Mac17,2"] = "MacBook Pro",
    };

    private static AppleModelInfo MacGeneric(string code)
    {
        var name = MacCodes.GetValueOrDefault(code, "Mac");
        var type = name.StartsWith("MacBook", StringComparison.Ordinal) ? DeviceType.Laptop : DeviceType.Desktop;
        return new AppleModelInfo($"{name} ({code})", type, "macOS");
    }

    /// <summary>Accumulates confidence votes per value with noisy-OR.</summary>
    private sealed class Votes
    {
        private readonly Dictionary<string, double> _scores = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _display = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, double> _max = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string? value, double confidence)
        {
            if (string.IsNullOrWhiteSpace(value) || confidence <= 0) return;
            confidence = Math.Min(confidence, 0.99);
            _scores[value] = 1 - (1 - _scores.GetValueOrDefault(value)) * (1 - confidence);
            // keep the display form from the most confident vote
            if (!_max.TryGetValue(value, out var mx) || confidence > mx) { _max[value] = confidence; _display[value] = value; }
        }

        public double Score(string value) => _scores.GetValueOrDefault(value);

        public (string? Value, double Score) Best()
        {
            string? best = null; double score = 0;
            foreach (var (k, v) in _scores)
            {
                // tie-break: the single strongest vote, then longer (more specific) value
                if (v > score + 1e-9 || (Math.Abs(v - score) <= 1e-9 && best is not null &&
                    (_max[k] > _max[best] || (_max[k] == _max[best] && k.Length > best.Length))))
                { best = k; score = v; }
            }
            return (best is null ? null : _display[best], score);
        }
    }
}
