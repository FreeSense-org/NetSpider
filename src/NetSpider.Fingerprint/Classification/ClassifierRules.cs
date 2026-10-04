using System.Text.RegularExpressions;
using NetSpider.Core.Model;

namespace NetSpider.Fingerprint.Classification;

/// <summary>Which text channels a rule looks at.</summary>
[Flags]
public enum Channel
{
    None = 0,
    /// <summary>Hostnames (DNS, mDNS, NetBIOS, DHCP, ...).</summary>
    Host = 1,
    /// <summary>Model / model-number evidence and mDNS TXT model keys.</summary>
    Model = 2,
    /// <summary>Descriptions, vendor/manufacturer strings, banners, SNMP sysDescr, certificate names.</summary>
    Text = 4,
    /// <summary>mDNS/DNS-SD service types such as _airplay._tcp.</summary>
    Service = 8,
    /// <summary>OUI vendor name.</summary>
    Oui = 16,
    /// <summary>Explicit device-type evidence (SSDP deviceType URNs, ...).</summary>
    Kind = 32,
    /// <summary>SNMP sysObjectID.</summary>
    Oid = 64,
    /// <summary>DHCP vendor class and parameter-request-list fingerprint.</summary>
    Dhcp = 128,
    Default = Host | Model | Text | Oui | Kind,
    Strong = Host | Model | Text | Kind,
}

/// <summary>
/// One classification rule: when <see cref="Pattern"/> matches a signal on one of <see cref="Channels"/>, it votes for
/// brand/type/OS/model with confidence = signal confidence × <see cref="Weight"/>. A named group "model" supplies the model.
/// Rules with <see cref="RequireBrand"/> only apply once that brand has been chosen (product-line disambiguation).
/// </summary>
public sealed record ClassifierRule(Regex Pattern, Channel Channels, double Weight, string? Brand, DeviceType? Type, string? Os, string? Model, string? RequireBrand);

/// <summary>The built-in, data-driven rule table.</summary>
public static class ClassifierRules
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    private static ClassifierRule R(string pattern, string? brand = null, DeviceType? type = null, double w = 1.0, Channel ch = Channel.Default,
        string? os = null, string? model = null, string? requireBrand = null) =>
        new(new Regex(pattern, Opts), ch, w, brand, type, os, model, requireBrand);

    private static ClassifierRule B(string requireBrand, string pattern, DeviceType? type, double w = 0.9, string? model = null, string? os = null) =>
        new(new Regex(pattern, Opts), Channel.Strong, w, null, type, os, model, requireBrand);

    public static IReadOnlyList<ClassifierRule> Brand { get; } =
    [
        // ---------------- network infrastructure ----------------
        R(@"\bnetgear\b|\borbi\b|nighthawk|\bNSDP\b", "Netgear"),
        R(@"\bubiquiti\b|\bubnt\b|\bunifi\b|\bedgeos\b|edgerouter|edgeswitch|airmax|\bUAP-|\bUSW-|\bUDM\b|\bUDM-|\bUDR\b|\bUXG\b|\bUCG\b", "Ubiquiti"),
        R(@"\bmeraki\b", "Meraki"),
        R(@"\bcisco\b|\bcatalyst\b|\bIOS-XE\b|\bNX-OS\b|\bWS-C\d|\bC9[2-5]00\b|aironet|\bcisco ios\b", "Cisco"),
        R(@"\btp-?link\b|\bdeco ?(m|x|s|e|p|w|be)\d+|\bomada\b|\bkasa\b|\btapo\b|\barcher [a-z]*\d", "TP-Link"),
        R(@"mikrotik|routeros|routerboard|\bMNDP\b", "MikroTik", os: "RouterOS"),
        R(@"fortinet|fortigate|fortios|fortiswitch|fortiap|\bFGT\d", "Fortinet"),
        R(@"pfsense", "Netgate", DeviceType.Firewall, 0.95, os: "pfSense"),
        R(@"opnsense", "OPNsense", DeviceType.Firewall, 0.95, os: "OPNsense"),
        R(@"fritz!?\s?box|fritz\.box|\bAVM\b|fritz!?os", "AVM"),
        R(@"\basus\b|asuswrt|\bzenwifi\b|\bRT-[A-Z]{1,3}\d{2,5}|\bGT-AX\d+|\bROG Rapture", "ASUS"),
        R(@"\bd-?link\b|\bDIR-\d{3}|\bDGS-\d{3,4}|\bDCS-\d{3,4}|\bDAP-\d{3,4}", "D-Link"),
        R(@"\bzyxel\b|\bzywall\b|\bUSG FLEX\b|\bNBG\d", "Zyxel"),
        R(@"\baruba\b|instant on|\bArubaOS", "Aruba"),
        R(@"\bjuniper\b|\bjunos\b|\bmist\b ap", "Juniper", os: "Junos"),
        R(@"\beero\b", "eero", DeviceType.Router, 0.8),
        R(@"\bhuawei\b|\bechoLife\b|\bhonor\b router", "Huawei"),
        R(@"\blinksys\b|\bvelop\b", "Linksys"),
        R(@"\bsonicwall\b", "SonicWall", DeviceType.Firewall),
        R(@"\bwatchguard\b|\bfirebox\b", "WatchGuard", DeviceType.Firewall),
        R(@"\bsophos\b|\bXGS?\s?\d{3}\b.*sophos", "Sophos", DeviceType.Firewall, 0.8),
        R(@"palo ?alto|\bPAN-OS\b", "Palo Alto", DeviceType.Firewall),
        R(@"\bruckus\b", "Ruckus", DeviceType.AccessPoint, 0.7),
        R(@"\barista\b|\bEOS-\d", "Arista", DeviceType.CoreSwitch, 0.7),
        R(@"\bdraytek\b|\bvigor\d+", "DrayTek", DeviceType.Router),
        R(@"\btenda\b", "Tenda", DeviceType.Router, 0.6),
        R(@"\bopenwrt\b|\bLuCI\b", null, DeviceType.Router, 0.7, os: "OpenWrt"),
        R(@"\bdd-wrt\b", null, DeviceType.Router, 0.7, os: "DD-WRT"),
        R(@"\bInternetGatewayDevice\b|\bWANDevice\b|\bWANConnectionDevice\b", null, DeviceType.Router, 0.85, Channel.Kind | Channel.Text),
        R(@"\bWLANAccessPointDevice\b|\bWFADevice\b", null, DeviceType.AccessPoint, 0.6, Channel.Kind),

        // ---------------- Apple ----------------
        R(@"\bapple\b|\bmacOS\b|\bMac OS X\b|\bdarwin\b", "Apple"),
        R(@"\biphone\b|^iphone|iphone-|s-iphone", "Apple", DeviceType.Phone, 0.9, Channel.Host | Channel.Model, os: "iOS"),
        R(@"\bipad\b|^ipad|ipad-", "Apple", DeviceType.Tablet, 0.9, Channel.Host | Channel.Model, os: "iPadOS"),
        R(@"macbook", "Apple", DeviceType.Laptop, 0.9, Channel.Host | Channel.Model, os: "macOS"),
        R(@"\bimac\b|^imac|mac-?mini|mac-?pro\b|mac-?studio", "Apple", DeviceType.Desktop, 0.85, Channel.Host | Channel.Model, os: "macOS"),
        R(@"apple-?tv|appletv", "Apple", DeviceType.MediaStreamer, 0.95, Channel.Host | Channel.Model, os: "tvOS", model: "Apple TV"),
        R(@"homepod", "Apple", DeviceType.AudioStreamer, 0.95, Channel.Host | Channel.Model, os: "audioOS", model: "HomePod"),
        R(@"apple-?watch", "Apple", DeviceType.IoT, 0.8, Channel.Host | Channel.Model, os: "watchOS"),
        R(@"^_apple-mobdev2\._tcp", "Apple", DeviceType.Phone, 0.5, Channel.Service),
        R(@"^_companion-link\._tcp", "Apple", null, 0.8, Channel.Service),
        R(@"^_(mediaremotetv|touch-able)\._tcp", "Apple", DeviceType.MediaStreamer, 0.7, Channel.Service, os: "tvOS"),
        R(@"^_sleep-proxy\._udp", "Apple", null, 0.6, Channel.Service),
        R(@"^_airplay\._tcp", null, DeviceType.MediaStreamer, 0.35, Channel.Service),
        R(@"^_raop\._tcp", null, DeviceType.AudioStreamer, 0.3, Channel.Service),
        R(@"^_afpovertcp\._tcp|^_adisk\._tcp", null, DeviceType.Nas, 0.4, Channel.Service),
        R(@"^_rfb\._tcp", null, DeviceType.Desktop, 0.35, Channel.Service),

        // ---------------- Google / Amazon / Samsung / LG / Sony / Microsoft / Nintendo / Roku ----------------
        R(@"\bgoogle\b|\bnest\b", "Google"),
        R(@"chromecast", "Google", DeviceType.MediaStreamer, 0.95, Channel.Strong, model: "Chromecast"),
        R(@"google[- ]?home[- ]?mini|nest[- ]?mini|home[- ]?mini", "Google", DeviceType.AudioStreamer, 0.9, Channel.Strong, model: "Nest Mini"),
        R(@"nest[- ]?audio", "Google", DeviceType.AudioStreamer, 0.9, Channel.Strong, model: "Nest Audio"),
        R(@"nest[- ]?hub|home[- ]?hub", "Google", DeviceType.SmartHomeHub, 0.9, Channel.Strong, model: "Nest Hub"),
        R(@"google[- ]?home\b", "Google", DeviceType.AudioStreamer, 0.85, Channel.Strong, model: "Google Home"),
        R(@"nest[- ]?wifi|google[- ]?wifi|\bonhub\b", "Google", DeviceType.Router, 0.85, Channel.Strong, model: "Nest Wifi"),
        R(@"nest[- ]?(cam|doorbell)", "Google", DeviceType.Camera, 0.9, Channel.Strong),
        R(@"nest[- ]?(thermostat|learning|protect)", "Google", DeviceType.IoT, 0.9, Channel.Strong),
        R(@"\bpixel[- ]?\d", "Google", DeviceType.Phone, 0.85, Channel.Host | Channel.Model, os: "Android"),
        R(@"^_googlecast\._tcp", null, DeviceType.MediaStreamer, 0.45, Channel.Service),
        R(@"\bamazon\b|^amazon-[0-9a-f]+", "Amazon"),
        R(@"\becho[- ]?show\b|\becho[- ]?hub\b", "Amazon", DeviceType.SmartHomeHub, 0.9, Channel.Strong, model: "Echo Show"),
        R(@"\becho[- ]?(dot|studio|pop|plus)?\b", "Amazon", DeviceType.AudioStreamer, 0.7, Channel.Model | Channel.Kind),
        R(@"fire[- ]?tv|\bAFT[A-Z]{1,4}\b|firetv|\bfire[- ]?stick", "Amazon", DeviceType.MediaStreamer, 0.9, Channel.Strong, os: "Fire OS", model: "Fire TV"),
        R(@"^_amzn-wplay\._tcp", "Amazon", DeviceType.MediaStreamer, 0.75, Channel.Service, os: "Fire OS"),
        R(@"\bkindle\b", "Amazon", DeviceType.Tablet, 0.85, Channel.Strong),
        R(@"\bring\b[- ](doorbell|cam|stick|spotlight|floodlight)|^ring-[0-9a-f]+", "Ring", DeviceType.Camera, 0.9, Channel.Strong),
        R(@"^Ring\b", "Ring", DeviceType.Camera, 0.6, Channel.Oui),
        R(@"\bsamsung\b", "Samsung"),
        R(@"\[TV\]\s*Samsung|samsung.*\btv\b|\btizen\b|\b(QN|UN|UE|GQ|QE)\d{2}[A-Z]", "Samsung", DeviceType.Tv, 0.9, Channel.Strong, os: "Tizen"),
        R(@"\bgalaxy[- ]?(s|a|z|note|m)\d|\bSM-[ASGMNFE]\d{3}", "Samsung", DeviceType.Phone, 0.9, Channel.Host | Channel.Model | Channel.Kind, os: "Android"),
        R(@"\bgalaxy[- ]?tab\b|\bSM-[TX]\d{3}", "Samsung", DeviceType.Tablet, 0.9, Channel.Host | Channel.Model | Channel.Kind, os: "Android"),
        R(@"smartthings", "Samsung", DeviceType.SmartHomeHub, 0.85, Channel.Strong | Channel.Service),
        R(@"\bwebos\b|lgwebostv|\bLG[- ]?(OLED|NanoCell|smart ?tv)|\bOLED\d{2}[A-Z]\d", "LG", DeviceType.Tv, 0.9, Channel.Strong, os: "webOS"),
        R(@"\bLG\b", "LG", null, 0.7, Channel.Strong),
        R(@"\bbravia\b|\bKD-\d{2}[A-Z]|\bXR-\d{2}[A-Z]", "Sony", DeviceType.Tv, 0.9, Channel.Strong),
        R(@"playstation|\bPS[345]\b|\bPS[345]-", "Sony", DeviceType.GameConsole, 0.9, Channel.Strong),
        R(@"^Sony Interactive", "Sony", DeviceType.GameConsole, 0.8, Channel.Oui),
        R(@"\bsony\b", "Sony"),
        R(@"\bxbox\b", "Microsoft", DeviceType.GameConsole, 0.9, Channel.Strong),
        R(@"\bsurface\b[- ]?(pro|laptop|book|go)", "Microsoft", DeviceType.Laptop, 0.85, Channel.Strong, os: "Windows"),
        R(@"^DESKTOP-[A-Z0-9]{7}$|^WIN-[A-Z0-9]{11}$", null, DeviceType.Desktop, 0.7, Channel.Host, os: "Windows"),
        R(@"^LAPTOP-[A-Z0-9]{7}$", null, DeviceType.Laptop, 0.75, Channel.Host, os: "Windows"),
        R(@"\bwindows\b|microsoft-windows|\bwin(7|8|10|11)\b|microsoft-ds", null, null, 0.8, Channel.Text, os: "Windows"),
        R(@"\bnintendo\b", "Nintendo", DeviceType.GameConsole, 0.9),
        R(@"\broku\b", "Roku", DeviceType.MediaStreamer, 0.9),
        R(@"\broku ?tv\b", "Roku", DeviceType.Tv, 0.9, Channel.Strong),
        R(@"\bandroid[- ]?tv\b|^_androidtvremote2?\._tcp", null, DeviceType.Tv, 0.6, Channel.Strong | Channel.Service, os: "Android TV"),
        R(@"\bvizio\b", "Vizio", DeviceType.Tv, 0.8),
        R(@"\bhisense\b", "Hisense", DeviceType.Tv, 0.6),
        R(@"\bTCL\b", "TCL", DeviceType.Tv, 0.5),
        R(@"^android-[0-9a-f]{8,}|^android_|\bandroid\b", null, DeviceType.Phone, 0.6, Channel.Host, os: "Android"),
        R(@"\b(oneplus|xiaomi|redmi|oppo|vivo|realme|motorola|moto g|huawei p\d|pixel)\b", null, DeviceType.Phone, 0.5, Channel.Host, os: "Android"),

        // ---------------- smart home / IoT ----------------
        R(@"philips ?hue|hue ?bridge|\bBSB00\d\b|\bsignify\b|^_hue\._tcp", "Philips Hue", DeviceType.SmartHomeHub, 0.9, Channel.Default | Channel.Service),
        R(@"\btradfri\b|\bdirigera\b|\bikea\b", "IKEA", DeviceType.SmartHomeHub, 0.85, Channel.Default),
        R(@"\bshelly|^_shelly\._tcp|allterco", "Shelly", DeviceType.SmartPlug, 0.9, Channel.Default | Channel.Service),
        R(@"\btuya\b|smart ?life|\bsmartlife\b", "Tuya", DeviceType.IoT, 0.8),
        R(@"\btasmota\b", null, DeviceType.IoT, 0.85, Channel.Strong, os: "Tasmota"),
        R(@"\besphome\b|^_esphomelib\._tcp", null, DeviceType.IoT, 0.85, Channel.Strong | Channel.Service, os: "ESPHome"),
        R(@"\bespressif\b|^ESP[_-][0-9A-F]{6}|\besp32\b|\besp8266\b|^esp-", "Espressif", DeviceType.IoT, 0.6),
        R(@"\bsonoff\b|\bewelink\b|^_ewelink\._tcp", "Sonoff", DeviceType.SmartPlug, 0.8, Channel.Default | Channel.Service),
        R(@"\bwiz\b ?(light|bulb)|\bwiz_", "WiZ", DeviceType.Light, 0.8, Channel.Strong),
        R(@"\blifx\b", "LIFX", DeviceType.Light, 0.9),
        R(@"\bnanoleaf\b", "Nanoleaf", DeviceType.Light, 0.9, Channel.Default | Channel.Service),
        R(@"\becobee\b", "ecobee", DeviceType.IoT, 0.9),
        R(@"^_hap\._(tcp|udp)", null, DeviceType.IoT, 0.3, Channel.Service),
        R(@"^_matterc?\._(tcp|udp)", null, DeviceType.IoT, 0.3, Channel.Service),
        R(@"\braspberry ?pi\b|^raspberrypi", "Raspberry Pi", DeviceType.Server, 0.5, os: "Linux"),
        R(@"home ?assistant|^homeassistant|^_home-assistant\._tcp", "Home Assistant", DeviceType.SmartHomeHub, 0.9, Channel.Strong | Channel.Service, os: "Home Assistant OS"),
        R(@"\bhomey\b", "Athom", DeviceType.SmartHomeHub, 0.8, Channel.Strong),
        R(@"\bhubitat\b", "Hubitat", DeviceType.SmartHomeHub, 0.9),

        // ---------------- NAS / servers / virtualisation ----------------
        R(@"\bsynology\b|diskstation|\bDSM\b ?\d?|\b(DS|RS|DVA)\d{3,4}(\+|xs\+?|j|play)?\b", "Synology", DeviceType.Nas, 0.9, os: "DSM"),
        R(@"\bqnap\b|\bQTS\b|\bQuTS\b|\bTS-\d{3,4}|\bTVS-\w+", "QNAP", DeviceType.Nas, 0.9, os: "QTS"),
        R(@"truenas|freenas|ixsystems", "TrueNAS", DeviceType.Nas, 0.9, os: "TrueNAS"),
        R(@"\bunraid\b", "Unraid", DeviceType.Nas, 0.9, os: "Unraid"),
        R(@"\bwd ?my ?cloud\b|\bmycloud\b", "Western Digital", DeviceType.Nas, 0.85),
        R(@"\bnetgear readynas|readynas", "Netgear", DeviceType.Nas, 0.9),
        R(@"\bproxmox\b|^pve\d*$|^pve-|\bPVE\b", "Proxmox", DeviceType.Hypervisor, 0.9, os: "Proxmox VE"),
        R(@"\besxi\b|vmware esx|vsphere|vcenter", "VMware", DeviceType.Hypervisor, 0.9, os: "VMware ESXi"),
        R(@"\bhyper-v\b", "Microsoft", DeviceType.Hypervisor, 0.6, Channel.Text, os: "Windows Server"),
        R(@"\bidrac\b", "Dell", DeviceType.Server, 0.95, os: "iDRAC"),
        R(@"\bilo\b ?\d?|integrated lights-?out|\bproliant\b|^ILO[A-Z0-9]{6,}", "HPE", DeviceType.Server, 0.9, os: "iLO"),
        R(@"\bsupermicro\b|\bsuper micro\b", "Supermicro", DeviceType.Server, 0.8),
        R(@"\bIPMI\b|\bBMC\b", null, DeviceType.Server, 0.6, Channel.Text),
        R(@"plex ?media ?server|^_plexmediasvr\._tcp", null, DeviceType.Server, 0.6, Channel.Strong | Channel.Service),
        R(@"\bubuntu\b|\bdebian\b|\bfedora\b|\bcentos\b|\brhel\b|red hat|\bLinux\b", null, null, 0.7, Channel.Text, os: "Linux"),
        R(@"\bfreebsd\b", null, null, 0.7, Channel.Text, os: "FreeBSD"),
        R(@"^_workstation\._tcp", null, DeviceType.Desktop, 0.25, Channel.Service, os: "Linux"),

        // ---------------- printers ----------------
        R(@"laserjet|officejet|deskjet|\benvy\b ?\d|pagewide|designjet|\bHP (Color|Smart Tank|Neverstop)|^NPI[0-9A-F]{6}|^HP[0-9A-F]{6}\b", "HP", DeviceType.Printer, 0.95),
        R(@"\bbrother\b|^BR[NW][0-9A-F]{12}|\bMFC-[A-Z0-9]+|\bHL-[A-Z0-9]+|\bDCP-[A-Z0-9]+", "Brother", DeviceType.Printer, 0.95),
        R(@"\bcanon\b.*(printer|pixma|mf\d|maxify|imagerunner|i-sensys|selphy)|\bpixma\b|imagerunner|i-sensys|\bmaxify\b|\bselphy\b", "Canon", DeviceType.Printer, 0.95),
        R(@"\bcanon\b", "Canon"),
        R(@"\bepson\b|ecotank|workforce|\bET-\d{4}|\bXP-\d{3,4}", "Epson", DeviceType.Printer, 0.9),
        R(@"\bxerox\b|\bversalink\b|\baltalink\b", "Xerox", DeviceType.Printer, 0.9),
        R(@"\blexmark\b", "Lexmark", DeviceType.Printer, 0.9),
        R(@"\bricoh\b", "Ricoh", DeviceType.Printer, 0.85),
        R(@"\bkyocera\b|ecosys", "Kyocera", DeviceType.Printer, 0.9),
        R(@"^_(ipps?|pdl-datastream|printer|uscan|scanner|ipp-tls)\._tcp", null, DeviceType.Printer, 0.85, Channel.Service),
        R(@"\bprinter\b|\bPrinter:\d\b", null, DeviceType.Printer, 0.7, Channel.Kind | Channel.Model),

        // ---------------- cameras ----------------
        R(@"hikvision|\bDS-2CD|\bDS-7\d{3}|\bDS-2DE", "Hikvision", DeviceType.Camera, 0.9),
        R(@"\bdahua\b|\bIPC-H[DF]W|\bDH-", "Dahua", DeviceType.Camera, 0.9),
        R(@"\baxis\b ?(communications|[A-Z]\d{4})|^_axis-video\._tcp|^AXIS ", "Axis", DeviceType.Camera, 0.9, Channel.Default | Channel.Service),
        R(@"\breolink\b|\bRLC-\d+", "Reolink", DeviceType.Camera, 0.9),
        R(@"\bamcrest\b", "Amcrest", DeviceType.Camera, 0.9),
        R(@"\bwyze\b", "Wyze", DeviceType.Camera, 0.7),
        R(@"\beufy\b", "eufy", DeviceType.Camera, 0.7),
        R(@"\barlo\b", "Arlo", DeviceType.Camera, 0.85),
        R(@"\bezviz\b", "EZVIZ", DeviceType.Camera, 0.85),
        R(@"\bonvif\b|NetworkVideoTransmitter", null, DeviceType.Camera, 0.8, Channel.Strong | Channel.Service),
        R(@"^_rtsp\._tcp", null, DeviceType.Camera, 0.4, Channel.Service),

        // ---------------- audio / media ----------------
        R(@"\bsonos\b|zoneplayer|^_sonos\._tcp", "Sonos", DeviceType.AudioStreamer, 0.95, Channel.Default | Channel.Service),
        R(@"^_spotify-connect\._tcp", null, DeviceType.AudioStreamer, 0.35, Channel.Service),
        R(@"\bbose\b|soundtouch", "Bose", DeviceType.AudioStreamer, 0.9),
        R(@"\bdenon\b|\bheos\b|\bmarantz\b|sound united", "Denon", DeviceType.AudioStreamer, 0.9, Channel.Default | Channel.Service),
        R(@"\byamaha\b|musiccast|\bRX-V\d+", "Yamaha", DeviceType.AudioStreamer, 0.85),
        R(@"bang ?(&|&amp;|and) ?olufsen|beoplay|beosound|beolink|beovision", "Bang & Olufsen", DeviceType.AudioStreamer, 0.9),
        R(@"\belgato\b|key ?light|^_elg\._tcp", "Elgato", DeviceType.Light, 0.9, Channel.Default | Channel.Service),
        R(@"\bnvidia shield\b|^_nvstream\._tcp", "NVIDIA", DeviceType.MediaStreamer, 0.8, Channel.Strong | Channel.Service),
        R(@"MediaRenderer", null, DeviceType.MediaStreamer, 0.4, Channel.Kind),

        // ---------------- power / UPS / VoIP ----------------
        R(@"\bAPC\b|american power conversion|smart-?ups|back-?ups|\bAP9\d{3}|powerchute|schneider electric it", "APC", DeviceType.Ups, 0.9),
        R(@"\beaton\b|\bcyberpower\b", null, DeviceType.Ups, 0.7, Channel.Strong),
        R(@"\byealink\b|\bpolycom\b|\bsnom\b|\bgrandstream\b|\bIP ?phone\b|\bSIP-T\d", null, DeviceType.VoipPhone, 0.85),
    ];

    /// <summary>Brand-specific product-line rules (applied after the brand is chosen).</summary>
    public static IReadOnlyList<ClassifierRule> ProductLines { get; } =
    [
        // Netgear
        B("Netgear", @"\b(?<model>(GS|GSM|XS|MS|JGS|JGSM|GC)\d{3,4}[A-Z]{0,4}(v\d)?)\b", DeviceType.AccessSwitch),
        B("Netgear", @"\b(?<model>RB[RK]\d{2,4}[A-Z]?)\b|\borbi\b(?! satellite)", DeviceType.Router, model: null),
        B("Netgear", @"\b(?<model>RBS\d{2,4}[A-Z]?)\b|orbi satellite", DeviceType.AccessPoint),
        B("Netgear", @"\b(?<model>(R|RAX|RS|XR|C|CAX|CM)\d{3,4}[A-Z]?\d?)\b|nighthawk", DeviceType.Router, 0.8),
        B("Netgear", @"\b(?<model>(WAX|WAC|WAX6|WNDAP)\d{3}[A-Z]?)\b", DeviceType.AccessPoint),
        B("Netgear", @"\b(?<model>EX\d{4})\b", DeviceType.AccessPoint),
        // Ubiquiti
        B("Ubiquiti", @"\b(?<model>(UAP|U6|U7|UAL|UAC)[-\w+]*)\b|nanohd|flexhd|unifi ?ap|access point", DeviceType.AccessPoint),
        B("Ubiquiti", @"\b(?<model>(USW|US|USL)-[\w-]+)\b|unifi ?switch|edgeswitch|\bES-\d", DeviceType.AccessSwitch),
        B("Ubiquiti", @"\b(?<model>(UDM|UDR|UXG|USG|UCG|UDW|EFG)[-\w]*)\b|dream ?machine|dream ?router|cloud ?gateway|unifi ?gateway|unifi ?os", DeviceType.Router, os: "UniFi OS"),
        B("Ubiquiti", @"edgerouter|\b(?<model>ER-[\w]+)\b|edgeos", DeviceType.Router, os: "EdgeOS"),
        B("Ubiquiti", @"\b(?<model>(UVC|G4|G5)[- ][\w-]+)\b|unifi ?protect|unifi ?video", DeviceType.Camera),
        B("Ubiquiti", @"\b(?<model>UNVR[\w-]*|UCK[\w-]*)\b|cloud ?key", DeviceType.Server),
        // Cisco / Meraki
        B("Meraki", @"\b(?<model>MR\d{2,3}[A-Z]?)\b", DeviceType.AccessPoint),
        B("Meraki", @"\b(?<model>MS\d{2,3}[-\w]*)\b", DeviceType.AccessSwitch),
        B("Meraki", @"\b(?<model>(MX|Z)\d{1,3}[A-Z]?)\b", DeviceType.Firewall),
        B("Meraki", @"\b(?<model>MV\d{2}[A-Z]?)\b", DeviceType.Camera),
        B("Cisco", @"\b(?<model>(WS-C|C9[2-5]00|C3850|C3650|C2960|C1000|CBS\d{3}|SG\d{3})[-\w]*)\b|catalyst|nx-os|nexus", DeviceType.AccessSwitch),
        B("Cisco", @"\b(?<model>(ISR|ASR|C11\d\d|C8\d{3})[-\w]*)\b", DeviceType.Router),
        B("Cisco", @"\b(?<model>(ASA|FPR)[-\w]*)\b|firepower|adaptive security", DeviceType.Firewall),
        B("Cisco", @"\b(?<model>(AIR-|C91\d\d|CW91\d\d)[-\w]*)\b|aironet", DeviceType.AccessPoint),
        B("Cisco", @"\b(?<model>(CP-|SPA)\d[-\w]*)\b|ip phone", DeviceType.VoipPhone),
        B("Cisco", @"\bcisco ios\b", DeviceType.Router, 0.5, os: "Cisco IOS"),
        // TP-Link
        B("TP-Link", @"\b(?<model>deco ?[A-Z]{0,2}\d+[\w]*)\b", DeviceType.AccessPoint, model: null),
        B("TP-Link", @"\b(?<model>EAP\d{3}[-\w]*)\b|omada ?ap", DeviceType.AccessPoint),
        B("TP-Link", @"\b(?<model>(TL-SG|TL-SX|TL-SL|SG|SX)\d{3,4}[\w-]*)\b", DeviceType.AccessSwitch),
        B("TP-Link", @"\b(?<model>(ER|TL-ER)\d{3,4}[\w-]*)\b|\b(?<model>archer [A-Z]*\d+[\w]*)\b", DeviceType.Router),
        B("TP-Link", @"\b(?<model>(HS|KP|EP|KS)\d{3}[\w]*)\b|\bkasa\b.*plug|\btapo ?p\d+|\b(?<model>P1\d{2}[M]?)\b", DeviceType.SmartPlug),
        B("TP-Link", @"\b(?<model>(KL|L)\d{3}[\w]*)\b|\btapo ?l\d+", DeviceType.Light),
        B("TP-Link", @"\btapo ?(?<model>C\d{3}[\w]*)\b|\b(?<model>C[12]\d{2})\b|kasa ?cam", DeviceType.Camera),
        B("TP-Link", @"\b(?<model>(RE|TL-WA)\d{3}[\w]*)\b", DeviceType.AccessPoint),
        // MikroTik
        B("MikroTik", @"\b(?<model>(CRS|CSS)\d{3}[-\w+]*)(?![\w+])", DeviceType.AccessSwitch),
        B("MikroTik", @"\b(?<model>(cAP|wAP|mAP)[\w ²]*)\b", DeviceType.AccessPoint),
        B("MikroTik", @"\b(?<model>(RB|CCR|hEX|hAP|RB\d)[-\w²+]*)(?![\w+])|routeros", DeviceType.Router, 0.7),
        // Fortinet
        B("Fortinet", @"\b(?<model>(FortiGate|FGT|FG)[-\w]*)\b|fortios", DeviceType.Firewall, os: "FortiOS"),
        B("Fortinet", @"\b(?<model>(FortiSwitch|FS)-\w+)\b", DeviceType.AccessSwitch),
        B("Fortinet", @"\b(?<model>(FortiAP|FAP)-?\w+)\b", DeviceType.AccessPoint),
        // AVM
        B("AVM", @"(?<model>fritz!?\s?box\s?\d{4}[\w ]*?)(\s|$)|fritz!?box|fritz\.box", DeviceType.Router, os: "FRITZ!OS"),
        B("AVM", @"(?<model>fritz!?\s?repeater\s?\w*)", DeviceType.AccessPoint),
        B("AVM", @"(?<model>fritz!?\s?dect\s?\d+)", DeviceType.SmartPlug),
        // ASUS
        B("ASUS", @"\b(?<model>(RT|GT|TUF|ZenWiFi|XT|XD|RP)-?[A-Z]{0,4}\d{2,5}[\w]*)\b|asuswrt|zenwifi", DeviceType.Router, os: "ASUSWRT"),
        // D-Link
        B("D-Link", @"\b(?<model>DIR-\w+)\b", DeviceType.Router),
        B("D-Link", @"\b(?<model>(DGS|DES|DXS)-[\w-]+)\b", DeviceType.AccessSwitch),
        B("D-Link", @"\b(?<model>DCS-\w+)\b", DeviceType.Camera),
        B("D-Link", @"\b(?<model>DAP-\w+)\b", DeviceType.AccessPoint),
        // Zyxel
        B("Zyxel", @"\b(?<model>(GS|XGS|XS|GS1900|MS)\d{3,4}[-\w]*)\b", DeviceType.AccessSwitch),
        B("Zyxel", @"\b(?<model>(USG FLEX|ZyWALL|ATP|USG)\s?\d+[\w]*)\b", DeviceType.Firewall),
        B("Zyxel", @"\b(?<model>(NWA|WAX|WAC)\d+[\w]*)\b", DeviceType.AccessPoint),
        B("Zyxel", @"\b(?<model>(NBG|VMG|EX|AX|DX)\d{3,4}[\w-]*)\b|armor", DeviceType.Router),
        // Aruba
        B("Aruba", @"\b(?<model>(AP|IAP)-\d{3}[\w]*)\b|instant on ap|access point", DeviceType.AccessPoint),
        B("Aruba", @"\b(?<model>(\d{4}[A-Z]?|CX ?\d{4}|JL\d{3}A))\b.*switch|arubaos-cx|\bswitch\b", DeviceType.AccessSwitch),
        // Juniper
        B("Juniper", @"\b(?<model>EX\d{4}[-\w]*)\b", DeviceType.AccessSwitch),
        B("Juniper", @"\b(?<model>QFX\d{4}[-\w]*)\b", DeviceType.CoreSwitch),
        B("Juniper", @"\b(?<model>SRX\d{3,4}[\w]*)\b", DeviceType.Firewall),
        B("Juniper", @"\b(?<model>(MX|ACX|PTX)\d{2,4}[\w]*)\b", DeviceType.Router),
        B("Juniper", @"\bmist\b|\b(?<model>AP\d{2}[\w]*)\b", DeviceType.AccessPoint),
        // Huawei
        B("Huawei", @"\b(?<model>(HG|B|HN|EG)\d{3,4}[\w-]*)\b|echolife|ax3", DeviceType.Router),
        B("Huawei", @"\b(?<model>S\d{4}[-\w]*)\b", DeviceType.AccessSwitch),
        B("Huawei", @"\bmate\b|\bnova\b|\bP\d{2}\b", DeviceType.Phone, os: "Android"),
        // Samsung / Google / Apple misc
        B("Samsung", @"\bfamily ?hub\b|refrigerator|washer|dryer", DeviceType.IoT),
        B("Synology", @"\b(?<model>(DS|RS|DVA|DX|FS|SA)\d{3,4}(\+|xs\+?|j|play)?)(?![\w+])", DeviceType.Nas),
        B("Synology", @"\b(?<model>(RT|MR|WRX)\d{3,4}\w*)\b|synology router|\bSRM\b", DeviceType.Router, os: "SRM"),
        B("QNAP", @"\b(?<model>(TS|TVS|TS-h|TBS)-[\w-]+)\b", DeviceType.Nas),
        B("Hikvision", @"\b(?<model>DS-[\w-]+)\b", DeviceType.Camera),
        B("Sonos", @"\b(?<model>(One SL|One|Play:1|Play:3|Play:5|Beam|Arc Ultra|Arc|Ray|Era 100|Era 300|Move 2|Move|Roam 2|Roam SL|Roam|Five|Sub Mini|Sub|Amp|Port|Connect:Amp|Connect|Playbar|Playbase|Ace))\b", DeviceType.AudioStreamer),
        B("Sonos", @"\bboost\b|\bbridge\b", DeviceType.AccessPoint, 0.6),
        B("APC", @"\b(?<model>(Smart-UPS|Back-UPS|SMT|SMX|SRT)[\w -]*?\d{3,4}\w*)", DeviceType.Ups),
        B("HP", @"\b(?<model>(LaserJet|OfficeJet|DeskJet|ENVY|PageWide|Color LaserJet|Smart Tank)[\w -]*?\d{3,4}\w*)", DeviceType.Printer),
        B("Brother", @"\b(?<model>(MFC|HL|DCP)-[\w]+)\b", DeviceType.Printer),
        B("Epson", @"\b(?<model>(ET|XP|WF|L)-?\d{3,5}\w*)\b", DeviceType.Printer),
    ];

    /// <summary>SNMP enterprise numbers (1.3.6.1.4.1.N) → brand (and optional type hint).</summary>
    public static IReadOnlyDictionary<int, (string Brand, DeviceType? Type)> Enterprises { get; } = new Dictionary<int, (string, DeviceType?)>
    {
        [9] = ("Cisco", null), [4526] = ("Netgear", null), [41112] = ("Ubiquiti", null), [10002] = ("Ubiquiti", DeviceType.AccessPoint),
        [14988] = ("MikroTik", DeviceType.Router), [12356] = ("Fortinet", DeviceType.Firewall), [11] = ("HP", null), [232] = ("HPE", DeviceType.Server),
        [674] = ("Dell", null), [318] = ("APC", DeviceType.Ups), [2636] = ("Juniper", null), [14823] = ("Aruba", null), [2011] = ("Huawei", null),
        [171] = ("D-Link", null), [890] = ("Zyxel", null), [11863] = ("TP-Link", null), [6574] = ("Synology", DeviceType.Nas), [24681] = ("QNAP", DeviceType.Nas),
        [55062] = ("QNAP", DeviceType.Nas), [311] = ("Microsoft", null), [2435] = ("Brother", DeviceType.Printer), [1602] = ("Canon", DeviceType.Printer),
        [1248] = ("Epson", DeviceType.Printer), [367] = ("Ricoh", DeviceType.Printer), [253] = ("Xerox", DeviceType.Printer), [641] = ("Lexmark", DeviceType.Printer),
        [1347] = ("Kyocera", DeviceType.Printer), [25506] = ("H3C", null), [30065] = ("Arista", DeviceType.CoreSwitch), [1916] = ("Extreme Networks", null),
        [25053] = ("Ruckus", DeviceType.AccessPoint), [29671] = ("Meraki", null), [6876] = ("VMware", DeviceType.Hypervisor), [368] = ("Axis", DeviceType.Camera),
        [39165] = ("Hikvision", DeviceType.Camera), [8072] = ("", null), [2021] = ("", null), [12325] = ("Netgate", DeviceType.Firewall),
        [21067] = ("Supermicro", DeviceType.Server), [10876] = ("Supermicro", DeviceType.Server), [534] = ("Eaton", DeviceType.Ups), [3808] = ("CyberPower", DeviceType.Ups),
        [8741] = ("SonicWall", DeviceType.Firewall), [3097] = ("WatchGuard", DeviceType.Firewall), [25461] = ("Palo Alto", DeviceType.Firewall),
        [2604] = ("Sophos", DeviceType.Firewall), [872] = ("AVM", DeviceType.Router), [5624] = ("Enterasys", null), [4413] = ("Broadcom", null),
        [8691] = ("Moxa", null), [17713] = ("Cambium", DeviceType.AccessPoint), [7779] = ("Infoblox", DeviceType.Server), [3375] = ("F5", null),
    };

    /// <summary>Normalized brands that are mostly chipset/ODM vendors: OUI alone is weak brand evidence for them.</summary>
    public static IReadOnlySet<string> ChipsetVendors { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Espressif", "Realtek", "Murata", "AzureWave", "Foxconn", "Lite-On", "Texas Instruments", "Silicon Labs", "Quectel", "USI", "Gaoshengda",
        "Fugui", "Qualcomm", "MediaTek", "Broadcom", "AMPAK", "Arcadyan", "Sagemcom", "Sercomm", "Askey", "Wistron", "Pegatron", "Compal",
        "Intel", "Liteon", "Tuya", "Technicolor", "Inventec", "Universal Global Scientific", "Hui Zhou Gaoshengda", "Chongqing Fugui", "Shenzhen",
    };
}
