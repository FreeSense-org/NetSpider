using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace NetSpider.Fingerprint;

/// <summary>Turns registered company names ("TP-LINK TECHNOLOGIES CO.,LTD.") into short consumer brands ("TP-Link").</summary>
public static class BrandNormalizer
{
    private static readonly (Regex Pattern, string Brand)[] Overrides = Build(
    [
        // Other companies whose names would otherwise reduce to a well-known brand; they keep their own name.
        (@"^Arista Corp", "Arista Corporation"),
        (@"^AVM Electronics", "AVM Electronics"),
        (@"^Axis Corporation", "Axis Corporation"),
        (@"^Bang and Olufsen Medicom", "Bang and Olufsen Medicom"),
        (@"^Beijing ECHO", "Beijing ECHO"),
        (@"^Brother, Brother", "Brother, Brother & Sons"),
        (@"Dahua Scale", "Dahua Scale"),
        (@"^Broadlink Pty", "Broadlink Pty"),
        (@"^Juniper Systems", "Juniper Systems"),
        (@"^Marshall Electronics", "Marshall Electronics"),
        (@"^META SYSTEM", "Meta System"),
        (@"^Ring Solutions", "Ring Solutions"),
        (@"^Vivo International", "Vivo International"),

        (@"^LCFC", "Lenovo"), // Lenovo's own manufacturing subsidiary, LCFC (Hefei) Electronics
        (@"^TP-?LINK", "TP-Link"),
        (@"^HUAWEI|^Huawei", "Huawei"),
        (@"Hon ?Hai|Foxconn|^CLOUD NETWORK TECHNOLOGY SINGAPORE", "Foxconn"),
        (@"^Aruba", "Aruba"),
        (@"^Hewlett Packard Enterprise|^HPE\b|^ProCurve|^HPN Supply Chain", "HPE"),
        (@"^Hewlett[ -]?Packard|^HP Inc", "HP"),
        (@"^ASUSTek|^ASUS\b", "ASUS"),
        (@"^Samsung", "Samsung"),
        (@"^Sony", "Sony"),
        (@"^LG ", "LG"),
        (@"^Intel\b", "Intel"),
        (@"^Amazon", "Amazon"),
        (@"^Google|^Nest Labs", "Google"),
        (@"^Microsoft", "Microsoft"),
        (@"Xiaomi", "Xiaomi"),
        (@"^zte\b", "ZTE"),
        (@"^Ubiquiti", "Ubiquiti"),
        (@"^Cisco Meraki|^Meraki", "Meraki"),
        (@"^Cisco[- ]Linksys|^Linksys", "Linksys"),
        (@"^Cisco", "Cisco"),
        (@"^Juniper", "Juniper"),
        (@"^Murata Manufacturing", "Murata"),
        (@"^D-?Link", "D-Link"),
        (@"^Zyxel", "Zyxel"),
        (@"^AVM\b|^AVM Audiovisuelles", "AVM"),
        (@"^Synology", "Synology"),
        (@"^QNAP", "QNAP"),
        (@"Hikvision", "Hikvision"),
        (@"Dahua", "Dahua"),
        (@"^Axis Communications", "Axis"),
        (@"Reolink", "Reolink"),
        (@"^Signify|^Philips Lighting", "Philips Hue"),
        (@"^Philips", "Philips"),
        (@"^Sonos\b", "Sonos"),
        (@"^Roku", "Roku"),
        (@"^Nintendo", "Nintendo"),
        (@"^Raspberry ?Pi", "Raspberry Pi"),
        (@"^Espressif", "Espressif"),
        (@"Tuya", "Tuya"),
        (@"Allterco|^Shelly", "Shelly"),
        (@"^Lite-?On", "Lite-On"),
        (@"^Texas Instruments", "Texas Instruments"),
        (@"^Silicon Lab", "Silicon Labs"),
        (@"^Arcadyan", "Arcadyan"),
        (@"^Sagemcom", "Sagemcom"),
        (@"^ARRIS", "ARRIS"),
        (@"^Commscope", "CommScope"),
        (@"^Dell\b", "Dell"),
        (@"^Motorola Mobility", "Motorola"),
        (@"^Lenovo", "Lenovo"),
        (@"^Fortinet", "Fortinet"),
        (@"^MikroTik|^Routerboard", "MikroTik"),
        (@"^NETGEAR", "Netgear"),
        (@"^Belkin", "Belkin"),
        (@"^Extreme Networks", "Extreme Networks"),
        (@"^Ruckus", "Ruckus"),
        (@"^Arista", "Arista"),
        (@"^Brother", "Brother"),
        (@"^Canon", "Canon"),
        (@"Epson", "Epson"),
        (@"^Bose\b", "Bose"),
        (@"^Sound United|^Denon|^D&M Holdings", "Denon"),
        (@"^Yamaha", "Yamaha"),
        (@"^Bang ?(&|&amp;|and) ?Olufsen", "Bang & Olufsen"),
        (@"^Super ?Micro", "Supermicro"),
        (@"^American Power Conversion|^Schneider Electric IT", "APC"),
        (@"^VMware", "VMware"),
        (@"^PCS Systemtechnik", "VirtualBox"),
        (@"^Elgato", "Elgato"),
        (@"^eero\b", "eero"),
        (@"^IKEA", "IKEA"),
        (@"^GUANGDONG OPPO", "OPPO"),
        (@"^OnePlus", "OnePlus"),
        (@"^vivo Mobile", "vivo"),
        (@"^Realme", "realme"),
        (@"^Honor Device", "Honor"),
        (@"^Nokia", "Nokia"),
        (@"H3C", "H3C"),
        (@"^Fiberhome", "FiberHome"),
        (@"^Universal Global Scientific", "USI"),
        (@"Gaoshengda", "Gaoshengda"),
        (@"^Chongqing Fugui", "Fugui"),
        (@"^Sercomm", "Sercomm"),
        (@"^Technicolor|^Vantiva|^Thomson Telecom", "Technicolor"),
        (@"EZVIZ", "EZVIZ"),
        (@"^Wyze", "Wyze"),
        (@"^Tenda|Shenzhen Tenda", "Tenda"),
        (@"^Hisense", "Hisense"),
        (@"^TCL\b", "TCL"),
        (@"^VIZIO\b", "Vizio"),
        (@"^Ring LLC", "Ring"),
        (@"^Arlo\b", "Arlo"),
        (@"^Polycom|^Plantronics", "Poly"),
        (@"^Yealink", "Yealink"),
        (@"^Grandstream", "Grandstream"),
        (@"^Xerox", "Xerox"),
        (@"^Lexmark", "Lexmark"),
        (@"^Ricoh", "Ricoh"),
        (@"^Kyocera", "Kyocera"),
        (@"^Proxmox", "Proxmox"),
        (@"^Netgate|Rubicon Communications", "Netgate"),
        (@"^Deciso", "OPNsense"),
        (@"^Realtek", "Realtek"),
        (@"^MediaTek", "MediaTek"),
        (@"^Qualcomm", "Qualcomm"),
        (@"^Broadcom", "Broadcom"),
        (@"^AzureWave", "AzureWave"),
        (@"^Quectel", "Quectel"),
        (@"^Ampak", "AMPAK"),
        (@"^Acer\b", "Acer"),
        (@"^ASRock", "ASRock"),
        (@"^Compal\b", "Compal"),
        (@"^Giga-?Byte", "Gigabyte"),
        (@"^Micro-?Star", "MSI"),
        (@"^Quanta (Computer|Network|Microsystems|Storage)", "Quanta"),
        (@"Skyworth", "Skyworth"),
        (@"^Wistron", "Wistron"),
        (@"^Advanced Micro Devices|^AMD\b", "AMD"),
        (@"^Alcatel-Lucent Enterprise", "Alcatel-Lucent Enterprise"),
        (@"^Alcatel[- ]?Lucent", "Nokia"),
        (@"^ABB\b", "ABB"),
        (@"^Accton", "Accton"),
        (@"^Adtran\b", "Adtran"),
        (@"^Allied Teles[iy][sn]", "Allied Telesis"),
        (@"^AT&T|^AT&amp;T", "AT&T"),
        (@"^BlackBerry|^Research In Motion|^RIM\b", "BlackBerry"),
        (@"^Check Point", "Check Point"),
        (@"^China Mobile", "China Mobile"),
        (@"^Comcast", "Xfinity"),
        (@"^Delta Electronics", "Delta Electronics"),
        (@"\bDJI\b", "DJI"),
        (@"^Edge-?Core", "Edgecore"),
        (@"^Ericsson\b|LM Ericsson", "Ericsson"),
        (@"^Flextronics", "Flex"),
        (@"^Fujitsu", "Fujitsu"),
        (@"Goertek", "Goertek"),
        (@"^GREE Electric", "Gree"),
        (@"Haier", "Haier"),
        (@"^Hanwha", "Hanwha"),
        (@"^Hitachi", "Hitachi"),
        (@"^HMD Global", "HMD"),
        (@"^International Business Machines|^IBM\b", "IBM"),
        (@"^Infineon", "Infineon"),
        (@"^Infinix", "Infinix"),
        (@"^ITEL MOBILE", "itel"),
        (@"^Jabil", "Jabil"),
        (@"^GN (Netcom|Audio)|^Jabra", "Jabra"),
        (@"^Konica ?Minolta", "Konica Minolta"),
        (@"Changhong", "Changhong"),
        (@"\bMidea\b", "Midea"),
        (@"^Microchip", "Microchip"),
        (@"^Mitsubishi Electric", "Mitsubishi Electric"),
        (@"^NEC\b", "NEC"),
        (@"^Nordic Semiconductor", "Nordic Semiconductor"),
        (@"^NXP", "NXP"),
        (@"^Oki (Electric|Data)", "OKI"),
        (@"^Oracle|^Sun Microsystems", "Oracle"),
        (@"^Renesas", "Renesas"),
        (@"^Rockwell Automation", "Rockwell Automation"),
        (@"^Schneider Electric", "Schneider Electric"),
        (@"^Sierra Wireless", "Sierra Wireless"),
        (@"^SKY UK|^Sky Italia|^Sky Deutschland", "Sky"),
        (@"^ST ?Microelectronics", "STMicroelectronics"),
        (@"^Sumitomo Electric", "Sumitomo Electric"),
        (@"^TCT mobile", "TCL"),
        (@"^Tecno\b", "Tecno"),
        (@"^Toshiba", "Toshiba"),
        (@"^Verizon", "Verizon"),
        (@"^Vodafone", "Vodafone"),
        (@"^Zebra Technologies", "Zebra"),
    ]);

    private static readonly HashSet<string> SuffixTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "inc", "incorporated", "ltd", "limited", "co", "corp", "corporation", "company", "llc", "l.l.c", "gmbh", "ag", "sa", "s.a", "sas", "s.a.s",
        "bv", "b.v", "nv", "n.v", "ab", "as", "a/s", "aps", "oy", "oyj", "spa", "s.p.a", "srl", "s.r.l", "pte", "pty", "plc", "kg", "kk", "co.ltd",
        "co.,ltd", "technologies", "technology", "tech", "electronics", "electronic", "communications", "communication", "systems", "system",
        "networks", "network", "international", "intl", "holdings", "holding", "group", "trading", "industrial", "industries", "ind", "industry",
        "manufacturing", "mfg", "products", "solutions", "corporate", "precision", "sdn", "bhd", "s.l", "sl", "se", "ug", "mbh", "&", "and", "the",
        "devices", "device", "enterprises", "labs", "lab", "development", "dev", "jsc", "ooo", "zao", "llp", "lp", "ltda", "s.de", "r.l", "c.v", "de",
    };

    private static readonly HashSet<string> CityPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "shenzhen", "guangzhou", "guangdong", "hangzhou", "beijing", "shanghai", "zhejiang", "jiangsu", "xiamen", "fujian", "dongguan", "suzhou",
        "ningbo", "wuhan", "chengdu", "qingdao", "tianjin", "hefei", "nanjing", "sichuan", "chongqing", "huizhou", "taicang", "zhuhai", "foshan",
        "shandong", "jiangxi", "hunan", "hubei", "anhui", "kunshan", "wuxi", "changzhou", "zhongshan", "jiaxing", "hui", "zhou",
    };

    private static (Regex, string)[] Build((string, string)[] items) =>
        items.Select(i => (new Regex(i.Item1, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled), i.Item2)).ToArray();

    /// <summary>Returns a short brand name, or null for empty/private/placeholder registrations.</summary>
    public static string? Normalize(string? organization)
    {
        if (string.IsNullOrWhiteSpace(organization)) return null;
        var name = string.Join(' ', organization.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).Trim().Trim('"');
        if (name.Length == 0 || name.Equals("Private", StringComparison.OrdinalIgnoreCase) || name.StartsWith("IEEE Registration Authority", StringComparison.OrdinalIgnoreCase))
            return null;

        foreach (var (p, brand) in Overrides)
            if (p.IsMatch(name)) return brand;

        // drop parentheticals and everything after the first comma ("Sonos, Inc." -> "Sonos")
        var s = Regex.Replace(name, @"\(.*?\)", " ");
        s = s.Replace('，', ',');
        int comma = s.IndexOf(',');
        if (comma > 0) s = s[..comma];

        var words = s.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        while (words.Count > 1 && CityPrefixes.Contains(words[0].Trim('.', ','))) words.RemoveAt(0);
        while (words.Count > 1 && SuffixTokens.Contains(words[^1].Trim('.', ',')))
            words.RemoveAt(words.Count - 1);
        // "Foo Co.,Ltd" glued forms
        if (words.Count > 0)
        {
            var last = Regex.Replace(words[^1], @"(?i)(co\.?,?\s*ltd\.?|,?ltd\.?|,?inc\.?)$", "").TrimEnd('.', ',');
            if (last.Length > 0) words[^1] = last;
            else if (words.Count > 1) words.RemoveAt(words.Count - 1);
        }
        if (words.Count == 0) return name;

        var sb = new StringBuilder();
        foreach (var w in words)
        {
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(FixCase(w));
        }
        var result = sb.ToString().Trim(' ', '.', ',', '-');
        return result.Length == 0 ? name : result;
    }

    private static string FixCase(string w)
    {
        int letters = 0, upper = 0;
        foreach (var c in w) { if (char.IsLetter(c)) { letters++; if (char.IsUpper(c)) upper++; } }
        if (letters >= 5 && upper == letters)
            return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(w.ToLowerInvariant());
        return w;
    }

    /// <summary>Stable file-system/lookup key for a brand: "TP-Link" -> "tp-link", "Bang &amp; Olufsen" -> "bang-olufsen".</summary>
    public static string Key(string brand)
    {
        var sb = new StringBuilder(brand.Length);
        bool dash = false;
        foreach (var c in brand.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(c)) { sb.Append(c); dash = false; }
            else if (!dash && sb.Length > 0) { sb.Append('-'); dash = true; }
        }
        return sb.ToString().TrimEnd('-');
    }
}
