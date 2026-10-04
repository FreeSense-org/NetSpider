using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Export.Exporters;

/// <summary>
/// Nmap-compatible XML (nmap.dtd, xmloutputversion 1.05) so results can be opened in Zenmap, diffed with ndiff or imported
/// into tools that consume Nmap output. Synthetic nodes and hosts without any IP address are omitted.
/// </summary>
public sealed class NmapXmlExporter : IExporter
{
    public string Name => "Nmap XML";
    public string FileExtension => ".xml";

    public async Task ExportAsync(string path, ExportData data, CancellationToken ct = default)
    {
        var xml = Build(data, DateTimeOffset.Now);
        ExportFile.EnsureDirectory(path);
        await File.WriteAllTextAsync(path, xml, new UTF8Encoding(false), ct).ConfigureAwait(false);
    }

    public static string Build(ExportData data, DateTimeOffset now)
    {
        var hosts = data.Devices
            .Where(d => !SyntheticNodes.IsGraphOnly(d.Mac) && (d.IPv4.Length > 0 || d.IPv6.Length > 0))
            .OrderBy(d => ExportText.IpSortKey(d.PrimaryIPv4))
            .ToList();

        long start = hosts.Count == 0 ? now.ToUnixTimeSeconds() : Math.Min(now.ToUnixTimeSeconds(), hosts.Min(h => h.FirstSeen.ToUnixTimeSeconds()));
        var tcpPorts = hosts.SelectMany(h => h.Ports).Where(p => IsTcp(p.Protocol)).Select(p => p.Port).Distinct().Order().ToList();
        var udpPorts = hosts.SelectMany(h => h.Ports).Where(p => !IsTcp(p.Protocol)).Select(p => p.Port).Distinct().Order().ToList();

        // XmlWriter over a StringBuilder would declare utf-16; write the declaration ourselves (the file is saved as UTF-8).
        var sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        var settings = new XmlWriterSettings { Indent = true, OmitXmlDeclaration = true, NewLineChars = "\n" };
        using (var w = XmlWriter.Create(sb, settings))
        {
            w.WriteDocType("nmaprun", null, null, null);
            w.WriteProcessingInstruction("xml-stylesheet", "href=\"file:///usr/share/nmap/nmap.xsl\" type=\"text/xsl\"");
            w.WriteComment($" NetSpider {ExportText.AppVersion} scan exported as Nmap XML on {ExportText.Time(now)} ");

            w.WriteStartElement("nmaprun");
            w.WriteAttributeString("scanner", "nmap");
            w.WriteAttributeString("args", Clean($"netspider (L2/L3 discovery) {data.Adapter?.Name}".Trim()));
            w.WriteAttributeString("start", Num(start));
            w.WriteAttributeString("startstr", Ctime(DateTimeOffset.FromUnixTimeSeconds(start).ToLocalTime()));
            w.WriteAttributeString("version", "7.94");
            w.WriteAttributeString("xmloutputversion", "1.05");

            WriteScanInfo(w, "syn", "tcp", tcpPorts);
            if (udpPorts.Count > 0) WriteScanInfo(w, "udp", "udp", udpPorts);
            w.WriteStartElement("verbose"); w.WriteAttributeString("level", "0"); w.WriteEndElement();
            w.WriteStartElement("debugging"); w.WriteAttributeString("level", "0"); w.WriteEndElement();

            foreach (var d in hosts) WriteHost(w, d);

            int up = hosts.Count(h => h.State != DeviceState.Offline);
            w.WriteStartElement("runstats");
            w.WriteStartElement("finished");
            w.WriteAttributeString("time", Num(now.ToUnixTimeSeconds()));
            w.WriteAttributeString("timestr", Ctime(now));
            w.WriteAttributeString("summary", $"NetSpider done at {Ctime(now)}; {hosts.Count} IP addresses ({up} hosts up) scanned");
            w.WriteAttributeString("elapsed", (now.ToUnixTimeSeconds() - start).ToString(CultureInfo.InvariantCulture) + ".00");
            w.WriteAttributeString("exit", "success");
            w.WriteEndElement();
            w.WriteStartElement("hosts");
            w.WriteAttributeString("up", Num(up));
            w.WriteAttributeString("down", Num(hosts.Count - up));
            w.WriteAttributeString("total", Num(hosts.Count));
            w.WriteEndElement();
            w.WriteEndElement(); // runstats

            w.WriteEndElement(); // nmaprun
        }
        sb.Append('\n');
        return sb.ToString();
    }

    private static void WriteScanInfo(XmlWriter w, string type, string protocol, List<int> ports)
    {
        w.WriteStartElement("scaninfo");
        w.WriteAttributeString("type", type);
        w.WriteAttributeString("protocol", protocol);
        w.WriteAttributeString("numservices", Num(ports.Count));
        w.WriteAttributeString("services", CompressPorts(ports));
        w.WriteEndElement();
    }

    private static void WriteHost(XmlWriter w, Device d)
    {
        bool up = d.State != DeviceState.Offline;
        w.WriteStartElement("host");
        w.WriteAttributeString("starttime", Num(d.FirstSeen.ToUnixTimeSeconds()));
        w.WriteAttributeString("endtime", Num(d.LastSeen.ToUnixTimeSeconds()));

        w.WriteStartElement("status");
        w.WriteAttributeString("state", up ? "up" : "down");
        w.WriteAttributeString("reason", !up ? "no-response"
            : d.Latency.Last(LatencyKind.Arp) is not null ? "arp-response"
            : d.Latency.Last(LatencyKind.Ndp) is not null ? "nd-response"
            : d.Latency.Last(LatencyKind.Icmp) is not null ? "echo-reply"
            : d.Has(DeviceFlags.ThisHost) ? "localhost-response" : "user-set");
        w.WriteAttributeString("reason_ttl", Num(d.Ttl ?? 0));
        w.WriteEndElement();

        foreach (var ip in d.IPv4.OrderBy(ExportText.IpSortKey)) WriteAddress(w, ip.ToString(), "ipv4", null);
        foreach (var ip in d.IPv6.Select(x => x.Address).OrderBy(a => a.IsIPv6LinkLocal)) WriteAddress(w, ip.ToString(), "ipv6", null);
        if (!d.Mac.IsZero) WriteAddress(w, d.Mac.ToString(), "mac", d.OuiVendor ?? d.Brand);

        w.WriteStartElement("hostnames");
        var hostnames = d.Hostnames;
        var written = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (hostnames.TryGetValue("dns", out var ptr) && written.Add(ptr)) WriteHostname(w, ptr, "PTR");
        foreach (var (src, name) in hostnames.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            if (written.Add(name)) WriteHostname(w, name, "user");
        if (d.UserLabel is { } label && written.Add(label)) WriteHostname(w, label, "user");
        w.WriteEndElement();

        var ports = d.Ports;
        if (ports.Length > 0)
        {
            w.WriteStartElement("ports");
            foreach (var p in ports.OrderBy(p => IsTcp(p.Protocol) ? 0 : 1).ThenBy(p => p.Port)) WritePort(w, p, d);
            w.WriteEndElement();
        }

        if (!string.IsNullOrWhiteSpace(d.OsGuess)) WriteOs(w, d);

        var icmp = d.Latency.Summarize(LatencyKind.Icmp);
        var best = icmp.Avg is not null ? icmp : d.Latency.Summarize(LatencyKind.Arp);
        if (best.Avg is { } avg)
        {
            long srtt = (long)Math.Round(avg * 1000);
            long rttvar = (long)Math.Round((best.Jitter ?? 0) * 1000);
            w.WriteStartElement("times");
            w.WriteAttributeString("srtt", Num(srtt));
            w.WriteAttributeString("rttvar", Num(rttvar));
            w.WriteAttributeString("to", Num(Math.Max(100_000, srtt + 4 * rttvar)));
            w.WriteEndElement();
        }

        w.WriteEndElement(); // host
    }

    private static void WriteAddress(XmlWriter w, string addr, string type, string? vendor)
    {
        w.WriteStartElement("address");
        w.WriteAttributeString("addr", addr);
        w.WriteAttributeString("addrtype", type);
        if (!string.IsNullOrWhiteSpace(vendor)) w.WriteAttributeString("vendor", Clean(vendor));
        w.WriteEndElement();
    }

    private static void WriteHostname(XmlWriter w, string name, string type)
    {
        w.WriteStartElement("hostname");
        w.WriteAttributeString("name", Clean(name));
        w.WriteAttributeString("type", type);
        w.WriteEndElement();
    }

    private static void WritePort(XmlWriter w, PortInfo p, Device d)
    {
        bool tcp = IsTcp(p.Protocol);
        w.WriteStartElement("port");
        w.WriteAttributeString("protocol", tcp ? "tcp" : p.Protocol.ToLowerInvariant());
        w.WriteAttributeString("portid", Num(p.Port));

        w.WriteStartElement("state");
        w.WriteAttributeString("state", p.State switch { PortState.Open => "open", PortState.Closed => "closed", _ => "filtered" });
        w.WriteAttributeString("reason", p.State switch
        {
            PortState.Open => tcp ? "syn-ack" : "udp-response",
            PortState.Closed => tcp ? "reset" : "port-unreach",
            _ => "no-response",
        });
        w.WriteAttributeString("reason_ttl", Num(d.Ttl ?? 0));
        w.WriteEndElement();

        var svcName = p.ServiceName ?? d.Services.FirstOrDefault(s => s.Port == p.Port)?.Name;
        var banner = p.Banner ?? d.Services.FirstOrDefault(s => s.Port == p.Port && s.Banner is not null)?.Banner;
        if (svcName is not null || banner is not null)
        {
            var info = ExportText.ParseBanner(banner);
            w.WriteStartElement("service");
            w.WriteAttributeString("name", Clean(NmapServiceName(svcName ?? "unknown")));
            if (info.Product is { } prod) w.WriteAttributeString("product", Clean(prod));
            if (info.Version is { } ver) w.WriteAttributeString("version", Clean(ver));
            if (info.ExtraInfo is { } extra) w.WriteAttributeString("extrainfo", Clean(extra));
            if (svcName is not null && (svcName.Contains("https", StringComparison.OrdinalIgnoreCase) || d.Certificates.Any(c => c.Port == p.Port)))
                w.WriteAttributeString("tunnel", "ssl");
            w.WriteAttributeString("method", banner is null ? "table" : "probed");
            w.WriteAttributeString("conf", banner is null ? "3" : "10");
            w.WriteEndElement();
        }
        w.WriteEndElement(); // port
    }

    private static void WriteOs(XmlWriter w, Device d)
    {
        var os = d.OsGuess!;
        int accuracy = (int)Math.Clamp(Math.Round((d.IdentityConfidence > 0 ? d.IdentityConfidence : 0.85) * 100), 1, 100);
        var (vendor, family) = OsFamily(os);
        w.WriteStartElement("os");
        w.WriteStartElement("osmatch");
        w.WriteAttributeString("name", Clean(os));
        w.WriteAttributeString("accuracy", Num(accuracy));
        w.WriteAttributeString("line", "0");
        w.WriteStartElement("osclass");
        w.WriteAttributeString("type", OsClassType(d.Type));
        w.WriteAttributeString("vendor", vendor);
        w.WriteAttributeString("osfamily", family);
        w.WriteAttributeString("accuracy", Num(accuracy));
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteEndElement();
    }

    internal static (string Vendor, string Family) OsFamily(string os)
    {
        bool Has(string s) => os.Contains(s, StringComparison.OrdinalIgnoreCase);
        if (Has("windows")) return ("Microsoft", "Windows");
        if (Has("ios") && !Has("cisco")) return ("Apple", "iOS");
        if (Has("mac") || Has("darwin")) return ("Apple", "Mac OS X");
        if (Has("android")) return ("Google", "Android");
        if (Has("routeros") || Has("mikrotik")) return ("MikroTik", "RouterOS");
        if (Has("cisco") || Has("ios-xe") || Has("nx-os")) return ("Cisco", "IOS");
        if (Has("freebsd") || Has("pfsense") || Has("opnsense")) return ("FreeBSD", "FreeBSD");
        if (Has("linux") || Has("ubuntu") || Has("debian") || Has("openwrt")) return ("Linux", "Linux");
        return ("unknown", "embedded");
    }

    internal static string OsClassType(DeviceType t) => t switch
    {
        DeviceType.Router or DeviceType.Firewall => "router",
        DeviceType.CoreSwitch or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch => "switch",
        DeviceType.AccessPoint => "WAP",
        DeviceType.Printer => "printer",
        DeviceType.Phone or DeviceType.Tablet => "phone",
        DeviceType.Camera => "webcam",
        DeviceType.Tv or DeviceType.MediaStreamer or DeviceType.AudioStreamer => "media device",
        DeviceType.Nas => "storage-misc",
        DeviceType.GameConsole => "game console",
        DeviceType.VoipPhone => "VoIP phone",
        DeviceType.Ups => "power-device",
        DeviceType.IoT or DeviceType.SmartHomeHub or DeviceType.SmartPlug or DeviceType.Light => "specialized",
        _ => "general purpose",
    };

    private static string NmapServiceName(string name)
    {
        var n = name.Trim().ToLowerInvariant().Replace(' ', '-');
        return n.Length == 0 ? "unknown" : n;
    }

    private static bool IsTcp(string protocol) => protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase);

    /// <summary>"22,80,443,8000-8003" style list.</summary>
    internal static string CompressPorts(IReadOnlyList<int> sorted)
    {
        var parts = new List<string>();
        for (int i = 0; i < sorted.Count;)
        {
            int j = i;
            while (j + 1 < sorted.Count && sorted[j + 1] == sorted[j] + 1) j++;
            parts.Add(j == i ? Num(sorted[i]) : $"{Num(sorted[i])}-{Num(sorted[j])}");
            i = j + 1;
        }
        return string.Join(',', parts);
    }

    /// <summary>Removes characters that are not legal in XML 1.0 (banners can contain raw control bytes).</summary>
    internal static string Clean(string s)
    {
        if (s.All(XmlConvert.IsXmlChar)) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (XmlConvert.IsXmlChar(s[i])) sb.Append(s[i]);
            else if (i + 1 < s.Length && XmlConvert.IsXmlSurrogatePair(s[i + 1], s[i])) { sb.Append(s[i]).Append(s[i + 1]); i++; }
            else sb.Append('?');
        }
        return sb.ToString();
    }

    private static string Num(long v) => v.ToString(CultureInfo.InvariantCulture);

    /// <summary>ctime()-style date as Nmap writes it, e.g. "Sun Oct  4 17:05:00 2026".</summary>
    private static string Ctime(DateTimeOffset t) =>
        t.ToString("ddd MMM ", CultureInfo.InvariantCulture) + t.Day.ToString(CultureInfo.InvariantCulture).PadLeft(2) + t.ToString(" HH:mm:ss yyyy", CultureInfo.InvariantCulture);
}
