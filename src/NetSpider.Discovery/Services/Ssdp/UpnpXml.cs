using System.Net;
using System.Xml.Linq;

namespace NetSpider.Discovery.Services.Ssdp;

/// <summary>Parses a UPnP device description XML document into a device tree. Namespace-agnostic (ignores prefixes).</summary>
public static class UpnpXml
{
    public static UpnpDevice? Parse(string xml, Uri location)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); } catch { return null; }
        var root = doc.Root;
        if (root is null) return null;
        var deviceEl = Descendant(root, "device");
        return deviceEl is null ? null : ParseDevice(deviceEl, location);
    }

    private static UpnpDevice ParseDevice(XElement el, Uri baseUri)
    {
        string? Val(string n) => Child(el, n)?.Value?.Trim();

        var services = new List<UpnpService>();
        var serviceList = Child(el, "serviceList");
        if (serviceList is not null)
            foreach (var s in Children(serviceList, "service"))
                services.Add(new UpnpService(
                    Child(s, "serviceType")?.Value?.Trim() ?? "",
                    Abs(baseUri, Child(s, "controlURL")?.Value),
                    Abs(baseUri, Child(s, "SCPDURL")?.Value),
                    Abs(baseUri, Child(s, "eventSubURL")?.Value)));

        var children = new List<UpnpDevice>();
        var deviceList = Child(el, "deviceList");
        if (deviceList is not null)
            foreach (var c in Children(deviceList, "device"))
                children.Add(ParseDevice(c, baseUri));

        string? icon = BestIcon(el, baseUri);

        return new UpnpDevice(
            Val("deviceType"), Val("friendlyName"), Val("manufacturer"), Val("manufacturerURL"),
            Val("modelName"), Val("modelNumber"), Val("modelDescription"), Val("serialNumber"),
            Val("UDN"), Abs(baseUri, Val("presentationURL")), icon, services, children);
    }

    private static string? BestIcon(XElement deviceEl, Uri baseUri)
    {
        var iconList = Child(deviceEl, "iconList");
        if (iconList is null) return null;
        string? best = null; int bestScore = -1;
        foreach (var icon in Children(iconList, "icon"))
        {
            var mime = Child(icon, "mimetype")?.Value ?? "";
            if (!mime.Contains("png", StringComparison.OrdinalIgnoreCase) && !mime.Contains("jpeg", StringComparison.OrdinalIgnoreCase) && !mime.Contains("jpg", StringComparison.OrdinalIgnoreCase))
                continue;
            int w = ParseInt(Child(icon, "width")?.Value);
            int h = ParseInt(Child(icon, "height")?.Value);
            int depth = ParseInt(Child(icon, "depth")?.Value);
            int score = w * h * 100 + depth;
            var url = Child(icon, "url")?.Value;
            if (score > bestScore && !string.IsNullOrWhiteSpace(url)) { bestScore = score; best = Abs(baseUri, url); }
        }
        return best;
    }

    private static int ParseInt(string? s) => int.TryParse(s, out var v) ? v : 0;

    public static string? Abs(Uri baseUri, string? rel)
    {
        if (string.IsNullOrWhiteSpace(rel)) return null;
        if (Uri.TryCreate(rel, UriKind.Absolute, out var abs)) return abs.AbsoluteUri;
        return Uri.TryCreate(baseUri, rel, out var combined) ? combined.AbsoluteUri : rel;
    }

    // ---- namespace-agnostic element access ----
    private static XElement? Child(XElement parent, string local) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase));
    private static IEnumerable<XElement> Children(XElement parent, string local) =>
        parent.Elements().Where(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase));
    private static XElement? Descendant(XElement root, string local) =>
        root.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase) ? root
        : root.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase));
}
