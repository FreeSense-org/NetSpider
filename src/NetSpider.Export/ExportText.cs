using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.RegularExpressions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Export;

/// <summary>Formatting helpers shared by the exporters.</summary>
public static partial class ExportText
{
    public static string AppVersion { get; } =
        typeof(ExportText).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0]
        ?? typeof(ExportText).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    /// <summary>Sort key placing IPv4 addresses in numeric order, IPv6 after, missing last.</summary>
    public static string IpSortKey(IPAddress? ip)
    {
        if (ip is null) return "~";
        var b = ip.GetAddressBytes();
        return (ip.AddressFamily == AddressFamily.InterNetwork ? "4" : "6") + Convert.ToHexString(b);
    }

    /// <summary>Numeric IPv4 key for the HTML table sort (0 when not IPv4).</summary>
    public static long Ipv4Number(IPAddress? ip)
    {
        if (ip is null || ip.AddressFamily != AddressFamily.InterNetwork) return 0;
        var b = ip.GetAddressBytes();
        return (long)b[0] << 24 | (long)b[1] << 16 | (long)b[2] << 8 | b[3];
    }

    /// <summary>Best human name for the scanned network: the connected SSID, else local segment and adapter.</summary>
    public static string NetworkName(ExportData data)
    {
        try
        {
            var ssid = data.Network.WifiNetworks.FirstOrDefault(w => w.Connected)?.Ssid;
            if (!string.IsNullOrWhiteSpace(ssid)) return ssid;
            var local = data.Network.Segments.FirstOrDefault(s => s.IsLocal) ?? data.Network.Segments.FirstOrDefault();
            if (local is not null) return data.Adapter is null ? local.Cidr : $"{local.Cidr} on {data.Adapter.Name}";
            if (data.Adapter?.PrimaryV4 is { } p) return $"{p} on {data.Adapter.Name}";
            return data.Adapter?.Name ?? "Local network";
        }
        catch { return "Local network"; }
    }

    public static string Ms(double? ms) => ms switch
    {
        null => "",
        < 0.1 => "<0.1",
        < 10 => ms.Value.ToString("0.00", CultureInfo.InvariantCulture),
        _ => ms.Value.ToString("0.0", CultureInfo.InvariantCulture),
    };

    public static string Time(DateTimeOffset t) => t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string Duration(TimeSpan? t) => t is not { } v ? "" : v.TotalDays >= 1 ? $"{(int)v.TotalDays}d {v.Hours}h {v.Minutes}m" : $"{v.Hours}h {v.Minutes}m {v.Seconds}s";

    public static string OpenPorts(Device d) =>
        string.Join(", ", d.Ports.Where(p => p.State == PortState.Open).Select(p => p.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase) ? p.Port.ToString(CultureInfo.InvariantCulture) : $"{p.Port}/{p.Protocol}"));

    // ------------------------------------------------------------------ banners

    /// <summary>Product/version/extra info parsed from a service banner (SSH ident, HTTP Server header, FTP greeting, ...).</summary>
    public sealed record BannerInfo(string? Product, string? Version, string? ExtraInfo);

    public static BannerInfo ParseBanner(string? banner)
    {
        if (string.IsNullOrWhiteSpace(banner)) return new(null, null, null);
        var line = banner.Split('\n', 2)[0].Trim().TrimEnd('\r');

        var ssh = SshRegex().Match(line);
        if (ssh.Success)
        {
            var soft = ssh.Groups["soft"].Value;
            var parts = soft.Split('_', 2);
            string? extra = ssh.Groups["extra"].Success ? ssh.Groups["extra"].Value.Trim() : null;
            string product = parts[0] switch { "OpenSSH" => "OpenSSH", "dropbear" => "Dropbear sshd", var p => p };
            return new(product, parts.Length > 1 ? parts[1] : null, string.IsNullOrEmpty(extra) ? $"protocol {ssh.Groups["proto"].Value}" : $"{extra}; protocol {ssh.Groups["proto"].Value}");
        }

        var server = ServerHeaderRegex().Match(banner);
        if (server.Success) line = server.Groups[1].Value.Trim();
        else line = FtpCodeRegex().Replace(line, "");

        var pv = ProductVersionRegex().Match(line);
        if (pv.Success)
        {
            var rest = pv.Groups["rest"].Value.Trim().Trim('(', ')').Trim();
            return new(pv.Groups["p"].Value.Trim(), pv.Groups["v"].Value, rest.Length == 0 ? null : Truncate(rest, 80));
        }
        return new(Truncate(line, 80), null, null);
    }

    public static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    [GeneratedRegex(@"^SSH-(?<proto>[\d.]+)-(?<soft>\S+)(?<extra>\s.*)?$")]
    private static partial Regex SshRegex();

    [GeneratedRegex(@"^Server:\s*(.+)$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex ServerHeaderRegex();

    [GeneratedRegex(@"^\d{3}[\s-]+")]
    private static partial Regex FtpCodeRegex();

    [GeneratedRegex(@"^(?<p>[A-Za-z][\w.\- ]*?)[/ _]v?(?<v>\d[\w.\-]*)(?<rest>.*)$")]
    private static partial Regex ProductVersionRegex();
}
