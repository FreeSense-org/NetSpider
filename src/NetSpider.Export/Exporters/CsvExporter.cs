using System.Globalization;
using System.Text;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Json;

namespace NetSpider.Export.Exporters;

/// <summary>RFC 4180 device inventory (UTF-8 with BOM for Excel, CRLF line endings, formula-injection safe).</summary>
public sealed class CsvExporter : IExporter
{
    public static readonly string[] Header =
    [
        "MAC", "IPv4", "IPv6", "Name", "Hostname", "User Label", "Vendor", "Brand", "Model", "Type", "OS", "Firmware", "State",
        "First Seen", "Last Seen", "L2 RTT ms", "ICMP RTT ms", "Open Ports", "VLANs", "Wi-Fi SSID", "Flags",
    ];

    public string Name => "CSV";
    public string FileExtension => ".csv";

    public async Task ExportAsync(string path, ExportData data, CancellationToken ct = default)
    {
        var text = Build(data.Devices);
        ExportFile.EnsureDirectory(path);
        await File.WriteAllTextAsync(path, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), ct).ConfigureAwait(false);
    }

    public static string Build(IEnumerable<Device> devices)
    {
        var sb = new StringBuilder();
        AppendRow(sb, Header);
        foreach (var d in devices.Where(d => !SyntheticNodes.IsGraphOnly(d.Mac)).OrderBy(d => ExportText.IpSortKey(d.PrimaryIPv4)).ThenBy(d => d.Mac))
        {
            AppendRow(sb,
            [
                d.Mac.ToString(),
                string.Join(" ", d.IPv4.OrderBy(ExportText.IpSortKey)),
                string.Join(" ", d.IPv6.Select(x => x.Address)),
                d.DisplayName,
                d.Hostname,
                d.UserLabel,
                d.OuiVendor,
                d.Brand,
                d.Model,
                d.Type.ToString(),
                d.OsGuess,
                d.Firmware,
                d.State.ToString(),
                d.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
                d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
                ExportText.Ms(d.Latency.Last(LatencyKind.Arp) ?? d.Latency.Last(LatencyKind.Ndp)),
                ExportText.Ms(d.Latency.Last(LatencyKind.Icmp)),
                ExportText.OpenPorts(d),
                string.Join(" ", d.Vlans),
                d.Wifi?.Ssid,
                string.Join(" ", DeviceDto.FlagNames(d.Flags)),
            ]);
        }
        return sb.ToString();
    }

    private static void AppendRow(StringBuilder sb, IReadOnlyList<string?> fields)
    {
        for (int i = 0; i < fields.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(Escape(fields[i]));
        }
        sb.Append("\r\n");
    }

    /// <summary>Quotes fields containing separators, quotes, line breaks or edge whitespace; neutralizes spreadsheet formulas.</summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value[0] is '=' or '+' or '@' or '\t' or '\r' || (value[0] == '-' && value.Length > 1 && !char.IsDigit(value[1])))
            value = "'" + value;
        bool quote = value.AsSpan().IndexOfAny(",\"\r\n") >= 0 || char.IsWhiteSpace(value[0]) || char.IsWhiteSpace(value[^1]);
        return quote ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
