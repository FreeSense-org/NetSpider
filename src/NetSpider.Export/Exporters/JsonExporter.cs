using System.Text.Json;
using NetSpider.Core.Abstractions;
using NetSpider.Export.Json;

namespace NetSpider.Export.Exporters;

/// <summary>Full JSON dump: devices with all details, links, alerts, segments, VLANs, DHCP, STP, WAN, Wi-Fi and health.</summary>
public sealed class JsonExporter : IExporter
{
    public string Name => "JSON";
    public string FileExtension => ".json";

    public async Task ExportAsync(string path, ExportData data, CancellationToken ct = default)
    {
        var doc = ExportDocument.From(data);
        ExportFile.EnsureDirectory(path);
        await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true);
        await JsonSerializer.SerializeAsync(fs, doc, ExportJson.Options, ct).ConfigureAwait(false);
    }
}

internal static class ExportFile
{
    public static void EnsureDirectory(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }
}
