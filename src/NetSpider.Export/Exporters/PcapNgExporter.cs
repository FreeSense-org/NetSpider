using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Export.Exporters;

/// <summary>Exports the capture ring buffer as pcapng via <see cref="IFrameSource.DumpRecent"/>.</summary>
public sealed class PcapNgExporter : IExporter
{
    private readonly IServiceProvider _services;

    public PcapNgExporter(IServiceProvider services) => _services = services;

    public string Name => "pcapng";
    public string FileExtension => ".pcapng";

    public async Task ExportAsync(string path, ExportData data, CancellationToken ct = default)
    {
        var source = _services.GetService<IFrameSource>();
        if (source is null || !source.IsRunning)
            throw new InvalidOperationException("Packet capture is not running. Start monitoring on an adapter first; the pcapng export contains the most recent captured frames.");

        var dump = await Task.Run(() => source.DumpRecent("export"), ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(dump) || !File.Exists(dump))
            throw new InvalidOperationException("The capture buffer could not be written (no frames captured yet, or the dump failed).");

        ExportFile.EnsureDirectory(path);
        if (!string.Equals(Path.GetFullPath(dump), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
        {
            await using var src = new FileStream(dump, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 81920, useAsync: true);
            await using var dst = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
            await src.CopyToAsync(dst, ct).ConfigureAwait(false);
        }
    }
}
