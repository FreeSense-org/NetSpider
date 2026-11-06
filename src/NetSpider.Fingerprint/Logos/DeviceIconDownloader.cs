using System.Net;
using Microsoft.Extensions.Logging;

namespace NetSpider.Fingerprint.Logos;

/// <summary>A downloaded, validated image.</summary>
public sealed record LogoImage(byte[] Bytes, string Extension, Uri Source, string Kind);

/// <summary>Downloads the icon a device advertises about itself (SSDP iconList) and checks that it really is an image.</summary>
public sealed class DeviceIconDownloader(HttpClient http, ILogger log)
{
    public const int MaxImageBytes = 3 * 1024 * 1024;

    /// <summary>Downloads and validates an image (content type + magic bytes).</summary>
    public async Task<LogoImage?> DownloadImageAsync(Uri url, string kind, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("image/avif,image/webp,image/svg+xml,image/png,image/*;q=0.8,*/*;q=0.5");
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            if (!ImageSniffer.AcceptableContentType(resp.Content.Headers.ContentType?.MediaType)) return null;
            if (resp.Content.Headers.ContentLength > MaxImageBytes) return null;
            var bytes = await ReadLimitedAsync(resp.Content, MaxImageBytes, ct).ConfigureAwait(false);
            if (bytes.Length < 64) return null;
            var ext = ImageSniffer.Sniff(bytes);
            return ext is null ? null : new LogoImage(bytes, ext, resp.RequestMessage?.RequestUri ?? url, kind);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or IOException)
        {
            log.LogDebug("Image download {Url} failed: {Error}", url, ex.Message);
            return null;
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpContent content, int max, CancellationToken ct)
    {
        await using var s = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        int n;
        while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buf, 0, n);
            if (ms.Length > max) throw new InvalidOperationException("Response too large");
        }
        return ms.ToArray();
    }
}
