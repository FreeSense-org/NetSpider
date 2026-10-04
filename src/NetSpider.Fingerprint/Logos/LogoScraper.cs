using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using AngleSharp.Html.Parser;
using Microsoft.Extensions.Logging;

namespace NetSpider.Fingerprint.Logos;

/// <summary>A possible logo image found on a page, with a rank (higher is better).</summary>
public sealed record LogoCandidate(Uri Url, string Kind, int Score);

/// <summary>A downloaded, validated image.</summary>
public sealed record LogoImage(byte[] Bytes, string Extension, Uri Source, string Kind);

/// <summary>
/// Finds the best logo/icon on a vendor homepage. Ranking (best → worst): apple-touch-icon, rel=icon (svg or sizes ≥ 96),
/// mask-icon, largest rel=icon, web-manifest icons, &lt;img&gt; containing "logo", og:image, /favicon.ico.
/// </summary>
public sealed class LogoScraper
{
    public const int MaxImageBytes = 3 * 1024 * 1024;
    private const int MaxHtmlBytes = 4 * 1024 * 1024;
    private static readonly Regex SizeRx = new(@"(\d+)\s*x\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex LogoWord = new(@"logo|brand", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HttpClient _http;
    private readonly ILogger _log;

    public LogoScraper(HttpClient http, ILogger log)
    {
        _http = http;
        _log = log;
    }

    /// <summary>Scrapes the first reachable of the given domains; returns null when nothing usable was found.</summary>
    public async Task<LogoImage?> ScrapeAsync(IEnumerable<string> domains, CancellationToken ct)
    {
        foreach (var domain in domains)
        {
            foreach (var root in new[] { $"https://{domain}/", domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? null : $"https://www.{domain}/" })
            {
                if (root is null) continue;
                ct.ThrowIfCancellationRequested();
                var (html, baseUri) = await FetchHtmlAsync(new Uri(root), ct).ConfigureAwait(false);
                if (baseUri is null) continue;
                var candidates = html is null ? [] : ExtractCandidates(html, baseUri);
                candidates.AddRange(await ManifestCandidatesAsync(html, baseUri, ct).ConfigureAwait(false));
                candidates.Add(new LogoCandidate(new Uri(baseUri, "/favicon.ico"), "favicon.ico", 100));
                foreach (var c in Dedupe(candidates).Take(10))
                {
                    var img = await DownloadImageAsync(c.Url, c.Kind, ct).ConfigureAwait(false);
                    if (img is not null)
                    {
                        _log.LogDebug("Logo for {Domain}: {Kind} {Url}", domain, c.Kind, c.Url);
                        return img;
                    }
                }
                break; // the site answered but had no usable image; don't also try www.
            }
        }
        return null;
    }

    private static IEnumerable<LogoCandidate> Dedupe(IEnumerable<LogoCandidate> c) =>
        c.GroupBy(x => x.Url.AbsoluteUri).Select(g => g.MaxBy(x => x.Score)!).OrderByDescending(x => x.Score);

    private async Task<(string? Html, Uri? BaseUri)> FetchHtmlAsync(Uri url, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            var final = resp.RequestMessage?.RequestUri ?? url;
            if (!resp.IsSuccessStatusCode)
            {
                _log.LogDebug("{Url} answered {Status}", url, (int)resp.StatusCode);
                // still usable as a base for /favicon.ico when the server exists (e.g. bot walls answering 403)
                return (null, (int)resp.StatusCode is 401 or 403 or 429 or 503 ? final : null);
            }
            var bytes = await ReadLimitedAsync(resp.Content, MaxHtmlBytes, ct).ConfigureAwait(false);
            var html = System.Text.Encoding.UTF8.GetString(bytes);
            return (html, final);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { _log.LogDebug("Timeout fetching {Url}", url); return (null, null); }
        catch (HttpRequestException ex) { _log.LogDebug("Fetching {Url} failed: {Error}", url, ex.Message); return (null, null); }
    }

    /// <summary>Parses HTML and returns ranked logo candidates (excluding manifest icons and /favicon.ico).</summary>
    public static List<LogoCandidate> ExtractCandidates(string html, Uri baseUri)
    {
        var list = new List<LogoCandidate>();
        var doc = new HtmlParser().ParseDocument(html);
        var docBase = baseUri;
        var baseHref = doc.QuerySelector("base[href]")?.GetAttribute("href");
        if (baseHref is not null && Uri.TryCreate(baseUri, baseHref, out var b2)) docBase = b2;

        foreach (var link in doc.QuerySelectorAll("link[rel][href]"))
        {
            var rel = (link.GetAttribute("rel") ?? "").ToLowerInvariant();
            var href = link.GetAttribute("href");
            if (!TryResolve(docBase, href, out var url)) continue;
            var type = (link.GetAttribute("type") ?? "").ToLowerInvariant();
            int size = MaxSize(link.GetAttribute("sizes"));
            bool svg = type.Contains("svg") || url.AbsolutePath.EndsWith(".svg", StringComparison.OrdinalIgnoreCase) || href!.StartsWith("data:image/svg", StringComparison.OrdinalIgnoreCase);
            var rels = rel.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (rels.Any(r => r.StartsWith("apple-touch-icon", StringComparison.Ordinal)))
            {
                int closeness = size == 0 ? 50 : Math.Max(0, 100 - Math.Abs(size - 180) / 4);
                list.Add(new LogoCandidate(url, "apple-touch-icon", 1000 + closeness));
            }
            else if (rels.Contains("mask-icon"))
                list.Add(new LogoCandidate(url, "mask-icon", 800));
            else if (rels.Contains("icon"))
            {
                if (svg) list.Add(new LogoCandidate(url, "icon-svg", 900));
                else if (size >= 96) list.Add(new LogoCandidate(url, $"icon-{size}", 850 + Math.Min(size, 512) / 10));
                else list.Add(new LogoCandidate(url, size > 0 ? $"icon-{size}" : "icon", 600 + size));
            }
        }

        foreach (var img in doc.QuerySelectorAll("img"))
        {
            var src = img.GetAttribute("src") ?? img.GetAttribute("data-src");
            if (string.IsNullOrWhiteSpace(src)) continue;
            var hay = string.Join(' ', img.GetAttribute("class"), img.GetAttribute("id"), img.GetAttribute("alt"), src, img.ParentElement?.GetAttribute("class"));
            if (!LogoWord.IsMatch(hay)) continue;
            if (!TryResolve(docBase, src, out var url)) continue;
            var path = url.AbsolutePath.ToLowerInvariant();
            bool svg = path.EndsWith(".svg") || src.StartsWith("data:image/svg", StringComparison.OrdinalIgnoreCase);
            bool png = path.EndsWith(".png") || src.StartsWith("data:image/png", StringComparison.OrdinalIgnoreCase);
            if (!svg && !png) continue;
            list.Add(new LogoCandidate(url, svg ? "img-logo-svg" : "img-logo-png", svg ? 450 : 400));
        }

        foreach (var meta in doc.QuerySelectorAll("meta[property='og:image'], meta[name='og:image'], meta[property='og:logo']"))
            if (TryResolve(docBase, meta.GetAttribute("content"), out var url))
                list.Add(new LogoCandidate(url, "og:image", 200));

        return Dedupe(list).ToList();
    }

    /// <summary>Extracts icons from a web app manifest JSON document.</summary>
    public static IEnumerable<LogoCandidate> ParseManifest(string json, Uri manifestUri)
    {
        var list = new List<LogoCandidate>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("icons", out var icons) || icons.ValueKind != JsonValueKind.Array) return list;
            foreach (var i in icons.EnumerateArray())
            {
                if (!i.TryGetProperty("src", out var srcEl) || srcEl.GetString() is not { } src) continue;
                if (!TryResolve(manifestUri, src, out var url)) continue;
                int size = i.TryGetProperty("sizes", out var s) ? MaxSize(s.GetString()) : 0;
                bool svg = url.AbsolutePath.EndsWith(".svg", StringComparison.OrdinalIgnoreCase) || (i.TryGetProperty("type", out var t) && (t.GetString() ?? "").Contains("svg"));
                list.Add(new LogoCandidate(url, "manifest", svg ? 560 : 500 + Math.Min(size, 512) / 10));
            }
        }
        catch (JsonException) { }
        return list;
    }

    private async Task<IEnumerable<LogoCandidate>> ManifestCandidatesAsync(string? html, Uri baseUri, CancellationToken ct)
    {
        if (html is null) return [];
        try
        {
            var doc = new HtmlParser().ParseDocument(html);
            var href = doc.QuerySelector("link[rel~='manifest'][href]")?.GetAttribute("href");
            if (!TryResolve(baseUri, href, out var url) || url.Scheme == "data") return [];
            using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return [];
            var bytes = await ReadLimitedAsync(resp.Content, 512 * 1024, ct).ConfigureAwait(false);
            return ParseManifest(System.Text.Encoding.UTF8.GetString(bytes), resp.RequestMessage?.RequestUri ?? url);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return []; }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException) { return []; }
    }

    /// <summary>Downloads and validates an image (content type + magic bytes). Supports data: URIs.</summary>
    public async Task<LogoImage?> DownloadImageAsync(Uri url, string kind, CancellationToken ct)
    {
        try
        {
            if (url.Scheme == "data") return DecodeDataUri(url, kind);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("image/avif,image/webp,image/svg+xml,image/png,image/*;q=0.8,*/*;q=0.5");
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
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
            _log.LogDebug("Image download {Url} failed: {Error}", url, ex.Message);
            return null;
        }
    }

    private static LogoImage? DecodeDataUri(Uri url, string kind)
    {
        var s = url.OriginalString;
        int comma = s.IndexOf(',');
        if (comma < 0) return null;
        var meta = s[5..comma];
        var payload = s[(comma + 1)..];
        byte[] bytes;
        try
        {
            bytes = meta.EndsWith(";base64", StringComparison.OrdinalIgnoreCase)
                ? Convert.FromBase64String(payload)
                : System.Text.Encoding.UTF8.GetBytes(WebUtility.UrlDecode(payload));
        }
        catch (FormatException) { return null; }
        if (bytes.Length < 64) return null;
        var ext = ImageSniffer.Sniff(bytes);
        return ext is null ? null : new LogoImage(bytes, ext, url, kind);
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

    private static bool TryResolve(Uri baseUri, string? href, out Uri url)
    {
        url = baseUri;
        if (string.IsNullOrWhiteSpace(href)) return false;
        href = href.Trim();
        if (href.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return href.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(href, UriKind.Absolute, out url!);
        if (!Uri.TryCreate(baseUri, href, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp)) return false;
        url = u;
        return true;
    }

    private static int MaxSize(string? sizes)
    {
        if (string.IsNullOrWhiteSpace(sizes)) return 0;
        if (sizes.Contains("any", StringComparison.OrdinalIgnoreCase)) return 512;
        int max = 0;
        foreach (Match m in SizeRx.Matches(sizes))
            max = Math.Max(max, int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture));
        return max;
    }
}
