using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Fingerprint.Logos;

namespace NetSpider.Fingerprint;

/// <summary>
/// Resolves a logo image for a device: (1) the device's own SSDP icon, (2) a logo scraped from the vendor's homepage
/// (domain from the embedded vendors.json, or guessed from the brand), (3) null so the UI draws a type glyph.
/// Original bytes are cached as <c>Logos/&lt;brand-key&gt;.&lt;ext&gt;</c>; misses are remembered with a <c>.none</c>
/// marker for 7 days. At most 4 fetches run concurrently.
/// </summary>
public sealed class VendorLogoService : ILogoProvider, IDisposable
{
    public const string BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    internal static readonly TimeSpan NegativeTtl = TimeSpan.FromDays(7);

    private readonly ILogger<VendorLogoService> _log;
    private readonly AppSettings _settings;
    private readonly string _cacheDir;
    private readonly HttpClient _web;
    private readonly HttpClient _lan;
    private readonly LogoScraper _scraper;
    private readonly LogoScraper _lanScraper;
    private readonly SemaphoreSlim _gate = new(4, 4);
    private readonly ConcurrentDictionary<string, Lazy<Task<string?>>> _inflight = new(StringComparer.OrdinalIgnoreCase);

    public VendorLogoService(ILogger<VendorLogoService> log, AppSettings settings) : this(log, settings, null, null) { }

    internal VendorLogoService(ILogger<VendorLogoService> log, AppSettings settings, string? cacheDir, HttpMessageHandler? handler)
    {
        _log = log;
        _settings = settings;
        _cacheDir = cacheDir ?? AppPaths.Logos;
        Directory.CreateDirectory(_cacheDir);
        Catalog = VendorCatalog.LoadEmbedded();

        _web = handler is null ? new HttpClient(CreateHandler(false), true) : new HttpClient(handler, false);
        _lan = handler is null ? new HttpClient(CreateHandler(true), true) : new HttpClient(handler, false);
        foreach (var c in new[] { _web, _lan })
        {
            c.Timeout = TimeSpan.FromSeconds(8);
            c.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
            c.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
        }
        _scraper = new LogoScraper(_web, log);
        _lanScraper = new LogoScraper(_lan, log);
    }

    private static SocketsHttpHandler CreateHandler(bool lan)
    {
        var h = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 8,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(lan ? 3 : 6),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            UseCookies = true,
            CookieContainer = new CookieContainer(),
        };
        // LAN devices (routers, NAS, ...) almost always use self-signed certificates for their icons.
        if (lan) h.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        return h;
    }

    public VendorCatalog Catalog { get; }

    public string CacheDirectory => _cacheDir;

    public async Task<string?> GetLogoAsync(Device device, CancellationToken ct = default)
    {
        try
        {
            // 1. the device's own icon (SSDP iconList)
            if (!string.IsNullOrWhiteSpace(device.IconUrl) && Uri.TryCreate(device.IconUrl, UriKind.Absolute, out var iconUrl) &&
                iconUrl.Scheme is "http" or "https")
            {
                var key = "icon-" + Hash(iconUrl.AbsoluteUri);
                var path = await Dedupe(key, () => FetchIconAsync(key, iconUrl, ct)).ConfigureAwait(false);
                if (path is not null) return path;
            }

            // 2. vendor logo
            var brand = device.Brand ?? device.OuiVendor;
            return string.IsNullOrWhiteSpace(brand) ? null : await GetBrandLogoAsync(brand, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Logo lookup failed for {Device}", device.Mac);
            return null;
        }
    }

    /// <summary>Returns the cached or freshly scraped logo for a brand (null when none / scraping disabled).</summary>
    public async Task<string?> GetBrandLogoAsync(string brand, CancellationToken ct = default)
    {
        var key = KeyFor(brand);
        if (key.Length == 0) return null;
        if (FindCached(key) is { } cached) return cached;
        if (!_settings.ScrapeVendorLogos || IsNegative(key)) return null;
        return await Dedupe(key, () => ScrapeBrandAsync(key, brand, ct)).ConfigureAwait(false);
    }

    public string? TryGetCachedBrandLogo(string brand)
    {
        if (string.IsNullOrWhiteSpace(brand)) return null;
        var key = KeyFor(brand);
        return key.Length == 0 ? null : FindCached(key);
    }

    public async Task PrefetchAllAsync(IProgress<ScanProgress>? progress, CancellationToken ct = default)
    {
        var entries = Catalog.Entries;
        int done = 0, found = 0;
        progress?.Report(new ScanProgress("Prefetching vendor logos", 0, $"0/{entries.Count}"));
        await Parallel.ForEachAsync(entries, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, async (e, token) =>
        {
            string? path = null;
            try { path = await GetBrandLogoAsync(e.Brand, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { _log.LogDebug(ex, "Prefetch {Brand}", e.Brand); }
            if (path is not null) Interlocked.Increment(ref found);
            int n = Interlocked.Increment(ref done);
            progress?.Report(new ScanProgress("Prefetching vendor logos", (double)n / entries.Count, $"{n}/{entries.Count} ({e.Brand})"));
        }).ConfigureAwait(false);
        _log.LogInformation("Logo prefetch finished: {Found}/{Total} brands have logos", found, entries.Count);
    }

    // ------------------------------------------------------------------------------------------------

    /// <summary>Cache key for a brand: the catalog's canonical brand if known, else the normalized brand.</summary>
    internal string KeyFor(string brand)
    {
        var canonical = Catalog.Find(brand)?.Brand ?? BrandNormalizer.Normalize(brand) ?? brand;
        return BrandNormalizer.Key(canonical);
    }

    private Task<string?> Dedupe(string key, Func<Task<string?>> factory)
    {
        var lazy = _inflight.GetOrAdd(key, k => new Lazy<Task<string?>>(async () =>
        {
            try { return await factory().ConfigureAwait(false); }
            finally { _inflight.TryRemove(key, out _); }
        }));
        return lazy.Value;
    }

    private async Task<string?> ScrapeBrandAsync(string key, string brand, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (FindCached(key) is { } cached) return cached;
            var domains = Catalog.CandidateDomains(brand);
            if (domains.Count == 0) { MarkNegative(key); return null; }
            var img = await _scraper.ScrapeAsync(domains, ct).ConfigureAwait(false);
            if (img is null)
            {
                _log.LogDebug("No logo found for {Brand} ({Domains})", brand, string.Join(", ", domains));
                MarkNegative(key);
                return null;
            }
            var path = Save(key, img);
            _log.LogInformation("Cached logo for {Brand}: {Kind} from {Url}", brand, img.Kind, img.Source);
            return path;
        }
        finally { _gate.Release(); }
    }

    private async Task<string?> FetchIconAsync(string key, Uri url, CancellationToken ct)
    {
        if (FindCached(key) is { } cached) return cached;
        if (IsNegative(key)) return null;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var img = await _lanScraper.DownloadImageAsync(url, "device-icon", ct).ConfigureAwait(false);
            if (img is null) { MarkNegative(key); return null; }
            return Save(key, img);
        }
        finally { _gate.Release(); }
    }

    private string Save(string key, LogoImage img)
    {
        foreach (var ext in ImageSniffer.Extensions)
        {
            var old = Path.Combine(_cacheDir, key + ext);
            if (ext != img.Extension && File.Exists(old)) TryDelete(old);
        }
        var path = Path.Combine(_cacheDir, key + img.Extension);
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, img.Bytes);
        File.Move(tmp, path, true);
        TryDelete(Path.Combine(_cacheDir, key + ".none"));
        return path;
    }

    private string? FindCached(string key)
    {
        foreach (var ext in ImageSniffer.Extensions)
        {
            var p = Path.Combine(_cacheDir, key + ext);
            if (File.Exists(p)) return p;
        }
        return null;
    }

    private bool IsNegative(string key)
    {
        var p = Path.Combine(_cacheDir, key + ".none");
        try
        {
            if (!File.Exists(p)) return false;
            if (DateTime.UtcNow - File.GetLastWriteTimeUtc(p) < NegativeTtl) return true;
            TryDelete(p);
        }
        catch (IOException) { }
        return false;
    }

    private void MarkNegative(string key)
    {
        try { File.WriteAllText(Path.Combine(_cacheDir, key + ".none"), DateTimeOffset.Now.ToString("O")); }
        catch (Exception ex) { _log.LogDebug(ex, "Could not write negative marker for {Key}", key); }
    }

    private static void TryDelete(string p) { try { File.Delete(p); } catch { } }

    private static string Hash(string s) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(s)))[..16].ToLowerInvariant();

    public void Dispose()
    {
        _web.Dispose();
        _lan.Dispose();
        _gate.Dispose();
    }
}
