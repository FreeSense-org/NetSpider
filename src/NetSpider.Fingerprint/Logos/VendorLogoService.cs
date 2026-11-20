using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Fingerprint.Logos;

namespace NetSpider.Fingerprint;

/// <summary>
/// Resolves a logo image for a device: (1) the device's own SSDP icon from the LAN, (2) the brand's logo shipped with the
/// app in Data/Logos, (3) null so the UI draws a type glyph. Logos are never looked up on the internet.
/// Images are kept as files in <c>Logos/</c> because the renderers load them by path: brand logos are extracted as
/// <c>&lt;brand-key&gt;.png</c>, device icons cached as <c>icon-&lt;hash&gt;.&lt;ext&gt;</c>, with failed icons remembered
/// by a <c>.none</c> marker for 7 days.
/// </summary>
public sealed class VendorLogoService : ILogoProvider, IDisposable
{
    public const string BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    internal static readonly TimeSpan NegativeTtl = TimeSpan.FromDays(7);
    private const string RevisionFile = "catalog.rev";
    private const string BundledMarker = ".Data.Logos.";

    private static readonly Assembly Asm = typeof(VendorLogoService).Assembly;

    /// <summary>Brand key → embedded Data/Logos/&lt;brand-key&gt;.png.</summary>
    private static readonly Dictionary<string, string> BundledLogos = Asm.GetManifestResourceNames()
        .Where(n => n.Contains(BundledMarker, StringComparison.Ordinal) && n.EndsWith(".png", StringComparison.Ordinal))
        .ToDictionary(n => n[(n.IndexOf(BundledMarker, StringComparison.Ordinal) + BundledMarker.Length)..^4], StringComparer.OrdinalIgnoreCase);

    private readonly ILogger<VendorLogoService> _log;
    private readonly string _cacheDir;
    private readonly HttpClient _lan;
    private readonly DeviceIconDownloader _icons;
    private readonly object _extractLock = new();
    private readonly SemaphoreSlim _gate = new(4, 4);
    private readonly ConcurrentDictionary<string, Lazy<Task<string?>>> _inflight = new(StringComparer.OrdinalIgnoreCase);

    public VendorLogoService(ILogger<VendorLogoService> log) : this(log, null, null) { }

    internal VendorLogoService(ILogger<VendorLogoService> log, string? cacheDir, HttpMessageHandler? handler)
    {
        _log = log;
        _cacheDir = cacheDir ?? AppPaths.Logos;
        Directory.CreateDirectory(_cacheDir);
        Catalog = VendorCatalog.LoadEmbedded();
        DiscardOutdatedBrandLogos();

        _lan = handler is null ? new HttpClient(CreateHandler(), true) : new HttpClient(handler, false);
        _lan.Timeout = TimeSpan.FromSeconds(8);
        _lan.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
        _icons = new DeviceIconDownloader(_lan, log);
    }

    private static SocketsHttpHandler CreateHandler()
    {
        var h = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 8,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        // LAN devices (routers, NAS, ...) almost always use self-signed certificates for their icons.
        h.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
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
            return string.IsNullOrWhiteSpace(brand) ? null : GetBrandLogo(brand);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Logo lookup failed for {Device}", device.Mac);
            return null;
        }
    }

    /// <summary>Returns the path of the shipped logo for a brand, an alias or a registered company name; null when there is none.</summary>
    public string? GetBrandLogo(string brand)
    {
        if (string.IsNullOrWhiteSpace(brand)) return null;
        var key = KeyFor(brand);
        if (!BundledLogos.TryGetValue(key, out var resource)) return null;
        var path = Path.Combine(_cacheDir, key + ".png");
        lock (_extractLock)
        {
            if (File.Exists(path)) return path;
            using var s = Asm.GetManifestResourceStream(resource)!;
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return Save(key, new LogoImage(ms.ToArray(), ".png", new Uri("about:bundled"), "bundled"));
        }
    }

    // ------------------------------------------------------------------------------------------------

    /// <summary>Logo key for a brand: the catalog's canonical brand if known, else the normalized brand.</summary>
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

    private async Task<string?> FetchIconAsync(string key, Uri url, CancellationToken ct)
    {
        if (FindCached(key) is { } cached) return cached;
        if (IsNegative(key)) return null;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var img = await _icons.DownloadImageAsync(url, "device-icon", ct).ConfigureAwait(false);
            if (img is null) { MarkNegative(key); return null; }
            return Save(key, img);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Extracted logos stay valid only for the build that shipped them, and profiles from older versions hold logos scraped
    /// from the web. Device icons are keyed by their URL and stay.
    /// </summary>
    private void DiscardOutdatedBrandLogos()
    {
        var marker = Path.Combine(_cacheDir, RevisionFile);
        try
        {
            var bytes = BundledLogos.Values.Sum(r => { using var s = Asm.GetManifestResourceStream(r)!; return s.Length; });
            var revision = $"bundled+{BundledLogos.Count}+{bytes}";
            if (File.Exists(marker) && File.ReadAllText(marker) == revision) return;
            foreach (var file in Directory.GetFiles(_cacheDir))
                if (!Path.GetFileName(file).StartsWith("icon-", StringComparison.Ordinal)) TryDelete(file);
            File.WriteAllText(marker, revision);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.LogDebug(ex, "Could not refresh the logo folder");
        }
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
        _lan.Dispose();
        _gate.Dispose();
    }
}
