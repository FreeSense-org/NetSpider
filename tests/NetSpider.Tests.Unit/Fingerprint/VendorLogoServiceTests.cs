using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Fingerprint;
using NetSpider.Fingerprint.Logos;
using Xunit.Abstractions;

namespace NetSpider.Tests.Unit.Fingerprint;

public sealed class LogoScraperTests
{
    private static readonly Uri Base = new("https://www.example.com/en/");

    [Fact]
    public void Ranks_candidates_in_documented_order()
    {
        const string html = """
            <html><head>
              <meta property="og:image" content="/img/banner-1200x630.jpg">
              <link rel="icon" href="/favicon-16.png" sizes="16x16">
              <link rel="icon" href="/favicon-32.png" sizes="32x32">
              <link rel="mask-icon" href="/safari-pinned.svg" color="#000">
              <link rel="icon" type="image/svg+xml" href="/icon.svg">
              <link rel="icon" href="/icon-192.png" sizes="192x192">
              <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
              <link rel="manifest" href="/site.webmanifest">
            </head><body>
              <header><a href="/"><img class="site-logo" src="/assets/logo.svg" alt="Example"></a></header>
              <img src="/hero.jpg" alt="hero">
            </body></html>
            """;
        var c = LogoScraper.ExtractCandidates(html, Base);
        Assert.Equal(["apple-touch-icon", "icon-svg", "icon-192", "mask-icon", "icon-32", "icon-16", "img-logo-svg", "og:image"], c.Select(x => x.Kind).ToArray());
        Assert.Equal("https://www.example.com/apple-touch-icon.png", c[0].Url.AbsoluteUri);
        Assert.DoesNotContain(c, x => x.Url.AbsolutePath == "/hero.jpg");
    }

    [Fact]
    public void Resolves_relative_urls_and_base_href()
    {
        const string html = """<html><head><base href="https://cdn.example.net/static/"><link rel="shortcut icon" href="fav.ico"></head></html>""";
        var c = LogoScraper.ExtractCandidates(html, Base);
        Assert.Single(c);
        Assert.Equal("https://cdn.example.net/static/fav.ico", c[0].Url.AbsoluteUri);
    }

    [Fact]
    public void Manifest_icons_rank_between_icons_and_img_logo()
    {
        const string json = """{"name":"x","icons":[{"src":"/android-192.png","sizes":"192x192","type":"image/png"},{"src":"icons/512.png","sizes":"512x512"}]}""";
        var c = LogoScraper.ParseManifest(json, new Uri("https://example.com/static/site.webmanifest")).OrderByDescending(x => x.Score).ToList();
        Assert.Equal("https://example.com/static/icons/512.png", c[0].Url.AbsoluteUri);
        Assert.All(c, x => Assert.InRange(x.Score, 451, 599));
    }

    [Theory]
    [InlineData(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0 }, ".png")]
    [InlineData(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 0x4A, 0x46 }, ".jpg")]
    [InlineData(new byte[] { 0, 0, 1, 0, 2, 0, 16, 16 }, ".ico")]
    [InlineData(new byte[] { (byte)'R', (byte)'I', (byte)'F', (byte)'F', 0, 0, 0, 0, (byte)'W', (byte)'E', (byte)'B', (byte)'P' }, ".webp")]
    [InlineData(new byte[] { (byte)'<', (byte)'h', (byte)'t', (byte)'m', (byte)'l', (byte)'>', 0, 0 }, null)]
    [InlineData(new byte[] { (byte)'G', (byte)'I', (byte)'F', (byte)'8', (byte)'9', (byte)'a', 0, 0 }, null)]
    public void Sniffs_magic_bytes(byte[] data, string? ext) => Assert.Equal(ext, ImageSniffer.Sniff(data));

    [Fact]
    public void Sniffs_svg()
    {
        Assert.Equal(".svg", ImageSniffer.Sniff(Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")));
        Assert.Equal(".svg", ImageSniffer.Sniff(Encoding.UTF8.GetBytes("  <svg viewBox=\"0 0 10 10\"><path d=\"M0 0\"/></svg>")));
        Assert.Null(ImageSniffer.Sniff(Encoding.UTF8.GetBytes("<!DOCTYPE html><html><body><svg></svg></body></html>")));
    }
}

public sealed class VendorLogoServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "netspider-logos-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, .. new byte[200]];

    private sealed class FakeWeb : HttpMessageHandler
    {
        public readonly List<string> Requests = new();
        public Func<Uri, HttpResponseMessage?> Route = _ => null;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (Requests) Requests.Add(request.RequestUri!.AbsoluteUri);
            var r = Route(request.RequestUri!) ?? new HttpResponseMessage(HttpStatusCode.NotFound);
            r.RequestMessage ??= request;
            return Task.FromResult(r);
        }
    }

    private static HttpResponseMessage Html(string s) => new(HttpStatusCode.OK) { Content = new StringContent(s, Encoding.UTF8, "text/html") };
    private static HttpResponseMessage Image(byte[] b, string type) { var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(b) }; r.Content.Headers.ContentType = new(type); return r; }

    private VendorLogoService Service(FakeWeb web, bool scrape = true) =>
        new(NullLogger<VendorLogoService>.Instance, new AppSettings { ScrapeVendorLogos = scrape }, _dir, web);

    [Fact]
    public async Task Scrapes_apple_touch_icon_for_known_vendor_and_caches_original_bytes()
    {
        var web = new FakeWeb
        {
            Route = u => u.AbsoluteUri switch
            {
                "https://sonos.com/" => Html("<link rel='icon' href='/f.png' sizes='32x32'><link rel='apple-touch-icon' href='/touch.png'>"),
                "https://sonos.com/touch.png" => Image(Png, "image/png"),
                _ => null,
            },
        };
        using var svc = Service(web);
        var d = new Device(Mac.Parse("00:0E:58:01:02:03")) { Brand = "Sonos" };
        var path = await svc.GetLogoAsync(d);
        Assert.Equal(Path.Combine(_dir, "sonos.png"), path);
        Assert.Equal(Png, await File.ReadAllBytesAsync(path!));
        Assert.Equal(path, svc.TryGetCachedBrandLogo("Sonos, Inc."));

        int before = web.Requests.Count;
        Assert.Equal(path, await svc.GetLogoAsync(d));
        Assert.Equal(before, web.Requests.Count); // served from cache
    }

    [Fact]
    public async Task Rejects_html_masquerading_as_image_and_falls_back()
    {
        var svg = Encoding.UTF8.GetBytes("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='40'/></svg>" + new string(' ', 64));
        var web = new FakeWeb
        {
            Route = u => u.AbsoluteUri switch
            {
                "https://netgear.com/" => Html("<link rel='apple-touch-icon' href='/bad.png'><img class='logo' src='/logo.svg'>"),
                "https://netgear.com/bad.png" => Html("<html>blocked</html>"),
                "https://netgear.com/logo.svg" => Image(svg, "image/svg+xml"),
                _ => null,
            },
        };
        using var svc = Service(web);
        var path = await svc.GetBrandLogoAsync("NETGEAR");
        Assert.Equal(Path.Combine(_dir, "netgear.svg"), path);
    }

    [Fact]
    public async Task Writes_negative_marker_and_does_not_retry()
    {
        var web = new FakeWeb();
        using var svc = Service(web);
        Assert.Null(await svc.GetBrandLogoAsync("Zzyzx Obscure Widgets"));
        Assert.True(File.Exists(Path.Combine(_dir, "zzyzx-obscure-widgets.none")));
        int n = web.Requests.Count;
        Assert.True(n > 0);
        Assert.Null(await svc.GetBrandLogoAsync("Zzyzx Obscure Widgets"));
        Assert.Equal(n, web.Requests.Count);
    }

    [Fact]
    public async Task Guesses_domain_for_unknown_brand()
    {
        var web = new FakeWeb
        {
            Route = u => u.AbsoluteUri switch
            {
                "https://frobnicator.com/" => Html("<p>no icons</p>"),
                "https://frobnicator.com/favicon.ico" => Image([0, 0, 1, 0, 1, 0, 16, 16, .. new byte[100]], "image/x-icon"),
                _ => null,
            },
        };
        using var svc = Service(web);
        var path = await svc.GetBrandLogoAsync("Frobnicator GmbH");
        Assert.Equal(Path.Combine(_dir, "frobnicator.ico"), path);
    }

    [Fact]
    public async Task Respects_scrape_setting_but_uses_device_icon()
    {
        var web = new FakeWeb { Route = u => u.AbsoluteUri == "http://192.168.1.20:1400/img/icon-S1.png" ? Image(Png, "image/png") : null };
        using var svc = Service(web, scrape: false);
        Assert.Null(await svc.GetBrandLogoAsync("Sonos"));
        Assert.Empty(web.Requests);

        var d = new Device(Mac.Parse("00:0E:58:01:02:04")) { Brand = "Sonos", IconUrl = "http://192.168.1.20:1400/img/icon-S1.png" };
        var path = await svc.GetLogoAsync(d);
        Assert.NotNull(path);
        Assert.StartsWith("icon-", Path.GetFileName(path));
        Assert.EndsWith(".png", path);
    }

    [Fact]
    public void Catalog_has_about_150_brands_with_aliases()
    {
        var cat = VendorCatalog.LoadEmbedded();
        Assert.InRange(cat.Entries.Count, 140, 250);
        Assert.Equal("ui.com", cat.Find("Ubiquiti Inc")!.Domain);
        Assert.Equal("ui.com", cat.Find("UniFi")!.Domain);
        Assert.Equal("tp-link.com", cat.Find("TP-LINK TECHNOLOGIES CO.,LTD.")!.Domain);
        Assert.Equal("philips-hue.com", cat.Find("Signify")!.Domain);
        Assert.Equal(["acmewidgets.com", "acme-widgets.com", "acmewidgets.net", "acmewidgets.de", "acmewidgets.co.uk"], cat.CandidateDomains("Acme Widgets Inc."));
    }

    [Fact]
    public async Task Prefetch_reports_progress()
    {
        using var svc = Service(new FakeWeb(), scrape: false);
        var reports = new List<ScanProgress>();
        await svc.PrefetchAllAsync(new SyncProgress(reports.Add));
        Assert.True(reports.Count > 100);
        Assert.Equal(1.0, reports.Max(r => r.Fraction), 3);
    }

    private sealed class SyncProgress(Action<ScanProgress> a) : IProgress<ScanProgress>
    {
        private readonly object _l = new();
        public void Report(ScanProgress value) { lock (_l) a(value); }
    }
}

/// <summary>Live scraping sanity check against real vendor sites. Run with: dotnet test --filter Category=Network</summary>
[Trait("Category", "Network")]
public sealed class VendorLogoNetworkTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "netspider-logos-live-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Theory]
    [InlineData("Sonos")]
    [InlineData("Netgear")]
    [InlineData("Ubiquiti")]
    [InlineData("Cisco")]
    [InlineData("Apple")]
    [InlineData("Synology")]
    public async Task Scrapes_real_vendor_site(string brand)
    {
        using var svc = new VendorLogoService(NullLogger<VendorLogoService>.Instance, new AppSettings(), _dir, null);
        var path = await svc.GetBrandLogoAsync(brand);
        output.WriteLine(path is null ? $"{brand}: none" : $"{brand}: {Path.GetFileName(path)} {new FileInfo(path).Length} bytes");
        Assert.NotNull(path);
        Assert.NotNull(ImageSniffer.Sniff(await File.ReadAllBytesAsync(path!)));
    }
}
