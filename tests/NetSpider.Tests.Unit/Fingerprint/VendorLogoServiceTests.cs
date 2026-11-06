using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Fingerprint;
using NetSpider.Fingerprint.Logos;

namespace NetSpider.Tests.Unit.Fingerprint;

public sealed class ImageSnifferTests
{
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

    private VendorLogoService Service(FakeWeb web) => new(NullLogger<VendorLogoService>.Instance, _dir, web);

    [Fact]
    public async Task Brand_logos_come_from_the_app_and_never_the_web()
    {
        var web = new FakeWeb();
        using var svc = Service(web);
        var d = new Device(Mac.Parse("02:00:00:01:02:03")) { Brand = "Sony Corporation" };
        var path = await svc.GetLogoAsync(d);
        Assert.Equal(Path.Combine(_dir, "sony.png"), path);
        Assert.Equal(".png", ImageSniffer.Sniff(await File.ReadAllBytesAsync(path!)));

        // Issue #6: the OUI registers Lenovo's laptops as LCFC, which is also a football club's domain.
        Assert.Equal(Path.Combine(_dir, "lenovo.png"), svc.GetBrandLogo("LCFC(Hefei) Electronics Technology co., ltd"));
        Assert.Equal(Path.Combine(_dir, "tp-link.png"), svc.GetBrandLogo("TP-LINK TECHNOLOGIES CO.,LTD."));
        Assert.Null(svc.GetBrandLogo("Frobnicator GmbH"));
        Assert.Empty(web.Requests);
    }

    [Fact]
    public void Every_catalog_brand_has_a_logo_and_every_logo_a_brand()
    {
        const string marker = ".Data.Logos.";
        var brands = VendorCatalog.LoadEmbedded().Entries.Select(e => BrandNormalizer.Key(e.Brand)).Order(StringComparer.Ordinal);
        var logos = typeof(VendorCatalog).Assembly.GetManifestResourceNames().Where(n => n.Contains(marker))
            .Select(n => n[(n.IndexOf(marker) + marker.Length)..^4]).Order(StringComparer.Ordinal);
        Assert.Equal(brands, logos);
    }

    [Fact]
    public async Task Discards_logos_from_older_versions_but_keeps_device_icons()
    {
        Directory.CreateDirectory(_dir);
        await File.WriteAllBytesAsync(Path.Combine(_dir, "lcfc.png"), Png);
        await File.WriteAllBytesAsync(Path.Combine(_dir, "sharp.png"), Png);
        await File.WriteAllTextAsync(Path.Combine(_dir, "arlo.none"), "");
        await File.WriteAllBytesAsync(Path.Combine(_dir, "icon-0123456789abcdef.png"), Png);

        using (Service(new FakeWeb()))
            Assert.Equal(["catalog.rev", "icon-0123456789abcdef.png"], Directory.GetFiles(_dir).Select(f => Path.GetFileName(f)).Order(StringComparer.Ordinal));

        // The same build leaves what it extracted alone.
        await File.WriteAllBytesAsync(Path.Combine(_dir, "sonos.png"), Png);
        using var again = Service(new FakeWeb());
        Assert.Equal(Png, await File.ReadAllBytesAsync(again.GetBrandLogo("Sonos")!));
    }

    [Theory]
    [InlineData("LCFC(Hefei) Electronics Technology co., ltd", "Lenovo")]
    [InlineData("Micro-Star INTL CO., LTD.", "MSI")]
    [InlineData("GIGA-BYTE TECHNOLOGY CO.,LTD.", "Gigabyte")]
    [InlineData("Sonos, Inc.", "Sonos")]
    [InlineData("Juniper Networks", "Juniper")]
    [InlineData("Asustor Inc.", "Asustor")]
    public void Registered_names_reach_their_brand(string organization, string catalogBrand) =>
        Assert.Equal(catalogBrand, VendorCatalog.LoadEmbedded().Find(BrandNormalizer.Normalize(organization)!)!.Brand);

    [Theory]
    [InlineData("SonoSite, Inc.")]
    [InlineData("Juniper Systems")]
    [InlineData("Beijing ECHO Technologies Co.,Ltd")]
    [InlineData("Brother, Brother & Sons ApS")]
    [InlineData("Ring Solutions")]
    [InlineData("AVM ELECTRONICS PTE LTD")]
    [InlineData("MURATA MACHINERY, LTD.")]
    [InlineData("Shanghai Dahua Scale Factory")]
    [InlineData("Viziontech UK")]
    [InlineData("Adtranz Sweden")]
    [InlineData("Flex-P Industries Sdn. Bhd.")]
    [InlineData("Limidea Concept Pte. Ltd.")]
    [InlineData("META SYSTEM SPA")]
    [InlineData("Marshall Electronics")]
    public void Lookalike_companies_do_not_get_another_brands_logo(string organization) =>
        Assert.Null(VendorCatalog.LoadEmbedded().Find(BrandNormalizer.Normalize(organization)!));

    [Fact]
    public async Task Prefers_the_devices_own_icon_and_rejects_html_posing_as_an_image()
    {
        var web = new FakeWeb
        {
            Route = u => u.AbsoluteUri switch
            {
                "http://192.168.1.20:1400/img/icon-S1.png" => Image(Png, "image/png"),
                "http://192.168.1.21/blocked.png" => Html("<html>blocked</html>"),
                _ => null,
            },
        };
        using var svc = Service(web);
        var d = new Device(Mac.Parse("02:00:00:01:02:04")) { Brand = "Sonos", IconUrl = "http://192.168.1.20:1400/img/icon-S1.png" };
        var path = await svc.GetLogoAsync(d);
        Assert.StartsWith("icon-", Path.GetFileName(path));
        Assert.EndsWith(".png", path);

        // A bad icon falls back to the brand logo and is not asked for again.
        var bad = new Device(Mac.Parse("02:00:00:01:02:05")) { Brand = "Sonos", IconUrl = "http://192.168.1.21/blocked.png" };
        Assert.Equal(Path.Combine(_dir, "sonos.png"), await svc.GetLogoAsync(bad));
        int n = web.Requests.Count;
        Assert.Equal(Path.Combine(_dir, "sonos.png"), await svc.GetLogoAsync(bad));
        Assert.Equal(n, web.Requests.Count);
    }

    [Fact]
    public void Catalog_covers_the_major_brands_with_aliases()
    {
        var cat = VendorCatalog.LoadEmbedded();
        Assert.InRange(cat.Entries.Count, 250, 500);
        Assert.Equal("Ubiquiti", cat.Find("Ubiquiti Inc")!.Brand);
        Assert.Equal("Ubiquiti", cat.Find("UniFi")!.Brand);
        Assert.Equal("TP-Link", cat.Find("TP-LINK TECHNOLOGIES CO.,LTD.")!.Brand);
        Assert.Equal("Philips Hue", cat.Find("Signify")!.Brand);
        Assert.Null(cat.Find("Acme Widgets Inc."));
    }
}
