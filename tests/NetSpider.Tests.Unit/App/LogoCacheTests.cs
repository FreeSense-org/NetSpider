using NetSpider.App.Rendering;
using SkiaSharp;

namespace NetSpider.Tests.Unit.App;

public sealed class LogoCacheTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("ns-logo-").FullName;

    [Fact]
    public void Svg_logos_decode_into_a_square_image()
    {
        // Svg.Skia renders SVG logos; it must stay on the SkiaSharp line Avalonia uses.
        var path = Path.Combine(_dir, "brand.svg");
        File.WriteAllText(path, """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 20"><rect width="40" height="20" fill="#e11d48"/></svg>""");
        LogoCache.Preload([path]);
        var img = LogoCache.Get(path);
        Assert.NotNull(img);
        Assert.Equal(LogoCache.Size, img.Width);
        Assert.Equal(LogoCache.Size, img.Height);
        using var bmp = SKBitmap.FromImage(img);
        var center = bmp.GetPixel(LogoCache.Size / 2, LogoCache.Size / 2);
        Assert.Equal(new SKColor(0xe1, 0x1d, 0x48), center.WithAlpha(255));
        Assert.True(center.Alpha > 200);
    }

    [Fact]
    public void A_broken_svg_gives_no_image()
    {
        var path = Path.Combine(_dir, "broken.svg");
        File.WriteAllText(path, "<svg");
        LogoCache.Preload([path]);
        Assert.Null(LogoCache.Get(path));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}
