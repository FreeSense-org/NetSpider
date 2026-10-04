using System.Collections.Concurrent;
using SkiaSharp;
using Svg.Skia;

namespace NetSpider.App.Rendering;

/// <summary>
/// Decodes brand logos (png/jpg/ico/webp/bmp/gif via SkiaSharp codecs, svg via Svg.Skia) into normalized square
/// <see cref="SKImage"/>s. Decoding happens on the thread pool; callers get null until the image is ready.
/// Failed decodes are remembered so they are not retried every frame.
/// </summary>
public static class LogoCache
{
    public const int Size = 128;
    private static readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);

    private sealed class Entry
    {
        public volatile SKImage? Image;
        public volatile bool Done;
        public volatile bool IsLight;
    }

    /// <summary>Returns the decoded logo or null (not yet decoded, missing or invalid). Never throws.</summary>
    public static SKImage? Get(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var e = _cache.GetOrAdd(path, p =>
        {
            var n = new Entry();
            ThreadPool.QueueUserWorkItem(_ => { n.Image = TryDecode(p); n.IsLight = IsLightLogo(n.Image); n.Done = true; });
            return n;
        });
        return e.Image;
    }

    /// <summary>Synchronously decodes the given logos (used by headless snapshot rendering).</summary>
    public static void Preload(IEnumerable<string?> paths)
    {
        foreach (var p in paths.Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var e = _cache.GetOrAdd(p!, _ => new Entry());
            if (e.Done) continue;
            e.Image ??= TryDecode(p!);
            e.IsLight = IsLightLogo(e.Image);
            e.Done = true;
        }
    }

    /// <summary>true when the logo is mostly white/light on a transparent background and needs a dark backdrop.</summary>
    public static bool IsLight(string? path) => !string.IsNullOrEmpty(path) && _cache.TryGetValue(path, out var e) && e.IsLight;

    public static void Invalidate(string path) => _cache.TryRemove(path, out _);

    private static SKImage? TryDecode(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            if (path.EndsWith(".svg", StringComparison.OrdinalIgnoreCase)) return DecodeSvg(path);
            using var decoded = SKBitmap.Decode(path);
            if (decoded is null) return null;
            using var bmp = TrimTransparent(decoded);
            return Normalize(bmp.Width, bmp.Height, (c, dst) =>
            {
                using var img = SKImage.FromBitmap(bmp);
                c.DrawImage(img, dst, new SKSamplingOptions(SKCubicResampler.Mitchell));
            });
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Crops fully transparent borders so padded logos fill the badge.</summary>
    private static SKBitmap TrimTransparent(SKBitmap src)
    {
        int minX = src.Width, minY = src.Height, maxX = -1, maxY = -1;
        for (int y = 0; y < src.Height; y++)
            for (int x = 0; x < src.Width; x++)
            {
                if (src.GetPixel(x, y).Alpha <= 16) continue;
                if (x < minX) minX = x;
                if (x > maxX) maxX = x;
                if (y < minY) minY = y;
                if (y > maxY) maxY = y;
            }
        if (maxX < 0 || (minX == 0 && minY == 0 && maxX == src.Width - 1 && maxY == src.Height - 1)) return src.Copy();
        var cropped = new SKBitmap(maxX - minX + 1, maxY - minY + 1);
        src.ExtractSubset(cropped, SKRectI.Create(minX, minY, cropped.Width, cropped.Height));
        return cropped.Copy();
    }

    private static bool IsLightLogo(SKImage? img)
    {
        if (img is null) return false;
        try
        {
            using var bmp = SKBitmap.FromImage(img);
            double lum = 0; int opaque = 0, total = bmp.Width * bmp.Height;
            for (int y = 0; y < bmp.Height; y += 2)
                for (int x = 0; x < bmp.Width; x += 2)
                {
                    var p = bmp.GetPixel(x, y);
                    if (p.Alpha < 128) continue;
                    opaque++;
                    lum += (0.2126 * p.Red + 0.7152 * p.Green + 0.0722 * p.Blue) / 255.0;
                }
            if (opaque == 0) return false;
            // Logos with their own (mostly opaque) background render fine on the light disc.
            double coverage = opaque / (total / 4.0);
            return coverage < 0.85 && lum / opaque > 0.82;
        }
        catch { return false; }
    }

    private static SKImage? DecodeSvg(string path)
    {
        using var svg = new SKSvg();
        var pic = svg.Load(path);
        if (pic is null) return null;
        var b = pic.CullRect;
        if (b.Width <= 0 || b.Height <= 0) return null;
        return Normalize((int)Math.Ceiling(b.Width), (int)Math.Ceiling(b.Height), (c, dst) =>
        {
            var m = SKMatrix.CreateScaleTranslation(dst.Width / b.Width, dst.Height / b.Height,
                dst.Left - b.Left * dst.Width / b.Width, dst.Top - b.Top * dst.Height / b.Height);
            c.DrawPicture(pic, in m);
        });
    }

    /// <summary>Fits the source (aspect preserved) into a transparent square with a little padding.</summary>
    private static SKImage? Normalize(int w, int h, Action<SKCanvas, SKRect> draw)
    {
        if (w <= 0 || h <= 0) return null;
        var info = new SKImageInfo(Size, Size, SKColorType.Rgba8888, SKAlphaType.Premul);
        using var surface = SKSurface.Create(info);
        if (surface is null) return null;
        var c = surface.Canvas;
        c.Clear(SKColors.Transparent);
        float pad = Size * 0.06f;
        float scale = Math.Min((Size - 2 * pad) / w, (Size - 2 * pad) / h);
        float dw = w * scale, dh = h * scale;
        var dst = SKRect.Create((Size - dw) / 2, (Size - dh) / 2, dw, dh);
        draw(c, dst);
        c.Flush();
        return surface.Snapshot();
    }
}
