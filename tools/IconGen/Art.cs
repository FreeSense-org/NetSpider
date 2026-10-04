using SkiaSharp;
using static NetSpider.Tools.IconGen.Program;

namespace NetSpider.Tools.IconGen;

/// <summary>Composed raster art: installer images, splash, tray icons and the variant comparison sheet.</summary>
internal static class Art
{
    // Palette from src/NetSpider.App/Theme/NeonTheme.axaml
    public static readonly SKColor Bg = SKColor.Parse("#070B14");
    public static readonly SKColor Panel = SKColor.Parse("#0D1424");
    public static readonly SKColor Cyan = SKColor.Parse("#00E5FF");
    public static readonly SKColor Violet = SKColor.Parse("#7A5CFF");
    public static readonly SKColor Magenta = SKColor.Parse("#FF2BD6");
    public static readonly SKColor Green = SKColor.Parse("#3DFF8B");
    public static readonly SKColor Red = SKColor.Parse("#FF3D5A");
    public static readonly SKColor Text = SKColor.Parse("#E8F1FF");
    public static readonly SKColor TextDim = SKColor.Parse("#8A9BB8");
    public static readonly SKColor TextFaint = SKColor.Parse("#56657F");

    private const string FontFamily = "Segoe UI";

    private static SKFont Font(float size, SKFontStyleWeight weight = SKFontStyleWeight.Normal) =>
        new(SKTypeface.FromFamilyName(FontFamily, weight, SKFontStyleWidth.Normal, SKFontStyleSlant.Upright), size)
        {
            Edging = SKFontEdging.SubpixelAntialias,
            Subpixel = true,
        };

    private static SKShader NeonShader(SKPoint a, SKPoint b) =>
        SKShader.CreateLinearGradient(a, b, [Cyan, Violet, Magenta], [0f, 0.6f, 1f], SKShaderTileMode.Clamp);

    private static SKBitmap NewBitmap(int w, int h) =>
        new(new SKImageInfo(w, h, SKColorType.Bgra8888, SKAlphaType.Premul));

    private static void DarkBackground(SKCanvas c, SKRect r)
    {
        using var p = new SKPaint { IsAntialias = true };
        p.Shader = SKShader.CreateLinearGradient(new SKPoint(r.Left, r.Top), new SKPoint(r.Left + r.Width * 0.35f, r.Bottom),
            [Panel, Bg], SKShaderTileMode.Clamp);
        c.DrawRect(r, p);
    }

    /// <summary>Faint concentric web (8 spokes, sagging rings) used as a background motif.</summary>
    private static void WebMotif(SKCanvas c, SKPoint center, float radius, int rings, byte alpha, float stroke)
    {
        using var p = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = stroke, StrokeCap = SKStrokeCap.Round };
        p.Shader = NeonShader(new SKPoint(center.X - radius, center.Y - radius), new SKPoint(center.X + radius, center.Y + radius));
        p.Color = SKColors.White.WithAlpha(alpha);
        const int n = 8;
        using var path = new SKPath();
        for (int i = 0; i < n; i++)
        {
            var a = (22.5 + i * 45) * Math.PI / 180;
            path.MoveTo(center);
            path.LineTo(center.X + radius * (float)Math.Cos(a), center.Y + radius * (float)Math.Sin(a));
        }
        for (int ring = 1; ring <= rings; ring++)
        {
            var r = radius * ring / (rings + 0.4f);
            SKPoint P(int i)
            {
                var a = (22.5 + i * 45) * Math.PI / 180;
                return new SKPoint(center.X + r * (float)Math.Cos(a), center.Y + r * (float)Math.Sin(a));
            }
            path.MoveTo(P(0));
            for (int i = 0; i < n; i++)
            {
                SKPoint a = P(i), b = P(i + 1);
                var mid = new SKPoint((a.X + b.X) / 2, (a.Y + b.Y) / 2);
                var ctrl = new SKPoint(center.X + (mid.X - center.X) * 0.86f, center.Y + (mid.Y - center.Y) * 0.86f);
                path.QuadTo(ctrl, b);
            }
        }
        c.DrawPath(path, p); // paint alpha modulates the gradient shader
    }

    /// <summary>WiX banner (493×58). WiX draws the dialog title in black on the left, so the banner stays light.</summary>
    public static SKBitmap InstallerBanner(BrandSource src)
    {
        const int W = 493, H = 58;
        var bmp = NewBitmap(W, H);
        using var c = new SKCanvas(bmp);
        c.Clear(SKColors.White);
        // Faint web behind the logo on the right; the tile itself carries the dark brand color.
        c.Save();
        c.ClipRect(new SKRect(W - 150, 0, W, H - 2));
        WebMotif(c, new SKPoint(W - 30, H / 2f), 110, 4, 70, 1.1f);
        c.Restore();
        src.Draw(c, new SKRect(W - 52, 7, W - 8, 51));
        using (var p = new SKPaint { IsAntialias = true })
        {
            p.Shader = NeonShader(new SKPoint(0, 0), new SKPoint(W, 0));
            c.DrawRect(new SKRect(0, H - 2, W, H), p);
        }
        return bmp;
    }

    /// <summary>WiX dialog background (493×312): brand panel on the left 164 px, white text area on the right.</summary>
    public static SKBitmap InstallerDialog(BrandSource src)
    {
        const int W = 493, H = 312, PanelW = 164;
        var bmp = NewBitmap(W, H);
        using var c = new SKCanvas(bmp);
        c.Clear(SKColors.White);
        var panel = new SKRect(0, 0, PanelW, H);
        DarkBackground(c, panel);
        c.Save();
        c.ClipRect(panel);
        WebMotif(c, new SKPoint(PanelW / 2f, 96), 150, 4, 46, 1.2f);
        c.Restore();

        src.Draw(c, new SKRect(PanelW / 2f - 48, 48, PanelW / 2f + 48, 144));

        using var paint = new SKPaint { IsAntialias = true };
        using (var f = Font(11, SKFontStyleWeight.SemiBold))
        {
            paint.Shader = NeonShader(new SKPoint(40, 0), new SKPoint(124, 0));
            DrawSpaced(c, "FREESENSE", PanelW / 2f, 178, f, paint, 2.2f);
            paint.Shader = null;
        }
        using (var f = Font(24, SKFontStyleWeight.Bold))
        {
            paint.Color = Text;
            c.DrawText("NetSpider", PanelW / 2f, 206, SKTextAlign.Center, f, paint);
        }
        using (var f = Font(10.5f))
        {
            paint.Color = TextDim;
            c.DrawText("L2 · L3 network diagnostics", PanelW / 2f, 226, SKTextAlign.Center, f, paint);
            paint.Color = TextFaint;
            c.DrawText("freesense.org", PanelW / 2f, H - 18, SKTextAlign.Center, f, paint);
        }
        using (var p = new SKPaint { IsAntialias = true })
        {
            p.Shader = NeonShader(new SKPoint(0, 0), new SKPoint(0, H));
            c.DrawRect(new SKRect(PanelW - 2, 0, PanelW, H), p);
        }
        return bmp;
    }

    /// <summary>Velopack installer splash (600×300).</summary>
    public static SKBitmap Splash(BrandSource src)
    {
        const int W = 600, H = 300;
        var bmp = NewBitmap(W, H);
        using var c = new SKCanvas(bmp);
        DarkBackground(c, new SKRect(0, 0, W, H));
        using (var glow = new SKPaint { IsAntialias = true })
        {
            glow.Shader = SKShader.CreateRadialGradient(new SKPoint(150, 150), 190,
                [Violet.WithAlpha(70), Violet.WithAlpha(0)], SKShaderTileMode.Clamp);
            c.DrawRect(new SKRect(0, 0, W, H), glow);
        }
        WebMotif(c, new SKPoint(W - 40, H + 30), 300, 5, 34, 1.3f);

        src.Draw(c, new SKRect(52, 62, 228, 238));

        using var paint = new SKPaint { IsAntialias = true };
        const float X = 262;
        using (var f = Font(15, SKFontStyleWeight.SemiBold))
        {
            paint.Shader = NeonShader(new SKPoint(X, 0), new SKPoint(X + 120, 0));
            DrawSpaced(c, "FREESENSE", X, 120, f, paint, 3.5f, center: false);
            paint.Shader = null;
        }
        using (var f = Font(50, SKFontStyleWeight.Bold))
        {
            paint.Color = Text;
            c.DrawText("NetSpider", X - 2, 172, SKTextAlign.Left, f, paint);
        }
        using (var f = Font(15))
        {
            paint.Color = TextDim;
            c.DrawText("L2 · L3 network diagnostics", X, 202, SKTextAlign.Left, f, paint);
        }
        using (var f = Font(12))
        {
            paint.Color = TextFaint;
            c.DrawText("freesense.org", W - 22, H - 20, SKTextAlign.Right, f, paint);
        }
        using (var p = new SKPaint { IsAntialias = true })
        {
            p.Shader = NeonShader(new SKPoint(0, 0), new SKPoint(W, 0));
            c.DrawRect(new SKRect(0, H - 3, W, H), p);
        }
        return bmp;
    }

    /// <summary>Tray icon: the small icon plus an optional status dot (bottom-right) with a dark cut-out ring.</summary>
    public static SKBitmap TrayIcon(BrandSource src, int size, SKColor? dot)
    {
        var bmp = src.Render(size);
        if (dot is not { } color) return bmp;
        using var c = new SKCanvas(bmp);
        float r = size * 0.24f, ring = Math.Max(1f, size * 0.08f);
        var center = new SKPoint(size - r - 0.25f, size - r - 0.25f);
        using var p = new SKPaint { IsAntialias = true };
        p.BlendMode = SKBlendMode.Clear;
        c.DrawCircle(center, r + ring, p);
        p.BlendMode = SKBlendMode.SrcOver;
        p.Color = Bg;
        c.DrawCircle(center, r + ring * 0.6f, p);
        p.Color = color;
        c.DrawCircle(center, r, p);
        p.Color = SKColors.White.WithAlpha(110);
        c.DrawCircle(center.X - r * 0.3f, center.Y - r * 0.3f, r * 0.32f, p);
        return bmp;
    }

    /// <summary>Comparison sheet: every variant at 256/64/32/16 px on dark and light backgrounds, plus zoomed 16/32 px.</summary>
    public static SKBitmap VariantSheet(BrandSource[] variants)
    {
        int[] sizes = [256, 64, 32, 16];
        const int Pad = 40, Gap = 28, RowH = 256 + 92, HeaderH = 92;
        const int Zoom = 4;
        int panelW = 18 + sizes.Sum() + Gap * sizes.Length + (32 * Zoom) + Gap + (16 * Zoom) + 18 + 12;
        int W = Pad + panelW * 2 + Pad, H = HeaderH + RowH * variants.Length + Pad;
        var bmp = NewBitmap(W, H);
        using var c = new SKCanvas(bmp);
        c.Clear(SKColor.Parse("#05080F"));

        using var paint = new SKPaint { IsAntialias = true };
        using var title = Font(26, SKFontStyleWeight.Bold);
        using var label = Font(13, SKFontStyleWeight.SemiBold);
        using var small = Font(11);

        paint.Color = Text;
        c.DrawText("NetSpider icon variants", Pad, 46, SKTextAlign.Left, title, paint);
        paint.Color = TextDim;
        c.DrawText("256 · 64 · 32 · 16 px (≤32 px uses the simplified small SVG) · zoomed 32 and 16 px at 4×", Pad, 70, SKTextAlign.Left, small, paint);

        string[] names = ["A · concentric web rings", "B · hexagon web, bold glyph", "C · \"N\" web monogram"];
        for (int row = 0; row < variants.Length; row++)
        {
            int y = HeaderH + row * RowH;
            paint.Color = Text;
            c.DrawText(row < names.Length ? names[row] : variants[row].Variant, Pad, y + 18, SKTextAlign.Left, label, paint);
            y += 30;

            for (int bgIdx = 0; bgIdx < 2; bgIdx++)
            {
                bool dark = bgIdx == 0;
                float x0 = Pad + bgIdx * panelW;
                var bgRect = new SKRect(x0, y, x0 + panelW - 12, y + RowH - 46);
                paint.Color = dark ? SKColor.Parse("#0B111D") : SKColor.Parse("#F2F4F8");
                c.DrawRoundRect(bgRect, 14, 14, paint);

                float x = x0 + 18;
                float baseline = y + 20 + 256;
                foreach (var s in sizes)
                {
                    using var icon = variants[row].Render(s);
                    c.DrawBitmap(icon, x, baseline - s);
                    paint.Color = dark ? TextFaint : SKColor.Parse("#7A869C");
                    c.DrawText($"{s}", x + s / 2f, baseline + 20, SKTextAlign.Center, small, paint);
                    x += s + Gap;
                }
                foreach (var s in new[] { 32, 16 })
                {
                    using var icon = variants[row].Render(s);
                    var dest = new SKRect(x, baseline - s * Zoom, x + s * Zoom, baseline);
                    c.DrawImage(SKImage.FromBitmap(icon), dest, new SKSamplingOptions(SKFilterMode.Nearest), null);
                    paint.Color = dark ? TextFaint : SKColor.Parse("#7A869C");
                    c.DrawText($"{s} ×{Zoom}", x + s * Zoom / 2f, baseline + 20, SKTextAlign.Center, small, paint);
                    x += s * Zoom + Gap;
                }
            }
        }
        return bmp;
    }

    private static void DrawSpaced(SKCanvas c, string text, float x, float y, SKFont font, SKPaint paint, float spacing, bool center = true)
    {
        var widths = text.Select(ch => font.MeasureText(ch.ToString())).ToArray();
        float total = widths.Sum() + spacing * (text.Length - 1);
        float cx = center ? x - total / 2 : x;
        for (int i = 0; i < text.Length; i++)
        {
            c.DrawText(text[i].ToString(), cx, y, SKTextAlign.Left, font, paint);
            cx += widths[i] + spacing;
        }
    }
}
