using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Rendering.SceneGraph;
using Avalonia.Skia;
using Avalonia.Threading;
using NetSpider.App.Rendering;
using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Controls;

/// <summary>Small round device badge: brand logo (if cached) or the procedural type glyph, with a colored ring.</summary>
public sealed class DeviceBadge : Control
{
    public static readonly StyledProperty<DeviceType> DeviceTypeProperty = AvaloniaProperty.Register<DeviceBadge, DeviceType>(nameof(DeviceType));
    public static readonly StyledProperty<string?> LogoPathProperty = AvaloniaProperty.Register<DeviceBadge, string?>(nameof(LogoPath));
    public static readonly StyledProperty<Color> RingColorProperty = AvaloniaProperty.Register<DeviceBadge, Color>(nameof(RingColor), Color.Parse("#00E5FF"));

    public DeviceType DeviceType { get => GetValue(DeviceTypeProperty); set => SetValue(DeviceTypeProperty, value); }
    public string? LogoPath { get => GetValue(LogoPathProperty); set => SetValue(LogoPathProperty, value); }
    public Color RingColor { get => GetValue(RingColorProperty); set => SetValue(RingColorProperty, value); }

    static DeviceBadge() => AffectsRender<DeviceBadge>(DeviceTypeProperty, LogoPathProperty, RingColorProperty);

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        // logos decode asynchronously; re-render once it's likely ready
        if (change.Property == LogoPathProperty && LogoPath is not null && LogoCache.Get(LogoPath) is null)
            DispatcherTimer.RunOnce(InvalidateVisual, TimeSpan.FromMilliseconds(300));
    }

    public override void Render(DrawingContext context)
    {
        var c = RingColor;
        context.Custom(new Op(new Rect(Bounds.Size), DeviceType, LogoPath, new SKColor(c.R, c.G, c.B, c.A)));
    }

    private sealed class Op(Rect bounds, DeviceType type, string? logo, SKColor ring) : ICustomDrawOperation
    {
        public Rect Bounds => bounds;
        public bool HitTest(Point p) => bounds.Contains(p);
        public bool Equals(ICustomDrawOperation? other) => false;
        public void Dispose() { }

        public void Render(ImmediateDrawingContext context)
        {
            var lease = context.TryGetFeature<ISkiaSharpApiLeaseFeature>();
            if (lease is null) return;
            using var l = lease.Lease();
            var canvas = l.SkCanvas;
            float w = (float)bounds.Width, h = (float)bounds.Height;
            float r = Math.Min(w, h) / 2 - 2;
            float cx = w / 2, cy = h / 2;
            using var fill = new SKPaint { IsAntialias = true };
            using (var sh = SKShader.CreateRadialGradient(new SKPoint(cx - r * 0.3f, cy - r * 0.35f), r * 1.4f,
                       [SKColor.Parse("#1F3157"), SKColor.Parse("#0B1324")], SKShaderTileMode.Clamp))
            {
                fill.Shader = sh;
                canvas.DrawCircle(cx, cy, r, fill);
                fill.Shader = null;
            }
            var img = LogoCache.Get(logo);
            if (img is not null)
            {
                fill.Color = LogoCache.IsLight(logo) ? SKColor.Parse("#111A2E") : SKColor.Parse("#F2F6FC");
                canvas.DrawCircle(cx, cy, r - 2.5f, fill);
                canvas.Save();
                using var clip = new SKPath();
                clip.AddCircle(cx, cy, r - 2.5f);
                canvas.ClipPath(clip, antialias: true);
                float s = (r - 2.5f) * 1.45f;
                canvas.DrawImage(img, new SKRect(cx - s / 2, cy - s / 2, cx + s / 2, cy + s / 2), new SKSamplingOptions(SKFilterMode.Linear, SKMipmapMode.Linear));
                canvas.Restore();
            }
            else Glyphs.Draw(canvas, type, cx, cy, r * 1.15f, SKColor.Parse("#CFEFFF"));
            using var stroke = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = Math.Max(1.5f, r * 0.1f), Color = ring };
            canvas.DrawCircle(cx, cy, r, stroke);
        }
    }
}
