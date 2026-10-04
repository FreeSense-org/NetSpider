using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Rendering.SceneGraph;
using Avalonia.Skia;
using Avalonia.Threading;
using NetSpider.App.Rendering;
using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Controls;

/// <summary>Everything the chain control needs to draw one hop (immutable; rebuilt by the view model on each update).</summary>
public sealed record HopVisual(
    int Index, HopRole Role, DeviceType Glyph, string Name, string? Ip, string RoleText, HopHealth Health,
    string Rtt, string? Added, string Loss, bool? Arp, bool? Icmp, string? Note, string? LogoPath,
    bool LinkFault, bool Beyond, double?[] Recent);

/// <summary>
/// Path Doctor's horizontal hop chain: one card per hop (glyph/logo, name, IP, RTT, added latency, loss, ARP/ICMP chips,
/// mini timeline, note) joined by animated link segments. The link into the first failing hop turns red with a fault
/// marker. Cards shrink to fit up to ~9 hops on one row and wrap (with a return connector) when the space runs out.
/// </summary>
public sealed class PathChainControl : Control
{
    public static readonly StyledProperty<IReadOnlyList<HopVisual>?> HopsProperty =
        AvaloniaProperty.Register<PathChainControl, IReadOnlyList<HopVisual>?>(nameof(Hops));
    public static readonly StyledProperty<int> SelectedIndexProperty =
        AvaloniaProperty.Register<PathChainControl, int>(nameof(SelectedIndex), -1, defaultBindingMode: BindingMode.TwoWay);

    public IReadOnlyList<HopVisual>? Hops { get => GetValue(HopsProperty); set => SetValue(HopsProperty, value); }
    public int SelectedIndex { get => GetValue(SelectedIndexProperty); set => SetValue(SelectedIndexProperty, value); }

    public const float CardH = 224, Gap = 34, RowGap = 40, MinCardW = 128, MaxCardW = 200;

    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private DispatcherTimer? _timer;
    private int _hover = -1;

    static PathChainControl()
    {
        AffectsMeasure<PathChainControl>(HopsProperty);
        AffectsRender<PathChainControl>(HopsProperty, SelectedIndexProperty);
    }

    public PathChainControl() => Cursor = new Cursor(StandardCursorType.Arrow);

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(33), DispatcherPriority.Render, (_, _) => { if (IsEffectivelyVisible) InvalidateVisual(); });
        _timer.Start();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _timer?.Stop();
        _timer = null;
    }

    // ---- layout ----
    private readonly record struct Layout(float CardW, int PerRow, int Rows, float Left);

    private static Layout Compute(int n, double width)
    {
        if (n == 0 || width <= 0 || double.IsInfinity(width)) return new Layout(MaxCardW, Math.Max(1, n), 1, 0);
        float w = (float)width;
        float cw = (w - (n - 1) * Gap) / n;
        if (cw >= MinCardW) { cw = Math.Min(cw, MaxCardW); return new Layout(cw, n, 1, (w - (n * cw + (n - 1) * Gap)) / 2); }
        // wrap: keep a gutter on both sides for the return connector
        float inner = w - Gap;
        int per = Math.Max(1, (int)((inner + Gap) / (MinCardW + Gap)));
        cw = Math.Min(MaxCardW, (inner - (per - 1) * Gap) / per);
        int rows = (n + per - 1) / per;
        return new Layout(cw, per, rows, Gap / 2);
    }

    private static SKRect CardRect(Layout l, int i)
    {
        int row = i / l.PerRow, col = i % l.PerRow;
        float x = l.Left + col * (l.CardW + Gap), y = 4 + row * (CardH + RowGap);
        return new SKRect(x, y, x + l.CardW, y + CardH);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        int n = Hops?.Count ?? 0;
        var l = Compute(n, availableSize.Width);
        double h = n == 0 ? 60 : l.Rows * CardH + (l.Rows - 1) * RowGap + 8;
        double w = double.IsInfinity(availableSize.Width) ? n * (MaxCardW + Gap) : availableSize.Width;
        return new Size(w, h);
    }

    private int HitTest(Point p)
    {
        var hops = Hops;
        if (hops is null) return -1;
        var l = Compute(hops.Count, Bounds.Width);
        for (int i = 0; i < hops.Count; i++) if (CardRect(l, i).Contains((float)p.X, (float)p.Y)) return i;
        return -1;
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        int h = HitTest(e.GetPosition(this));
        if (h != _hover) { _hover = h; Cursor = new Cursor(h >= 0 ? StandardCursorType.Hand : StandardCursorType.Arrow); }
    }

    protected override void OnPointerExited(PointerEventArgs e) { base.OnPointerExited(e); _hover = -1; }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        int h = HitTest(e.GetPosition(this));
        if (h >= 0) SelectedIndex = SelectedIndex == h ? -1 : h;
    }

    public override void Render(DrawingContext context)
    {
        var hops = Hops ?? [];
        context.Custom(new DrawOp(new Rect(Bounds.Size), hops, SelectedIndex, _hover, _clock.Elapsed.TotalSeconds));
    }

    // =========================================================================================================
    //  drawing (render thread)
    // =========================================================================================================

    private sealed class DrawOp(Rect bounds, IReadOnlyList<HopVisual> hops, int selected, int hover, double time) : ICustomDrawOperation
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
            var c = l.SkCanvas;
            c.Save();
            c.ClipRect(new SKRect(0, 0, (float)bounds.Width, (float)bounds.Height));
            try { lock (Painter) Painter.Draw(c, (float)bounds.Width, hops, selected, hover, (float)time); }
            catch (Exception ex) { Debug.WriteLine(ex); }
            c.Restore();
        }
    }

    private static readonly ChainPainter Painter = new();

    private sealed class ChainPainter
    {
        private readonly SKPaint _fill = new() { IsAntialias = true, Style = SKPaintStyle.Fill };
        private readonly SKPaint _stroke = new() { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeCap = SKStrokeCap.Round };
        private readonly SKPaint _text = new() { IsAntialias = true };
        private readonly SKFont _fName = new(Fonts.SemiBold, 13f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fMono = new(Fonts.Mono, 10.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fRole = new(Fonts.Bold, 8.5f) { Subpixel = true };
        private readonly SKFont _fRtt = new(Fonts.SemiBold, 21f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fRttSmall = new(Fonts.SemiBold, 16.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fSmall = new(Fonts.Regular, 10.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fSmallBold = new(Fonts.SemiBold, 10.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
        private readonly SKFont _fChip = new(Fonts.Bold, 8.5f) { Subpixel = true };
        private readonly SKPath _path = new();
        private readonly SKMaskFilter _blur = SKMaskFilter.CreateBlur(SKBlurStyle.Normal, 9);

        private static SKColor HealthColor(HopHealth h, bool beyond) => beyond ? Neon.Grey : h switch
        {
            HopHealth.Up => Neon.Green,
            HopHealth.Degraded => Neon.Amber,
            HopHealth.Down => Neon.Red,
            _ => Neon.Grey,
        };

        public void Draw(SKCanvas c, float width, IReadOnlyList<HopVisual> hops, int selected, int hover, float t)
        {
            if (hops.Count == 0) return;
            var l = Compute(hops.Count, width);
            // links first so the cards sit on top
            for (int i = 1; i < hops.Count; i++) DrawLink(c, l, hops[i - 1], hops[i], i, t);
            for (int i = 0; i < hops.Count; i++) DrawCard(c, CardRect(l, i), hops[i], i == selected, i == hover, t);
        }

        // ---- links ----
        private void DrawLink(SKCanvas c, Layout l, HopVisual from, HopVisual to, int i, float t)
        {
            var a = CardRect(l, i - 1);
            var b = CardRect(l, i);
            float ly = 40; // at glyph height
            _path.Reset();
            bool wrapped = b.Top > a.Top + 1;
            if (!wrapped)
            {
                _path.MoveTo(a.Right, a.Top + ly);
                _path.LineTo(b.Left, b.Top + ly);
            }
            else
            {
                // return connector: out to the right gutter, down between the rows, back left, into the next row
                float gx = a.Right + Gap / 2 - 6, midY = a.Bottom + RowGap / 2, lx = b.Left - Gap / 2 + 6;
                _path.MoveTo(a.Right, a.Top + ly);
                _path.LineTo(gx, a.Top + ly);
                _path.LineTo(gx, midY);
                _path.LineTo(lx, midY);
                _path.LineTo(lx, b.Top + ly);
                _path.LineTo(b.Left, b.Top + ly);
            }

            var col = to.LinkFault ? Neon.Red : HealthColor(to.Health, to.Beyond);
            _stroke.PathEffect = null;
            _stroke.StrokeJoin = SKStrokeJoin.Round;
            if (to.LinkFault)
            {
                float pulse = 0.5f + 0.5f * MathF.Sin(t * 5);
                _stroke.StrokeWidth = 12;
                _stroke.Color = Neon.Red.A(0.10f + 0.14f * pulse);
                c.DrawPath(_path, _stroke);
                using var dash = SKPathEffect.CreateDash([8f, 6f], -t * 26);
                _stroke.PathEffect = dash;
                _stroke.StrokeWidth = 3;
                _stroke.Color = Neon.Red;
                c.DrawPath(_path, _stroke);
                _stroke.PathEffect = null;
                // fault marker (✕ in a circle) at the middle of the segment
                using var measure = new SKPathMeasure(_path);
                measure.GetPosition(measure.Length / 2, out var m);
                _fill.Color = SKColor.Parse("#2A0C14");
                c.DrawCircle(m, 11, _fill);
                _stroke.StrokeWidth = 2;
                _stroke.Color = Neon.Red;
                c.DrawCircle(m, 11, _stroke);
                _stroke.StrokeWidth = 2.4f;
                c.DrawLine(m.X - 4.5f, m.Y - 4.5f, m.X + 4.5f, m.Y + 4.5f, _stroke);
                c.DrawLine(m.X + 4.5f, m.Y - 4.5f, m.X - 4.5f, m.Y + 4.5f, _stroke);
                _text.Color = Neon.Red;
                c.DrawText("FAULT", m.X, m.Y - 17, SKTextAlign.Center, _fChip, _text);
                return;
            }
            if (to.Beyond)
            {
                using var dash = SKPathEffect.CreateDash([3f, 5f], 0);
                _stroke.PathEffect = dash;
                _stroke.StrokeWidth = 2;
                _stroke.Color = Neon.Grey.A(0.7f);
                c.DrawPath(_path, _stroke);
                _stroke.PathEffect = null;
                return;
            }
            _stroke.StrokeWidth = 8;
            _stroke.Color = col.A(0.10f);
            c.DrawPath(_path, _stroke);
            _stroke.StrokeWidth = 2.2f;
            _stroke.Color = col.A(0.85f);
            c.DrawPath(_path, _stroke);
            // packets flowing towards the internet
            using var pm = new SKPathMeasure(_path);
            float len = pm.Length;
            for (int k = 0; k < 3; k++)
            {
                float p = (t * 0.55f + k / 3f + i * 0.13f) % 1f;
                pm.GetPosition(p * len, out var pt);
                float fade = MathF.Sin(p * MathF.PI);
                _fill.Color = col.A(0.3f * fade);
                c.DrawCircle(pt, 5.5f, _fill);
                _fill.Color = SKColors.White.A(0.95f * fade);
                c.DrawCircle(pt, 1.8f, _fill);
            }
        }

        // ---- cards ----
        private void DrawCard(SKCanvas c, SKRect r, HopVisual h, bool selected, bool hover, float t)
        {
            var hc = HealthColor(h.Health, h.Beyond);
            bool down = h.Health == HopHealth.Down && !h.Beyond;

            // shadow + body
            _fill.Color = SKColors.Black.A(0.45f);
            _fill.MaskFilter = _blur;
            c.DrawRoundRect(new SKRect(r.Left + 2, r.Top + 8, r.Right + 2, r.Bottom + 10), 14, 14, _fill);
            _fill.MaskFilter = null;
            using (var body = SKShader.CreateLinearGradient(new SKPoint(0, r.Top), new SKPoint(0, r.Bottom),
                       [SKColor.Parse(down ? "#1C0E18" : "#111A2E"), SKColor.Parse("#0B1222")], SKShaderTileMode.Clamp))
            {
                _fill.Shader = body;
                c.DrawRoundRect(r, 14, 14, _fill);
                _fill.Shader = null;
            }
            if (down)
            {
                float pulse = 0.5f + 0.5f * MathF.Sin(t * 5);
                _stroke.StrokeWidth = 7;
                _stroke.Color = Neon.Red.A(0.08f + 0.12f * pulse);
                c.DrawRoundRect(r, 14, 14, _stroke);
            }
            _stroke.PathEffect = null;
            _stroke.StrokeWidth = selected ? 2 : 1.2f;
            _stroke.Color = selected ? Neon.Cyan : hover ? hc.A(0.85f) : hc.A(h.Beyond ? 0.25f : 0.45f);
            c.DrawRoundRect(r, 14, 14, _stroke);
            // top accent bar
            _fill.Color = hc.A(h.Beyond ? 0.35f : 0.9f);
            c.DrawRoundRect(new SKRect(r.Left + 14, r.Top, r.Right - 14, r.Top + 3), 1.5f, 1.5f, _fill);

            float pad = 12, x0 = r.Left + pad, inner = r.Width - pad * 2;
            float alpha = h.Beyond ? 0.55f : 1f;

            // glyph / logo badge
            float gr = 17, gx = x0 + gr, gy = r.Top + 40;
            _fill.Color = SKColor.Parse("#0B1324");
            c.DrawCircle(gx, gy, gr, _fill);
            var logo = LogoCache.Get(h.LogoPath);
            if (logo is not null)
            {
                _fill.Color = (LogoCache.IsLight(h.LogoPath) ? SKColor.Parse("#111A2E") : SKColor.Parse("#F2F6FC")).A(alpha);
                c.DrawCircle(gx, gy, gr - 3, _fill);
                c.Save();
                _path.Reset();
                _path.AddCircle(gx, gy, gr - 3);
                c.ClipPath(_path, antialias: true);
                float s = (gr - 3) * 1.45f;
                _fill.Color = SKColors.White.A(alpha);
                c.DrawImage(logo, new SKRect(gx - s / 2, gy - s / 2, gx + s / 2, gy + s / 2), new SKSamplingOptions(SKFilterMode.Linear, SKMipmapMode.Linear), _fill);
                c.Restore();
            }
            else Glyphs.Draw(c, h.Glyph, gx, gy, gr * 1.15f, (h.Role == HopRole.InternetTarget ? Neon.Cyan : SKColor.Parse("#9FF6FF")).A(alpha));
            _stroke.StrokeWidth = 2.4f;
            _stroke.Color = hc.A(alpha);
            c.DrawCircle(gx, gy, gr, _stroke);
            // hop number
            _text.Color = Neon.TextFaint;
            c.DrawText($"#{h.Index}", r.Right - pad, r.Top + 20, SKTextAlign.Right, _fChip, _text);

            // name + IP
            float tx = gx + gr + 9, tw = r.Right - pad - tx;
            _text.Color = Neon.Text.A(alpha);
            c.DrawText(Fit(h.Name, _fName, tw - (tx + tw > r.Right - 30 ? 0 : 0)), tx, gy - 2, SKTextAlign.Left, _fName, _text);
            _text.Color = Neon.TextDim.A(alpha);
            c.DrawText(Fit(h.Ip ?? "no IP (anchors)", _fMono, tw), tx, gy + 13, SKTextAlign.Left, _fMono, _text);

            // role caption
            float y = r.Top + 78;
            _text.Color = Neon.Cyan.A(0.75f * alpha);
            c.DrawText(Fit(h.RoleText.ToUpperInvariant(), _fRole, inner), x0, y, SKTextAlign.Left, _fRole, _text);

            // RTT + added
            y += 27;
            _text.Color = (down ? Neon.Red : h.Beyond ? Neon.Grey : Neon.Text);
            // shrink the RTT on narrow cards so the "+added" latency still fits beside it
            float addW = h.Added is { } a0 ? _fSmallBold.MeasureText(a0) + 6 : 0;
            var rttFont = _fRtt.MeasureText(h.Rtt) + addW <= inner ? _fRtt : _fRttSmall;
            c.DrawText(h.Rtt, x0, y, SKTextAlign.Left, rttFont, _text);
            if (h.Added is { } add && rttFont.MeasureText(h.Rtt) + addW <= inner)
            {
                _text.Color = Neon.Magenta.A(alpha);
                c.DrawText(add, r.Right - pad, y - 1, SKTextAlign.Right, _fSmallBold, _text);
            }

            // loss + chips
            y += 18;
            _text.Color = Neon.TextDim.A(alpha);
            c.DrawText(Fit(h.Loss, _fSmall, inner), x0, y, SKTextAlign.Left, _fSmall, _text);
            y += 9;
            float cx = x0;
            if (h.Arp is not null) cx = Chip(c, cx, y, "ARP", h.Arp, alpha);
            if (h.Icmp is not null) cx = Chip(c, cx, y, "ICMP", h.Icmp, alpha);
            if (h.Arp is null && h.Icmp is null) Chip(c, cx, y, h.Role == HopRole.ThisHost ? "LOCAL" : "ANCHORS", null, alpha);

            // mini timeline
            y += 24;
            var spark = new SKRect(x0, y, r.Right - pad, y + 28);
            DrawSpark(c, spark, h.Recent, hc, alpha);

            // note (up to two lines)
            if (h.Note is { Length: > 0 } note)
            {
                _text.Color = (down ? SKColor.Parse("#FF9AAA") : Neon.TextDim).A(alpha);
                var lines = Wrap(note, _fSmall, inner, 2);
                float ny = spark.Bottom + 15;
                foreach (var line in lines) { c.DrawText(line, x0, ny, SKTextAlign.Left, _fSmall, _text); ny += 13; }
            }
        }

        private float Chip(SKCanvas c, float x, float y, string label, bool? ok, float alpha)
        {
            var col = ok switch { true => Neon.Green, false => Neon.Red, _ => Neon.TextDim };
            string text = ok switch { true => label + " ✓", false => label + " ✕", _ => label };
            // ✓/✕ may be missing from Inter: draw the mark manually instead
            float w = _fChip.MeasureText(label) + (ok is null ? 12 : 22);
            var rr = new SKRect(x, y, x + w, y + 15);
            _fill.Color = col.A(0.14f * alpha);
            c.DrawRoundRect(rr, 7.5f, 7.5f, _fill);
            _stroke.StrokeWidth = 1;
            _stroke.Color = col.A(0.55f * alpha);
            c.DrawRoundRect(rr, 7.5f, 7.5f, _stroke);
            _text.Color = col.A(alpha);
            c.DrawText(label, x + 6, y + 10.8f, SKTextAlign.Left, _fChip, _text);
            if (ok is not null)
            {
                float mx = rr.Right - 10, my = rr.MidY;
                _stroke.StrokeWidth = 1.6f;
                _stroke.Color = col.A(alpha);
                if (ok == true) { c.DrawLine(mx - 3, my, mx - 1, my + 2.5f, _stroke); c.DrawLine(mx - 1, my + 2.5f, mx + 3.2f, my - 2.6f, _stroke); }
                else { c.DrawLine(mx - 2.6f, my - 2.6f, mx + 2.6f, my + 2.6f, _stroke); c.DrawLine(mx + 2.6f, my - 2.6f, mx - 2.6f, my + 2.6f, _stroke); }
            }
            _ = text;
            return rr.Right + 5;
        }

        private void DrawSpark(SKCanvas c, SKRect r, double?[] vals, SKColor col, float alpha)
        {
            _fill.Color = SKColor.Parse("#080E1B");
            c.DrawRoundRect(r, 6, 6, _fill);
            int n = Math.Min(vals.Length, 60);
            if (n < 2) return;
            var v = vals.Skip(vals.Length - n).ToArray();
            double max = Math.Max(0.5, v.Where(x => x is not null).Select(x => x!.Value).DefaultIfEmpty(0).Max()) * 1.15;
            float X(int i) => r.Left + 3 + (r.Width - 6) * i / (n - 1);
            float Y(double x) => r.Bottom - 3 - (float)((r.Height - 6) * Math.Min(x, max) / max);
            _path.Reset();
            bool open = false;
            for (int i = 0; i < n; i++)
            {
                if (v[i] is not { } x) { open = false; continue; }
                if (!open) { _path.MoveTo(X(i), Y(x)); open = true; }
                else _path.LineTo(X(i), Y(x));
            }
            _stroke.StrokeWidth = 1.4f;
            _stroke.Color = col.A(0.9f * alpha);
            c.DrawPath(_path, _stroke);
            _fill.Color = Neon.Red.A(0.9f * alpha);
            for (int i = 0; i < n; i++) if (v[i] is null) c.DrawRect(X(i) - 1, r.Bottom - 8, 2, 6, _fill);
        }

        private static string Fit(string s, SKFont f, float max)
        {
            if (f.MeasureText(s) <= max) return s;
            for (int n = s.Length - 1; n > 1; n--)
            {
                var t = s[..n].TrimEnd() + "…";
                if (f.MeasureText(t) <= max) return t;
            }
            return "…";
        }

        private static List<string> Wrap(string s, SKFont f, float max, int maxLines)
        {
            var lines = new List<string>();
            var words = s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var cur = "";
            for (int i = 0; i < words.Length; i++)
            {
                var next = cur.Length == 0 ? words[i] : cur + " " + words[i];
                if (f.MeasureText(next) <= max) { cur = next; continue; }
                if (cur.Length > 0) lines.Add(cur);
                cur = words[i];
                if (lines.Count == maxLines - 1)
                {
                    lines.Add(Fit(string.Join(' ', words.Skip(i)), f, max));
                    return lines;
                }
            }
            if (cur.Length > 0) lines.Add(Fit(cur, f, max));
            return lines.Take(maxLines).ToList();
        }
    }
}
