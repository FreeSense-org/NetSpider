using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace NetSpider.App.Controls;

/// <summary>A thin rounded progress/meter bar (confidence, per-protocol share, client reachability).</summary>
public sealed class MeterBar : Control
{
    public static readonly StyledProperty<double> FractionProperty = AvaloniaProperty.Register<MeterBar, double>(nameof(Fraction));
    public static readonly StyledProperty<IBrush?> BarBrushProperty = AvaloniaProperty.Register<MeterBar, IBrush?>(nameof(BarBrush));

    public double Fraction { get => GetValue(FractionProperty); set => SetValue(FractionProperty, value); }
    public IBrush? BarBrush { get => GetValue(BarBrushProperty); set => SetValue(BarBrushProperty, value); }

    static MeterBar() => AffectsRender<MeterBar>(FractionProperty, BarBrushProperty);

    public MeterBar() { Height = 6; }

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        ctx.FillRectangle(new SolidColorBrush(Color.Parse("#16213A")), new Rect(0, 0, w, h), (float)(h / 2));
        double f = Math.Clamp(double.IsNaN(Fraction) ? 0 : Fraction, 0, 1);
        if (f <= 0) return;
        var brush = BarBrush ?? new SolidColorBrush(Color.Parse("#00E5FF"));
        double bw = Math.Max(h, w * f);
        if (brush is ISolidColorBrush sb)
            ctx.FillRectangle(new SolidColorBrush(sb.Color, 0.25), new Rect(0, -1, bw, h + 2), (float)(h / 2 + 1));
        ctx.FillRectangle(brush, new Rect(0, 0, bw, h), (float)(h / 2));
    }
}

/// <summary>
/// Semicircular packets-per-second meter on a log scale (10 → 10k pps) with the learned baseline drawn as a band and the
/// storm threshold as a red tick. Used by the Storm Center for broadcast / multicast / unknown-unicast.
/// </summary>
public sealed class RateGauge : Control
{
    public static readonly StyledProperty<double> ValueProperty = AvaloniaProperty.Register<RateGauge, double>(nameof(Value));
    public static readonly StyledProperty<double> BaselineProperty = AvaloniaProperty.Register<RateGauge, double>(nameof(Baseline));
    public static readonly StyledProperty<double> ThresholdProperty = AvaloniaProperty.Register<RateGauge, double>(nameof(Threshold), 500);
    public static readonly StyledProperty<string?> CaptionProperty = AvaloniaProperty.Register<RateGauge, string?>(nameof(Caption));
    public static readonly StyledProperty<Color> AccentProperty = AvaloniaProperty.Register<RateGauge, Color>(nameof(Accent), Color.Parse("#00E5FF"));

    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public double Baseline { get => GetValue(BaselineProperty); set => SetValue(BaselineProperty, value); }
    public double Threshold { get => GetValue(ThresholdProperty); set => SetValue(ThresholdProperty, value); }
    public string? Caption { get => GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }
    public Color Accent { get => GetValue(AccentProperty); set => SetValue(AccentProperty, value); }

    private double _shown = -1;
    private double _phase;
    private DispatcherTimer? _timer;
    private const double MaxPps = 20000;

    static RateGauge() => AffectsRender<RateGauge>(CaptionProperty, BaselineProperty, ThresholdProperty, AccentProperty);

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(16), DispatcherPriority.Render, (_, _) =>
        {
            double target = Scale(Value);
            if (_shown < 0) _shown = target;
            _shown += (target - _shown) * 0.12;
            _phase += 0.016;
            if (IsEffectivelyVisible) InvalidateVisual();
        });
        _timer.Start();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _timer?.Stop();
    }

    private static double Scale(double pps) => Math.Clamp(Math.Log10(1 + Math.Max(0, pps)) / Math.Log10(1 + MaxPps), 0, 1);

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        const double th = 14;
        double r = Math.Min(w / 2 - th - 6, h - th - 34);
        if (r < 20) return;
        var c = new Point(w / 2, th + 8 + r);

        Point At(double f, double rr)
        {
            double a = Math.PI + f * Math.PI;
            return new Point(c.X + rr * Math.Cos(a), c.Y + rr * Math.Sin(a));
        }
        Geometry Arc(double f0, double f1, double rr)
        {
            var g = new StreamGeometry();
            using var gc = g.Open();
            gc.BeginFigure(At(f0, rr), false);
            gc.ArcTo(At(f1, rr), new Size(rr, rr), 0, false, SweepDirection.Clockwise);
            gc.EndFigure(false);
            return g;
        }

        var red = Color.Parse("#FF3D5A");
        var amber = Color.Parse("#FFC23D");
        double thrF = Scale(Threshold);
        double v = Value;
        var col = v >= Threshold ? red : v >= Math.Max(Baseline * 3, Threshold * 0.4) ? amber : Accent;

        // track
        ctx.DrawGeometry(null, new Pen(new SolidColorBrush(Color.Parse("#16213A")), th, lineCap: PenLineCap.Round), Arc(0, 1, r));
        // baseline band (0.5× .. 1.6× baseline) just outside the track
        if (Baseline > 0)
        {
            double b0 = Scale(Baseline * 0.5), b1 = Scale(Baseline * 1.6);
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(ChartText.WithAlpha(Color.Parse("#3DFF8B"), 0.55)), 5, lineCap: PenLineCap.Flat), Arc(b0, b1, r + th / 2 + 6));
        }
        // scale labels
        foreach (var (pps, label) in new[] { (10.0, "10"), (100.0, "100"), (1000.0, "1k"), (10000.0, "10k") })
        {
            double f = Scale(pps);
            var p0 = At(f, r - th / 2 - 3);
            var p1 = At(f, r - th / 2 - 9);
            ctx.DrawLine(new Pen(new SolidColorBrush(Color.Parse("#2A3A5C")), 1.2), p0, p1);
            var t = ChartText.Make(label, 9.5, ChartText.Axis);
            var lp = At(f, r - th / 2 - 19);
            ctx.DrawText(t, new Point(lp.X - t.Width / 2, lp.Y - t.Height / 2));
        }
        // value arc
        double fv = Math.Clamp(_shown, 0, 1);
        if (fv > 0.003)
        {
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(ChartText.WithAlpha(col, 0.18)), th + 10, lineCap: PenLineCap.Flat), Arc(0, fv, r));
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(col), th, lineCap: PenLineCap.Round), Arc(0, fv, r));
            double pulse = 0.5 + 0.5 * Math.Sin(_phase * (v >= Threshold ? 9 : 3));
            var head = At(fv, r);
            ctx.DrawEllipse(new SolidColorBrush(ChartText.WithAlpha(col, 0.25 + 0.25 * pulse)), null, head, th * 0.95, th * 0.95);
            ctx.DrawEllipse(Brushes.White, null, head, th * 0.28, th * 0.28);
        }
        // threshold tick
        var t0 = At(thrF, r - th / 2 - 2);
        var t1 = At(thrF, r + th / 2 + 9);
        ctx.DrawLine(new Pen(new SolidColorBrush(red), 2.4, lineCap: PenLineCap.Round), t0, t1);

        // value text
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        string txt = v >= 10000 ? (v / 1000).ToString("0.#", inv) + "k" : v >= 1000 ? (v / 1000).ToString("0.0", inv) + "k" : v.ToString("0", inv);
        var vt = ChartText.Make(txt, Math.Max(16, r * 0.42), new SolidColorBrush(col), true);
        ctx.DrawText(vt, new Point(c.X - vt.Width / 2, c.Y - vt.Height + 2));
        var ut = ChartText.Make("pps", 11, ChartText.Dim);
        ctx.DrawText(ut, new Point(c.X - ut.Width / 2, c.Y + 2));
        if (Caption is { } cap)
        {
            var ct = ChartText.Make(cap, 12, ChartText.Text, true);
            ctx.DrawText(ct, new Point(c.X - ct.Width / 2, c.Y + 18));
        }
    }
}
