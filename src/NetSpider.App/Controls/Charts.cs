using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;
using NetSpider.Core.Model;

namespace NetSpider.App.Controls;

internal static class ChartText
{
    public static readonly Typeface Regular = new(new FontFamily("fonts:Inter#Inter, Segoe UI"));
    public static readonly Typeface Bold = new(new FontFamily("fonts:Inter#Inter, Segoe UI"), FontStyle.Normal, FontWeight.SemiBold);

    public static FormattedText Make(string s, double size, IBrush brush, bool bold = false) =>
        new(s, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, bold ? Bold : Regular, size, brush);

    public static readonly IBrush Grid = new SolidColorBrush(Color.Parse("#16213A"));
    public static readonly IBrush Axis = new SolidColorBrush(Color.Parse("#56657F"));
    public static readonly IBrush Text = new SolidColorBrush(Color.Parse("#E8F1FF"));
    public static readonly IBrush Dim = new SolidColorBrush(Color.Parse("#8A9BB8"));

    public static Color WithAlpha(Color c, double a) => Color.FromArgb((byte)Math.Clamp(a * 255, 0, 255), c.R, c.G, c.B);
}

// =========================================================================================================
//  Sparkline: L2 (ARP/NDP) vs L3 (ICMP) latency for the inspector
// =========================================================================================================

public sealed class Sparkline : Control
{
    public static readonly StyledProperty<IReadOnlyList<double?>?> L2Property = AvaloniaProperty.Register<Sparkline, IReadOnlyList<double?>?>(nameof(L2));
    public static readonly StyledProperty<IReadOnlyList<double?>?> L3Property = AvaloniaProperty.Register<Sparkline, IReadOnlyList<double?>?>(nameof(L3));

    public IReadOnlyList<double?>? L2 { get => GetValue(L2Property); set => SetValue(L2Property, value); }
    public IReadOnlyList<double?>? L3 { get => GetValue(L3Property); set => SetValue(L3Property, value); }

    static Sparkline() => AffectsRender<Sparkline>(L2Property, L3Property);

    private static readonly Color L2Color = Color.Parse("#00E5FF");
    private static readonly Color L3Color = Color.Parse("#FF2BD6");

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        if (w < 10 || h < 10) return;
        ctx.FillRectangle(new SolidColorBrush(Color.Parse("#0A1020")), new Rect(0, 0, w, h), 8);
        var l2 = L2 ?? [];
        var l3 = L3 ?? [];
        double max = 0.5;
        foreach (var v in l2) if (v is { } x) max = Math.Max(max, x);
        foreach (var v in l3) if (v is { } x) max = Math.Max(max, x);
        max *= 1.18;
        const double padT = 18, padB = 6, padL = 6, padR = 6;
        double ph = h - padT - padB, pw = w - padL - padR;

        var gridPen = new Pen(ChartText.Grid, 1);
        for (int i = 1; i <= 3; i++) ctx.DrawLine(gridPen, new Point(padL, padT + ph * i / 4), new Point(w - padR, padT + ph * i / 4));
        ctx.DrawText(ChartText.Make($"{max:0.##} ms", 9.5, ChartText.Dim), new Point(padL + 2, 2));

        void Series(IReadOnlyList<double?> s, Color col, bool fill)
        {
            int n = s.Count;
            if (n < 2) return;
            double X(int i) => padL + pw * i / (n - 1);
            double Y(double v) => padT + ph - ph * Math.Min(v, max) / max;
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                bool open = false;
                for (int i = 0; i < n; i++)
                {
                    if (s[i] is not { } v) { if (open) { g.EndFigure(false); open = false; } continue; }
                    if (!open) { g.BeginFigure(new Point(X(i), Y(v)), false); open = true; }
                    else g.LineTo(new Point(X(i), Y(v)));
                }
                if (open) g.EndFigure(false);
            }
            if (fill)
            {
                var area = new StreamGeometry();
                using (var g = area.Open())
                {
                    int first = -1, last = -1;
                    for (int i = 0; i < n; i++)
                    {
                        if (s[i] is not { } v) continue;
                        if (first < 0) { first = i; g.BeginFigure(new Point(X(i), padT + ph), true); }
                        g.LineTo(new Point(X(i), Y(v)));
                        last = i;
                    }
                    if (first >= 0) { g.LineTo(new Point(X(last), padT + ph)); g.EndFigure(true); }
                }
                var grad = new LinearGradientBrush
                {
                    StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                    GradientStops = { new GradientStop(ChartText.WithAlpha(col, 0.35), 0), new GradientStop(ChartText.WithAlpha(col, 0.0), 1) },
                };
                ctx.DrawGeometry(grad, null, area);
            }
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(ChartText.WithAlpha(col, 0.25)), 5, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round), geo);
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(col), 1.6, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round), geo);
            // lost probes as red ticks
            var red = new Pen(new SolidColorBrush(Color.Parse("#FF3D5A")), 2);
            for (int i = 0; i < n; i++) if (s[i] is null) ctx.DrawLine(red, new Point(X(i), padT + ph - 5), new Point(X(i), padT + ph));
        }

        Series(l3, L3Color, false);
        Series(l2, L2Color, true);

        // legend
        double lx = w - 120;
        ctx.FillRectangle(new SolidColorBrush(L2Color), new Rect(lx, 6, 10, 3), 1.5f);
        ctx.DrawText(ChartText.Make("L2 ARP/NDP", 9.5, ChartText.Dim), new Point(lx + 14, 1));
        ctx.FillRectangle(new SolidColorBrush(L3Color), new Rect(lx + 72, 6, 10, 3), 1.5f);
        ctx.DrawText(ChartText.Make("L3", 9.5, ChartText.Dim), new Point(lx + 86, 1));
    }
}

// =========================================================================================================
//  Time-series chart (traffic): stacked areas or lines over the last N seconds, with hover readout
// =========================================================================================================

public sealed record ChartSeries(string Name, Color Color, double[] Values, bool Fill = true);

public sealed class TimeSeriesChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<ChartSeries>?> SeriesProperty = AvaloniaProperty.Register<TimeSeriesChart, IReadOnlyList<ChartSeries>?>(nameof(Series));
    public static readonly StyledProperty<bool> StackedProperty = AvaloniaProperty.Register<TimeSeriesChart, bool>(nameof(Stacked));
    public static readonly StyledProperty<string> UnitProperty = AvaloniaProperty.Register<TimeSeriesChart, string>(nameof(Unit), "pps");
    public static readonly StyledProperty<int> SecondsProperty = AvaloniaProperty.Register<TimeSeriesChart, int>(nameof(Seconds), 120);

    public IReadOnlyList<ChartSeries>? Series { get => GetValue(SeriesProperty); set => SetValue(SeriesProperty, value); }
    public bool Stacked { get => GetValue(StackedProperty); set => SetValue(StackedProperty, value); }
    public string Unit { get => GetValue(UnitProperty); set => SetValue(UnitProperty, value); }
    public int Seconds { get => GetValue(SecondsProperty); set => SetValue(SecondsProperty, value); }
    /// <summary>Lower edge of the value axis (NaN = 0). Set it for negative data such as RSSI in dBm.</summary>
    public static readonly StyledProperty<double> FloorProperty = AvaloniaProperty.Register<TimeSeriesChart, double>(nameof(Floor), double.NaN);
    public double Floor { get => GetValue(FloorProperty); set => SetValue(FloorProperty, value); }

    private Point? _mouse;

    static TimeSeriesChart() => AffectsRender<TimeSeriesChart>(SeriesProperty, StackedProperty);

    protected override void OnPointerMoved(PointerEventArgs e) { base.OnPointerMoved(e); _mouse = e.GetPosition(this); InvalidateVisual(); }
    protected override void OnPointerExited(PointerEventArgs e) { base.OnPointerExited(e); _mouse = null; InvalidateVisual(); }

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        ctx.FillRectangle(Brushes.Transparent, new Rect(0, 0, w, h));
        var series = Series ?? [];
        const double padL = 48, padR = 12, padT = 26, padB = 22;
        double pw = w - padL - padR, ph = h - padT - padB;
        if (pw < 20 || ph < 20) return;
        // window grows with the available history (30 s minimum) instead of squeezing data to the right edge
        int avail = series.Count == 0 ? 0 : series.Max(x => x.Values.Length);
        int n = Math.Clamp(avail, 30, Seconds);

        // cumulative values for stacking
        var bottoms = new double[series.Count][];
        var tops = new double[series.Count][];
        var acc = new double[n];
        // Non-stacked charts support gaps: NaN in the data is a lost sample (marked red), missing history is blank.
        var lost = new bool[series.Count][];
        for (int s = 0; s < series.Count; s++)
        {
            bottoms[s] = new double[n];
            tops[s] = new double[n];
            lost[s] = new bool[n];
            var vals = series[s].Values;
            for (int i = 0; i < n; i++)
            {
                int vi = vals.Length - n + i;
                bool inData = vi >= 0 && vi < vals.Length;
                double v = inData ? vals[vi] : double.NaN;
                lost[s][i] = inData && double.IsNaN(v);
                if (Stacked && double.IsNaN(v)) v = 0;
                bottoms[s][i] = Stacked ? acc[i] : 0;
                tops[s][i] = bottoms[s][i] + v;
                if (Stacked) acc[i] = tops[s][i];
            }
        }
        double floor = double.IsNaN(Floor) ? 0 : Floor;
        double max;
        if (double.IsNaN(Floor))
        {
            max = 1;
            foreach (var t in tops) foreach (var v in t) if (!double.IsNaN(v)) max = Math.Max(max, v);
            max = NiceMax(max * 1.1);
        }
        else
        {
            max = floor + 10;
            foreach (var t in tops) foreach (var v in t) if (!double.IsNaN(v)) max = Math.Max(max, v);
            max = floor + Math.Ceiling((max - floor + 3) / 20) * 20;
        }

        double X(int i) => padL + pw * i / (n - 1);
        double Y(double v) => padT + ph - ph * Math.Clamp((v - floor) / (max - floor), 0, 1);

        var gridPen = new Pen(ChartText.Grid, 1);
        for (int i = 0; i <= 4; i++)
        {
            double y = padT + ph * i / 4;
            ctx.DrawLine(gridPen, new Point(padL, y), new Point(w - padR, y));
            var label = ChartText.Make(Format(floor + (max - floor) * (4 - i) / 4), 10, ChartText.Axis);
            ctx.DrawText(label, new Point(padL - 6 - label.Width, y - label.Height / 2));
        }
        for (int sec = 0; sec <= n; sec += n > 60 ? 30 : 10)
        {
            double x = padL + pw * (1 - sec / (double)(n - 1));
            if (x < padL - 1) continue;
            var t = ChartText.Make(sec == 0 ? "now" : $"-{sec}s", 10, ChartText.Axis);
            ctx.DrawText(t, new Point(x - t.Width / 2, h - padB + 5));
        }

        for (int s = series.Count - 1; s >= 0; s--)
        {
            var col = series[s].Color;
            // contiguous runs of real values (NaN = gap)
            var runs = new List<(int From, int To)>();
            for (int i = 0; i < n; i++)
            {
                if (double.IsNaN(tops[s][i])) continue;
                int j = i;
                while (j + 1 < n && !double.IsNaN(tops[s][j + 1])) j++;
                runs.Add((i, j));
                i = j;
            }
            var line = new StreamGeometry();
            using (var g = line.Open())
            {
                foreach (var (from, to) in runs)
                {
                    g.BeginFigure(new Point(X(from), Y(tops[s][from])), false);
                    if (from == to) g.LineTo(new Point(X(from) + 1.5, Y(tops[s][from])));
                    for (int i = from + 1; i <= to; i++) g.LineTo(new Point(X(i), Y(tops[s][i])));
                    g.EndFigure(false);
                }
            }
            // lost samples: red ticks on the baseline
            var lossBrush = new SolidColorBrush(Color.Parse("#FF3D5A"));
            for (int i = 0; i < n; i++)
                if (lost[s][i]) ctx.FillRectangle(lossBrush, new Rect(X(i) - 1.5, padT + ph - 10, 3, 10), 1);
            if (series[s].Fill)
            {
                var area = new StreamGeometry();
                using (var g = area.Open())
                {
                    foreach (var (from, to) in runs)
                    {
                        g.BeginFigure(new Point(X(from), Y(tops[s][from])), true);
                        for (int i = from + 1; i <= to; i++) g.LineTo(new Point(X(i), Y(tops[s][i])));
                        for (int i = to; i >= from; i--) g.LineTo(new Point(X(i), Y(bottoms[s][i])));
                        g.EndFigure(true);
                    }
                }
                var grad = new LinearGradientBrush
                {
                    StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                    GradientStops = { new GradientStop(ChartText.WithAlpha(col, 0.42), 0), new GradientStop(ChartText.WithAlpha(col, 0.08), 1) },
                };
                ctx.DrawGeometry(grad, null, area);
            }
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(ChartText.WithAlpha(col, 0.22)), 5, lineJoin: PenLineJoin.Round), line);
            ctx.DrawGeometry(null, new Pen(new SolidColorBrush(col), 1.6, lineJoin: PenLineJoin.Round), line);
        }

        // legend
        double lx = padL;
        foreach (var s in series)
        {
            ctx.FillRectangle(new SolidColorBrush(s.Color), new Rect(lx, 8, 10, 10), 3);
            var t = ChartText.Make(s.Name, 11, ChartText.Dim);
            ctx.DrawText(t, new Point(lx + 14, 5));
            lx += t.Width + 30;
        }

        // hover readout
        if (_mouse is { } m && m.X >= padL && m.X <= w - padR && series.Count > 0)
        {
            int i = (int)Math.Round((m.X - padL) / pw * (n - 1));
            i = Math.Clamp(i, 0, n - 1);
            double x = X(i);
            ctx.DrawLine(new Pen(new SolidColorBrush(Color.Parse("#5500E5FF")), 1), new Point(x, padT), new Point(x, padT + ph));
            var lines = series.Select((s, k) => (s, v: tops[k][i] - bottoms[k][i], lost: lost[k][i])).ToList();
            double bw = 150, bh = 22 + lines.Count * 16;
            double bx = x + 12 + bw > w ? x - bw - 12 : x + 12;
            ctx.FillRectangle(new SolidColorBrush(Color.Parse("#EE0D1526")), new Rect(bx, padT, bw, bh), 8);
            ctx.DrawText(ChartText.Make(i == n - 1 ? "now" : $"-{n - 1 - i}s", 10.5, ChartText.Dim), new Point(bx + 10, padT + 4));
            double y = padT + 20;
            foreach (var (s, v, isLost) in lines)
            {
                ctx.FillRectangle(new SolidColorBrush(s.Color), new Rect(bx + 10, y + 4, 8, 8), 2);
                string val = isLost ? "lost" : double.IsNaN(v) ? "—" : $"{Format(v)} {Unit}";
                ctx.DrawText(ChartText.Make($"{s.Name}: {val}", 11, ChartText.Text), new Point(bx + 24, y));
                y += 16;
            }
        }
    }

    private static string Format(double v)
    {
        var inv = CultureInfo.InvariantCulture;
        return v >= 10000 ? (v / 1000).ToString("0", inv) + "k" : v >= 1000 ? (v / 1000).ToString("0.#", inv) + "k" : v >= 100 || v % 1 == 0 ? v.ToString("0", inv) : v.ToString("0.#", inv);
    }

    private static double NiceMax(double v)
    {
        double p = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10 }) if (m * p >= v) return m * p;
        return 10 * p;
    }
}

// =========================================================================================================
//  Animated arc gauge (broadcast %, health score)
// =========================================================================================================

public sealed class Gauge : Control
{
    public static readonly StyledProperty<double> ValueProperty = AvaloniaProperty.Register<Gauge, double>(nameof(Value));
    public static readonly StyledProperty<double> MaximumProperty = AvaloniaProperty.Register<Gauge, double>(nameof(Maximum), 100);
    public static readonly StyledProperty<string?> TextProperty = AvaloniaProperty.Register<Gauge, string?>(nameof(Text));
    public static readonly StyledProperty<string?> CaptionProperty = AvaloniaProperty.Register<Gauge, string?>(nameof(Caption));
    /// <summary>true: high values are good (health score); false: high values are bad (broadcast %).</summary>
    public static readonly StyledProperty<bool> HighIsGoodProperty = AvaloniaProperty.Register<Gauge, bool>(nameof(HighIsGood));
    public static readonly StyledProperty<double> ThicknessProperty = AvaloniaProperty.Register<Gauge, double>(nameof(Thickness), 14);

    public double Value { get => GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public double Maximum { get => GetValue(MaximumProperty); set => SetValue(MaximumProperty, value); }
    public string? Text { get => GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public string? Caption { get => GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }
    public bool HighIsGood { get => GetValue(HighIsGoodProperty); set => SetValue(HighIsGoodProperty, value); }
    public double Thickness { get => GetValue(ThicknessProperty); set => SetValue(ThicknessProperty, value); }

    private double _shown;
    private double _phase;
    private DispatcherTimer? _timer;

    static Gauge() => AffectsRender<Gauge>(TextProperty, CaptionProperty);

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(16), DispatcherPriority.Render, (_, _) =>
        {
            double target = Math.Clamp(Value / Math.Max(0.0001, Maximum), 0, 1);
            _phase += 0.016;
            bool moving = Math.Abs(target - _shown) > 0.0005;
            _shown += (target - _shown) * 0.08;
            if (moving || IsEffectivelyVisible) InvalidateVisual();
        });
        _timer.Start();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _timer?.Stop();
    }

    private Color ColorAt(double f)
    {
        var good = Color.Parse("#3DFF8B");
        var mid = Color.Parse("#FFC23D");
        var bad = Color.Parse("#FF3D5A");
        double q = HighIsGood ? 1 - f : f;
        return q < 0.5 ? Mix(good, mid, q * 2) : Mix(mid, bad, (q - 0.5) * 2);
    }

    private static Color Mix(Color a, Color b, double t) =>
        Color.FromRgb((byte)(a.R + (b.R - a.R) * t), (byte)(a.G + (b.G - a.G) * t), (byte)(a.B + (b.B - a.B) * t));

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        double size = Math.Min(w, h * 1.25);
        double th = Thickness;
        double r = size / 2 - th - 4;
        var c = new Point(w / 2, Math.Min(h / 2 + r * 0.18, h - th));
        const double start = 135, sweep = 270;

        Geometry Arc(double from, double deg)
        {
            var g = new StreamGeometry();
            using var gc = g.Open();
            double a0 = from * Math.PI / 180, a1 = (from + deg) * Math.PI / 180;
            gc.BeginFigure(new Point(c.X + r * Math.Cos(a0), c.Y + r * Math.Sin(a0)), false);
            gc.ArcTo(new Point(c.X + r * Math.Cos(a1), c.Y + r * Math.Sin(a1)), new Size(r, r), 0, deg > 180, SweepDirection.Clockwise);
            gc.EndFigure(false);
            return g;
        }

        ctx.DrawGeometry(null, new Pen(new SolidColorBrush(Color.Parse("#16213A")), th, lineCap: PenLineCap.Round), Arc(start, sweep));
        // ticks
        var tick = new Pen(new SolidColorBrush(Color.Parse("#2A3A5C")), 1.2);
        for (int i = 0; i <= 10; i++)
        {
            double a = (start + sweep * i / 10) * Math.PI / 180;
            double r0 = r - th / 2 - 6, r1 = r - th / 2 - (i % 5 == 0 ? 14 : 10);
            ctx.DrawLine(tick, new Point(c.X + r0 * Math.Cos(a), c.Y + r0 * Math.Sin(a)), new Point(c.X + r1 * Math.Cos(a), c.Y + r1 * Math.Sin(a)));
        }
        double f = Math.Clamp(_shown, 0, 1);
        if (f > 0.002)
        {
            // segmented gradient arc
            int segs = Math.Max(1, (int)(f * 60));
            for (int i = 0; i < segs; i++)
            {
                double a = sweep * f * i / segs, d = sweep * f / segs + 0.6;
                var col = ColorAt(f * (i + 0.5) / segs);
                ctx.DrawGeometry(null, new Pen(new SolidColorBrush(ChartText.WithAlpha(col, 0.18)), th + 10, lineCap: PenLineCap.Flat), Arc(start + a, d));
                ctx.DrawGeometry(null, new Pen(new SolidColorBrush(col), th, lineCap: i == 0 || i == segs - 1 ? PenLineCap.Round : PenLineCap.Flat), Arc(start + a, d));
            }
            // glowing head dot that breathes
            double ha = (start + sweep * f) * Math.PI / 180;
            var head = new Point(c.X + r * Math.Cos(ha), c.Y + r * Math.Sin(ha));
            double pulse = 0.5 + 0.5 * Math.Sin(_phase * 3);
            ctx.DrawEllipse(new SolidColorBrush(ChartText.WithAlpha(ColorAt(f), 0.25 + 0.2 * pulse)), null, head, th * 0.95, th * 0.95);
            ctx.DrawEllipse(Brushes.White, null, head, th * 0.28, th * 0.28);
        }
        var text = ChartText.Make(Text ?? $"{Value:0}", Math.Max(14, r * 0.52), new SolidColorBrush(ColorAt(f)), true);
        ctx.DrawText(text, new Point(c.X - text.Width / 2, c.Y - text.Height / 2 - r * 0.06));
        if (Caption is { } cap)
        {
            var ct = ChartText.Make(cap, Math.Max(10, r * 0.14), ChartText.Dim);
            ctx.DrawText(ct, new Point(c.X - ct.Width / 2, c.Y + text.Height / 2 - r * 0.02));
        }
    }
}

// =========================================================================================================
//  Wi-Fi channel congestion (analyzer-style bell curves per AP)
// =========================================================================================================

public sealed class ChannelChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<WifiNetwork>?> NetworksProperty = AvaloniaProperty.Register<ChannelChart, IReadOnlyList<WifiNetwork>?>(nameof(Networks));
    public static readonly StyledProperty<string> BandProperty = AvaloniaProperty.Register<ChannelChart, string>(nameof(Band), "2.4 GHz");

    public IReadOnlyList<WifiNetwork>? Networks { get => GetValue(NetworksProperty); set => SetValue(NetworksProperty, value); }
    public string Band { get => GetValue(BandProperty); set => SetValue(BandProperty, value); }

    static ChannelChart() => AffectsRender<ChannelChart>(NetworksProperty, BandProperty);

    private static readonly Color[] Palette =
        new[] { "#00E5FF", "#FF2BD6", "#3DFF8B", "#FFC23D", "#9B7BFF", "#FF8A3D", "#4DD8FF", "#FF7AB8", "#E9F542", "#7DFFB9", "#3D8BFF", "#FF3D5A" }
            .Select(Color.Parse).ToArray();

    public static Color ColorFor(string ssid) => Palette[(int)((uint)StableHash(ssid) % (uint)Palette.Length)];

    private static int StableHash(string s) { unchecked { int h = 23; foreach (var ch in s) h = h * 31 + ch; return h; } }

    private (double MinMhz, double MaxMhz, int[] Channels, Func<int, double> Freq) Axis() => Band switch
    {
        "5 GHz" => (5160, 5900, [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165], ch => 5000 + 5 * ch),
        "6 GHz" => (5935, 7125, [1, 33, 65, 97, 129, 161, 193, 225], ch => 5950 + 5 * ch),
        _ => (2392, 2494, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], ch => ch == 14 ? 2484 : 2407 + 5 * ch),
    };

    public override void Render(DrawingContext ctx)
    {
        double w = Bounds.Width, h = Bounds.Height;
        ctx.FillRectangle(new SolidColorBrush(Color.Parse("#0A1020")), new Rect(0, 0, w, h), 10);
        const double padL = 44, padR = 14, padT = 30, padB = 24;
        double pw = w - padL - padR, ph = h - padT - padB;
        if (pw < 40 || ph < 30) return;
        var (minF, maxF, chans, freq) = Axis();
        double X(double mhz) => padL + pw * (mhz - minF) / (maxF - minF);
        double Y(double dbm) => padT + ph - ph * Math.Clamp((dbm + 100) / 75.0, 0, 1);

        var grid = new Pen(ChartText.Grid, 1);
        foreach (var dbm in new[] { -90, -80, -70, -60, -50, -40, -30 })
        {
            ctx.DrawLine(grid, new Point(padL, Y(dbm)), new Point(w - padR, Y(dbm)));
            var t = ChartText.Make($"{dbm}", 10, ChartText.Axis);
            ctx.DrawText(t, new Point(padL - 6 - t.Width, Y(dbm) - t.Height / 2));
        }
        foreach (var ch in chans)
        {
            double x = X(freq(ch));
            var t = ChartText.Make(ch.ToString(), 10, ChartText.Axis);
            ctx.DrawText(t, new Point(x - t.Width / 2, h - padB + 5));
        }
        ctx.DrawText(ChartText.Make($"{Band} · dBm by channel", 11.5, ChartText.Dim, true), new Point(padL, 7));

        var nets = (Networks ?? []).Where(n => n.Band == Band).OrderBy(n => n.RssiDbm).ToList();
        if (nets.Count == 0)
        {
            var t = ChartText.Make("No networks in this band", 12, ChartText.Axis);
            ctx.DrawText(t, new Point(w / 2 - t.Width / 2, h / 2 - t.Height / 2));
            return;
        }
        var labels = new List<Rect>();
        foreach (var n in nets)
        {
            double center = n.FrequencyMhz > 0 ? n.FrequencyMhz : freq(n.Channel);
            double halfW = (n.ChannelWidthMhz ?? 20) / 2.0;
            var col = ColorFor(n.Ssid);
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                // flat-topped bell: rises over 4 MHz shoulders like an analyzer trace
                double l = center - halfW - 2, r = center + halfW + 2;
                g.BeginFigure(new Point(X(l), Y(-100)), true);
                for (int i = 0; i <= 40; i++)
                {
                    double t = i / 40.0;
                    double mhz = l + (r - l) * t;
                    double shape = Math.Pow(Math.Sin(Math.PI * t), 0.55);
                    double dbm = -100 + (n.RssiDbm + 100) * shape;
                    g.LineTo(new Point(X(mhz), Y(dbm)));
                }
                g.EndFigure(true);
            }
            var fill = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(ChartText.WithAlpha(col, n.Connected ? 0.38 : 0.22), 0), new GradientStop(ChartText.WithAlpha(col, 0.02), 1) },
            };
            ctx.DrawGeometry(fill, new Pen(new SolidColorBrush(col), n.Connected ? 2.6 : 1.4), geo);
            var name = string.IsNullOrEmpty(n.Ssid) ? "(hidden)" : n.Ssid;
            var label = ChartText.Make(n.Connected ? $"★ {name}" : name, 10.5, new SolidColorBrush(col), n.Connected);
            var rect = new Rect(X(center) - label.Width / 2, Y(n.RssiDbm) - label.Height - 2, label.Width, label.Height);
            int guard = 0;
            while (labels.Any(o => o.Intersects(rect)) && guard++ < 8) rect = rect.Translate(new Vector(0, -label.Height));
            labels.Add(rect);
            ctx.DrawText(label, rect.TopLeft);
        }
    }
}

/// <summary>Four-bar RSSI indicator.</summary>
public sealed class SignalBars : Control
{
    public static readonly StyledProperty<int> RssiProperty = AvaloniaProperty.Register<SignalBars, int>(nameof(Rssi), -100);
    public int Rssi { get => GetValue(RssiProperty); set => SetValue(RssiProperty, value); }
    static SignalBars() => AffectsRender<SignalBars>(RssiProperty);

    public override void Render(DrawingContext ctx)
    {
        int level = Rssi >= -55 ? 4 : Rssi >= -65 ? 3 : Rssi >= -75 ? 2 : Rssi >= -85 ? 1 : 0;
        var on = new SolidColorBrush(level >= 3 ? Color.Parse("#3DFF8B") : level == 2 ? Color.Parse("#FFC23D") : Color.Parse("#FF3D5A"));
        var off = new SolidColorBrush(Color.Parse("#1E2B47"));
        double w = Bounds.Width, h = Bounds.Height, bw = (w - 6) / 4;
        for (int i = 0; i < 4; i++)
        {
            double bh = h * (i + 1) / 4;
            ctx.FillRectangle(i < level ? on : off, new Rect(i * (bw + 2), h - bh, bw, bh), 1.5f);
        }
    }
}
