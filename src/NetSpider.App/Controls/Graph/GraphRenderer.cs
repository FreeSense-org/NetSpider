using System.Collections.Concurrent;
using NetSpider.App.Rendering;
using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Controls.Graph;

/// <summary>
/// Draws the spider web / tree / port matrix with SkiaSharp. Owned by the render thread: it keeps its own animated
/// display positions and short-lived effects, and only reads the immutable snapshot + layout frame.
/// </summary>
public sealed partial class GraphRenderer : IDisposable
{
    private readonly Dictionary<Mac, SKPoint> _display = new();
    private readonly List<Ripple> _ripples = [];
    private readonly List<Spark> _sparks = [];
    private readonly Dictionary<Mac, double> _flash = new();
    private double _lastTime = -1;
    private double _vibrateStart = -100;
    private float _webBlend = 1f;   // 1 = spider web decorations visible, 0 = tree
    private float _portBlend;       // 1 = port matrix
    private volatile float _treeBlend; // 1 = tree (edges become vertical S-curves)
    public float TreeBlend => _treeBlend;
    private GraphSnapshot? _lastSnap;
    /// <summary>Incident/port overlay for the frame being rendered.</summary>
    private GraphDiagnostics _diag = GraphDiagnostics.Empty;
    private static readonly float[] DashFault = [9f, 6f];

    private volatile RenderedFrame _output = RenderedFrame.Empty;
    public RenderedFrame Output => _output;

    private readonly record struct Ripple(Mac Mac, double Start, double Duration, SKColor Color, float MaxR, float Width);
    private readonly record struct Spark(Mac Mac, double Start, SKColor Color, string Text, float Dx);

    // ---- reusable paints/fonts (render thread only) ----
    private readonly SKPaint _fill = new() { IsAntialias = true, Style = SKPaintStyle.Fill };
    private readonly SKPaint _stroke = new() { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeCap = SKStrokeCap.Round };
    private readonly SKPaint _text = new() { IsAntialias = true };
    private readonly SKFont _fName = new(Fonts.SemiBold, 12.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
    private readonly SKFont _fSmall = new(Fonts.Regular, 10.5f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
    private readonly SKFont _fSmallBold = new(Fonts.SemiBold, 10.5f) { Subpixel = true };
    private readonly SKFont _fMono = new(Fonts.Mono, 10f) { Subpixel = true, Edging = SKFontEdging.SubpixelAntialias };
    private readonly SKFont _fTiny = new(Fonts.Bold, 8f) { Subpixel = true };
    private readonly SKFont _fThread = new(Fonts.Medium, 9.5f) { Subpixel = true };
    private readonly SKFont _fTitle = new(Fonts.Bold, 15f) { Subpixel = true };
    private readonly SKPath _path = new();
    private readonly SKMaskFilter _blur4 = SKMaskFilter.CreateBlur(SKBlurStyle.Normal, 4);
    private readonly SKMaskFilter _blur10 = SKMaskFilter.CreateBlur(SKBlurStyle.Normal, 10);
    private static readonly float[] DashEstimated = [7f, 6f];
    private static readonly float[] DashWifi = [0.1f, 6f];
    private static readonly float[] DashThread = [3f, 4f];
    private static readonly float[] DashHalo = [5f, 5f];
    private static readonly float[] ThreadLabelStops = [0.5f, 0.42f, 0.58f, 0.34f, 0.66f, 0.26f, 0.74f, 0.2f, 0.8f];

    public void Dispose()
    {
        _fill.Dispose(); _stroke.Dispose(); _text.Dispose(); _path.Dispose();
        _fName.Dispose(); _fSmall.Dispose(); _fSmallBold.Dispose(); _fMono.Dispose(); _fTiny.Dispose(); _fThread.Dispose(); _fTitle.Dispose();
        _blur4.Dispose(); _blur10.Dispose();
    }

    /// <summary>Renders one frame. <paramref name="time"/> is seconds since an arbitrary epoch.</summary>
    public void Render(SKCanvas c, GraphViewState v, LayoutFrame frame, ConcurrentQueue<GraphEvent>? events, double time, GraphDiagnostics? diagnostics = null)
    {
        _diag = diagnostics ?? GraphDiagnostics.Empty;
        var snap = frame.Snapshot;
        float dt = _lastTime < 0 || v.Instant ? 1f : (float)Math.Clamp(time - _lastTime, 0, 0.1);
        _lastTime = time;
        if (!v.Animations) time = 0;

        DrainEvents(events, snap, time);
        UpdateBlends(v, dt);
        var (dx, dy) = UpdatePositions(snap, frame, v, dt);
        _lastSnap = snap;

        DrawBackground(c, v, time);

        var portHits = new List<(SKRect, SwitchPanel, PortCell)>();
        if (_portBlend < 0.999f)
        {
            bool layer = _portBlend > 0.001f;
            using var lp1 = new SKPaint { Color = SKColors.White.A(1 - _portBlend) };
            if (layer) c.SaveLayer(lp1);
            c.Save();
            c.Translate(v.Width / 2 + v.PanX, v.Height / 2 + v.PanY);
            c.Scale(v.Zoom);
            if (_webBlend > 0.01f) DrawWeb(c, snap, dx, dy, v, time);
            DrawEdges(c, snap, dx, dy, v, time);
            if (v.Selected is { } sel && snap.Index.TryGetValue(sel, out var si) && v.Mode != GraphViewMode.Ports) DrawLatencyThreads(c, snap, dx, dy, v, si, time, labels: false);
            DrawEffectsBelow(c, snap, dx, dy, time);
            DrawNodes(c, snap, dx, dy, v, time);
            if (v.Selected is { } sel2 && snap.Index.TryGetValue(sel2, out var si2) && v.Mode != GraphViewMode.Ports) DrawLatencyThreads(c, snap, dx, dy, v, si2, time, labels: true);
            DrawEffectsAbove(c, snap, dx, dy, time);
            c.Restore();
            if (layer) c.Restore();
        }
        if (_portBlend > 0.001f)
        {
            bool layer = _portBlend < 0.999f;
            using var lp2 = new SKPaint { Color = SKColors.White.A(_portBlend) };
            if (layer) c.SaveLayer(lp2);
            c.Save();
            c.Translate(v.Width / 2 + v.PanX, v.Height / 2 + v.PanY);
            c.Scale(v.Zoom);
            DrawPortMatrix(c, snap, v, time, portHits);
            c.Restore();
            if (layer) c.Restore();
        }

        if (v.ShowLegend && v.Mode != GraphViewMode.Ports) DrawLegend(c, v);
        DrawTooltips(c, snap, dx, dy, v, portHits);

        _output = new RenderedFrame { Snapshot = snap, X = dx, Y = dy, Mode = v.Mode, PortHits = portHits };
    }

    // =====================================================================================================
    //  state updates
    // =====================================================================================================

    private void DrainEvents(ConcurrentQueue<GraphEvent>? events, GraphSnapshot snap, double time)
    {
        if (events is null) return;
        int budget = 300;
        while (budget-- > 0 && events.TryDequeue(out var e))
        {
            switch (e.Kind)
            {
                case GraphEventKind.Packet:
                    if (_ripples.Count > 400) continue;
                    var col = Neon.Protocol(e.Protocol ?? "");
                    _ripples.Add(new Ripple(e.Mac, time, 0.9, col, 26, 1.4f));
                    if (_sparks.Count < 160)
                        _sparks.Add(new Spark(e.Mac, time, col, Neon.ProtocolInitials(e.Protocol ?? "?"), ((e.Mac.GetHashCode() ^ (int)(time * 1000)) % 40 - 20) * 0.5f));
                    break;
                case GraphEventKind.NewDevice:
                    _ripples.Add(new Ripple(e.Mac, time, 2.2, Neon.Green, 140, 3f));
                    _ripples.Add(new Ripple(e.Mac, time + 0.3, 2.0, Neon.Cyan, 100, 2f));
                    _vibrateStart = time;
                    break;
                case GraphEventKind.Alert:
                    if (e.Severity >= AlertSeverity.Warning)
                    {
                        _flash[e.Mac] = time;
                        _ripples.Add(new Ripple(e.Mac, time, 1.6, Neon.Red, 110, 3f));
                        _ripples.Add(new Ripple(e.Mac, time + 0.35, 1.6, Neon.Red, 80, 2f));
                    }
                    else _ripples.Add(new Ripple(e.Mac, time, 1.2, Neon.Cyan, 60, 2f));
                    break;
            }
        }
        _ripples.RemoveAll(r => time - r.Start > r.Duration);
        _sparks.RemoveAll(s => time - s.Start > 1.3);
        foreach (var k in _flash.Where(kv => time - kv.Value > 2.5).Select(kv => kv.Key).ToList()) _flash.Remove(k);
    }

    private void UpdateBlends(GraphViewState v, float dt)
    {
        float k = v.Instant ? 1f : 1f - MathF.Exp(-dt * 7f);
        _webBlend += ((v.Mode == GraphViewMode.Web ? 1f : 0f) - _webBlend) * k;
        _portBlend += ((v.Mode == GraphViewMode.Ports ? 1f : 0f) - _portBlend) * k;
        _treeBlend += ((v.Mode == GraphViewMode.Tree ? 1f : 0f) - _treeBlend) * k;
    }

    /// <summary>Smoothly interpolates display positions towards the current mode's targets (gives animated mode transitions).</summary>
    private (float[] X, float[] Y) UpdatePositions(GraphSnapshot snap, LayoutFrame frame, GraphViewState v, float dt)
    {
        int n = snap.Nodes.Length;
        var xs = new float[n];
        var ys = new float[n];
        float k = v.Instant ? 1f : 1f - MathF.Exp(-dt * 8.5f);
        bool tree = v.Mode == GraphViewMode.Tree;
        for (int i = 0; i < n; i++)
        {
            var node = snap.Nodes[i];
            float tx, ty;
            if (tree) { tx = node.TreeX; ty = node.TreeY; }
            else if (i < frame.X.Length) { tx = frame.X[i]; ty = frame.Y[i]; }
            else (tx, ty) = ForceLayout.AnchorTarget(snap, node);

            if (v.Dragging == node.Mac) { tx = v.DragWorld.X; ty = v.DragWorld.Y; _display[node.Mac] = new SKPoint(tx, ty); }
            if (!_display.TryGetValue(node.Mac, out var p))
            {
                // new: appear at the parent's current position and fly out
                p = node.Parent >= 0 && node.Parent < n && _display.TryGetValue(snap.Nodes[node.Parent].Mac, out var pp) && !v.Instant ? pp : new SKPoint(tx, ty);
            }
            p = new SKPoint(p.X + (tx - p.X) * k, p.Y + (ty - p.Y) * k);
            _display[node.Mac] = p;
            xs[i] = p.X; ys[i] = p.Y;
        }
        if (_display.Count > n * 2 + 64)
        {
            var keep = new HashSet<Mac>(snap.Nodes.Select(x => x.Mac));
            foreach (var m in _display.Keys.Where(m => !keep.Contains(m)).ToList()) _display.Remove(m);
        }
        return (xs, ys);
    }

    // =====================================================================================================
    //  background + web
    // =====================================================================================================

    private static readonly (float X, float Y, float S)[] Stars = MakeStars();

    private static (float, float, float)[] MakeStars()
    {
        var r = new Random(7);
        return Enumerable.Range(0, 140).Select(_ => ((float)r.NextDouble(), (float)r.NextDouble(), (float)r.NextDouble())).ToArray();
    }

    private void DrawBackground(SKCanvas c, GraphViewState v, double time)
    {
        var rect = new SKRect(0, 0, v.Width, v.Height);
        var center = v.ToScreen(0, 0);
        float rad = Math.Max(v.Width, v.Height) * 0.9f;
        using (var bg = SKShader.CreateRadialGradient(center, rad,
                   [SKColor.Parse("#0E1B33"), SKColor.Parse("#0A1222"), Neon.Background, Neon.BackgroundDeep], [0f, 0.3f, 0.65f, 1f], SKShaderTileMode.Clamp))
        {
            _fill.Shader = bg;
            c.DrawRect(rect, _fill);
            _fill.Shader = null;
        }
        // nebula tint
        using (var neb = SKShader.CreateRadialGradient(new SKPoint(v.Width * 0.82f, v.Height * 0.15f), v.Width * 0.45f,
                   [Neon.Magenta.A(0.045f), SKColors.Transparent], SKShaderTileMode.Clamp))
        {
            _fill.Shader = neb;
            c.DrawRect(rect, _fill);
            _fill.Shader = null;
        }
        using (var neb2 = SKShader.CreateRadialGradient(new SKPoint(v.Width * 0.1f, v.Height * 0.92f), v.Width * 0.4f,
                   [Neon.Cyan.A(0.035f), SKColors.Transparent], SKShaderTileMode.Clamp))
        {
            _fill.Shader = neb2;
            c.DrawRect(rect, _fill);
            _fill.Shader = null;
        }

        // stars (parallax with pan)
        foreach (var (sx, sy, s) in Stars)
        {
            float x = ((sx * v.Width + v.PanX * 0.08f) % v.Width + v.Width) % v.Width;
            float y = ((sy * v.Height + v.PanY * 0.08f) % v.Height + v.Height) % v.Height;
            float tw = 0.35f + 0.65f * (0.5f + 0.5f * MathF.Sin((float)time * (0.6f + s) + s * 40));
            _fill.Color = SKColors.White.A(0.05f + 0.22f * s * tw);
            c.DrawCircle(x, y, 0.5f + s * 0.9f, _fill);
        }

        // faint world grid
        float step = 60 * v.Zoom;
        while (step < 28) step *= 2;
        var origin = v.ToScreen(0, 0);
        _stroke.StrokeWidth = 1;
        _stroke.Color = Neon.Cyan.A(0.028f);
        _stroke.PathEffect = null;
        for (float x = origin.X % step; x < v.Width; x += step) c.DrawLine(x, 0, x, v.Height, _stroke);
        for (float y = origin.Y % step; y < v.Height; y += step) c.DrawLine(0, y, v.Width, y, _stroke);
    }

    private void DrawWeb(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, GraphViewState v, double time)
    {
        if (snap.Gateway < 0 || snap.Gateway >= xs.Length) return;
        float cx = xs[snap.Gateway], cy = ys[snap.Gateway];
        float a = _webBlend;
        float t = (float)time;
        float vib = (float)Math.Max(0, 1 - (time - _vibrateStart) / 1.6);
        float vibOffset(float phase) => vib * 7f * MathF.Sin(t * 26f + phase) * vib;

        int maxDepth = Math.Max(1, snap.MaxDepth);
        float outer = snap.RingRadius(maxDepth) + 90;

        // spokes: evenly spaced + one per first-level node
        var angles = new List<float>();
        const int baseSpokes = 24;
        for (int i = 0; i < baseSpokes; i++) angles.Add(i * MathF.Tau / baseSpokes);
        var firstLevel = new List<int>();
        foreach (var node in snap.Nodes) if (node.Depth == 1 && !node.IsInternet && node.Index < xs.Length) firstLevel.Add(node.Index);

        _stroke.PathEffect = null;
        _stroke.StrokeCap = SKStrokeCap.Round;
        // faint base spokes
        _stroke.StrokeWidth = 1f / Math.Max(0.6f, v.Zoom);
        _stroke.Color = Neon.Cyan.A(0.10f * a);
        foreach (var ang in angles)
            c.DrawLine(cx, cy, cx + MathF.Cos(ang) * outer * GraphSnapshot.Ex, cy + MathF.Sin(ang) * outer * GraphSnapshot.Ey, _stroke);

        // radial threads to each first-level node (glowing)
        foreach (var i in firstLevel)
        {
            float dx = xs[i] - cx, dy = ys[i] - cy;
            float len = MathF.Sqrt(dx * dx + dy * dy) + 0.01f;
            float ex = cx + dx / len * outer * 1.05f, ey = cy + dy / len * outer * 1.05f;
            using var sh = SKShader.CreateLinearGradient(new SKPoint(cx, cy), new SKPoint(ex, ey),
                [Neon.Cyan.A(0.20f * a), Neon.Cyan.A(0.09f * a), SKColors.Transparent], [0, 0.6f, 1], SKShaderTileMode.Clamp);
            _stroke.Shader = sh;
            _stroke.StrokeWidth = 1.3f;
            c.DrawLine(cx, cy, ex, ey, _stroke);
            _stroke.Shader = null;
        }

        // rings (sagging polygon segments between spokes = classic orb web) + capture spiral rings in between
        using var sweep = SKShader.CreateSweepGradient(new SKPoint(cx, cy),
            [Neon.Cyan.A(0.0f), Neon.Cyan.A(0.55f * a), Neon.Magenta.A(0.25f * a), Neon.Cyan.A(0.0f), Neon.Cyan.A(0.0f)],
            [0f, 0.06f, 0.1f, 0.16f, 1f], SKShaderTileMode.Clamp, 0, 360);
        var rot = SKMatrix.CreateRotationDegrees(t * 14f % 360, cx, cy);
        using var sweepRot = sweep.WithLocalMatrix(rot);

        for (int d = 1; d <= maxDepth + 1; d++)
        {
            float r = d <= maxDepth ? snap.RingRadius(d) : snap.RingRadius(maxDepth) + 120;
            float breathe = 1 + 0.008f * MathF.Sin(t * 0.9f + d * 1.3f);
            for (int sub = 0; sub < 3; sub++)
            {
                // main ring + two faint capture-spiral rings inside it
                float rr = (r - sub * (d == 1 ? r / 3.2f : 62f)) * breathe;
                if (rr < 50) continue;
                BuildWebRing(_path, cx, cy, rr, angles, vibOffset(d * 0.7f + sub));
                bool main = sub == 0;
                float alpha = (main ? (d <= maxDepth ? 0.34f : 0.12f) : 0.11f) * a;
                // glow underlay
                if (main && d <= maxDepth)
                {
                    _stroke.StrokeWidth = 7f;
                    _stroke.Color = Neon.Cyan.A(0.06f * a);
                    c.DrawPath(_path, _stroke);
                }
                _stroke.StrokeWidth = main ? 1.25f : 0.8f;
                _stroke.Color = Neon.Cyan.A(alpha);
                c.DrawPath(_path, _stroke);
                if (main && d <= maxDepth)
                {
                    _stroke.Shader = sweepRot;
                    _stroke.StrokeWidth = 2f;
                    c.DrawPath(_path, _stroke);
                    _stroke.Shader = null;
                }
            }
        }

        // hub: small glowing core around the gateway
        using (var hub = SKShader.CreateRadialGradient(new SKPoint(cx, cy), 120, [Neon.Cyan.A(0.13f * a), SKColors.Transparent], SKShaderTileMode.Clamp))
        {
            _fill.Shader = hub;
            c.DrawCircle(cx, cy, 120, _fill);
            _fill.Shader = null;
        }
    }

    private static void BuildWebRing(SKPath p, float cx, float cy, float r, List<float> angles, float vib)
    {
        p.Reset();
        int n = angles.Count;
        for (int i = 0; i <= n; i++)
        {
            float ang = angles[i % n];
            float rr = r + vib * MathF.Sin(i * 1.7f);
            float x = cx + MathF.Cos(ang) * rr * GraphSnapshot.Ex, y = cy + MathF.Sin(ang) * rr * GraphSnapshot.Ey;
            if (i == 0) { p.MoveTo(x, y); continue; }
            float prev = angles[(i - 1) % n];
            float mid = (prev + ang) / 2;
            if (ang < prev) mid += MathF.PI;
            // control point pulled toward the centre: the silk sags between spokes
            float sag = rr * 0.955f;
            p.QuadTo(cx + MathF.Cos(mid) * sag * GraphSnapshot.Ex, cy + MathF.Sin(mid) * sag * GraphSnapshot.Ey, x, y);
        }
        p.Close();
    }

    // =====================================================================================================
    //  edges
    // =====================================================================================================

    private float NodeAlpha(GraphViewState v, GNode n)
    {
        float a = 1f;
        if (!v.IsVisible(n)) a = 0.1f;
        else if (!string.IsNullOrWhiteSpace(v.Search) && !v.MatchesSearch(n)) a = 0.18f;
        if (n.Offline) a *= 0.55f;
        if (_diag.Affected.Contains(n.Mac)) a *= 0.5f; // unreachable during an ongoing incident
        return a;
    }

    private static SKPoint Bezier(SKPoint a, SKPoint ctl, SKPoint b, float t)
    {
        float u = 1 - t;
        return new SKPoint(u * u * a.X + 2 * u * t * ctl.X + t * t * b.X, u * u * a.Y + 2 * u * t * ctl.Y + t * t * b.Y);
    }

    /// <summary>
    /// Edge geometry: a cubic in the web (straight, or an arc for Wi-Fi); in the tree a vertical S-curve, or for leaf
    /// rows an elbow along a shared "trunk" bus line. Tree shapes are blended point-wise so mode switches morph smoothly.
    /// </summary>
    public sealed class EdgeGeom
    {
        public SKPoint A, C1, C2, B;
        public SKPoint[]? Poly;

        public SKPoint At(float t)
        {
            if (Poly is null)
            {
                float u = 1 - t;
                float w0 = u * u * u, w1 = 3 * u * u * t, w2 = 3 * u * t * t, w3 = t * t * t;
                return new SKPoint(w0 * A.X + w1 * C1.X + w2 * C2.X + w3 * B.X, w0 * A.Y + w1 * C1.Y + w2 * C2.Y + w3 * B.Y);
            }
            float f = Math.Clamp(t, 0, 1) * (Poly.Length - 1);
            int i = Math.Min((int)f, Poly.Length - 2);
            float k = f - i;
            return new SKPoint(Poly[i].X + (Poly[i + 1].X - Poly[i].X) * k, Poly[i].Y + (Poly[i + 1].Y - Poly[i].Y) * k);
        }

        public void AddTo(SKPath p)
        {
            p.MoveTo(A);
            if (Poly is null) { p.CubicTo(C1, C2, B); return; }
            for (int i = 1; i < Poly.Length; i++) p.LineTo(Poly[i]);
        }
    }

    private const int PolySamples = 28;

    public static EdgeGeom Geometry(GraphSnapshot snap, GEdge e, SKPoint a, SKPoint b, float treeBlend)
    {
        var ctl = EdgeControl(a, b, e);
        var g = new EdgeGeom
        {
            A = a, B = b,
            C1 = new SKPoint(a.X + (ctl.X - a.X) * 2 / 3, a.Y + (ctl.Y - a.Y) * 2 / 3),
            C2 = new SKPoint(b.X + (ctl.X - b.X) * 2 / 3, b.Y + (ctl.Y - b.Y) * 2 / 3),
        };
        if (treeBlend <= 0.001f || e.A >= snap.Nodes.Length || e.B >= snap.Nodes.Length) return g;

        // which end is the BFS parent?
        GNode na = snap.Nodes[e.A], nb = snap.Nodes[e.B];
        bool bIsChild = nb.Parent == e.A, aIsChild = na.Parent == e.B;
        var child = bIsChild ? nb : aIsChild ? na : null;
        if (child is not null && !float.IsNaN(child.TrunkX))
        {
            var web = new SKPoint[PolySamples];
            for (int i = 0; i < PolySamples; i++) web[i] = g.At(i / (float)(PolySamples - 1));
            var p = bIsChild ? a : b;
            var c = bIsChild ? b : a;
            var elbow = Elbow(p, c, child.TrunkX, p.Y + GraphBuilder.TreeLevelGap * 0.48f);
            if (!bIsChild) Array.Reverse(elbow);
            for (int i = 0; i < PolySamples; i++)
                web[i] = new SKPoint(web[i].X + (elbow[i].X - web[i].X) * treeBlend, web[i].Y + (elbow[i].Y - web[i].Y) * treeBlend);
            g.Poly = web;
            return g;
        }
        float my = (a.Y + b.Y) / 2;
        g.C1 = new SKPoint(g.C1.X + (a.X - g.C1.X) * treeBlend, g.C1.Y + (my - g.C1.Y) * treeBlend);
        g.C2 = new SKPoint(g.C2.X + (b.X - g.C2.X) * treeBlend, g.C2.Y + (my - g.C2.Y) * treeBlend);
        return g;
    }

    /// <summary>Parent → S-curve down to the trunk → straight down the trunk → across to the leaf, resampled by arc length.</summary>
    private static SKPoint[] Elbow(SKPoint p, SKPoint c, float tx, float ty)
    {
        ty = Math.Min(ty, c.Y);
        var pts = new List<SKPoint>(48);
        for (int i = 0; i <= 12; i++)
        {
            float t = i / 12f, u = 1 - t;
            var c1 = new SKPoint(p.X, p.Y + (ty - p.Y) * 0.6f);
            var c2 = new SKPoint(tx, ty - (ty - p.Y) * 0.6f);
            pts.Add(new SKPoint(u * u * u * p.X + 3 * u * u * t * c1.X + 3 * u * t * t * c2.X + t * t * t * tx,
                u * u * u * p.Y + 3 * u * u * t * c1.Y + 3 * u * t * t * c2.Y + t * t * t * ty));
        }
        pts.Add(new SKPoint(tx, c.Y));
        pts.Add(c);
        // resample uniformly by arc length
        var len = new float[pts.Count];
        for (int i = 1; i < pts.Count; i++) len[i] = len[i - 1] + SKPoint.Distance(pts[i - 1], pts[i]);
        var res = new SKPoint[PolySamples];
        float total = Math.Max(0.001f, len[^1]);
        int j = 1;
        for (int i = 0; i < PolySamples; i++)
        {
            float d = total * i / (PolySamples - 1);
            while (j < pts.Count - 1 && len[j] < d) j++;
            float seg = Math.Max(0.0001f, len[j] - len[j - 1]);
            float k = Math.Clamp((d - len[j - 1]) / seg, 0, 1);
            res[i] = new SKPoint(pts[j - 1].X + (pts[j].X - pts[j - 1].X) * k, pts[j - 1].Y + (pts[j].Y - pts[j - 1].Y) * k);
        }
        return res;
    }

    public static SKPoint EdgeControl(SKPoint a, SKPoint b, GEdge e)
    {
        var mid = new SKPoint((a.X + b.X) / 2, (a.Y + b.Y) / 2);
        if (!e.IsWifi) return mid;
        float dx = b.X - a.X, dy = b.Y - a.Y;
        return new SKPoint(mid.X - dy * 0.18f, mid.Y + dx * 0.18f);
    }

    private void DrawEdges(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, GraphViewState v, double time)
    {
        float t = (float)time;
        int? selIdx = v.Selected is { } s && snap.Index.TryGetValue(s, out var si) ? si : null;
        int? hovIdx = v.Hovered is { } h && snap.Index.TryGetValue(h, out var hi) ? hi : null;
        foreach (var e in snap.Edges)
        {
            if (e.A >= xs.Length || e.B >= xs.Length) continue;
            var na = snap.Nodes[e.A];
            var nb = snap.Nodes[e.B];
            float alpha = Math.Min(NodeAlpha(v, na), NodeAlpha(v, nb));
            bool focus = selIdx is { } x && (e.A == x || e.B == x) || hovIdx is { } y && (e.A == y || e.B == y);
            bool hovered = v.HoveredEdge is { } he && ((he.A == na.Mac && he.B == nb.Mac) || (he.A == nb.Mac && he.B == na.Mac));
            if (selIdx is not null && !focus) alpha *= 0.45f;

            var a = new SKPoint(xs[e.A], ys[e.A]);
            var b = new SKPoint(xs[e.B], ys[e.B]);
            var geom = Geometry(snap, e, a, b, _treeBlend);
            double? lat = e.LatencyMs ?? (e.Kind == LinkKind.Wan ? (na.IsInternet ? na.L3 : nb.L3) : null);
            var col = lat is null ? Neon.Cyan.A(0.6f) : Neon.Latency(lat, snap.GoodMs, snap.WarnMs, snap.BadMs);
            float w = e.IsWifi ? 1.8f : Neon.SpeedWidth(e.SpeedMbps);
            if (e.Kind == LinkKind.Wan) w = Math.Max(w, 2.6f);
            if (hovered) w += 1.8f;

            _path.Reset();
            geom.AddTo(_path);

            // glow
            _stroke.PathEffect = null;
            _stroke.StrokeCap = SKStrokeCap.Round;
            _stroke.StrokeWidth = w * 3.6f + 2;
            _stroke.Color = col.A((hovered || focus ? 0.22f : 0.10f) * alpha);
            c.DrawPath(_path, _stroke);

            // body
            _stroke.StrokeWidth = w;
            _stroke.Color = col.A((hovered ? 1f : 0.78f) * alpha);
            SKPathEffect? fx = null;
            if (e.IsWifi) fx = SKPathEffect.CreateDash(DashWifi, -t * 10f);
            else if (e.Origin == LatencyOrigin.Estimated || e.Kind == LinkKind.InferredUnmanagedSwitch) fx = SKPathEffect.CreateDash(DashEstimated, -t * 14f);
            if (e.IsWifi) _stroke.StrokeWidth = 2.6f;
            _stroke.PathEffect = fx;
            c.DrawPath(_path, _stroke);
            _stroke.PathEffect = null;
            fx?.Dispose();

            // suspected faulty link (ongoing incident): red glow + marching red dashes, no traffic particles
            if (_diag.Faults.Count > 0 && _diag.IsSuspectLink(na.Mac, nb.Mac))
            {
                float pulse = 0.5f + 0.5f * MathF.Sin(t * 4.2f);
                _stroke.StrokeWidth = w * 3.6f + 8;
                _stroke.Color = Neon.Red.A(0.10f + 0.12f * pulse);
                c.DrawPath(_path, _stroke);
                using var dash = SKPathEffect.CreateDash(DashFault, -t * 22f);
                _stroke.PathEffect = dash;
                _stroke.StrokeWidth = Math.Max(2.6f, w + 1.2f);
                _stroke.Color = Neon.Red.A(0.95f);
                c.DrawPath(_path, _stroke);
                _stroke.PathEffect = null;
                continue;
            }

            // particles: speed ∝ 1/latency
            if (alpha > 0.2f && !na.Offline && !nb.Offline)
            {
                double lms = lat ?? 1.0;
                float rate = (float)Math.Clamp(1.1 / (lms + 0.35), 0.06, 1.3);
                int count = na.IsInfra && nb.IsInfra ? 3 : 2;
                for (int k = 0; k < count; k++)
                {
                    float p = (t * rate + e.Phase + k / (float)count) % 1f;
                    if ((k & 1) == 1) p = 1 - p;
                    var pt = geom.At(p);
                    float fade = MathF.Sin(p * MathF.PI);
                    _fill.Color = col.A(0.28f * fade * alpha);
                    c.DrawCircle(pt, 5.5f, _fill);
                    _fill.Color = SKColors.White.A(0.9f * fade * alpha);
                    c.DrawCircle(pt, 1.7f, _fill);
                }
            }
        }
        _stroke.PathEffect = null;
    }

    // =====================================================================================================
    //  device↔device latency threads ("MAC timing from each device to device")
    // =====================================================================================================

    private void DrawLatencyThreads(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, GraphViewState v, int sel, double time, bool labels)
    {
        if (sel >= xs.Length) return;
        var src = new SKPoint(xs[sel], ys[sel]);
        float t = (float)time;
        int k = 0;
        var placed = new List<SKRect>();
        if (labels)
        {
            // node badges + labels are obstacles: thread labels never cover them
            foreach (var n in snap.Nodes)
            {
                if (n.Index >= xs.Length) continue;
                float hw = Math.Max(n.Radius + 4, n.LabelW / 2);
                placed.Add(new SKRect(xs[n.Index] - hw, ys[n.Index] - n.Radius - 4, xs[n.Index] + hw, ys[n.Index] + n.Radius + 7 + n.LabelH));
            }
        }
        foreach (var node in snap.Nodes.OrderBy(n => (n.Index * 7919) % 101))
        {
            int j = node.Index;
            if (j == sel || j >= xs.Length || !v.IsVisible(node) || node.IsInferred) continue;
            var info = snap.GetPair(sel, j);
            if (info is not { } pi) continue;
            if (!snap.ShowEstimated && pi.Origin == LatencyOrigin.Estimated && pi.Method != "path-sum") continue;
            var dst = new SKPoint(xs[j], ys[j]);
            float dx = dst.X - src.X, dy = dst.Y - src.Y;
            float len = MathF.Sqrt(dx * dx + dy * dy);
            if (len < 1) continue;
            float bow = ((j & 1) == 0 ? 1 : -1) * Math.Min(60f, len * 0.12f);
            var ctl = new SKPoint((src.X + dst.X) / 2 - dy / len * bow, (src.Y + dst.Y) / 2 + dx / len * bow);
            var col = Neon.Latency(pi.Ms, snap.GoodMs, snap.WarnMs, snap.BadMs);
            bool measured = pi.Origin == LatencyOrigin.Measured;
            k++;

            if (!labels)
            {
                _path.Reset();
                _path.MoveTo(src);
                _path.QuadTo(ctl, dst);
                _stroke.StrokeWidth = 4f;
                _stroke.Color = col.A(0.06f);
                _stroke.PathEffect = null;
                c.DrawPath(_path, _stroke);
                _stroke.StrokeWidth = measured ? 1.3f : 1.0f;
                _stroke.Color = col.A(measured ? 0.75f : 0.5f);
                using var dash = measured ? null : SKPathEffect.CreateDash(DashThread, -t * 8);
                _stroke.PathEffect = dash;
                c.DrawPath(_path, _stroke);
                _stroke.PathEffect = null;
                // timing pulse travelling out from the selected node; faster for lower latency
                float rate = (float)Math.Clamp(0.9 / (pi.Ms + 0.4), 0.12, 1.2);
                float p = (t * rate + j * 0.137f) % 1f;
                var pt = Bezier(src, ctl, dst, p);
                _fill.Color = col.A(0.35f);
                c.DrawCircle(pt, 4.5f, _fill);
                _fill.Color = SKColors.White.A(0.9f);
                c.DrawCircle(pt, 1.5f, _fill);
                continue;
            }

            // label pill on the thread (avoid overlapping other thread labels)
            string txt = Neon.FormatMs(pi.Ms);
            float tw = _fThread.MeasureText(txt);
            SKRect r = default;
            bool ok = false;
            foreach (var tt in ThreadLabelStops)
            {
                var lp = Bezier(src, ctl, dst, tt);
                r = new SKRect(lp.X - tw / 2 - 6, lp.Y - 8, lp.X + tw / 2 + 6, lp.Y + 8);
                if (!placed.Any(o => o.IntersectsWith(r))) { ok = true; break; }
            }
            if (!ok) continue;
            placed.Add(r);
            _fill.Color = Neon.Background.A(0.88f);
            c.DrawRoundRect(r, 8, 8, _fill);
            _stroke.StrokeWidth = 1;
            _stroke.Color = col.A(0.75f);
            using (var d2 = measured ? null : SKPathEffect.CreateDash([2.5f, 2f], 0))
            {
                _stroke.PathEffect = d2;
                c.DrawRoundRect(r, 8, 8, _stroke);
                _stroke.PathEffect = null;
            }
            _text.Color = col;
            c.DrawText(txt, r.MidX, r.MidY + 3.4f, SKTextAlign.Center, _fThread, _text);
        }
    }

    // =====================================================================================================
    //  nodes
    // =====================================================================================================

    private static float PulsePeriod(double? ms, GraphSnapshot snap) => ms switch
    {
        null => 3.2f,
        var v when v < snap.GoodMs => 2.6f,
        var v when v < snap.WarnMs => 1.6f,
        var v when v < snap.BadMs => 1.0f,
        _ => 0.6f,
    };

    private void DrawNodes(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, GraphViewState v, double time)
    {
        float t = (float)time;
        float vib = (float)Math.Max(0, 1 - (time - _vibrateStart) / 1.6);
        bool searching = !string.IsNullOrWhiteSpace(v.Search);
        int labelLod = v.Zoom < 0.28f ? 0 : v.Zoom < 0.5f ? 1 : 2;
        bool tree = v.Mode == GraphViewMode.Tree;

        // draw deep nodes first so infrastructure ends up on top
        var order = snap.Nodes.Where(n => n.Index < xs.Length).OrderByDescending(n => n.Depth).ThenBy(n => n.IsInfra ? 1 : 0);
        foreach (var n in order)
        {
            float alpha = NodeAlpha(v, n);
            float x = xs[n.Index], y = ys[n.Index];
            if (vib > 0) { x += MathF.Sin(t * 31 + n.Index) * 3.2f * vib * vib; y += MathF.Cos(t * 27 + n.Index * 1.3f) * 3.2f * vib * vib; }
            bool flashing = _flash.TryGetValue(n.Mac, out var fStart);
            float fp = flashing ? (float)Math.Clamp((time - fStart) / 2.5, 0, 1) : 1;
            if (flashing) x += MathF.Sin(t * 70) * 5f * (1 - fp);

            float r = n.Radius;
            var ringCol = n.Offline ? Neon.Grey : n.IsInferred ? Neon.TextDim : Neon.Latency(n.Best, snap.GoodMs, snap.WarnMs, snap.BadMs);
            if (n.IsInternet) ringCol = n.L3 is { } wl ? Neon.Latency(wl, snap.GoodMs * 6, snap.WarnMs * 2, snap.BadMs * 2) : Neon.Cyan;
            if (flashing) ringCol = Neon.Lerp(Neon.Red, ringCol, fp);
            bool selected = v.Selected == n.Mac;
            bool hovered = v.Hovered == n.Mac;
            bool match = searching && v.MatchesSearch(n) && v.IsVisible(n);

            // ---- glow ----
            float period = PulsePeriod(n.Best, snap);
            float pulse = 0.5f + 0.5f * MathF.Sin(t * MathF.Tau / period + n.Index);
            float glowR = r * (selected ? 3.1f : 2.5f);
            using (var glow = SKShader.CreateRadialGradient(new SKPoint(x, y), glowR,
                       [ringCol.A((selected ? 0.5f : 0.30f + 0.10f * pulse) * alpha), ringCol.A(0.08f * alpha), SKColors.Transparent], [0.25f, 0.6f, 1f], SKShaderTileMode.Clamp))
            {
                _fill.Shader = glow;
                c.DrawCircle(x, y, glowR, _fill);
                _fill.Shader = null;
            }

            // ---- latency pulse ring (rate tied to latency) ----
            if (!n.Offline && !n.IsInferred && alpha > 0.3f)
            {
                float ph = (t / period + n.Index * 0.173f) % 1f;
                _stroke.PathEffect = null;
                _stroke.StrokeWidth = 1.6f;
                _stroke.Color = ringCol.A((1 - ph) * 0.55f * alpha);
                c.DrawCircle(x, y, r + 3 + ph * r * 0.9f, _stroke);
            }

            // ---- multicast halo ----
            if (n.Multicast && alpha > 0.3f)
            {
                using var dash = SKPathEffect.CreateDash(DashHalo, t * 10);
                _stroke.PathEffect = dash;
                _stroke.StrokeWidth = 1.6f;
                _stroke.Color = Neon.Magenta.A(0.75f * alpha);
                c.DrawCircle(x, y, r + 8.5f, _stroke);
                _stroke.PathEffect = null;
                _stroke.StrokeWidth = 6f;
                _stroke.Color = Neon.Magenta.A(0.08f * alpha);
                c.DrawCircle(x, y, r + 8.5f, _stroke);
            }

            // ---- search highlight ----
            if (match)
            {
                _stroke.StrokeWidth = 3;
                _stroke.Color = Neon.Cyan.A(0.5f + 0.4f * pulse);
                c.DrawCircle(x, y, r + 13 + pulse * 3, _stroke);
            }

            // ---- badge ----
            if (n.IsInferred)
            {
                _fill.Color = Neon.Background.A(0.8f * alpha);
                c.DrawCircle(x, y, r, _fill);
                using var dash = SKPathEffect.CreateDash([5f, 4f], t * 4);
                _stroke.PathEffect = dash;
                _stroke.StrokeWidth = 2f;
                _stroke.Color = Neon.TextDim.A(0.85f * alpha);
                c.DrawCircle(x, y, r, _stroke);
                _stroke.PathEffect = null;
                Glyphs.Draw(c, DeviceType.UnmanagedSwitch, x, y, r * 1.1f, Neon.TextDim.A(0.7f * alpha));
            }
            else
            {
                using (var body = SKShader.CreateRadialGradient(new SKPoint(x - r * 0.3f, y - r * 0.35f), r * 1.4f,
                           [SKColor.Parse("#1F3157").A(alpha), SKColor.Parse("#0B1324").A(alpha)], SKShaderTileMode.Clamp))
                {
                    _fill.Shader = body;
                    c.DrawCircle(x, y, r, _fill);
                    _fill.Shader = null;
                }
                var logo = LogoCache.Get(n.LogoPath);
                if (logo is not null)
                {
                    _fill.Color = (LogoCache.IsLight(n.LogoPath) ? SKColor.Parse("#111A2E") : SKColor.Parse("#F2F6FC")).A(0.96f * alpha);
                    c.DrawCircle(x, y, r - 3.5f, _fill);
                    c.Save();
                    _path.Reset();
                    _path.AddCircle(x, y, r - 3.5f);
                    c.ClipPath(_path, antialias: true);
                    float s = (r - 3.5f) * 1.45f;
                    _fill.Color = SKColors.White.A(alpha);
                    c.DrawImage(logo, new SKRect(x - s / 2, y - s / 2, x + s / 2, y + s / 2), new SKSamplingOptions(SKFilterMode.Linear, SKMipmapMode.Linear), _fill);
                    c.Restore();
                }
                else
                {
                    var gc = n.IsInternet ? Neon.Cyan : n.IsInfra ? SKColor.Parse("#9FF6FF") : SKColor.Parse("#DDE8FF");
                    Glyphs.Draw(c, n.Type == DeviceType.Unknown && n.IsGateway ? DeviceType.Router : n.Type, x, y, r * 1.12f, gc.A(alpha));
                }
                // outer ring
                _stroke.PathEffect = null;
                _stroke.StrokeWidth = n.IsInfra ? 3.2f : 2.5f;
                _stroke.Color = ringCol.A(alpha);
                c.DrawCircle(x, y, r, _stroke);
                _stroke.StrokeWidth = 1f;
                _stroke.Color = SKColors.White.A(0.10f * alpha);
                c.DrawCircle(x, y, r - 3.2f, _stroke);
                if (n.IsGateway)
                {
                    _stroke.StrokeWidth = 1.2f;
                    _stroke.Color = ringCol.A(0.55f * alpha);
                    c.DrawCircle(x, y, r + 4.5f, _stroke);
                }
            }

            // ---- alert flash ----
            if (flashing)
            {
                float fa = (1 - fp) * (0.55f + 0.45f * MathF.Sin(t * 22));
                _fill.Color = Neon.Red.A(0.45f * fa);
                c.DrawCircle(x, y, r, _fill);
                _stroke.StrokeWidth = 3;
                _stroke.Color = Neon.Red.A(0.9f * fa);
                c.DrawCircle(x, y, r + 5, _stroke);
            }

            // ---- ongoing incident: suspect pulses red, affected devices get a thin red outline ----
            if (_diag.Faults.Count > 0)
            {
                if (_diag.IsSuspect(n.Mac)) DrawSuspect(c, x, y, r, t);
                else if (_diag.Affected.Contains(n.Mac))
                {
                    _stroke.PathEffect = null;
                    _stroke.StrokeWidth = 1.6f;
                    _stroke.Color = Neon.Red.A(0.75f);
                    c.DrawCircle(x, y, r + 3.5f, _stroke);
                }
            }

            // ---- selection / hover ----
            if (selected)
            {
                _stroke.StrokeWidth = 2.4f;
                _stroke.Color = Neon.Cyan;
                float rr = r + 12;
                var oval = new SKRect(x - rr, y - rr, x + rr, y + rr);
                float rot = t * 60 % 360;
                for (int q = 0; q < 4; q++) c.DrawArc(oval, rot + q * 90, 52, false, _stroke);
                _stroke.StrokeWidth = 8;
                _stroke.Color = Neon.Cyan.A(0.12f);
                c.DrawCircle(x, y, rr, _stroke);
            }
            else if (hovered)
            {
                _stroke.StrokeWidth = 1.5f;
                _stroke.Color = SKColors.White.A(0.55f);
                c.DrawCircle(x, y, r + 7, _stroke);
            }

            // ---- badges ----
            if (n.IsNew && alpha > 0.3f)
            {
                var tagR = new SKRect(x + r * 0.45f, y - r - 6, x + r * 0.45f + 26, y - r + 7);
                _fill.Color = Neon.Green.A(alpha);
                c.DrawRoundRect(tagR, 6.5f, 6.5f, _fill);
                _text.Color = Neon.Background;
                c.DrawText("NEW", tagR.MidX, tagR.MidY + 3, SKTextAlign.Center, _fTiny, _text);
            }
            if (n.SecurityWarning && alpha > 0.3f)
            {
                float bx = x - r * 0.78f, by = y - r * 0.78f;
                _path.Reset();
                _path.MoveTo(bx, by - 8);
                _path.LineTo(bx + 8.5f, by + 6.5f);
                _path.LineTo(bx - 8.5f, by + 6.5f);
                _path.Close();
                bool rogue = n.Flags.HasFlag(DeviceFlags.RogueDhcp) || n.Flags.HasFlag(DeviceFlags.RogueRouterAdvert);
                _fill.Color = (rogue ? Neon.Red : Neon.Amber).A(alpha);
                _stroke.StrokeJoin = SKStrokeJoin.Round;
                _stroke.StrokeWidth = 3;
                _stroke.Color = Neon.Background.A(alpha);
                c.DrawPath(_path, _stroke);
                c.DrawPath(_path, _fill);
                _text.Color = Neon.Background;
                c.DrawText("!", bx, by + 5f, SKTextAlign.Center, _fTiny, _text);
            }

            // ---- label ----
            if (labelLod > 0) DrawLabel(c, n, x, y + r + 7, alpha, labelLod, v.ShowMac, snap, tree);
        }
    }

    /// <summary>Red pulsing rings and a "⚠ suspected" tag on the node an ongoing incident blames.</summary>
    private void DrawSuspect(SKCanvas c, float x, float y, float r, float t)
    {
        float pulse = 0.5f + 0.5f * MathF.Sin(t * 4.2f);
        _stroke.PathEffect = null;
        // two expanding rings
        for (int k = 0; k < 2; k++)
        {
            float ph = (t * 0.7f + k * 0.5f) % 1f;
            _stroke.StrokeWidth = 2.2f;
            _stroke.Color = Neon.Red.A((1 - ph) * 0.7f);
            c.DrawCircle(x, y, r + 4 + ph * r * 1.1f, _stroke);
        }
        _stroke.StrokeWidth = 3f;
        _stroke.Color = Neon.Red.A(0.75f + 0.25f * pulse);
        c.DrawCircle(x, y, r + 2.5f, _stroke);
        _stroke.StrokeWidth = 9f;
        _stroke.Color = Neon.Red.A(0.10f + 0.10f * pulse);
        c.DrawCircle(x, y, r + 2.5f, _stroke);

        // tag pill above the badge: ⚠ suspected
        const string label = "suspected";
        float tw = _fSmallBold.MeasureText(label);
        float pw = tw + 26, ph2 = 17;
        var tag = new SKRect(x - pw / 2, y - r - 12 - ph2, x + pw / 2, y - r - 12);
        _fill.Color = SKColor.Parse("#2A0C14").A(0.95f);
        c.DrawRoundRect(tag, ph2 / 2, ph2 / 2, _fill);
        _stroke.StrokeWidth = 1.2f;
        _stroke.Color = Neon.Red.A(0.8f + 0.2f * pulse);
        c.DrawRoundRect(tag, ph2 / 2, ph2 / 2, _stroke);
        float bx = tag.Left + 11, by = tag.MidY;
        _path.Reset();
        _path.MoveTo(bx, by - 5.2f);
        _path.LineTo(bx + 5.6f, by + 4.4f);
        _path.LineTo(bx - 5.6f, by + 4.4f);
        _path.Close();
        _fill.Color = Neon.Red;
        c.DrawPath(_path, _fill);
        _text.Color = SKColor.Parse("#2A0C14");
        c.DrawText("!", bx, by + 3.6f, SKTextAlign.Center, _fTiny, _text);
        _text.Color = SKColor.Parse("#FFC9D1");
        c.DrawText(label, tag.Left + 19, by + 3.8f, SKTextAlign.Left, _fSmallBold, _text);
    }

    private void DrawLabel(SKCanvas c, GNode n, float cx, float top, float alpha, int lod, bool showMac, GraphSnapshot snap, bool tree)
    {
        var name = GraphBuilder.Truncate(n.Name, 28);
        string lat = GraphBuilder.LatencyLine(n);
        bool mac = showMac && !n.IsInternet && !n.IsInferred && lod > 1;
        bool ip = n.Ip is not null && lod > 1;
        bool latLine = lat.Length > 0 && lod > 1;
        int lines = 1 + (ip ? 1 : 0) + (mac ? 1 : 0) + (latLine ? 1 : 0);
        float w = n.LabelW;
        if (lod == 1) w = _fName.MeasureText(name) + 14;
        float h = 6 + 16 + (lines - 1) * 13.5f;
        var rect = new SKRect(cx - w / 2, top, cx + w / 2, top + h);
        _fill.Color = SKColor.Parse("#060A13").A(0.72f * alpha);
        c.DrawRoundRect(rect, 7, 7, _fill);
        _stroke.PathEffect = null;
        _stroke.StrokeWidth = 1;
        _stroke.Color = Neon.Cyan.A(0.10f * alpha);
        c.DrawRoundRect(rect, 7, 7, _stroke);

        float y = top + 16;
        _text.Color = Neon.Text.A(alpha);
        c.DrawText(name, cx, y, SKTextAlign.Center, _fName, _text);
        y += 13.5f;
        if (ip)
        {
            _text.Color = SKColor.Parse("#7FEFFF").A(0.95f * alpha);
            c.DrawText(n.Ip!, cx, y, SKTextAlign.Center, _fSmall, _text);
            y += 13.5f;
        }
        if (mac)
        {
            _text.Color = Neon.TextDim.A(0.9f * alpha);
            c.DrawText(n.MacText, cx, y, SKTextAlign.Center, _fMono, _text);
            y += 13.5f;
        }
        if (latLine)
        {
            if (n.IsInternet || n.L2 is null && n.L3 is null)
            {
                _text.Color = Neon.TextDim.A(alpha);
                c.DrawText(lat, cx, y, SKTextAlign.Center, _fSmall, _text);
            }
            else
            {
                // "L2 0.42 ms · L3 0.61 ms" with each value in its latency color
                string p1 = "L2 ", v1 = Neon.FormatMs(n.L2), p2 = " · L3 ", v2 = Neon.FormatMs(n.L3);
                float total = _fSmall.MeasureText(p1) + _fSmallBold.MeasureText(v1) + _fSmall.MeasureText(p2) + _fSmallBold.MeasureText(v2);
                float x = cx - total / 2;
                _text.Color = Neon.TextFaint.A(alpha);
                c.DrawText(p1, x, y, SKTextAlign.Left, _fSmall, _text); x += _fSmall.MeasureText(p1);
                _text.Color = Neon.Latency(n.L2, snap.GoodMs, snap.WarnMs, snap.BadMs).A(alpha);
                c.DrawText(v1, x, y, SKTextAlign.Left, _fSmallBold, _text); x += _fSmallBold.MeasureText(v1);
                _text.Color = Neon.TextFaint.A(alpha);
                c.DrawText(p2, x, y, SKTextAlign.Left, _fSmall, _text); x += _fSmall.MeasureText(p2);
                _text.Color = Neon.Latency(n.L3, snap.GoodMs, snap.WarnMs, snap.BadMs).A(alpha);
                c.DrawText(v2, x, y, SKTextAlign.Left, _fSmallBold, _text);
            }
        }
        _ = tree;
    }

    // =====================================================================================================
    //  packet rain effects
    // =====================================================================================================

    private bool TryPos(GraphSnapshot snap, float[] xs, float[] ys, Mac mac, out SKPoint p, out float r)
    {
        if (snap.Index.TryGetValue(mac, out var i) && i < xs.Length) { p = new SKPoint(xs[i], ys[i]); r = snap.Nodes[i].Radius; return true; }
        p = default; r = 0; return false;
    }

    private void DrawEffectsBelow(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, double time)
    {
        _stroke.PathEffect = null;
        foreach (var rp in _ripples)
        {
            double age = time - rp.Start;
            if (age < 0 || !TryPos(snap, xs, ys, rp.Mac, out var p, out var r)) continue;
            float k = (float)(age / rp.Duration);
            float ease = 1 - (1 - k) * (1 - k);
            _stroke.StrokeWidth = rp.Width * (1 - k * 0.6f);
            _stroke.Color = rp.Color.A((1 - k) * 0.75f);
            c.DrawCircle(p, r + 2 + ease * rp.MaxR, _stroke);
            if (rp.Width > 2)
            {
                _stroke.StrokeWidth = rp.Width * 4;
                _stroke.Color = rp.Color.A((1 - k) * 0.12f);
                c.DrawCircle(p, r + 2 + ease * rp.MaxR, _stroke);
            }
        }
    }

    private void DrawEffectsAbove(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, double time)
    {
        foreach (var s in _sparks)
        {
            double age = time - s.Start;
            if (age < 0 || !TryPos(snap, xs, ys, s.Mac, out var p, out var r)) continue;
            float k = (float)(age / 1.3);
            float sx = p.X + r * 0.8f + s.Dx * k, sy = p.Y - r - 4 - k * 34;
            // spark dot
            _fill.Color = s.Color.A((1 - k) * 0.35f);
            c.DrawCircle(p.X + r * 0.7f * MathF.Cos(s.Dx), p.Y - r * 0.7f, 6 * (1 - k) + 1, _fill);
            _fill.Color = s.Color.A(1 - k);
            c.DrawCircle(p.X + r * 0.7f * MathF.Cos(s.Dx), p.Y - r * 0.7f, 2.2f * (1 - k) + 0.6f, _fill);
            // floating protocol initials
            _text.Color = s.Color.A((1 - k) * 0.95f);
            c.DrawText(s.Text, sx, sy, SKTextAlign.Center, _fTiny, _text);
        }
    }
}
