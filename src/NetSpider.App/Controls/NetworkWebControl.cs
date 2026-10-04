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
using NetSpider.App.Controls.Graph;
using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Controls;

/// <summary>
/// The animated spider-web network graph. Rendering goes through <see cref="ICustomDrawOperation"/> straight onto the
/// Skia canvas (render thread); physics runs on the <see cref="GraphEngine"/>'s own thread; this control only handles
/// input, view state (pan/zoom/selection) and frame pacing.
/// </summary>
public sealed class NetworkWebControl : Control
{
    public static readonly StyledProperty<GraphEngine?> EngineProperty =
        AvaloniaProperty.Register<NetworkWebControl, GraphEngine?>(nameof(Engine));
    public static readonly StyledProperty<GraphViewMode> ModeProperty =
        AvaloniaProperty.Register<NetworkWebControl, GraphViewMode>(nameof(Mode));
    public static readonly StyledProperty<Device?> SelectedDeviceProperty =
        AvaloniaProperty.Register<NetworkWebControl, Device?>(nameof(SelectedDevice), defaultBindingMode: BindingMode.TwoWay);
    public static readonly StyledProperty<string?> SearchTextProperty =
        AvaloniaProperty.Register<NetworkWebControl, string?>(nameof(SearchText));
    public static readonly StyledProperty<int?> VlanFilterProperty =
        AvaloniaProperty.Register<NetworkWebControl, int?>(nameof(VlanFilter));
    /// <summary>Bit mask of hidden <see cref="TypeGroup"/>s (bit = 1 &lt;&lt; (int)group).</summary>
    public static readonly StyledProperty<int> HiddenGroupsProperty =
        AvaloniaProperty.Register<NetworkWebControl, int>(nameof(HiddenGroups));
    public static readonly StyledProperty<bool> ShowMacProperty =
        AvaloniaProperty.Register<NetworkWebControl, bool>(nameof(ShowMac), true);
    public static readonly StyledProperty<bool> AnimationsProperty =
        AvaloniaProperty.Register<NetworkWebControl, bool>(nameof(Animations), true);

    /// <summary>Height of overlays at the top (toolbar) that fitting should keep clear.</summary>
    public static readonly StyledProperty<double> TopInsetProperty = AvaloniaProperty.Register<NetworkWebControl, double>(nameof(TopInset));
    public double TopInset { get => GetValue(TopInsetProperty); set => SetValue(TopInsetProperty, value); }

    public GraphEngine? Engine { get => GetValue(EngineProperty); set => SetValue(EngineProperty, value); }
    public GraphViewMode Mode { get => GetValue(ModeProperty); set => SetValue(ModeProperty, value); }
    public Device? SelectedDevice { get => GetValue(SelectedDeviceProperty); set => SetValue(SelectedDeviceProperty, value); }
    public string? SearchText { get => GetValue(SearchTextProperty); set => SetValue(SearchTextProperty, value); }
    public int? VlanFilter { get => GetValue(VlanFilterProperty); set => SetValue(VlanFilterProperty, value); }
    public int HiddenGroups { get => GetValue(HiddenGroupsProperty); set => SetValue(HiddenGroupsProperty, value); }
    public bool ShowMac { get => GetValue(ShowMacProperty); set => SetValue(ShowMacProperty, value); }
    public bool Animations { get => GetValue(AnimationsProperty); set => SetValue(AnimationsProperty, value); }

    private readonly GraphRenderer _renderer = new();
    private readonly GraphViewState _state = new();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private DispatcherTimer? _slowTimer;
    private bool _attached;
    private bool _fitPending = true;
    private int _fitSettleFrames;

    // interaction
    private Point _pressPos;
    private Point _lastPos;
    private Mac? _pressNode;
    private bool _panning;
    private bool _moved;
    private (float Zoom, float PanX, float PanY)? _anim;

    static NetworkWebControl()
    {
        AffectsRender<NetworkWebControl>(ModeProperty, SearchTextProperty, VlanFilterProperty, HiddenGroupsProperty, ShowMacProperty);
        FocusableProperty.OverrideDefaultValue<NetworkWebControl>(true);
        ClipToBoundsProperty.OverrideDefaultValue<NetworkWebControl>(true);
    }

    public NetworkWebControl()
    {
        GestureRecognizers.Add(new PinchGestureRecognizer());
        AddHandler(Gestures.PinchEvent, OnPinch);
        AddHandler(Gestures.PinchEndedEvent, (_, _) => _lastPinch = 1);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ModeProperty)
        {
            _state.Mode = Mode;
            FitAnimated();
        }
        else if (change.Property == SelectedDeviceProperty) _state.Selected = SelectedDevice?.Mac;
        else if (change.Property == SearchTextProperty) _state.Search = SearchText;
        else if (change.Property == VlanFilterProperty) _state.VlanFilter = VlanFilter;
        else if (change.Property == HiddenGroupsProperty)
        {
            _state.HiddenGroups.Clear();
            foreach (TypeGroup g in Enum.GetValues<TypeGroup>()) if ((HiddenGroups & (1 << (int)g)) != 0) _state.HiddenGroups.Add(g);
        }
        else if (change.Property == ShowMacProperty) _state.ShowMac = ShowMac;
        else if (change.Property == AnimationsProperty) { _state.Animations = Animations; }
        else if (change.Property == EngineProperty) _fitPending = true;
    }

    // =====================================================================================================
    //  frame pacing
    // =====================================================================================================

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        RequestFrame();
        _slowTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) =>
        {
            if (!Animations && IsEffectivelyVisible) InvalidateVisual();
        });
        _slowTimer.Start();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        _attached = false;
        _slowTimer?.Stop();
        _slowTimer = null;
    }

    private void RequestFrame()
    {
        if (!_attached) return;
        TopLevel.GetTopLevel(this)?.RequestAnimationFrame(_ =>
        {
            if (!_attached) return;
            if (IsEffectivelyVisible && (Animations || _anim is not null || _fitPending)) { Tick(); InvalidateVisual(); }
            RequestFrame();
        });
    }

    private void Tick()
    {
        if (_fitPending && Engine is { } eng && eng.Frame.Snapshot.Nodes.Length > 0 && Bounds.Width > 0)
        {
            // let physics settle a little before the first fit
            if (++_fitSettleFrames > 20) { _fitPending = false; FitAnimated(); }
        }
        if (_anim is { } a)
        {
            float k = 0.16f;
            _state.Zoom += (a.Zoom - _state.Zoom) * k;
            _state.PanX += (a.PanX - _state.PanX) * k;
            _state.PanY += (a.PanY - _state.PanY) * k;
            if (Math.Abs(a.Zoom - _state.Zoom) < 0.002f && Math.Abs(a.PanX - _state.PanX) < 0.5f && Math.Abs(a.PanY - _state.PanY) < 0.5f)
            {
                (_state.Zoom, _state.PanX, _state.PanY) = a;
                _anim = null;
            }
        }
    }

    // =====================================================================================================
    //  rendering
    // =====================================================================================================

    public override void Render(DrawingContext context)
    {
        _state.Width = (float)Bounds.Width;
        _state.Height = (float)Bounds.Height;
        var engine = Engine;
        if (engine is null || Bounds.Width < 1 || Bounds.Height < 1)
        {
            context.FillRectangle(new SolidColorBrush(Color.Parse("#070B14")), new Rect(Bounds.Size));
            return;
        }
        context.Custom(new DrawOp(new Rect(Bounds.Size), _renderer, _state.Clone(), engine, _clock.Elapsed.TotalSeconds));
    }

    private sealed class DrawOp(Rect bounds, GraphRenderer renderer, GraphViewState state, GraphEngine engine, double time) : ICustomDrawOperation
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
            canvas.Save();
            canvas.ClipRect(new SKRect(0, 0, (float)bounds.Width, (float)bounds.Height));
            try
            {
                lock (renderer) renderer.Render(canvas, state, engine.Frame, engine.Events, time, engine.Diagnostics);
            }
            catch (Exception ex) { Debug.WriteLine(ex); }
            canvas.Restore();
        }
    }

    // =====================================================================================================
    //  public API
    // =====================================================================================================

    /// <summary>Re-arms the start-up behaviour: fit as soon as the graph has nodes and the layout had ~20 frames to settle.</summary>
    public void FitWhenSettled()
    {
        _fitPending = true;
        _fitSettleFrames = 0;
        InvalidateVisual();
    }

    /// <summary>Zooms/pans so the whole graph (or the port panels) is visible.</summary>
    public void FitAnimated()
    {
        var target = ComputeFit();
        if (target is not null) _anim = target;
        InvalidateVisual();
    }

    private (float, float, float)? ComputeFit()
    {
        if (Engine is not { } engine || Bounds.Width < 1) return null;
        var frame = engine.Frame;
        var v = new GraphViewState { Width = (float)Bounds.Width, Height = (float)Bounds.Height, Mode = Mode };
        GraphExport.Fit(v, GraphRenderer.ContentBounds(frame.Snapshot, frame.X, frame.Y, Mode), Mode == GraphViewMode.Ports ? 1.6f : 1.4f, topInset: (float)TopInset);
        return (v.Zoom, v.PanX, v.PanY);
    }

    public void ZoomBy(double factor) => ZoomAt(new Point(Bounds.Width / 2, Bounds.Height / 2), factor);

    /// <summary>Renders the graph offscreen to a PNG (for the HTML report).</summary>
    public byte[] RenderToPng(int width, int height)
    {
        if (Engine is not { } engine) return [];
        var s = _state.Clone();
        s.Hovered = null; s.HoveredEdge = null; s.MouseInside = false;
        return GraphExport.RenderPng(engine, s, width, height);
    }

    public void ResetPins() => Engine?.ClearPins();

    // =====================================================================================================
    //  input
    // =====================================================================================================

    private SKPoint World(Point p) => _state.ToWorld((float)p.X, (float)p.Y);

    private Mac? HitNode(Point p)
    {
        var f = _renderer.Output;
        if (f.Mode == GraphViewMode.Ports) return null;
        var w = World(p);
        Mac? best = null;
        float bestD = float.MaxValue;
        var snap = f.Snapshot;
        for (int i = 0; i < snap.Nodes.Length && i < f.X.Length; i++)
        {
            var n = snap.Nodes[i];
            float dx = w.X - f.X[i], dy = w.Y - f.Y[i];
            float d = dx * dx + dy * dy;
            float r = n.Radius + 5;
            bool inBadge = d <= r * r;
            // the label under the badge is also clickable
            bool inLabel = Math.Abs(dx) <= n.LabelW / 2 && dy > n.Radius && dy < n.Radius + 8 + n.LabelH && _state.Zoom >= 0.5f;
            if ((inBadge || inLabel) && d < bestD) { bestD = d; best = n.Mac; }
        }
        return best;
    }

    private (Mac, Mac)? HitEdge(Point p)
    {
        var f = _renderer.Output;
        if (f.Mode == GraphViewMode.Ports) return null;
        var w = World(p);
        float tol = 6f / _state.Zoom;
        (Mac, Mac)? best = null;
        float bestD = tol;
        foreach (var e in f.Snapshot.Edges)
        {
            if (e.A >= f.X.Length || e.B >= f.X.Length) continue;
            var a = new SKPoint(f.X[e.A], f.Y[e.A]);
            var b = new SKPoint(f.X[e.B], f.Y[e.B]);
            var geom = GraphRenderer.Geometry(f.Snapshot, e, a, b, _renderer.TreeBlend);
            // sample the (possibly curved) edge
            var prev = a;
            for (int k = 1; k <= 12; k++)
            {
                var pt = geom.At(k / 12f);
                float d = DistToSegment(w, prev, pt);
                if (d < bestD) { bestD = d; best = (f.Snapshot.Nodes[e.A].Mac, f.Snapshot.Nodes[e.B].Mac); }
                prev = pt;
            }
        }
        return best;
    }

    private static float DistToSegment(SKPoint p, SKPoint a, SKPoint b)
    {
        float dx = b.X - a.X, dy = b.Y - a.Y;
        float l2 = dx * dx + dy * dy;
        float t = l2 == 0 ? 0 : Math.Clamp(((p.X - a.X) * dx + (p.Y - a.Y) * dy) / l2, 0, 1);
        float x = a.X + t * dx - p.X, y = a.Y + t * dy - p.Y;
        return MathF.Sqrt(x * x + y * y);
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        var pt = e.GetCurrentPoint(this);
        if (!pt.Properties.IsLeftButtonPressed) return;
        Focus();
        _anim = null;
        _pressPos = _lastPos = e.GetPosition(this);
        _moved = false;
        _pressNode = Mode == GraphViewMode.Ports ? null : HitNode(_pressPos);
        if (e.ClickCount == 2 && _pressNode is { } dbl)
        {
            Engine?.Unpin(dbl);
            _pressNode = null;
            e.Handled = true;
            return;
        }
        _panning = _pressNode is null;
        e.Pointer.Capture(this);
        e.Handled = true;
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var p = e.GetPosition(this);
        _state.Mouse = new SKPoint((float)p.X, (float)p.Y);
        _state.MouseInside = true;
        if (e.Pointer.Captured == this && (_panning || _pressNode is not null))
        {
            if (Math.Abs(p.X - _pressPos.X) + Math.Abs(p.Y - _pressPos.Y) > 4) _moved = true;
            if (_panning)
            {
                _state.PanX += (float)(p.X - _lastPos.X);
                _state.PanY += (float)(p.Y - _lastPos.Y);
                Cursor = new Cursor(StandardCursorType.SizeAll);
            }
            else if (_pressNode is { } m && _moved && Mode != GraphViewMode.Tree)
            {
                var w = World(p);
                _state.Dragging = m;
                _state.DragWorld = w;
                Engine?.Pin(m, w.X, w.Y);
                Cursor = new Cursor(StandardCursorType.Hand);
            }
            _lastPos = p;
            InvalidateVisual();
            return;
        }

        // hover
        var node = HitNode(p);
        _state.Hovered = node;
        _state.HoveredEdge = node is null ? HitEdge(p) : null;
        Cursor = node is not null ? new Cursor(StandardCursorType.Hand) : Cursor.Default;
        if (!Animations) InvalidateVisual();
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        if (e.Pointer.Captured != this) return;
        e.Pointer.Capture(null);
        if (!_moved)
        {
            if (_pressNode is { } m) SelectedDevice = Engine?.GetDevice(m);
            else if (Mode == GraphViewMode.Ports) SelectPortDevice(e.GetPosition(this));
            else SelectedDevice = null;
        }
        _state.Dragging = null;
        _panning = false;
        _pressNode = null;
        Cursor = Cursor.Default;
        InvalidateVisual();
    }

    private void SelectPortDevice(Point p)
    {
        var w = World(p);
        foreach (var (r, _, port) in _renderer.Output.PortHits)
            if (r.Contains(w) && port.Devices.Count > 0) { SelectedDevice = Engine?.GetDevice(port.Devices[0].Mac); return; }
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        _state.MouseInside = false;
        _state.Hovered = null;
        _state.HoveredEdge = null;
    }

    protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
    {
        base.OnPointerWheelChanged(e);
        ZoomAt(e.GetPosition(this), Math.Pow(1.15, e.Delta.Y));
        e.Handled = true;
    }

    private double _lastPinch = 1;

    private void OnPinch(object? sender, PinchEventArgs e)
    {
        // Scale is cumulative since the gesture started; apply the incremental ratio around the pinch origin
        if (e.Scale <= 0) return;
        double ratio = e.Scale / _lastPinch;
        _lastPinch = e.Scale;
        if (Math.Abs(ratio - 1) > 0.5) { _lastPinch = 1; return; }
        ZoomAt(new Point(e.ScaleOrigin.X * Bounds.Width, e.ScaleOrigin.Y * Bounds.Height), ratio);
        e.Handled = true;
    }

    private void ZoomAt(Point screen, double factor)
    {
        _anim = null;
        var world = World(screen);
        float nz = (float)Math.Clamp(_state.Zoom * factor, 0.2, 5.0);
        _state.Zoom = nz;
        _state.PanX = (float)screen.X - _state.Width / 2 - world.X * nz;
        _state.PanY = (float)screen.Y - _state.Height / 2 - world.Y * nz;
        InvalidateVisual();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        switch (e.Key)
        {
            case Key.F: FitAnimated(); e.Handled = true; break;
            case Key.Escape: SelectedDevice = null; e.Handled = true; break;
            case Key.OemPlus or Key.Add: ZoomBy(1.2); e.Handled = true; break;
            case Key.OemMinus or Key.Subtract: ZoomBy(1 / 1.2); e.Handled = true; break;
        }
    }
}
