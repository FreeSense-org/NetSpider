using System.Collections.Concurrent;
using System.Diagnostics;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.App.Controls.Graph;

/// <summary>
/// Owns the graph data pipeline: store events → throttled (~4 Hz) immutable snapshots → physics thread (~60 Hz) →
/// double-buffered <see cref="LayoutFrame"/>s that the render thread reads. Also collects transient events
/// (packet activity, new devices, alerts) into a lock-free queue for the renderer's effects.
/// </summary>
public sealed class GraphEngine : IDisposable
{
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly IAlertService _alerts;
    private readonly IEventBus _bus;
    private readonly AppSettings _settings;
    private readonly ForceLayout _layout = new();
    private readonly ConcurrentQueue<Action<ForceLayout>> _commands = new();
    private readonly List<IDisposable> _subs = [];
    private readonly ConcurrentQueue<GraphEvent> _events = new();
    private readonly object _buildSync = new();

    private volatile GraphSnapshot _snapshot = GraphSnapshot.Empty;
    private volatile LayoutFrame _frame = LayoutFrame.Empty;
    private volatile bool _dirty = true;
    private int _version;
    private Timer? _throttle;
    private Thread? _physics;
    private volatile bool _running;
    private readonly AutoResetEvent _wake = new(false);

    public GraphEngine(IDeviceStore devices, ITopologyStore topology, INetworkState network, IAlertService alerts, IEventBus bus, AppSettings settings)
    {
        _devices = devices; _topology = topology; _network = network; _alerts = alerts; _bus = bus; _settings = settings;
    }

    public GraphSnapshot Snapshot => _snapshot;
    public LayoutFrame Frame => _frame;
    public AppSettings Settings => _settings;
    public Device? GetDevice(Mac mac) => _devices.TryGet(mac, out var d) ? d : null;
    public ConcurrentQueue<GraphEvent> Events => _events;
    /// <summary>Fault highlights and switch-port health drawn over the topology (set by the UI's diagnostics feed; never null).</summary>
    public GraphDiagnostics Diagnostics { get => _diagnostics; set => _diagnostics = value ?? GraphDiagnostics.Empty; }
    private volatile GraphDiagnostics _diagnostics = GraphDiagnostics.Empty;
    /// <summary>Raised (on a thread-pool thread) after a new snapshot was built.</summary>
    public event Action<GraphSnapshot>? SnapshotChanged;

    /// <summary>Subscribes to the stores and starts the 4 Hz snapshot throttle.</summary>
    public void Attach()
    {
        _devices.DeviceAdded += OnDeviceAdded;
        _devices.DeviceChanged += OnDeviceChanged;
        _devices.DeviceRemoved += OnDeviceRemoved;
        _topology.Changed += MarkDirty;
        _network.Changed += OnNetworkChanged;
        _alerts.AlertRaised += OnAlert;
        _subs.Add(_bus.Subscribe<PacketActivity>(OnPacket));
        _throttle = new Timer(_ => { if (_dirty) Rebuild(); }, null, 100, 250);
    }

    public void MarkDirty() => _dirty = true;

    private long _addWindowStart;
    private int _addsInWindow;

    private void OnDeviceAdded(Device d)
    {
        _dirty = true;
        // a bulk load (scan start, demo, persistence) shouldn't fire dozens of "new device" ripples at once
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _addWindowStart) > 2000) { Interlocked.Exchange(ref _addWindowStart, now); _addsInWindow = 0; }
        if (Interlocked.Increment(ref _addsInWindow) <= 3) _events.Enqueue(new GraphEvent(GraphEventKind.NewDevice, d.Mac));
    }
    private void OnDeviceChanged(Device d, string? reason) => _dirty = true;
    private void OnDeviceRemoved(Mac m) => _dirty = true;
    private void OnNetworkChanged(string what) { if (what is "fdb" or "switchports") _dirty = true; }
    private void OnAlert(Alert a)
    {
        if (a.Source is { } m) _events.Enqueue(new GraphEvent(GraphEventKind.Alert, m, a.Kind.ToString(), a.Severity));
    }
    private void OnPacket(PacketActivity p)
    {
        if (_events.Count < 2000) _events.Enqueue(new GraphEvent(GraphEventKind.Packet, p.Source, p.Protocol));
    }

    /// <summary>Builds a new snapshot now (synchronously) and hands it to the physics thread.</summary>
    public GraphSnapshot Rebuild()
    {
        lock (_buildSync)
        {
            _dirty = false;
            GraphSnapshot snap;
            try { snap = GraphBuilder.Build(_devices, _topology, _network, _settings, Interlocked.Increment(ref _version)); }
            catch (Exception ex) { Debug.WriteLine(ex); return _snapshot; }
            _snapshot = snap;
            if (_running) { _commands.Enqueue(l => l.SetSnapshot(snap)); _wake.Set(); }
            else { _layout.SetSnapshot(snap); _frame = _layout.Publish(); }
            try { SnapshotChanged?.Invoke(snap); } catch { }
            return snap;
        }
    }

    /// <summary>Runs the force layout synchronously (headless snapshot mode).</summary>
    public void RunLayout(int iterations)
    {
        if (_running) throw new InvalidOperationException("Physics thread is running");
        _layout.SetSnapshot(_snapshot);
        _layout.Run(iterations);
        _frame = _layout.Publish();
    }

    public void StartPhysics()
    {
        if (_running) return;
        _running = true;
        _layout.SetSnapshot(_snapshot);
        _physics = new Thread(PhysicsLoop) { IsBackground = true, Name = "NetSpider graph physics", Priority = ThreadPriority.BelowNormal };
        _physics.Start();
    }

    public void StopPhysics()
    {
        _running = false;
        _wake.Set();
        _physics?.Join(500);
        _physics = null;
    }

    private void PhysicsLoop()
    {
        var sw = Stopwatch.StartNew();
        const double stepMs = 1000.0 / 60.0;
        double next = 0;
        while (_running)
        {
            bool cmd = false;
            while (_commands.TryDequeue(out var c)) { try { c(_layout); } catch (Exception ex) { Debug.WriteLine(ex); } cmd = true; }
            bool moved;
            try { moved = _layout.Step(); }
            catch (Exception ex) { Debug.WriteLine(ex); moved = false; }
            if (moved || cmd) _frame = _layout.Publish();

            if (!moved && !cmd)
            {
                // asleep: wait for a command / snapshot instead of spinning
                _wake.WaitOne(200);
                next = sw.Elapsed.TotalMilliseconds;
                continue;
            }
            next += stepMs;
            double wait = next - sw.Elapsed.TotalMilliseconds;
            if (wait > 1) Thread.Sleep((int)wait);
            else if (wait < -100) next = sw.Elapsed.TotalMilliseconds;
        }
    }

    // ---- commands from the UI thread ----
    public void Pin(Mac mac, float x, float y) { Post(l => l.Pin(mac, x, y)); }
    public void Unpin(Mac mac) { Post(l => l.Unpin(mac)); }
    public void ClearPins() { Post(l => l.ClearPins()); }
    public void Reheat(float a = 0.5f) { Post(l => l.Reheat(a)); }

    /// <summary>
    /// Demo ↔ real switch: drops queued effects (packet rain, ripples, alert pulses), forgets every node position and user pin,
    /// clears the diagnostics overlay and rebuilds the snapshot from the (already reset) stores.
    /// </summary>
    public void ResetLayout()
    {
        while (_events.TryDequeue(out _)) { }
        _diagnostics = GraphDiagnostics.Empty;
        lock (_buildSync)
        {
            _snapshot = GraphSnapshot.Empty;
            Post(l => l.Reset());
        }
        Rebuild();
    }

    private void Post(Action<ForceLayout> a)
    {
        if (_running) { _commands.Enqueue(a); _wake.Set(); }
        else { a(_layout); _frame = _layout.Publish(); }
    }

    public void Dispose()
    {
        StopPhysics();
        _throttle?.Dispose();
        _devices.DeviceAdded -= OnDeviceAdded;
        _devices.DeviceChanged -= OnDeviceChanged;
        _devices.DeviceRemoved -= OnDeviceRemoved;
        _topology.Changed -= MarkDirty;
        _network.Changed -= OnNetworkChanged;
        _alerts.AlertRaised -= OnAlert;
        foreach (var s in _subs) s.Dispose();
        _subs.Clear();
    }
}
