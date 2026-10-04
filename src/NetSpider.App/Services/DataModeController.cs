using NetSpider.App.Controls.Graph;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// The one place that switches between the simulated demo network and real monitoring, so the two never mix:
/// <list type="bullet">
/// <item><b>Enter demo:</b> <see cref="INetworkState.IsDemo"/> is set first (persistence, notifications and every real
/// background monitor stop writing), then every store, the network state, the diagnostic signals, the graph layout and the
/// view caches are cleared, and only then is the demo built. Nothing real is kept ("snapshot nothing, clear everything").</item>
/// <item><b>Exit demo:</b> the demo timers are stopped and drained, every demo artifact is removed with the same reset,
/// <see cref="INetworkState.IsDemo"/> is cleared and the real path monitor is rebuilt from real data. The caller restarts
/// monitoring on the returned adapter when monitoring was running before the demo.</item>
/// </list>
/// Real devices are not reloaded from the database on exit: the app never preloads history into the live store (the
/// persistence service only uses it to recognise returning devices), so real data repopulates from capture/discovery.
/// Call on the UI thread; <see cref="ViewsReset"/> is raised synchronously so view models can drop their caches.
/// </summary>
public sealed class DataModeController
{
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly IAlertService _alerts;
    private readonly INetworkState _network;
    private readonly DemoNetwork _demo;
    private readonly DiagnosticsFeed _feed;
    private readonly GraphEngine _engine;
    private readonly object _sync = new();
    private bool _active;

    public DataModeController(IDeviceStore devices, ITopologyStore topology, IAlertService alerts, INetworkState network, DemoNetwork demo,
        DiagnosticsFeed feed, GraphEngine engine)
    {
        _devices = devices;
        _topology = topology;
        _alerts = alerts;
        _network = network;
        _demo = demo;
        _feed = feed;
        _engine = engine;
    }

    /// <summary>true between <see cref="EnterDemo"/> and <see cref="ExitDemo"/>.</summary>
    public bool IsDemo { get { lock (_sync) return _active; } }

    /// <summary>Adapter that was being monitored when the demo started (monitoring resumes on it when the demo ends).</summary>
    public AdapterInfo? ResumeAdapter { get; private set; }

    /// <summary>Raised (on the calling thread) after every reset: view models drop cached rows, histories, toasts and badges.</summary>
    public event Action? ViewsReset;

    /// <summary>
    /// Switches to the demo network. The caller stops monitoring/scanning first and passes the adapter that was monitored
    /// (null when monitoring wasn't running). Idempotent.
    /// </summary>
    public void EnterDemo(AdapterInfo? resumeMonitoringOn = null)
    {
        lock (_sync)
        {
            if (_active) return;
            _active = true;
            ResumeAdapter = resumeMonitoringOn;
            _network.IsDemo = true;   // gate first: nothing real may be written from here on (and nothing demo gets persisted)
            _demo.Stop();
            ResetAllData();           // drop every real artifact: the demo is shown on its own
            _demo.Build();
            _demo.Start();
            _feed.SetDemo(true);      // after the build: the simulated diagnostics name the demo devices
        }
        ResetAllViews();
        Log.Information("Demo network on: {Devices} devices, {Links} links, {Alerts} alerts", _devices.Count, _topology.Links.Count, _alerts.Alerts.Count);
    }

    /// <summary>
    /// Leaves the demo: stops it, removes every demo artifact and re-opens the stores to real data. Returns the adapter to
    /// resume monitoring on (null when monitoring wasn't running before the demo). Idempotent.
    /// </summary>
    public AdapterInfo? ExitDemo()
    {
        AdapterInfo? resume;
        lock (_sync)
        {
            if (!_active) return null;
            _demo.Stop();             // waits for a running tick so nothing demo arrives after the reset
            _feed.SetDemo(false);
            _demo.Clear();
            ResetAllData();           // still gated (IsDemo) while clearing
            _network.IsDemo = false;
            _active = false;
            resume = ResumeAdapter;
            ResumeAdapter = null;
            try { _feed.Path?.Rebuild(); } // the real path monitor paused during the demo; recompute it from real data now
            catch (Exception ex) { Log.Warning(ex, "Rebuilding the real path after the demo failed"); }
        }
        ResetAllViews();
        Log.Information("Demo network off: {Devices} devices, {Links} links, {Alerts} alerts left", _devices.Count, _topology.Links.Count, _alerts.Alerts.Count);
        return resume;
    }

    /// <summary>Clears every shared store: devices, links + pair latencies, alerts, network-wide state, real diagnostic signals.</summary>
    public void ResetAllData()
    {
        _devices.Clear();
        _topology.Clear();
        _alerts.Clear();
        _network.Reset();
        _feed.ClearSignals();
    }

    /// <summary>Forgets graph positions/pins/effects, refreshes the diagnostics overlay and tells the view models to reset.</summary>
    public void ResetAllViews()
    {
        try { _engine.ResetLayout(); }
        catch (Exception ex) { Log.Warning(ex, "Resetting the graph layout failed"); }
        _feed.UpdateOverlay();
        ViewsReset?.Invoke();
    }

    /// <summary>Counts for the debug switch and tests: devices, links, alerts, demo MACs present in the device store.</summary>
    public (int Devices, int Links, int Alerts, int DemoDevices, int DemoAlerts, int Segments) Counts()
    {
        var demo = _demo.BuiltMacs.ToHashSet();
        var devices = _devices.All;
        var alerts = _alerts.Alerts;
        return (devices.Count, _topology.Links.Count, alerts.Count, devices.Count(d => demo.Contains(d.Mac)),
            alerts.Count(a => a.Source is { } m && demo.Contains(m)), _network.Segments.Count);
    }
}
