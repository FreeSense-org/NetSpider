using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Controls.Graph;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// One place for the UI to reach the diagnostics engine (path monitor, incidents, port health, storm center, Wi-Fi link,
/// AP health, probe agents). Real services are optional (resolved with <c>GetService</c>); in demo mode the simulated
/// <see cref="DemoDiagnostics"/> takes their place. Change events are raised on any thread — consumers throttle them onto
/// the UI thread. Also keeps the spider web's fault/port overlay (<see cref="GraphEngine.Diagnostics"/>) up to date.
/// </summary>
public sealed class DiagnosticsFeed : IDisposable
{
    private readonly DemoDiagnostics _demo;
    private readonly GraphEngine _engine;
    private readonly IDeviceStore _devices;
    private readonly IFrameSource? _frames;
    private readonly IPathMonitor? _path;
    private readonly IIncidentService? _incidents;
    private readonly IPortHealthMonitor? _ports;
    private readonly IStormCenter? _storm;
    private readonly IWifiLinkMonitor? _wifi;
    private readonly IApHealthMonitor? _aps;
    private readonly IProbeAgentHub? _agents;
    private readonly List<IDisposable> _subs = [];
    private readonly List<DiagnosticSignal> _signals = [];
    private readonly object _sync = new();
    private volatile bool _isDemo;
    private readonly INetworkState? _network;

    public DiagnosticsFeed(IServiceProvider sp, DemoDiagnostics demo, GraphEngine engine, IDeviceStore devices, IEventBus bus)
    {
        _demo = demo;
        _engine = engine;
        _devices = devices;
        _frames = sp.GetService<IFrameSource>();
        _network = sp.GetService<INetworkState>();
        _path = Try<IPathMonitor>(sp);
        _incidents = Try<IIncidentService>(sp);
        _ports = Try<IPortHealthMonitor>(sp);
        _storm = Try<IStormCenter>(sp);
        _wifi = Try<IWifiLinkMonitor>(sp);
        _aps = Try<IApHealthMonitor>(sp);
        _agents = Try<IProbeAgentHub>(sp);

        if (_path is not null) _path.Updated += _ => { if (!_isDemo) PathChanged?.Invoke(); };
        if (_incidents is not null) _incidents.IncidentChanged += _ => { if (!_isDemo) OnIncidents(); };
        if (_ports is not null) _ports.Updated += () => { if (!_isDemo) OnPorts(); };
        if (_storm is not null) _storm.Updated += _ => { if (!_isDemo) StormChanged?.Invoke(); };
        if (_wifi is not null) _wifi.Updated += () => { if (!_isDemo) WifiChanged?.Invoke(); };
        if (_aps is not null) _aps.Updated += () => { if (!_isDemo) ApsChanged?.Invoke(); };
        if (_agents is not null) _agents.Updated += () => { if (!_isDemo) AgentsChanged?.Invoke(); };

        demo.Path.Updated += _ => { if (_isDemo) PathChanged?.Invoke(); };
        demo.Incidents.IncidentChanged += _ => { if (_isDemo) OnIncidents(); };
        demo.Ports.Updated += () => { if (_isDemo) OnPorts(); };
        demo.Storm.Updated += _ => { if (_isDemo) StormChanged?.Invoke(); };
        demo.Wifi.Updated += () => { if (_isDemo) WifiChanged?.Invoke(); };
        demo.Aps.Updated += () => { if (_isDemo) ApsChanged?.Invoke(); };
        demo.Agents.Updated += () => { if (_isDemo) AgentsChanged?.Invoke(); };
        demo.SignalsChanged += () => { if (_isDemo) SignalsChanged?.Invoke(); };

        _subs.Add(bus.Subscribe<DiagnosticSignal>(s =>
        {
            // real signals that arrive while the demo is shown (link watcher, Wi-Fi link, ...) are not kept: demo and real never mix
            if (DemoActive) return;
            lock (_sync)
            {
                _signals.Insert(0, s);
                if (_signals.Count > 100) _signals.RemoveAt(_signals.Count - 1);
            }
            if (!_isDemo) SignalsChanged?.Invoke();
        }));
    }

    private static T? Try<T>(IServiceProvider sp) where T : class
    {
        try { return sp.GetService<T>(); }
        catch (Exception ex) { Log.Warning(ex, "Resolving {Service} failed", typeof(T).Name); return null; }
    }

    // ---- source selection ----
    public bool IsDemo => _isDemo;

    /// <summary>
    /// true while the demo is shown or being set up/torn down (<see cref="INetworkState.IsDemo"/> is switched before the
    /// feed). Use this to suppress real-world side effects such as desktop notifications.
    /// </summary>
    public bool DemoActive => _isDemo || _network?.IsDemo == true;

    /// <summary>Forgets the real diagnostic signals collected so far (part of the demo/real reset).</summary>
    public void ClearSignals()
    {
        lock (_sync) _signals.Clear();
        SignalsChanged?.Invoke();
    }

    public void SetDemo(bool on)
    {
        if (on == _isDemo) return;
        _isDemo = on;
        if (on) _demo.Start(); else _demo.Stop();
        UpdateOverlay();
        SourceChanged?.Invoke();
        PathChanged?.Invoke(); IncidentsChanged?.Invoke(); PortsChanged?.Invoke(); StormChanged?.Invoke();
        WifiChanged?.Invoke(); ApsChanged?.Invoke(); AgentsChanged?.Invoke(); SignalsChanged?.Invoke();
    }

    // ---- current sources (null = not available in this build) ----
    public IPathMonitor? Path => _isDemo ? _demo.Path : _path;
    public IIncidentService? Incidents => _isDemo ? _demo.Incidents : _incidents;
    public IPortHealthMonitor? Ports => _isDemo ? _demo.Ports : _ports;
    public IStormCenter? Storm => _isDemo ? _demo.Storm : _storm;
    public IWifiLinkMonitor? Wifi => _isDemo ? _demo.Wifi : _wifi;
    public IApHealthMonitor? Aps => _isDemo ? _demo.Aps : _aps;
    public IProbeAgentHub? Agents => _isDemo ? _demo.Agents : _agents;
    public DemoDiagnostics Demo => _demo;

    /// <summary>The storm-control check needs live capture (the demo simulates it).</summary>
    public bool CaptureRunning => _isDemo || _frames?.IsRunning == true;

    public IReadOnlyList<DiagnosticSignal> Signals
    {
        get
        {
            if (_isDemo) return _demo.Signals;
            lock (_sync) return _signals.ToArray();
        }
    }

    public string NameOf(Mac m) => _devices.TryGet(m, out var d) ? d.DisplayName : m.ToString();
    public Device? Device(Mac m) => _devices.TryGet(m, out var d) ? d : null;

    // ---- change notifications (any thread) ----
    public event Action? SourceChanged;
    public event Action? PathChanged;
    public event Action? IncidentsChanged;
    public event Action? PortsChanged;
    public event Action? StormChanged;
    public event Action? WifiChanged;
    public event Action? ApsChanged;
    public event Action? AgentsChanged;
    public event Action? SignalsChanged;

    private void OnIncidents() { UpdateOverlay(); IncidentsChanged?.Invoke(); }
    private void OnPorts() { UpdateOverlay(); PortsChanged?.Invoke(); }

    /// <summary>Rebuilds the web overlay: ongoing incidents → suspect node + suspect link + dimmed affected devices; port health.</summary>
    public void UpdateOverlay()
    {
        try
        {
            var faults = new List<FaultMark>();
            var affected = new HashSet<Mac>();
            foreach (var inc in Incidents?.Active ?? [])
            {
                foreach (var a in inc.Affected) affected.Add(a);
                if (inc.SuspectDevice is not { } s) continue;
                Mac? up = _devices.TryGet(s, out var d) ? d.UpstreamMac : null;
                faults.Add(new FaultMark(s, up, "suspected"));
            }
            foreach (var f in faults) affected.Remove(f.Suspect);
            var ports = new Dictionary<(Mac, string), PortHealth>();
            foreach (var p in Ports?.Ports ?? []) ports[(p.Switch, p.Name)] = p;
            _engine.Diagnostics = new GraphDiagnostics { Faults = faults, Affected = affected, Ports = ports };
        }
        catch (Exception ex) { Log.Warning(ex, "Updating the diagnostics overlay failed"); }
    }

    public void Dispose()
    {
        foreach (var s in _subs) s.Dispose();
        _demo.Dispose();
    }
}
