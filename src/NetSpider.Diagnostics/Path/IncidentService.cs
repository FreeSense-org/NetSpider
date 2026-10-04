using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>
/// Fault locator: collects every <see cref="DiagnosticSignal"/> from the event bus, path updates from
/// <see cref="IPathMonitor"/> and device online→offline transitions, groups what happens within
/// <see cref="CorrelationWindow"/> into one <see cref="Incident"/> with a root cause from <see cref="FaultRules"/>, keeps it
/// updated while ongoing and closes it once the condition has been clear for <see cref="ClearAfter"/>. New incidents raise
/// an alert (suspect MAC as source), optionally dump the capture ring buffer, and are persisted when an
/// <see cref="IIncidentRepository"/> is registered.
/// </summary>
public sealed class IncidentService : IIncidentService, IStartable, IDisposable
{
    public static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan ClearAfter = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan HistoryKeep = TimeSpan.FromMinutes(30);
    public const int MaxIncidents = 500;
    public const int MaxEvidence = 40;

    private readonly IEventBus _bus;
    private readonly IAlertService _alerts;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly ISettingsStore _settings;
    private readonly ILogger<IncidentService> _log;
    private readonly IPathMonitor? _pathMonitor;
    private readonly IFrameSource? _frames;
    private readonly IIncidentRepository? _repo;
    private readonly TimeProvider _time;
    private readonly object _sync = new();
    private readonly List<DiagnosticSignal> _history = new();
    private readonly Dictionary<Mac, DeviceState> _states = new();
    private readonly Dictionary<Mac, DateTimeOffset> _offlineSince = new();
    private readonly List<Incident> _incidents = new();
    private Incident? _current;
    private DateTimeOffset? _clearSince;
    private NetworkPath? _path;
    private IDisposable? _sub;
    private ITimer? _timer;
    private bool _started;
    private readonly INetworkState? _network;

    /// <summary>While the demo network is shown, the real fault locator ignores all input (demo devices, signals) and never opens incidents.</summary>
    private bool Paused => _network?.IsDemo == true;

    public IncidentService(IEventBus bus, IAlertService alerts, IDeviceStore devices, ITopologyStore topology, ISettingsStore settings,
        ILogger<IncidentService> log, IPathMonitor? pathMonitor = null, IFrameSource? frames = null, IIncidentRepository? repository = null,
        TimeProvider? time = null, INetworkState? network = null)
    {
        _network = network;
        _bus = bus;
        _alerts = alerts;
        _devices = devices;
        _topology = topology;
        _settings = settings;
        _log = log;
        _pathMonitor = pathMonitor;
        _frames = frames;
        _repo = repository;
        _time = time ?? TimeProvider.System;
    }

    public IReadOnlyList<Incident> Incidents { get { lock (_sync) return _incidents.ToArray(); } }
    public IReadOnlyList<Incident> Active { get { lock (_sync) return _incidents.Where(i => i.Ongoing).ToArray(); } }
    public event Action<Incident>? IncidentChanged;

    /// <summary>Hooks the inputs. <paramref name="autoTick"/> = false lets tests drive <see cref="Tick"/> by hand.</summary>
    public void Start() => Start(autoTick: true);

    public void Start(bool autoTick)
    {
        if (_started) return;
        _started = true;
        _sub = _bus.Subscribe<DiagnosticSignal>(Ingest);
        _devices.DeviceChanged += OnDeviceChanged;
        _devices.DeviceRemoved += OnDeviceRemoved;
        foreach (var d in _devices.All) lock (_sync) _states[d.Mac] = d.State;
        if (_pathMonitor is not null)
        {
            _pathMonitor.Updated += OnPath;
            if (_pathMonitor.Path is { } p) OnPath(p);
        }
        if (autoTick) _timer = _time.CreateTimer(_ => SafeTick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        if (_repo is not null) _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        try
        {
            var loaded = await _repo!.LoadIncidentsAsync(MaxIncidents).ConfigureAwait(false);
            lock (_sync)
            {
                var known = _incidents.Select(i => i.Id).ToHashSet();
                // incidents left open by a previous session cannot be ongoing any more
                var add = loaded.Where(i => !known.Contains(i.Id)).Select(i => i.End is null ? i with { End = i.Start } : i);
                _incidents.InsertRange(0, add.OrderBy(i => i.Start));
                Trim();
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Loading incidents failed"); }
    }

    // ------------------------------------------------------------------------------------------- inputs

    /// <summary>Adds a signal (normally via the event bus).</summary>
    public void Ingest(DiagnosticSignal s)
    {
        if (Paused) return;
        lock (_sync)
        {
            _history.Add(s);
            var cutoff = _time.GetLocalNow() - HistoryKeep;
            if (_history.Count > 5000 || (_history.Count > 0 && _history[0].Time < cutoff))
                _history.RemoveAll(x => x.Time < cutoff);
            if (_history.Count > 5000) _history.RemoveRange(0, _history.Count - 5000);
        }
    }

    private void OnPath(NetworkPath p) { lock (_sync) _path = p; }

    /// <summary>Sets the latest path (normally from <see cref="IPathMonitor.Updated"/>).</summary>
    public void SetPath(NetworkPath? p) { lock (_sync) _path = p; }

    private void OnDeviceChanged(Device d, string? reason)
    {
        try
        {
            if (Paused || d.Has(DeviceFlags.ThisHost)) return;
            var state = d.State;
            lock (_sync)
            {
                var had = _states.TryGetValue(d.Mac, out var old);
                _states[d.Mac] = state;
                if (!had || old == state) return;
                if (state == DeviceState.Offline) _offlineSince[d.Mac] = _time.GetLocalNow();
                else if (old == DeviceState.Offline) _offlineSince.Remove(d.Mac);
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "incident device handler"); }
    }

    private void OnDeviceRemoved(Mac m)
    {
        lock (_sync) { _states.Remove(m); _offlineSince.Remove(m); }
    }

    // ------------------------------------------------------------------------------------------- evaluation

    private void SafeTick()
    {
        try { Tick(); }
        catch (Exception ex) { _log.LogWarning(ex, "Incident evaluation failed"); }
    }

    /// <summary>One correlation step: evaluate the rules, open/update/close the current incident.</summary>
    public void Tick()
    {
        if (Paused) return;
        var now = _time.GetLocalNow();
        Incident? opened = null, changed = null;
        lock (_sync)
        {
            var windowStart = (_current?.Start ?? now) - CorrelationWindow;
            var active = SignalActivity.Active(_history, now);
            var unreachable = _offlineSince.Where(kv => kv.Value >= windowStart).Select(kv => kv.Key).ToList();
            bool pathTrouble = _path?.Hops.Any(h => h.Health == HopHealth.Down) == true;
            if (_current is null && active.Count == 0 && unreachable.Count == 0 && !pathTrouble) return;

            var all = _devices.All;
            var snapshot = new FaultSnapshot(now, active, _history.Where(x => x.Time >= windowStart).ToList(), _path, unreachable,
                TopologyTree.Build(_topology.Links, all), all.Select(NodeInfo.From).GroupBy(n => n.Mac).ToDictionary(g => g.Key, g => g.First()));
            var verdict = FaultRules.Evaluate(snapshot);

            if (_current is null)
            {
                if (verdict is null) return;
                var starts = snapshot.Window.Where(x => x.Time >= now - CorrelationWindow).Select(x => x.Time)
                    .Concat(unreachable.Select(m => _offlineSince[m]));
                var start = starts.DefaultIfEmpty(now).Min();
                _current = new Incident(Guid.NewGuid(), start, null, verdict.Severity, verdict.Category, verdict.Title, verdict.RootCause,
                    verdict.Confidence, verdict.SuspectDevice, verdict.SuspectPort, verdict.SuspectLink, verdict.Affected, Cap(verdict.Evidence), null);
                _clearSince = null;
                _incidents.Add(_current);
                Trim();
                opened = _current;
            }
            else if (verdict is not null)
            {
                _clearSince = null;
                var merged = _current with
                {
                    Severity = (AlertSeverity)Math.Max((int)_current.Severity, (int)verdict.Severity),
                    Category = verdict.Category,
                    Title = verdict.Title,
                    RootCause = verdict.RootCause,
                    Confidence = verdict.Confidence,
                    SuspectDevice = verdict.SuspectDevice,
                    SuspectPort = verdict.SuspectPort,
                    SuspectLink = verdict.SuspectLink,
                    Affected = _current.Affected.Concat(verdict.Affected).Distinct().ToList(),
                    Evidence = Cap(_current.Evidence.Concat(verdict.Evidence).Distinct()),
                };
                if (!SameContent(merged, _current)) changed = Replace(merged);
            }
            else
            {
                _clearSince ??= now;
                if (now - _clearSince.Value >= ClearAfter)
                {
                    changed = Replace(_current with { End = _clearSince.Value });
                    _current = null;
                    _clearSince = null;
                }
            }
        }

        if (opened is not null) OnOpened(opened);
        else if (changed is not null) Emit(changed);
    }

    private Incident Replace(Incident updated)
    {
        int i = _incidents.FindIndex(x => x.Id == updated.Id);
        if (i >= 0) _incidents[i] = updated; else _incidents.Add(updated);
        if (_current?.Id == updated.Id) _current = updated;
        return updated;
    }

    private void OnOpened(Incident inc)
    {
        _log.LogWarning("Incident: {Title} — {Root} ({Conf:P0})", inc.Title, inc.RootCause, inc.Confidence);
        string? pcap = null;
        try
        {
            if (_settings.Settings.DumpPcapOnAlert && _frames is { IsRunning: true }) pcap = _frames.DumpRecent("incident");
        }
        catch (Exception ex) { _log.LogDebug(ex, "incident pcap dump failed"); }
        if (pcap is not null)
            lock (_sync) inc = Replace(inc with { PcapPath = pcap });

        try
        {
            var kind = inc.Category switch
            {
                IncidentCategory.Storm => AlertKind.BroadcastStorm,
                IncidentCategory.Loop => AlertKind.L2Loop,
                IncidentCategory.Isp => AlertKind.InternetDown,
                _ => AlertKind.Incident,
            };
            var details = $"{inc.RootCause} (confidence {inc.Confidence:P0})" + (inc.Evidence.Count > 0 ? $". Evidence: {string.Join("; ", inc.Evidence.Take(5))}" : "");
            _alerts.Raise(Alert.Create(inc.Severity, kind, inc.Title, details, inc.SuspectDevice), TimeSpan.Zero);
        }
        catch (Exception ex) { _log.LogDebug(ex, "incident alert failed"); }
        Emit(inc);
    }

    private void Emit(Incident inc)
    {
        Persist(inc);
        try { IncidentChanged?.Invoke(inc); } catch (Exception ex) { _log.LogDebug(ex, "incident subscriber failed"); }
    }

    private void Persist(Incident inc)
    {
        if (_repo is null) return;
        _ = Task.Run(async () =>
        {
            try { await _repo.SaveIncidentAsync(inc).ConfigureAwait(false); }
            catch (Exception ex) { _log.LogWarning(ex, "Saving incident failed"); }
        });
    }

    private static bool SameContent(Incident a, Incident b) =>
        a.Severity == b.Severity && a.Category == b.Category && a.Title == b.Title && a.RootCause == b.RootCause &&
        Math.Abs(a.Confidence - b.Confidence) < 0.001 && a.SuspectDevice == b.SuspectDevice && a.SuspectPort == b.SuspectPort &&
        a.SuspectLink == b.SuspectLink && a.Affected.SequenceEqual(b.Affected) && a.Evidence.SequenceEqual(b.Evidence);

    private static IReadOnlyList<string> Cap(IEnumerable<string> evidence) => evidence.Distinct().Take(MaxEvidence).ToList();

    private void Trim()
    {
        if (_incidents.Count > MaxIncidents) _incidents.RemoveRange(0, _incidents.Count - MaxIncidents);
    }

    public void Clear()
    {
        lock (_sync)
        {
            _incidents.Clear();
            _current = null;
            _clearSince = null;
            _history.Clear();
            _offlineSince.Clear();
        }
    }

    public void Dispose()
    {
        _sub?.Dispose();
        _timer?.Dispose();
        _devices.DeviceChanged -= OnDeviceChanged;
        _devices.DeviceRemoved -= OnDeviceRemoved;
        if (_pathMonitor is not null) _pathMonitor.Updated -= OnPath;
    }
}
