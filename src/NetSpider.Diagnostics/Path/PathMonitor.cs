using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.LocalLink;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>
/// Path Doctor: keeps the hop chain from this PC to the internet (<see cref="PathBuilder"/>) and probes every hop each
/// <see cref="AppSettings.PathIntervalSeconds"/> while <see cref="AppSettings.PathMonitorEnabled"/>. Per hop it tracks
/// health (down after <see cref="AppSettings.HopDownRounds"/> misses, degraded on loss/RTT spikes or ARP-only answers),
/// RTT, jitter, loss and added latency, publishes the path via <see cref="Updated"/> and HopDown/HopUp/HopDegraded
/// <see cref="DiagnosticSignal"/>s on the event bus. Independent of full scans and packet capture.
/// </summary>
public sealed class PathMonitor : IPathMonitor, IStartable, IDisposable
{
    public static readonly TimeSpan TopologyDebounce = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ResolveEvery = TimeSpan.FromMinutes(5);

    private readonly ISettingsStore _settingsStore;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly IEventBus _bus;
    private readonly IHopProber _prober;
    private readonly IFrameSource? _frames;
    private readonly ILogger<PathMonitor> _log;
    private readonly PathBuilder _builder;
    private readonly Func<AdapterInfo?> _adapter;
    private readonly object _sync = new();
    private readonly Dictionary<string, HopTracker> _trackers = new();
    /// <summary>Published health/note per hop key (tracker health after the "later hops answer" correction).</summary>
    private readonly Dictionary<string, (HopHealth Health, string? Note)> _shown = new();
    private readonly Timer _debounce;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private NetworkPath? _template;
    private NetworkPath? _path;
    private volatile bool _rebuildRequested = true;
    private IReadOnlyList<TracerouteHop>? _lastTrace;
    private (string Host, IPAddress? Ip, DateTimeOffset At)? _resolved;
    private bool _started;

    public PathMonitor(ISettingsStore settingsStore, IDeviceStore devices, ITopologyStore topology, INetworkState network, IEventBus bus,
        IHopProber prober, ILogger<PathMonitor> log, IFrameSource? frames = null, Func<AdapterInfo?>? adapterProvider = null)
    {
        _settingsStore = settingsStore;
        _devices = devices;
        _topology = topology;
        _network = network;
        _bus = bus;
        _prober = prober;
        _frames = frames;
        _log = log;
        _adapter = adapterProvider ?? DefaultAdapter;
        _builder = new PathBuilder(devices, topology, network, () => _settingsStore.Settings, () => _adapter());
        _debounce = new Timer(_ => SafeRebuild(), null, Timeout.Infinite, Timeout.Infinite);
    }

    private AppSettings Settings => _settingsStore.Settings;

    public bool IsRunning => _loop is { IsCompleted: false };
    public NetworkPath? Path { get { lock (_sync) return _path; } }
    public event Action<NetworkPath>? Updated;

    private AdapterInfo? _cachedAdapter;
    private DateTimeOffset _cachedAt;

    private AdapterInfo? DefaultAdapter()
    {
        if (_frames is { IsRunning: true, Adapter: { } a }) return a;
        if (_cachedAdapter is null || DateTimeOffset.Now - _cachedAt > TimeSpan.FromSeconds(30))
        {
            _cachedAdapter = LocalAdapters.ToAdapterInfo(LocalAdapters.FindBest()) ?? _cachedAdapter;
            _cachedAt = DateTimeOffset.Now;
        }
        return _cachedAdapter;
    }

    public void Start()
    {
        if (_started) return;
        _started = true;
        _settingsStore.Saved += ApplySettings;
        _topology.Changed += OnTopologyChanged;
        _network.Changed += OnNetworkChanged;
        if (_frames is not null)
        {
            _frames.Started += OnCaptureStarted;
            _frames.Stopped += OnCaptureStopped;
        }
        ApplySettings();
    }

    public void ApplySettings()
    {
        bool enable = Settings.PathMonitorEnabled;
        if (enable && !IsRunning)
        {
            _cts = new CancellationTokenSource();
            _rebuildRequested = true;
            _loop = Task.Run(() => LoopAsync(_cts.Token));
            _log.LogInformation("Path monitor started");
        }
        else if (!enable && IsRunning)
        {
            StopLoop();
            _log.LogInformation("Path monitor stopped");
        }
        else if (enable) _rebuildRequested = true; // targets may have changed
    }

    private void OnTopologyChanged()
    {
        try { _debounce.Change(TopologyDebounce, Timeout.InfiniteTimeSpan); } catch (ObjectDisposedException) { }
    }

    private void OnNetworkChanged(string what)
    {
        if (what is "wan" or "wifi") _rebuildRequested = true;
        else if (what == "path")
        {
            var trace = _network.InternetPath;
            if (!SameTrace(trace, _lastTrace)) _rebuildRequested = true;
        }
    }

    private void OnCaptureStarted(AdapterInfo a) => _rebuildRequested = true;
    private void OnCaptureStopped() => _rebuildRequested = true;

    private static bool SameTrace(IReadOnlyList<TracerouteHop>? a, IReadOnlyList<TracerouteHop>? b)
    {
        if (a is null || b is null) return a is null && b is null;
        return a.Select(h => h.Address?.ToString()).SequenceEqual(b.Select(h => h.Address?.ToString()));
    }

    private void SafeRebuild()
    {
        // demo devices/topology must never become the real path (and must never be probed on the real network)
        if (_network.IsDemo) { _rebuildRequested = true; return; }
        try { Rebuild(); }
        catch (Exception ex) { _log.LogWarning(ex, "Path rebuild failed"); }
    }

    /// <summary>Recomputes the hop chain now (keeps per-hop history for hops that survive) and publishes it.</summary>
    public void Rebuild()
    {
        _rebuildRequested = false;
        _lastTrace = _network.InternetPath;
        var template = _builder.Build();
        NetworkPath composed;
        lock (_sync)
        {
            _template = template;
            var keys = template.Hops.Select(KeyOf).ToHashSet();
            foreach (var stale in _trackers.Keys.Where(k => !keys.Contains(k)).ToList()) { _trackers.Remove(stale); _shown.Remove(stale); }
            composed = Compose(template, DateTimeOffset.Now);
            _path = composed;
        }
        _log.LogDebug("Path rebuilt: {Hops}", string.Join(" → ", template.Hops.Select(h => h.Name)));
        Publish(composed);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            try
            {
                if (_network.IsDemo) _rebuildRequested = true; // paused while the demo network is shown; rebuild from real data afterwards
                else
                {
                    if (_rebuildRequested || _template is null) Rebuild();
                    await ProbeOnceAsync(ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Path monitor round failed"); }

            var wait = Interval - Stopwatch.GetElapsedTime(started);
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private TimeSpan Interval => TimeSpan.FromSeconds(Math.Clamp(Settings.PathIntervalSeconds, 1, 300));

    /// <summary>Probes every hop once (in parallel), updates health, publishes the path and transition signals.</summary>
    public async Task ProbeOnceAsync(CancellationToken ct = default)
    {
        NetworkPath? template;
        lock (_sync) template = _template;
        if (template is null) { Rebuild(); lock (_sync) template = _template; }
        if (template is null) return;

        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(Interval.TotalMilliseconds * 0.75, 500, 2000));
        var adapter = _adapter();
        var tasks = template.Hops.Select(h => ProbeHopAsync(h, adapter, timeout, ct)).ToArray();
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var signals = new List<DiagnosticSignal>();
        NetworkPath composed;
        lock (_sync)
        {
            if (!ReferenceEquals(template, _template)) return; // rebuilt meanwhile; next round probes the new path
            int downRounds = Math.Max(1, Settings.HopDownRounds);
            var trackers = new HopTracker[template.Hops.Count];
            for (int i = 0; i < template.Hops.Count; i++)
            {
                var key = KeyOf(template.Hops[i]);
                if (!_trackers.TryGetValue(key, out var tr)) _trackers[key] = tr = new HopTracker();
                tr.Record(results[i], downRounds, template.Hops[i].Probe);
                trackers[i] = tr;
            }
            var shown = Effective(trackers.Select(t => (t.Health, t.Note, t.EverAnswered)).ToList());
            for (int i = 0; i < template.Hops.Count; i++)
            {
                var hop = template.Hops[i];
                var key = KeyOf(hop);
                var before = _shown.TryGetValue(key, out var b) ? b.Health : HopHealth.Unknown;
                _shown[key] = shown[i];
                if (Transition(hop, key, before, shown[i].Health, shown[i].Note) is { } s) signals.Add(s);
            }
            composed = Compose(template, DateTimeOffset.Now);
            _path = composed;
        }
        Publish(composed);
        foreach (var s in signals)
        {
            _log.LogInformation("Path: {Kind} {Summary}", s.Kind, s.Summary);
            try { _bus.Publish(s); } catch (Exception ex) { _log.LogDebug(ex, "signal subscriber failed"); }
        }
    }

    private async Task<HopProbeResult> ProbeHopAsync(PathHop hop, AdapterInfo? adapter, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            switch (hop.Probe)
            {
                case HopProbe.ArpIcmp:
                case HopProbe.IcmpOnly:
                {
                    var ip = hop.Ip ?? (hop.Role == HopRole.InternetTarget ? await ResolveTargetAsync(ct).ConfigureAwait(false) : null);
                    if (ip is null) return new HopProbeResult(null, false, null);
                    return await _prober.ProbeAsync(ip, hop.Probe == HopProbe.ArpIcmp, timeout, ct).ConfigureAwait(false);
                }
                case HopProbe.Anchors:
                {
                    var ips = new List<IPAddress>();
                    foreach (var m in hop.Anchors)
                        if (_devices.TryGet(m, out var d) && d.PrimaryIPv4 is { } ip) ips.Add(ip);
                    if (ips.Count == 0) return new HopProbeResult(null, false, null);
                    var rs = await Task.WhenAll(ips.Select(ip => _prober.ProbeAsync(ip, OnSubnet(ip, adapter), timeout, ct))).ConfigureAwait(false);
                    var ok = rs.Where(r => r.Answered).ToList();
                    bool? arp = rs.Any(r => r.ArpOk is not null) ? rs.Any(r => r.ArpOk == true) : null;
                    bool? icmp = rs.Any(r => r.IcmpOk is not null) ? rs.Any(r => r.IcmpOk == true) : null;
                    return new HopProbeResult(arp, icmp, ok.Select(r => r.RttMs).Where(x => x is not null).DefaultIfEmpty().Min(), ok.Count, ips.Count);
                }
                default:
                    return HopProbeResult.NotProbed;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Probe of hop {Hop} failed", hop.Name);
            return new HopProbeResult(null, false, null);
        }
    }

    private static bool OnSubnet(IPAddress ip, AdapterInfo? adapter) =>
        adapter is not null && ip.AddressFamily == AddressFamily.InterNetwork && adapter.IPv4.Any(a => IpUtil.InSubnet(ip, a.Address, a.PrefixLength));

    private async Task<IPAddress?> ResolveTargetAsync(CancellationToken ct)
    {
        var host = Settings.InternetTargets.FirstOrDefault(t => t.Enabled && !string.IsNullOrWhiteSpace(t.Host))?.Host.Trim();
        if (host is null) return PathBuilder.DefaultTarget;
        if (IPAddress.TryParse(host, out var lit)) return lit;
        if (_resolved is { } r && r.Host == host && r.Ip is not null && DateTimeOffset.Now - r.At < ResolveEvery) return r.Ip;
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct).WaitAsync(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            var ip = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
            _resolved = (host, ip, DateTimeOffset.Now);
            return ip;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return _resolved is { } old && old.Host == host ? old.Ip : null; }
    }

    /// <summary>
    /// A hop that does not answer while hops behind it do is not a break: routers often drop or rate-limit ICMP to
    /// themselves. Such hops are shown Unknown (never answered) or Degraded (stopped answering) instead of Down.
    /// </summary>
    public static IReadOnlyList<(HopHealth Health, string? Note)> Effective(IReadOnlyList<(HopHealth Health, string? Note, bool EverAnswered)> raw)
    {
        var result = new (HopHealth, string?)[raw.Count];
        for (int i = 0; i < raw.Count; i++)
        {
            var (h, note, ever) = raw[i];
            bool laterAnswers = false;
            for (int j = i + 1; j < raw.Count && !laterAnswers; j++) laterAnswers = raw[j].Health is HopHealth.Up or HopHealth.Degraded;
            if (h == HopHealth.Down && laterAnswers)
                result[i] = ever
                    ? (HopHealth.Degraded, "stopped answering pings, but hops behind it answer — ICMP filtered/rate-limited, traffic passes")
                    : (HopHealth.Unknown, "does not answer pings (hops behind it do) — common for routers that filter ICMP");
            else result[i] = (h, note);
        }
        return result;
    }

    private DiagnosticSignal? Transition(PathHop hop, string key, HopHealth before, HopHealth after, string? note)
    {
        if (before == after) return null;
        string who = hop.Ip is { } ip ? $"{hop.Name} ({ip})" : hop.Name;
        string src = $"path:{key}";
        if (after == HopHealth.Down)
            return DiagnosticSignal.Create(SignalKind.HopDown, src, $"{who} is down — {note}", hop.Mac, hop.PortIn, 0.8);
        if (before == HopHealth.Down && after is HopHealth.Up or HopHealth.Degraded)
            return DiagnosticSignal.Create(SignalKind.HopUp, src, $"{who} answers again", hop.Mac, hop.PortIn, 0.3);
        if (after == HopHealth.Degraded && before is HopHealth.Up or HopHealth.Unknown)
            return DiagnosticSignal.Create(SignalKind.HopDegraded, src, $"{who} degraded — {note}", hop.Mac, hop.PortIn, 0.4);
        if (after == HopHealth.Up && before == HopHealth.Degraded)
            return DiagnosticSignal.Create(SignalKind.HopUp, src, $"{who} healthy again", hop.Mac, hop.PortIn, 0.2);
        return null;
    }

    /// <summary>Template hops + tracker state → published hops (health, RTT, jitter, loss, added latency, notes).</summary>
    private NetworkPath Compose(NetworkPath template, DateTimeOffset now)
    {
        var hops = new List<PathHop>(template.Hops.Count);
        double? prevUpRtt = null;
        foreach (var h in template.Hops)
        {
            if (!_trackers.TryGetValue(KeyOf(h), out var tr))
            {
                hops.Add(h);
                if (h.Probe == HopProbe.Self) prevUpRtt = 0;
                continue;
            }
            var (health, trNote) = _shown.TryGetValue(KeyOf(h), out var sh) ? sh : (tr.Health, tr.Note);
            double? rtt = tr.LastRtt;
            double? added = null;
            if (rtt is { } r && health is HopHealth.Up or HopHealth.Degraded)
            {
                added = prevUpRtt is { } p ? Math.Max(0, r - p) : r;
                prevUpRtt = r;
            }
            var note = trNote ?? h.Note;
            if (trNote is not null && h.Note is not null && trNote != h.Note) note = $"{h.Note}; {trNote}";
            hops.Add(h with
            {
                Health = health,
                RttMs = rtt is { } x ? Math.Round(x, 3) : null,
                AddedMs = added is { } a ? Math.Round(a, 3) : null,
                LossPercent = Math.Round(tr.LossPercent, 1),
                JitterMs = tr.Jitter is { } j ? Math.Round(j, 3) : null,
                ArpOk = tr.ArpOk,
                IcmpOk = tr.IcmpOk,
                Note = note,
                Recent = tr.Recent,
            });
        }
        return new NetworkPath(template.Built, now, template.Medium, hops);
    }

    public static string KeyOf(PathHop h) =>
        h.Role == HopRole.ThisHost ? "self"
        : h.Mac is { } m ? m.ToString()
        : h.Ip is { } ip ? ip.ToString()
        : $"{h.Role}:{h.Name}";

    private void Publish(NetworkPath p)
    {
        try { Updated?.Invoke(p); } catch (Exception ex) { _log.LogDebug(ex, "Path subscriber failed"); }
    }

    private void StopLoop()
    {
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        _cts?.Dispose();
        _cts = null;
        _loop = null;
    }

    public void Dispose()
    {
        _settingsStore.Saved -= ApplySettings;
        _topology.Changed -= OnTopologyChanged;
        _network.Changed -= OnNetworkChanged;
        if (_frames is not null)
        {
            _frames.Started -= OnCaptureStarted;
            _frames.Stopped -= OnCaptureStopped;
        }
        StopLoop();
        _debounce.Dispose();
    }
}
