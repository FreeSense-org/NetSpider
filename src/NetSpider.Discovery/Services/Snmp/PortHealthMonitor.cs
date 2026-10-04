using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>
/// Polls IF-MIB/EtherLike-MIB counters on every SNMP-speaking device (switches first of all) every
/// <see cref="AppSettings.PortCounterPollSeconds"/> while <see cref="AppSettings.PortCountersEnabled"/>, derives per-port
/// <see cref="PortHealth"/> and publishes <see cref="DiagnosticSignal"/>s (PortDown/Up/Flapping/Errors/DuplexMismatch/
/// SpeedDowngrade) plus matching alerts on transitions. Keeps the latest health and 60 samples of history per port.
/// </summary>
public sealed class PortHealthMonitor : IPortHealthMonitor, IStartable, IDisposable
{
    private const string SignalSource = "port-health";
    public const int MaxParallelPolls = 4;
    public static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan MinPollInterval = TimeSpan.FromSeconds(10);

    private readonly ILogger<PortHealthMonitor> _log;
    private readonly IDeviceStore _devices;
    private readonly INetworkState _network;
    private readonly IEventBus _bus;
    private readonly IAlertService _alerts;
    private readonly ISettingsStore _settingsStore;

    private readonly ConcurrentDictionary<(Mac Switch, int IfIndex), PortHealthTracker> _trackers = new();
    private readonly ConcurrentDictionary<Mac, Session> _sessions = new();
    private readonly Dictionary<(Mac, int, SignalKind), DateTimeOffset> _lastAlert = new();
    private readonly object _sync = new();
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly CancellationTokenSource _cts = new();
    private PortHealth[] _ports = [];
    private Task? _loop;
    private bool _started;

    private sealed class Session
    {
        public SnmpClient? Client;
        public IPAddress? Ip;
        public int Failures;
        public DateTimeOffset RetryAfter;
        public readonly SemaphoreSlim Gate = new(1, 1);
    }

    public PortHealthMonitor(ILogger<PortHealthMonitor> log, IDeviceStore devices, INetworkState network, IEventBus bus, IAlertService alerts, ISettingsStore settings)
    {
        _log = log;
        _devices = devices;
        _network = network;
        _bus = bus;
        _alerts = alerts;
        _settingsStore = settings;
    }

    public IReadOnlyList<PortHealth> Ports => Volatile.Read(ref _ports);
    public event Action? Updated;
    public DateTimeOffset? LastPoll { get; private set; }

    private AppSettings Settings => _settingsStore.Settings;

    public PortHealth? Get(Mac switchMac, string port)
    {
        var t = FindTracker(switchMac, port);
        return t?.Latest;
    }

    /// <summary>Up to <see cref="PortHealthTracker.HistorySize"/> recent health samples for the port (oldest first).</summary>
    public IReadOnlyList<PortHealth> History(Mac switchMac, string port) => FindTracker(switchMac, port)?.History ?? [];

    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
        }
        _settingsStore.Saved += OnSettingsSaved;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    public void Dispose()
    {
        _settingsStore.Saved -= OnSettingsSaved;
        try { _cts.Cancel(); } catch { }
    }

    private void OnSettingsSaved()
    {
        try { _wake.Release(); } catch { }
    }

    // =========================================================================================================
    //  Poll loop
    // =========================================================================================================

    private async Task LoopAsync(CancellationToken ct)
    {
        // give the first scan a moment to find SNMP devices
        await WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        while (!ct.IsCancellationRequested)
        {
            var interval = Interval();
            try
            {
                var due = LastPoll is { } last ? last + interval : DateTimeOffset.MinValue;
                if (Settings.PortCountersEnabled && !_network.IsDemo && DateTimeOffset.Now >= due)
                    await PollAllAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "port counter poll failed"); }

            var wait = LastPoll is { } lp ? lp + Interval() - DateTimeOffset.Now : Interval();
            if (wait < TimeSpan.FromSeconds(1)) wait = TimeSpan.FromSeconds(1);
            await WaitAsync(wait, ct).ConfigureAwait(false);
        }
    }

    private TimeSpan Interval()
    {
        var s = TimeSpan.FromSeconds(Math.Max(1, Settings.PortCounterPollSeconds));
        return s < MinPollInterval ? MinPollInterval : s;
    }

    private async Task WaitAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await _wake.WaitAsync(delay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
    }

    /// <summary>Devices worth polling: anything that answered SNMP, plus every switch with a port table.</summary>
    public IReadOnlyList<Device> Targets()
    {
        var switches = _network.SwitchPorts.Select(p => p.Switch).ToHashSet();
        return _devices.All
            .Where(d => !d.Mac.IsMulticast && !d.Has(DeviceFlags.Inferred) && d.PrimaryIPv4 is not null)
            .Where(d => switches.Contains(d.Mac) || d.GetProperty("snmp.sysObjectID") is not null || d.GetProperty("snmp.community") is not null)
            .ToList();
    }

    public async Task PollAllAsync(CancellationToken ct)
    {
        var targets = Targets();
        LastPoll = DateTimeOffset.Now;
        if (targets.Count == 0) return;
        using var gate = new SemaphoreSlim(MaxParallelPolls);
        var tasks = targets.Select(async d =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try { await PollDeviceAsync(d, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex) { _log.LogDebug(ex, "port poll {Device}", d); }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        Publish();
    }

    private async Task PollDeviceAsync(Device device, CancellationToken ct)
    {
        var session = _sessions.GetOrAdd(device.Mac, _ => new Session());
        if (DateTimeOffset.Now < session.RetryAfter) return;
        await session.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var client = await ClientAsync(device, session, ct).ConfigureAwait(false);
            if (client is null) { Fail(session); return; }
            var poll = await PortCounterPoller.PollAsync(client, device.Mac, ct).ConfigureAwait(false);
            if (poll is null) { session.Client = null; Fail(session); return; }
            session.Failures = 0;
            Apply(device.Mac, poll);
        }
        finally { session.Gate.Release(); }
    }

    private void Fail(Session s)
    {
        s.Failures++;
        var backoff = TimeSpan.FromSeconds(Interval().TotalSeconds * Math.Pow(2, Math.Min(5, s.Failures)));
        if (backoff > TimeSpan.FromMinutes(30)) backoff = TimeSpan.FromMinutes(30);
        s.RetryAfter = DateTimeOffset.Now + backoff;
    }

    /// <summary>Reuses the established session; otherwise tries the device's known community first, then the configured credentials.</summary>
    private async Task<SnmpClient?> ClientAsync(Device device, Session session, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return null;
        if (session.Client is not null && Equals(session.Ip, ip)) return session.Client;
        var s = Settings;
        var communities = new List<string>();
        if (device.GetProperty("snmp.community") is { Length: > 0 } known) communities.Add(known);
        communities.AddRange(s.SnmpCommunities.Where(c => !communities.Contains(c)));
        try
        {
            session.Client = await SnmpClient.EstablishAsync(ip, communities, s.SnmpTimeoutMs, s.SnmpV3User, s.SnmpV3AuthPassword, s.SnmpV3PrivPassword,
                s.SnmpV3AuthProtocol, s.SnmpV3PrivProtocol, ct).ConfigureAwait(false);
            session.Ip = ip;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "SNMP establish {Ip}", ip); session.Client = null; }
        return session.Client;
    }

    /// <summary>
    /// On-demand read of one port's counters (bypasses the poll interval). Used by the Storm Center's storm-control check.
    /// Returns null when the device has no working SNMP session or the port is unknown.
    /// </summary>
    public async Task<PortCounterSample?> ReadPortNowAsync(Mac switchMac, string port, CancellationToken ct)
    {
        try
        {
            var tracker = FindTracker(switchMac, port);
            if (tracker is null || !_devices.TryGet(switchMac, out var device)) return null;
            var session = _sessions.GetOrAdd(switchMac, _ => new Session());
            var client = await ClientAsync(device, session, ct).ConfigureAwait(false);
            if (client is null) return null;
            var (sample, _) = await PortCounterPoller.ReadPortAsync(client, switchMac, tracker.IfIndex, tracker.Name ?? port, ct).ConfigureAwait(false);
            return sample;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "read port {Switch} {Port}", switchMac, port); return null; }
    }

    // =========================================================================================================
    //  Deltas → health → signals/alerts
    // =========================================================================================================

    /// <summary>Feeds one device poll through the per-port trackers and publishes signals/alerts for transitions.</summary>
    public void Apply(Mac switchMac, PortCounterPoll poll)
    {
        double warn = Settings.PortErrorsPerMinWarn;
        foreach (var sample in poll.Samples)
        {
            var tracker = _trackers.GetOrAdd((switchMac, sample.IfIndex), k => new PortHealthTracker(k.Switch, k.IfIndex));
            PortUpdate update;
            lock (tracker) update = tracker.Update(sample, poll.SysUpTime, warn);
            foreach (var e in update.Events) Emit(switchMac, update.Health, e);
        }
    }

    /// <summary>Rebuilds <see cref="Ports"/> and raises <see cref="Updated"/>.</summary>
    public void Publish()
    {
        var ports = _trackers.Values.Select(t => t.Latest).OfType<PortHealth>()
            .OrderBy(p => p.Switch.Value).ThenBy(p => p.IfIndex).ToArray();
        Volatile.Write(ref _ports, ports);
        try { Updated?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "port health Updated handler"); }
    }

    private void Emit(Mac sw, PortHealth h, PortEvent e)
    {
        string swName = _devices.TryGet(sw, out var d) ? d.DisplayName : sw.ToString();
        string summary = $"{swName} port {h.Name}: {e.Summary}";
        try { _bus.Publish(DiagnosticSignal.Create(e.Kind, SignalSource, summary, sw, h.Name, e.Weight)); }
        catch (Exception ex) { _log.LogDebug(ex, "publish port signal"); }

        lock (_lastAlert)
        {
            var key = (sw, h.IfIndex, e.Kind);
            var now = DateTimeOffset.Now;
            if (_lastAlert.TryGetValue(key, out var last) && now - last < AlertCooldown) return;
            _lastAlert[key] = now;
        }
        // the alert service keys its cooldown by (kind, source); per-port cooldown is handled above, so pass zero
        try { _alerts.Raise(Alert.Create(e.Severity, AlertKindFor(e.Kind), TitleFor(e.Kind), summary, sw), TimeSpan.Zero); }
        catch (Exception ex) { _log.LogDebug(ex, "raise port alert"); }
    }

    /// <summary>
    /// Maps port signals onto existing alert kinds. Requested Core additions (PortErrors, PortFlapping, PortDown,
    /// DuplexMismatch, SpeedDowngrade) would replace these at merge.
    /// </summary>
    public static AlertKind AlertKindFor(SignalKind kind) => kind switch
    {
        SignalKind.PortErrors => AlertKind.PortErrors,
        SignalKind.PortFlapping => AlertKind.PortFlapping,
        SignalKind.PortDown => AlertKind.PortDown,
        SignalKind.PortDuplexMismatch => AlertKind.DuplexMismatch,
        SignalKind.PortSpeedDowngrade => AlertKind.SpeedDowngrade,
        _ => AlertKind.Info,
    };

    public static string TitleFor(SignalKind kind) => kind switch
    {
        SignalKind.PortDown => "Switch port down",
        SignalKind.PortUp => "Switch port up",
        SignalKind.PortFlapping => "Switch port flapping",
        SignalKind.PortErrors => "Switch port errors",
        SignalKind.PortDuplexMismatch => "Duplex mismatch suspected",
        SignalKind.PortSpeedDowngrade => "Switch port speed downgrade",
        _ => "Switch port",
    };

    private PortHealthTracker? FindTracker(Mac switchMac, string port)
    {
        if (string.IsNullOrWhiteSpace(port)) return null;
        PortHealthTracker? byIndex = null;
        foreach (var ((sw, idx), t) in _trackers)
        {
            if (sw != switchMac) continue;
            if (string.Equals(t.Name, port, StringComparison.OrdinalIgnoreCase)) return t;
            if (byIndex is null && int.TryParse(port, out var n) && n == idx) byIndex = t;
        }
        return byIndex;
    }
}
