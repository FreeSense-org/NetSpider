using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Internet;

/// <summary>
/// Opt-in internet monitor (<see cref="AppSettings.InternetMonitorEnabled"/>, off by default). Every interval it pings
/// all enabled targets in parallel. The internet is <c>Online</c> when all targets answer, <c>Degraded</c> when some
/// fail or latency exceeds the warning threshold, and <c>Offline</c> after N consecutive rounds where every target
/// failed. Outages are recorded and alerted (down = Critical, restored = Info with the duration).
/// </summary>
public sealed class InternetMonitor : IInternetMonitor, IStartable, IDisposable
{
    private const int HistoryLength = 300;
    private static readonly TimeSpan ResolveEvery = TimeSpan.FromMinutes(5);

    private readonly ISettingsStore _settingsStore;
    private readonly IAlertService _alerts;
    private readonly ILogger<InternetMonitor> _log;
    private readonly IEventBus? _bus;
    private readonly object _sync = new();
    private readonly List<TargetState> _targets = new();
    private readonly List<InternetOutage> _outages = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private InternetStatus _status = InternetStatus.Disabled;
    private InternetState _state = InternetState.Disabled;
    private DateTimeOffset _stateSince = DateTimeOffset.Now;
    private int _allDownRounds;
    private long _rounds, _onlineRounds;

    private readonly INetworkState? _network;

    public InternetMonitor(ISettingsStore settingsStore, IAlertService alerts, ILogger<InternetMonitor> log, IEventBus? bus = null, INetworkState? network = null)
    {
        _network = network;
        _settingsStore = settingsStore;
        _alerts = alerts;
        _log = log;
        _bus = bus;
    }

    /// <summary>While the demo network is shown the monitor keeps measuring, but never alerts or signals (only demo alerts are shown then).</summary>
    private bool Quiet => _network?.IsDemo == true;

    private void Raise(Alert alert, TimeSpan cooldown)
    {
        if (!Quiet) _alerts.Raise(alert, cooldown);
    }

    private void Signal(SignalKind kind, string summary)
    {
        if (Quiet) return;
        try { _bus?.Publish(DiagnosticSignal.Create(kind, "internet-monitor", summary, weight: kind == SignalKind.InternetDown ? 0.7 : 0.3)); }
        catch (Exception ex) { _log.LogDebug(ex, "Internet signal subscriber failed"); }
    }

    private AppSettings Settings => _settingsStore.Settings;

    public bool IsRunning => _loop is { IsCompleted: false };
    public InternetStatus Status { get { lock (_sync) return _status; } }
    public event Action<InternetStatus>? Updated;

    public void Start()
    {
        _settingsStore.Saved += ApplySettings;
        ApplySettings();
    }

    public void ApplySettings()
    {
        lock (_sync)
        {
            var wanted = Settings.InternetTargets
                .Where(t => t.Enabled && !string.IsNullOrWhiteSpace(t.Host))
                .Select(t => (Name: string.IsNullOrWhiteSpace(t.Name) ? t.Host.Trim() : t.Name.Trim(), Host: t.Host.Trim()))
                .ToList();
            // keep history for targets that are still configured
            var keep = _targets.Where(t => wanted.Any(w => w.Host.Equals(t.Host, StringComparison.OrdinalIgnoreCase))).ToList();
            _targets.Clear();
            foreach (var w in wanted)
            {
                var existing = keep.FirstOrDefault(t => t.Host.Equals(w.Host, StringComparison.OrdinalIgnoreCase));
                if (existing is not null) { existing.Name = w.Name; _targets.Add(existing); }
                else _targets.Add(new TargetState(w.Name, w.Host));
            }
        }

        bool enable = Settings.InternetMonitorEnabled && _targets.Count > 0;
        if (enable && !IsRunning)
        {
            _cts = new CancellationTokenSource();
            SetState(InternetState.Starting);
            _loop = Task.Run(() => LoopAsync(_cts.Token));
            _log.LogInformation("Internet monitor started ({Count} targets)", _targets.Count);
        }
        else if (!enable && IsRunning)
        {
            StopLoop();
            SetState(InternetState.Disabled);
            _log.LogInformation("Internet monitor stopped");
        }
        Publish();
    }

    private void StopLoop()
    {
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        _cts?.Dispose();
        _cts = null;
        _loop = null;
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            try { await RoundAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Internet monitor round failed"); }

            var interval = TimeSpan.FromSeconds(Math.Clamp(Settings.InternetIntervalSeconds, 1, 300));
            var wait = interval - Stopwatch.GetElapsedTime(started);
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task RoundAsync(CancellationToken ct)
    {
        TargetState[] targets;
        lock (_sync) targets = _targets.ToArray();
        if (targets.Length == 0) return;

        var timeout = TimeSpan.FromSeconds(Math.Clamp(Settings.InternetIntervalSeconds, 1, 2));
        await Task.WhenAll(targets.Select(t => ProbeAsync(t, timeout, ct))).ConfigureAwait(false);

        int up = targets.Count(t => t.Up);
        bool slow = targets.Any(t => t.Up && t.LastMs > Settings.InternetLatencyWarnMs);
        _rounds++;
        if (up > 0) _onlineRounds++;

        if (up == 0)
        {
            _allDownRounds++;
            if (_allDownRounds >= Math.Max(1, Settings.InternetOutageRounds) && _state != InternetState.Offline) GoOffline(targets);
            else if (_state is InternetState.Starting or InternetState.Online) SetState(InternetState.Degraded);
        }
        else
        {
            _allDownRounds = 0;
            if (_state == InternetState.Offline) Restore();
            var next = up == targets.Length && !slow ? InternetState.Online : InternetState.Degraded;
            if (next == InternetState.Degraded && _state == InternetState.Online)
            {
                var bad = targets.Where(t => !t.Up || t.LastMs > Settings.InternetLatencyWarnMs).Select(t => t.Up ? $"{t.Name} {t.LastMs:0} ms" : $"{t.Name} down");
                Raise(Alert.Create(AlertSeverity.Warning, AlertKind.InternetDegraded, "Internet degraded", string.Join(", ", bad)), TimeSpan.FromMinutes(10));
            }
            SetState(next);
        }
        Publish();
    }

    private async Task ProbeAsync(TargetState t, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            if (t.Address is null || DateTimeOffset.Now - t.Resolved > ResolveEvery)
            {
                if (IPAddress.TryParse(t.Host, out var literal)) t.Address = literal;
                else
                {
                    var addrs = await Dns.GetHostAddressesAsync(t.Host, ct).WaitAsync(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
                    t.Address = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
                }
                t.Resolved = DateTimeOffset.Now;
                if (t.Address is null) throw new InvalidOperationException("no address");
            }

            using var ping = new Ping();
            long t0 = Stopwatch.GetTimestamp();
            var reply = await ping.SendPingAsync(t.Address, timeout, new byte[32], new PingOptions(128, false), ct).ConfigureAwait(false);
            double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
            if (reply.Status == IPStatus.Success)
            {
                if (reply.RoundtripTime > 0 && ms > reply.RoundtripTime + 1) ms = reply.RoundtripTime;
                t.Record(ms, null);
            }
            else t.Record(null, reply.Status.ToString());
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            t.Address = t.Address is not null && IPAddress.TryParse(t.Host, out _) ? t.Address : null; // re-resolve names next round
            t.Record(null, ex is SocketException or TimeoutException or InvalidOperationException ? "cannot resolve host" : ex.Message);
        }
    }

    private void GoOffline(TargetState[] targets)
    {
        var start = targets.Select(t => t.DownSince).Where(d => d is not null).Select(d => d!.Value).DefaultIfEmpty(DateTimeOffset.Now).Min();
        lock (_sync) _outages.Add(new InternetOutage(start, null));
        SetState(InternetState.Offline);
        Raise(Alert.Create(AlertSeverity.Critical, AlertKind.InternetDown, "Internet is down",
            $"None of {targets.Length} ping targets answered ({string.Join(", ", targets.Select(t => t.Host))}) since {start:HH:mm:ss}."), TimeSpan.Zero);
        Signal(SignalKind.InternetDown, $"Internet down: none of {targets.Length} ping targets answer ({string.Join(", ", targets.Select(t => t.Host))}) since {start:HH:mm:ss}");
    }

    private void Restore()
    {
        InternetOutage? closed = null;
        lock (_sync)
        {
            int i = _outages.FindLastIndex(o => o.End is null);
            if (i >= 0) { closed = _outages[i] with { End = DateTimeOffset.Now }; _outages[i] = closed; }
            if (_outages.Count > 200) _outages.RemoveRange(0, _outages.Count - 200);
        }
        var d = closed?.Duration ?? TimeSpan.Zero;
        Raise(Alert.Create(AlertSeverity.Info, AlertKind.InternetRestored, "Internet restored",
            $"Connectivity is back after {FormatDuration(d)} (down since {closed?.Start:HH:mm:ss})."), TimeSpan.Zero);
        Signal(SignalKind.InternetUp, $"Internet restored after {FormatDuration(d)}");
    }

    private void SetState(InternetState s)
    {
        if (_state == s) return;
        _state = s;
        _stateSince = DateTimeOffset.Now;
    }

    private void Publish()
    {
        InternetStatus status;
        lock (_sync)
        {
            var targets = _targets.Select(t => t.Snapshot()).ToList();
            double uptime = _rounds == 0 ? 100 : 100.0 * _onlineRounds / _rounds;
            var best = targets.Where(t => t.Up && t.LastMs is not null).Select(t => t.LastMs!.Value).DefaultIfEmpty().Min();
            status = new InternetStatus(_state, _stateSince, targets, _outages.ToList(), uptime,
                targets.Any(t => t.Up && t.LastMs is not null) ? best : null, DateTimeOffset.Now);
            _status = status;
        }
        try { Updated?.Invoke(status); } catch (Exception ex) { _log.LogDebug(ex, "Internet status subscriber failed"); }
    }

    public static string FormatDuration(TimeSpan d) =>
        d.TotalHours >= 1 ? $"{(int)d.TotalHours}h {d.Minutes}m" : d.TotalMinutes >= 1 ? $"{d.Minutes}m {d.Seconds}s" : $"{Math.Max(1, (int)d.TotalSeconds)}s";

    public void Dispose()
    {
        _settingsStore.Saved -= ApplySettings;
        StopLoop();
    }

    private sealed class TargetState(string name, string host)
    {
        private readonly LatencyStats _stats = new();
        private readonly Queue<double?> _recent = new();
        public string Name { get; set; } = name;
        public string Host { get; } = host;
        public IPAddress? Address { get; set; }
        public DateTimeOffset Resolved { get; set; } = DateTimeOffset.MinValue;
        public bool Up { get; private set; }
        public double? LastMs { get; private set; }
        public DateTimeOffset? DownSince { get; private set; }
        public string? Error { get; private set; }

        public void Record(double? ms, string? error)
        {
            lock (_recent)
            {
                _stats.Add(LatencyKind.Icmp, ms);
                _recent.Enqueue(ms);
                while (_recent.Count > HistoryLength) _recent.Dequeue();
                LastMs = ms;
                Error = error;
                if (ms is not null) { Up = true; DownSince = null; }
                else { if (Up || DownSince is null) DownSince = DateTimeOffset.Now; Up = false; }
            }
        }

        public InternetTargetStatus Snapshot()
        {
            lock (_recent)
                return new InternetTargetStatus(Name, Host, Address, Up, LastMs, _stats.Summarize(LatencyKind.Icmp, 60), _recent.ToArray(), DownSince, Error);
        }
    }
}
