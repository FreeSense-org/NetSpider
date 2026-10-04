using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Wifi;

/// <summary>
/// This host's Wi-Fi link telemetry. While <see cref="AppSettings.WifiLinkMonitorEnabled"/> is on it samples the connected
/// interface every second (SSID/BSSID, RSSI, quality, PHY, rates, channel) and pings the AP's management IP (radio hop) and the
/// adapter gateway (wired backhaul). WLAN ACM/MSM notifications become <see cref="WifiEvent"/>s; connects, disconnects, auth
/// failures, roams (BSSID changes) and sustained weak signal are published as <see cref="DiagnosticSignal"/>s on the event bus.
/// </summary>
public sealed class WifiLinkMonitor : IWifiLinkMonitor, IStartable, IDisposable
{
    public const int HistoryLength = 3600;
    public const int EventLength = 500;
    public const string SignalSource = "wifi-link";
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan PingTimeout = TimeSpan.FromMilliseconds(800);
    private static readonly TimeSpan GatewayRefresh = TimeSpan.FromSeconds(15);

    private readonly ISettingsStore _settings;
    private readonly IEventBus _bus;
    private readonly ILogger<WifiLinkMonitor> _log;
    private readonly IServiceProvider? _services;
    private readonly IWlanLinkApi _api;
    private readonly Func<IPAddress, TimeSpan, CancellationToken, Task<double?>> _ping;
    private readonly object _sync = new();
    private readonly Queue<WifiLinkSample> _history = new();
    private readonly Queue<WifiEvent> _events = new();
    private readonly ConcurrentQueue<WlanNotification> _pending = new();
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly WeakSignalDetector _weak = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _available;
    private bool _started;
    private bool _disposed;
    private WifiLinkSample? _current;
    private Mac? _lastBssid;
    private int _lastRssi;
    private string? _lastSsid;
    private bool _lastConnected;
    private uint? _lastQualityEvent;
    private (Guid Itf, IPAddress? Gw, DateTimeOffset At)? _gateway;

    public WifiLinkMonitor(ISettingsStore settings, IEventBus bus, ILogger<WifiLinkMonitor> log, IServiceProvider? services = null)
        : this(settings, bus, log, services, new WlanLinkApi(), null) { }

    internal WifiLinkMonitor(ISettingsStore settings, IEventBus bus, ILogger<WifiLinkMonitor> log, IServiceProvider? services,
        IWlanLinkApi api, Func<IPAddress, TimeSpan, CancellationToken, Task<double?>>? ping)
    {
        _settings = settings;
        _bus = bus;
        _log = log;
        _services = services;
        _api = api;
        _ping = ping ?? DefaultPingAsync;
        _api.Notification += OnNotification;
    }

    public bool Available { get { lock (_sync) return _available; } }
    public WifiLinkSample? Current { get { lock (_sync) return _current; } }
    public IReadOnlyList<WifiLinkSample> History { get { lock (_sync) return _history.ToArray(); } }
    public IReadOnlyList<WifiEvent> Events { get { lock (_sync) return _events.ToArray(); } }
    public bool IsRunning => _loop is { IsCompleted: false };
    /// <summary>Last WLAN status/error text (service not running, no interface, ...).</summary>
    public string? Status { get; private set; }
    public event Action? Updated;

    public void Start()
    {
        if (_started) return;
        _started = true;
        _settings.Saved += ApplySettings;
        ApplySettings();
    }

    public void ApplySettings()
    {
        if (_disposed) return;
        bool enable = _settings.Settings.WifiLinkMonitorEnabled;
        if (enable && !IsRunning)
        {
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            _loop = Task.Run(() => LoopAsync(ct));
            _log.LogInformation("Wi-Fi link monitor started");
        }
        else if (!enable && IsRunning)
        {
            StopLoop();
            _log.LogInformation("Wi-Fi link monitor stopped");
        }
    }

    private void StopLoop()
    {
        try { _cts?.Cancel(); } catch { }
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
            TimeSpan wait = SampleInterval;
            try { wait = await TickAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogDebug(ex, "Wi-Fi link sample failed"); }

            var remaining = wait - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero) continue;
            try { await _wake.WaitAsync(remaining, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>One sampling round; returns the delay until the next one.</summary>
    private async Task<TimeSpan> TickAsync(CancellationToken ct)
    {
        if (!_api.Open())
        {
            SetAvailable(false, _api.Status);
            return TimeSpan.FromSeconds(30);
        }
        var ifs = _api.Interfaces();
        if (ifs.Count == 0)
        {
            SetAvailable(false, "No wireless LAN interface found.");
            DrainNotifications();
            return TimeSpan.FromSeconds(10);
        }
        SetAvailable(true, _api.Status);
        DrainNotifications();

        var itf = ifs.FirstOrDefault(i => i.State == Native.WlanNative.wlan_interface_state_connected) ?? ifs[0];
        var raw = _api.Query(itf.Id);
        if (raw is null) return SampleInterval;

        double? apRtt = null, gwRtt = null;
        if (raw.Connected)
        {
            var apIp = raw.Bssid is { } b ? FindApIp(b) : null;
            var gw = GatewayOf(itf.Id);
            var apTask = apIp is null ? Task.FromResult<double?>(null) : SafePingAsync(apIp, ct);
            var gwTask = gw is null ? Task.FromResult<double?>(null) : gw.Equals(apIp) ? apTask : SafePingAsync(gw, ct);
            await Task.WhenAll(apTask, gwTask).ConfigureAwait(false);
            apRtt = apTask.Result;
            gwRtt = gwTask.Result;
        }
        else _gateway = null;

        DrainNotifications(); // notifications that arrived during the pings belong before this sample
        ProcessSample(raw, apRtt, gwRtt, DateTimeOffset.Now);
        return SampleInterval;
    }

    private void SetAvailable(bool available, string? status)
    {
        bool changed;
        lock (_sync) { changed = _available != available; _available = available; }
        Status = status;
        if (changed)
        {
            _log.LogInformation(available ? "Wi-Fi link monitor: WLAN interface available" : "Wi-Fi link monitor: {Status}", status);
            RaiseUpdated();
        }
    }

    // ------------------------------------------------------------------ notifications

    private void OnNotification(WlanNotification n)
    {
        // runs on a WLAN service thread: only queue and wake the sampler
        _pending.Enqueue(n);
        while (_pending.Count > 1000 && _pending.TryDequeue(out _)) { }
        try { _wake.Release(); } catch { }
    }

    private void DrainNotifications()
    {
        while (_pending.TryDequeue(out var n))
        {
            try { ProcessNotification(n); }
            catch (Exception ex) { _log.LogDebug(ex, "Wi-Fi notification handling failed"); }
        }
    }

    internal void ProcessNotification(WlanNotification n)
    {
        var kind = n.Kind;
        switch (kind)
        {
            case WlanNotificationKind.Ignored:
                return;
            case WlanNotificationKind.SignalQualityChange:
                // frequent: only record moves of ≥10 points
                if (n.SignalQuality is { } q && (_lastQualityEvent is not { } last || Math.Abs((int)q - (int)last) >= 10))
                {
                    _lastQualityEvent = q;
                    AddEvent(new WifiEvent(n.Time, "SignalQuality", n.Ssid ?? _lastSsid, n.Bssid ?? _lastBssid, $"Signal quality {q}%"));
                }
                return;
        }

        var (name, signal) = WlanCodes.Map(kind, n.ReasonCode);
        string? reason = n.ReasonCode != WlanCodes.ReasonSuccess || kind is WlanNotificationKind.ConnectFailed or WlanNotificationKind.Disconnected
            ? _api.ReasonToString(n.ReasonCode) : null;
        var ssid = n.Ssid ?? _lastSsid;
        var bssid = n.Bssid ?? (kind is WlanNotificationKind.Disconnected or WlanNotificationKind.MsmDisconnected ? _lastBssid : null);
        AddEvent(new WifiEvent(n.Time, name, ssid, bssid, reason));

        // a reconnect to another BSSID after a disconnect is not a roam
        if (kind == WlanNotificationKind.Disconnected) _lastBssid = null;
        if (signal is not { } s) return;
        string target = ssid is null ? "Wi-Fi" : $"\"{ssid}\"";
        var summary = s switch
        {
            SignalKind.WifiConnected => $"Connected to {target}" + (bssid is { } bc ? $" via {bc}" : ""),
            SignalKind.WifiDisconnected => $"Disconnected from {target}" + (reason is null ? "" : $": {reason}"),
            _ => (kind == WlanNotificationKind.ConnectFailed || n.ReasonCode != 0 ? $"Connection to {target} failed" : $"Connection to {target}") + (reason is null ? "" : $": {reason}"),
        };
        double weight = s switch
        {
            SignalKind.WifiDisconnected => 0.6,
            SignalKind.WifiAuthFailed => WlanCodes.IsAuthFailure(n.ReasonCode) ? 0.6 : 0.4,
            _ => 0.1,
        };
        Publish(s, summary, bssid, weight);
    }

    // ------------------------------------------------------------------ samples

    internal void ProcessSample(WlanLinkState raw, double? apRtt, double? gwRtt, DateTimeOffset now)
    {
        string? band = null;
        if (raw.Connected)
            band = raw.FrequencyMhz > 0 ? WifiMath.BandOf(raw.FrequencyMhz) : WlanCodes.BandOfChannel(raw.Channel);
        int rssi = raw.Connected ? raw.RssiDbm ?? WlanCodes.QualityToDbm(raw.SignalQuality) : 0;
        string? phy = raw.Connected ? WifiMath.PhyName(WifiMath.FromDot11PhyType(raw.PhyType), band ?? "") : null;
        var sample = new WifiLinkSample(now, raw.Connected, raw.Ssid, raw.Bssid, raw.Channel, string.IsNullOrEmpty(band) ? null : band,
            rssi, raw.SignalQuality, raw.TxMbps, raw.RxMbps, phy, apRtt, gwRtt);

        // connect/disconnect from polling only when notifications are not available
        if (!_api.NotificationsActive && raw.Connected != _lastConnected)
        {
            if (raw.Connected)
            {
                AddEvent(new WifiEvent(now, "Connected", raw.Ssid, raw.Bssid, null));
                Publish(SignalKind.WifiConnected, $"Connected to \"{raw.Ssid}\"" + (raw.Bssid is { } b ? $" via {b}" : ""), raw.Bssid, 0.1);
            }
            else
            {
                AddEvent(new WifiEvent(now, "Disconnected", _lastSsid, _lastBssid, null));
                Publish(SignalKind.WifiDisconnected, $"Disconnected from \"{_lastSsid}\"", _lastBssid, 0.6);
                _lastBssid = null;
            }
        }

        if (raw.Connected && raw.Bssid is { } bssid)
        {
            if (_lastBssid is { } old && old != bssid)
            {
                var text = $"Roamed {old} → {bssid} ({_lastRssi} → {rssi} dBm)";
                AddEvent(new WifiEvent(now, "Roamed", raw.Ssid, bssid, text));
                Publish(SignalKind.WifiRoamed, (raw.Ssid is null ? "" : $"\"{raw.Ssid}\": ") + text, bssid, 0.2);
            }
            _lastBssid = bssid;
            _lastRssi = rssi;
            _lastSsid = raw.Ssid;
        }
        else if (!raw.Connected) _lastBssid = null;
        _lastConnected = raw.Connected;

        int threshold = _settings.Settings.WifiWeakRssiDbm;
        switch (_weak.Update(now, raw.Connected, rssi, threshold))
        {
            case 1:
                AddEvent(new WifiEvent(now, "WeakSignal", raw.Ssid, raw.Bssid, $"RSSI {rssi} dBm below {threshold} dBm for {WeakSignalDetector.Hold.TotalSeconds:0} s"));
                Publish(SignalKind.WifiWeakSignal, $"Weak Wi-Fi signal: {rssi} dBm (threshold {threshold} dBm)" + (raw.Ssid is null ? "" : $" on \"{raw.Ssid}\""), raw.Bssid, 0.4);
                break;
            case -1:
                AddEvent(new WifiEvent(now, "SignalRecovered", raw.Ssid, raw.Bssid, $"RSSI {rssi} dBm"));
                break;
        }

        lock (_sync)
        {
            _current = sample;
            _history.Enqueue(sample);
            while (_history.Count > HistoryLength) _history.Dequeue();
        }
        RaiseUpdated();
    }

    private void AddEvent(WifiEvent e)
    {
        lock (_sync)
        {
            _events.Enqueue(e);
            while (_events.Count > EventLength) _events.Dequeue();
        }
        try { _bus.Publish(e); } catch { }
    }

    private void Publish(SignalKind kind, string summary, Mac? bssid, double weight)
    {
        try
        {
            Mac? device = bssid is { } b ? FindApDevice(b)?.Mac ?? b : null;
            _bus.Publish(DiagnosticSignal.Create(kind, SignalSource, summary, device, null, weight));
        }
        catch (Exception ex) { _log.LogDebug(ex, "Publishing Wi-Fi signal failed"); }
    }

    private void RaiseUpdated()
    {
        try { Updated?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "Wi-Fi link Updated handler failed"); }
    }

    // ------------------------------------------------------------------ AP / gateway resolution

    private Device? FindApDevice(Mac bssid)
    {
        var devices = _services?.GetService<IDeviceStore>();
        return devices is null ? null : MatchAp(devices.All, bssid);
    }

    private IPAddress? FindApIp(Mac bssid) => FindApDevice(bssid)?.PrimaryIPv4;

    /// <summary>
    /// The NetSpider device that owns <paramref name="bssid"/>: same OUI with the MAC within ±8 (APs derive BSSIDs from their base
    /// MAC), also comparing with the locally-administered bit cleared (many vendors set it on extra BSSIDs). Prefers AccessPoint-typed devices.
    /// </summary>
    internal static Device? MatchAp(IEnumerable<Device> devices, Mac bssid)
    {
        Device? best = null;
        (int Rank, long Diff) bestKey = (int.MaxValue, long.MaxValue);
        var bssidGlobal = new Mac(bssid.Value & ~0x0200_0000_0000UL);
        foreach (var d in devices)
        {
            if (d.Has(DeviceFlags.ThisHost) || d.Has(DeviceFlags.Inferred)) continue;
            long diff = Distance(d.Mac, bssid);
            if (diff > 8) diff = Distance(new Mac(d.Mac.Value & ~0x0200_0000_0000UL), bssidGlobal);
            if (diff > 8) continue;
            var key = (d.Type == DeviceType.AccessPoint ? 0 : 1, diff);
            if (key.CompareTo(bestKey) < 0) { bestKey = key; best = d; }
        }
        return best;

        static long Distance(Mac a, Mac b) => a.Oui24 != b.Oui24 ? long.MaxValue : Math.Abs((long)a.Value - (long)b.Value);
    }

    private IPAddress? GatewayOf(Guid itf)
    {
        if (_gateway is { } g && g.Itf == itf && DateTimeOffset.Now - g.At < GatewayRefresh) return g.Gw;
        IPAddress? gw = null;
        try
        {
            var id = itf.ToString("B");
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => string.Equals(n.Id, id, StringComparison.OrdinalIgnoreCase));
            gw = nic?.GetIPProperties().GatewayAddresses
                .Select(a => a.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
        }
        catch (Exception ex) { _log.LogDebug(ex, "Could not read the WLAN adapter gateway"); }
        _gateway = (itf, gw, DateTimeOffset.Now);
        return gw;
    }

    private async Task<double?> SafePingAsync(IPAddress ip, CancellationToken ct)
    {
        try { return await _ping(ip, PingTimeout, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    private async Task<double?> DefaultPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        if (_services?.GetService<ILatencyProber>() is { } prober)
            return await prober.IcmpPingAsync(ip, timeout, ct).ConfigureAwait(false);
        using var ping = new Ping();
        long t0 = Stopwatch.GetTimestamp();
        var reply = await ping.SendPingAsync(ip, timeout, null, null, ct).ConfigureAwait(false);
        return reply.Status == IPStatus.Success ? Stopwatch.GetElapsedTime(t0).TotalMilliseconds : null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _settings.Saved -= ApplySettings; } catch { }
        StopLoop();
        _api.Notification -= OnNotification;
        _api.Dispose();
        _wake.Dispose();
    }
}
