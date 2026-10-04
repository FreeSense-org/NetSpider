using System.Net.NetworkInformation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Wifi;

/// <summary>
/// Background Wi-Fi scanner: scans every <see cref="Interval"/> (and on demand via <see cref="ScanNowAsync"/>), publishes the
/// results to <see cref="INetworkState.WifiNetworks"/> and sets <see cref="Device.Wifi"/> on this host's device.
/// </summary>
public sealed class WifiMonitor : IStartable, IDisposable
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    private readonly IWifiScanner _scanner;
    private readonly INetworkState _network;
    private readonly IDeviceStore _devices;
    private readonly IServiceProvider? _services;
    private readonly ILogger<WifiMonitor> _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private Task? _loop;

    public WifiMonitor(IWifiScanner scanner, INetworkState network, IDeviceStore devices, ILogger<WifiMonitor> log, IServiceProvider? services = null)
    {
        _scanner = scanner;
        _network = network;
        _devices = devices;
        _log = log;
        _services = services;
    }

    public DateTimeOffset? LastScan { get; private set; }

    public void Start()
    {
        if (_loop is not null) return;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        try
        {
            if (!_scanner.Available)
            {
                _log.LogInformation("Wi-Fi scanning disabled: no WLAN interface or service");
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                await ScanNowAsync(ct).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "Wi-Fi monitor loop failed"); }
    }

    /// <summary>Runs a scan now (concurrent callers share the in-flight scan's result).</summary>
    public async Task<IReadOnlyList<WifiNetwork>> ScanNowAsync(CancellationToken ct = default)
    {
        // the demo network shows simulated Wi-Fi: real scans must not overwrite it (or tag the demo host with the real association)
        if (_network.IsDemo) return _network.WifiNetworks;
        if (!await _scanGate.WaitAsync(0, ct).ConfigureAwait(false))
        {
            // a scan is already running: wait for it and return its result
            await _scanGate.WaitAsync(ct).ConfigureAwait(false);
            _scanGate.Release();
            return _network.WifiNetworks;
        }
        try
        {
            var nets = await _scanner.ScanAsync(ct).ConfigureAwait(false);
            if (_network.IsDemo) return _network.WifiNetworks; // demo was switched on while scanning
            LastScan = DateTimeOffset.Now;
            _network.WifiNetworks = nets;
            ApplyAssociation(nets);
            if (_scanner is WlanNativeScanner { LocationPermissionDenied: true })
            {
                _services?.GetService<IAlertService>()?.Raise(
                    Alert.Create(AlertSeverity.Info, AlertKind.Info, "Wi-Fi scan blocked by Windows location privacy", WlanNativeScanner.LocationDeniedMessage),
                    TimeSpan.FromHours(12));
            }
            _log.LogDebug("Wi-Fi scan: {Count} BSSIDs", nets.Count);
            return nets;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Wi-Fi scan failed");
            return _network.WifiNetworks;
        }
        finally { _scanGate.Release(); }
    }

    /// <summary>Sets the Wi-Fi association of this host's device from the connected BSS.</summary>
    internal void ApplyAssociation(IReadOnlyList<WifiNetwork> nets)
    {
        try
        {
            var hosts = _devices.All.Where(d => d.Has(DeviceFlags.ThisHost)).ToList();
            if (hosts.Count == 0) return;

            var wlanMacs = WirelessMacs();
            var target = hosts.FirstOrDefault(d => wlanMacs.Contains(d.Mac));
            if (target is null)
            {
                // The capture adapter's MAC is not a WLAN NIC; only attribute the association when capture runs on a wireless adapter.
                var adapter = _services?.GetService<IFrameSource>()?.Adapter;
                if (adapter is { IsWireless: false } && wlanMacs.Count > 0) return;
                target = hosts[0];
            }

            var conn = nets.FirstOrDefault(n => n.Connected);
            var assoc = conn is null ? null : new WifiAssociation(conn.Ssid, conn.Bssid, conn.Channel, conn.Band, conn.RssiDbm, conn.Phy);
            if (Equals(target.Wifi, assoc)) return;
            target.Wifi = assoc;
            target.SetFlag(DeviceFlags.WifiClient, assoc is not null);
            _devices.NotifyChanged(target, "wifi");
        }
        catch (Exception ex) { _log.LogDebug(ex, "Could not apply Wi-Fi association"); }
    }

    private static HashSet<Mac> WirelessMacs()
    {
        var set = new HashSet<Mac>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) continue;
                var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                if (bytes.Length == 6) set.Add(Mac.FromBytes(bytes));
            }
        }
        catch { }
        return set;
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}
