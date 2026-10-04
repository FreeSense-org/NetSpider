using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Wifi.Native;
using static NetSpider.Wifi.Native.WlanNative;

namespace NetSpider.Wifi;

/// <summary>A WLAN interface as reported by WlanEnumInterfaces.</summary>
public sealed record WlanInterfaceInfo(Guid Id, string Description, int State);

/// <summary><see cref="IWifiScanner"/> on top of the Windows Native Wifi API (wlanapi.dll).</summary>
public sealed class WlanNativeScanner : IWifiScanner, IDisposable
{
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(4);
    private static readonly ConcurrentDictionary<nint, WlanNativeScanner> Instances = new();
    private static int _nextId;

    private readonly ILogger<WlanNativeScanner> _log;
    private readonly IServiceProvider? _services;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<bool>> _pendingScans = new();
    private readonly nint _contextId;
    private readonly object _handleSync = new();
    private nint _handle;
    private bool _notificationsRegistered;
    private bool? _available;
    private bool _disposed;
    private volatile bool _accessDenied;

    public const string LocationDeniedMessage =
        "Windows denied access to Wi-Fi scan results. Turn on Location services (Settings > Privacy & security > Location) and allow desktop apps to access your location.";

    public WlanNativeScanner(ILogger<WlanNativeScanner> log, IServiceProvider? services = null)
    {
        _log = log;
        _services = services;
        _contextId = Interlocked.Increment(ref _nextId);
        Instances[_contextId] = this;
    }

    /// <summary>Last error/status message, for the UI ("WLAN AutoConfig service is not running", ...).</summary>
    public string? Status { get; private set; }

    /// <summary>true when the last scan was refused with ERROR_ACCESS_DENIED (Windows 11: location services off or denied for desktop apps).</summary>
    public bool LocationPermissionDenied => _accessDenied;

    /// <summary>Interfaces seen during the last successful enumeration.</summary>
    public IReadOnlyList<WlanInterfaceInfo> Interfaces { get; private set; } = [];

    public bool Available
    {
        get
        {
            if (_available is { } a) return a;
            try
            {
                var h = EnsureHandle();
                var ifs = h == 0 ? [] : EnumInterfaces(h);
                Interfaces = ifs;
                _available = ifs.Count > 0;
                if (h != 0 && ifs.Count == 0) Status = "No wireless LAN interface found.";
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "WLAN availability probe failed");
                _available = false;
            }
            return _available.Value;
        }
    }

    public async Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken ct)
    {
        if (_disposed) return [];
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var h = EnsureHandle();
            if (h == 0) return [];
            var ifs = EnumInterfaces(h);
            Interfaces = ifs;
            _available = ifs.Count > 0;
            if (ifs.Count == 0) { Status = "No wireless LAN interface found."; return []; }
            _accessDenied = false;

            // 1) trigger scans on all interfaces and wait for scan_complete / scan_fail (or the timeout)
            var waits = new List<Task>();
            foreach (var itf in ifs)
            {
                var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                _pendingScans[itf.Id] = tcs;
                uint rc = WlanScan(h, itf.Id, 0, 0, 0);
                if (rc != ERROR_SUCCESS)
                {
                    if (rc == ERROR_ACCESS_DENIED) _accessDenied = true;
                    _pendingScans.TryRemove(itf.Id, out _);
                    _log.LogDebug("WlanScan on {Itf} returned {Rc}", itf.Description, rc);
                    continue;
                }
                waits.Add(tcs.Task);
            }
            if (waits.Count > 0)
            {
                try { await Task.WhenAll(waits).WaitAsync(ScanTimeout, ct).ConfigureAwait(false); }
                catch (TimeoutException) { _log.LogDebug("WLAN scan notification timed out after {S}s; reading cached BSS list", ScanTimeout.TotalSeconds); }
            }
            foreach (var itf in ifs) _pendingScans.TryRemove(itf.Id, out _);

            ct.ThrowIfCancellationRequested();

            // 2) read results
            var oui = _services?.GetService<IOuiLookup>();
            var result = new List<WifiNetwork>();
            var seen = new HashSet<Mac>();
            // Windows can briefly flush the BSS cache around a scan (especially on a disconnected adapter), so an empty
            // read right after scan_complete is retried a couple of times before reporting "no networks".
            for (int attempt = 0; attempt < 3 && result.Count == 0; attempt++)
            {
                if (attempt > 0) await Task.Delay(TimeSpan.FromMilliseconds(1500), ct).ConfigureAwait(false);
                foreach (var itf in ifs)
                {
                    foreach (var n in ReadInterface(h, itf, oui))
                        if (seen.Add(n.Bssid)) result.Add(n);
                }
            }
            Status = _accessDenied ? LocationDeniedMessage : result.Count == 0 ? "Scan returned no networks." : null;
            if (_accessDenied) _log.LogWarning("Wi-Fi scan: {Message}", LocationDeniedMessage);
            return result.OrderByDescending(n => n.Connected).ThenByDescending(n => n.RssiDbm).ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Wi-Fi scan failed");
            Status = ex.Message;
            return [];
        }
        finally { _gate.Release(); }
    }

    private unsafe List<WifiNetwork> ReadInterface(nint h, WlanInterfaceInfo itf, IOuiLookup? oui)
    {
        var security = ReadSecurity(h, itf.Id);
        var connected = ReadConnectedBssid(h, itf.Id);
        var list = new List<WifiNetwork>();

        WLAN_BSS_LIST* bss = null;
        uint rc = WlanGetNetworkBssList(h, itf.Id, 0, dot11_BSS_type_any, 0, 0, out bss);
        if (rc != ERROR_SUCCESS)
        {
            if (rc == ERROR_ACCESS_DENIED) _accessDenied = true;
            _log.LogDebug("WlanGetNetworkBssList on {Itf} returned {Rc}", itf.Description, rc);
            return list;
        }
        try
        {
            var now = DateTimeOffset.Now;
            var first = &bss->wlanBssEntries;
            for (uint k = 0; k < bss->dwNumberOfItems; k++)
            {
                var e = first + k;
                try { list.Add(ToNetwork(e, security, connected, oui, now)); }
                catch (Exception ex) { _log.LogDebug(ex, "Skipping malformed BSS entry"); }
            }
        }
        finally { WlanFreeMemory(bss); }
        return list;
    }

    private unsafe static WifiNetwork ToNetwork(WLAN_BSS_ENTRY* e, Dictionary<string, string> security, Mac? connected, IOuiLookup? oui, DateTimeOffset now)
    {
        string ssid = e->dot11Ssid.ToText();
        var bssid = Mac.FromBytes(new ReadOnlySpan<byte>(e->dot11Bssid, 6));
        int mhz = WifiMath.KhzToMhz(e->ulChCenterFrequency);
        string band = WifiMath.BandOf(mhz);

        var ies = e->ulIeSize > 0 ? new ReadOnlySpan<byte>((byte*)e + e->ulIeOffset, (int)e->ulIeSize) : default;
        var ie = WifiMath.ParseIes(ies);

        // ulChCenterFrequency is the primary channel frequency; fall back to the DS/HT primary channel when the frequency is odd.
        int channel = WifiMath.ChannelOf(mhz);
        if (channel == 0 && ie.PrimaryChannel is { } pc) channel = pc;

        var gen = WifiMath.FromDot11PhyType(e->dot11BssPhyType);
        if (ie.Generation > gen) gen = ie.Generation;

        bool privacy = (e->usCapabilityInformation & 0x0010) != 0;
        string sec = security.TryGetValue(ssid, out var s) ? s
            : ie.RsnSecurity ?? (privacy ? "WEP" : "Open");

        string? vendor = null;
        try { vendor = oui?.Lookup(bssid); } catch { /* OUI lookup is best-effort */ }

        return new WifiNetwork(ssid, bssid, channel, mhz, band, e->lRssi, (int)e->uLinkQuality, sec,
            WifiMath.PhyName(gen, band), vendor, connected == bssid, ie.ChannelWidthMhz, now);
    }

    private unsafe Dictionary<string, string> ReadSecurity(nint h, Guid itf)
    {
        var map = new Dictionary<string, (int Rank, string Text)>(StringComparer.Ordinal);
        WLAN_AVAILABLE_NETWORK_LIST* list = null;
        uint rc = WlanGetAvailableNetworkList(h, itf, 0, 0, out list);
        if (rc != ERROR_SUCCESS) { if (rc == ERROR_ACCESS_DENIED) _accessDenied = true; _log.LogDebug("WlanGetAvailableNetworkList returned {Rc}", rc); return []; }
        try
        {
            var first = &list->Network;
            for (uint k = 0; k < list->dwNumberOfItems; k++)
            {
                var n = first + k;
                var ssid = n->dot11Ssid.ToText();
                int auth = n->dot11DefaultAuthAlgorithm;
                // the same SSID can be listed once per profile; keep the strongest auth
                int rank = auth switch { 9 => 100, 11 => 95, 8 => 94, 10 => 90, 7 => 80, 6 => 79, 4 => 60, 3 => 59, _ => auth };
                if (!map.TryGetValue(ssid, out var old) || rank > old.Rank)
                    map[ssid] = (rank, WifiMath.SecurityName(auth, n->dot11DefaultCipherAlgorithm));
            }
        }
        finally { WlanFreeMemory(list); }
        return map.ToDictionary(kv => kv.Key, kv => kv.Value.Text, StringComparer.Ordinal);
    }

    private unsafe Mac? ReadConnectedBssid(nint h, Guid itf)
    {
        uint rc = WlanQueryInterface(h, itf, wlan_intf_opcode_current_connection, 0, out var size, out var data, 0);
        if (rc != ERROR_SUCCESS || data == null) return null; // ERROR_INVALID_STATE when not connected
        try
        {
            if (size < (uint)sizeof(WLAN_CONNECTION_ATTRIBUTES)) return null;
            var attr = (WLAN_CONNECTION_ATTRIBUTES*)data;
            if (attr->isState != 1 /* wlan_interface_state_connected */) return null;
            var mac = Mac.FromBytes(new ReadOnlySpan<byte>(attr->wlanAssociationAttributes.dot11Bssid, 6));
            return mac.IsZero ? null : mac;
        }
        finally { WlanFreeMemory(data); }
    }

    private unsafe static List<WlanInterfaceInfo> EnumInterfaces(nint h)
    {
        var result = new List<WlanInterfaceInfo>();
        uint rc = WlanEnumInterfaces(h, 0, out var list);
        if (rc != ERROR_SUCCESS) return result;
        try
        {
            var first = &list->InterfaceInfo;
            for (uint k = 0; k < list->dwNumberOfItems; k++)
            {
                var i = first + k;
                result.Add(new WlanInterfaceInfo(i->InterfaceGuid, i->Description, i->isState));
            }
        }
        finally { WlanFreeMemory(list); }
        return result;
    }

    /// <summary>Opens (once) the client handle and registers for ACM notifications. Returns 0 when WLAN is unavailable.</summary>
    private unsafe nint EnsureHandle()
    {
        lock (_handleSync)
        {
            if (_handle != 0 || _disposed) return _handle;
            try
            {
                uint rc = WlanOpenHandle(ClientVersion2, 0, out _, out var h);
                if (rc != ERROR_SUCCESS)
                {
                    Status = rc switch
                    {
                        ERROR_SERVICE_NOT_ACTIVE => "WLAN AutoConfig service (WlanSvc) is not running.",
                        RPC_S_SERVER_UNAVAILABLE => "WLAN AutoConfig service is unavailable.",
                        ERROR_ACCESS_DENIED => "Access to the WLAN service was denied.",
                        _ => $"WlanOpenHandle failed ({rc}).",
                    };
                    _log.LogInformation("Wi-Fi unavailable: {Status}", Status);
                    _available = false;
                    return 0;
                }
                _handle = h;
                if (!_notificationsRegistered)
                {
                    rc = WlanRegisterNotification(h, WLAN_NOTIFICATION_SOURCE_ACM, 1, &OnNotification, _contextId, 0, out _);
                    _notificationsRegistered = rc == ERROR_SUCCESS;
                    if (!_notificationsRegistered) _log.LogDebug("WlanRegisterNotification returned {Rc}; using timeout fallback", rc);
                }
                return _handle;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                Status = "wlanapi.dll is not present on this system (Wireless LAN feature not installed).";
                _log.LogInformation("Wi-Fi unavailable: {Status}", Status);
                _available = false;
                return 0;
            }
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private unsafe static void OnNotification(WLAN_NOTIFICATION_DATA* data, nint context)
    {
        try
        {
            if (data == null || data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) return;
            if (!Instances.TryGetValue(context, out var self)) return;
            bool ok = data->NotificationCode == wlan_notification_acm_scan_complete;
            if (!ok && data->NotificationCode != wlan_notification_acm_scan_fail) return;
            if (self._pendingScans.TryGetValue(data->InterfaceGuid, out var tcs)) tcs.TrySetResult(ok);
        }
        catch { /* never throw across the native boundary */ }
    }

    public unsafe void Dispose()
    {
        lock (_handleSync)
        {
            if (_disposed) return;
            _disposed = true;
            Instances.TryRemove(_contextId, out _);
            if (_handle != 0)
            {
                try
                {
                    if (_notificationsRegistered) WlanRegisterNotification(_handle, WLAN_NOTIFICATION_SOURCE_NONE, 1, null, 0, 0, out _);
                    WlanCloseHandle(_handle, 0);
                }
                catch { }
                _handle = 0;
            }
        }
        _gate.Dispose();
    }
}
