using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NetSpider.Core.Model;
using NetSpider.Wifi.Native;
using static NetSpider.Wifi.Native.WlanNative;

namespace NetSpider.Wifi;

/// <summary>This host's association on one WLAN interface (current_connection + rssi + channel + BSS entry).</summary>
public sealed record WlanLinkState(Guid Interface, bool Connected, string? Ssid, Mac? Bssid, int SignalQuality, int? RssiDbm,
    int Channel, int FrequencyMhz, int PhyType, double RxMbps, double TxMbps, string? Profile);

/// <summary>A WLAN notification copied out of the native callback (pData is only valid during the callback).</summary>
public sealed record WlanNotification(DateTimeOffset Time, uint Source, uint Code, Guid Interface, string? Ssid, Mac? Bssid,
    uint ReasonCode, uint? SignalQuality)
{
    public WlanNotificationKind Kind => WlanCodes.Classify(Source, Code);
}

/// <summary>Seam over wlanapi.dll for the link monitor (faked in unit tests).</summary>
internal interface IWlanLinkApi : IDisposable
{
    /// <summary>Opens the client handle and registers ACM+MSM notifications; false when WLAN is unavailable.</summary>
    bool Open();
    string? Status { get; }
    bool NotificationsActive { get; }
    IReadOnlyList<WlanInterfaceInfo> Interfaces();
    WlanLinkState? Query(Guid itf);
    string ReasonToString(uint reasonCode);
    event Action<WlanNotification>? Notification;
}

/// <summary>
/// Native implementation of <see cref="IWlanLinkApi"/>. It keeps its own client handle (separate from
/// <see cref="WlanNativeScanner"/>, whose ACM-only registration drives scan completion), because a WLAN handle has exactly
/// one notification callback and the scanner's behaviour and tests must stay untouched.
/// </summary>
internal sealed unsafe class WlanLinkApi : IWlanLinkApi
{
    private static readonly ConcurrentDictionary<nint, WlanLinkApi> Instances = new();
    private static int _nextId = 1_000_000;

    private readonly object _sync = new();
    private readonly nint _contextId;
    private nint _handle;
    private bool _registered;
    private bool _disposed;

    public WlanLinkApi()
    {
        _contextId = Interlocked.Increment(ref _nextId);
        Instances[_contextId] = this;
    }

    public string? Status { get; private set; }
    public bool NotificationsActive => _registered;
    public event Action<WlanNotification>? Notification;

    public bool Open()
    {
        lock (_sync)
        {
            if (_disposed) return false;
            if (_handle != 0) return true;
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
                    return false;
                }
                _handle = h;
                rc = WlanRegisterNotification(h, WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM, 1, &OnNotification, _contextId, 0, out _);
                _registered = rc == ERROR_SUCCESS;
                Status = _registered ? null : $"WlanRegisterNotification failed ({rc}); polling only.";
                return true;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                Status = "wlanapi.dll is not present on this system (Wireless LAN feature not installed).";
                return false;
            }
        }
    }

    public IReadOnlyList<WlanInterfaceInfo> Interfaces()
    {
        var h = _handle;
        var result = new List<WlanInterfaceInfo>();
        if (h == 0) return result;
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

    public WlanLinkState? Query(Guid itf)
    {
        var h = _handle;
        if (h == 0) return null;

        uint rc = WlanQueryInterface(h, itf, wlan_intf_opcode_current_connection, 0, out var size, out var data, 0);
        if (rc == ERROR_INVALID_STATE || (rc == ERROR_SUCCESS && data == null))
            return new WlanLinkState(itf, false, null, null, 0, null, 0, 0, 0, 0, 0, null);
        if (rc != ERROR_SUCCESS) return null;

        string? ssid, profile;
        Mac bssid;
        int quality, phy;
        double rx, tx;
        try
        {
            if (size < (uint)sizeof(WLAN_CONNECTION_ATTRIBUTES)) return null;
            var attr = (WLAN_CONNECTION_ATTRIBUTES*)data;
            if (attr->isState != wlan_interface_state_connected)
                return new WlanLinkState(itf, false, null, null, 0, null, 0, 0, 0, 0, 0, null);
            ref var a = ref attr->wlanAssociationAttributes;
            ssid = a.dot11Ssid.ToText();
            fixed (byte* b = a.dot11Bssid) bssid = Mac.FromBytes(new ReadOnlySpan<byte>(b, 6));
            quality = (int)a.wlanSignalQuality;
            phy = a.dot11PhyType;
            rx = a.ulRxRate / 1000.0;
            tx = a.ulTxRate / 1000.0;
            profile = new string(attr->strProfileName);
        }
        finally { WlanFreeMemory(data); }

        int? rssi = QueryInt(h, itf, wlan_intf_opcode_rssi);
        int channel = QueryInt(h, itf, wlan_intf_opcode_channel_number) ?? 0;

        // the BSS entry gives the centre frequency (band) and a cached RSSI
        int mhz = 0;
        if (WlanGetNetworkBssList(h, itf, 0, dot11_BSS_type_any, 0, 0, out var bss) == ERROR_SUCCESS)
        {
            try
            {
                var first = &bss->wlanBssEntries;
                for (uint k = 0; k < bss->dwNumberOfItems; k++)
                {
                    var e = first + k;
                    if (Mac.FromBytes(new ReadOnlySpan<byte>(e->dot11Bssid, 6)) != bssid) continue;
                    mhz = WifiMath.KhzToMhz(e->ulChCenterFrequency);
                    rssi ??= e->lRssi;
                    if (channel == 0) channel = WifiMath.ChannelOf(mhz);
                    break;
                }
            }
            finally { WlanFreeMemory(bss); }
        }

        return new WlanLinkState(itf, true, ssid, bssid.IsZero ? null : bssid, quality, rssi, channel, mhz, phy, rx, tx,
            string.IsNullOrEmpty(profile) ? null : profile);
    }

    private static int? QueryInt(nint h, Guid itf, int opcode)
    {
        uint rc = WlanQueryInterface(h, itf, opcode, 0, out var size, out var data, 0);
        if (rc != ERROR_SUCCESS || data == null) return null;
        try { return size >= 4 ? *(int*)data : null; }
        finally { WlanFreeMemory(data); }
    }

    public string ReasonToString(uint reasonCode)
    {
        try
        {
            const int Len = 512;
            char* buf = stackalloc char[Len];
            if (WlanReasonCodeToString(reasonCode, Len, buf, 0) == ERROR_SUCCESS)
            {
                var s = new string(buf).Trim();
                if (s.Length > 0) return s;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        return WlanCodes.ReasonText(reasonCode);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void OnNotification(WLAN_NOTIFICATION_DATA* data, nint context)
    {
        try
        {
            if (data == null || !Instances.TryGetValue(context, out var self)) return;
            var n = Copy(data);
            if (n is not null) self.Notification?.Invoke(n);
        }
        catch { /* never throw across the native boundary */ }
    }

    /// <summary>Copies the notification payload into a managed record (null for notifications the monitor ignores).</summary>
    internal static WlanNotification? Copy(WLAN_NOTIFICATION_DATA* data)
    {
        uint src = data->NotificationSource, code = data->NotificationCode;
        if (WlanCodes.Classify(src, code) == WlanNotificationKind.Ignored) return null;
        string? ssid = null;
        Mac? bssid = null;
        uint reason = 0;
        uint? quality = null;
        var p = (byte*)data->pData;
        if (p != null)
        {
            if (WlanCodes.HasConnectionData(src, code) && data->dwDataSize >= (uint)sizeof(WLAN_CONNECTION_NOTIFICATION_DATA))
            {
                var c = (WLAN_CONNECTION_NOTIFICATION_DATA*)p;
                ssid = c->dot11Ssid.ToText();
                reason = c->wlanReasonCode;
            }
            else if (WlanCodes.HasMsmData(src, code) && data->dwDataSize >= (uint)sizeof(WLAN_MSM_NOTIFICATION_DATA))
            {
                var m = (WLAN_MSM_NOTIFICATION_DATA*)p;
                ssid = m->dot11Ssid.ToText();
                var mac = Mac.FromBytes(new ReadOnlySpan<byte>(m->dot11MacAddr, 6));
                bssid = mac.IsZero ? null : mac;
                reason = m->wlanReasonCode;
            }
            else if (src == WLAN_NOTIFICATION_SOURCE_MSM && code == wlan_notification_msm_signal_quality_change && data->dwDataSize >= 4)
            {
                quality = *(uint*)p;
            }
        }
        return new WlanNotification(DateTimeOffset.Now, src, code, data->InterfaceGuid, string.IsNullOrEmpty(ssid) ? null : ssid, bssid, reason, quality);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            Instances.TryRemove(_contextId, out _);
            if (_handle != 0)
            {
                try
                {
                    if (_registered) WlanRegisterNotification(_handle, WLAN_NOTIFICATION_SOURCE_NONE, 1, null, 0, 0, out _);
                    WlanCloseHandle(_handle, 0);
                }
                catch { }
                _handle = 0;
            }
        }
    }
}
