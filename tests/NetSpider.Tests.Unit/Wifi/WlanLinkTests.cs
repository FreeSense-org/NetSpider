using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Wifi;
using NetSpider.Wifi.Native;
using static NetSpider.Wifi.Native.WlanNative;

namespace NetSpider.Tests.Unit.Wifi;

public sealed class WlanLinkTests
{
    // ---- native layouts (must match wlanapi.h, x64) ------------------------------------------

    [Fact]
    public void Notification_struct_layouts_match_wlanapi()
    {
        Assert.Equal(568, Unsafe.SizeOf<WLAN_CONNECTION_NOTIFICATION_DATA>());
        Assert.Equal(4, (int)Marshal.OffsetOf<WLAN_CONNECTION_NOTIFICATION_DATA>(nameof(WLAN_CONNECTION_NOTIFICATION_DATA.strProfileName)));
        Assert.Equal(516, (int)Marshal.OffsetOf<WLAN_CONNECTION_NOTIFICATION_DATA>(nameof(WLAN_CONNECTION_NOTIFICATION_DATA.dot11Ssid)));
        Assert.Equal(552, (int)Marshal.OffsetOf<WLAN_CONNECTION_NOTIFICATION_DATA>(nameof(WLAN_CONNECTION_NOTIFICATION_DATA.dot11BssType)));
        Assert.Equal(560, (int)Marshal.OffsetOf<WLAN_CONNECTION_NOTIFICATION_DATA>(nameof(WLAN_CONNECTION_NOTIFICATION_DATA.wlanReasonCode)));
        Assert.Equal(564, (int)Marshal.OffsetOf<WLAN_CONNECTION_NOTIFICATION_DATA>(nameof(WLAN_CONNECTION_NOTIFICATION_DATA.dwFlags)));

        Assert.Equal(580, Unsafe.SizeOf<WLAN_MSM_NOTIFICATION_DATA>());
        Assert.Equal(516, (int)Marshal.OffsetOf<WLAN_MSM_NOTIFICATION_DATA>(nameof(WLAN_MSM_NOTIFICATION_DATA.dot11Ssid)));
        Assert.Equal(556, (int)Marshal.OffsetOf<WLAN_MSM_NOTIFICATION_DATA>(nameof(WLAN_MSM_NOTIFICATION_DATA.dot11MacAddr)));
        Assert.Equal(564, (int)Marshal.OffsetOf<WLAN_MSM_NOTIFICATION_DATA>(nameof(WLAN_MSM_NOTIFICATION_DATA.bSecurityEnabled)));
        Assert.Equal(576, (int)Marshal.OffsetOf<WLAN_MSM_NOTIFICATION_DATA>(nameof(WLAN_MSM_NOTIFICATION_DATA.wlanReasonCode)));

        Assert.Equal(IntPtr.Size == 8 ? 40 : 32, Unsafe.SizeOf<WLAN_NOTIFICATION_DATA>());
        Assert.Equal(8, (int)Marshal.OffsetOf<WLAN_NOTIFICATION_DATA>(nameof(WLAN_NOTIFICATION_DATA.InterfaceGuid)));
        Assert.Equal(IntPtr.Size == 8 ? 32 : 28, (int)Marshal.OffsetOf<WLAN_NOTIFICATION_DATA>(nameof(WLAN_NOTIFICATION_DATA.pData)));

        Assert.Equal(604, Unsafe.SizeOf<WLAN_CONNECTION_ATTRIBUTES>());
        Assert.Equal(56, (int)Marshal.OffsetOf<WLAN_ASSOCIATION_ATTRIBUTES>(nameof(WLAN_ASSOCIATION_ATTRIBUTES.wlanSignalQuality)));
        Assert.Equal(60, (int)Marshal.OffsetOf<WLAN_ASSOCIATION_ATTRIBUTES>(nameof(WLAN_ASSOCIATION_ATTRIBUTES.ulRxRate)));
        Assert.Equal(64, (int)Marshal.OffsetOf<WLAN_ASSOCIATION_ATTRIBUTES>(nameof(WLAN_ASSOCIATION_ATTRIBUTES.ulTxRate)));
        Assert.Equal(0x10000102, wlan_intf_opcode_rssi);
    }

    [Fact]
    public unsafe void Copies_msm_roam_notification_payload()
    {
        var msm = new WLAN_MSM_NOTIFICATION_DATA { wlanReasonCode = 0 };
        var ssid = "Office"u8;
        msm.dot11Ssid.uSSIDLength = (uint)ssid.Length;
        for (int i = 0; i < ssid.Length; i++) msm.dot11Ssid.ucSSID[i] = ssid[i];
        Mac.Parse("74:83:C2:00:00:12").WriteTo(new Span<byte>(msm.dot11MacAddr, 6));
        var itf = Guid.NewGuid();
        var data = new WLAN_NOTIFICATION_DATA
        {
            NotificationSource = WLAN_NOTIFICATION_SOURCE_MSM,
            NotificationCode = wlan_notification_msm_roaming_end,
            InterfaceGuid = itf,
            dwDataSize = (uint)sizeof(WLAN_MSM_NOTIFICATION_DATA),
            pData = (nint)(&msm),
        };
        var n = WlanLinkApi.Copy(&data);
        Assert.NotNull(n);
        Assert.Equal(WlanNotificationKind.RoamEnd, n.Kind);
        Assert.Equal("Office", n.Ssid);
        Assert.Equal(Mac.Parse("74:83:C2:00:00:12"), n.Bssid);
        Assert.Equal(itf, n.Interface);
    }

    [Fact]
    public unsafe void Copies_acm_disconnect_reason_and_ignores_scan_codes()
    {
        var c = new WLAN_CONNECTION_NOTIFICATION_DATA { wlanReasonCode = WlanCodes.ReasonDriverDisconnected };
        var data = new WLAN_NOTIFICATION_DATA
        {
            NotificationSource = WLAN_NOTIFICATION_SOURCE_ACM,
            NotificationCode = wlan_notification_acm_disconnected,
            dwDataSize = (uint)sizeof(WLAN_CONNECTION_NOTIFICATION_DATA) + 2,
            pData = (nint)(&c),
        };
        var n = WlanLinkApi.Copy(&data);
        Assert.Equal(WlanNotificationKind.Disconnected, n!.Kind);
        Assert.Equal(WlanCodes.ReasonDriverDisconnected, n.ReasonCode);

        data.NotificationCode = wlan_notification_acm_scan_complete;
        Assert.Null(WlanLinkApi.Copy(&data));

        uint q = 73;
        data = new WLAN_NOTIFICATION_DATA { NotificationSource = WLAN_NOTIFICATION_SOURCE_MSM, NotificationCode = wlan_notification_msm_signal_quality_change, dwDataSize = 4, pData = (nint)(&q) };
        Assert.Equal(73u, WlanLinkApi.Copy(&data)!.SignalQuality);
    }

    // ---- code mapping ----------------------------------------------------------------------

    [Theory]
    [InlineData(WLAN_NOTIFICATION_SOURCE_ACM, 10u, WlanNotificationKind.Connected)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_ACM, 11u, WlanNotificationKind.ConnectFailed)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_ACM, 21u, WlanNotificationKind.Disconnected)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_ACM, 13u, WlanNotificationKind.InterfaceArrival)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_ACM, 7u, WlanNotificationKind.Ignored)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_MSM, 5u, WlanNotificationKind.RoamStart)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_MSM, 6u, WlanNotificationKind.RoamEnd)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_MSM, 8u, WlanNotificationKind.SignalQualityChange)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_MSM, 10u, WlanNotificationKind.MsmDisconnected)]
    [InlineData(WLAN_NOTIFICATION_SOURCE_MSM, 99u, WlanNotificationKind.Ignored)]
    [InlineData(0x40u, 1u, WlanNotificationKind.Ignored)]
    public void Classifies_notification_codes(uint source, uint code, WlanNotificationKind kind) =>
        Assert.Equal(kind, WlanCodes.Classify(source, code));

    [Fact]
    public void Maps_notifications_to_signals()
    {
        Assert.Equal(("Connected", SignalKind.WifiConnected), WlanCodes.Map(WlanNotificationKind.Connected, 0));
        Assert.Equal(("AuthFailed", SignalKind.WifiAuthFailed), WlanCodes.Map(WlanNotificationKind.Connected, WlanCodes.ReasonKeyMismatch));
        Assert.Equal(("AuthFailed", SignalKind.WifiAuthFailed), WlanCodes.Map(WlanNotificationKind.ConnectFailed, 0x48010));
        Assert.Equal(("ConnectFailed", SignalKind.WifiAuthFailed), WlanCodes.Map(WlanNotificationKind.ConnectFailed, WlanCodes.ReasonAssociationTimeout));
        Assert.Equal(("Disconnected", SignalKind.WifiDisconnected), WlanCodes.Map(WlanNotificationKind.Disconnected, WlanCodes.ReasonDriverDisconnected));
        Assert.Equal(("RoamEnd", (SignalKind?)null), WlanCodes.Map(WlanNotificationKind.RoamEnd, 0));
    }

    [Fact]
    public void Reason_codes_have_fallback_text()
    {
        Assert.Equal("Success", WlanCodes.ReasonText(0));
        Assert.Contains("wrong password", WlanCodes.ReasonText(WlanCodes.ReasonKeyMismatch));
        Assert.Contains("driver", WlanCodes.ReasonText(WlanCodes.ReasonDriverDisconnected));
        Assert.StartsWith("Security error", WlanCodes.ReasonText(0x48001));
        Assert.StartsWith("802.1X", WlanCodes.ReasonText(0x50005));
        Assert.True(WlanCodes.IsAuthFailure(WlanCodes.ReasonSecurityTimeout));
        Assert.False(WlanCodes.IsAuthFailure(WlanCodes.ReasonAssociationFailure));
        Assert.True(WlanCodes.HasMsmData(WLAN_NOTIFICATION_SOURCE_MSM, wlan_notification_msm_roaming_start));
        Assert.False(WlanCodes.HasMsmData(WLAN_NOTIFICATION_SOURCE_MSM, wlan_notification_msm_signal_quality_change));
        Assert.Equal(-100, WlanCodes.QualityToDbm(0));
        Assert.Equal(-50, WlanCodes.QualityToDbm(100));
    }

    [Fact]
    public void Weak_signal_needs_ten_seconds_and_recovers_with_hysteresis()
    {
        var d = new WeakSignalDetector();
        var t = DateTimeOffset.Now;
        Assert.Equal(0, d.Update(t, true, -80, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(9), true, -80, -75));
        Assert.Equal(1, d.Update(t.AddSeconds(10), true, -80, -75));
        Assert.True(d.IsWeak);
        // -73 is above the threshold but inside the 5 dB hysteresis band: stays weak
        Assert.Equal(0, d.Update(t.AddSeconds(11), true, -73, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(30), true, -73, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(31), true, -68, -75));
        Assert.Equal(-1, d.Update(t.AddSeconds(41), true, -68, -75));
        // a brief dip does not trigger
        Assert.Equal(0, d.Update(t.AddSeconds(50), true, -80, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(55), true, -70, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(65), true, -80, -75));
        Assert.Equal(0, d.Update(t.AddSeconds(66), false, 0, -75));
        Assert.False(d.IsWeak);
    }

    // ---- monitor logic over a fake WLAN API ------------------------------------------------

    private static readonly Mac Bssid1 = Mac.Parse("74:83:C2:00:00:11");
    private static readonly Mac Bssid2 = Mac.Parse("74:83:C2:00:00:A1");

    private static WlanLinkState Link(Mac bssid, int rssi) =>
        new(Guid.Empty, true, "Office", bssid, 60, rssi, 36, 5180, 10, 1200, 960, "Office");

    private static (WifiLinkMonitor Mon, FakeWlanApi Api, List<DiagnosticSignal> Signals, DeviceStore Devices) Create()
    {
        var store = new SettingsStore(Path.Combine(Path.GetTempPath(), $"ns-wifilink-{Guid.NewGuid():N}.json"));
        var bus = new EventBus();
        var signals = new List<DiagnosticSignal>();
        bus.Subscribe<DiagnosticSignal>(signals.Add);
        var devices = new DeviceStore();
        var sp = new SimpleServices().Add<IDeviceStore>(devices);
        var api = new FakeWlanApi();
        var mon = new WifiLinkMonitor(store, bus, NullLogger<WifiLinkMonitor>.Instance, sp, api, (_, _, _) => Task.FromResult<double?>(2.0));
        return (mon, api, signals, devices);
    }

    [Fact]
    public void Bssid_change_is_a_roam_with_rssi_before_and_after()
    {
        var (mon, _, signals, devices) = Create();
        var ap = devices.GetOrAdd(Mac.Parse("74:83:C2:00:00:A0"));
        ap.Type = DeviceType.AccessPoint;
        var t = DateTimeOffset.Now;
        mon.ProcessSample(Link(Bssid1, -70), 3, 4, t);
        mon.ProcessSample(Link(Bssid2, -55), 3, 4, t.AddSeconds(1));

        var roam = Assert.Single(signals, s => s.Kind == SignalKind.WifiRoamed);
        Assert.Contains("-70 → -55 dBm", roam.Summary);
        Assert.Equal(ap.Mac, roam.Device); // BSSID resolved to the AP device (±8)
        Assert.Contains(mon.Events, e => e.Kind == "Roamed" && e.Bssid == Bssid2);
        Assert.Equal(2, mon.History.Count);
        Assert.Equal(1200, mon.Current!.RxRateMbps);
        Assert.Equal("5 GHz", mon.Current.Band);
        Assert.Equal("Wi-Fi 6 (802.11ax)", mon.Current.Phy);
    }

    [Fact]
    public void Disconnect_then_reconnect_elsewhere_is_not_a_roam()
    {
        var (mon, api, signals, _) = Create();
        var t = DateTimeOffset.Now;
        mon.ProcessSample(Link(Bssid1, -60), null, null, t);
        mon.ProcessNotification(new WlanNotification(t, WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_disconnected, Guid.Empty, "Office", null, WlanCodes.ReasonDriverDisconnected, null));
        mon.ProcessSample(Link(Bssid2, -60), null, null, t.AddSeconds(1));

        Assert.DoesNotContain(signals, s => s.Kind == SignalKind.WifiRoamed);
        var dis = Assert.Single(signals, s => s.Kind == SignalKind.WifiDisconnected);
        Assert.Contains("fake reason", dis.Summary);
        var ev = Assert.Single(mon.Events, e => e.Kind == "Disconnected");
        Assert.Equal(Bssid1, ev.Bssid);
        Assert.Equal(1, api.ReasonLookups);
    }

    [Fact]
    public void Connection_failures_become_auth_failed_signals()
    {
        var (mon, _, signals, _) = Create();
        mon.ProcessNotification(new WlanNotification(DateTimeOffset.Now, WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_connection_attempt_fail, Guid.Empty, "Office", null, WlanCodes.ReasonKeyMismatch, null));
        mon.ProcessNotification(new WlanNotification(DateTimeOffset.Now, WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_connection_complete, Guid.Empty, "Office", null, 0, null));
        Assert.Equal([SignalKind.WifiAuthFailed, SignalKind.WifiConnected], signals.Select(s => s.Kind));
        Assert.Contains("Connection to \"Office\" failed", signals[0].Summary);
    }

    [Fact]
    public void Sustained_weak_rssi_signals_once()
    {
        var (mon, _, signals, _) = Create();
        var t = DateTimeOffset.Now;
        for (int i = 0; i <= 15; i++) mon.ProcessSample(Link(Bssid1, -82), 3, 4, t.AddSeconds(i));
        Assert.Single(signals, s => s.Kind == SignalKind.WifiWeakSignal);
        Assert.Contains(mon.Events, e => e.Kind == "WeakSignal");
    }

    [Fact]
    public void History_is_capped()
    {
        var (mon, _, _, _) = Create();
        var t = DateTimeOffset.Now;
        for (int i = 0; i < WifiLinkMonitor.HistoryLength + 10; i++) mon.ProcessSample(Link(Bssid1, -50), null, null, t.AddSeconds(i));
        Assert.Equal(WifiLinkMonitor.HistoryLength, mon.History.Count);
    }

    [Fact]
    public async Task Unavailable_without_wlan_interface()
    {
        var (mon, api, _, _) = Create();
        api.Itfs = [];
        mon.Start();
        await Task.Delay(300);
        Assert.False(mon.Available);
        mon.Dispose();
        Assert.True(api.Disposed);
    }

    [Fact]
    public void Matches_ap_device_by_bssid_including_laa_variants()
    {
        var ap = new Device(Mac.Parse("74:83:C2:10:20:30")) { Type = DeviceType.AccessPoint };
        var other = new Device(Mac.Parse("74:83:C2:10:20:31"));
        Assert.Same(ap, WifiLinkMonitor.MatchAp([other, ap], Mac.Parse("74:83:C2:10:20:35")));
        Assert.Same(ap, WifiLinkMonitor.MatchAp([ap], Mac.Parse("76:83:C2:10:20:32"))); // LAA bit set on the BSSID
        Assert.Null(WifiLinkMonitor.MatchAp([ap], Mac.Parse("74:83:C2:10:20:50")));
    }

    private sealed class FakeWlanApi : IWlanLinkApi
    {
        public IReadOnlyList<WlanInterfaceInfo> Itfs = [new(Guid.Empty, "Fake Wi-Fi", 1)];
        public int ReasonLookups;
        public bool Disposed;
        public bool Open() => true;
        public string? Status => null;
        public bool NotificationsActive => true;
        public IReadOnlyList<WlanInterfaceInfo> Interfaces() => Itfs;
        public WlanLinkState? Query(Guid itf) => Link(Bssid1, -50);
        public string ReasonToString(uint reasonCode) { ReasonLookups++; return "fake reason"; }
        public event Action<WlanNotification>? Notification { add { } remove { } }
        public void Dispose() => Disposed = true;
    }

    private sealed class SimpleServices : IServiceProvider
    {
        private readonly Dictionary<Type, object> _items = new();
        public SimpleServices Add<T>(T instance) where T : notnull { _items[typeof(T)] = instance; return this; }
        public object? GetService(Type serviceType) => _items.GetValueOrDefault(serviceType);
    }
}
