using NetSpider.Core.Model;
using static NetSpider.Wifi.Native.WlanNative;

namespace NetSpider.Wifi;

/// <summary>What a WLAN notification means for the link monitor.</summary>
public enum WlanNotificationKind
{
    Ignored,
    ConnectionStart, Connected, ConnectFailed, Disconnecting, Disconnected,
    InterfaceArrival, InterfaceRemoval,
    Associating, Associated, Authenticating, MsmConnected, RoamStart, RoamEnd, RadioStateChange, SignalQualityChange,
    Disassociating, MsmDisconnected, LinkDegraded, LinkImproved,
}

/// <summary>Pure mapping of WLAN notification codes and WLAN_REASON_CODE values (wlanapi.h / wlantypes.h / l2cmn.h).</summary>
public static class WlanCodes
{
    // l2cmn.h / wlanapi.h reason-code ranges
    public const uint ReasonSuccess = 0;
    public const uint ReasonUnknown = 0x10001;
    public const uint ReasonAcBase = 0x20000;
    public const uint ReasonMsmBase = 0x30000;
    public const uint ReasonMsmSecBase = 0x40000;
    public const uint ReasonOneXBase = 0x50000;
    public const uint ReasonProfileBase = 0x80000;

    public const uint ReasonNetworkNotAvailable = 0x2800B;
    public const uint ReasonKeyMismatch = 0x2800D;
    public const uint ReasonUserCancelled = 0x38001;
    public const uint ReasonAssociationFailure = 0x38002;
    public const uint ReasonAssociationTimeout = 0x38003;
    public const uint ReasonPreSecurityFailure = 0x38004;
    public const uint ReasonStartSecurityFailure = 0x38005;
    public const uint ReasonSecurityFailure = 0x38006;
    public const uint ReasonSecurityTimeout = 0x38007;
    public const uint ReasonRoamingFailure = 0x38008;
    public const uint ReasonRoamingSecurityFailure = 0x38009;
    public const uint ReasonDriverDisconnected = 0x3800B;
    public const uint ReasonDriverOperationFailure = 0x3800C;
    public const uint ReasonDisconnectTimeout = 0x3800F;
    public const uint ReasonInternalFailure = 0x38010;
    public const uint ReasonTooManySecurityAttempts = 0x38012;

    /// <summary>Classifies a notification by source (ACM/MSM) and code.</summary>
    public static WlanNotificationKind Classify(uint source, uint code) => source switch
    {
        WLAN_NOTIFICATION_SOURCE_ACM => code switch
        {
            wlan_notification_acm_connection_start => WlanNotificationKind.ConnectionStart,
            wlan_notification_acm_connection_complete => WlanNotificationKind.Connected,
            wlan_notification_acm_connection_attempt_fail => WlanNotificationKind.ConnectFailed,
            wlan_notification_acm_disconnecting => WlanNotificationKind.Disconnecting,
            wlan_notification_acm_disconnected => WlanNotificationKind.Disconnected,
            wlan_notification_acm_interface_arrival => WlanNotificationKind.InterfaceArrival,
            wlan_notification_acm_interface_removal => WlanNotificationKind.InterfaceRemoval,
            _ => WlanNotificationKind.Ignored,
        },
        WLAN_NOTIFICATION_SOURCE_MSM => code switch
        {
            wlan_notification_msm_associating => WlanNotificationKind.Associating,
            wlan_notification_msm_associated => WlanNotificationKind.Associated,
            wlan_notification_msm_authenticating => WlanNotificationKind.Authenticating,
            wlan_notification_msm_connected => WlanNotificationKind.MsmConnected,
            wlan_notification_msm_roaming_start => WlanNotificationKind.RoamStart,
            wlan_notification_msm_roaming_end => WlanNotificationKind.RoamEnd,
            wlan_notification_msm_radio_state_change => WlanNotificationKind.RadioStateChange,
            wlan_notification_msm_signal_quality_change => WlanNotificationKind.SignalQualityChange,
            wlan_notification_msm_disassociating => WlanNotificationKind.Disassociating,
            wlan_notification_msm_disconnected => WlanNotificationKind.MsmDisconnected,
            wlan_notification_msm_adapter_removal => WlanNotificationKind.InterfaceRemoval,
            wlan_notification_msm_link_degraded => WlanNotificationKind.LinkDegraded,
            wlan_notification_msm_link_improved => WlanNotificationKind.LinkImproved,
            _ => WlanNotificationKind.Ignored,
        },
        _ => WlanNotificationKind.Ignored,
    };

    /// <summary>True when the notification's pData is a WLAN_CONNECTION_NOTIFICATION_DATA.</summary>
    public static bool HasConnectionData(uint source, uint code) =>
        source == WLAN_NOTIFICATION_SOURCE_ACM && code is wlan_notification_acm_connection_start or wlan_notification_acm_connection_complete
            or wlan_notification_acm_connection_attempt_fail or wlan_notification_acm_disconnecting or wlan_notification_acm_disconnected;

    /// <summary>True when the notification's pData is a WLAN_MSM_NOTIFICATION_DATA.</summary>
    public static bool HasMsmData(uint source, uint code) =>
        source == WLAN_NOTIFICATION_SOURCE_MSM && code is >= wlan_notification_msm_associating and <= wlan_notification_msm_roaming_end
            or wlan_notification_msm_disassociating or wlan_notification_msm_disconnected;

    /// <summary>
    /// <see cref="WifiEvent.Kind"/> string and the diagnostic signal (if any) for a notification. Only the ACM connection
    /// results and disconnects produce signals; MSM detail is recorded as events. Roams are signalled from BSSID changes.
    /// </summary>
    public static (string Kind, SignalKind? Signal) Map(WlanNotificationKind kind, uint reasonCode) => kind switch
    {
        WlanNotificationKind.Connected when reasonCode == ReasonSuccess => ("Connected", SignalKind.WifiConnected),
        WlanNotificationKind.Connected or WlanNotificationKind.ConnectFailed => IsAuthFailure(reasonCode)
            ? ("AuthFailed", SignalKind.WifiAuthFailed)
            : ("ConnectFailed", SignalKind.WifiAuthFailed),
        WlanNotificationKind.Disconnected => ("Disconnected", SignalKind.WifiDisconnected),
        _ => (kind.ToString(), null),
    };

    /// <summary>Security/802.1X/key failures (as opposed to association/range problems).</summary>
    public static bool IsAuthFailure(uint reasonCode) =>
        reasonCode is >= ReasonMsmSecBase and < ReasonMsmSecBase + 0x10000
        || reasonCode is >= ReasonOneXBase and < ReasonOneXBase + 0x10000
        || reasonCode is ReasonKeyMismatch or ReasonPreSecurityFailure or ReasonStartSecurityFailure or ReasonSecurityFailure
            or ReasonSecurityTimeout or ReasonRoamingSecurityFailure or ReasonTooManySecurityAttempts;

    /// <summary>Managed fallback text for a WLAN_REASON_CODE (used when WlanReasonCodeToString is unavailable).</summary>
    public static string ReasonText(uint code) => code switch
    {
        ReasonSuccess => "Success",
        ReasonUnknown => "Unknown reason",
        ReasonNetworkNotAvailable => "The network is not available",
        ReasonKeyMismatch => "Security key mismatch (wrong password)",
        ReasonUserCancelled => "Cancelled by the user",
        ReasonAssociationFailure => "Association failed",
        ReasonAssociationTimeout => "Association timed out",
        ReasonPreSecurityFailure => "Pre-security failure",
        ReasonStartSecurityFailure => "Security could not be started",
        ReasonSecurityFailure => "Security (authentication) failure",
        ReasonSecurityTimeout => "Security (authentication) timed out",
        ReasonRoamingFailure => "Roaming failed",
        ReasonRoamingSecurityFailure => "Security failure while roaming",
        ReasonDriverDisconnected => "Disconnected by the driver (AP deauth/disassoc or signal lost)",
        ReasonDriverOperationFailure => "Driver operation failed",
        ReasonDisconnectTimeout => "Disconnect timed out",
        ReasonInternalFailure => "Internal failure",
        ReasonTooManySecurityAttempts => "Too many security attempts",
        >= ReasonMsmSecBase and < ReasonMsmSecBase + 0x10000 => $"Security error (0x{code:X5})",
        >= ReasonOneXBase and < ReasonOneXBase + 0x10000 => $"802.1X authentication error (0x{code:X5})",
        >= ReasonMsmBase and < ReasonMsmBase + 0x10000 => $"Connection/association error (0x{code:X5})",
        >= ReasonAcBase and < ReasonAcBase + 0x10000 => $"Auto-config error (0x{code:X5})",
        >= ReasonProfileBase and < ReasonProfileBase + 0x10000 => $"Profile error (0x{code:X5})",
        _ => $"Reason 0x{code:X}",
    };

    /// <summary>Approximate RSSI from WLAN_SIGNAL_QUALITY (0 = −100 dBm, 100 = −50 dBm).</summary>
    public static int QualityToDbm(int quality) => Math.Clamp(quality, 0, 100) / 2 - 100;

    /// <summary>Band guess from a channel number when no centre frequency is known (6 GHz cannot be told apart).</summary>
    public static string BandOfChannel(int channel) => channel switch
    {
        >= 1 and <= 14 => WifiMath.Band24,
        >= 32 and <= 177 => WifiMath.Band5,
        _ => "",
    };
}

/// <summary>
/// Weak-signal state with hysteresis: weak after RSSI stays below the threshold for <see cref="Hold"/>; recovered after it
/// stays at or above threshold + <see cref="HysteresisDb"/> for <see cref="Hold"/>. Disconnects reset the state silently.
/// </summary>
public sealed class WeakSignalDetector
{
    public static readonly TimeSpan Hold = TimeSpan.FromSeconds(10);
    public const int HysteresisDb = 5;

    private DateTimeOffset? _belowSince, _aboveSince;

    public bool IsWeak { get; private set; }

    /// <returns>+1 when the link just became weak, −1 when it just recovered, 0 otherwise.</returns>
    public int Update(DateTimeOffset now, bool connected, int rssiDbm, int thresholdDbm)
    {
        if (!connected) { _belowSince = _aboveSince = null; IsWeak = false; return 0; }
        if (!IsWeak)
        {
            _aboveSince = null;
            if (rssiDbm < thresholdDbm)
            {
                _belowSince ??= now;
                if (now - _belowSince.Value >= Hold) { IsWeak = true; _belowSince = null; return 1; }
            }
            else _belowSince = null;
            return 0;
        }
        _belowSince = null;
        if (rssiDbm >= thresholdDbm + HysteresisDb)
        {
            _aboveSince ??= now;
            if (now - _aboveSince.Value >= Hold) { IsWeak = false; _aboveSince = null; return -1; }
        }
        else _aboveSince = null;
        return 0;
    }
}
