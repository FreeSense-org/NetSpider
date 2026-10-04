using System.Runtime.InteropServices;

namespace NetSpider.Wifi.Native;

/// <summary>P/Invoke surface of wlanapi.dll (Native Wifi API). All structs are blittable and laid out as in wlanapi.h / windot11.h.</summary>
internal static unsafe partial class WlanNative
{
    private const string Lib = "wlanapi.dll";

    public const uint ClientVersion2 = 2;

    public const uint ERROR_SUCCESS = 0;
    public const uint ERROR_ACCESS_DENIED = 5;
    public const uint ERROR_INVALID_STATE = 5023;
    public const uint ERROR_SERVICE_NOT_ACTIVE = 1062;
    public const uint ERROR_NOT_FOUND = 1168;
    public const uint ERROR_NDIS_DOT11_POWER_STATE_INVALID = 0x80342002;
    public const uint RPC_S_SERVER_UNAVAILABLE = 1722;

    public const uint WLAN_NOTIFICATION_SOURCE_NONE = 0;
    public const uint WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008;
    public const uint wlan_notification_acm_scan_complete = 7;
    public const uint wlan_notification_acm_scan_fail = 8;

    public const uint WLAN_NOTIFICATION_SOURCE_MSM = 0x00000010;

    // WLAN_NOTIFICATION_ACM (wlanapi.h)
    public const uint wlan_notification_acm_connection_start = 9;
    public const uint wlan_notification_acm_connection_complete = 10;
    public const uint wlan_notification_acm_connection_attempt_fail = 11;
    public const uint wlan_notification_acm_interface_arrival = 13;
    public const uint wlan_notification_acm_interface_removal = 14;
    public const uint wlan_notification_acm_network_not_available = 18;
    public const uint wlan_notification_acm_network_available = 19;
    public const uint wlan_notification_acm_disconnecting = 20;
    public const uint wlan_notification_acm_disconnected = 21;

    // WLAN_NOTIFICATION_MSM (wlanapi.h)
    public const uint wlan_notification_msm_associating = 1;
    public const uint wlan_notification_msm_associated = 2;
    public const uint wlan_notification_msm_authenticating = 3;
    public const uint wlan_notification_msm_connected = 4;
    public const uint wlan_notification_msm_roaming_start = 5;
    public const uint wlan_notification_msm_roaming_end = 6;
    public const uint wlan_notification_msm_radio_state_change = 7;
    public const uint wlan_notification_msm_signal_quality_change = 8;
    public const uint wlan_notification_msm_disassociating = 9;
    public const uint wlan_notification_msm_disconnected = 10;
    public const uint wlan_notification_msm_adapter_removal = 13;
    public const uint wlan_notification_msm_link_degraded = 15;
    public const uint wlan_notification_msm_link_improved = 16;

    // WLAN_INTF_OPCODE
    public const int wlan_intf_opcode_interface_state = 6;
    public const int wlan_intf_opcode_current_connection = 7;
    public const int wlan_intf_opcode_channel_number = 8;
    public const int wlan_intf_opcode_rssi = 0x10000102;

    public const int dot11_BSS_type_infrastructure = 1;
    public const int dot11_BSS_type_any = 3;

    public const int wlan_interface_state_connected = 1;

    [LibraryImport(Lib)]
    public static partial uint WlanOpenHandle(uint dwClientVersion, nint pReserved, out uint pdwNegotiatedVersion, out nint phClientHandle);

    [LibraryImport(Lib)]
    public static partial uint WlanCloseHandle(nint hClientHandle, nint pReserved);

    [LibraryImport(Lib)]
    public static partial uint WlanEnumInterfaces(nint hClientHandle, nint pReserved, out WLAN_INTERFACE_INFO_LIST* ppInterfaceList);

    [LibraryImport(Lib)]
    public static partial uint WlanScan(nint hClientHandle, in Guid pInterfaceGuid, nint pDot11Ssid, nint pIeData, nint pReserved);

    [LibraryImport(Lib)]
    public static partial uint WlanGetNetworkBssList(nint hClientHandle, in Guid pInterfaceGuid, nint pDot11Ssid, int dot11BssType,
        int bSecurityEnabled, nint pReserved, out WLAN_BSS_LIST* ppWlanBssList);

    [LibraryImport(Lib)]
    public static partial uint WlanGetAvailableNetworkList(nint hClientHandle, in Guid pInterfaceGuid, uint dwFlags, nint pReserved,
        out WLAN_AVAILABLE_NETWORK_LIST* ppAvailableNetworkList);

    [LibraryImport(Lib)]
    public static partial uint WlanQueryInterface(nint hClientHandle, in Guid pInterfaceGuid, int opCode, nint pReserved,
        out uint pdwDataSize, out void* ppData, nint pWlanOpcodeValueType);

    [LibraryImport(Lib)]
    public static partial uint WlanRegisterNotification(nint hClientHandle, uint dwNotifSource, int bIgnoreDuplicate,
        delegate* unmanaged[Stdcall]<WLAN_NOTIFICATION_DATA*, nint, void> funcCallback, nint pCallbackContext, nint pReserved, out uint pdwPrevNotifSource);

    [LibraryImport(Lib)]
    public static partial void WlanFreeMemory(void* pMemory);

    [LibraryImport(Lib)]
    public static partial uint WlanReasonCodeToString(uint dwReasonCode, uint dwBufferSize, char* pStringBuffer, nint pReserved);

    // ------------------------------------------------------------------ structs

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_SSID
    {
        public uint uSSIDLength;
        public fixed byte ucSSID[32];

        public readonly string ToText()
        {
            int n = (int)Math.Min(uSSIDLength, 32u);
            fixed (byte* p = ucSSID) return WifiMath.DecodeSsid(new ReadOnlySpan<byte>(p, n));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        public fixed char strInterfaceDescription[256];
        public int isState;

        public readonly string Description
        {
            get { fixed (char* p = strInterfaceDescription) return new string(p); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        public WLAN_INTERFACE_INFO InterfaceInfo; // variable-length array, first element
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_RATE_SET
    {
        public uint uRateSetLength;
        public fixed ushort usRateSet[126];
    }

    /// <summary>sizeof == 360 on both x86 and x64.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_ENTRY
    {
        public DOT11_SSID dot11Ssid;
        public uint uPhyId;
        public fixed byte dot11Bssid[6];
        public int dot11BssType;
        public int dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        public byte bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency;
        public WLAN_RATE_SET wlanRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_LIST
    {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
        public WLAN_BSS_ENTRY wlanBssEntries; // variable-length array, first element
    }

    /// <summary>sizeof == 628.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_AVAILABLE_NETWORK
    {
        public fixed char strProfileName[256];
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        public uint uNumberOfBssids;
        public int bNetworkConnectable;
        public uint wlanNotConnectableReason;
        public uint uNumberOfPhyTypes;
        public fixed int dot11PhyTypes[8];
        public int bMorePhyTypes;
        public uint wlanSignalQuality;
        public int bSecurityEnabled;
        public int dot11DefaultAuthAlgorithm;
        public int dot11DefaultCipherAlgorithm;
        public uint dwFlags;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_AVAILABLE_NETWORK_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        public WLAN_AVAILABLE_NETWORK Network; // variable-length array, first element
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        public fixed byte dot11Bssid[6];
        public int dot11PhyType;
        public uint uDot11PhyIndex;
        public uint wlanSignalQuality;
        public uint ulRxRate;
        public uint ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_SECURITY_ATTRIBUTES
    {
        public int bSecurityEnabled;
        public int bOneXEnabled;
        public int dot11AuthAlgorithm;
        public int dot11CipherAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_CONNECTION_ATTRIBUTES
    {
        public int isState;
        public int wlanConnectionMode;
        public fixed char strProfileName[256];
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_NOTIFICATION_DATA
    {
        public uint NotificationSource;
        public uint NotificationCode;
        public Guid InterfaceGuid;
        public uint dwDataSize;
        public nint pData;
    }

    /// <summary>pData of ACM connection_* / disconnect* notifications. Fixed part only (strProfileXml follows at offset 568); sizeof == 568.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_CONNECTION_NOTIFICATION_DATA
    {
        public int wlanConnectionMode;
        public fixed char strProfileName[256];
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        public int bSecurityEnabled;
        public uint wlanReasonCode;
        public uint dwFlags;
    }

    /// <summary>pData of most MSM notifications (associating … disconnected, roaming_*). sizeof == 580.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_MSM_NOTIFICATION_DATA
    {
        public int wlanConnectionMode;
        public fixed char strProfileName[256];
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        public fixed byte dot11MacAddr[6];
        public int bSecurityEnabled;
        public int bFirstPeer;
        public int bLastPeer;
        public uint wlanReasonCode;
    }
}
