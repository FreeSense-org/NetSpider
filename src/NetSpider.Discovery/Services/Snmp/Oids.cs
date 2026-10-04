namespace NetSpider.Discovery.Services.Snmp;

/// <summary>Well-known SNMP object identifiers used by the probe.</summary>
internal static class Oids
{
    // system group
    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysUpTime = "1.3.6.1.2.1.1.3.0";
    public const string SysContact = "1.3.6.1.2.1.1.4.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string SysLocation = "1.3.6.1.2.1.1.6.0";

    // IF-MIB
    public const string IfName = "1.3.6.1.2.1.31.1.1.1.1";
    public const string IfAlias = "1.3.6.1.2.1.31.1.1.1.18";
    public const string IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15";
    public const string IfDescr = "1.3.6.1.2.1.2.2.1.2";
    public const string IfOperStatus = "1.3.6.1.2.1.2.2.1.8";

    // IF-MIB counters (ifTable 32-bit, ifXTable 64-bit HC) used by the port-health poller
    public const string IfType = "1.3.6.1.2.1.2.2.1.3";
    public const string IfSpeed = "1.3.6.1.2.1.2.2.1.5";
    public const string IfLastChange = "1.3.6.1.2.1.2.2.1.9";
    public const string IfInOctets = "1.3.6.1.2.1.2.2.1.10";
    public const string IfInUcastPkts = "1.3.6.1.2.1.2.2.1.11";
    public const string IfInDiscards = "1.3.6.1.2.1.2.2.1.13";
    public const string IfInErrors = "1.3.6.1.2.1.2.2.1.14";
    public const string IfOutOctets = "1.3.6.1.2.1.2.2.1.16";
    public const string IfOutDiscards = "1.3.6.1.2.1.2.2.1.19";
    public const string IfOutErrors = "1.3.6.1.2.1.2.2.1.20";
    public const string IfInMulticastPkts = "1.3.6.1.2.1.31.1.1.1.2";
    public const string IfInBroadcastPkts = "1.3.6.1.2.1.31.1.1.1.3";
    public const string IfHCInOctets = "1.3.6.1.2.1.31.1.1.1.6";
    public const string IfHCInUcastPkts = "1.3.6.1.2.1.31.1.1.1.7";
    public const string IfHCInMulticastPkts = "1.3.6.1.2.1.31.1.1.1.8";
    public const string IfHCInBroadcastPkts = "1.3.6.1.2.1.31.1.1.1.9";
    public const string IfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10";

    // EtherLike-MIB dot3StatsTable
    public const string Dot3StatsAlignmentErrors = "1.3.6.1.2.1.10.7.2.1.2";
    public const string Dot3StatsFcsErrors = "1.3.6.1.2.1.10.7.2.1.3";
    public const string Dot3StatsLateCollisions = "1.3.6.1.2.1.10.7.2.1.8";
    public const string Dot3StatsExcessiveCollisions = "1.3.6.1.2.1.10.7.2.1.9";

    // dot3 duplex
    public const string Dot3DuplexStatus = "1.3.6.1.2.1.10.7.2.1.19";

    // BRIDGE-MIB
    public const string Dot1dBaseNumPorts = "1.3.6.1.2.1.17.1.2.0";
    public const string Dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";
    public const string Dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2";
    // Q-BRIDGE-MIB
    public const string Dot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2";
    public const string Dot1qPvid = "1.3.6.1.2.1.17.7.1.4.5.1.1";

    // POWER-ETHERNET-MIB
    public const string PethPsePortActualPower = "1.3.6.1.2.1.105.1.1.1.9";

    // LLDP-MIB (base 1.0.8802.1.1.2)
    public const string LldpRemTable = "1.0.8802.1.1.2.1.4.1.1";
    public const string LldpRemSysName = "1.0.8802.1.1.2.1.4.1.1.9";
    public const string LldpRemSysDesc = "1.0.8802.1.1.2.1.4.1.1.10";
    public const string LldpRemPortId = "1.0.8802.1.1.2.1.4.1.1.7";
    public const string LldpRemChassis = "1.0.8802.1.1.2.1.4.1.1.5";
    public const string LldpRemSysCapEnabled = "1.0.8802.1.1.2.1.4.1.1.12";
    public const string LldpRemManAddrTable = "1.0.8802.1.1.2.1.4.2.1";
    public const string LldpLocPortId = "1.0.8802.1.1.2.1.3.7.1.3";

    // ARP / neighbors
    public const string IpNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2";
    public const string IpNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4";

    // routes
    public const string IpCidrRouteDest = "1.3.6.1.2.1.4.24.4.1.1";
    public const string IpRouteDest = "1.3.6.1.2.1.4.21.1.1";
    public const string IpRouteMask = "1.3.6.1.2.1.4.21.1.11";

    // HOST-RESOURCES-MIB
    public const string HrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2";
    public const string HrStorageDescr = "1.3.6.1.2.1.25.2.3.1.3";
    public const string HrStorageAllocationUnits = "1.3.6.1.2.1.25.2.3.1.4";
    public const string HrStorageSize = "1.3.6.1.2.1.25.2.3.1.5";
    public const string HrStorageUsed = "1.3.6.1.2.1.25.2.3.1.6";
    public const string HrSystemUptime = "1.3.6.1.2.1.25.1.1.0";

    // PRINTER-MIB
    public const string PrtMarkerLifeCount = "1.3.6.1.2.1.43.10.2.1.4";
    public const string PrtMarkerSuppliesDescription = "1.3.6.1.2.1.43.11.1.1.6";
    public const string PrtMarkerSuppliesLevel = "1.3.6.1.2.1.43.11.1.1.9";
    public const string PrtMarkerSuppliesMaxCapacity = "1.3.6.1.2.1.43.11.1.1.8";

    // DISMAN-PING-MIB
    public const string PingCtlTargetAddressType = "1.3.6.1.2.1.80.1.2.1.3";
    public const string PingCtlTargetAddress = "1.3.6.1.2.1.80.1.2.1.4";
    public const string PingCtlProbeCount = "1.3.6.1.2.1.80.1.2.1.5";
    public const string PingCtlAdminStatus = "1.3.6.1.2.1.80.1.2.1.8";
    public const string PingCtlRowStatus = "1.3.6.1.2.1.80.1.2.1.23";
    public const string PingResultsAverageRtt = "1.3.6.1.2.1.80.1.3.1.6";

    /// <summary>Maps the enterprise number under 1.3.6.1.4.1.N to a vendor name.</summary>
    public static readonly Dictionary<uint, string> EnterpriseVendors = new()
    {
        [9] = "Cisco", [11] = "HP", [171] = "D-Link", [311] = "Microsoft", [674] = "Dell", [890] = "Zyxel",
        [1916] = "Extreme", [2011] = "Huawei", [2636] = "Juniper", [3375] = "F5", [4413] = "Broadcom",
        [4526] = "Netgear", [6574] = "Synology", [8072] = "Linux (net-snmp)", [10002] = "Ubiquiti",
        [11863] = "TP-Link", [12356] = "Fortinet", [14823] = "Aruba", [14988] = "MikroTik", [24681] = "QNAP",
        [25506] = "H3C", [30065] = "Arista", [41112] = "Ubiquiti",
    };

    public static uint? EnterpriseOf(string sysObjectId)
    {
        // sysObjectID like 1.3.6.1.4.1.<enterprise>.*
        const string prefix = "1.3.6.1.4.1.";
        if (!sysObjectId.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var rest = sysObjectId[prefix.Length..];
        var first = rest.Split('.').FirstOrDefault();
        return uint.TryParse(first, out var n) ? n : null;
    }
}
