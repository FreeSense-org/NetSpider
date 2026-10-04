namespace NetSpider.Core.Model;

public enum DeviceType
{
    Unknown, Internet, Router, Firewall, CoreSwitch, AccessSwitch, UnmanagedSwitch, AccessPoint,
    Server, Nas, Hypervisor, VirtualMachine, Desktop, Laptop, Phone, Tablet, Printer, Camera,
    Tv, MediaStreamer, AudioStreamer, GameConsole, SmartHomeHub, SmartPlug, Light, IoT, VoipPhone, Ups, ThisComputer,
}

[Flags]
public enum DeviceFlags : long
{
    None = 0,
    Gateway = 1 << 0,
    ThisHost = 1 << 1,
    Virtual = 1 << 2,
    RandomizedMac = 1 << 3,
    Inferred = 1 << 4,
    Infrastructure = 1 << 5,
    DhcpServer = 1 << 6,
    RogueDhcp = 1 << 7,
    RogueRouterAdvert = 1 << 8,
    CleartextManagement = 1 << 9,
    ExpiredCertificate = 1 << 10,
    SelfSignedCertificate = 1 << 11,
    SmbV1 = 1 << 12,
    DefaultSnmpCommunity = 1 << 13,
    IpConflict = 1 << 14,
    StpRoot = 1 << 15,
    IgmpQuerier = 1 << 16,
    MulticastSource = 1 << 17,
    StormSource = 1 << 18,
    WakeOnLanCapable = 1 << 19,
    New = 1 << 20,
    OffSubnet = 1 << 21,
    WifiClient = 1 << 22,
    PoePowered = 1 << 23,
}

public enum DeviceState { Online, Offline, Flapping }

public enum LinkKind { LldpCdp, BridgeFdb, L3Hop, InferredUnmanagedSwitch, VirtualHypervisor, WifiAssoc, GatewayStar, Wan }

public enum LatencyOrigin { Measured, Estimated }

public enum LatencyKind { Arp, Ndp, Icmp, Tcp }

public enum PortState { Open, Closed, Filtered }

public enum AlertSeverity { Info, Warning, Critical }

public enum AlertKind
{
    NewDevice, DeviceOffline, BroadcastStorm, MulticastStorm, UnknownUnicastFlood, L2Loop, StpTopologyChange, MultipleStpRoots,
    MacFlapping, ArpSpoofing, GatewayMacChanged, DuplicateIp, RogueDhcp, RogueRouterAdvert, MdnsSpam, SsdpSpam,
    TopTalker, IgmpQuerierMissing, LatencySpike, PacketLoss, CleartextManagement, ExpiredCertificate, DefaultSnmpCommunity,
    SmbV1, MtuBlackHole, DnsHijack, DnsSlow, Bufferbloat, NpcapMissing, Info,
    InternetDown, InternetRestored, InternetDegraded,
    PortErrors, PortFlapping, PortDown, DuplexMismatch, SpeedDowngrade, Incident,
}

public enum Ipv6Kind { LinkLocal, GlobalUnicast, UniqueLocal, Multicast, Other }

public enum Ipv6InterfaceIdKind { Eui64, StablePrivacy, Temporary, Unknown }

public enum ProbeLayer { L2, L3, L4, L7, Vendor, Health }

public enum HealthStatus { Pass, Warn, Fail, Skipped }
