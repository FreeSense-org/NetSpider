using System.Net;

namespace NetSpider.Core.Model;

// =============================================================================================================
//  Path Doctor: the live chain from this PC to the internet
// =============================================================================================================

public enum HopRole { ThisHost, AccessPoint, Switch, UnmanagedSwitch, Router, Firewall, Modem, IspHop, InternetTarget }

public enum HopHealth { Unknown, Up, Degraded, Down }

/// <summary>How a hop is probed. Unmanaged/inferred switches have no IP and are judged through anchor devices behind them.</summary>
public enum HopProbe { Self, ArpIcmp, IcmpOnly, Anchors, None }

/// <summary>One element of the path. <see cref="AddedMs"/> is this hop's RTT minus the previous healthy hop's RTT.</summary>
public sealed record PathHop(
    int Index, HopRole Role, string Name, Mac? Mac, IPAddress? Ip, HopProbe Probe, IReadOnlyList<Mac> Anchors,
    string? PortIn, HopHealth Health, double? RttMs, double? AddedMs, double LossPercent, double? JitterMs,
    bool? ArpOk, bool? IcmpOk, string? Note, IReadOnlyList<double?> Recent);

/// <summary>The ordered path this host uses to reach the internet. <see cref="Medium"/> is "Wired" or "Wi-Fi".</summary>
public sealed record NetworkPath(DateTimeOffset Built, DateTimeOffset Updated, string Medium, IReadOnlyList<PathHop> Hops)
{
    public PathHop? FirstFailing => Hops.FirstOrDefault(h => h.Health == HopHealth.Down);
}

// =============================================================================================================
//  Diagnostic signals → incidents
// =============================================================================================================

public enum SignalKind
{
    // this host
    LocalLinkDown, LocalLinkUp, LocalSpeedChanged, LocalIpChanged, LocalGatewayChanged, DhcpLeaseLost,
    // path
    HopDown, HopUp, HopDegraded, DevicesUnreachable,
    // switch ports (SNMP)
    PortDown, PortUp, PortFlapping, PortErrors, PortDuplexMismatch, PortSpeedDowngrade, PortPoeOverload,
    // L2 health
    StormDetected, StormEnded, LoopSuspected, StpTopologyChange,
    // Wi-Fi
    WifiDisconnected, WifiConnected, WifiRoamed, WifiAuthFailed, WifiWeakSignal, ApDown, ApClientsUnreachable, ApDegraded,
    // remote probe agents
    AgentReportFailure, AgentReportRecovered, AgentOffline,
    // internet monitor
    InternetDown, InternetUp,
}

/// <summary>
/// A fact a monitor observed, published on <c>IEventBus</c>. The fault locator correlates signals into incidents.
/// <see cref="Weight"/> (0..1) is how strongly the signal points at <see cref="Device"/>/<see cref="Port"/> being the culprit.
/// </summary>
public sealed record DiagnosticSignal(DateTimeOffset Time, SignalKind Kind, string Source, string Summary,
    Mac? Device = null, string? Port = null, double Weight = 0.5, IReadOnlyList<Mac>? Affected = null)
{
    public static DiagnosticSignal Create(SignalKind kind, string source, string summary, Mac? device = null, string? port = null, double weight = 0.5, IReadOnlyList<Mac>? affected = null) =>
        new(DateTimeOffset.Now, kind, source, summary, device, port, weight, affected);
}

public enum IncidentCategory { OwnLink, LocalNetwork, SwitchPort, Wifi, Router, Modem, Isp, Storm, Loop, Unknown }

/// <summary>A correlated problem with a root-cause hypothesis ("usw-lite-office or its uplink to core-sw-01 port 12").</summary>
public sealed record Incident(
    Guid Id, DateTimeOffset Start, DateTimeOffset? End, AlertSeverity Severity, IncidentCategory Category,
    string Title, string RootCause, double Confidence, Mac? SuspectDevice, string? SuspectPort, string? SuspectLink,
    IReadOnlyList<Mac> Affected, IReadOnlyList<string> Evidence, string? PcapPath)
{
    public bool Ongoing => End is null;
    public TimeSpan Duration => (End ?? DateTimeOffset.Now) - Start;
}

// =============================================================================================================
//  Switch-port diagnostics (SNMP IF-MIB / EtherLike-MIB)
// =============================================================================================================

/// <summary>Raw counter snapshot of one switch port. Counters are 64-bit where the agent supports HC counters.</summary>
public sealed record PortCounterSample(
    Mac Switch, int IfIndex, string Name, DateTimeOffset Time, bool OperUp, long? SpeedMbps, string? Duplex, TimeSpan? LastChange,
    ulong InOctets, ulong OutOctets, ulong InErrors, ulong OutErrors, ulong InDiscards, ulong OutDiscards,
    ulong InBroadcast, ulong InMulticast, ulong InUnicast, ulong FcsErrors, ulong AlignmentErrors, ulong LateCollisions, ulong ExcessiveCollisions);

/// <summary>Rates/derived health for one switch port, computed from consecutive counter samples.</summary>
public sealed record PortHealth(
    Mac Switch, int IfIndex, string Name, bool OperUp, long? SpeedMbps, string? Duplex,
    double InBps, double OutBps, double ErrorsPerSec, double DiscardsPerSec, double FcsPerSec, double BroadcastPps, double MulticastPps,
    int FlapsLastHour, bool DuplexSuspect, bool SpeedDowngraded, string? Problem, HopHealth Health, DateTimeOffset Updated);

// =============================================================================================================
//  Storm Center
// =============================================================================================================

public enum StormLevel { Normal, Elevated, Storm }

public sealed record StormSource(Mac Mac, string? Name, double Pps, double BroadcastPps, double MulticastPps, string DominantProtocol,
    Mac? Switch, string? SwitchName, string? Port, string? Location);

/// <summary>Port where storm traffic enters the network (from per-port broadcast counters), or a loop suspect.</summary>
public sealed record StormIngress(Mac Switch, string SwitchName, string Port, double BroadcastPps, double MulticastPps, string? Note);

public sealed record LoopSuspect(string Description, Mac? Switch, IReadOnlyList<string> Ports, IReadOnlyList<Mac> FlappingMacs, double Confidence, DateTimeOffset Time);

public sealed record StormEvent(DateTimeOffset Start, DateTimeOffset? End, StormLevel PeakLevel, double PeakPps, string DominantProtocol, string Summary, string? PcapPath);

public sealed record StormStatus(
    DateTimeOffset Time, StormLevel Level, double BroadcastPps, double MulticastPps, double UnknownUnicastPps, double TotalPps,
    double BaselineBroadcastPps, double BaselineMulticastPps, IReadOnlyDictionary<string, double> PpsByProtocol,
    IReadOnlyList<StormSource> Sources, IReadOnlyList<StormIngress> Ingress, IReadOnlyList<LoopSuspect> Loops)
{
    public static readonly StormStatus Empty = new(DateTimeOffset.MinValue, StormLevel.Normal, 0, 0, 0, 0, 0, 0,
        new Dictionary<string, double>(), [], [], []);
}

public sealed record StormControlOptions(int DurationMs = 2000, int Pps = 2000, int? VlanId = null);

/// <summary>Result of the opt-in active storm-control check.</summary>
public sealed record StormControlResult(bool Ran, int Sent, TimeSpan Duration, bool? StormControlTriggered, string Verdict, IReadOnlyList<string> Details);

// =============================================================================================================
//  Wi-Fi ↔ LAN
// =============================================================================================================

/// <summary>This host's wireless link at one moment (WlanQueryInterface current_connection + statistics).</summary>
public sealed record WifiLinkSample(DateTimeOffset Time, bool Connected, string? Ssid, Mac? Bssid, int Channel, string? Band,
    int RssiDbm, int SignalQuality, double TxRateMbps, double RxRateMbps, string? Phy, double? ApRttMs, double? GatewayRttMs);

public sealed record WifiEvent(DateTimeOffset Time, string Kind, string? Ssid, Mac? Bssid, string? Reason);

/// <summary>Health of one access point as seen from this host (management IP plus its wireless clients).</summary>
public sealed record ApHealth(Mac Ap, string Name, IPAddress? Ip, bool? MgmtUp, double? MgmtRttMs, int Clients, int ClientsReachable,
    double? AvgClientRttMs, double ClientLossPercent, HopHealth Health, string? Diagnosis, DateTimeOffset Updated);

// =============================================================================================================
//  Remote probe agents (second vantage point)
// =============================================================================================================

public sealed record ProbeTargetResult(string Target, string? Ip, double? RttMs, double? AvgMs, double LossPercent, int Sent, string? Error);

/// <summary>Periodic report from a NetSpider.Probe agent (JSON over UDP, HMAC-signed with the shared key).</summary>
public sealed record ProbeAgentReport(string AgentId, string Hostname, string? Ip, string? Mac, string Medium, DateTimeOffset Time,
    IReadOnlyList<ProbeTargetResult> Results, WifiLinkSample? Wifi, string? Gateway, string Version);

public sealed record ProbeAgentInfo(string AgentId, string Hostname, string? Ip, string? Mac, string Medium, DateTimeOffset LastSeen,
    bool Online, ProbeAgentReport? Latest);
