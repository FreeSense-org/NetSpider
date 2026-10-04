using System.Net;

namespace NetSpider.Core.Model;

/// <summary>An edge between two devices. Synthetic nodes (Internet, inferred switches) are real <see cref="Device"/>s with LAA MACs.</summary>
public sealed class Link
{
    public Link(Mac a, Mac b, LinkKind kind)
    {
        // normalize so (a,b) and (b,a) are the same key
        if (b.Value < a.Value) (a, b) = (b, a);
        A = a; B = b; Kind = kind;
        LastSeen = DateTimeOffset.Now;
    }

    public Mac A { get; }
    public Mac B { get; }
    public LinkKind Kind { get; }
    public string? PortA { get; set; }
    public string? PortB { get; set; }
    public long? SpeedMbps { get; set; }
    public string? Duplex { get; set; }
    public double? PoeWatts { get; set; }
    public double? LatencyMs { get; set; }
    public LatencyOrigin LatencyOrigin { get; set; } = LatencyOrigin.Estimated;
    public double Confidence { get; set; } = 1.0;
    public DateTimeOffset LastSeen { get; set; }

    public (Mac, Mac, LinkKind) Key => (A, B, Kind);
    public bool Touches(Mac m) => A == m || B == m;
    public Mac Other(Mac m) => A == m ? B : A;
    public string? PortOf(Mac m) => A == m ? PortA : PortB;
    public void SetPort(Mac m, string? port) { if (A == m) PortA = port; else PortB = port; }

    public override string ToString() => $"{A} <-{Kind}-> {B}";
}

/// <summary>Device↔device latency, measured (SNMP ping, passive TCP) or estimated (topology path sum).</summary>
public sealed record PairLatency(Mac From, Mac To, double Ms, LatencyOrigin Origin, string Method, DateTimeOffset Time);

/// <summary>An IPv4 subnet (optionally a VLAN) known to exist on the network.</summary>
public sealed class NetworkSegment
{
    public NetworkSegment(IPAddress network, int prefixLength, string source)
    {
        Network = IpUtil.NetworkAddress(network, prefixLength);
        PrefixLength = prefixLength;
        Source = source;
    }

    public IPAddress Network { get; }
    public int PrefixLength { get; }
    public string Source { get; set; }
    public int? VlanId { get; set; }
    public string? VlanName { get; set; }
    public IPAddress? Gateway { get; set; }
    /// <summary>true when the segment is directly attached (L2 reachable) to the capture adapter.</summary>
    public bool IsLocal { get; set; }
    public bool ScanEnabled { get; set; } = true;
    public DateTimeOffset? LastScanned { get; set; }
    public int HostsFound { get; set; }

    public string Cidr => $"{Network}/{PrefixLength}";
    public bool Contains(IPAddress ip) => IpUtil.InSubnet(ip, Network, PrefixLength);
    public override string ToString() => VlanId is { } v ? $"{Cidr} (VLAN {v})" : Cidr;
}

public sealed record Alert(Guid Id, DateTimeOffset Time, AlertSeverity Severity, AlertKind Kind, string Title, string Details, Mac? Source = null, double? Rate = null)
{
    public static Alert Create(AlertSeverity sev, AlertKind kind, string title, string details, Mac? source = null, double? rate = null) =>
        new(Guid.NewGuid(), DateTimeOffset.Now, sev, kind, title, details, source, rate);
}

public sealed record DhcpServerInfo(IPAddress ServerIp, Mac ServerMac, IPAddress? OfferedIp, IPAddress? Router, IReadOnlyList<IPAddress> Dns, IPAddress? SubnetMask, TimeSpan? Lease, DateTimeOffset Seen, bool IsRogue);

public sealed record StpInfo(string RootBridgeId, Mac RootMac, int RootPriority, int RootPathCost, string BridgeId, Mac SenderMac, string Protocol, DateTimeOffset Seen);

public sealed record VlanInfo(int Id, string? Name, string Source, bool Native, bool Voice);

public sealed record PortMapping(string Protocol, int ExternalPort, IPAddress? InternalClient, int InternalPort, string? Description, bool Enabled, TimeSpan? Lease, string? RemoteHost);

public sealed record WanInfo(IPAddress? ExternalIp, string? ConnectionStatus, string? ConnectionType, TimeSpan? Uptime, string? GatewayModel, string Method, IReadOnlyList<PortMapping> PortMappings, DateTimeOffset Time);

public sealed record WifiNetwork(string Ssid, Mac Bssid, int Channel, int FrequencyMhz, string Band, int RssiDbm, int LinkQuality,
    string Security, string Phy, string? Vendor, bool Connected, int? ChannelWidthMhz, DateTimeOffset Seen);

public sealed record TracerouteHop(int Ttl, IPAddress? Address, double? RttMs, string? Hostname, Mac? Mac);

public sealed record HealthCheckResult(string Id, string Name, HealthStatus Status, int Score, string Summary, string? Details = null, Mac? Device = null);

public sealed record HealthReport(DateTimeOffset Time, int OverallScore, IReadOnlyList<HealthCheckResult> Checks)
{
    public static readonly HealthReport Empty = new(DateTimeOffset.MinValue, 100, []);
}

/// <summary>One-second traffic statistics from the capture adapter.</summary>
public sealed record TrafficSnapshot(DateTimeOffset Time, double TotalPps, double BroadcastPps, double MulticastPps, double UnicastPps,
    double BytesPerSecond, IReadOnlyDictionary<string, double> PpsByProtocol, IReadOnlyList<TalkerStat> TopTalkers, long Dropped)
{
    public double BroadcastRatio => TotalPps <= 0 ? 0 : BroadcastPps / TotalPps;
    public double MulticastRatio => TotalPps <= 0 ? 0 : MulticastPps / TotalPps;
}

public sealed record TalkerStat(Mac Mac, double Pps, double BroadcastPps, double MulticastPps, double Bps);

/// <summary>Lightweight "this device just said something" event for the graph's packet-rain ripples.</summary>
public readonly record struct PacketActivity(Mac Source, string Protocol, DateTimeOffset Time);

public readonly record struct ScanProgress(string Stage, double Fraction, string? Detail = null);

/// <summary>A switch forwarding-database entry: <see cref="Mac"/> was learned on <see cref="Switch"/>'s port.</summary>
public sealed record FdbEntry(Mac Switch, string Port, int? PortIndex, Mac Mac, int? Vlan, DateTimeOffset Seen);

/// <summary>
/// An LLDP/CDP adjacency: <see cref="Reporter"/>'s port <see cref="ReporterPort"/> is cabled to the neighbor.
/// For a frame received directly by this host, Reporter = the advertising switch/device and Neighbor = this host
/// (the advertised port is the switch port we are plugged into). From SNMP LLDP-MIB, Reporter = the polled switch.
/// </summary>
public sealed record NeighborEntry(
    Mac Reporter, string? ReporterPort,
    Mac? NeighborMac, string? NeighborChassisId, string? NeighborPort, string? NeighborName,
    System.Net.IPAddress? NeighborMgmtIp, string? NeighborDescription, string? NeighborCapabilities,
    string Protocol, DateTimeOffset Seen);

/// <summary>Port of a managed switch (from SNMP IF-MIB / BRIDGE-MIB / POWER-ETHERNET-MIB).</summary>
public sealed record SwitchPortInfo(Mac Switch, int Index, string Name, string? Alias, long? SpeedMbps, bool? Up, string? Duplex, double? PoeWatts, int? Pvid);
