using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Export.Json;

/// <summary>Serializable snapshot of a <see cref="Device"/> with all details.</summary>
public sealed record DeviceDto
{
    public required Mac Mac { get; init; }
    public required string DisplayName { get; init; }
    public string? Hostname { get; init; }
    public string? UserLabel { get; init; }
    public string? OuiVendor { get; init; }
    public string? Brand { get; init; }
    public string? Model { get; init; }
    public string? Firmware { get; init; }
    public string? OsGuess { get; init; }
    public DeviceType Type { get; init; }
    public double TypeConfidence { get; init; }
    public double IdentityConfidence { get; init; }
    public DeviceState State { get; init; }
    public string[] Flags { get; init; } = [];
    public IPAddress[] IPv4 { get; init; } = [];
    public Ipv6Info[] IPv6 { get; init; } = [];
    public IReadOnlyDictionary<string, string> Hostnames { get; init; } = new Dictionary<string, string>();
    public PortInfo[] Ports { get; init; } = [];
    public ServiceInfo[] Services { get; init; } = [];
    public TlsCertInfo[] Certificates { get; init; } = [];
    public int[] Vlans { get; init; } = [];
    public int? NativeVlan { get; init; }
    public IPAddress[] MulticastGroups { get; init; } = [];
    public Mac? UpstreamMac { get; init; }
    public string? UpstreamPort { get; init; }
    public WifiAssociation? Wifi { get; init; }
    public int? Ttl { get; init; }
    public string? IconUrl { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public IReadOnlyDictionary<string, LatencySummary> Latency { get; init; } = new Dictionary<string, LatencySummary>();
    public IReadOnlyDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
    public Evidence[] Evidence { get; init; } = [];

    public static DeviceDto From(Device d)
    {
        var lat = new Dictionary<string, LatencySummary>();
        foreach (var k in Enum.GetValues<LatencyKind>())
        {
            var s = d.Latency.Summarize(k);
            if (s.Count > 0) lat[k.ToString()] = s;
        }
        return new DeviceDto
        {
            Mac = d.Mac,
            DisplayName = d.DisplayName,
            Hostname = d.Hostname,
            UserLabel = d.UserLabel,
            OuiVendor = d.OuiVendor,
            Brand = d.Brand,
            Model = d.Model,
            Firmware = d.Firmware,
            OsGuess = d.OsGuess,
            Type = d.Type,
            TypeConfidence = d.TypeConfidence,
            IdentityConfidence = d.IdentityConfidence,
            State = d.State,
            Flags = FlagNames(d.Flags),
            IPv4 = d.IPv4.OrderBy(ExportText.IpSortKey).ToArray(),
            IPv6 = d.IPv6,
            Hostnames = d.Hostnames,
            Ports = d.Ports,
            Services = d.Services,
            Certificates = d.Certificates,
            Vlans = d.Vlans,
            NativeVlan = d.NativeVlan,
            MulticastGroups = d.MulticastGroups,
            UpstreamMac = d.UpstreamMac,
            UpstreamPort = d.UpstreamPort,
            Wifi = d.Wifi,
            Ttl = d.Ttl,
            IconUrl = d.IconUrl,
            FirstSeen = d.FirstSeen,
            LastSeen = d.LastSeen,
            Latency = lat,
            Properties = d.Properties,
            Evidence = d.Evidence,
        };
    }

    public static string[] FlagNames(DeviceFlags flags) =>
        Enum.GetValues<DeviceFlags>().Where(f => f != DeviceFlags.None && (flags & f) == f).Select(f => f.ToString()).ToArray();
}

public sealed record LinkDto(Mac A, Mac B, LinkKind Kind, string? PortA, string? PortB, long? SpeedMbps, string? Duplex, double? PoeWatts,
    double? LatencyMs, LatencyOrigin LatencyOrigin, double Confidence, DateTimeOffset LastSeen)
{
    public static LinkDto From(Link l) => new(l.A, l.B, l.Kind, l.PortA, l.PortB, l.SpeedMbps, l.Duplex, l.PoeWatts, l.LatencyMs, l.LatencyOrigin, l.Confidence, l.LastSeen);
}

public sealed record SegmentDto(string Cidr, IPAddress Network, int PrefixLength, string Source, int? VlanId, string? VlanName, IPAddress? Gateway,
    bool IsLocal, bool ScanEnabled, DateTimeOffset? LastScanned, int HostsFound)
{
    public static SegmentDto From(NetworkSegment s) => new(s.Cidr, s.Network, s.PrefixLength, s.Source, s.VlanId, s.VlanName, s.Gateway, s.IsLocal, s.ScanEnabled, s.LastScanned, s.HostsFound);
}

public sealed record NetworkDto(
    IReadOnlyList<SegmentDto> Segments,
    IReadOnlyList<VlanInfo> Vlans,
    IReadOnlyList<DhcpServerInfo> DhcpServers,
    IReadOnlyList<StpInfo> Stp,
    WanInfo? Wan,
    IReadOnlyList<TracerouteHop> InternetPath,
    IReadOnlyList<WifiNetwork> Wifi,
    HealthReport Health,
    IReadOnlyList<NeighborEntry> Neighbors,
    IReadOnlyList<FdbEntry> Fdb,
    IReadOnlyList<SwitchPortInfo> SwitchPorts,
    Mac? IgmpQuerier,
    bool? NicPassesVlanTags,
    TrafficSnapshot? Traffic)
{
    public static NetworkDto From(INetworkState n) => new(
        n.Segments.Select(SegmentDto.From).ToList(), n.Vlans, n.DhcpServers, n.StpBridges, n.Wan, n.InternetPath, n.WifiNetworks, n.Health,
        n.Neighbors, n.Fdb, n.SwitchPorts, n.IgmpQuerier, n.NicPassesVlanTags, n.LastTraffic);
}

/// <summary>Root document of the JSON export.</summary>
public sealed record ExportDocument(
    string Generator,
    string Version,
    DateTimeOffset GeneratedAt,
    AdapterInfo? Adapter,
    IReadOnlyList<DeviceDto> Devices,
    IReadOnlyList<LinkDto> Links,
    IReadOnlyList<Alert> Alerts,
    NetworkDto Network)
{
    public static ExportDocument From(ExportData data) => new(
        "NetSpider", ExportText.AppVersion, DateTimeOffset.Now, data.Adapter,
        data.Devices.OrderBy(d => ExportText.IpSortKey(d.PrimaryIPv4)).ThenBy(d => d.Mac).Select(DeviceDto.From).ToList(),
        data.Links.Select(LinkDto.From).ToList(),
        data.Alerts,
        NetworkDto.From(data.Network));
}
