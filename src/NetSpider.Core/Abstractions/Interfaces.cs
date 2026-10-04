using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Core.Abstractions;

// ============================================================================================
//  Stores (implemented in NetSpider.Core.Services, registered as singletons)
// ============================================================================================

public interface IDeviceStore
{
    IReadOnlyList<Device> All { get; }
    int Count { get; }
    /// <summary>Returns the device for the MAC, creating it (and raising <see cref="DeviceAdded"/>) if needed.</summary>
    Device GetOrAdd(Mac mac);
    bool TryGet(Mac mac, out Device device);
    Device? FindByIp(IPAddress ip);
    /// <summary>Records that <paramref name="ip"/> belongs to <paramref name="mac"/>, maintains the IP index and returns the device.</summary>
    Device Observe(Mac mac, IPAddress? ip, string source);
    /// <summary>Call after mutating a device; bumps its version and raises <see cref="DeviceChanged"/> (coalesced for the UI).</summary>
    void NotifyChanged(Device device, string? reason = null);
    bool Remove(Mac mac);
    void Clear();

    event Action<Device>? DeviceAdded;
    event Action<Device, string?>? DeviceChanged;
    event Action<Mac>? DeviceRemoved;
}

public interface ITopologyStore
{
    IReadOnlyList<Link> Links { get; }
    /// <summary>Inserts or returns the existing link with the same (A,B,Kind) key; call <see cref="NotifyChanged"/> after mutating.</summary>
    Link Upsert(Mac a, Mac b, LinkKind kind, Action<Link>? update = null);
    void RemoveWhere(Func<Link, bool> predicate);
    void ReplaceAll(IEnumerable<Link> links);
    IEnumerable<Link> LinksOf(Mac mac);
    void NotifyChanged();

    IReadOnlyList<PairLatency> PairLatencies { get; }
    void SetPairLatency(PairLatency p);
    PairLatency? GetPairLatency(Mac a, Mac b);

    /// <summary>Removes every link and pair latency (switching between the demo network and real monitoring).</summary>
    void Clear() => ReplaceAll([]);

    event Action? Changed;
}

public interface IAlertService
{
    IReadOnlyList<Alert> Alerts { get; }
    /// <summary>Raises an alert; identical kind+source alerts are suppressed for a cool-down period.</summary>
    bool Raise(Alert alert, TimeSpan? cooldown = null);
    void Clear();
    event Action<Alert>? AlertRaised;
}

/// <summary>Network-wide facts that are not per-device.</summary>
public interface INetworkState
{
    IReadOnlyList<NetworkSegment> Segments { get; }
    NetworkSegment AddOrGetSegment(IPAddress network, int prefix, string source, Action<NetworkSegment>? update = null);

    IReadOnlyList<DhcpServerInfo> DhcpServers { get; }
    void AddDhcpServer(DhcpServerInfo info);

    IReadOnlyList<StpInfo> StpBridges { get; }
    void AddStp(StpInfo info);

    IReadOnlyList<VlanInfo> Vlans { get; }
    void AddVlan(VlanInfo vlan);

    /// <summary>LLDP/CDP adjacencies (direct frames and SNMP LLDP-MIB). Keyed by (Reporter, ReporterPort, Neighbor id).</summary>
    IReadOnlyList<NeighborEntry> Neighbors { get; }
    void AddNeighbor(NeighborEntry entry);

    /// <summary>Forwarding databases of managed switches; <see cref="SetFdb"/> replaces one switch's table.</summary>
    IReadOnlyList<FdbEntry> Fdb { get; }
    void SetFdb(Mac switchMac, IEnumerable<FdbEntry> entries);

    IReadOnlyList<SwitchPortInfo> SwitchPorts { get; }
    void SetSwitchPorts(Mac switchMac, IEnumerable<SwitchPortInfo> ports);

    WanInfo? Wan { get; set; }
    IReadOnlyList<TracerouteHop> InternetPath { get; set; }
    IReadOnlyList<WifiNetwork> WifiNetworks { get; set; }
    HealthReport Health { get; set; }
    TrafficSnapshot? LastTraffic { get; set; }
    Mac? IgmpQuerier { get; set; }
    /// <summary>Hint shown in the UI about whether the NIC passes 802.1Q tags.</summary>
    bool? NicPassesVlanTags { get; set; }

    /// <summary>
    /// true while the synthetic demo network populates the stores. Persistence, notifications and every real background
    /// monitor (internet, Wi-Fi, path, incidents, anomaly/storm, probe agents, AP/port health) must not write while it is set.
    /// </summary>
    bool IsDemo { get; set; }

    /// <summary>
    /// Forgets every network-wide fact (segments, VLANs, DHCP, STP, neighbors, FDB, switch ports, WAN, path, Wi-Fi, health,
    /// traffic, IGMP querier, VLAN-tag hint). <see cref="IsDemo"/> is left unchanged. Used when switching between the demo
    /// network and real monitoring so the two never mix. The default only resets the settable properties.
    /// </summary>
    void Reset()
    {
        Wan = null;
        InternetPath = [];
        WifiNetworks = [];
        Health = HealthReport.Empty;
        LastTraffic = null;
        IgmpQuerier = null;
        NicPassesVlanTags = null;
    }

    event Action<string>? Changed;
}

/// <summary>Minimal in-process pub/sub for high-rate events (traffic, packet activity, progress).</summary>
public interface IEventBus
{
    void Publish<T>(T evt);
    IDisposable Subscribe<T>(Action<T> handler);
}

// ============================================================================================
//  Capture (implemented in NetSpider.Capture)
// ============================================================================================

public interface IFrameHandler
{
    /// <summary>Called on the capture dispatch thread for every frame. Must be fast and must not throw.</summary>
    void OnFrame(CapturedFrame frame);
}

public interface IFrameSource
{
    bool IsRunning { get; }
    AdapterInfo? Adapter { get; }
    bool PcapAvailable { get; }
    string? PcapVersion { get; }

    IReadOnlyList<AdapterInfo> ListAdapters();
    void Start(AdapterInfo adapter);
    void Stop();

    IDisposable Subscribe(IFrameHandler handler);

    /// <summary>Injects a raw Ethernet frame immediately. Returns the Stopwatch timestamp taken just before sending.</summary>
    long Send(ReadOnlySpan<byte> frame);
    /// <summary>Injects a frame through the global rate limiter (<see cref="AppSettings.MaxInjectPps"/>).</summary>
    ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default);

    /// <summary>Writes the rolling capture buffer to a pcapng file and returns its path.</summary>
    string? DumpRecent(string reason);

    event Action<AdapterInfo>? Started;
    event Action? Stopped;
}

public sealed record PcapStatus(bool NpcapInstalled, bool IsAdmin, string? Version, string? Message);

// ============================================================================================
//  Discovery / probing (implemented in NetSpider.Discovery)
// ============================================================================================

/// <summary>A scan stage that runs once per scan (e.g. ARP sweep, mDNS browse, SSDP search).</summary>
public interface IActiveProbe
{
    string Name { get; }
    ProbeLayer Layer { get; }
    /// <summary>Lower runs first. 0-99 L2 sweeps, 100-199 L3 sweeps, 200-299 service discovery, 300+ per-device and topology.</summary>
    int Order { get; }
    Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct);
}

/// <summary>Deep per-device probe (port scan, TLS, SNMP, HTTP, vendor APIs).</summary>
public interface IDeviceProbe
{
    string Name { get; }
    int Order { get; }
    bool AppliesTo(Device device, ScanContext ctx);
    Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct);
}

/// <summary>Long-running passive listener (usually also an <see cref="IFrameHandler"/> or a socket listener).</summary>
public interface IPassiveMonitor
{
    string Name { get; }
    void Start(ScanContext ctx);
    void Stop();
}

/// <summary>Host→device latency primitives used by the latency engine.</summary>
public interface ILatencyProber
{
    /// <summary>L2 RTT in ms via ARP request/reply (same subnet only); null on timeout. Learns the MAC as a side effect.</summary>
    Task<(double? Ms, Mac? Mac)> ArpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct);
    /// <summary>L2 RTT in ms via ICMPv6 Neighbor Solicitation → Advertisement.</summary>
    Task<double?> NdpPingAsync(IPAddress ipv6, Mac? knownMac, TimeSpan timeout, CancellationToken ct);
    Task<double?> IcmpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct, int payloadSize = 32, bool dontFragment = false);
    Task<double?> TcpPingAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct);
}

/// <summary>Asks a device to measure latency to another device (SNMP DISMAN-PING-MIB, vendor APIs).</summary>
public interface IRemotePinger
{
    Task<double?> PingFromAsync(Device from, IPAddress target, CancellationToken ct);
}

public interface ITracerouter
{
    Task<IReadOnlyList<TracerouteHop>> TraceAsync(IPAddress target, int maxHops, CancellationToken ct);
}

public interface IWakeOnLan
{
    Task SendAsync(Mac target, CancellationToken ct = default);
}

// ============================================================================================
//  Fingerprinting (implemented in NetSpider.Fingerprint)
// ============================================================================================

public interface IOuiLookup
{
    string? Lookup(Mac mac);
    int Count { get; }
    Task EnsureLoadedAsync(CancellationToken ct = default);
}

public interface IDeviceClassifier
{
    /// <summary>Re-derives Brand/Model/Type/Os/confidence from the device's evidence. Returns true if anything changed.</summary>
    bool Classify(Device device);
}

public interface ILogoProvider
{
    /// <summary>Returns a cached PNG path for the device's brand/icon, fetching if needed; null when nothing found.</summary>
    Task<string?> GetLogoAsync(Device device, CancellationToken ct = default);
    string? TryGetCachedBrandLogo(string brand);
    Task PrefetchAllAsync(IProgress<ScanProgress>? progress, CancellationToken ct = default);
}

// ============================================================================================
//  Diagnostics (implemented in NetSpider.Diagnostics)
// ============================================================================================

public interface ILatencyEngine
{
    bool IsRunning { get; }
    void Start(ScanContext ctx);
    void Stop();
    /// <summary>Measured or estimated device↔device latency.</summary>
    Task<PairLatency?> MeasurePairAsync(Mac from, Mac to, CancellationToken ct);
}

public interface ITopologyBuilder
{
    /// <summary>Rebuilds links from all collected evidence (LLDP/CDP, FDB, traceroute, Wi-Fi, inference).</summary>
    void Rebuild(ScanContext ctx);
}

public interface IHealthService
{
    Task<HealthReport> RunAsync(ScanContext ctx, bool includeBufferbloat, CancellationToken ct);
}

/// <summary>
/// Opt-in internet reachability monitor: pings user-defined targets on an interval, tracks per-target latency/loss,
/// overall online/degraded/offline state and outage history. Works without packet capture.
/// </summary>
public interface IInternetMonitor
{
    bool IsRunning { get; }
    InternetStatus Status { get; }
    /// <summary>Starts or stops according to <see cref="AppSettings.InternetMonitorEnabled"/> and re-reads the target list.</summary>
    void ApplySettings();
    event Action<InternetStatus>? Updated;
}

public interface IWifiScanner
{
    bool Available { get; }
    Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken ct);
}

// ============================================================================================
//  Persistence / export (implemented in NetSpider.Export)
// ============================================================================================

public interface IDeviceRepository
{
    Task InitializeAsync(CancellationToken ct = default);
    /// <summary>Loads known devices (for "new device" detection and history).</summary>
    Task<IReadOnlyList<KnownDevice>> LoadKnownAsync(CancellationToken ct = default);
    Task SaveAsync(IEnumerable<Device> devices, CancellationToken ct = default);
    Task SaveAlertAsync(Alert alert, CancellationToken ct = default);
    Task SetUserLabelAsync(Mac mac, string? label, CancellationToken ct = default);
    /// <summary>Deletes all known devices and stored alerts (Settings → "Clear device history and incidents").</summary>
    Task ClearAsync(CancellationToken ct = default) => Task.CompletedTask;
}

public sealed record KnownDevice(Mac Mac, string? Name, string? Brand, string? Model, DeviceType Type, string? UserLabel, string? LastIp, DateTimeOffset FirstSeen, DateTimeOffset LastSeen);

public interface IExporter
{
    string Name { get; }
    string FileExtension { get; }
    Task ExportAsync(string path, ExportData data, CancellationToken ct = default);
}

public sealed record ExportData(IReadOnlyList<Device> Devices, IReadOnlyList<Link> Links, IReadOnlyList<Alert> Alerts, INetworkState Network, byte[]? TopologyPng, AdapterInfo? Adapter);

public interface INotifier
{
    Task NotifyAsync(Alert alert, CancellationToken ct = default);
}
