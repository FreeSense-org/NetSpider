using System.Net;
using System.Net.Sockets;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Shared view of "where are we" for the L2/L3 frame handlers: the current <see cref="ScanContext"/> (set when passive
/// monitoring starts and refreshed by every active probe) with a fallback to the capture adapter. Registered as an
/// <see cref="IPassiveMonitor"/> so the orchestrator hands it the context on start.
/// </summary>
public sealed class DiscoveryContext(IFrameSource frames, INetworkState network) : IPassiveMonitor
{
    private volatile ScanContext? _ctx;

    public string Name => "L2 discovery context";
    public ScanContext? Current => _ctx;
    public DateTimeOffset? MonitoringSince { get; private set; }

    public void Start(ScanContext ctx) { _ctx = ctx; MonitoringSince ??= DateTimeOffset.Now; }
    public void Stop() { MonitoringSince = null; }
    public void Update(ScanContext ctx) { _ctx = ctx; MonitoringSince ??= DateTimeOffset.Now; }

    public AdapterInfo? Adapter => _ctx?.Adapter ?? frames.Adapter;
    public Mac LocalMac => Adapter?.Mac ?? Mac.Zero;
    public IPAddress? LocalIPv4 => Adapter?.PrimaryV4?.Address;
    public IPAddress? Gateway => Adapter?.GatewayV4;
    public IPAddress? GatewayV6 => Adapter?.GatewayV6;
    public IPAddress? AdapterDhcpServer => Adapter?.DhcpServer;

    public bool IsLocalIp(IPAddress ip)
    {
        var a = Adapter;
        if (a is null) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork) return a.IPv4.Any(x => x.Address.Equals(ip));
        return a.IPv6.Any(x => x.Equals(ip) || x.GetAddressBytes().AsSpan().SequenceEqual(ip.GetAddressBytes()));
    }

    /// <summary>Every segment known for this scan: the context's plus anything discovered since (deduplicated by CIDR).</summary>
    public IReadOnlyList<NetworkSegment> AllSegments(ScanContext? ctx = null)
    {
        var list = new List<NetworkSegment>();
        var seen = new HashSet<string>();
        foreach (var s in network.Segments.Concat((ctx ?? _ctx)?.Segments ?? []))
            if (seen.Add(s.Cidr)) list.Add(s);
        return list;
    }

    public bool InLocalSegment(IPAddress ip)
    {
        var a = Adapter;
        if (a is not null && a.IPv4.Any(x => IpUtil.InSubnet(ip, x.Address, x.PrefixLength))) return true;
        return AllSegments().Any(s => s.IsLocal && s.Contains(ip));
    }
}

/// <summary>Publishes <see cref="PacketActivity"/> for the graph's packet rain, throttled to ~4 per second per source MAC.</summary>
public sealed class ActivityPublisher(IEventBus bus)
{
    private const int MaxPerSecond = 4;
    private readonly object _sync = new();
    private readonly Dictionary<Mac, (long Second, int Count)> _window = new();
    private long _lastPrune;

    public void Publish(Mac source, string protocol)
    {
        if (source.IsZero || source.IsMulticast) return;
        long now = Environment.TickCount64;
        long sec = now / 1000;
        lock (_sync)
        {
            if (_window.TryGetValue(source, out var w) && w.Second == sec)
            {
                if (w.Count >= MaxPerSecond) return;
                _window[source] = (sec, w.Count + 1);
            }
            else _window[source] = (sec, 1);
            if (now - _lastPrune > 60_000 && _window.Count > 4096)
            {
                _lastPrune = now;
                foreach (var k in _window.Where(kv => kv.Value.Second < sec - 5).Select(kv => kv.Key).ToList()) _window.Remove(k);
            }
        }
        bus.Publish(new PacketActivity(source, protocol, DateTimeOffset.Now));
    }
}

/// <summary>Evidence helpers shared by the passive parsers.</summary>
public static class DeviceHints
{
    /// <summary>Adds a <see cref="Fields.DeviceType"/> hint and sets the type immediately when nothing better is known yet.</summary>
    public static bool HintType(Device d, string source, DeviceType type, double confidence)
    {
        bool changed = d.AddEvidence(source, Fields.DeviceType, type.ToString(), confidence);
        if (d.Type == DeviceType.Unknown || (d.TypeConfidence < confidence && d.Type != DeviceType.ThisComputer && !d.Has(DeviceFlags.ThisHost)))
        {
            if (d.Type != type) { d.Type = type; d.TypeConfidence = confidence; changed = true; }
        }
        return changed;
    }

    /// <summary>
    /// Adds an advertised management IP. ARP is authoritative for on-link addresses (the mgmt IP may answer from an SVI MAC
    /// rather than the chassis MAC), so on-link IPs are attached without touching the store's IP index, and IPs another
    /// device already owns are left alone. Off-link management IPs are indexed normally.
    /// </summary>
    public static bool AddManagementIp(IDeviceStore store, DiscoveryContext ctx, Device d, IPAddress ip, string source)
    {
        ip = Normalize(ip);
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Loopback) || IpUtil.IsMulticast(ip)) return false;
        var owner = store.FindByIp(ip);
        if (owner is not null) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork && !ctx.InLocalSegment(ip))
        {
            bool had = d.HasIp(ip);
            store.Observe(d.Mac, ip, source);
            return !had;
        }
        return d.AddIp(ip);
    }

    /// <summary>Normalizes an IPv6 key (drops the scope id) / maps IPv4-in-IPv6.</summary>
    public static IPAddress Normalize(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) return ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0) return new IPAddress(ip.GetAddressBytes());
        return ip;
    }
}
