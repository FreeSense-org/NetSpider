using System.Collections.Concurrent;
using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Core.Services;

public sealed class DeviceStore : IDeviceStore
{
    private readonly ConcurrentDictionary<Mac, Device> _devices = new();
    private readonly ConcurrentDictionary<IPAddress, Mac> _ipIndex = new();

    public IReadOnlyList<Device> All => _devices.Values.ToArray();
    public int Count => _devices.Count;

    public event Action<Device>? DeviceAdded;
    public event Action<Device, string?>? DeviceChanged;
    public event Action<Mac>? DeviceRemoved;

    public Device GetOrAdd(Mac mac)
    {
        if (_devices.TryGetValue(mac, out var d)) return d;
        var created = new Device(mac);
        d = _devices.GetOrAdd(mac, created);
        if (ReferenceEquals(d, created)) Safe(() => DeviceAdded?.Invoke(d));
        return d;
    }

    public bool TryGet(Mac mac, out Device device) => _devices.TryGetValue(mac, out device!);

    public Device? FindByIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return _ipIndex.TryGetValue(ip, out var mac) && _devices.TryGetValue(mac, out var d) ? d : null;
    }

    public Device Observe(Mac mac, IPAddress? ip, string source)
    {
        var d = GetOrAdd(mac);
        d.Touch();
        bool changed = false;
        if (ip is not null && !ip.Equals(IPAddress.Any) && !IpUtil.IsMulticast(ip))
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            changed = d.AddIp(ip);
            var prev = _ipIndex.GetOrAdd(ip, mac);
            if (prev != mac)
            {
                // IP moved to a new MAC (DHCP re-lease, conflict or spoof); detectors look at this separately.
                _ipIndex[ip] = mac;
                if (_devices.TryGetValue(prev, out var old) && old.State == DeviceState.Offline) old.RemoveIp(ip);
                changed = true;
            }
        }
        if (changed) NotifyChanged(d, source);
        return d;
    }

    public void NotifyChanged(Device device, string? reason = null)
    {
        device.Bump();
        Safe(() => DeviceChanged?.Invoke(device, reason));
    }

    public bool Remove(Mac mac)
    {
        if (!_devices.TryRemove(mac, out var d)) return false;
        foreach (var kv in _ipIndex.Where(kv => kv.Value == mac).ToList()) _ipIndex.TryRemove(kv.Key, out _);
        Safe(() => DeviceRemoved?.Invoke(mac));
        return true;
    }

    public void Clear()
    {
        foreach (var mac in _devices.Keys.ToList()) Remove(mac);
    }

    private static void Safe(Action a) { try { a(); } catch { /* subscribers must not break probes */ } }
}

public sealed class TopologyStore : ITopologyStore
{
    private readonly object _sync = new();
    private readonly Dictionary<(Mac, Mac, LinkKind), Link> _links = new();
    private readonly Dictionary<(Mac, Mac), PairLatency> _pairs = new();

    public event Action? Changed;

    public IReadOnlyList<Link> Links { get { lock (_sync) return _links.Values.ToArray(); } }

    public Link Upsert(Mac a, Mac b, LinkKind kind, Action<Link>? update = null)
    {
        var probe = new Link(a, b, kind);
        Link link;
        lock (_sync)
        {
            if (!_links.TryGetValue(probe.Key, out link!)) _links[probe.Key] = link = probe;
            link.LastSeen = DateTimeOffset.Now;
            update?.Invoke(link);
        }
        return link;
    }

    public void RemoveWhere(Func<Link, bool> predicate)
    {
        lock (_sync)
            foreach (var k in _links.Where(kv => predicate(kv.Value)).Select(kv => kv.Key).ToList()) _links.Remove(k);
    }

    public void ReplaceAll(IEnumerable<Link> links)
    {
        lock (_sync)
        {
            _links.Clear();
            foreach (var l in links) _links[l.Key] = l;
        }
        NotifyChanged();
    }

    public IEnumerable<Link> LinksOf(Mac mac)
    {
        lock (_sync) return _links.Values.Where(l => l.Touches(mac)).ToArray();
    }

    public void NotifyChanged() { try { Changed?.Invoke(); } catch { } }

    public IReadOnlyList<PairLatency> PairLatencies { get { lock (_sync) return _pairs.Values.ToArray(); } }

    public void SetPairLatency(PairLatency p)
    {
        lock (_sync) _pairs[Key(p.From, p.To)] = p;
    }

    public PairLatency? GetPairLatency(Mac a, Mac b)
    {
        lock (_sync) return _pairs.TryGetValue(Key(a, b), out var p) ? p : null;
    }

    public void Clear()
    {
        lock (_sync)
        {
            _links.Clear();
            _pairs.Clear();
        }
        NotifyChanged();
    }

    private static (Mac, Mac) Key(Mac a, Mac b) => a.Value <= b.Value ? (a, b) : (b, a);
}

public sealed class AlertService : IAlertService
{
    private readonly object _sync = new();
    private readonly List<Alert> _alerts = new();
    private readonly Dictionary<(AlertKind, Mac?), DateTimeOffset> _lastRaised = new();
    public const int MaxAlerts = 5000;

    public event Action<Alert>? AlertRaised;

    public IReadOnlyList<Alert> Alerts { get { lock (_sync) return _alerts.ToArray(); } }

    public bool Raise(Alert alert, TimeSpan? cooldown = null)
    {
        var cd = cooldown ?? TimeSpan.FromSeconds(60);
        lock (_sync)
        {
            var key = (alert.Kind, alert.Source);
            if (_lastRaised.TryGetValue(key, out var last) && alert.Time - last < cd) return false;
            _lastRaised[key] = alert.Time;
            _alerts.Add(alert);
            if (_alerts.Count > MaxAlerts) _alerts.RemoveRange(0, _alerts.Count - MaxAlerts);
        }
        try { AlertRaised?.Invoke(alert); } catch { }
        return true;
    }

    public void Clear() { lock (_sync) { _alerts.Clear(); _lastRaised.Clear(); } }
}

public sealed class NetworkState : INetworkState
{
    private readonly object _sync = new();
    private readonly List<NetworkSegment> _segments = new();
    private readonly Dictionary<IPAddress, DhcpServerInfo> _dhcp = new();
    private readonly Dictionary<Mac, StpInfo> _stp = new();
    private readonly Dictionary<int, VlanInfo> _vlans = new();
    private WanInfo? _wan;
    private IReadOnlyList<TracerouteHop> _path = [];
    private IReadOnlyList<WifiNetwork> _wifi = [];
    private HealthReport _health = HealthReport.Empty;
    private Mac? _querier;
    private bool? _tags;

    public event Action<string>? Changed;

    public IReadOnlyList<NetworkSegment> Segments { get { lock (_sync) return _segments.ToArray(); } }

    public NetworkSegment AddOrGetSegment(IPAddress network, int prefix, string source, Action<NetworkSegment>? update = null)
    {
        NetworkSegment seg;
        bool added = false;
        lock (_sync)
        {
            var net = IpUtil.NetworkAddress(network, prefix);
            seg = _segments.FirstOrDefault(s => s.Network.Equals(net) && s.PrefixLength == prefix)!;
            if (seg is null) { seg = new NetworkSegment(net, prefix, source); _segments.Add(seg); added = true; }
            update?.Invoke(seg);
        }
        Raise(added ? "segments" : "segment");
        return seg;
    }

    public IReadOnlyList<DhcpServerInfo> DhcpServers { get { lock (_sync) return _dhcp.Values.ToArray(); } }
    public void AddDhcpServer(DhcpServerInfo info) { lock (_sync) _dhcp[info.ServerIp] = info; Raise("dhcp"); }

    public IReadOnlyList<StpInfo> StpBridges { get { lock (_sync) return _stp.Values.ToArray(); } }
    public void AddStp(StpInfo info) { lock (_sync) _stp[info.SenderMac] = info; Raise("stp"); }

    public IReadOnlyList<VlanInfo> Vlans { get { lock (_sync) return _vlans.Values.OrderBy(v => v.Id).ToArray(); } }
    public void AddVlan(VlanInfo vlan)
    {
        lock (_sync)
        {
            if (_vlans.TryGetValue(vlan.Id, out var old))
                vlan = vlan with { Name = vlan.Name ?? old.Name, Native = vlan.Native || old.Native, Voice = vlan.Voice || old.Voice };
            _vlans[vlan.Id] = vlan;
        }
        Raise("vlans");
    }

    private readonly Dictionary<(Mac, string?, string), NeighborEntry> _neighbors = new();
    private readonly Dictionary<Mac, FdbEntry[]> _fdb = new();
    private readonly Dictionary<Mac, SwitchPortInfo[]> _ports = new();

    public IReadOnlyList<NeighborEntry> Neighbors { get { lock (_sync) return _neighbors.Values.ToArray(); } }

    public void AddNeighbor(NeighborEntry e)
    {
        var id = e.NeighborMac?.ToString() ?? e.NeighborChassisId ?? e.NeighborName ?? "";
        lock (_sync) _neighbors[(e.Reporter, e.ReporterPort, id)] = e;
        Raise("neighbors");
    }

    public IReadOnlyList<FdbEntry> Fdb { get { lock (_sync) return _fdb.Values.SelectMany(x => x).ToArray(); } }
    public void SetFdb(Mac switchMac, IEnumerable<FdbEntry> entries) { lock (_sync) _fdb[switchMac] = entries.ToArray(); Raise("fdb"); }

    public IReadOnlyList<SwitchPortInfo> SwitchPorts { get { lock (_sync) return _ports.Values.SelectMany(x => x).ToArray(); } }
    public void SetSwitchPorts(Mac switchMac, IEnumerable<SwitchPortInfo> ports) { lock (_sync) _ports[switchMac] = ports.ToArray(); Raise("switchports"); }

    public WanInfo? Wan { get { lock (_sync) return _wan; } set { lock (_sync) _wan = value; Raise("wan"); } }
    public IReadOnlyList<TracerouteHop> InternetPath { get { lock (_sync) return _path; } set { lock (_sync) _path = value; Raise("path"); } }
    public IReadOnlyList<WifiNetwork> WifiNetworks { get { lock (_sync) return _wifi; } set { lock (_sync) _wifi = value; Raise("wifi"); } }
    public HealthReport Health { get { lock (_sync) return _health; } set { lock (_sync) _health = value; Raise("health"); } }
    public TrafficSnapshot? LastTraffic { get; set; }
    public Mac? IgmpQuerier { get { lock (_sync) return _querier; } set { lock (_sync) _querier = value; Raise("igmp"); } }
    public bool? NicPassesVlanTags { get { lock (_sync) return _tags; } set { lock (_sync) _tags = value; Raise("vlans"); } }
    private volatile bool _isDemo;
    public bool IsDemo { get => _isDemo; set => _isDemo = value; }

    /// <summary>Change keys raised by <see cref="Reset"/> so every listener refreshes.</summary>
    public static readonly string[] ResetKeys = ["segments", "dhcp", "stp", "vlans", "neighbors", "fdb", "switchports", "wan", "path", "wifi", "health", "igmp"];

    public void Reset()
    {
        lock (_sync)
        {
            _segments.Clear();
            _dhcp.Clear();
            _stp.Clear();
            _vlans.Clear();
            _neighbors.Clear();
            _fdb.Clear();
            _ports.Clear();
            _wan = null;
            _path = [];
            _wifi = [];
            _health = HealthReport.Empty;
            _querier = null;
            _tags = null;
            LastTraffic = null;
        }
        foreach (var k in ResetKeys) Raise(k);
    }

    private void Raise(string what) { try { Changed?.Invoke(what); } catch { } }
}

public sealed class EventBus : IEventBus
{
    private readonly ConcurrentDictionary<Type, ImmutableHandlers> _handlers = new();

    private sealed class ImmutableHandlers(Delegate[] items) { public readonly Delegate[] Items = items; }

    public void Publish<T>(T evt)
    {
        if (!_handlers.TryGetValue(typeof(T), out var h)) return;
        foreach (var d in h.Items)
        {
            try { ((Action<T>)d)(evt); } catch { }
        }
    }

    public IDisposable Subscribe<T>(Action<T> handler)
    {
        _handlers.AddOrUpdate(typeof(T), _ => new([handler]), (_, old) => new([.. old.Items, handler]));
        return new Unsub(() => _handlers.AddOrUpdate(typeof(T), _ => new([]), (_, old) => new(old.Items.Where(x => !Equals(x, handler)).ToArray())));
    }

    private sealed class Unsub(Action a) : IDisposable { public void Dispose() => a(); }
}
