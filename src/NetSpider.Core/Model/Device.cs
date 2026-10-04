using System.Net;
using System.Net.Sockets;

namespace NetSpider.Core.Model;

public sealed record ServiceInfo(string Protocol, int Port, string Name, string? Type = null, string? Banner = null, IReadOnlyDictionary<string, string>? Txt = null)
{
    public string Key => $"{Protocol}/{Port}/{Type ?? Name}";
}

public sealed record PortInfo(int Port, string Protocol, PortState State, string? ServiceName = null, string? Banner = null, double? RttMs = null);

public sealed record TlsCertInfo(int Port, string Subject, string? CommonName, IReadOnlyList<string> SubjectAltNames, string Issuer,
    string? IssuerOrganization, DateTime NotBefore, DateTime NotAfter, string Serial, string Thumbprint, bool SelfSigned)
{
    public bool Expired => DateTime.UtcNow > NotAfter;
}

public sealed record Ipv6Info(IPAddress Address, Ipv6Kind Kind, Ipv6InterfaceIdKind InterfaceId);

public sealed record WifiAssociation(string Ssid, Mac Bssid, int Channel, string Band, int RssiDbm, string Phy);

/// <summary>
/// A network device, identified by MAC. Scalar properties may be written by any probe; collections are guarded by an
/// internal lock and exposed as snapshots. After mutating, call <c>IDeviceStore.NotifyChanged</c>.
/// </summary>
public sealed class Device
{
    private readonly object _sync = new();
    private readonly HashSet<IPAddress> _ipv4 = new();
    private readonly Dictionary<IPAddress, Ipv6Info> _ipv6 = new();
    private readonly Dictionary<string, string> _hostnames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ServiceInfo> _services = new();
    private readonly Dictionary<(int, string), PortInfo> _ports = new();
    private readonly HashSet<int> _vlans = new();
    private readonly HashSet<IPAddress> _groups = new();
    private readonly List<Evidence> _evidence = new();
    private readonly Dictionary<string, string> _props = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, TlsCertInfo> _certs = new();
    private long _flags;
    private int _version;

    public Device(Mac mac)
    {
        Mac = mac;
        FirstSeen = LastSeen = DateTimeOffset.Now;
        if (mac.IsRandomized) _flags |= (long)DeviceFlags.RandomizedMac;
    }

    public Mac Mac { get; }
    public string? OuiVendor { get; set; }
    public string? Brand { get; set; }
    public string? Model { get; set; }
    public string? Firmware { get; set; }
    public string? OsGuess { get; set; }
    public string? UserLabel { get; set; }
    public DeviceType Type { get; set; }
    public double TypeConfidence { get; set; }
    public double IdentityConfidence { get; set; }
    public int? NativeVlan { get; set; }
    public Mac? UpstreamMac { get; set; }
    public string? UpstreamPort { get; set; }
    public WifiAssociation? Wifi { get; set; }
    public string? LogoPath { get; set; }
    public string? IconUrl { get; set; }
    public int? Ttl { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public DeviceState State { get; set; } = DeviceState.Online;
    public LatencyStats Latency { get; } = new();
    /// <summary>Monotonic change counter for cheap UI diffing; incremented by the store on NotifyChanged.</summary>
    public int Version => Volatile.Read(ref _version);
    public void Bump() => Interlocked.Increment(ref _version);

    public DeviceFlags Flags => (DeviceFlags)Interlocked.Read(ref _flags);
    public bool Has(DeviceFlags f) => (Flags & f) == f;
    public void SetFlag(DeviceFlags f, bool on = true)
    {
        long cur, next;
        do { cur = Interlocked.Read(ref _flags); next = on ? cur | (long)f : cur & ~(long)f; }
        while (Interlocked.CompareExchange(ref _flags, next, cur) != cur);
    }

    public void Touch() { LastSeen = DateTimeOffset.Now; State = DeviceState.Online; }

    // ---- display helpers ----
    private static readonly string[] HostnamePriority = ["user", "snmp", "lldp", "cdp", "mdns", "ssdp", "netbios", "dhcp", "dns", "llmnr", "smb", "vendor", "tls"];

    public string? Hostname
    {
        get
        {
            lock (_sync)
            {
                foreach (var src in HostnamePriority) if (_hostnames.TryGetValue(src, out var h)) return h;
                return _hostnames.Values.FirstOrDefault();
            }
        }
    }

    public string DisplayName => UserLabel ?? Hostname ?? (Brand != null && Model != null ? $"{Brand} {Model}" : null) ?? Model ?? Brand ?? OuiVendor ?? Mac.ToString();

    public IPAddress? PrimaryIPv4 { get { lock (_sync) return _ipv4.OrderBy(a => a.ToString(), StringComparer.Ordinal).FirstOrDefault(); } }

    // ---- collections (snapshots) ----
    public IPAddress[] IPv4 { get { lock (_sync) return _ipv4.ToArray(); } }
    public Ipv6Info[] IPv6 { get { lock (_sync) return _ipv6.Values.ToArray(); } }
    public IReadOnlyDictionary<string, string> Hostnames { get { lock (_sync) return new Dictionary<string, string>(_hostnames); } }
    public ServiceInfo[] Services { get { lock (_sync) return _services.Values.ToArray(); } }
    public PortInfo[] Ports { get { lock (_sync) return _ports.Values.OrderBy(p => p.Port).ToArray(); } }
    public int[] Vlans { get { lock (_sync) return _vlans.OrderBy(v => v).ToArray(); } }
    public IPAddress[] MulticastGroups { get { lock (_sync) return _groups.ToArray(); } }
    public Evidence[] Evidence { get { lock (_sync) return _evidence.ToArray(); } }
    public IReadOnlyDictionary<string, string> Properties { get { lock (_sync) return new Dictionary<string, string>(_props); } }
    public TlsCertInfo[] Certificates { get { lock (_sync) return _certs.Values.ToArray(); } }

    /// <returns>true when the address is new.</returns>
    public bool AddIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        lock (_sync)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork) return _ipv4.Add(ip);
            if (_ipv6.ContainsKey(ip)) return false;
            _ipv6[ip] = new Ipv6Info(ip, Ipv6Classifier.Kind(ip), Ipv6Classifier.InterfaceId(ip, Mac));
            return true;
        }
    }

    public bool RemoveIp(IPAddress ip) { lock (_sync) return _ipv4.Remove(ip) | _ipv6.Remove(ip); }

    public bool HasIp(IPAddress ip) { lock (_sync) return _ipv4.Contains(ip) || _ipv6.ContainsKey(ip); }

    /// <param name="source">Lowercase source key, e.g. "mdns", "netbios", "dns", "snmp", "dhcp", "user".</param>
    public bool SetHostname(string source, string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        name = name.Trim().TrimEnd('.');
        lock (_sync)
        {
            if (_hostnames.TryGetValue(source, out var old) && old == name) return false;
            _hostnames[source] = name;
            return true;
        }
    }

    public bool AddService(ServiceInfo s)
    {
        lock (_sync)
        {
            if (_services.TryGetValue(s.Key, out var old) && old.Name == s.Name && old.Banner == s.Banner) return false;
            _services[s.Key] = s;
            return true;
        }
    }

    public bool SetPort(PortInfo p)
    {
        lock (_sync)
        {
            var key = (p.Port, p.Protocol);
            if (_ports.TryGetValue(key, out var old) && old.State == p.State && old.Banner == p.Banner) return false;
            _ports[key] = p;
            return true;
        }
    }

    public bool AddVlan(int vlan) { lock (_sync) return _vlans.Add(vlan); }
    public bool AddMulticastGroup(IPAddress g) { lock (_sync) return _groups.Add(g); }
    public bool RemoveMulticastGroup(IPAddress g) { lock (_sync) return _groups.Remove(g); }

    public bool SetCertificate(TlsCertInfo c) { lock (_sync) { _certs[c.Port] = c; return true; } }

    /// <summary>Adds evidence, replacing an older entry with the same source+field.</summary>
    public bool AddEvidence(Evidence e)
    {
        lock (_sync)
        {
            var i = _evidence.FindIndex(x => x.Source == e.Source && x.Field == e.Field);
            if (i >= 0)
            {
                if (_evidence[i].Value == e.Value) return false;
                _evidence[i] = e;
            }
            else _evidence.Add(e);
            return true;
        }
    }

    public bool AddEvidence(string source, string field, string? value, double confidence) =>
        !string.IsNullOrWhiteSpace(value) && AddEvidence(NetSpider.Core.Model.Evidence.Of(source, field, value.Trim(), confidence));

    public bool SetProperty(string key, string? value)
    {
        if (value is null) return false;
        lock (_sync)
        {
            if (_props.TryGetValue(key, out var old) && old == value) return false;
            _props[key] = value;
            return true;
        }
    }

    public string? GetProperty(string key) { lock (_sync) return _props.TryGetValue(key, out var v) ? v : null; }

    public override string ToString() => $"{DisplayName} [{Mac}] {PrimaryIPv4}";
}

public static class Ipv6Classifier
{
    public static Ipv6Kind Kind(IPAddress ip)
    {
        if (ip.IsIPv6LinkLocal) return Ipv6Kind.LinkLocal;
        if (ip.IsIPv6Multicast) return Ipv6Kind.Multicast;
        var b = ip.GetAddressBytes();
        if ((b[0] & 0xFE) == 0xFC) return Ipv6Kind.UniqueLocal;
        if ((b[0] & 0xE0) == 0x20) return Ipv6Kind.GlobalUnicast;
        return Ipv6Kind.Other;
    }

    /// <summary>EUI-64 if the interface id is the MAC with FFFE inserted; otherwise privacy (stable or temporary).</summary>
    public static Ipv6InterfaceIdKind InterfaceId(IPAddress ip, Mac mac)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 16) return Ipv6InterfaceIdKind.Unknown;
        if (b[11] == 0xFF && b[12] == 0xFE)
        {
            var m = mac.ToBytes();
            bool matches = (b[8] ^ 0x02) == m[0] && b[9] == m[1] && b[10] == m[2] && b[13] == m[3] && b[14] == m[4] && b[15] == m[5];
            if (matches || mac.IsZero) return Ipv6InterfaceIdKind.Eui64;
        }
        // Link-local/ULA privacy ids are typically RFC 7217 stable; GUA without EUI-64 may be temporary (RFC 8981).
        return Kind(ip) == Ipv6Kind.GlobalUnicast ? Ipv6InterfaceIdKind.Temporary : Ipv6InterfaceIdKind.StablePrivacy;
    }
}
