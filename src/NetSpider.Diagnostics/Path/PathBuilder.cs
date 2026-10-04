using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Topology;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>
/// Computes the ordered hop chain this host uses to reach the internet:
/// <c>This PC → [Wi-Fi AP] → switches (incl. inferred unmanaged ones) → router/firewall → [modem(s)] → ISP hops (≤3) → target</c>.
/// LAN hops come from the topology tree, the ISP side from the traceroute in <see cref="INetworkState.InternetPath"/>.
/// Works without topology too (this host → gateway → traceroute hops → target). Hop health fields are left empty.
/// </summary>
public sealed class PathBuilder
{
    public const int MaxIspHops = 3;
    public const int MaxAnchors = 3;
    public static readonly IPAddress DefaultTarget = IPAddress.Parse("1.1.1.1");

    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly Func<AppSettings> _settings;
    private readonly Func<AdapterInfo?> _adapter;

    public PathBuilder(IDeviceStore devices, ITopologyStore topology, INetworkState network, Func<AppSettings> settings, Func<AdapterInfo?> adapter)
    {
        _devices = devices;
        _topology = topology;
        _network = network;
        _settings = settings;
        _adapter = adapter;
    }

    public NetworkPath Build()
    {
        var now = DateTimeOffset.Now;
        var adapter = _adapter();
        var all = _devices.All;
        var hops = new List<HopDraft>();

        // ---- this host ---------------------------------------------------------------------------------
        Device? me = (adapter is { Mac.IsZero: false } && _devices.TryGet(adapter.Mac, out var byMac) ? byMac : null)
                     ?? all.FirstOrDefault(d => d.Has(DeviceFlags.ThisHost));
        var myIp = adapter?.PrimaryV4?.Address ?? me?.PrimaryIPv4;
        Mac? myMac = me?.Mac ?? (adapter is { Mac.IsZero: false } ? adapter.Mac : null);
        hops.Add(new HopDraft(HopRole.ThisHost, me?.DisplayName ?? Environment.MachineName, myMac, myIp, HopProbe.Self));

        bool wifi = me?.Wifi is not null || adapter?.IsWireless == true || (me?.Has(DeviceFlags.WifiClient) ?? false);

        // ---- gateway -----------------------------------------------------------------------------------
        var gwIp = adapter?.GatewayV4;
        Device? gw = (gwIp is not null ? _devices.FindByIp(gwIp) : null) ?? all.FirstOrDefault(d => d.Has(DeviceFlags.Gateway));
        gwIp ??= gw?.PrimaryIPv4;

        // ---- LAN hops from the topology tree ----------------------------------------------------------------
        var tree = TopologyTree.Build(_topology.Links, all);
        var lan = new List<Device>();
        if (myMac is { } mm && tree.Contains(mm))
        {
            foreach (var m in tree.ChainToRoot(mm).Skip(1))
            {
                if (gw is not null && m == gw.Mac) break;
                if (m == SyntheticNodes.Internet || !_devices.TryGet(m, out var d)) break;
                if (d.Type == DeviceType.Internet) break;
                if (gwIp is not null && d.HasIp(gwIp)) { gw ??= d; break; }
                lan.Add(d);
            }
        }

        // Wi-Fi: the first hop is the access point
        if (wifi)
        {
            var bssid = me?.Wifi?.Bssid ?? _network.WifiNetworks.FirstOrDefault(w => w.Connected)?.Bssid;
            var ssid = me?.Wifi?.Ssid ?? _network.WifiNetworks.FirstOrDefault(w => w.Connected)?.Ssid;
            Device? ap = lan.FirstOrDefault(d => d.Type == DeviceType.AccessPoint);
            if (ap is null && myMac is { } m0 && tree.UpstreamKind(m0) == LinkKind.WifiAssoc && tree.Parent(m0) is { } p0 && _devices.TryGet(p0, out var pd)) ap = pd;
            ap ??= bssid is { } b ? MatchBssid(all, b) : null;
            if (ap is not null && gw is not null && ap == gw)
            {
                // all-in-one router/AP: the router hop doubles as the radio hop
            }
            else if (ap is not null)
            {
                lan.Remove(ap);
                hops.Add(LanHop(ap, HopRole.AccessPoint, adapter, tree, all, myMac, prev: hops[^1]));
            }
            else
            {
                hops.Add(new HopDraft(HopRole.AccessPoint, string.IsNullOrEmpty(ssid) ? "Wi-Fi AP" : $"Wi-Fi AP {ssid}", bssid, null, HopProbe.None));
            }
        }

        foreach (var d in lan)
            hops.Add(LanHop(d, RoleOf(d), adapter, tree, all, myMac, prev: hops[^1]));

        if (gw is not null)
        {
            var role = gw.Type == DeviceType.Firewall ? HopRole.Firewall : HopRole.Router;
            hops.Add(LanHop(gw, role, adapter, tree, all, myMac, prev: hops[^1], ipOverride: gwIp));
        }
        else if (gwIp is not null)
        {
            hops.Add(new HopDraft(HopRole.Router, $"Gateway {gwIp}", null, gwIp, OnLocalSubnet(gwIp, adapter) ? HopProbe.ArpIcmp : HopProbe.IcmpOnly));
        }

        // ---- ISP side from the traceroute --------------------------------------------------------------------
        bool sawPublic = false;
        int ispHops = 0, modems = 0;
        var seenIps = new HashSet<IPAddress>(hops.Where(h => h.Ip is not null).Select(h => h.Ip!));
        foreach (var t in _network.InternetPath.OrderBy(h => h.Ttl))
        {
            if (t.Address is not { } ip) continue;
            if (seenIps.Contains(ip) || (gw is not null && gw.HasIp(ip)) || (myIp is not null && ip.Equals(myIp))) continue;
            if (OnLocalSubnet(ip, adapter) && !sawPublic) continue; // LAN-side hop already covered by the gateway
            seenIps.Add(ip);
            var dev = _devices.FindByIp(ip);
            bool knownLanBox = dev is not null && !SyntheticNodes.IsSynthetic(dev.Mac);
            // the first private hop behind the gateway is the ISP modem (double NAT); later private hops are only
            // modems when they are known LAN devices — otherwise they are the ISP's internal (RFC 1918) routers
            if (!sawPublic && IpUtil.IsPrivate(ip) && !IsCgnat(ip) && (modems == 0 || knownLanBox))
            {
                var name = knownLanBox ? dev!.DisplayName : t.Hostname ?? $"Modem {ip}";
                hops.Add(new HopDraft(HopRole.Modem, name, dev?.Mac, ip, HopProbe.IcmpOnly));
                modems++;
                continue;
            }
            sawPublic = true;
            if (ispHops >= MaxIspHops) break;
            ispHops++;
            hops.Add(new HopDraft(HopRole.IspHop, t.Hostname ?? $"ISP hop {ispHops} ({ip})", null, ip, HopProbe.IcmpOnly));
        }

        // UPnP IGD: a private WAN address on the router means another NAT box (ISP modem) sits upstream
        if (_network.Wan is { ExternalIp: { } ext } wan && IpUtil.IsPrivate(ext) && !IsCgnat(ext) && !hops.Any(h => h.Role == HopRole.Modem))
        {
            int at = hops.FindIndex(h => h.Role is HopRole.IspHop);
            var modem = new HopDraft(HopRole.Modem, "ISP modem (double NAT)", null, null, HopProbe.None)
            {
                Note = $"router WAN address {ext} is private (UPnP{(wan.GatewayModel is { } gm ? $", {gm}" : "")}) — a modem/NAT device sits upstream",
            };
            if (at < 0) hops.Add(modem); else hops.Insert(at, modem);
        }

        // ---- final target --------------------------------------------------------------------------------
        var target = _settings().InternetTargets.FirstOrDefault(t => t.Enabled && !string.IsNullOrWhiteSpace(t.Host));
        IPAddress? targetIp = target is null ? DefaultTarget : IPAddress.TryParse(target.Host.Trim(), out var tip) ? tip : null;
        string targetName = target is null ? $"Internet ({DefaultTarget})"
            : $"Internet ({(string.IsNullOrWhiteSpace(target.Name) ? target.Host.Trim() : $"{target.Name.Trim()} {target.Host.Trim()}")})";
        hops.Add(new HopDraft(HopRole.InternetTarget, targetName, null, targetIp, HopProbe.IcmpOnly));

        var result = hops.Select((h, i) => new PathHop(i, h.Role, h.Name, h.Mac, h.Ip, h.Probe, h.Anchors, h.PortIn,
            h.Probe == HopProbe.Self ? HopHealth.Up : HopHealth.Unknown, h.Probe == HopProbe.Self ? 0 : null, null, 0, null, null, null, h.Note, [])).ToList();
        return new NetworkPath(now, now, wifi ? "Wi-Fi" : "Wired", result);
    }

    private HopDraft LanHop(Device d, HopRole role, AdapterInfo? adapter, TopologyTree tree, IReadOnlyList<Device> all, Mac? myMac, HopDraft prev, IPAddress? ipOverride = null)
    {
        var ip = ipOverride ?? d.PrimaryIPv4;
        bool inferred = d.Has(DeviceFlags.Inferred) || (SyntheticNodes.IsGraphOnly(d.Mac) && ip is null);
        if (inferred && role == HopRole.Switch) role = HopRole.UnmanagedSwitch;
        if (d.Type == DeviceType.UnmanagedSwitch && ip is null) role = HopRole.UnmanagedSwitch;

        // port on this hop that faces the previous (downstream) hop
        string? portIn = prev.Mac is { } pm ? PortBetween(d.Mac, pm, tree) : null;

        IReadOnlyList<Mac> anchors = [];
        HopProbe probe;
        if (ip is not null && !inferred) probe = OnLocalSubnet(ip, adapter) ? HopProbe.ArpIcmp : HopProbe.IcmpOnly;
        else
        {
            anchors = PickAnchors(d.Mac, tree, myMac);
            probe = anchors.Count > 0 ? HopProbe.Anchors : HopProbe.None;
        }
        return new HopDraft(role, d.DisplayName, d.Mac, inferred ? null : ip, probe) { Anchors = anchors, PortIn = portIn };
    }

    private string? PortBetween(Mac hop, Mac prev, TopologyTree tree)
    {
        if (tree.Parent(prev) == hop) return tree.UpstreamPort(prev);
        var link = _topology.LinksOf(hop).FirstOrDefault(l => l.Touches(prev));
        return link?.PortOf(hop);
    }

    private IReadOnlyList<Mac> PickAnchors(Mac sw, TopologyTree tree, Mac? myMac)
    {
        var candidates = new List<Device>();
        foreach (var m in tree.Children(sw).Concat(tree.Descendants(sw)).Distinct())
        {
            if (m == myMac || !_devices.TryGet(m, out var d)) continue;
            if (d.Has(DeviceFlags.ThisHost) || NodeKinds.IsGraphOnly(d) || d.State != DeviceState.Online || d.PrimaryIPv4 is null) continue;
            candidates.Add(d);
        }
        var direct = tree.Children(sw).ToHashSet();
        return candidates
            .OrderByDescending(d => direct.Contains(d.Mac))
            .ThenByDescending(d => d.Latency.BestLast is not null)
            .ThenByDescending(d => NodeKinds.IsInfrastructure(d))
            .ThenBy(d => d.Mac)
            .Take(MaxAnchors).Select(d => d.Mac).ToList();
    }

    public static HopRole RoleOf(Device d) => d.Type switch
    {
        DeviceType.AccessPoint => HopRole.AccessPoint,
        DeviceType.Router => HopRole.Router,
        DeviceType.Firewall => HopRole.Firewall,
        DeviceType.UnmanagedSwitch => HopRole.UnmanagedSwitch,
        _ when d.Has(DeviceFlags.Inferred) => HopRole.UnmanagedSwitch,
        _ => HopRole.Switch,
    };

    private static Device? MatchBssid(IReadOnlyList<Device> all, Mac bssid)
    {
        Device? best = null;
        long bestDiff = long.MaxValue;
        foreach (var d in all)
        {
            if (d.Has(DeviceFlags.ThisHost) || SyntheticNodes.IsSynthetic(d.Mac) || d.Mac.Oui24 != bssid.Oui24) continue;
            long diff = Math.Abs((long)d.Mac.Value - (long)bssid.Value);
            if (diff <= 8 && diff < bestDiff) { bestDiff = diff; best = d; }
        }
        return best;
    }

    private static bool OnLocalSubnet(IPAddress ip, AdapterInfo? adapter) =>
        adapter is not null && adapter.IPv4.Any(a => IpUtil.InSubnet(ip, a.Address, a.PrefixLength));

    /// <summary>100.64.0.0/10 carrier-grade NAT: inside the ISP network, so it is an ISP hop rather than a home modem.</summary>
    private static bool IsCgnat(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 100 && b[1] >= 64 && b[1] < 128;
    }

    private sealed record HopDraft(HopRole Role, string Name, Mac? Mac, IPAddress? Ip, HopProbe Probe)
    {
        public IReadOnlyList<Mac> Anchors { get; init; } = [];
        public string? PortIn { get; init; }
        public string? Note { get; init; }
    }
}
