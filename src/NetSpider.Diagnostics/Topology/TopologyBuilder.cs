using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.Topology;

/// <summary>
/// Rebuilds the full link set from collected evidence: WAN/traceroute, LLDP/CDP, switch FDBs (with unmanaged-switch
/// inference), Wi-Fi BSSIDs, virtual machines, routed hosts and finally a low-confidence star around the gateway.
/// </summary>
public sealed class TopologyBuilder : ITopologyBuilder
{
    /// <summary>Device property a probe may set (MAC string) to name the hypervisor hosting a VM.</summary>
    public const string HypervisorHostProperty = "hypervisorHost";

    private static readonly Mac VirtualGroup = SyntheticNodes.InferredSwitch(SyntheticNodes.Internet, "virtual-group");

    private readonly ILogger<TopologyBuilder> _log;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly object _gate = new();

    public TopologyBuilder(ILogger<TopologyBuilder> log, IDeviceStore devices, ITopologyStore topology, INetworkState network)
    {
        _log = log;
        _devices = devices;
        _topology = topology;
        _network = network;
    }

    public void Rebuild(ScanContext ctx)
    {
        lock (_gate)
        {
            try
            {
                var links = Compute(ctx);
                // keep the latency already measured/estimated for links that survive the rebuild
                var old = _topology.Links.ToDictionary(l => l.Key);
                foreach (var l in links)
                {
                    if (old.TryGetValue(l.Key, out var o))
                    {
                        if (l.LatencyMs is null && o.LatencyMs is not null) { l.LatencyMs = o.LatencyMs; l.LatencyOrigin = o.LatencyOrigin; }
                        l.SpeedMbps ??= o.SpeedMbps;
                        l.PoeWatts ??= o.PoeWatts;
                        l.Duplex ??= o.Duplex;
                    }
                }
                LinkLatencyCalculator.Apply(links, m => _devices.TryGet(m, out var d) ? d : null, ctx.LocalMac, _topology.GetPairLatency);
                _topology.ReplaceAll(links);
                AssignUpstream(links, ctx);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Topology rebuild failed");
            }
        }
    }

    /// <summary>Computes the link set (creating synthetic nodes in the device store as needed) without touching the topology store.</summary>
    public IReadOnlyList<Link> Compute(ScanContext ctx)
    {
        var b = new Builder();
        var byMac = _devices.All.ToDictionary(d => d.Mac);
        Device? thisHost = byMac.GetValueOrDefault(ctx.LocalMac) ?? byMac.Values.FirstOrDefault(d => d.Has(DeviceFlags.ThisHost));
        Device? gateway = byMac.Values.FirstOrDefault(d => d.Has(DeviceFlags.Gateway))
                          ?? (ctx.Gateway is { } g ? _devices.FindByIp(g) : null);
        Device? root = gateway ?? thisHost;

        Device Add(Mac mac)
        {
            if (byMac.TryGetValue(mac, out var d)) return d;
            d = _devices.GetOrAdd(mac);
            byMac[mac] = d;
            return d;
        }

        var portInfo = _network.SwitchPorts.GroupBy(p => p.Switch).ToDictionary(g => g.Key, g => g.ToArray());
        SwitchPortInfo? PortInfo(Mac sw, string? name, int? index)
        {
            if (!portInfo.TryGetValue(sw, out var ports)) return null;
            return ports.FirstOrDefault(p => index is not null && p.Index == index)
                   ?? ports.FirstOrDefault(p => name is not null && (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) || string.Equals(p.Alias, name, StringComparison.OrdinalIgnoreCase)));
        }

        // ---- 1. WAN / Internet ------------------------------------------------------------------------
        if (gateway is not null)
        {
            var chainEnd = gateway;
            double? prevRtt = null, wanRtt = null;
            foreach (var hop in _network.InternetPath.OrderBy(h => h.Ttl))
            {
                if (hop.Address is null) continue;
                if (gateway.HasIp(hop.Address)) { prevRtt = hop.RttMs; continue; }
                Device? hopDev = null;
                if (NodeKinds.IsRfc1918(hop.Address))
                    hopDev = _devices.FindByIp(hop.Address) ?? (byMac.TryGetValue(SyntheticNodes.Hop(hop.Address), out var hd) ? hd : null);
                if (hopDev is not null && hopDev != chainEnd)
                {
                    var from = chainEnd;
                    double? ms = hop.RttMs is { } r && prevRtt is { } p ? Math.Max(LinkLatencyCalculator.FloorMs, r - p) : null;
                    b.Add(from.Mac, hopDev.Mac, LinkKind.L3Hop, l => { l.Confidence = 0.8; if (ms is not null) { l.LatencyMs = ms; l.LatencyOrigin = LatencyOrigin.Measured; } });
                    chainEnd = hopDev;
                    prevRtt = hop.RttMs;
                    continue;
                }
                wanRtt = hop.RttMs;
                break;
            }

            var inet = Add(SyntheticNodes.Internet);
            if (inet.Type != DeviceType.Internet) inet.Type = DeviceType.Internet;
            inet.TypeConfidence = 1;
            inet.SetHostname("vendor", "Internet");
            if (_network.Wan?.ExternalIp is { } ext) inet.AddIp(ext);
            b.Add(chainEnd.Mac, inet.Mac, LinkKind.Wan, l =>
            {
                l.SetPort(chainEnd.Mac, "WAN");
                l.Confidence = 1;
                if (wanRtt is { } w) { l.LatencyMs = Math.Max(LinkLatencyCalculator.FloorMs, w); l.LatencyOrigin = LatencyOrigin.Measured; }
            });
        }

        // ---- 2. LLDP / CDP -----------------------------------------------------------------------------
        var lldpPorts = new Dictionary<(Mac, string), Mac>();
        foreach (var n in _network.Neighbors)
        {
            if (n.Reporter.IsZero || n.Reporter.IsMulticast) continue;
            var neighbor = ResolveNeighbor(n, byMac);
            if (neighbor is null)
            {
                Mac? m = n.NeighborMac is { IsZero: false, IsMulticast: false } nm ? nm
                    : Mac.TryParse(n.NeighborChassisId, out var cm) && !cm.IsZero && !cm.IsMulticast ? cm : null;
                if (m is null) continue;
                neighbor = Add(m.Value);
                neighbor.SetHostname(n.Protocol.ToLowerInvariant().Contains("cdp") ? "cdp" : "lldp", n.NeighborName);
                if (n.NeighborMgmtIp is { } ip) _devices.Observe(neighbor.Mac, ip, "lldp");
            }
            var reporter = Add(n.Reporter);
            if (reporter == neighbor) continue;
            var pi = PortInfo(reporter.Mac, n.ReporterPort, null);
            b.Add(reporter.Mac, neighbor.Mac, LinkKind.LldpCdp, l =>
            {
                l.SetPort(reporter.Mac, n.ReporterPort);
                l.SetPort(neighbor.Mac, n.NeighborPort);
                l.Confidence = 1;
                if (pi is not null) { l.SpeedMbps ??= pi.SpeedMbps; l.PoeWatts ??= pi.PoeWatts; l.Duplex ??= pi.Duplex; }
            });
            if (n.ReporterPort is { } rp) lldpPorts[(reporter.Mac, rp)] = neighbor.Mac;
        }

        // ---- 3. Bridge FDB -----------------------------------------------------------------------------
        BuildFromFdb(b, byMac, Add, lldpPorts, PortInfo);

        // ---- 4. Wi-Fi ----------------------------------------------------------------------------------
        foreach (var w in _network.WifiNetworks)
        {
            Device? ap = null;
            long best = long.MaxValue;
            foreach (var d in byMac.Values)
            {
                if (d.Mac.Oui24 != w.Bssid.Oui24 || d.Has(DeviceFlags.ThisHost) || SyntheticNodes.IsSynthetic(d.Mac)) continue;
                long diff = Math.Abs((long)d.Mac.Value - (long)w.Bssid.Value);
                if (diff <= 8 && diff < best) { best = diff; ap = d; }
            }
            if (ap is null) continue;
            if (ap.Type == DeviceType.Unknown) { ap.Type = DeviceType.AccessPoint; ap.TypeConfidence = Math.Max(ap.TypeConfidence, 0.6); }
            if (w.Connected && thisHost is not null)
            {
                var label = string.IsNullOrEmpty(w.Ssid) ? w.Band : $"{w.Ssid} ({w.Band})";
                b.Add(ap.Mac, thisHost.Mac, LinkKind.WifiAssoc, l => { l.SetPort(ap.Mac, label); l.Confidence = 0.95; });
                thisHost.SetFlag(DeviceFlags.WifiClient);
                thisHost.Wifi = new WifiAssociation(w.Ssid, w.Bssid, w.Channel, w.Band, w.RssiDbm, w.Phy);
            }
        }

        // ---- 5. Virtual machines -----------------------------------------------------------------------
        var hypervisors = byMac.Values.Where(d => d.Type == DeviceType.Hypervisor && !d.Has(DeviceFlags.Inferred)).ToList();
        foreach (var d in byMac.Values.ToList())
        {
            if (b.IsLinked(d.Mac) || !NodeKinds.IsVirtual(d) || d.Has(DeviceFlags.ThisHost) || d.Type == DeviceType.Hypervisor || NodeKinds.IsGraphOnly(d)) continue;
            Device? host = null;
            double conf = 0.8;
            if (Mac.TryParse(d.GetProperty(HypervisorHostProperty), out var hm) && byMac.TryGetValue(hm, out var hd)) host = hd;
            else if (ctx.Adapter.IsVirtual && thisHost is not null) host = thisHost;
            else if (hypervisors.Count == 1) { host = hypervisors[0]; conf = 0.5; }
            if (host is null || host == d)
            {
                var group = Add(VirtualGroup);
                group.Type = DeviceType.Hypervisor;
                group.TypeConfidence = 0.3;
                group.SetFlag(DeviceFlags.Inferred);
                group.SetFlag(DeviceFlags.Virtual);
                group.SetHostname("vendor", "Virtual machines");
                host = group;
                conf = 0.4;
            }
            var c = conf;
            b.Add(host.Mac, d.Mac, LinkKind.VirtualHypervisor, l => { l.Confidence = c; });
        }

        // ---- 6. Routed (off-subnet) hosts --------------------------------------------------------------
        var segments = _network.Segments;
        bool haveLocalInfo = ctx.Adapter.IPv4.Count > 0 || segments.Any(s => s.IsLocal) || ctx.Segments.Any(s => s.IsLocal);
        foreach (var d in byMac.Values.ToList())
        {
            if (b.IsLinked(d.Mac) || d == gateway || d == thisHost || d.Mac == SyntheticNodes.Internet) continue;
            var ip = d.PrimaryIPv4;
            bool off = d.Has(DeviceFlags.OffSubnet) || (ip is not null && haveLocalInfo && !NodeKinds.IsOnLocalSubnet(ip, ctx, segments));
            if (!off || ip is null) continue;
            var seg = segments.Where(s => s.Contains(ip)).OrderByDescending(s => s.PrefixLength).FirstOrDefault();
            Device? via = seg?.Gateway is { } sg ? _devices.FindByIp(sg) : null;
            if (via is null || via == d) via = gateway ?? thisHost;
            if (via is null || via == d) continue;
            b.Add(via.Mac, d.Mac, LinkKind.L3Hop, l => { l.Confidence = 0.5; });
        }

        // ---- 7. Remove stale synthetic nodes, then fallback star ----------------------------------------
        foreach (var d in byMac.Values.ToList())
        {
            if (d.Has(DeviceFlags.Inferred) && SyntheticNodes.IsSynthetic(d.Mac) && d.Mac != SyntheticNodes.Internet && !b.IsLinked(d.Mac))
            {
                _devices.Remove(d.Mac);
                byMac.Remove(d.Mac);
            }
        }
        if (root is not null)
        {
            foreach (var d in byMac.Values)
            {
                if (d == root || b.IsLinked(d.Mac) || d.Mac == SyntheticNodes.Internet) continue;
                b.Add(root.Mac, d.Mac, LinkKind.GatewayStar, l => { l.Confidence = 0.3; });
            }
            // islands (e.g. two devices only linked to each other) hang off the root through their best representative
            var reachable = Reachable(b.Links, (gateway is not null ? SyntheticNodes.Internet : root.Mac));
            reachable.Add(root.Mac);
            var visited = new HashSet<Mac>(reachable);
            foreach (var d in byMac.Values.Where(d => !visited.Contains(d.Mac) && b.IsLinked(d.Mac)).ToList())
            {
                if (visited.Contains(d.Mac)) continue;
                var island = Reachable(b.Links, d.Mac);
                visited.UnionWith(island);
                var rep = island.Select(m => byMac.GetValueOrDefault(m)).OfType<Device>()
                    .OrderByDescending(x => NodeKinds.IsInfrastructure(x) || x.Has(DeviceFlags.Inferred) || x.Type == DeviceType.Hypervisor)
                    .ThenByDescending(x => b.Degree(x.Mac))
                    .ThenBy(x => x.Mac)
                    .FirstOrDefault();
                if (rep is not null) b.Add(root.Mac, rep.Mac, LinkKind.GatewayStar, l => { l.Confidence = 0.3; });
            }
        }

        return b.Links.ToList();
    }

    // ---------------------------------------------------------------------------------------------------

    private void BuildFromFdb(Builder b, Dictionary<Mac, Device> byMac, Func<Mac, Device> add,
        Dictionary<(Mac, string), Mac> lldpPorts, Func<Mac, string?, int?, SwitchPortInfo?> portInfo)
    {
        var fdb = _network.Fdb;
        if (fdb.Count == 0) return;

        var switches = fdb.Select(e => e.Switch).ToHashSet();
        foreach (var d in byMac.Values) if (d.Type is DeviceType.CoreSwitch or DeviceType.AccessSwitch) switches.Add(d.Mac);

        // (switch, port) -> MACs learned there (excluding the switch itself, multicast and zero)
        var portMacs = new Dictionary<(Mac Sw, string Port), HashSet<Mac>>();
        var portIndex = new Dictionary<(Mac, string), int?>();
        foreach (var e in fdb)
        {
            if (e.Mac == e.Switch || e.Mac.IsMulticast || e.Mac.IsZero) continue;
            var key = (e.Switch, e.Port);
            if (!portMacs.TryGetValue(key, out var set)) portMacs[key] = set = [];
            set.Add(e.Mac);
            portIndex.TryAdd(key, e.PortIndex);
        }

        string? PortTowards(Mac sw, Mac target) =>
            portMacs.Where(kv => kv.Key.Sw == sw && kv.Value.Contains(target)).OrderBy(kv => kv.Value.Count).Select(kv => kv.Key.Port).FirstOrDefault();

        void ApplyPort(Link l, Mac sw, string port)
        {
            l.SetPort(sw, port);
            if (portInfo(sw, port, portIndex.GetValueOrDefault((sw, port))) is { } pi)
            {
                l.SpeedMbps ??= pi.SpeedMbps; l.PoeWatts ??= pi.PoeWatts; l.Duplex ??= pi.Duplex;
            }
        }

        // ---- switch <-> switch (uplinks) ----
        foreach (var ((sw, port), macs) in portMacs)
        {
            var others = macs.Where(m => switches.Contains(m) && m != sw).ToList();
            if (others.Count == 0) continue;
            if (lldpPorts.ContainsKey((sw, port))) continue; // LLDP already describes this port
            Mac direct; double conf;
            if (others.Count == 1) { direct = others[0]; conf = 0.95; }
            else
            {
                // the direct neighbour's port back towards us does not see any of the other candidates
                var passing = others.Where(c =>
                {
                    var back = PortTowards(c, sw);
                    return back is not null && !portMacs[(c, back)].Overlaps(others.Where(o => o != c));
                }).ToList();
                if (passing.Count == 1) { direct = passing[0]; conf = 0.9; }
                else
                {
                    // fall back to the candidate that sees the fewest MACs in total (closest to the edge is unlikely here)
                    direct = others.OrderBy(c => portMacs.Where(kv => kv.Key.Sw == c).Sum(kv => kv.Value.Count)).ThenBy(c => c).First();
                    conf = 0.5;
                }
            }
            if (b.HasPair(sw, direct)) continue;
            var dev = add(direct);
            var back2 = PortTowards(direct, sw);
            b.Add(sw, dev.Mac, LinkKind.BridgeFdb, l =>
            {
                ApplyPort(l, sw, port);
                if (back2 is not null) l.SetPort(direct, back2);
                l.Confidence = conf;
            });
        }

        // ---- end devices: each MAC belongs to the edge port (no switch behind it) with the fewest MACs ----
        bool IsEdge((Mac Sw, string Port) key) => !portMacs[key].Any(m => switches.Contains(m) && m != key.Sw);
        var assignment = new Dictionary<(Mac Sw, string Port), List<Mac>>();
        var allMacs = portMacs.Values.SelectMany(x => x).Where(m => !switches.Contains(m)).ToHashSet();
        foreach (var mac in allMacs)
        {
            var best = portMacs.Where(kv => kv.Value.Contains(mac) && IsEdge(kv.Key))
                .OrderBy(kv => kv.Value.Count).ThenBy(kv => kv.Key.Sw).Select(kv => (Found: true, kv.Key)).FirstOrDefault();
            if (!best.Found) continue;
            if (!assignment.TryGetValue(best.Key, out var list)) assignment[best.Key] = list = [];
            list.Add(mac);
        }

        foreach (var ((sw, port), members) in assignment)
        {
            if (!byMac.ContainsKey(sw)) add(sw);
            var known = members.Where(byMac.ContainsKey).Select(m => byMac[m]).ToList();

            // an LLDP/CDP neighbour on this port: it is the direct device; everything else sits behind it
            if (lldpPorts.TryGetValue((sw, port), out var lldpNeighbor))
            {
                var nb = byMac.GetValueOrDefault(lldpNeighbor);
                foreach (var d in known.Where(d => d.Mac != lldpNeighbor && !b.IsLinked(d.Mac)))
                    LinkBehind(b, nb, d);
                continue;
            }

            if (members.Count == 1)
            {
                if (known.Count == 1 && !b.HasPair(sw, known[0].Mac))
                    b.Add(sw, known[0].Mac, LinkKind.BridgeFdb, l => { ApplyPort(l, sw, port); l.Confidence = 1; });
                continue;
            }

            // a physical host plus its VMs
            var physical = members.Where(m => !NodeKinds.IsVirtualMac(m) && !(byMac.TryGetValue(m, out var x) && x.Has(DeviceFlags.Virtual))).ToList();
            if (physical.Count == 1 && byMac.TryGetValue(physical[0], out var host))
            {
                b.Add(sw, host.Mac, LinkKind.BridgeFdb, l => { ApplyPort(l, sw, port); l.Confidence = 0.9; });
                foreach (var vm in known.Where(k => k != host)) b.Add(host.Mac, vm.Mac, LinkKind.VirtualHypervisor, l => { l.Confidence = 0.8; });
                continue;
            }

            // exactly one known infrastructure device (AP, router, switch): direct device, the rest behind it
            var infra = known.Where(NodeKinds.IsInfrastructure).ToList();
            if (infra.Count == 1)
            {
                var head = infra[0];
                b.Add(sw, head.Mac, LinkKind.BridgeFdb, l => { ApplyPort(l, sw, port); l.Confidence = 0.8; });
                foreach (var d in known.Where(k => k != head)) LinkBehind(b, head, d);
                continue;
            }

            // several MACs on an edge port without LLDP/CDP: an unmanaged switch (or hub) sits there
            var inferredMac = SyntheticNodes.InferredSwitch(sw, port);
            var inferred = add(inferredMac);
            inferred.Type = DeviceType.UnmanagedSwitch;
            inferred.TypeConfidence = 0.6;
            inferred.SetFlag(DeviceFlags.Inferred);
            inferred.SetFlag(DeviceFlags.Infrastructure);
            var swName = byMac.TryGetValue(sw, out var swDev) ? swDev.DisplayName : sw.ToString();
            inferred.SetHostname("vendor", $"Inferred switch ({swName} {port})");
            inferred.SetProperty("inferredMacCount", members.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            b.Add(sw, inferredMac, LinkKind.InferredUnmanagedSwitch, l => { ApplyPort(l, sw, port); l.Confidence = 0.6; });
            foreach (var d in known) b.Add(inferredMac, d.Mac, LinkKind.InferredUnmanagedSwitch, l => { l.Confidence = 0.6; });
        }
    }

    private static void LinkBehind(Builder b, Device? head, Device d)
    {
        if (head is null || head == d) return;
        if (head.Type == DeviceType.AccessPoint)
            b.Add(head.Mac, d.Mac, LinkKind.WifiAssoc, l => { l.Confidence = 0.6; });
        else if (NodeKinds.IsVirtual(d))
            b.Add(head.Mac, d.Mac, LinkKind.VirtualHypervisor, l => { l.Confidence = 0.7; });
        else
            b.Add(head.Mac, d.Mac, LinkKind.BridgeFdb, l => { l.Confidence = 0.5; });
    }

    private Device? ResolveNeighbor(NeighborEntry n, Dictionary<Mac, Device> byMac)
    {
        if (n.NeighborMac is { } m && byMac.TryGetValue(m, out var d)) return d;
        if (Mac.TryParse(n.NeighborChassisId, out var cm) && byMac.TryGetValue(cm, out d)) return d;
        if (n.NeighborMgmtIp is { } ip && _devices.FindByIp(ip) is { } byIp) return byIp;
        if (n.NeighborChassisId is { } cid && IPAddress.TryParse(cid, out var cip) && cid.Contains('.') && _devices.FindByIp(cip) is { } byCip) return byCip;
        var name = n.NeighborName?.Trim();
        if (string.IsNullOrEmpty(name)) return null;
        var shortName = ShortName(name);
        foreach (var dev in byMac.Values)
        {
            foreach (var h in dev.Hostnames.Values)
                if (string.Equals(h, name, StringComparison.OrdinalIgnoreCase) || string.Equals(ShortName(h), shortName, StringComparison.OrdinalIgnoreCase))
                    return dev;
        }
        return null;
    }

    private static string ShortName(string s)
    {
        var i = s.IndexOf('.');
        return i > 0 && !IPAddress.TryParse(s, out _) ? s[..i] : s;
    }

    private static HashSet<Mac> Reachable(IEnumerable<Link> links, Mac start)
    {
        var adj = new Dictionary<Mac, List<Mac>>();
        foreach (var l in links)
        {
            if (!adj.TryGetValue(l.A, out var a)) adj[l.A] = a = [];
            if (!adj.TryGetValue(l.B, out var bb)) adj[l.B] = bb = [];
            a.Add(l.B); bb.Add(l.A);
        }
        var seen = new HashSet<Mac> { start };
        var q = new Queue<Mac>();
        q.Enqueue(start);
        while (q.TryDequeue(out var u))
            if (adj.TryGetValue(u, out var next))
                foreach (var v in next) if (seen.Add(v)) q.Enqueue(v);
        return seen;
    }

    /// <summary>BFS from the Internet/gateway (or this host) to set <see cref="Device.UpstreamMac"/>/<see cref="Device.UpstreamPort"/>.</summary>
    private void AssignUpstream(IReadOnlyList<Link> links, ScanContext ctx)
    {
        var adj = new Dictionary<Mac, List<Link>>();
        foreach (var l in links.OrderByDescending(l => l.Confidence))
        {
            if (!adj.TryGetValue(l.A, out var a)) adj[l.A] = a = [];
            if (!adj.TryGetValue(l.B, out var bb)) adj[l.B] = bb = [];
            a.Add(l); bb.Add(l);
        }
        Mac start;
        if (adj.ContainsKey(SyntheticNodes.Internet)) start = SyntheticNodes.Internet;
        else if (_devices.All.FirstOrDefault(d => d.Has(DeviceFlags.Gateway)) is { } gw && adj.ContainsKey(gw.Mac)) start = gw.Mac;
        else start = ctx.LocalMac;

        var parent = new Dictionary<Mac, (Mac Parent, string? Port)>();
        var seen = new HashSet<Mac> { start };
        var q = new Queue<Mac>();
        q.Enqueue(start);
        while (q.TryDequeue(out var u))
        {
            if (!adj.TryGetValue(u, out var ls)) continue;
            foreach (var l in ls)
            {
                var v = l.Other(u);
                if (!seen.Add(v)) continue;
                parent[v] = (u, l.PortOf(u));
                q.Enqueue(v);
            }
        }

        foreach (var d in _devices.All)
        {
            Mac? up = null; string? port = null;
            if (parent.TryGetValue(d.Mac, out var p)) { up = p.Parent; port = p.Port; }
            if (d.UpstreamMac != up || d.UpstreamPort != port)
            {
                d.UpstreamMac = up;
                d.UpstreamPort = port;
                _devices.NotifyChanged(d, "topology");
            }
        }
    }

    /// <summary>Accumulates links, de-duplicating per device pair (first, i.e. most deterministic, kind wins).</summary>
    private sealed class Builder
    {
        private readonly Dictionary<(Mac, Mac), Link> _byPair = new();
        private readonly Dictionary<Mac, int> _degree = new();

        public IEnumerable<Link> Links => _byPair.Values;

        public bool IsLinked(Mac m) => _degree.ContainsKey(m);
        public int Degree(Mac m) => _degree.GetValueOrDefault(m);
        public bool HasPair(Mac a, Mac b) => _byPair.ContainsKey(Key(a, b));

        public void Add(Mac a, Mac b, LinkKind kind, Action<Link>? init = null)
        {
            if (a == b) return;
            var key = Key(a, b);
            if (_byPair.TryGetValue(key, out var existing))
            {
                // keep the earlier (stronger) kind but fill in missing details
                var tmp = new Link(a, b, kind);
                init?.Invoke(tmp);
                existing.PortA ??= tmp.PortA;
                existing.PortB ??= tmp.PortB;
                existing.SpeedMbps ??= tmp.SpeedMbps;
                existing.PoeWatts ??= tmp.PoeWatts;
                existing.Duplex ??= tmp.Duplex;
                return;
            }
            var link = new Link(a, b, kind);
            link.Confidence = kind == LinkKind.GatewayStar ? 0.3 : 1.0;
            init?.Invoke(link);
            if (link.LatencyMs is null) link.LatencyOrigin = LatencyOrigin.Estimated;
            _byPair[key] = link;
            _degree[a] = _degree.GetValueOrDefault(a) + 1;
            _degree[b] = _degree.GetValueOrDefault(b) + 1;
        }

        private static (Mac, Mac) Key(Mac a, Mac b) => a.Value <= b.Value ? (a, b) : (b, a);
    }
}
