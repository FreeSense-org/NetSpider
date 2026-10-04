using System.Net;
using System.Net.Sockets;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.Topology;

/// <summary>Small classification helpers shared by the topology builder, latency engine and orchestrator.</summary>
public static class NodeKinds
{
    /// <summary>OUIs used by hypervisors / container runtimes for guest NICs.</summary>
    private static readonly uint[] VirtualOuis = [0x00155D /* Hyper-V */, 0x005056 /* VMware */, 0x000C29 /* VMware */, 0x000569 /* VMware */, 0x080027 /* VirtualBox */, 0x001C42 /* Parallels */, 0x525400 /* QEMU/KVM */];

    public static bool IsVirtualMac(Mac mac) =>
        Array.IndexOf(VirtualOuis, mac.Oui24) >= 0 || (mac[0] == 0x02 && mac[1] == 0x42 /* Docker */);

    public static bool IsVirtual(Device d) => d.Has(DeviceFlags.Virtual) || IsVirtualMac(d.Mac);

    /// <summary>Synthetic graph-only nodes (Internet, inferred switches, virtual groups) that have no IP and must not be probed.</summary>
    public static bool IsGraphOnly(Device d) =>
        d.Mac == SyntheticNodes.Internet || d.Type == DeviceType.Internet || d.Has(DeviceFlags.Inferred) ||
        (SyntheticNodes.IsSynthetic(d.Mac) && d.IPv4.Length == 0 && d.IPv6.Length == 0);

    public static bool IsSwitchType(DeviceType t) => t is DeviceType.CoreSwitch or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch;

    public static bool IsInfrastructure(Device d) =>
        d.Has(DeviceFlags.Infrastructure) || d.Has(DeviceFlags.Gateway) ||
        d.Type is DeviceType.Router or DeviceType.Firewall or DeviceType.CoreSwitch or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch or DeviceType.AccessPoint;

    public static bool IsRfc1918(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.IsIPv6LinkLocal || ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    }

    /// <summary>true when <paramref name="ip"/> lies in one of the directly attached (L2) subnets.</summary>
    public static bool IsOnLocalSubnet(IPAddress ip, ScanContext ctx, IEnumerable<NetworkSegment>? extra = null)
    {
        foreach (var a in ctx.Adapter.IPv4) if (IpUtil.InSubnet(ip, a.Address, a.PrefixLength)) return true;
        foreach (var s in ctx.Segments) if (s.IsLocal && s.Contains(ip)) return true;
        if (extra is not null) foreach (var s in extra) if (s.IsLocal && s.Contains(ip)) return true;
        return false;
    }
}

/// <summary>Assigns per-link latency: measured pair latency wins, otherwise |rtt(a) − rtt(b)| from host RTTs.</summary>
public static class LinkLatencyCalculator
{
    public const double FloorMs = 0.05;

    /// <returns>true when any link changed.</returns>
    public static bool Apply(IEnumerable<Link> links, Func<Mac, Device?> lookup, Mac localMac, Func<Mac, Mac, PairLatency?> pair)
    {
        bool changed = false;
        foreach (var l in links)
        {
            var p = pair(l.A, l.B);
            if (p is { Origin: LatencyOrigin.Measured })
            {
                changed |= Set(l, p.Ms, LatencyOrigin.Measured);
                continue;
            }
            // WAN latency comes from traceroute and is already measured.
            if (l.Kind == LinkKind.Wan && l.LatencyOrigin == LatencyOrigin.Measured && l.LatencyMs is not null) continue;
            var est = EstimateEdge(lookup(l.A), lookup(l.B), localMac);
            if (est is { } ms) changed |= Set(l, ms, LatencyOrigin.Estimated);
        }
        return changed;
    }

    /// <summary>Estimated latency of one edge from the two endpoints' host RTTs (same probe kind when possible).</summary>
    public static double? EstimateEdge(Device? a, Device? b, Mac localMac)
    {
        if (a is null || b is null) return null;
        bool aLocal = a.Mac == localMac || a.Has(DeviceFlags.ThisHost);
        bool bLocal = b.Mac == localMac || b.Has(DeviceFlags.ThisHost);
        if (aLocal && bLocal) return null;
        if (aLocal || bLocal)
        {
            var other = aLocal ? b : a;
            return other.Latency.BestLast is { } r ? Math.Max(FloorMs, r) : null;
        }
        foreach (var k in new[] { LatencyKind.Arp, LatencyKind.Ndp, LatencyKind.Icmp, LatencyKind.Tcp })
        {
            if (a.Latency.Last(k) is { } ra && b.Latency.Last(k) is { } rb) return Math.Max(FloorMs, Math.Abs(ra - rb));
        }
        if (a.Latency.BestLast is { } x && b.Latency.BestLast is { } y) return Math.Max(FloorMs, Math.Abs(x - y));
        return null;
    }

    private static bool Set(Link l, double ms, LatencyOrigin origin)
    {
        ms = Math.Round(ms, 3);
        if (l.LatencyMs == ms && l.LatencyOrigin == origin) return false;
        l.LatencyMs = ms;
        l.LatencyOrigin = origin;
        return true;
    }
}

/// <summary>Estimated device↔device latency as the cheapest path sum over the topology graph (Dijkstra).</summary>
public static class PathLatency
{
    public sealed record Result(double Ms, int Hops, IReadOnlyList<Mac> Path);

    /// <param name="unknownLinkMs">Weight used for links whose latency is not known yet.</param>
    public static Result? ShortestPath(IEnumerable<Link> links, Mac from, Mac to, double unknownLinkMs = 0.1)
    {
        if (from == to) return new Result(0, 0, [from]);
        var adj = new Dictionary<Mac, List<(Mac Next, double W)>>();
        foreach (var l in links)
        {
            double w = l.LatencyMs is { } ms && ms >= 0 ? ms : unknownLinkMs;
            Add(l.A, l.B, w);
            Add(l.B, l.A, w);
        }
        if (!adj.ContainsKey(from) || !adj.ContainsKey(to)) return null;

        var dist = new Dictionary<Mac, double> { [from] = 0 };
        var prev = new Dictionary<Mac, Mac>();
        var pq = new PriorityQueue<Mac, double>();
        pq.Enqueue(from, 0);
        var done = new HashSet<Mac>();
        while (pq.TryDequeue(out var u, out var du))
        {
            if (!done.Add(u)) continue;
            if (u == to) break;
            foreach (var (v, w) in adj[u])
            {
                var nd = du + w;
                if (!dist.TryGetValue(v, out var old) || nd < old)
                {
                    dist[v] = nd;
                    prev[v] = u;
                    pq.Enqueue(v, nd);
                }
            }
        }
        if (!dist.TryGetValue(to, out var total)) return null;
        var path = new List<Mac> { to };
        var cur = to;
        while (cur != from) { cur = prev[cur]; path.Add(cur); }
        path.Reverse();
        return new Result(Math.Round(total, 3), path.Count - 1, path);

        void Add(Mac a, Mac b, double w)
        {
            if (!adj.TryGetValue(a, out var list)) adj[a] = list = [];
            list.Add((b, w));
        }
    }
}
