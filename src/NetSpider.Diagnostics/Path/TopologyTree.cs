using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>
/// Rooted spanning tree of the topology (same BFS as <c>TopologyBuilder.AssignUpstream</c>: rooted at the Internet node,
/// else the gateway; links visited by descending confidence). Devices that are not reached through links fall back to
/// their <see cref="Device.UpstreamMac"/>/<see cref="Device.UpstreamPort"/>.
/// </summary>
public sealed class TopologyTree
{
    private readonly Dictionary<Mac, (Mac Parent, string? Port, LinkKind? Kind)> _parent = new();
    private readonly Dictionary<Mac, List<Mac>> _children = new();

    private TopologyTree(Mac? root) => Root = root;

    public Mac? Root { get; }
    public int Count => _parent.Count;

    public static TopologyTree Build(IEnumerable<Link> links, IEnumerable<Device> devices, Mac? preferredRoot = null)
    {
        var linkList = links.ToList();
        var devList = devices.ToList();
        var adj = new Dictionary<Mac, List<Link>>();
        foreach (var l in linkList.OrderByDescending(l => l.Confidence))
        {
            if (!adj.TryGetValue(l.A, out var a)) adj[l.A] = a = [];
            if (!adj.TryGetValue(l.B, out var b)) adj[l.B] = b = [];
            a.Add(l); b.Add(l);
        }

        Mac? root = null;
        if (preferredRoot is { } pr && adj.ContainsKey(pr)) root = pr;
        else if (adj.ContainsKey(SyntheticNodes.Internet)) root = SyntheticNodes.Internet;
        else if (devList.FirstOrDefault(d => d.Has(DeviceFlags.Gateway) && adj.ContainsKey(d.Mac)) is { } gw) root = gw.Mac;
        else if (devList.FirstOrDefault(d => d.Has(DeviceFlags.ThisHost) && adj.ContainsKey(d.Mac)) is { } me) root = me.Mac;

        var t = new TopologyTree(root);
        if (root is { } r)
        {
            var seen = new HashSet<Mac> { r };
            var q = new Queue<Mac>();
            q.Enqueue(r);
            while (q.TryDequeue(out var u))
            {
                if (!adj.TryGetValue(u, out var ls)) continue;
                foreach (var l in ls)
                {
                    var v = l.Other(u);
                    if (!seen.Add(v)) continue;
                    t.SetParent(v, u, l.PortOf(u), l.Kind);
                    q.Enqueue(v);
                }
            }
        }

        // fallback: upstream chains computed earlier by the topology builder
        foreach (var d in devList)
        {
            if (t._parent.ContainsKey(d.Mac) || d.Mac == root || d.UpstreamMac is not { } up || up == d.Mac) continue;
            t.SetParent(d.Mac, up, d.UpstreamPort, null);
        }
        return t;
    }

    private void SetParent(Mac child, Mac parent, string? port, LinkKind? kind)
    {
        _parent[child] = (parent, port, kind);
        if (!_children.TryGetValue(parent, out var list)) _children[parent] = list = [];
        list.Add(child);
    }

    public bool Contains(Mac m) => m == Root || _parent.ContainsKey(m);

    public Mac? Parent(Mac m) => _parent.TryGetValue(m, out var p) ? p.Parent : null;

    /// <summary>Port on the parent where <paramref name="m"/> (or the subtree containing it) is attached.</summary>
    public string? UpstreamPort(Mac m) => _parent.TryGetValue(m, out var p) ? p.Port : null;

    public LinkKind? UpstreamKind(Mac m) => _parent.TryGetValue(m, out var p) ? p.Kind : null;

    public IReadOnlyList<Mac> Children(Mac m) => _children.TryGetValue(m, out var c) ? c : [];

    /// <summary>All nodes below <paramref name="m"/> (not including it).</summary>
    public IEnumerable<Mac> Descendants(Mac m)
    {
        var stack = new Stack<Mac>(Children(m));
        var seen = new HashSet<Mac> { m };
        while (stack.TryPop(out var x))
        {
            if (!seen.Add(x)) continue;
            yield return x;
            foreach (var c in Children(x)) stack.Push(c);
        }
    }

    /// <summary><paramref name="m"/>, its parent, …, up to the root (cycle-safe).</summary>
    public IReadOnlyList<Mac> ChainToRoot(Mac m)
    {
        var chain = new List<Mac> { m };
        var seen = new HashSet<Mac> { m };
        var cur = m;
        while (Parent(cur) is { } p && seen.Add(p))
        {
            chain.Add(p);
            cur = p;
        }
        return chain;
    }

    /// <summary>Deepest node that is an ancestor-or-self of every given node; null when they are in different trees.</summary>
    public Mac? LowestCommonAncestor(IEnumerable<Mac> nodes)
    {
        List<Mac>? common = null;
        foreach (var n in nodes.Distinct())
        {
            var chain = ChainToRoot(n);
            if (common is null) { common = chain.ToList(); continue; }
            var set = chain.ToHashSet();
            common = common.Where(set.Contains).ToList();
            if (common.Count == 0) return null;
        }
        return common is { Count: > 0 } ? common[0] : null;
    }
}
