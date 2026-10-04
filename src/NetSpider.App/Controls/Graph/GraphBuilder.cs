using NetSpider.App.Rendering;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using SkiaSharp;

namespace NetSpider.App.Controls.Graph;

/// <summary>Builds an immutable <see cref="GraphSnapshot"/> from the Core stores (BFS depth, radial anchors, tidy tree, port panels).</summary>
public static class GraphBuilder
{
    public const float TreeLevelGap = 165f;
    public const float TreeRowGap = 128f;
    public const float InternetOffset = 175f;

    private static readonly LinkKind[] KindPriority =
        [LinkKind.Wan, LinkKind.LldpCdp, LinkKind.BridgeFdb, LinkKind.VirtualHypervisor, LinkKind.WifiAssoc, LinkKind.InferredUnmanagedSwitch, LinkKind.L3Hop, LinkKind.GatewayStar];

    public static GraphSnapshot Build(IDeviceStore store, ITopologyStore topo, INetworkState net, AppSettings settings, int version)
    {
        var devices = store.All.OrderBy(d => d.Mac.Value).ToArray();
        var nodes = new List<GNode>(devices.Length);
        var index = new Dictionary<Mac, int>(devices.Length);

        using var nameFont = new SKFont(Fonts.SemiBold, 12.5f);
        using var smallFont = new SKFont(Fonts.Regular, 10.5f);
        using var monoFont = new SKFont(Fonts.Mono, 10f);

        foreach (var d in devices)
        {
            var n = ToNode(d, settings);
            index[d.Mac] = nodes.Count;
            n.Index = nodes.Count;
            MeasureLabel(n, settings.ShowMacOnNodes, nameFont, smallFont, monoFont);
            nodes.Add(n);
        }

        // ---- edges: dedupe per unordered pair, keep the most authoritative kind ----
        var bestPerPair = new Dictionary<(Mac, Mac), Link>();
        foreach (var l in topo.Links)
        {
            if (!index.ContainsKey(l.A) || !index.ContainsKey(l.B) || l.A == l.B) continue;
            if (!settings.ShowEstimatedLinks && l.Kind is LinkKind.GatewayStar or LinkKind.InferredUnmanagedSwitch && l.Confidence < 0.5) continue;
            var k = (l.A, l.B);
            if (!bestPerPair.TryGetValue(k, out var cur) || Array.IndexOf(KindPriority, l.Kind) < Array.IndexOf(KindPriority, cur.Kind))
                bestPerPair[k] = l;
        }
        var edges = bestPerPair.Values.Select(l => new GEdge
        {
            A = index[l.A], B = index[l.B], Kind = l.Kind, SpeedMbps = l.SpeedMbps, LatencyMs = l.LatencyMs, Origin = l.LatencyOrigin,
            PortA = l.PortA, PortB = l.PortB, PoeWatts = l.PoeWatts, Duplex = l.Duplex, Confidence = l.Confidence,
            Phase = (float)((l.A.Value * 2654435761UL ^ l.B.Value) % 1000) / 1000f,
        }).ToArray();

        int gateway = nodes.FindIndex(n => n.IsGateway);
        if (gateway < 0) gateway = nodes.FindIndex(n => n.Type is DeviceType.Router or DeviceType.Firewall && !n.IsInternet);
        int internet = nodes.FindIndex(n => n.IsInternet);
        if (gateway < 0 && nodes.Count > 0)
        {
            // no gateway known: centre on the most connected node
            var deg = new int[nodes.Count];
            foreach (var e in edges) { deg[e.A]++; deg[e.B]++; }
            gateway = Enumerable.Range(0, nodes.Count).Where(i => i != internet).OrderByDescending(i => deg[i]).DefaultIfEmpty(-1).First();
        }

        int maxDepth = ComputeDepths(nodes, edges, gateway, internet);
        ComputeAnchors(nodes, gateway, internet);
        ComputeTree(nodes, gateway, internet);

        var pairs = new Dictionary<(Mac, Mac), PairLatency>();
        foreach (var p in topo.PairLatencies)
            pairs[p.From.Value <= p.To.Value ? (p.From, p.To) : (p.To, p.From)] = p;

        // ring radii sized so each ring's circumference can hold its nodes (labels stagger in/out of the ring)
        var rings = new float[Math.Max(1, maxDepth) + 1];
        for (int d = 1; d < rings.Length; d++)
        {
            float need = nodes.Where(n => n.Depth == d && n.Index != internet).Sum(n => Math.Max(120f, n.LabelW + 10f));
            float byCount = need / (MathF.Tau * 1.55f) / ((GraphSnapshot.Ex + GraphSnapshot.Ey) / 2);
            rings[d] = Math.Max(d == 1 ? 215f : rings[d - 1] + 150f, byCount);
        }

        return new GraphSnapshot
        {
            Rings = rings,
            Version = version,
            Nodes = nodes.ToArray(),
            Edges = edges,
            Index = index,
            Pairs = pairs,
            Panels = BuildPanels(store, net),
            Gateway = gateway,
            Internet = internet,
            MaxDepth = maxDepth,
            GoodMs = settings.LatencyGoodMs,
            WarnMs = settings.LatencyWarnMs,
            BadMs = settings.LatencyBadMs,
            ShowEstimated = settings.ShowEstimatedLinks,
        };
    }

    private static GNode ToNode(Device d, AppSettings settings)
    {
        var type = d.Type;
        bool internet = d.Mac == SyntheticNodes.Internet || type == DeviceType.Internet;
        if (internet) type = DeviceType.Internet;
        bool gateway = d.Has(DeviceFlags.Gateway);
        bool inferred = d.Has(DeviceFlags.Inferred) || type == DeviceType.UnmanagedSwitch && SyntheticNodes.IsSynthetic(d.Mac);
        bool infra = internet || gateway || d.Has(DeviceFlags.Infrastructure) || GraphSnapshot.IsInfraType(type);

        var secFlags = new List<string>();
        if (d.Has(DeviceFlags.RogueDhcp)) secFlags.Add("Rogue DHCP server");
        if (d.Has(DeviceFlags.RogueRouterAdvert)) secFlags.Add("Rogue IPv6 RA");
        if (d.Has(DeviceFlags.CleartextManagement)) secFlags.Add("Cleartext management");
        if (d.Has(DeviceFlags.ExpiredCertificate)) secFlags.Add("Expired certificate");
        if (d.Has(DeviceFlags.SmbV1)) secFlags.Add("SMBv1 enabled");
        if (d.Has(DeviceFlags.DefaultSnmpCommunity)) secFlags.Add("Default SNMP community");
        if (d.Has(DeviceFlags.IpConflict)) secFlags.Add("IP conflict");

        var arp = d.Latency.Summarize(LatencyKind.Arp, 30);
        var icmp = d.Latency.Summarize(LatencyKind.Icmp, 30);
        var main = arp.Count > 0 ? arp : icmp;
        var l2 = d.Latency.Last(LatencyKind.Arp) ?? d.Latency.Last(LatencyKind.Ndp);
        var l3 = d.Latency.Last(LatencyKind.Icmp) ?? d.Latency.Last(LatencyKind.Tcp);

        string? subtitle = d.Brand is not null && d.Model is not null
            ? (d.Model.StartsWith(d.Brand, StringComparison.OrdinalIgnoreCase) ? d.Model : $"{d.Brand} {d.Model}")
            : d.Model ?? d.Brand;
        var ip = d.PrimaryIPv4?.ToString() ?? d.IPv6.FirstOrDefault()?.Address.ToString();
        var name = internet ? "Internet" : d.DisplayName;

        float radius = internet ? 30 : gateway ? 34 : type switch
        {
            DeviceType.Router or DeviceType.Firewall or DeviceType.CoreSwitch => 29,
            DeviceType.AccessSwitch or DeviceType.AccessPoint or DeviceType.UnmanagedSwitch => 25,
            DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor => 22,
            _ => 19,
        };

        return new GNode
        {
            Mac = d.Mac,
            Name = name,
            Subtitle = subtitle,
            Vendor = d.OuiVendor,
            Ip = internet ? (ip ?? null) : ip,
            MacText = d.Mac.ToString(),
            Type = type,
            Flags = d.Flags,
            State = d.State,
            L2 = internet ? null : l2,
            L3 = l3,
            Jitter = main.Jitter,
            Loss = main.LossPercent,
            LogoPath = d.LogoPath,
            Vlans = d.Vlans,
            NativeVlan = d.NativeVlan,
            Multicast = d.MulticastGroups.Length > 0,
            IsGateway = gateway,
            IsInternet = internet,
            IsInfra = infra,
            IsInferred = inferred,
            IsNew = d.Has(DeviceFlags.New),
            SecurityWarning = secFlags.Count > 0,
            SecurityText = secFlags.Count > 0 ? string.Join(", ", secFlags) : null,
            Group = GraphSnapshot.GroupOf(type),
            Radius = radius,
            SearchText = string.Join(' ', new[] { name, subtitle, d.OuiVendor, ip, d.Mac.ToString(), d.Hostname, type.ToString() }.Where(s => s is not null)).ToLowerInvariant(),
            Version = d.Version,
        };
    }

    public static string LatencyLine(GNode n) => n.IsInternet
        ? (n.L3 is { } w ? $"WAN {Neon.FormatMs(w)}" : "")
        : n.L2 is null && n.L3 is null ? (n.Offline ? "offline" : "") : $"L2 {Neon.FormatMs(n.L2)} · L3 {Neon.FormatMs(n.L3)}";

    private static void MeasureLabel(GNode n, bool showMac, SKFont nameFont, SKFont smallFont, SKFont monoFont)
    {
        float w = nameFont.MeasureText(Truncate(n.Name, 28));
        int lines = 1;
        if (n.Ip is { } ip) { w = Math.Max(w, smallFont.MeasureText(ip)); lines++; }
        if (showMac && !n.IsInternet && !n.IsInferred) { w = Math.Max(w, monoFont.MeasureText(n.MacText)); lines++; }
        var lat = LatencyLine(n);
        if (lat.Length > 0) { w = Math.Max(w, smallFont.MeasureText(lat)); lines++; }
        n.LabelW = w + 14;
        n.LabelH = 6 + 16 + (lines - 1) * 13.5f;
    }

    public static string Truncate(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    /// <summary>BFS from the gateway over the links; unreachable nodes hang off the gateway at depth 1.</summary>
    private static int ComputeDepths(List<GNode> nodes, GEdge[] edges, int gateway, int internet)
    {
        var adj = new List<(int To, GEdge E)>[nodes.Count];
        for (int i = 0; i < adj.Length; i++) adj[i] = [];
        foreach (var e in edges) { adj[e.A].Add((e.B, e)); adj[e.B].Add((e.A, e)); }

        foreach (var n in nodes) { n.Depth = -1; n.Parent = -1; }
        int maxDepth = 0;
        if (gateway < 0) return 0;
        var q = new Queue<int>();
        nodes[gateway].Depth = 0;
        q.Enqueue(gateway);
        while (q.Count > 0)
        {
            int i = q.Dequeue();
            // explore infrastructure first so endpoints attach to the deepest switch path deterministically
            foreach (var (to, e) in adj[i].OrderBy(a => nodes[a.To].IsInfra ? 0 : 1).ThenBy(a => Array.IndexOf(KindPriority, a.E.Kind)))
            {
                if (to == internet || nodes[to].Depth >= 0) continue;
                nodes[to].Depth = nodes[i].Depth + 1;
                nodes[to].Parent = i;
                nodes[to].ParentLatency = e.LatencyMs;
                maxDepth = Math.Max(maxDepth, nodes[to].Depth);
                q.Enqueue(to);
            }
        }
        foreach (var n in nodes)
        {
            if (n.Index == internet) { n.Depth = 0; n.Parent = gateway; n.ParentLatency = edges.FirstOrDefault(e => (e.A == internet || e.B == internet))?.LatencyMs; continue; }
            if (n.Depth < 0) { n.Depth = 1; n.Parent = gateway; maxDepth = Math.Max(maxDepth, 1); }
        }
        return maxDepth;
    }

    private static List<int>[] Children(List<GNode> nodes, int internet)
    {
        var ch = new List<int>[nodes.Count];
        for (int i = 0; i < ch.Length; i++) ch[i] = [];
        foreach (var n in nodes)
            if (n.Parent >= 0 && n.Index != internet) ch[n.Parent].Add(n.Index);
        foreach (var list in ch)
            list.Sort((a, b) =>
            {
                var na = nodes[a]; var nb = nodes[b];
                int c = (nb.IsInfra ? 1 : 0).CompareTo(na.IsInfra ? 1 : 0);
                if (c != 0) return c;
                c = na.Group.CompareTo(nb.Group);
                return c != 0 ? c : string.Compare(na.Name, nb.Name, StringComparison.OrdinalIgnoreCase);
            });
        return ch;
    }

    /// <summary>Radial-tree angles: every subtree gets an angular wedge proportional to its leaf count.</summary>
    private static void ComputeAnchors(List<GNode> nodes, int gateway, int internet)
    {
        if (gateway < 0) return;
        var ch = Children(nodes, internet);
        var leaves = new int[nodes.Count];
        int Count(int i) { int s = 0; foreach (var c in ch[i]) s += Count(c); return leaves[i] = Math.Max(1, s); }
        Count(gateway);

        // keep a gap at the top (−90°) for the Internet node
        float gap = internet >= 0 ? 0.62f : 0f;
        float start = -MathF.PI / 2 + gap / 2, span = MathF.Tau - gap;
        void Assign(int i, float a0, float a1, int depth)
        {
            nodes[i].AnchorAngle = (a0 + a1) / 2;
            float total = leaves[i] - (ch[i].Count == 0 ? 1 : 0);
            if (ch[i].Count == 0) return;
            // narrow wedges at depth > 1 so children huddle around their parent's direction
            float range = a1 - a0;
            if (depth >= 1)
            {
                float mid = (a0 + a1) / 2;
                float maxRange = Math.Min(range, 0.34f * ch[i].Sum(c => (float)leaves[c]) + 0.1f);
                a0 = mid - maxRange / 2; a1 = mid + maxRange / 2; range = maxRange;
            }
            float acc = a0;
            float sum = ch[i].Sum(c => (float)leaves[c]);
            foreach (var c in ch[i])
            {
                float w = range * leaves[c] / Math.Max(1, sum);
                Assign(c, acc, acc + w, depth + 1);
                acc += w;
            }
            _ = total;
        }
        Assign(gateway, start, start + span, 0);
        nodes[gateway].AnchorAngle = 0;
        if (internet >= 0) nodes[internet].AnchorAngle = -MathF.PI / 2;
    }

    /// <summary>Tidy top-down tree: Internet → gateway → switches → endpoints. Leaf children wrap into rows.</summary>
    private static void ComputeTree(List<GNode> nodes, int gateway, int internet)
    {
        if (gateway < 0 || nodes.Count == 0) return;
        // pick the leaf-grid width that gives the best fit for a 16:9 viewport
        int bestCols = 3;
        float bestZoom = 0;
        for (int cols = 2; cols <= 6; cols++)
        {
            ComputeTree(nodes, gateway, internet, cols);
            float w = nodes.Max(n => n.TreeX + n.LabelW / 2) - nodes.Min(n => n.TreeX - n.LabelW / 2) + 80;
            float h = nodes.Max(n => n.TreeY + n.Radius + n.LabelH) - nodes.Min(n => n.TreeY - n.Radius) + 80;
            float zoom = Math.Min(1920f / w, 1000f / h);
            if (zoom > bestZoom + 0.01f) { bestZoom = zoom; bestCols = cols; }
        }
        ComputeTree(nodes, gateway, internet, bestCols);
    }

    private static void ComputeTree(List<GNode> nodes, int gateway, int internet, int maxCols)
    {
        var ch = Children(nodes, internet);
        foreach (var n in nodes) n.TrunkX = float.NaN;
        float Slot(int i) => Math.Max(150f, nodes[i].LabelW + 22f);
        var width = new float[nodes.Count];

        float Measure(int i)
        {
            var leafs = ch[i].Where(c => ch[c].Count == 0).ToList();
            var subs = ch[i].Where(c => ch[c].Count > 0).ToList();
            float total = 0;
            foreach (var s in subs) total += Measure(s);
            if (leafs.Count > 0)
            {
                float slot = leafs.Max(Slot);
                total += Math.Min(maxCols, leafs.Count) * slot;
            }
            total += Math.Max(0, subs.Count + (leafs.Count > 0 ? 1 : 0) - 1) * 24f;
            return width[i] = Math.Max(Slot(i), total);
        }

        void Place(int i, float left, float y)
        {
            nodes[i].TreeX = left + width[i] / 2;
            nodes[i].TreeY = y;
            var leafs = ch[i].Where(c => ch[c].Count == 0).ToList();
            var subs = ch[i].Where(c => ch[c].Count > 0).ToList();
            float leafSlot = leafs.Count > 0 ? leafs.Max(Slot) : 0;
            int cols = Math.Min(maxCols, leafs.Count);
            float itemsW = subs.Sum(s => width[s]) + cols * leafSlot + Math.Max(0, subs.Count + (leafs.Count > 0 ? 1 : 0) - 1) * 24f;
            float x = left + (width[i] - itemsW) / 2;
            float cy = y + TreeLevelGap;
            // leaf block in the middle, subtrees split left and right of it so the tree stays balanced
            int half = subs.Count / 2;
            for (int k = 0; k < half; k++) { Place(subs[k], x, cy); x += width[subs[k]] + 24f; }
            if (leafs.Count > 0)
            {
                for (int k = 0; k < leafs.Count; k++)
                {
                    int r = k / cols, c = k % cols;
                    int inRow = Math.Min(cols, leafs.Count - r * cols);
                    float rowOffset = (cols - inRow) * leafSlot / 2;
                    nodes[leafs[k]].TreeX = x + rowOffset + c * leafSlot + leafSlot / 2;
                    nodes[leafs[k]].TreeY = cy + r * TreeRowGap;
                    // a single row hangs directly off the parent; multi-row grids share a trunk line
                    if (leafs.Count > cols) nodes[leafs[k]].TrunkX = x + cols * leafSlot / 2;
                }
                x += cols * leafSlot + 24f;
            }
            for (int k = half; k < subs.Count; k++) { Place(subs[k], x, cy); x += width[subs[k]] + 24f; }
        }

        float w = Measure(gateway);
        Place(gateway, -w / 2, 0);
        nodes[gateway].TreeX = 0;
        if (internet >= 0) { nodes[internet].TreeX = 0; nodes[internet].TreeY = -TreeLevelGap; }

        // centre vertically around 0 so transitions from the web stay in frame
        float minY = nodes.Min(n => n.TreeY), maxY = nodes.Max(n => n.TreeY);
        float shift = -(minY + maxY) / 2;
        foreach (var n in nodes) n.TreeY += shift;
    }

    private static SwitchPanel[] BuildPanels(IDeviceStore store, INetworkState net)
    {
        var ports = net.SwitchPorts;
        if (ports.Count == 0) return [];
        var fdb = net.Fdb;
        var panels = new List<SwitchPanel>();
        foreach (var g in ports.GroupBy(p => p.Switch))
        {
            store.TryGet(g.Key, out var sw);
            var cells = g.OrderBy(p => p.Index).Select(p => new PortCell
            {
                Index = p.Index, Name = p.Name, Alias = p.Alias, SpeedMbps = p.SpeedMbps, Up = p.Up, PoeWatts = p.PoeWatts, Duplex = p.Duplex, Pvid = p.Pvid,
            }).ToArray();
            foreach (var e in fdb.Where(f => f.Switch == g.Key))
            {
                var cell = cells.FirstOrDefault(c => e.PortIndex is { } pi ? c.Index == pi : string.Equals(c.Name, e.Port, StringComparison.OrdinalIgnoreCase))
                           ?? cells.FirstOrDefault(c => string.Equals(c.Name, e.Port, StringComparison.OrdinalIgnoreCase));
                if (cell is null || cell.Devices.Any(x => x.Mac == e.Mac)) continue;
                var name = store.TryGet(e.Mac, out var d) ? d.DisplayName : e.Mac.ToString();
                cell.Devices.Add((e.Mac, name));
            }
            panels.Add(new SwitchPanel
            {
                Switch = g.Key,
                Name = sw?.DisplayName ?? g.Key.ToString(),
                Model = sw is null ? null : string.Join(' ', new[] { sw.Brand, sw.Model }.Where(x => x is not null)),
                Ip = sw?.PrimaryIPv4?.ToString(),
                Ports = cells,
            });
        }
        return panels.OrderByDescending(p => p.Ports.Length).ToArray();
    }
}
