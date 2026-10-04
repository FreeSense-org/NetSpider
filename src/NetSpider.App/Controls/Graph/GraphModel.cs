using NetSpider.Core.Model;

namespace NetSpider.App.Controls.Graph;

public enum GraphViewMode { Web, Tree, Ports }

/// <summary>Coarse device grouping used by the filter chips.</summary>
public enum TypeGroup { Infrastructure, Computers, Mobile, Media, SmartHome, Cameras, Printers, Other }

/// <summary>Immutable per-frame view of one device, built from the store at ~4 Hz.</summary>
public sealed class GNode
{
    public required Mac Mac { get; init; }
    public int Index { get; set; }
    public required string Name { get; init; }
    public string? Subtitle { get; init; }
    public string? Vendor { get; init; }
    public string? Ip { get; init; }
    public required string MacText { get; init; }
    public DeviceType Type { get; init; }
    public DeviceFlags Flags { get; init; }
    public DeviceState State { get; init; }
    public double? L2 { get; init; }
    public double? L3 { get; init; }
    public double? Jitter { get; init; }
    public double Loss { get; init; }
    public string? LogoPath { get; init; }
    public int[] Vlans { get; init; } = [];
    public int? NativeVlan { get; init; }
    public bool Multicast { get; init; }
    public bool IsGateway { get; init; }
    public bool IsInternet { get; init; }
    public bool IsInfra { get; init; }
    public bool IsInferred { get; init; }
    public bool IsNew { get; init; }
    public bool SecurityWarning { get; init; }
    public string? SecurityText { get; init; }
    public TypeGroup Group { get; init; }
    public float Radius { get; init; }
    public required string SearchText { get; init; }
    public int Version { get; init; }

    // ---- computed by the builder ----
    public int Depth { get; set; }
    public int Parent { get; set; } = -1;
    /// <summary>Latency of the edge to <see cref="Parent"/> (for path-sum estimates).</summary>
    public double? ParentLatency { get; set; }
    public float AnchorAngle { get; set; }
    public float TreeX { get; set; }
    public float TreeY { get; set; }
    /// <summary>X of the shared trunk line for leaf rows in the tree (NaN when the node is not in a leaf grid).</summary>
    public float TrunkX { get; set; } = float.NaN;
    /// <summary>Label block size below the badge (world units).</summary>
    public float LabelW { get; set; }
    public float LabelH { get; set; }

    /// <summary>Best host→node latency for coloring (L2 first, then L3).</summary>
    public double? Best => L2 ?? L3;
    public bool Offline => State == DeviceState.Offline;
}

public sealed class GEdge
{
    public int A { get; init; }
    public int B { get; init; }
    public LinkKind Kind { get; init; }
    public long? SpeedMbps { get; init; }
    public double? LatencyMs { get; init; }
    public LatencyOrigin Origin { get; init; }
    public string? PortA { get; init; }
    public string? PortB { get; init; }
    public double? PoeWatts { get; init; }
    public string? Duplex { get; init; }
    public double Confidence { get; init; }
    public bool IsWifi => Kind == LinkKind.WifiAssoc;
    /// <summary>Deterministic per-edge phase so particles don't move in lockstep.</summary>
    public float Phase { get; init; }
}

public sealed class PortCell
{
    public required int Index { get; init; }
    public required string Name { get; init; }
    public string? Alias { get; init; }
    public long? SpeedMbps { get; init; }
    public bool? Up { get; init; }
    public double? PoeWatts { get; init; }
    public string? Duplex { get; init; }
    public int? Pvid { get; init; }
    public List<(Mac Mac, string Name)> Devices { get; } = [];
}

public sealed class SwitchPanel
{
    public required Mac Switch { get; init; }
    public required string Name { get; init; }
    public string? Model { get; init; }
    public string? Ip { get; init; }
    public required PortCell[] Ports { get; init; }
}

/// <summary>Result of a device↔device latency lookup.</summary>
public readonly record struct PairInfo(double Ms, LatencyOrigin Origin, string Method);

/// <summary>An immutable snapshot of the whole graph; render and physics threads only read it.</summary>
public sealed class GraphSnapshot
{
    public static readonly GraphSnapshot Empty = new() { Nodes = [], Edges = [], Index = new(), Pairs = new(), Panels = [] };

    public int Version { get; init; }
    public required GNode[] Nodes { get; init; }
    public required GEdge[] Edges { get; init; }
    public required Dictionary<Mac, int> Index { get; init; }
    public required Dictionary<(Mac, Mac), PairLatency> Pairs { get; init; }
    public required SwitchPanel[] Panels { get; init; }
    public int Gateway { get; init; } = -1;
    public int Internet { get; init; } = -1;
    public int MaxDepth { get; init; }
    public double GoodMs { get; init; } = 2;
    public double WarnMs { get; init; } = 20;
    public double BadMs { get; init; } = 50;
    public bool ShowEstimated { get; init; } = true;

    /// <summary>Web ring radius per BFS depth (index 0 = gateway). Rings are ellipses scaled by <see cref="Ex"/>/<see cref="Ey"/>.</summary>
    public float[] Rings { get; init; } = [0];
    public const float Ex = 1.32f, Ey = 0.80f;

    public float RingRadius(int depth) => depth <= 0 ? 0 : depth < Rings.Length ? Rings[depth] : Rings[^1] + (depth - Rings.Length + 1) * 170f;

    public GNode? Find(Mac mac) => Index.TryGetValue(mac, out var i) ? Nodes[i] : null;

    /// <summary>Measured/estimated device↔device latency; falls back to a path-sum or |rttA − rttB| estimate.</summary>
    public PairInfo? GetPair(int a, int b)
    {
        if (a == b) return null;
        var na = Nodes[a];
        var nb = Nodes[b];
        var key = na.Mac.Value <= nb.Mac.Value ? (na.Mac, nb.Mac) : (nb.Mac, na.Mac);
        if (Pairs.TryGetValue(key, out var p)) return new PairInfo(p.Ms, p.Origin, p.Method);

        // path sum over the BFS tree (walk both nodes up to their lowest common ancestor)
        double sum = 0;
        bool complete = true;
        int x = a, y = b, guard = 0;
        while (x != y && guard++ < 64)
        {
            var nx = Nodes[x];
            var ny = Nodes[y];
            if (nx.Depth >= ny.Depth && nx.Parent >= 0) { sum += Hop(nx, Nodes[nx.Parent]); x = nx.Parent; }
            else if (ny.Parent >= 0) { sum += Hop(ny, Nodes[ny.Parent]); y = ny.Parent; }
            else { complete = false; break; }
        }
        if (complete && x == y && sum > 0) return new PairInfo(sum, LatencyOrigin.Estimated, "path-sum");
        if (na.Best is { } ra && nb.Best is { } rb) return new PairInfo(Math.Max(0.02, Math.Abs(ra - rb) + Math.Min(ra, rb) * 0.5), LatencyOrigin.Estimated, "rtt-diff");
        return null;

        static double Hop(GNode child, GNode parent) =>
            child.ParentLatency ?? (child.Best is { } c && parent.Best is { } p ? Math.Max(0.02, Math.Abs(c - p)) : child.Best ?? 0.3);
    }

    public static TypeGroup GroupOf(DeviceType t) => t switch
    {
        DeviceType.Router or DeviceType.Firewall or DeviceType.CoreSwitch or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch
            or DeviceType.AccessPoint or DeviceType.Internet or DeviceType.Ups => TypeGroup.Infrastructure,
        DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor or DeviceType.VirtualMachine or DeviceType.Desktop
            or DeviceType.Laptop or DeviceType.ThisComputer => TypeGroup.Computers,
        DeviceType.Phone or DeviceType.Tablet or DeviceType.VoipPhone => TypeGroup.Mobile,
        DeviceType.Tv or DeviceType.MediaStreamer or DeviceType.AudioStreamer or DeviceType.GameConsole => TypeGroup.Media,
        DeviceType.SmartHomeHub or DeviceType.SmartPlug or DeviceType.Light or DeviceType.IoT => TypeGroup.SmartHome,
        DeviceType.Camera => TypeGroup.Cameras,
        DeviceType.Printer => TypeGroup.Printers,
        _ => TypeGroup.Other,
    };

    public static bool IsInfraType(DeviceType t) => t is DeviceType.Router or DeviceType.Firewall or DeviceType.CoreSwitch
        or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch or DeviceType.AccessPoint or DeviceType.Internet;
}

/// <summary>Things that happened that the renderer turns into short-lived effects.</summary>
public readonly record struct GraphEvent(GraphEventKind Kind, Mac Mac, string? Protocol = null, AlertSeverity Severity = AlertSeverity.Info);

public enum GraphEventKind { Packet, NewDevice, Alert }

/// <summary>Physics output: world positions per snapshot index.</summary>
public sealed class LayoutFrame
{
    public static readonly LayoutFrame Empty = new(GraphSnapshot.Empty, [], []);
    public LayoutFrame(GraphSnapshot snap, float[] x, float[] y) { Snapshot = snap; X = x; Y = y; }
    public GraphSnapshot Snapshot { get; }
    public float[] X { get; }
    public float[] Y { get; }
}

/// <summary>A suspected fault to highlight on the web: the suspect node and the link to its upstream.</summary>
public readonly record struct FaultMark(Mac Suspect, Mac? Upstream, string Tag);

/// <summary>
/// Live diagnostics overlay (incidents + switch-port health) that the renderer draws on top of the topology.
/// Immutable; <see cref="GraphEngine.Diagnostics"/> is swapped atomically by the UI's diagnostics feed.
/// </summary>
public sealed class GraphDiagnostics
{
    public static readonly GraphDiagnostics Empty = new();

    public IReadOnlyList<FaultMark> Faults { get; init; } = [];
    public IReadOnlySet<Mac> Affected { get; init; } = new HashSet<Mac>();
    public IReadOnlyDictionary<(Mac Switch, string Port), PortHealth> Ports { get; init; } = new Dictionary<(Mac, string), PortHealth>();

    public bool IsSuspect(Mac m) => Faults.Any(f => f.Suspect == m);
    public bool IsSuspectLink(Mac a, Mac b) => Faults.Any(f => f.Upstream is { } u && ((f.Suspect == a && u == b) || (f.Suspect == b && u == a)));
    public PortHealth? Port(Mac sw, string port) => Ports.TryGetValue((sw, port), out var p) ? p : null;
}
