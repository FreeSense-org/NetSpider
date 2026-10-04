using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Controls.Graph;

/// <summary>UI-thread view parameters, copied into each draw operation (the renderer never sees a mutating instance).</summary>
public sealed class GraphViewState
{
    public float Width { get; set; }
    public float Height { get; set; }
    /// <summary>screen = world · Zoom + (Width/2 + PanX, Height/2 + PanY)</summary>
    public float Zoom { get; set; } = 1f;
    public float PanX { get; set; }
    public float PanY { get; set; }
    public GraphViewMode Mode { get; set; }
    public Mac? Selected { get; set; }
    public Mac? Hovered { get; set; }
    public (Mac A, Mac B)? HoveredEdge { get; set; }
    public SKPoint Mouse { get; set; }
    public bool MouseInside { get; set; }
    public string? Search { get; set; }
    public HashSet<TypeGroup> HiddenGroups { get; set; } = [];
    public int? VlanFilter { get; set; }
    public bool ShowMac { get; set; } = true;
    public bool Animations { get; set; } = true;
    public bool ShowLegend { get; set; } = true;
    /// <summary>Node currently dragged and its world position (applied immediately, before physics catches up).</summary>
    public Mac? Dragging { get; set; }
    public SKPoint DragWorld { get; set; }
    /// <summary>Render positions at their targets immediately (snapshot export).</summary>
    public bool Instant { get; set; }

    public GraphViewState Clone()
    {
        var c = (GraphViewState)MemberwiseClone();
        c.HiddenGroups = [.. HiddenGroups];
        return c;
    }

    public SKPoint ToScreen(float wx, float wy) => new(wx * Zoom + Width / 2 + PanX, wy * Zoom + Height / 2 + PanY);
    public SKPoint ToWorld(float sx, float sy) => new((sx - Width / 2 - PanX) / Zoom, (sy - Height / 2 - PanY) / Zoom);

    public bool IsVisible(GNode n)
    {
        if (HiddenGroups.Count > 0 && HiddenGroups.Contains(n.Group) && !n.IsGateway && !n.IsInternet) return false;
        if (VlanFilter is { } v && !n.IsGateway && !n.IsInternet && !n.IsInfra && !(n.Vlans.Contains(v) || n.NativeVlan == v || (v == 1 && n.Vlans.Length == 0 && n.NativeVlan is null))) return false;
        return true;
    }

    public bool MatchesSearch(GNode n) => string.IsNullOrWhiteSpace(Search) || n.SearchText.Contains(Search.Trim().ToLowerInvariant());
}

/// <summary>What the last rendered frame looked like (for hit testing on the UI thread).</summary>
public sealed class RenderedFrame
{
    public static readonly RenderedFrame Empty = new() { Snapshot = GraphSnapshot.Empty, X = [], Y = [] };
    public required GraphSnapshot Snapshot { get; init; }
    public required float[] X { get; init; }
    public required float[] Y { get; init; }
    public GraphViewMode Mode { get; init; }
    public List<(SKRect Rect, SwitchPanel Panel, PortCell Port)> PortHits { get; init; } = [];
    public SKRect ContentBounds { get; init; }
}
