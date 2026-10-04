using NetSpider.App.Rendering;
using SkiaSharp;

namespace NetSpider.App.Controls.Graph;

/// <summary>Offscreen rendering of the graph to PNG (HTML report, --snapshot).</summary>
public static class GraphExport
{
    /// <summary>Fits the view so the content bounds fill the viewport.</summary>
    public static void Fit(GraphViewState v, SKRect bounds, float maxZoom = 1.6f, float margin = 0.97f, float topInset = 0)
    {
        if (v.Width <= 0 || v.Height <= 0 || bounds.Width <= 0 || bounds.Height <= 0) return;
        // keep the bottom-left legend clear of content in graph modes
        float reserve = v.Mode == GraphViewMode.Ports || v.Height < 400 ? 0 : 70;
        float zoom = Math.Min(v.Width / bounds.Width, (v.Height - reserve - topInset) / bounds.Height) * margin;
        v.Zoom = Math.Clamp(zoom, 0.2f, maxZoom);
        v.PanX = -bounds.MidX * v.Zoom;
        v.PanY = -bounds.MidY * v.Zoom - reserve / 2 + topInset / 2;
    }

    /// <summary>
    /// Renders the current graph state to a PNG. <paramref name="warmupFrames"/> frames are simulated at 60 fps first so
    /// pulses, particles and packet ripples look alive in the still image.
    /// </summary>
    public static byte[] RenderPng(GraphEngine engine, GraphViewState state, int width, int height, int warmupFrames = 45, bool drainEvents = false, float scale = 1f)
    {
        var frame = engine.Frame;
        var snap = frame.Snapshot;
        LogoCache.Preload(snap.Nodes.Select(n => n.LogoPath));

        var v = state.Clone();
        v.Width = width;
        v.Height = height;
        v.MouseInside = v.Hovered is not null || v.HoveredEdge is not null;
        v.Dragging = null;
        Fit(v, GraphRenderer.ContentBounds(snap, frame.X, frame.Y, v.Mode), v.Mode == GraphViewMode.Ports ? 1.6f : 1.25f);

        var info = new SKImageInfo((int)(width * scale), (int)(height * scale), SKColorType.Rgba8888, SKAlphaType.Premul);
        using var surface = SKSurface.Create(info) ?? throw new InvalidOperationException("Could not create Skia surface");
        var canvas = surface.Canvas;
        using var renderer = new GraphRenderer();
        double t0 = 20;
        for (int i = 0; i <= warmupFrames; i++)
        {
            v.Instant = i == 0;
            canvas.Save();
            canvas.Scale(scale);
            canvas.Clear(Neon.Background);
            renderer.Render(canvas, v, frame, drainEvents ? engine.Events : null, t0 + i / 60.0, engine.Diagnostics);
            canvas.Restore();
        }
        canvas.Flush();
        using var img = surface.Snapshot();
        using var data = img.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }
}
