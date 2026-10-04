using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Controls.Graph;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Headless <c>--snapshot</c>: builds the demo network, runs the layout synchronously and writes the graph as a PNG.
/// </summary>
public static class SnapshotMode
{
    public static int Run(AppOptions o)
    {
        try
        {
            // initialise Avalonia (no window) so the Inter font assets can be loaded
            Program.BuildAvaloniaApp().SetupWithoutStarting();
        }
        catch (Exception ex) { Log.Warning(ex, "Avalonia setup failed; falling back to system fonts"); }

        var sp = AppHost.Build();
        var settings = sp.GetRequiredService<AppSettings>();
        var demo = sp.GetRequiredService<DemoNetwork>();
        var engine = sp.GetRequiredService<GraphEngine>();
        engine.Attach();
        demo.Build();
        engine.Events.Clear(); // don't flood the still with "new device" ripples for the whole network
        for (int i = 0; i < o.Ticks; i++) demo.Tick();
        while (engine.Events.Count > 40) engine.Events.TryDequeue(out _);
        // diagnostics overlay (incident fault highlight, port health) from the simulated diagnostics
        var feed = sp.GetRequiredService<DiagnosticsFeed>();
        feed.Demo.Scenario = o.Scenario;
        feed.SetDemo(true);
        feed.Demo.Stop();
        feed.UpdateOverlay();

        engine.Rebuild();
        engine.RunLayout(600);
        var frame = engine.Frame;
        var snap = frame.Snapshot;
        if (Environment.GetEnvironmentVariable("NETSPIDER_DEBUG_LAYOUT") == "1")
            foreach (var a in snap.Nodes)
                foreach (var b in snap.Nodes)
                {
                    if (b.Index <= a.Index) continue;
                    float ax = frame.X[a.Index], ay = frame.Y[a.Index], bx = frame.X[b.Index], by = frame.Y[b.Index];
                    float ox = Math.Min(ax + a.LabelW / 2, bx + b.LabelW / 2) - Math.Max(ax - a.LabelW / 2, bx - b.LabelW / 2);
                    float oy = Math.Min(ay + a.Radius + 4 + a.LabelH, by + b.Radius + 4 + b.LabelH) - Math.Max(ay - a.Radius - 8, by - b.Radius - 8);
                    if (ox > 0 && oy > 0) Console.WriteLine($"overlap {a.Name} ({ax:0},{ay:0}) <-> {b.Name} ({bx:0},{by:0}) ox={ox:0} oy={oy:0} {a.State}/{b.State}");
                }

        var state = new GraphViewState { Mode = o.View, ShowMac = settings.ShowMacOnNodes, Animations = true };
        GNode? Find(string? text) => string.IsNullOrWhiteSpace(text) ? null
            : snap.Nodes.FirstOrDefault(n => n.Name.Contains(text, StringComparison.OrdinalIgnoreCase))
              ?? snap.Nodes.FirstOrDefault(n => n.SearchText.Contains(text.ToLowerInvariant()));
        if (Find(o.Select) is { } sel) state.Selected = sel.Mac;
        if (Find(o.Hover) is { } hov)
        {
            // place the virtual mouse just right of the hovered node after fitting
            var fit = new GraphViewState { Width = o.Width, Height = o.Height, Mode = o.View };
            GraphExport.Fit(fit, GraphRenderer.ContentBounds(snap, frame.X, frame.Y, o.View), o.View == GraphViewMode.Ports ? 1.6f : 1.25f);
            float wx = o.View == GraphViewMode.Tree ? hov.TreeX : frame.X[hov.Index];
            float wy = o.View == GraphViewMode.Tree ? hov.TreeY : frame.Y[hov.Index];
            state.Hovered = hov.Mac;
            state.Mouse = fit.ToScreen(wx + hov.Radius, wy);
            state.MouseInside = true;
        }

        var png = GraphExport.RenderPng(engine, state, o.Width, o.Height, warmupFrames: 40, drainEvents: true);
        var path = Path.GetFullPath(o.SnapshotPath!);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, png);
        Log.Information("Snapshot written to {Path} ({Nodes} nodes, {Edges} edges, view {View})", path, snap.Nodes.Length, snap.Edges.Length, o.View);
        Console.WriteLine($"Snapshot written: {path}");
        demo.Stop();
        engine.Dispose();
        return 0;
    }
}
