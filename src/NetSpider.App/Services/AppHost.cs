using NetSpider.Diagnostics.PathDoctor;
using NetSpider.Diagnostics.Wifi;
using NetSpider.Diagnostics.Agents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.App.Controls.Graph;
using NetSpider.App.ViewModels;
using NetSpider.Capture;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics;
using NetSpider.Discovery;
using NetSpider.Export;
using NetSpider.Fingerprint;
using NetSpider.Wifi;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>Command line: <c>--demo</c>, <c>--snapshot &lt;png&gt; [--view web|tree|ports] [--select text] [--hover text] [--size WxH]</c>.</summary>
public sealed record AppOptions
{
    public bool Demo { get; init; }
    public string? SnapshotPath { get; init; }
    public GraphViewMode View { get; init; } = GraphViewMode.Web;
    public string? Select { get; init; }
    public string? Hover { get; init; }
    public int Width { get; init; } = 1920;
    public int Height { get; init; } = 1080;
    public int Ticks { get; init; } = 45;
    /// <summary>GUI: start on this navigation page (web, devices, alerts, traffic, internet, path, incidents, storm, wifi, segments, health, settings).</summary>
    public string? Page { get; init; }
    /// <summary>Debug: open the Live MTR window for this IP at startup.</summary>
    public string? Mtr { get; init; }
    /// <summary>Screenshots: hide the Npcap / administrator banners.</summary>
    public bool HideBanners { get; init; }
    /// <summary>Demo: force a diagnostics scenario (<c>--scenario fault,storm</c> or <c>healthy</c>) for screenshots.</summary>
    public DemoScenario Scenario { get; init; }
    /// <summary>Debug/screenshots: open the About dialog at startup.</summary>
    public bool About { get; init; }
    /// <summary>Debug/screenshots: open the Update dialog with fake data (available, downloading, ready, error, uptodate).</summary>
    public string? UpdatePreview { get; init; }
    /// <summary>Debug/screenshots: <c>--about-tab about|license|notices|changelog</c> opens the About dialog on that tab.</summary>
    public string? AboutTab { get; init; }
    /// <summary>Debug/screenshots: <c>--whats-new [last-seen-version]</c> opens the What's new dialog ("current" = this version's changes).</summary>
    public string? WhatsNew { get; init; }

    // ---- shell / first-run essentials ----
    /// <summary><c>--minimized</c>: start hidden in the tray (used by the "Start with Windows" logon task).</summary>
    public bool Minimized { get; init; }
    /// <summary><c>--no-welcome</c>: don't show the first-run welcome wizard.</summary>
    public bool NoWelcome { get; init; }
    /// <summary><c>--multi-instance</c>: skip the single-instance check (debugging, parallel screenshot runs).</summary>
    public bool MultiInstance { get; init; }
    /// <summary>Hidden <c>--test-crash [ui]</c>: crash (or throw a recovered UI exception) a few seconds after start.</summary>
    public string? TestCrash { get; init; }
    /// <summary>Hidden <c>--test-toast</c>: show a desktop notification shortly after start.</summary>
    public bool TestToast { get; init; }
    /// <summary>
    /// Hidden <c>--demo-toggle-test [seconds]</c>: seeds a fake "real" device + alert, then toggles the demo network on and off
    /// three times (each phase lasts the given seconds, default 6) and logs the store counts and any demo/real leak.
    /// </summary>
    public int? DemoToggleTest { get; init; }
    /// <summary>Headless/debug runs (snapshot, screenshots) don't take part in single-instance handling.</summary>
    public bool SkipSingleInstance => SnapshotPath is not null || HideBanners || MultiInstance;

    public static AppOptions Parse(string[] args)
    {
        var o = new AppOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            switch (a)
            {
                case "--demo": o = o with { Demo = true }; break;
                case "--snapshot": o = o with { SnapshotPath = Next() }; break;
                case "--view":
                    o = o with
                    {
                        View = (Next() ?? "web").ToLowerInvariant() switch { "tree" => GraphViewMode.Tree, "ports" or "port" or "matrix" => GraphViewMode.Ports, _ => GraphViewMode.Web },
                    };
                    break;
                case "--select": o = o with { Select = Next() }; break;
                case "--page": o = o with { Page = Next()?.ToLowerInvariant() }; break;
                case "--hover": o = o with { Hover = Next() }; break;
                case "--mtr": o = o with { Mtr = Next() }; break;
                case "--hide-banners": o = o with { HideBanners = true }; break;
                case "--about": o = o with { About = true }; break;
                case "--about-tab": o = o with { About = true, AboutTab = Next()?.ToLowerInvariant() }; break;
                case "--whats-new":
                    o = o with { WhatsNew = i + 1 < args.Length && !args[i + 1].StartsWith("--") ? Next()! : "current" };
                    break;
                case "--update-preview":
                    var st = i + 1 < args.Length && !args[i + 1].StartsWith("--") ? Next()! : "available";
                    o = o with { UpdatePreview = st.ToLowerInvariant() };
                    break;
                case "--scenario":
                    var sc = DemoScenario.None;
                    foreach (var part in (Next() ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        sc |= part.ToLowerInvariant() switch { "fault" or "pathfault" => DemoScenario.PathFault, "storm" => DemoScenario.Storm, "healthy" => DemoScenario.Healthy, "isolation" or "crossover" => DemoScenario.Isolation, _ => DemoScenario.None };
                    o = o with { Scenario = sc };
                    break;
                case "--minimized": o = o with { Minimized = true }; break;
                case "--no-welcome": o = o with { NoWelcome = true }; break;
                case "--multi-instance": o = o with { MultiInstance = true }; break;
                case "--test-toast": o = o with { TestToast = true }; break;
                case "--demo-toggle-test":
                    int dts = 6;
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out var parsed)) { dts = Math.Clamp(parsed, 1, 600); i++; }
                    o = o with { DemoToggleTest = dts };
                    break;
                case "--test-crash":
                    o = o with { TestCrash = i + 1 < args.Length && !args[i + 1].StartsWith("--") ? args[++i] : "fatal" };
                    break;
                case "--ticks": o = o with { Ticks = int.TryParse(Next(), out var t) ? t : 45 }; break;
                case "--size":
                    var parts = (Next() ?? "").Split('x', 'X');
                    if (parts.Length == 2 && int.TryParse(parts[0], out var w) && int.TryParse(parts[1], out var h)) o = o with { Width = w, Height = h };
                    break;
            }
        }
        return o;
    }
}

/// <summary>Builds and owns the DI container.</summary>
public static class AppHost
{
    public static AppOptions Options { get; set; } = new();
    public static ServiceProvider? Services { get; private set; }

    public static ServiceProvider Build()
    {
        var sc = new ServiceCollection();
        sc.AddLogging(b => b.ClearProviders().SetMinimumLevel(LogLevel.Debug).AddSerilog(dispose: false));
        sc.AddNetSpiderCore()
          .AddNetSpiderCapture()
          .AddNetSpiderL2Discovery()
          .AddNetSpiderServiceDiscovery()
          .AddNetSpiderFingerprint()
          .AddNetSpiderDiagnostics()
          .AddNetSpiderWifi()
          .AddNetSpiderExport()
          .AddNetSpiderIncidentStore()
          .AddNetSpiderPathDoctor()
          .AddNetSpiderPortHealth()
          .AddNetSpiderStormCenter()
          .AddNetSpiderWifiLink()
          .AddNetSpiderApHealth()
          .AddNetSpiderProbeAgents();

        sc.AddSingleton<DemoNetwork>();
        sc.AddSingleton(sp => new GraphEngine(sp.GetRequiredService<IDeviceStore>(), sp.GetRequiredService<ITopologyStore>(),
            sp.GetRequiredService<INetworkState>(), sp.GetRequiredService<IAlertService>(), sp.GetRequiredService<IEventBus>(),
            sp.GetRequiredService<NetSpider.Core.Model.AppSettings>()));
        sc.AddSingleton<SelectionService>();
        sc.AddSingleton<DemoDiagnostics>();
        sc.AddSingleton<DiagnosticsFeed>();
        sc.AddSingleton<DataModeController>();
        // built-in updater (Velopack)
        sc.AddSingleton(sp => new UpdateService(sp.GetRequiredService<ISettingsStore>(), sp));

        sc.AddSingleton<MainWindowViewModel>();
        sc.AddSingleton<WebViewModel>();
        sc.AddSingleton<InspectorViewModel>();
        sc.AddSingleton<DevicesViewModel>();
        sc.AddSingleton<AlertsViewModel>();
        sc.AddSingleton<TrafficViewModel>();
        sc.AddSingleton<WifiViewModel>();
        sc.AddSingleton<SegmentsViewModel>();
        sc.AddSingleton<HealthViewModel>();
        sc.AddSingleton<InternetViewModel>();
        sc.AddSingleton<SettingsViewModel>();
        sc.AddSingleton<AgentsViewModel>();
        sc.AddSingleton<PathViewModel>();
        sc.AddSingleton<IncidentsViewModel>();
        sc.AddSingleton<StormViewModel>();
        sc.AddSingleton<WifiLinkViewModel>();

        Services = sc.BuildServiceProvider();
        return Services;
    }

    /// <summary>Resolves and starts every <see cref="IStartable"/> (persistence, notifications, ...).</summary>
    public static void StartStartables(IServiceProvider sp)
    {
        foreach (var s in sp.GetServices<IStartable>())
        {
            try { s.Start(); Log.Information("Started {Service}", s.GetType().Name); }
            catch (Exception ex) { Log.Error(ex, "Starting {Service} failed", s.GetType().Name); }
        }
    }

    public static void Dispose()
    {
        try { Services?.Dispose(); }
        catch (Exception ex) { Log.Warning(ex, "Disposing services failed"); }
        Services = null;
    }
}
