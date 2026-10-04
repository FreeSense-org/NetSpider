using Avalonia;
using NetSpider.App.Services;
using NetSpider.Core.Services;
using Serilog;
using Serilog.Events;

namespace NetSpider.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // ---- updater: Velopack install/update/uninstall hooks must run before anything else ----
        VelopackHooks.Run(args);

        // ELEVATION (must run before single-instance check): Release builds are asInvoker so Velopack's unelevated
        // install/update/uninstall hooks can run; the GUI then relaunches itself elevated (UAC) for raw capture.
        if (Elevation.RelaunchElevatedIfNeeded(args)) return 0;

        var options = AppOptions.Parse(args);
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(AppLogging.LevelSwitch) // Settings → Application → Log level switches this at runtime
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.File(Path.Combine(AppPaths.Logs, "netspider-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
            .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
            .CreateLogger();

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Log.Fatal(e.ExceptionObject as Exception, "Unhandled exception");
            CrashReporter.Write(e.ExceptionObject as Exception, "AppDomain.UnhandledException", fatal: e.IsTerminating);
            if (e.IsTerminating) Log.CloseAndFlush();
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Log.Error(e.Exception, "Unobserved task exception");
            CrashReporter.Write(e.Exception, "TaskScheduler.UnobservedTaskException", fatal: false);
            e.SetObserved();
        };

        // ---- single instance (after Serilog, before any UI) ----------------------------------------------------------
        // A second launch forwards its arguments (e.g. --page) to the running NetSpider over a named pipe and exits.
        // Headless/debug switches (--snapshot, --hide-banners, --multi-instance) skip this.
        if (!options.SkipSingleInstance && !SingleInstance.TryStart(args))
        {
            Log.Information("NetSpider is already running; activated the existing window");
            Log.CloseAndFlush();
            return 0;
        }
        // ------------------------------------------------------------------------------------------------------------------

        try
        {
            Log.Information("FreeSense NetSpider {Version} ({Architecture}, {Runtime}) starting (args: {Args})",
                NetSpider.Core.AppInfo.InformationalVersion, NetSpider.Core.AppInfo.Architecture, NetSpider.Core.AppInfo.RuntimeVersion, string.Join(' ', args));
            AppHost.Options = options;
            if (options.SnapshotPath is not null) return SnapshotMode.Run(options);
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "NetSpider terminated unexpectedly");
            CrashReporter.Write(ex, "Main", fatal: true);
            return 1;
        }
        finally
        {
            AppHost.Dispose();
            SingleInstance.Current?.Dispose();
            Log.Information("NetSpider exited");
            Log.CloseAndFlush();
        }
    }

    // Avalonia configuration; also used by the visual designer.
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .With(new SkiaOptions { MaxGpuResourceSizeBytes = 256L * 1024 * 1024 })
            .LogToTrace();
}
