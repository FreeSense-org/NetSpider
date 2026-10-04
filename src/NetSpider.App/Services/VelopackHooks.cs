using NetSpider.Core;
using Velopack;

namespace NetSpider.App.Services;

/// <summary>
/// Velopack startup integration. Must run first in <c>Main</c>: during install/update/uninstall Velopack starts the exe
/// with <c>--veloapp-*</c> arguments, runs the matching hook and exits the process. Hooks are non-interactive (no UI).
/// Velopack itself creates/removes the Start menu and desktop shortcuts (vpk default: Desktop + StartMenuRoot).
/// </summary>
public static class VelopackHooks
{
    /// <summary>The data folder (%LOCALAPPDATA%\NetSpider) without creating it.</summary>
    public static string DataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSpider");
    public static string RemoveDataMarkerPath => Path.Combine(DataRoot, UpdateLogic.RemoveDataMarker);

    public static void Run(string[] args)
    {
        try
        {
            VelopackApp.Build()
                .SetArgs(args)
                // Never apply a downloaded update behind the user's back at startup: the updater UI decides
                // (ready → "Install & restart", or install-on-exit).
                .SetAutoApplyOnStartup(false)
                .OnAfterInstallFastCallback(v => HookLog($"Installed {AppInfo.InstalledName} {v}"))
                .OnAfterUpdateFastCallback(v => HookLog($"Updated {AppInfo.InstalledName} to {v}"))
                .OnBeforeUninstallFastCallback(OnBeforeUninstall)
                .Run();
        }
        catch (Exception ex)
        {
            // Velopack must never prevent the app from starting.
            HookLog("Velopack startup failed: " + ex.Message);
        }
    }

    private static void OnBeforeUninstall(SemanticVersion v)
    {
        bool remove = File.Exists(RemoveDataMarkerPath);
        HookLog($"Uninstalling {AppInfo.InstalledName} {v}; " + (remove ? "removing the data folder (requested in Settings)" : "keeping the data folder"));
        if (remove) RemoveDataFolder(DataRoot);
    }

    /// <summary>Deletes the data folder, best effort (files in use are skipped).</summary>
    public static void RemoveDataFolder(string root)
    {
        if (!Directory.Exists(root)) return;
        try { Directory.Delete(root, recursive: true); return; }
        catch { /* fall through to best-effort per file */ }
        foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            try { File.Delete(f); } catch { }
        foreach (var d in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories).OrderByDescending(d => d.Length))
            try { Directory.Delete(d); } catch { }
        try { Directory.Delete(root); } catch { }
    }

    /// <summary>Hooks run before Serilog is configured; append one line to install.log in the log folder.</summary>
    private static void HookLog(string message)
    {
        try
        {
            var dir = Path.Combine(DataRoot, "Logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "install.log"), $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}");
        }
        catch { /* logging must never fail the hook */ }
    }
}
