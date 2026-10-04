using System.ComponentModel;
using System.Diagnostics;
using NetSpider.Capture;

namespace NetSpider.App.Services;

/// <summary>
/// Release builds ship an asInvoker manifest (so Velopack's unelevated Setup/Update.exe can run the
/// <c>--veloapp-*</c> hooks). The GUI then relaunches itself elevated via UAC because Npcap capture/injection needs it.
/// </summary>
public static class Elevation
{
    public const string OptOutVariable = "NETSPIDER_NO_ELEVATE";

    /// <summary>Switches that never need elevation (screenshots, debug dialogs, snapshot rendering).</summary>
    private static readonly string[] NoElevateSwitches = ["--snapshot", "--hide-banners", "--about", "--update-preview"];

    /// <summary>Pure decision (unit-tested): should this process relaunch itself elevated?</summary>
    public static bool ShouldElevate(string[] args, bool isAdmin, bool isReleaseBuild, string? optOut)
    {
        if (!isReleaseBuild || isAdmin || !OperatingSystem.IsWindows()) return false;
        if (optOut is "1" || string.Equals(optOut, "true", StringComparison.OrdinalIgnoreCase)) return false;
        if (args.Any(a => a.StartsWith("--veloapp-", StringComparison.OrdinalIgnoreCase))) return false;
        return !args.Any(a => NoElevateSwitches.Contains(a, StringComparer.OrdinalIgnoreCase));
    }

#if DEBUG
    private const bool IsReleaseBuild = false;
#else
    private const bool IsReleaseBuild = true;
#endif

    /// <summary>
    /// Relaunches the same exe with the same arguments through UAC ("runas"). Returns true when the elevated copy was
    /// started and this process should exit; false to continue unelevated (not needed, UAC cancelled, or failure).
    /// </summary>
    public static bool RelaunchElevatedIfNeeded(string[] args)
    {
        bool admin;
        try { admin = NpcapEnvironment.IsAdministrator(); }
        catch { return false; }
        if (!ShouldElevate(args, admin, IsReleaseBuild, Environment.GetEnvironmentVariable(OptOutVariable))) return false;
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return false;
        try
        {
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", WorkingDirectory = Environment.CurrentDirectory };
            foreach (var a in args) psi.ArgumentList.Add(a);
            Process.Start(psi);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false; // the user cancelled UAC: run unelevated (the "Not running as administrator" banner explains the limits)
        }
        catch
        {
            return false;
        }
    }
}
