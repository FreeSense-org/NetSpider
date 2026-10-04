using System.Runtime.InteropServices;

namespace NetSpider.App.Services;

/// <summary>How this copy of NetSpider was installed; only <see cref="Setup"/> can update itself.</summary>
public enum InstallMode { Development, Portable, Standalone, Msi, Setup }

/// <summary>Updater state machine: Idle → Checking → UpToDate | Available → Downloading → ReadyToInstall, or Error.</summary>
public enum UpdateState { Idle, Checking, UpToDate, Available, Downloading, ReadyToInstall, Error }

/// <summary>A newer release found on the feed. <see cref="Native"/> carries the engine's own object (Velopack UpdateInfo).</summary>
public sealed record UpdateCandidate(string Version, string? NotesMarkdown, long SizeBytes, bool IsDelta, object? Native = null);

/// <summary>Thin seam over the update engine (Velopack in the app, a fake in tests).</summary>
public interface IUpdateEngine
{
    /// <summary>True when the app runs from a Velopack (Setup) install and can download/apply updates.</summary>
    bool CanSelfUpdate { get; }
    /// <summary>An update that was downloaded earlier and is waiting to be applied (survives restarts).</summary>
    UpdateCandidate? PendingRestart { get; }
    /// <summary>Returns the newest release when it's newer than the running version, else null.</summary>
    Task<UpdateCandidate?> CheckAsync(CancellationToken ct);
    Task DownloadAsync(UpdateCandidate candidate, Action<int> progress, CancellationToken ct);
    void ApplyAndRestart(UpdateCandidate candidate);
    /// <summary>Starts the updater in "wait for exit" mode: applies silently once NetSpider exits, without restarting.</summary>
    void ApplyOnExit(UpdateCandidate candidate);
}

/// <summary>Pure helpers for the updater (unit-tested).</summary>
public static class UpdateLogic
{
    public const string InstallModeFile = "install-mode.txt";
    public const string RegistryKey = @"Software\FreeSense\NetSpider";
    public const string FeedOverrideVariable = "NETSPIDER_UPDATE_FEED";
    /// <summary>Marker file (in the data folder) that tells the uninstall hook to delete the data folder.</summary>
    public const string RemoveDataMarker = ".remove-data-on-uninstall";

    public static string Rid(Architecture arch) => arch switch
    {
        Architecture.Arm64 => "win-arm64",
        Architecture.X86 => "win-x86",
        _ => "win-x64",
    };

    /// <summary>Settings value for the release channel (stable versions only).</summary>
    public const string ReleaseChannel = "release";
    /// <summary>Settings value for the pre-release channel (pre-releases and stable versions).</summary>
    public const string PrereleaseChannel = "prerelease";
    /// <summary>Suffix of the Velopack channel that carries pre-releases (stable versions are published to it too).</summary>
    public const string PrereleaseSuffix = "-prerelease";

    /// <summary>True for "prerelease" (and the legacy "beta").</summary>
    public static bool IsPrereleaseSetting(string? channel) =>
        string.Equals(channel?.Trim(), PrereleaseChannel, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(channel?.Trim(), "beta", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether this copy follows pre-releases: an explicit Settings choice wins; otherwise ("follow installer") it
    /// follows the channel the installer was built for (the "PreRelease" Setup installs into the pre-release channel).
    /// </summary>
    public static bool ResolvePrerelease(string? setting, string? installedChannel)
    {
        if (!string.IsNullOrWhiteSpace(setting))
            return IsPrereleaseSetting(setting);
        return installedChannel?.EndsWith(PrereleaseSuffix, StringComparison.OrdinalIgnoreCase) == true;
    }

    /// <summary>Velopack channel name: "win-x64", or "win-x64-prerelease" for the pre-release channel.</summary>
    public static string ChannelName(Architecture arch, bool prerelease) => Rid(arch) + (prerelease ? PrereleaseSuffix : "");

    /// <summary>
    /// Setup (Velopack-installed) wins; then a single-file build is the standalone exe; otherwise
    /// <c>install-mode.txt</c> next to the exe or the HKLM InstallMode value decide between MSI and portable; anything
    /// else is a development build.
    /// </summary>
    public static InstallMode DetectInstallMode(bool velopackInstalled, string baseDirectory, Func<string?>? registryInstallMode, bool singleFile = false)
    {
        if (velopackInstalled) return InstallMode.Setup;
        if (singleFile) return InstallMode.Standalone;
        string? marker = null;
        try
        {
            var path = Path.Combine(baseDirectory, InstallModeFile);
            if (File.Exists(path)) marker = File.ReadAllText(path).Trim();
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        if (string.Equals(marker, "msi", StringComparison.OrdinalIgnoreCase)) return InstallMode.Msi;
        string? reg = null;
        try { reg = registryInstallMode?.Invoke()?.Trim(); } catch { /* registry unavailable */ }
        if (string.Equals(reg, "msi", StringComparison.OrdinalIgnoreCase)) return InstallMode.Msi;
        if (string.Equals(marker, "portable", StringComparison.OrdinalIgnoreCase)) return InstallMode.Portable;
        return InstallMode.Development;
    }

    /// <summary>A skipped version stays hidden for automatic checks; a manual "Check now" shows it again.</summary>
    public static bool ShouldSurface(string candidateVersion, string? skippedVersion, bool manual) =>
        manual || string.IsNullOrWhiteSpace(skippedVersion) || !string.Equals(candidateVersion.Trim(), skippedVersion.Trim(), StringComparison.OrdinalIgnoreCase);

    public enum FeedKind { GitHub, Folder, Web }

    /// <summary>Classifies the <c>NETSPIDER_UPDATE_FEED</c> override (null/empty = the GitHub releases repo).</summary>
    public static FeedKind ClassifyFeed(string? overrideValue)
    {
        if (string.IsNullOrWhiteSpace(overrideValue)) return FeedKind.GitHub;
        var v = overrideValue.Trim();
        if (Uri.TryCreate(v, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)) return FeedKind.Web;
        return FeedKind.Folder;
    }

    public static string InstallModeText(InstallMode mode) => mode switch
    {
        InstallMode.Setup => "Installed with Setup — updates download and install automatically.",
        InstallMode.Msi => "Installed with MSI — updates are deployed by your administrator. NetSpider still checks and tells you when a new version exists.",
        InstallMode.Portable => "Portable copy — NetSpider checks for new versions; download them from the releases page.",
        InstallMode.Standalone => "Standalone exe — NetSpider checks for new versions; download the new standalone exe from the releases page.",
        _ => "Development build — automatic updates are disabled (set " + FeedOverrideVariable + " to test against a local feed).",
    };

    public static string InstallModeName(InstallMode mode) => mode switch
    {
        InstallMode.Setup => "Setup (auto-update)",
        InstallMode.Msi => "MSI (managed)",
        InstallMode.Portable => "Portable",
        InstallMode.Standalone => "Standalone (single exe)",
        _ => "Development",
    };

    public static string FormatBytes(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024.0:0} KB",
        _ => $"{bytes} B",
    };
}
