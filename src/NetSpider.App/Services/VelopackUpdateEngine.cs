using System.Runtime.InteropServices;
using NetSpider.Core;
using Serilog;
using Velopack;
using Velopack.Logging;
using Velopack.Sources;

namespace NetSpider.App.Services;

/// <summary>
/// <see cref="IUpdateEngine"/> over Velopack's <see cref="UpdateManager"/>. Installed (Setup) copies use the full
/// UpdateManager flow; MSI/portable/dev copies only read the release feed and compare versions (no download/apply).
/// </summary>
public sealed class VelopackUpdateEngine : IUpdateEngine
{
    private readonly IUpdateSource _source;
    private readonly string _channel;
    private readonly UpdateManager? _manager;

    public VelopackUpdateEngine(string channel, string? feedOverride)
    {
        _channel = channel;
        _source = CreateSource(channel.EndsWith(UpdateLogic.PrereleaseSuffix, StringComparison.OrdinalIgnoreCase), feedOverride);
        try
        {
            var mgr = new UpdateManager(_source, new UpdateOptions { ExplicitChannel = channel });
            if (mgr.IsInstalled) _manager = mgr;
        }
        catch (Exception ex) { Log.Debug(ex, "Velopack UpdateManager unavailable"); }
    }

    /// <summary>Velopack channel for this process: win-x64 / win-arm64 / win-x86, plus "-prerelease" when following pre-releases.</summary>
    public static string ChannelFor(string? settingsChannel) =>
        UpdateLogic.ChannelName(RuntimeInformation.ProcessArchitecture, UpdateLogic.ResolvePrerelease(settingsChannel, InstalledChannel()));

    /// <summary>The channel the Setup installer was built for (e.g. "win-x64-prerelease"); null when not Velopack-installed.</summary>
    public static string? InstalledChannel() => s_installedChannel.Value;

    private static readonly Lazy<string?> s_installedChannel = new(() =>
    {
        try
        {
            if (!IsVelopackInstalled()) return null;
            // Channel baked into the installed package (set by vpk pack --channel), e.g. "win-x64-prerelease".
            return Velopack.Locators.VelopackLocator.Current.Channel;
        }
        catch { return null; }
    });

    /// <summary>True when running as a single-file bundle (the standalone exe).</summary>
    public static bool IsSingleFile()
    {
        if (string.IsNullOrEmpty(typeof(VelopackUpdateEngine).Assembly.Location)) return true;
        // Bundles that extract to a temp folder run from there: the base directory is not the exe's folder.
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
        return exeDir is not null &&
               !string.Equals(Path.GetFullPath(exeDir).TrimEnd('\\'), Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }

    public static IUpdateSource CreateSource(bool prerelease, string? feedOverride)
    {
        switch (UpdateLogic.ClassifyFeed(feedOverride))
        {
            case UpdateLogic.FeedKind.Folder: return new SimpleFileSource(new DirectoryInfo(feedOverride!.Trim()));
            case UpdateLogic.FeedKind.Web: return new SimpleWebSource(feedOverride!.Trim());
            default: return new GithubSource(AppInfo.ReleasesRepository, accessToken: null, prerelease: prerelease);
        }
    }

    /// <summary>True when this process runs from a Velopack install (checked without building a feed source).</summary>
    public static bool IsVelopackInstalled()
    {
        try { return new UpdateManager(new SimpleFileSource(new DirectoryInfo(Path.GetTempPath()))).IsInstalled; }
        catch { return false; }
    }

    public bool CanSelfUpdate => _manager is not null;

    public UpdateCandidate? PendingRestart =>
        _manager?.UpdatePendingRestart is { } a ? new UpdateCandidate(a.Version.ToString(), a.NotesMarkdown, a.Size, false, a) : null;

    public async Task<UpdateCandidate?> CheckAsync(CancellationToken ct)
    {
        if (_manager is not null)
        {
            var info = await _manager.CheckForUpdatesAsync().WaitAsync(ct).ConfigureAwait(false);
            if (info is null || info.IsDowngrade) return null;
            var t = info.TargetFullRelease;
            bool delta = info.DeltasToTarget.Length > 0;
            long size = delta ? info.DeltasToTarget.Sum(d => d.Size) : t.Size;
            return new UpdateCandidate(t.Version.ToString(), t.NotesMarkdown, size, delta, info);
        }

        // Not installed by Setup: read the feed ourselves and compare against the running version.
        var feed = await _source.GetReleaseFeed(NullVelopackLogger.Instance, null, _channel).WaitAsync(ct).ConfigureAwait(false);
        var latest = feed.Assets.Where(a => a.Type == VelopackAssetType.Full).MaxBy(a => a.Version);
        if (latest is null) return null;
        SemanticVersion current;
        try { current = SemanticVersion.Parse(AppInfo.Version); }
        catch { current = new SemanticVersion(0, 0, 0); }
        return latest.Version > current ? new UpdateCandidate(latest.Version.ToString(), latest.NotesMarkdown, latest.Size, false, latest) : null;
    }

    public Task DownloadAsync(UpdateCandidate candidate, Action<int> progress, CancellationToken ct)
    {
        if (_manager is null || candidate.Native is not UpdateInfo info) throw new InvalidOperationException("This copy of NetSpider can't install updates itself.");
        return _manager.DownloadUpdatesAsync(info, progress, ct);
    }

    public void ApplyAndRestart(UpdateCandidate candidate)
    {
        if (_manager is null) throw new InvalidOperationException("This copy of NetSpider can't install updates itself.");
        _manager.ApplyUpdatesAndRestart(Asset(candidate));
    }

    public void ApplyOnExit(UpdateCandidate candidate)
    {
        if (_manager is null) return;
        _manager.WaitExitThenApplyUpdates(Asset(candidate), silent: true, restart: false);
    }

    private static VelopackAsset? Asset(UpdateCandidate c) => c.Native switch
    {
        UpdateInfo i => i.TargetFullRelease,
        VelopackAsset a => a,
        _ => null,
    };
}
