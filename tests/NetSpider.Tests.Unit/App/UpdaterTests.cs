using System.Runtime.InteropServices;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.App;

public class UpdateLogicTests
{
    [Theory]
    [InlineData(Architecture.X64, false, "win-x64")]
    [InlineData(Architecture.X64, true, "win-x64-prerelease")]
    [InlineData(Architecture.Arm64, false, "win-arm64")]
    [InlineData(Architecture.Arm64, true, "win-arm64-prerelease")]
    [InlineData(Architecture.X86, false, "win-x86")]
    [InlineData(Architecture.X86, true, "win-x86-prerelease")]
    public void Channel_name_combines_rid_and_prerelease(Architecture arch, bool prerelease, string expected) =>
        Assert.Equal(expected, UpdateLogic.ChannelName(arch, prerelease));

    [Theory]
    [InlineData(null, null, false)]                        // dev / portable: release
    [InlineData(null, "win-x64", false)]                   // installed from the Release Setup
    [InlineData(null, "win-x64-prerelease", true)]         // installed from the PreRelease Setup
    [InlineData("release", "win-x64-prerelease", false)]   // explicit choice wins
    [InlineData("prerelease", "win-x64", true)]
    [InlineData("beta", null, true)]                       // legacy value
    [InlineData("stable", "win-x64-prerelease", false)]
    public void Prerelease_follows_setting_then_installer(string? setting, string? installed, bool expected) =>
        Assert.Equal(expected, UpdateLogic.ResolvePrerelease(setting, installed));

    [Fact]
    public void Single_file_build_is_standalone_unless_velopack_installed()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.Equal(InstallMode.Standalone, UpdateLogic.DetectInstallMode(false, dir, null, singleFile: true));
            Assert.Equal(InstallMode.Setup, UpdateLogic.DetectInstallMode(true, dir, null, singleFile: true));
            Assert.Equal(InstallMode.Development, UpdateLogic.DetectInstallMode(false, dir, null, singleFile: false));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(null, "1.2.0", false, true)]
    [InlineData("", "1.2.0", false, true)]
    [InlineData("1.1.0", "1.2.0", false, true)]
    [InlineData("1.2.0", "1.2.0", false, false)]
    [InlineData(" 1.2.0 ", "1.2.0", false, false)]
    [InlineData("1.2.0", "1.2.0", true, true)]
    public void Skipped_version_only_reappears_on_manual_check(string? skipped, string candidate, bool manual, bool expected) =>
        Assert.Equal(expected, UpdateLogic.ShouldSurface(candidate, skipped, manual));

    [Theory]
    [InlineData(null, UpdateLogic.FeedKind.GitHub)]
    [InlineData("  ", UpdateLogic.FeedKind.GitHub)]
    [InlineData(@"C:\feeds\netspider", UpdateLogic.FeedKind.Folder)]
    [InlineData(@"\\server\share\feed", UpdateLogic.FeedKind.Folder)]
    [InlineData("http://localhost:8080/feed", UpdateLogic.FeedKind.Web)]
    [InlineData("https://updates.example.org/netspider", UpdateLogic.FeedKind.Web)]
    public void Feed_override_is_classified(string? value, UpdateLogic.FeedKind expected) =>
        Assert.Equal(expected, UpdateLogic.ClassifyFeed(value));

    [Fact]
    public void Format_bytes_is_human_readable()
    {
        Assert.Equal("512 B", UpdateLogic.FormatBytes(512));
        Assert.Equal("2 KB", UpdateLogic.FormatBytes(2048));
        Assert.Equal($"{36.6:0.0} MB", UpdateLogic.FormatBytes(38_400_000)); // current culture
    }
}

public sealed class InstallModeDetectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("netspider-installmode-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void Marker(string text) => File.WriteAllText(Path.Combine(_dir, UpdateLogic.InstallModeFile), text);

    [Fact]
    public void Velopack_install_is_setup_regardless_of_markers()
    {
        Marker("portable");
        Assert.Equal(InstallMode.Setup, UpdateLogic.DetectInstallMode(true, _dir, () => "msi"));
    }

    [Fact]
    public void Msi_marker_file() { Marker("msi\r\n"); Assert.Equal(InstallMode.Msi, UpdateLogic.DetectInstallMode(false, _dir, null)); }

    [Fact]
    public void Msi_registry_value() => Assert.Equal(InstallMode.Msi, UpdateLogic.DetectInstallMode(false, _dir, () => "MSI"));

    [Fact]
    public void Portable_marker_file() { Marker("Portable"); Assert.Equal(InstallMode.Portable, UpdateLogic.DetectInstallMode(false, _dir, () => null)); }

    [Fact]
    public void Registry_msi_wins_over_portable_marker() { Marker("portable"); Assert.Equal(InstallMode.Msi, UpdateLogic.DetectInstallMode(false, _dir, () => "msi")); }

    [Fact]
    public void Nothing_means_development() => Assert.Equal(InstallMode.Development, UpdateLogic.DetectInstallMode(false, _dir, () => null));

    [Fact]
    public void Unknown_marker_and_failing_registry_mean_development()
    {
        Marker("something");
        Assert.Equal(InstallMode.Development, UpdateLogic.DetectInstallMode(false, _dir, () => throw new UnauthorizedAccessException()));
    }

    [Fact]
    public void Remove_data_folder_deletes_everything()
    {
        var root = Path.Combine(_dir, "NetSpider");
        Directory.CreateDirectory(Path.Combine(root, "Logs"));
        File.WriteAllText(Path.Combine(root, "settings.json"), "{}");
        File.WriteAllText(Path.Combine(root, "Logs", "a.log"), "x");
        VelopackHooks.RemoveDataFolder(root);
        Assert.False(Directory.Exists(root));
    }
}

public class UpdateServiceTests
{
    private sealed class FakeStore : ISettingsStore
    {
        public AppSettings Settings { get; } = new();
        public int Saves;
        public void Save() { Saves++; Saved?.Invoke(); }
        public event Action? Saved;
    }

    private sealed class FakeEngine : IUpdateEngine
    {
        public bool CanSelfUpdate { get; set; } = true;
        public UpdateCandidate? PendingRestart { get; set; }
        public UpdateCandidate? Next { get; set; }
        public Exception? CheckError { get; set; }
        public Exception? DownloadError { get; set; }
        public int Checks, Downloads, Restarts, OnExit;
        public List<string> Channels { get; } = [];

        public Task<UpdateCandidate?> CheckAsync(CancellationToken ct)
        {
            Checks++;
            if (CheckError is { } e) throw e;
            return Task.FromResult(Next);
        }

        public Task DownloadAsync(UpdateCandidate candidate, Action<int> progress, CancellationToken ct)
        {
            Downloads++;
            if (DownloadError is { } e) return Task.FromException(e);
            progress(50);
            progress(100);
            return Task.CompletedTask;
        }

        public void ApplyAndRestart(UpdateCandidate candidate) => Restarts++;
        public void ApplyOnExit(UpdateCandidate candidate) => OnExit++;
    }

    private static readonly UpdateCandidate V120 = new("1.2.0", "## Notes", 1000, false);

    private static (UpdateService svc, FakeEngine engine, FakeStore store, List<UpdateNotice> notices) Create(
        InstallMode mode = InstallMode.Setup, UpdateAction action = UpdateAction.DownloadAndAsk, string? feed = null, string? busy = null)
    {
        var store = new FakeStore();
        store.Settings.UpdateAction = action;
        var engine = new FakeEngine { CanSelfUpdate = mode == InstallMode.Setup };
        var svc = new UpdateService(store, mode, feed, ch => { engine.Channels.Add(ch); return engine; }, () => busy);
        var notices = new List<UpdateNotice>();
        svc.Notice += notices.Add;
        return (svc, engine, store, notices);
    }

    [Fact]
    public async Task Up_to_date_is_recorded_and_saved()
    {
        var (svc, engine, store, notices) = Create();
        await svc.CheckAsync(manual: false, CancellationToken.None);
        Assert.Equal(UpdateState.UpToDate, svc.State);
        Assert.Equal("Up to date", store.Settings.LastUpdateResult);
        Assert.NotNull(store.Settings.LastUpdateCheck);
        Assert.True(store.Saves > 0);
        Assert.Empty(notices);
        Assert.False(svc.ShowChip);
        Assert.Equal(1, engine.Checks);
    }

    [Fact]
    public async Task Notify_only_shows_the_chip_and_does_not_download()
    {
        var (svc, engine, store, notices) = Create(action: UpdateAction.NotifyOnly);
        engine.Next = V120;
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.Available, svc.State);
        Assert.Equal("1.2.0", svc.AvailableVersion);
        Assert.Equal("## Notes", svc.ReleaseNotes);
        Assert.True(svc.ShowChip);
        Assert.Equal(0, engine.Downloads);
        Assert.Equal(new UpdateNotice(UpdateNoticeKind.Available, "1.2.0"), Assert.Single(notices));
        Assert.Equal("1.2.0 available", store.Settings.LastUpdateResult);
    }

    [Fact]
    public async Task Download_and_ask_downloads_then_is_ready()
    {
        var (svc, engine, _, notices) = Create(action: UpdateAction.DownloadAndAsk);
        engine.Next = V120;
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.ReadyToInstall, svc.State);
        Assert.Equal(100, svc.ProgressPercent);
        Assert.Equal(1, engine.Downloads);
        Assert.Equal(UpdateNoticeKind.Ready, Assert.Single(notices).Kind);

        svc.InstallNow();
        Assert.Equal(1, engine.Restarts);
        svc.OnAppExit();
        Assert.Equal(0, engine.OnExit); // only "install on exit" applies on exit
    }

    [Fact]
    public async Task Install_on_exit_applies_when_the_app_exits()
    {
        var (svc, engine, _, _) = Create(action: UpdateAction.InstallOnExit);
        engine.Next = V120;
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.ReadyToInstall, svc.State);
        svc.OnAppExit();
        Assert.Equal(1, engine.OnExit);
        Assert.Equal(0, engine.Restarts);
    }

    [Fact]
    public async Task Skipped_version_is_hidden_for_automatic_checks_but_not_manual()
    {
        var (svc, engine, store, notices) = Create(action: UpdateAction.NotifyOnly);
        store.Settings.SkippedVersion = "1.2.0";
        engine.Next = V120;
        await svc.CheckAsync(manual: false, CancellationToken.None);
        Assert.Equal(UpdateState.Idle, svc.State);
        Assert.False(svc.ShowChip);
        Assert.Empty(notices);

        await svc.CheckAsync(manual: true, CancellationToken.None);
        Assert.Equal(UpdateState.Available, svc.State);
    }

    [Fact]
    public async Task Skip_records_the_version_and_clears_the_chip()
    {
        var (svc, engine, store, _) = Create(action: UpdateAction.NotifyOnly);
        engine.Next = V120;
        await svc.CheckNowAsync();
        svc.SkipAvailable();
        Assert.Equal("1.2.0", store.Settings.SkippedVersion);
        Assert.Equal(UpdateState.Idle, svc.State);
        Assert.False(svc.ShowChip);
        svc.ClearSkipped();
        Assert.Null(store.Settings.SkippedVersion);
    }

    [Fact]
    public async Task Check_error_then_retry_recovers()
    {
        var (svc, engine, store, _) = Create(action: UpdateAction.NotifyOnly);
        engine.CheckError = new HttpRequestException("offline");
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.Error, svc.State);
        Assert.Equal("offline", svc.ErrorMessage);
        Assert.StartsWith("Error", store.Settings.LastUpdateResult);

        engine.CheckError = null;
        engine.Next = V120;
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.Available, svc.State);
        Assert.Null(svc.ErrorMessage);
    }

    [Fact]
    public async Task Download_error_keeps_the_candidate_for_retry()
    {
        var (svc, engine, _, _) = Create(action: UpdateAction.DownloadAndAsk);
        engine.Next = V120;
        engine.DownloadError = new IOException("disk full");
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.Error, svc.State);
        Assert.True(svc.HasCandidate);

        engine.DownloadError = null;
        await svc.DownloadAsync();
        Assert.Equal(UpdateState.ReadyToInstall, svc.State);
    }

    [Theory]
    [InlineData(InstallMode.Portable)]
    [InlineData(InstallMode.Msi)]
    public async Task Non_setup_installs_only_notify(InstallMode mode)
    {
        var (svc, engine, _, notices) = Create(mode, UpdateAction.InstallOnExit);
        engine.Next = V120;
        await svc.CheckNowAsync();
        Assert.Equal(UpdateState.Available, svc.State);
        Assert.Equal(0, engine.Downloads);
        Assert.False(svc.CanSelfUpdate);
        Assert.Equal(UpdateNoticeKind.Available, Assert.Single(notices).Kind);
        svc.InstallNow();
        Assert.Equal(0, engine.Restarts);
    }

    [Fact]
    public async Task Development_build_does_not_check_unless_a_feed_override_is_set()
    {
        var (svc, engine, _, _) = Create(InstallMode.Development);
        Assert.False(svc.CanCheck);
        await svc.CheckNowAsync();
        Assert.Equal(0, engine.Checks);
        Assert.Equal(UpdateState.Idle, svc.State);

        var (svc2, engine2, _, _) = Create(InstallMode.Development, feed: @"C:\feed");
        Assert.True(svc2.CanCheck);
        await svc2.CheckNowAsync();
        Assert.Equal(1, engine2.Checks);
    }

    [Fact]
    public async Task Channel_change_recreates_the_engine_for_the_prerelease_channel()
    {
        var (svc, engine, store, _) = Create();
        await svc.CheckNowAsync();
        store.Settings.UpdateChannel = "prerelease";
        svc.ResetEngine();
        await svc.CheckNowAsync();
        Assert.Equal(2, engine.Channels.Count);
        Assert.EndsWith("-prerelease", engine.Channels[1]);
        Assert.DoesNotContain("-prerelease", engine.Channels[0]);
    }

    [Fact]
    public void Pending_update_from_a_previous_session_is_ready_unless_skipped()
    {
        var (svc, engine, _, _) = Create();
        engine.PendingRestart = V120;
        svc.RestorePending();
        Assert.Equal(UpdateState.ReadyToInstall, svc.State);

        var (svc2, engine2, store2, _) = Create();
        store2.Settings.SkippedVersion = "1.2.0";
        engine2.PendingRestart = V120;
        svc2.RestorePending();
        Assert.Equal(UpdateState.Idle, svc2.State);
    }

    [Fact]
    public void Busy_reason_comes_from_the_callback()
    {
        var (svc, _, _, _) = Create(busy: "Monitoring is active");
        Assert.Equal("Monitoring is active", svc.GetBusyReason());
    }
}

public class ElevationTests
{
    [Theory]
    [InlineData(new string[0], false, true, null, true)]
    [InlineData(new[] { "--page", "settings" }, false, true, null, true)]
    [InlineData(new[] { "--demo" }, false, true, null, true)]
    [InlineData(new string[0], true, true, null, false)]              // already admin
    [InlineData(new string[0], false, false, null, false)]            // Debug build
    [InlineData(new string[0], false, true, "1", false)]              // NETSPIDER_NO_ELEVATE=1
    [InlineData(new[] { "--veloapp-install", "1.0.0" }, false, true, null, false)]
    [InlineData(new[] { "--snapshot", "x.png" }, false, true, null, false)]
    [InlineData(new[] { "--demo", "--hide-banners" }, false, true, null, false)]
    [InlineData(new[] { "--about" }, false, true, null, false)]
    [InlineData(new[] { "--update-preview", "ready" }, false, true, null, false)]
    public void Elevation_decision(string[] args, bool admin, bool release, string? optOut, bool expected) =>
        Assert.Equal(expected, Elevation.ShouldElevate(args, admin, release, optOut));
}
