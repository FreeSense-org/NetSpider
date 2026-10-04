using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

public enum UpdateNoticeKind { Available, Ready }

/// <summary>Raised when the shell should toast: a new version was found, or it finished downloading.</summary>
public sealed record UpdateNotice(UpdateNoticeKind Kind, string Version);

/// <summary>
/// Built-in updater (singleton). Checks the release feed at startup and periodically, honours the skipped version, then
/// notifies / downloads / installs-on-exit according to <see cref="AppSettings.UpdateAction"/>. Only Setup installs
/// (Velopack) can download and apply; MSI, portable and dev copies just report that a new version exists.
/// Must be used from the UI thread (state changes raise PropertyChanged for bindings).
/// </summary>
public sealed partial class UpdateService : ObservableObject, IDisposable
{
    private readonly ISettingsStore _store;
    private readonly Func<string, IUpdateEngine?> _engineFactory;
    private readonly Func<string?> _busyReason;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IUpdateEngine? _engine;
    private string? _engineChannel;
    private UpdateCandidate? _candidate;
    private CancellationTokenSource? _loopCts;
    private CancellationTokenSource? _downloadCts;
    private bool _applyOnExit;

    /// <summary>App constructor: detects the install mode, uses Velopack and the DI-registered orchestrator/recorder.</summary>
    public UpdateService(ISettingsStore store, IServiceProvider sp)
        : this(store, DetectInstallMode(), FeedOverride, ch => new VelopackUpdateEngine(ch, FeedOverride), () => BusyReason(sp))
    {
    }

    /// <summary>Test constructor.</summary>
    public UpdateService(ISettingsStore store, InstallMode mode, string? feedOverride, Func<string, IUpdateEngine?> engineFactory, Func<string?> busyReason)
    {
        _store = store;
        InstallMode = mode;
        HasFeedOverride = !string.IsNullOrWhiteSpace(feedOverride);
        _engineFactory = engineFactory;
        _busyReason = busyReason;
    }

    public static string? FeedOverride => Environment.GetEnvironmentVariable(UpdateLogic.FeedOverrideVariable);

    public static InstallMode DetectInstallMode() =>
        UpdateLogic.DetectInstallMode(VelopackUpdateEngine.IsVelopackInstalled(), AppContext.BaseDirectory, ReadRegistryInstallMode, VelopackUpdateEngine.IsSingleFile());

    private static string? ReadRegistryInstallMode()
    {
        if (!OperatingSystem.IsWindows()) return null;
        using var key = Registry.LocalMachine.OpenSubKey(UpdateLogic.RegistryKey);
        return key?.GetValue("InstallMode") as string;
    }

    private static string? BusyReason(IServiceProvider sp)
    {
        if (sp.GetService<IPacketRecorder>() is { IsRecording: true }) return "A packet recording is running";
        if (sp.GetService<IScanOrchestrator>() is { IsMonitoring: true }) return "Monitoring is active";
        return null;
    }

    private AppSettings Settings => _store.Settings;

    // ---- observable state ----
    public InstallMode InstallMode { get; }
    public bool HasFeedOverride { get; }
    /// <summary>False for development builds without a feed override: nothing is checked.</summary>
    public bool CanCheck => InstallMode != InstallMode.Development || HasFeedOverride;
    /// <summary>True when this copy can download and apply updates itself (Setup install).</summary>
    public bool CanSelfUpdate => _previewSelfUpdate ?? _engine?.CanSelfUpdate ?? InstallMode == InstallMode.Setup;
    private bool? _previewSelfUpdate;
    public string CurrentVersion => AppInfo.Version;
    public bool IsPrerelease => UpdateLogic.ResolvePrerelease(Settings.UpdateChannel, VelopackUpdateEngine.InstalledChannel());
    public string Channel => IsPrerelease ? "Pre-release" : "Release";
    public string InstallModeText => UpdateLogic.InstallModeText(InstallMode);
    public string InstallModeName => UpdateLogic.InstallModeName(InstallMode);

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsBusy), nameof(ShowChip), nameof(ChipText), nameof(IsChecking), nameof(IsDownloading), nameof(StatusText))]
    private UpdateState _state = UpdateState.Idle;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ChipText), nameof(StatusText))] private string? _availableVersion;
    [ObservableProperty] private string? _releaseNotes;
    [ObservableProperty] private bool _isDelta;
    [ObservableProperty] private long _totalBytes;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ProgressText))] private int _progressPercent;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(StatusText))] private string? _errorMessage;

    /// <summary>True when a found update is known (Retry after a failed download re-downloads it).</summary>
    public bool HasCandidate => _candidate is not null;
    public bool IsChecking => State == UpdateState.Checking;
    public bool IsDownloading => State == UpdateState.Downloading;
    public bool IsBusy => State is UpdateState.Checking or UpdateState.Downloading;
    public bool ShowChip => State is UpdateState.Available or UpdateState.ReadyToInstall or UpdateState.Downloading && AvailableVersion is not null;
    public string ChipText => State == UpdateState.ReadyToInstall ? $"⬆ Restart to update {AvailableVersion}" : $"⬆ Update {AvailableVersion}";
    public string ProgressText => TotalBytes > 0
        ? $"{UpdateLogic.FormatBytes(TotalBytes * ProgressPercent / 100)} of {UpdateLogic.FormatBytes(TotalBytes)} · {ProgressPercent} %"
        : $"{ProgressPercent} %";
    public string StatusText => State switch
    {
        UpdateState.Checking => "Checking for updates…",
        UpdateState.UpToDate => "NetSpider is up to date",
        UpdateState.Available => $"Version {AvailableVersion} is available",
        UpdateState.Downloading => $"Downloading {AvailableVersion}…",
        UpdateState.ReadyToInstall => $"Version {AvailableVersion} is ready to install",
        UpdateState.Error => "Update check failed: " + ErrorMessage,
        _ => Settings.LastUpdateResult ?? "Not checked yet",
    };

    public event Action<UpdateNotice>? Notice;

    // =====================================================================================================

    /// <summary>Starts the startup check (after <paramref name="startupDelay"/>) and the periodic check loop.</summary>
    public void Start(TimeSpan startupDelay)
    {
        if (!CanCheck) { Log.Information("Updater: {Mode} build, automatic checks disabled", InstallMode); return; }
        RestorePending();
        _loopCts?.Cancel();
        _loopCts = new CancellationTokenSource();
        _ = LoopAsync(startupDelay, _loopCts.Token);
    }

    private async Task LoopAsync(TimeSpan startupDelay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(startupDelay, ct);
            if (Settings.UpdateCheckOnStartup) await CheckAsync(manual: false, ct);
            var last = DateTimeOffset.Now;
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(1), ct);
                int hours = Settings.UpdateCheckHours;
                if (hours <= 0 || DateTimeOffset.Now - last < TimeSpan.FromHours(hours)) continue;
                last = DateTimeOffset.Now;
                if (State is not (UpdateState.Downloading or UpdateState.ReadyToInstall)) await CheckAsync(manual: false, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Warning(ex, "Update loop failed"); }
    }

    /// <summary>A previously downloaded update waiting for a restart becomes "ready" again (unless skipped).</summary>
    public void RestorePending()
    {
        try
        {
            var pending = EnsureEngine()?.PendingRestart;
            if (pending is null || !UpdateLogic.ShouldSurface(pending.Version, Settings.SkippedVersion, manual: false)) return;
            SetCandidate(pending);
            State = UpdateState.ReadyToInstall;
            if (Settings.UpdateAction == UpdateAction.InstallOnExit) _applyOnExit = true;
        }
        catch (Exception ex) { Log.Debug(ex, "Reading pending update failed"); }
    }

    /// <summary>Manual "Check now": also shows a version the user skipped.</summary>
    public Task CheckNowAsync() => CheckAsync(manual: true, CancellationToken.None);

    public async Task CheckAsync(bool manual, CancellationToken ct)
    {
        if (!CanCheck) return;
        if (!await _gate.WaitAsync(0, ct)) return; // a check or download is already running
        try
        {
            if (State is UpdateState.Downloading or UpdateState.ReadyToInstall) return; // already have it
            ErrorMessage = null;
            State = UpdateState.Checking;
            var engine = EnsureEngine() ?? throw new InvalidOperationException("Updater not available");
            UpdateCandidate? found;
            try { found = await engine.CheckAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.Warning(ex, "Update check failed");
                ErrorMessage = ex.Message;
                State = UpdateState.Error;
                Record("Error: " + ex.Message);
                return;
            }

            if (found is null)
            {
                _candidate = null;
                AvailableVersion = null;
                State = UpdateState.UpToDate;
                Record("Up to date");
                return;
            }
            if (!UpdateLogic.ShouldSurface(found.Version, Settings.SkippedVersion, manual))
            {
                State = UpdateState.Idle;
                Record($"{found.Version} available (skipped)");
                return;
            }

            SetCandidate(found);
            State = UpdateState.Available;
            Record($"{found.Version} available");
            Log.Information("Update {Version} available (delta: {Delta}, {Size} bytes)", found.Version, found.IsDelta, found.SizeBytes);

            if (engine.CanSelfUpdate && Settings.UpdateAction != UpdateAction.NotifyOnly) await DownloadCoreAsync(ct);
            else Notice?.Invoke(new UpdateNotice(UpdateNoticeKind.Available, found.Version));
        }
        finally { _gate.Release(); }
    }

    /// <summary>Downloads the available update (from the Update window's "Install &amp; restart" or automatically).</summary>
    public async Task DownloadAsync()
    {
        if (!await _gate.WaitAsync(0)) return;
        try { await DownloadCoreAsync(CancellationToken.None); }
        finally { _gate.Release(); }
    }

    private async Task DownloadCoreAsync(CancellationToken ct)
    {
        if (_candidate is not { } c || _engine is not { CanSelfUpdate: true } engine) return;
        if (State is UpdateState.Downloading or UpdateState.ReadyToInstall) return;
        _downloadCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var ctx = SynchronizationContext.Current;
        ProgressPercent = 0;
        ErrorMessage = null;
        State = UpdateState.Downloading;
        try
        {
            await engine.DownloadAsync(c, p =>
            {
                if (ctx is null) ProgressPercent = p;
                else ctx.Post(_ => ProgressPercent = p, null);
            }, _downloadCts.Token);
            ProgressPercent = 100;
            State = UpdateState.ReadyToInstall;
            Record($"{c.Version} downloaded, ready to install");
            if (Settings.UpdateAction == UpdateAction.InstallOnExit) _applyOnExit = true;
            Notice?.Invoke(new UpdateNotice(UpdateNoticeKind.Ready, c.Version));
        }
        catch (OperationCanceledException)
        {
            State = UpdateState.Available;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Downloading update {Version} failed", c.Version);
            ErrorMessage = ex.Message;
            State = UpdateState.Error;
            Record("Download failed: " + ex.Message);
        }
    }

    /// <summary>Why installing right now would interrupt work (monitoring / recording), or null.</summary>
    public string? GetBusyReason()
    {
        try { return _busyReason(); }
        catch { return null; }
    }

    /// <summary>Applies the downloaded update and restarts NetSpider (the caller confirms first if <see cref="GetBusyReason"/> is set).</summary>
    public void InstallNow()
    {
        if (_candidate is not { } c || _engine is null || State != UpdateState.ReadyToInstall) return;
        Log.Information("Applying update {Version} and restarting", c.Version);
        _engine.ApplyAndRestart(c);
    }

    public void SkipAvailable()
    {
        if (AvailableVersion is not { } v) return;
        _downloadCts?.Cancel();
        Settings.SkippedVersion = v;
        _applyOnExit = false;
        _candidate = null;
        AvailableVersion = null;
        State = UpdateState.Idle;
        Record($"{v} skipped");
        Log.Information("Update {Version} skipped", v);
    }

    public void ClearSkipped()
    {
        Settings.SkippedVersion = null;
        Save();
    }

    /// <summary>Call on app exit: "Install on exit" hands the downloaded update to Velopack's updater.</summary>
    public void OnAppExit()
    {
        _loopCts?.Cancel();
        _downloadCts?.Cancel();
        if (!_applyOnExit || _candidate is null || _engine is null || State != UpdateState.ReadyToInstall
            || Settings.UpdateAction != UpdateAction.InstallOnExit) return;
        try
        {
            Log.Information("Installing update {Version} after exit", _candidate.Version);
            _engine.ApplyOnExit(_candidate);
        }
        catch (Exception ex) { Log.Warning(ex, "Scheduling update on exit failed"); }
    }

    /// <summary>Called when the channel setting changes so the next check uses the new feed.</summary>
    public void ResetEngine()
    {
        if (State is UpdateState.Downloading) return;
        _engine = null;
        _engineChannel = null;
        OnPropertyChanged(nameof(Channel));
    }

    /// <summary>Puts the updater into the error state (e.g. applying the update failed).</summary>
    public void Fail(string message)
    {
        ErrorMessage = message;
        State = UpdateState.Error;
    }

    /// <summary>Debug/screenshots: puts the service in a state with fake data (<c>--update-preview</c>).</summary>
    public void Preview(UpdateState state, string version, string notes, long size, int progress = 0, string? error = null, bool selfUpdate = true)
    {
        _previewSelfUpdate = selfUpdate;
        _candidate = new UpdateCandidate(version, notes, size, false);
        AvailableVersion = version;
        ReleaseNotes = notes;
        TotalBytes = size;
        ProgressPercent = progress;
        ErrorMessage = error;
        State = state;
    }

    private IUpdateEngine? EnsureEngine()
    {
        var channel = VelopackUpdateEngine.ChannelFor(Settings.UpdateChannel);
        if (_engine is null || _engineChannel != channel)
        {
            _engine = _engineFactory(channel);
            _engineChannel = channel;
            OnPropertyChanged(nameof(CanSelfUpdate));
        }
        return _engine;
    }

    private void SetCandidate(UpdateCandidate c)
    {
        _candidate = c;
        AvailableVersion = c.Version;
        ReleaseNotes = c.NotesMarkdown;
        TotalBytes = c.SizeBytes;
        IsDelta = c.IsDelta;
    }

    private void Record(string result)
    {
        Settings.LastUpdateCheck = DateTimeOffset.Now;
        Settings.LastUpdateResult = result;
        Save();
        OnPropertyChanged(nameof(StatusText));
    }

    private void Save()
    {
        try { _store.Save(); }
        catch (Exception ex) { Log.Warning(ex, "Saving update settings failed"); }
    }

    public void Dispose()
    {
        _loopCts?.Cancel();
        _downloadCts?.Cancel();
    }
}
