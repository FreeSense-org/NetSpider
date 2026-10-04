using System.ComponentModel;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Core;
using NetSpider.Core.Changelog;
using Serilog;

namespace NetSpider.App.ViewModels;

/// <summary>The modal update dialog: current → new version, release notes, download progress, install / later / skip, errors.</summary>
public sealed partial class UpdateWindowViewModel : ObservableObject, IDisposable
{
    private static UpdateWindow? _open;

    public UpdateWindowViewModel(UpdateService service)
    {
        Service = service;
        Service.PropertyChanged += OnServiceChanged;
    }

    /// <summary>Shows the update dialog (or brings the open one to the front); <paramref name="checkNow"/> starts a manual check.</summary>
    public static void Show(UpdateService service, bool checkNow = false)
    {
        if (_open is { } existing)
        {
            existing.Activate();
            if (checkNow) _ = service.CheckNowAsync();
            return;
        }
        var vm = new UpdateWindowViewModel(service);
        var w = new UpdateWindow { DataContext = vm, Title = AppInfo.WindowTitle("Update") };
        vm.Close = w.Close;
        vm.Owner = w;
        _open = w;
        w.Closed += (_, _) => { _open = null; vm.Dispose(); };
        if (Dialogs.Owner is { IsVisible: true } owner) _ = w.ShowDialog(owner);
        else w.Show();
        if (checkNow || service.State == UpdateState.Idle) _ = service.CheckNowAsync();
    }

    public UpdateService Service { get; }
    public Action? Close { get; set; }
    public Avalonia.Controls.Window? Owner { get; set; }

    public Bitmap? Logo => BrandAssets.Logo;
    public bool HasLogo => Logo is not null;
    public string CurrentVersion => AppInfo.Version;
    public string? NewVersion => Service.AvailableVersion;
    public string Channel => Service.Channel + " channel";
    public string SizeText => Service.TotalBytes > 0 ? UpdateLogic.FormatBytes(Service.TotalBytes) + (Service.IsDelta ? " · delta" : " · full package") : "";
    public bool HasSize => SizeText.Length > 0 && HasUpdate;

    private UpdateState S => Service.State;
    public bool IsChecking => S == UpdateState.Checking;
    public bool IsUpToDate => S is UpdateState.UpToDate || (S == UpdateState.Idle && !Service.HasCandidate);
    public bool HasUpdate => S is UpdateState.Available or UpdateState.Downloading or UpdateState.ReadyToInstall
                             || (S == UpdateState.Error && Service.HasCandidate);
    public bool IsDownloading => S == UpdateState.Downloading;
    public bool IsReady => S == UpdateState.ReadyToInstall;
    public bool IsError => S == UpdateState.Error;
    public bool ShowManualInfo => HasUpdate && !Service.CanSelfUpdate;
    public string ManualInfo => Service.InstallModeText;

    // ---- release notes: generated from CHANGELOG.md, so they parse into categories; anything else is plain markdown ----
    private string? _notesSource;
    private IReadOnlyList<ChangelogRelease>? _notesReleases;
    /// <summary>The release notes as a changelog section (one item), or null when they aren't in the changelog format.</summary>
    public IReadOnlyList<ChangelogRelease>? NotesReleases
    {
        get
        {
            var notes = Service.ReleaseNotes;
            if (!ReferenceEquals(notes, _notesSource))
            {
                _notesSource = notes;
                SemVer.TryParse(Service.AvailableVersion, out var v);
                _notesReleases = ChangelogMarkdown.ParseNotes(notes, Service.AvailableVersion is null ? null : v) is { } r ? [r] : null;
            }
            return _notesReleases;
        }
    }
    public bool HasStructuredNotes => NotesReleases is not null;
    public bool HasMarkdownNotes => !HasStructuredNotes;

    public string Heading => S switch
    {
        UpdateState.Checking => "Checking for updates…",
        UpdateState.Downloading => $"Downloading NetSpider {NewVersion}",
        UpdateState.ReadyToInstall => $"NetSpider {NewVersion} is ready to install",
        UpdateState.Error => Service.HasCandidate ? "The update couldn't be downloaded" : "Couldn't check for updates",
        UpdateState.Available => $"NetSpider {NewVersion} is available",
        _ => Service.CanCheck ? "NetSpider is up to date" : "Automatic updates are off",
    };
    public bool CanCheck => Service.CanCheck;

    public string UpToDateText => Service.CanCheck
        ? $"You're running the latest {Service.Channel.ToLowerInvariant()} version ({AppInfo.Version})."
        : UpdateLogic.InstallModeText(Service.InstallMode);

    public string PrimaryText => !Service.CanSelfUpdate ? "Open releases page" : "Install & restart";
    public bool ShowPrimary => HasUpdate && !IsError;
    public bool CanPrimary => !IsDownloading;
    public bool ShowSkip => HasUpdate && !IsDownloading;
    public string CloseText => HasUpdate ? "Later" : "Close";

    private void OnServiceChanged(object? sender, PropertyChangedEventArgs e) => OnPropertyChanged(string.Empty);

    [RelayCommand]
    private async Task Primary()
    {
        try
        {
            if (!Service.CanSelfUpdate) { Launcher.Open(AppInfo.ReleasesPage); return; }
            if (S == UpdateState.Available) await Service.DownloadAsync();
            if (S != UpdateState.ReadyToInstall) return;
            if (Service.GetBusyReason() is { } busy)
            {
                bool ok = await ConfirmDialog.ShowAsync("Install the update now?",
                    $"NetSpider will close, install version {NewVersion} and start again.",
                    busy + ". Restarting stops it — anything not yet saved is lost.", "Install & restart", Owner);
                if (!ok) return;
            }
            Service.InstallNow();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Installing update failed");
            Service.Fail(ex.Message);
        }
    }

    [RelayCommand] private void Later() => Close?.Invoke();

    [RelayCommand]
    private void Skip()
    {
        Service.SkipAvailable();
        Close?.Invoke();
    }

    [RelayCommand]
    private async Task Retry()
    {
        if (Service.HasCandidate && Service.CanSelfUpdate) await Service.DownloadAsync();
        else await Service.CheckNowAsync();
    }

    [RelayCommand] private void OpenReleases() => Launcher.Open(AppInfo.ReleasesPage);

    public void Dispose() => Service.PropertyChanged -= OnServiceChanged;
}
