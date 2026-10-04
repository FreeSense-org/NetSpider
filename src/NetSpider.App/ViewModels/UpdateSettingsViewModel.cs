using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Services;
using NetSpider.Core;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class SettingsViewModel
{
    private UpdateSettingsViewModel? _updates;

    /// <summary>The "Updates" card (resolved lazily so the settings page doesn't depend on the updater's construction order).</summary>
    public UpdateSettingsViewModel? Updates =>
        _updates ??= AppHost.Services?.GetService<UpdateService>() is { } svc ? new UpdateSettingsViewModel(svc, Settings) : null;
}

/// <summary>Settings → Updates: check schedule, channel, what to do when an update is found, skipped version, status.</summary>
public sealed partial class UpdateSettingsViewModel : ObservableObject
{
    public UpdateSettingsViewModel(UpdateService service, AppSettings settings)
    {
        Service = service;
        Settings = settings;
        Service.PropertyChanged += OnServiceChanged;
    }

    public UpdateService Service { get; }
    public AppSettings Settings { get; }

    /// <summary>"Also receive pre-releases": stable versions are always offered; pre-releases only when this is on.</summary>
    public bool IncludePrereleases
    {
        get => Service.IsPrerelease;
        set
        {
            if (value == Service.IsPrerelease) return;
            Settings.UpdateChannel = value ? UpdateLogic.PrereleaseChannel : UpdateLogic.ReleaseChannel;
            Service.ResetEngine();
            OnPropertyChanged();
            OnPropertyChanged(nameof(CurrentVersion));
        }
    }

    public decimal? CheckHours
    {
        get => Settings.UpdateCheckHours;
        set { Settings.UpdateCheckHours = Math.Clamp((int)(value ?? 6), 0, 24 * 7); OnPropertyChanged(); OnPropertyChanged(nameof(CheckHoursHint)); }
    }
    public string CheckHoursHint => Settings.UpdateCheckHours <= 0 ? "periodic checks off" : Settings.UpdateCheckHours == 1 ? "every hour" : $"every {Settings.UpdateCheckHours} hours";

    public bool IsNotifyOnly { get => Settings.UpdateAction == UpdateAction.NotifyOnly; set { if (value) SetAction(UpdateAction.NotifyOnly); } }
    public bool IsDownloadAndAsk { get => Settings.UpdateAction == UpdateAction.DownloadAndAsk; set { if (value) SetAction(UpdateAction.DownloadAndAsk); } }
    public bool IsInstallOnExit { get => Settings.UpdateAction == UpdateAction.InstallOnExit; set { if (value) SetAction(UpdateAction.InstallOnExit); } }

    private void SetAction(UpdateAction a)
    {
        Settings.UpdateAction = a;
        OnPropertyChanged(nameof(IsNotifyOnly));
        OnPropertyChanged(nameof(IsDownloadAndAsk));
        OnPropertyChanged(nameof(IsInstallOnExit));
    }

    // ---- what applies to this install ----
    public bool CanCheck => Service.CanCheck;
    public bool CanSelfUpdate => Service.CanSelfUpdate && Service.InstallMode == InstallMode.Setup;
    public string InstallModeName => Service.InstallModeName;
    public string InstallModeText => Service.InstallModeText;
    public bool IsSetup => Service.InstallMode == InstallMode.Setup;
    public string ActionHint => CanSelfUpdate ? "" : "Downloading and installing is only available in the Setup version.";
    public bool HasActionHint => !CanSelfUpdate;

    // ---- status ----
    public string? SkippedVersion => Settings.SkippedVersion;
    public bool HasSkipped => !string.IsNullOrWhiteSpace(Settings.SkippedVersion);
    public string LastChecked => Settings.LastUpdateCheck is { } t
        ? $"Last checked: {FormatTime(t)} — {Settings.LastUpdateResult ?? "no result"}"
        : "Last checked: never";
    public string CurrentVersion => $"Installed version {AppInfo.Version} · {Service.Channel} channel";
    public bool IsChecking => Service.IsChecking;
    public bool ShowOpenUpdate => Service.ShowChip;
    public string OpenUpdateText => Service.State == UpdateState.ReadyToInstall ? $"Install {Service.AvailableVersion}…" : $"View {Service.AvailableVersion}…";

    private static string FormatTime(DateTimeOffset t)
    {
        var local = t.ToLocalTime();
        return local.Date == DateTime.Today ? $"today {local:HH:mm}" : local.Date == DateTime.Today.AddDays(-1) ? $"yesterday {local:HH:mm}" : local.ToString("yyyy-MM-dd HH:mm");
    }

    /// <summary>"Remove my data when uninstalling": a marker file the Velopack uninstall hook looks for.</summary>
    public bool RemoveDataOnUninstall
    {
        get => File.Exists(VelopackHooks.RemoveDataMarkerPath);
        set
        {
            try
            {
                if (value)
                {
                    Directory.CreateDirectory(VelopackHooks.DataRoot);
                    File.WriteAllText(VelopackHooks.RemoveDataMarkerPath, "The uninstaller deletes this folder because \"Remove my data when uninstalling\" is on.\n");
                }
                else if (File.Exists(VelopackHooks.RemoveDataMarkerPath)) File.Delete(VelopackHooks.RemoveDataMarkerPath);
            }
            catch (Exception ex) { Log.Warning(ex, "Updating the uninstall marker failed"); }
            OnPropertyChanged();
        }
    }

    private bool CanCheckNow() => CanCheck && !Service.IsBusy;

    [RelayCommand(CanExecute = nameof(CanCheckNow))]
    private async Task CheckNow()
    {
        await Service.CheckNowAsync();
        if (Service.ShowChip) UpdateWindowViewModel.Show(Service);
    }

    [RelayCommand] private void OpenUpdate() => UpdateWindowViewModel.Show(Service);

    [RelayCommand]
    private void ClearSkipped()
    {
        Service.ClearSkipped();
        OnPropertyChanged(nameof(SkippedVersion));
        OnPropertyChanged(nameof(HasSkipped));
    }

    [RelayCommand] private static void ViewReleaseNotes() => Launcher.Open(AppInfo.ReleasesPage);

    /// <summary>The "What's new" dialog for the installed version (from the changelog built into the app).</summary>
    [RelayCommand] private static void ShowWhatsNew() => WhatsNewWindowViewModel.ShowCurrent();

    private void OnServiceChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(LastChecked));
        OnPropertyChanged(nameof(IsChecking));
        OnPropertyChanged(nameof(SkippedVersion));
        OnPropertyChanged(nameof(HasSkipped));
        OnPropertyChanged(nameof(ShowOpenUpdate));
        OnPropertyChanged(nameof(OpenUpdateText));
        OnPropertyChanged(nameof(CurrentVersion));
        CheckNowCommand.NotifyCanExecuteChanged();
    }
}
