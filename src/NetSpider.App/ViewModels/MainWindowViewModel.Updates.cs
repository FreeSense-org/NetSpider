using System.ComponentModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Services;
using NetSpider.Core;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

/// <summary>Shell part for the updater, the About dialog and FreeSense branding (top-bar update chip, toasts, F1).</summary>
public sealed partial class MainWindowViewModel
{
    private UpdateService? _updates;

    /// <summary>The updater (null only while the DI container isn't built, e.g. in the designer).</summary>
    public UpdateService? Updates => _updates ??= AppHost.Services?.GetService<UpdateService>();

    /// <summary>"FreeSense – NetSpider 1.2.3".</summary>
    public string WindowTitle => AppInfo.WindowTitle();

    public bool ShowUpdateChip => Updates?.ShowChip == true;
    /// <summary>Full text ("⬆ Update 1.2.3") on wide windows, just "⬆ 1.2.3" when the top bar is compact.</summary>
    public string UpdateChipText => Updates is not { } u ? "" : CompactTopBar ? $"⬆ {u.AvailableVersion}" : u.ChipText;
    public string UpdateChipTooltip => Updates?.State == UpdateState.ReadyToInstall
        ? $"NetSpider {Updates.AvailableVersion} is downloaded — click to install and restart"
        : $"NetSpider {Updates?.AvailableVersion} is available — click for release notes";

    private void InitializeUpdates(AppOptions options)
    {
        if (Updates is not { } svc) return;
        PropertyChanged += (_, e) => { if (e.PropertyName == nameof(CompactTopBar)) OnPropertyChanged(nameof(UpdateChipText)); };
        svc.PropertyChanged += OnUpdatesChanged;
        svc.Notice += OnUpdateNotice;

        if (options.UpdatePreview is { } preview)
        {
            ApplyUpdatePreview(svc, preview);
            if (preview == "chip") // top-bar chip + toast only
                DispatcherTimer.RunOnce(() => OnUpdateNotice(new UpdateNotice(UpdateNoticeKind.Available, "1.2.0")), TimeSpan.FromSeconds(1));
            else DispatcherTimer.RunOnce(() => UpdateWindowViewModel.Show(svc), TimeSpan.FromSeconds(1));
        }
        else svc.Start(TimeSpan.FromSeconds(20));

        if (options.About) DispatcherTimer.RunOnce(() => AboutWindowViewModel.Show(svc, options.AboutTab), TimeSpan.FromSeconds(1));
        if (options.WhatsNew is { } whatsNew) DispatcherTimer.RunOnce(() => WhatsNewWindowViewModel.ShowPreview(whatsNew), TimeSpan.FromSeconds(1));
    }

    private void ShutdownUpdates()
    {
        if (_updates is null) return;
        _updates.PropertyChanged -= OnUpdatesChanged;
        _updates.Notice -= OnUpdateNotice;
        _updates.OnAppExit();
    }

    private void OnUpdatesChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(ShowUpdateChip));
        OnPropertyChanged(nameof(UpdateChipText));
        OnPropertyChanged(nameof(UpdateChipTooltip));
    }

    private void OnUpdateNotice(UpdateNotice n)
    {
        Dispatcher.UIThread.Post(() =>
        {
            // Quiet while monitoring or recording: the chip still shows, but no toast pops up over the work.
            if (Updates?.GetBusyReason() is not null) return;
            var (title, details, action) = n.Kind == UpdateNoticeKind.Ready
                ? ($"NetSpider {n.Version} is ready to install", "Downloaded in the background. Restart NetSpider to finish updating.", "Install…")
                : ($"NetSpider {n.Version} is available", Updates?.CanSelfUpdate == true
                    ? "A new version is available. Open it for the release notes."
                    : "A new version is available on the releases page.", "Details");
            var toast = new ToastViewModel(new Alert(Guid.NewGuid(), DateTimeOffset.Now, AlertSeverity.Warning, AlertKind.Info, title, details))
            {
                OnShow = () => ShowUpdate(),
                ShowText = action,
            };
            Toasts.Insert(0, toast);
            while (Toasts.Count > 4) Toasts.RemoveAt(Toasts.Count - 1);
            DispatcherTimer.RunOnce(() => Toasts.Remove(toast), TimeSpan.FromSeconds(12));
        });
    }

    /// <summary>Opens the About dialog (nav "About", F1, and the tray menu).</summary>
    [RelayCommand]
    public void ShowAbout() => AboutWindowViewModel.Show(Updates);

    /// <summary>Opens the update dialog (top-bar chip, toasts, tray menu).</summary>
    [RelayCommand]
    public void ShowUpdate()
    {
        if (Updates is { } svc) UpdateWindowViewModel.Show(svc);
    }

    /// <summary>Opens the update dialog and runs a manual check (tray "Check for updates").</summary>
    [RelayCommand]
    public void CheckForUpdates()
    {
        if (Updates is { } svc) UpdateWindowViewModel.Show(svc, checkNow: true);
        else Launcher.Open(AppInfo.ReleasesPage);
    }

    [RelayCommand] private static void OpenFreeSense() => Launcher.Open(AppInfo.Website);

    private static void ApplyUpdatePreview(UpdateService svc, string state)
    {
        // the format build/release.ps1 ships: the version's CHANGELOG.md section (ChangelogTool notes)
        const string notes = """
            ### New
            - Storm Center shows a per-port broadcast breakdown for managed switches. (#212)
            - The spider web can be exported as SVG.

            ### Improved
            - Path Doctor finds the failing hop up to three times faster.
            - The Wi-Fi to LAN crossover test works on ARM64 laptops.

            ### Fixed
            - Devices with an empty mDNS name no longer show as `(null)`.
            - The topology export keeps manually pinned nodes.
            - A rare crash when the capture adapter disappeared is fixed. (#198)

            ### Security
            - The probe agent rejects reports signed with an outdated key.
            """;
        try
        {
            switch (state)
            {
                case "downloading": svc.Preview(UpdateState.Downloading, "1.2.0", notes, 38_400_000, 62); break;
                case "ready": svc.Preview(UpdateState.ReadyToInstall, "1.2.0", notes, 38_400_000, 100); break;
                case "error": svc.Preview(UpdateState.Error, "1.2.0", notes, 38_400_000, 0, "The remote server returned an error: (503) Service Unavailable."); break;
                case "uptodate": svc.Preview(UpdateState.UpToDate, "1.2.0", notes, 0); break;
                case "manual": svc.Preview(UpdateState.Available, "1.2.0", notes, 38_400_000, selfUpdate: false); break;
                default: svc.Preview(UpdateState.Available, "1.2.0", notes, 38_400_000); break;
            }
        }
        catch (Exception ex) { Log.Warning(ex, "Update preview failed"); }
    }
}
