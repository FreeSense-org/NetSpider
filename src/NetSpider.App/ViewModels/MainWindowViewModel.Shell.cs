using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Capture;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.ViewModels;

// First-run and in-app essentials (shell integration): crash notice, guided Npcap install, welcome, shortcuts, navigation helpers.
// Kept in its own partial so the main view model file stays focused on the network UI.
public sealed partial class MainWindowViewModel
{
    // ---- navigation helpers (tray, notifications, single-instance --page, shortcuts) ----

    /// <summary>Selects the page with this nav key (web, devices, alerts, …); unknown keys are ignored.</summary>
    public void Navigate(string key)
    {
        if (NavItems.FirstOrDefault(n => string.Equals(n.Key, key, StringComparison.OrdinalIgnoreCase)) is { } nav) SelectedNav = nav;
    }

    [RelayCommand] private void NavigateTo(string key) => Navigate(key);

    [RelayCommand] private void NavigateIndex(string index)
    {
        if (int.TryParse(index, out var i) && i >= 1 && i <= NavItems.Count) SelectedNav = NavItems[i - 1];
    }

    /// <summary>Ctrl+M: start monitoring, or stop when monitoring/scanning.</summary>
    [RelayCommand]
    private void ToggleMonitoring()
    {
        if (IsMonitoring || IsScanning) { if (StopCommand.CanExecute(null)) StopCommand.Execute(null); }
        else if (StartMonitoringCommand.CanExecute(null)) StartMonitoringCommand.Execute(null);
    }

    /// <summary>Ctrl+F: the view focuses the spider-web search box.</summary>
    public event Action? FocusSearchRequested;

    [RelayCommand]
    private void FocusSearch()
    {
        Navigate("web");
        Dispatcher.UIThread.Post(() => FocusSearchRequested?.Invoke(), DispatcherPriority.Loaded);
    }

    /// <summary>Shortcut hints shown in the navigation tooltips.</summary>
    internal void ApplyShortcutTips()
    {
        for (int i = 0; i < NavItems.Count; i++)
        {
            var n = NavItems[i];
            n.Tip = n.Key == "settings" ? $"{n.Title}  (Ctrl+,)" : i < 9 ? $"{n.Title}  (Ctrl+{i + 1})" : n.Title;
        }
    }

    // ---- crash notice ----

    [ObservableProperty] private bool _showCrashBanner;
    [ObservableProperty] private string _crashBannerText = "";
    private string? _crashFile;

    internal void SetPreviousCrash(IReadOnlyList<string> files)
    {
        if (files.Count == 0) return;
        _crashFile = files[0];
        CrashBannerText = files.Count == 1
            ? $"A crash report was saved: {System.IO.Path.GetFileName(files[0])}"
            : $"{files.Count} crash reports were saved, the latest is {System.IO.Path.GetFileName(files[0])}";
        ShowCrashBanner = true;
    }

    [RelayCommand]
    private void OpenLogFolder()
    {
        if (_crashFile is not null && File.Exists(_crashFile)) Launcher.Run("explorer.exe", $"/select,\"{_crashFile}\"");
        else Launcher.Open(AppPaths.Logs);
    }

    [RelayCommand] private void DismissCrash() => ShowCrashBanner = false;

    // ---- guided Npcap install ----

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(InstallNpcapCommand))] private bool _isInstallingNpcap;
    [ObservableProperty] private double _npcapInstallProgress;
    [ObservableProperty] private string? _npcapInstallText;
    [ObservableProperty] private bool _npcapInstalled = NpcapEnvironment.Check().NpcapInstalled;
    [ObservableProperty] private string _npcapStatusText = "";

    private bool CanInstallNpcap() => !IsInstallingNpcap;

    [RelayCommand(CanExecute = nameof(CanInstallNpcap))]
    private async Task InstallNpcap()
    {
        IsInstallingNpcap = true;
        NpcapInstallProgress = 0;
        try
        {
            var progress = new Progress<NpcapInstaller.Progress>(p => { NpcapInstallText = p.Stage; NpcapInstallProgress = p.Fraction * 100; });
            var outcome = await NpcapInstaller.InstallAsync(progress);
            bool ok = RecheckNpcap();
            NpcapInstallProgress = 100;
            NpcapInstallText = ok ? "Npcap is installed — you can start monitoring now." : outcome.Message;
            if (ok)
            {
                InfoMessage = "Npcap is installed. Pick your adapter and press Monitor.";
                Log.Information("Npcap install finished: {Message}", outcome.Message);
            }
            else if (!outcome.Success) ErrorMessage = outcome.Message;
        }
        finally { IsInstallingNpcap = false; }
    }

    /// <summary>Re-detects Npcap and refreshes the adapters without restarting. Returns true when Npcap is usable.</summary>
    public bool RecheckNpcap(bool refreshAdapters = true)
    {
        bool ok = _frames is CaptureService cs ? cs.RecheckPcap() : _frames.PcapAvailable;
        var status = NpcapEnvironment.Check();
        ok = ok && status.NpcapInstalled;
        NpcapInstalled = ok;
        NpcapStatusText = ok ? $"Npcap {ShortNpcapVersion(status.Version)} is installed" : "Npcap is not installed";
        if (ok && refreshAdapters)
        {
            ShowNpcapBanner = false;
            try { if (!AppHost.Options.HideBanners) RefreshAdaptersCommand.Execute(null); }
            catch (Exception ex) { Log.Warning(ex, "Refreshing adapters failed"); }
        }
        OnPropertyChanged(nameof(MonitorTooltip));
        StartMonitoringCommand.NotifyCanExecuteChanged();
        FullScanCommand.NotifyCanExecuteChanged();
        return ok;
    }

    /// <summary>"Npcap version 1.89, based on libpcap …" → "1.89".</summary>
    internal static string ShortNpcapVersion(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "(unknown version)";
        var m = System.Text.RegularExpressions.Regex.Match(v, @"Npcap version (\d+(?:\.\d+)*)");
        return m.Success ? m.Groups[1].Value : v.Split(',')[0];
    }

    // ---- welcome ----

    /// <summary>Opens the first-run welcome wizard (also linked from About and Settings).</summary>
    [RelayCommand]
    private Task ShowWelcome() => WelcomeWindow.ShowAsync(this, _settingsStore);
}
