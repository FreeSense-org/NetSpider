using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Services;
using NetSpider.Capture;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class WelcomeStep(int index, string title, string subtitle) : ObservableObject
{
    public int Index { get; } = index;
    public string Number => (Index + 1).ToString();
    public string Title { get; } = title;
    public string Subtitle { get; } = subtitle;
    [ObservableProperty] private bool _isCurrent;
    [ObservableProperty] private bool _isDone;
}

/// <summary>First-run wizard: brand → Npcap (guided install) → adapter → opt-ins → start monitoring / explore the demo.</summary>
public sealed partial class WelcomeViewModel : ObservableObject
{
    private readonly ISettingsStore _store;
    private AppSettings S => _store.Settings;

    public WelcomeViewModel(MainWindowViewModel main, ISettingsStore store)
    {
        Main = main;
        _store = store;
        Steps =
        [
            new WelcomeStep(0, "Welcome", "What NetSpider does"),
            new WelcomeStep(1, "Npcap", "Packet capture driver"),
            new WelcomeStep(2, "Adapter", "Where to listen"),
            new WelcomeStep(3, "Preferences", "How NetSpider runs"),
        ];
        _autoStartMonitoring = S.AutoStartMonitoring;
        _startWithWindows = S.StartWithWindows;
        _closeToTray = S.CloseToTray;
        _internetMonitor = S.InternetMonitorEnabled;
        _updateAction = S.UpdateAction;
        Logo = LoadLogo();
        Main.RecheckNpcap(refreshAdapters: false);
        Main.StartMonitoringCommand.CanExecuteChanged += (_, _) => StartMonitoringCommand.NotifyCanExecuteChanged();
        UpdateSteps();
    }

    public MainWindowViewModel Main { get; }
    public IReadOnlyList<WelcomeStep> Steps { get; }
    public string Title => $"Welcome to {AppInfo.BrandTitle}";
    public string VersionText => $"Version {AppInfo.Version} · {AppInfo.Architecture}";
    public IImage? Logo { get; }
    public bool HasLogo => Logo is not null;
    public string Website => AppInfo.Website;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsStep0), nameof(IsStep1), nameof(IsStep2), nameof(IsStep3), nameof(CanGoBack), nameof(IsLastStep), nameof(IsNotLastStep), nameof(StepCaption))]
    [NotifyCanExecuteChangedFor(nameof(BackCommand), nameof(NextCommand))]
    private int _step;

    public bool IsStep0 => Step == 0;
    public bool IsStep1 => Step == 1;
    public bool IsStep2 => Step == 2;
    public bool IsStep3 => Step == 3;
    public bool CanGoBack => Step > 0;
    public bool IsLastStep => Step == Steps.Count - 1;
    public bool IsNotLastStep => !IsLastStep;
    public string StepCaption => $"Step {Step + 1} of {Steps.Count}";

    partial void OnStepChanged(int value) => UpdateSteps();

    private void UpdateSteps()
    {
        foreach (var s in Steps) { s.IsCurrent = s.Index == Step; s.IsDone = s.Index < Step; }
    }

    // ---- staged opt-ins (applied on finish) ----
    [ObservableProperty] private bool _autoStartMonitoring;
    [ObservableProperty] private bool _startWithWindows;
    [ObservableProperty] private bool _closeToTray;
    [ObservableProperty] private bool _internetMonitor;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UpdateNotify), nameof(UpdateDownload), nameof(UpdateOnExit))]
    private UpdateAction _updateAction;

    public bool UpdateNotify { get => UpdateAction == UpdateAction.NotifyOnly; set { if (value) UpdateAction = UpdateAction.NotifyOnly; } }
    public bool UpdateDownload { get => UpdateAction == UpdateAction.DownloadAndAsk; set { if (value) UpdateAction = UpdateAction.DownloadAndAsk; } }
    public bool UpdateOnExit { get => UpdateAction == UpdateAction.InstallOnExit; set { if (value) UpdateAction = UpdateAction.InstallOnExit; } }

    public bool IsAdmin { get; } = NpcapEnvironment.IsAdministrator();
    public string StartWithWindowsHint => IsAdmin
        ? "Registers a sign-in task (runs elevated, starts minimized to the tray)."
        : "Needs NetSpider to run as administrator to register the sign-in task.";

    /// <summary>Raised when the wizard is finished or skipped; the window closes.</summary>
    public event Action? CloseRequested;
    public bool Finished { get; private set; }

    [RelayCommand(CanExecute = nameof(CanGoBack))] private void Back() => Step--;

    private bool CanNext() => !IsLastStep;
    [RelayCommand(CanExecute = nameof(CanNext))] private void Next() => Step++;

    [RelayCommand] private void GoTo(WelcomeStep s) => Step = s.Index;

    [RelayCommand] private void OpenWebsite() => Launcher.Open(AppInfo.Website);
    [RelayCommand] private void OpenNpcapSite() => Launcher.Open(NpcapEnvironment.DownloadUrl);

    private bool CanStartMonitoring() => Main.StartMonitoringCommand.CanExecute(null);

    [RelayCommand(CanExecute = nameof(CanStartMonitoring))]
    private async Task StartMonitoring()
    {
        await FinishAsync();
        if (Main.IsDemo) Main.IsDemo = false;
        if (Main.StartMonitoringCommand.CanExecute(null)) await Main.StartMonitoringCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private async Task ExploreDemo()
    {
        await FinishAsync();
        Main.IsDemo = true;
    }

    [RelayCommand]
    private void Skip()
    {
        MarkShown();
        CloseRequested?.Invoke();
    }

    /// <summary>The window's close button counts as "skip" (the wizard is still reachable from Settings and About).</summary>
    public void OnClosedWithoutFinishing()
    {
        if (!Finished) MarkShown();
    }

    private void MarkShown()
    {
        Finished = true;
        if (S.WelcomeShown) return;
        S.WelcomeShown = true;
        try { _store.Save(); } catch (Exception ex) { Log.Warning(ex, "Saving settings failed"); }
    }

    private async Task FinishAsync()
    {
        Finished = true;
        S.WelcomeShown = true;
        S.AutoStartMonitoring = AutoStartMonitoring;
        S.CloseToTray = CloseToTray;
        S.InternetMonitorEnabled = InternetMonitor;
        S.UpdateAction = UpdateAction;
        if (StartWithWindows != S.StartWithWindows)
        {
            var r = StartWithWindows ? await StartupTask.EnableAsync() : await StartupTask.DisableAsync();
            if (r.Success) S.StartWithWindows = StartWithWindows;
            else Main.ErrorMessage = r.Message;
        }
        try { _store.Save(); } catch (Exception ex) { Log.Warning(ex, "Saving settings failed"); }
        Main.Settings.RefreshApplication();
        CloseRequested?.Invoke();
    }

    private static IImage? LoadLogo()
    {
        foreach (var name in new[] { "logo-256.png", "logo-512.png" })
        {
            try
            {
                var uri = new Uri($"avares://NetSpider/Assets/Brand/{name}");
                if (AssetLoader.Exists(uri)) return new Bitmap(AssetLoader.Open(uri));
            }
            catch (Exception ex) { Log.Debug(ex, "Logo {Name} not usable", name); }
        }
        return null;
    }
}
