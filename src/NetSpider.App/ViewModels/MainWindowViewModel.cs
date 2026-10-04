using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Controls.Graph;
using NetSpider.App.Services;
using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class NavItem : ObservableObject
{
    public required string Key { get; init; }
    public required string Title { get; init; }
    public required Geometry Icon { get; init; }
    [ObservableProperty] private int _badge;
    /// <summary>Tooltip with the keyboard shortcut ("Devices  (Ctrl+2)").</summary>
    public string? Tip { get; set; }
    public bool HasBadge => Badge > 0;
    partial void OnBadgeChanged(int value) => OnPropertyChanged(nameof(HasBadge));
}

public sealed record AdapterItem(AdapterInfo Adapter)
{
    public string Title => Adapter.Name;
    public string Detail => (Adapter.PrimaryV4?.ToString() ?? "no IPv4") + (Adapter.IsWireless ? " · Wi-Fi" : "") + (Adapter.SpeedMbps > 0 ? $" · {Adapter.SpeedMbps} Mbps" : "");
    public bool IsVirtual => Adapter.IsVirtual;
    public string VirtualTag => Adapter.IsVirtual ? $"[{Adapter.VirtualKind ?? "virtual"}]" : "";
    public override string ToString() => $"{Title}  {Detail} {VirtualTag}";
}

public sealed partial class ExportItem(IExporter exporter, MainWindowViewModel owner) : ObservableObject
{
    public IExporter Exporter { get; } = exporter;
    public string Title => $"{Exporter.Name} (.{Exporter.FileExtension.TrimStart('.')})";
    [RelayCommand] private Task Export() => owner.ExportAsync(Exporter);
}

public sealed partial class ToastViewModel(Alert alert) : ObservableObject
{
    public Alert Alert { get; } = alert;
    /// <summary>Optional action for the toast's "Show" button (e.g. open the update dialog) instead of navigating to the alert source.</summary>
    public Action? OnShow { get; init; }
    public string ShowText { get; init; } = "Show";
    public string Title => Alert.Title;
    public string Details => Alert.Details;
    public IBrush Accent => AlertsViewModel.SeverityBrush(Alert.Severity);
    public Geometry Icon => AlertsViewModel.SeverityIcon(Alert.Severity);
    public string Time => Alert.Time.ToString("HH:mm:ss");
}

/// <summary>Shell: navigation, top bar (adapter, monitoring, scan, stats, export, demo), banners, toasts.</summary>
public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly IServiceProvider _sp;
    private readonly ISettingsStore _settingsStore;
    private readonly AppSettings _settings;
    private readonly IFrameSource _frames;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly IAlertService _alerts;
    private readonly INetworkState _network;
    private readonly IEventBus _bus;
    private readonly DemoNetwork _demo;
    private readonly GraphEngine _engine;
    private readonly IScanOrchestrator? _orchestrator;
    private readonly List<IDisposable> _subs = [];
    private Throttler? _statsThrottle;
    private CancellationTokenSource? _scanCts;
    private volatile TrafficSnapshot? _lastTraffic;

    public MainWindowViewModel(IServiceProvider sp, ISettingsStore settingsStore, IFrameSource frames, IDeviceStore devices, ITopologyStore topology,
        IAlertService alerts, INetworkState network, IEventBus bus, DemoNetwork demo, GraphEngine engine, SelectionService selection,
        WebViewModel web, InspectorViewModel inspector, DevicesViewModel devicesVm, AlertsViewModel alertsVm, TrafficViewModel traffic,
        WifiViewModel wifi, SegmentsViewModel segments, HealthViewModel health, SettingsViewModel settingsVm, InternetViewModel internet,
        DiagnosticsFeed feed, PathViewModel path, IncidentsViewModel incidents, StormViewModel storm, DataModeController mode)
    {
        _feed = feed;
        _mode = mode;
        mode.ViewsReset += ResetViews;
        Path = path; Incidents = incidents; Storm = storm;
        _sp = sp;
        _settingsStore = settingsStore;
        _settings = settingsStore.Settings;
        _frames = frames;
        _devices = devices;
        _topology = topology;
        _alerts = alerts;
        _network = network;
        _bus = bus;
        _demo = demo;
        _engine = engine;
        _orchestrator = sp.GetService<IScanOrchestrator>();
        Selection = selection;
        Web = web; Inspector = inspector; Devices = devicesVm; Alerts = alertsVm; Traffic = traffic; Wifi = wifi; Segments = segments; Health = health; Settings = settingsVm; Internet = internet;

        NavItems =
        [
            Nav("web", "Spider Web", "IconWeb"),
            Nav("devices", "Devices", "IconDevices"),
            Nav("alerts", "Alerts", "IconAlerts"),
            Nav("traffic", "Traffic", "IconTraffic"),
            Nav("internet", "Internet", "IconGlobe"),
            Nav("path", "Path Doctor", "IconPath"),
            Nav("incidents", "Incidents", "IconIncident"),
            Nav("storm", "Storm Center", "IconStorm"),
            Nav("wifi", "Wi-Fi", "IconWifi"),
            Nav("segments", "Segments & VLANs", "IconSegments"),
            Nav("health", "Health", "IconHealth"),
            Nav("settings", "Settings", "IconSettings"),
        ];
        _selectedNav = NavItems[0];
        foreach (var e in _sp.GetServices<IExporter>()) ExportItems.Add(new ExportItem(e, this));
        Selection.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(SelectionService.Selected) && Selection.Selected is not null) InspectorOpen = true; };
        alertsVm.NavigateToDevice = mac => { if (_devices.TryGet(mac, out var d)) { Selection.Selected = d; SelectedNav = NavItems[0]; } };
        devicesVm.Activated = d => { Selection.Selected = d; InspectorOpen = true; };
        incidents.NavigateToDevice = alertsVm.NavigateToDevice;
        path.Navigate = key => SelectedNav = NavItems.FirstOrDefault(n => n.Key == key) ?? SelectedNav;
        _incidentBadge = new Throttler(TimeSpan.FromMilliseconds(700), UpdateIncidentBadge);
        feed.IncidentsChanged += _incidentBadge.Signal;
        feed.SourceChanged += _incidentBadge.Signal;
    }

    private readonly DiagnosticsFeed _feed;
    private readonly DataModeController _mode;
    private readonly Throttler _incidentBadge;
    /// <summary>Adapter of the running monitoring session (resumed after the demo).</summary>
    private AdapterInfo? _monitoredAdapter;
    private bool _startInFlight;
    private bool _startingFromDemo;

    private void UpdateIncidentBadge()
    {
        if (NavItems.FirstOrDefault(n => n.Key == "incidents") is { } nav) nav.Badge = _feed.Incidents?.Active.Count ?? 0;
    }

    private static NavItem Nav(string key, string title, string icon) => new()
    {
        Key = key, Title = title,
        Icon = Avalonia.Application.Current?.TryGetResource(icon, null, out var g) == true && g is Geometry geo ? geo : new StreamGeometry(),
    };

    // ---- children ----
    public SelectionService Selection { get; }
    public WebViewModel Web { get; }
    public InspectorViewModel Inspector { get; }
    public DevicesViewModel Devices { get; }
    public AlertsViewModel Alerts { get; }
    public TrafficViewModel Traffic { get; }
    public WifiViewModel Wifi { get; }
    public SegmentsViewModel Segments { get; }
    public HealthViewModel Health { get; }
    public SettingsViewModel Settings { get; }
    public InternetViewModel Internet { get; }
    public PathViewModel Path { get; }
    public IncidentsViewModel Incidents { get; }
    public StormViewModel Storm { get; }

    // ---- navigation ----
    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsWebPage), nameof(IsDevicesPage), nameof(IsAlertsPage), nameof(IsTrafficPage), nameof(IsWifiPage),
        nameof(IsSegmentsPage), nameof(IsHealthPage), nameof(IsSettingsPage), nameof(IsInternetPage), nameof(PageTitle),
        nameof(IsPathPage), nameof(IsIncidentsPage), nameof(IsStormPage))]
    private NavItem? _selectedNav;

    private string Page => SelectedNav?.Key ?? "web";
    public bool IsWebPage => Page == "web";
    public bool IsDevicesPage => Page == "devices";
    public bool IsAlertsPage => Page == "alerts";
    public bool IsTrafficPage => Page == "traffic";
    public bool IsWifiPage => Page == "wifi";
    public bool IsSegmentsPage => Page == "segments";
    public bool IsHealthPage => Page == "health";
    public bool IsSettingsPage => Page == "settings";
    public bool IsInternetPage => Page == "internet";
    public bool IsPathPage => Page == "path";
    public bool IsIncidentsPage => Page == "incidents";
    public bool IsStormPage => Page == "storm";
    public string PageTitle => SelectedNav?.Title ?? "";

    // ---- adapters ----
    public ObservableCollection<AdapterItem> Adapters { get; } = [];
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartMonitoringCommand))] private AdapterItem? _selectedAdapter;
    partial void OnSelectedAdapterChanged(AdapterItem? value)
    {
        if (value is null || _settings.LastAdapterId == value.Adapter.Id) return;
        _settings.LastAdapterId = value.Adapter.Id;
        try { _settingsStore.Save(); } catch (Exception ex) { Log.Warning(ex, "Saving settings failed"); }
    }
    public bool HasAdapters => Adapters.Count > 0;

    // ---- state ----
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartMonitoringCommand), nameof(FullScanCommand), nameof(StopCommand))] private bool _isMonitoring;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartMonitoringCommand), nameof(FullScanCommand), nameof(StopCommand))] private bool _isScanning;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private string _scanStage = "";
    [ObservableProperty] private bool _isDemo;
    [ObservableProperty] private bool _inspectorOpen;
    [ObservableProperty] private bool _compactTopBar;

    // ---- stats ----
    [ObservableProperty] private int _deviceCount;
    [ObservableProperty] private int _linkCount;
    [ObservableProperty] private string _pps = "0";
    [ObservableProperty] private string _broadcastPct = "0 %";
    [ObservableProperty] private IBrush _broadcastBrush = Brushes.White;
    [ObservableProperty] private string _dropped = "0";

    // ---- banners ----
    [ObservableProperty] private bool _showNpcapBanner;
    [ObservableProperty] private bool _showAdminBanner;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string? _infoMessage;
    public bool HasError => ErrorMessage is not null;
    public bool HasInfo => InfoMessage is not null;
    partial void OnErrorMessageChanged(string? value) => OnPropertyChanged(nameof(HasError));
    partial void OnInfoMessageChanged(string? value) => OnPropertyChanged(nameof(HasInfo));
    public string NpcapUrl => NpcapEnvironment.DownloadUrl;

    public bool OrchestratorAvailable => _orchestrator is not null;
    public string MonitorTooltip => _orchestrator is null ? "Scan engine not available in this build"
        : !_frames.PcapAvailable ? "Npcap is required for monitoring" : SelectedAdapter is null ? "Select an adapter first" : "Start passive monitoring + latency probing  (Ctrl+M)";
    public string ScanTooltip => _orchestrator is null ? "Scan engine not available in this build" : "Run every discovery stage, then classify, build topology and run health checks  (F5)";

    public ObservableCollection<ExportItem> ExportItems { get; } = [];
    public bool HasExporters => ExportItems.Count > 0;
    public ObservableCollection<ToastViewModel> Toasts { get; } = [];

    // =====================================================================================================

    public void Initialize(AppOptions options)
    {
        Dialogs.Owner ??= (Avalonia.Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        var status = NpcapEnvironment.Check();
        ShowNpcapBanner = !status.NpcapInstalled && !options.HideBanners;
        ShowAdminBanner = !status.IsAdmin && !options.HideBanners;
        Log.Information("Npcap installed: {Installed} ({Version}), admin: {Admin}", status.NpcapInstalled, status.Version, status.IsAdmin);

        try
        {
            if (options.HideBanners)
            {
                // screenshot mode: never show the real adapter/IP of the machine taking the screenshots
                Adapters.Add(new AdapterItem(new AdapterInfo
                {
                    Id = "demo", PcapName = "demo", Name = "Ethernet", Description = "Demo adapter",
                    Mac = Mac.Parse("D8:BB:C1:7A:3F:10"), IPv4 = [new IpWithPrefix(System.Net.IPAddress.Parse("192.168.1.50"), 24)],
                    GatewayV4 = System.Net.IPAddress.Parse("192.168.1.1"), SpeedMbps = 1000, IsUp = true,
                }));
            }
            else
                foreach (var a in _frames.ListAdapters().OrderBy(a => a.IsVirtual).ThenBy(a => a.GatewayV4 is null).ThenBy(a => a.Name))
                    Adapters.Add(new AdapterItem(a));
        }
        catch (Exception ex) { Log.Error(ex, "Listing adapters failed"); }
        SelectedAdapter = Adapters.FirstOrDefault(a => a.Adapter.Id == _settings.LastAdapterId) ?? Adapters.FirstOrDefault();
        OnPropertyChanged(nameof(HasAdapters));
        OnPropertyChanged(nameof(MonitorTooltip));

        _engine.Attach();
        _engine.StartPhysics();
        _engine.Rebuild();

        _statsThrottle = new Throttler(TimeSpan.FromMilliseconds(500), UpdateStats);
        _devices.DeviceAdded += _ => _statsThrottle.Signal();
        _devices.DeviceRemoved += _ => _statsThrottle.Signal();
        _topology.Changed += () => _statsThrottle.Signal();
        _subs.Add(_bus.Subscribe<TrafficSnapshot>(t => { _lastTraffic = t; _statsThrottle.Signal(); }));
        _alerts.AlertRaised += OnAlert;

        if (_orchestrator is not null)
        {
            _orchestrator.Progress += p => Dispatcher.UIThread.Post(() => { ScanProgress = p.Fraction * 100; ScanStage = p.Detail is null ? p.Stage : $"{p.Stage} · {p.Detail}"; });
            _orchestrator.ScanCompleted += () => Dispatcher.UIThread.Post(() => { IsScanning = false; ScanStage = "Scan complete"; ScanProgress = 100; });
        }

        _feed.Demo.Scenario = options.Scenario;
        if (options.Demo) IsDemo = true;
        if (options.DemoToggleTest is { } toggleSeconds) _ = RunDemoToggleTestAsync(toggleSeconds);
        if (options.Page is { } page && NavItems.FirstOrDefault(n => n.Key == page) is { } nav) SelectedNav = nav;
        if (options.Mtr is { } mtrTarget && System.Net.IPAddress.TryParse(mtrTarget, out var mtrIp)
            && AppHost.Services?.GetService<ITracerouter>() is { } tracer && AppHost.Services.GetService<ILatencyProber>() is { } prober)
            DispatcherTimer.RunOnce(() => MtrViewModel.Open(mtrIp, mtrTarget, tracer, prober), TimeSpan.FromSeconds(1));
        if (options.Select is { } sel)
            DispatcherTimer.RunOnce(() =>
            {
                var d = _devices.All.FirstOrDefault(x => x.DisplayName.Contains(sel, StringComparison.OrdinalIgnoreCase));
                if (d is not null) Selection.Selected = d;
            }, TimeSpan.FromSeconds(1.5));
        else if (_orchestrator is null && _devices.Count == 0)
            InfoMessage = "The scan engine isn't part of this build yet. Turn on \"Demo network\" to explore NetSpider with a simulated home/office network.";
        UpdateStats();
        InitializeUpdates(options);
    }

    public void Shutdown()
    {
        ShutdownUpdates();
        _alerts.AlertRaised -= OnAlert;
        foreach (var s in _subs) s.Dispose();
        _statsThrottle?.Dispose();
        _scanCts?.Cancel();
        _demo.Stop();
        try { _orchestrator?.StopAll(); } catch (Exception ex) { Log.Warning(ex, "Stopping orchestrator failed"); }
        _engine.Dispose();
        Settings.Dispose();
    }

    private void UpdateStats()
    {
        DeviceCount = _devices.Count;
        LinkCount = _topology.Links.Count;
        var t = _lastTraffic ?? _network.LastTraffic;
        if (t is not null)
        {
            Pps = t.TotalPps >= 1000 ? $"{t.TotalPps / 1000:0.0}k" : $"{t.TotalPps:0}";
            BroadcastPct = $"{t.BroadcastRatio * 100:0.0} %";
            BroadcastBrush = t.BroadcastRatio >= _settings.StormBroadcastRatio ? AlertsViewModel.SeverityBrush(AlertSeverity.Critical)
                : t.BroadcastRatio >= _settings.StormBroadcastRatio * 0.6 ? AlertsViewModel.SeverityBrush(AlertSeverity.Warning) : Brushes.White;
            Dropped = t.Dropped.ToString("N0");
        }
        Web.HasDevices = DeviceCount > 0;
        NavItems[2].Badge = Alerts.Count;
    }

    private void OnAlert(Alert a)
    {
        Dispatcher.UIThread.Post(() =>
        {
            NavItems[2].Badge = _alerts.Alerts.Count;
            // posted before a demo/real reset: the alert is gone from the service, don't toast it into the other mode
            if (!_alerts.Alerts.Any(x => x.Id == a.Id)) return;
            // only toast fresh alerts (not history replayed by persistence or the demo)
            if (a.Severity < AlertSeverity.Warning || DateTimeOffset.Now - a.Time > TimeSpan.FromSeconds(30)) return;
            var toast = new ToastViewModel(a);
            Toasts.Insert(0, toast);
            while (Toasts.Count > 4) Toasts.RemoveAt(Toasts.Count - 1);
            DispatcherTimer.RunOnce(() => Toasts.Remove(toast), TimeSpan.FromSeconds(7));
        });
    }

    // =====================================================================================================
    //  commands
    // =====================================================================================================

    private bool CanStartMonitoring() => _orchestrator is not null && _frames.PcapAvailable && SelectedAdapter is not null && !IsMonitoring && !IsScanning;

    [RelayCommand(CanExecute = nameof(CanStartMonitoring))]
    private async Task StartMonitoring()
    {
        if (_orchestrator is null || SelectedAdapter is null || _startInFlight) return;
        _startInFlight = true;
        try
        {
            if (IsDemo)
            {
                // leave the demo through the same reset path (no automatic resume: we are starting right now)
                _startingFromDemo = true;
                try { IsDemo = false; } finally { _startingFromDemo = false; }
            }
            ErrorMessage = null;
            var adapter = SelectedAdapter.Adapter;
            await _orchestrator.StartMonitoringAsync(adapter);
            _monitoredAdapter = adapter;
            IsMonitoring = true;
            Health.RefreshCommands();
            ScanStage = $"Monitoring {SelectedAdapter.Title}";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Start monitoring failed");
            ErrorMessage = "Could not start monitoring: " + ex.Message;
        }
        finally { _startInFlight = false; }
    }

    private bool CanFullScan() => _orchestrator is not null && _frames.PcapAvailable && !IsScanning && (IsMonitoring || SelectedAdapter is not null);

    [RelayCommand(CanExecute = nameof(CanFullScan))]
    private async Task FullScan()
    {
        if (_orchestrator is null) return;
        try
        {
            ErrorMessage = null;
            if (!IsMonitoring && SelectedAdapter is not null) await StartMonitoring();
            if (!IsMonitoring) return;
            IsScanning = true;
            ScanProgress = 0;
            ScanStage = "Starting full scan…";
            _scanCts = new CancellationTokenSource();
            await Task.Run(() => _orchestrator.RunFullScanAsync(_scanCts.Token));
            ScanStage = "Scan complete";
            ScanProgress = 100;
        }
        catch (OperationCanceledException) { ScanStage = "Scan cancelled"; }
        catch (Exception ex)
        {
            Log.Error(ex, "Full scan failed");
            ErrorMessage = "Full scan failed: " + ex.Message;
        }
        finally { IsScanning = false; }
    }

    private bool CanStop() => IsMonitoring || IsScanning;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void Stop()
    {
        _scanCts?.Cancel();
        try { _orchestrator?.StopAll(); } catch (Exception ex) { Log.Warning(ex, "Stop failed"); }
        IsMonitoring = false;
        IsScanning = false;
        ScanStage = "Stopped";
    }

    /// <summary>
    /// Demo on/off goes through <see cref="DataModeController"/>: demo and real data never mix. Turning the demo on while
    /// monitoring pauses monitoring (a toast explains it) and turning it off resumes monitoring on the same adapter.
    /// </summary>
    partial void OnIsDemoChanged(bool value)
    {
        try
        {
            if (value)
            {
                AdapterInfo? resume = null;
                if (IsMonitoring || IsScanning)
                {
                    resume = _monitoredAdapter ?? SelectedAdapter?.Adapter;
                    Stop();
                }
                InfoMessage = null;
                Selection.Selected = null;
                _mode.EnterDemo(resume);
                ScanStage = "Demo network running";
                if (resume is not null)
                    ShowToast("Monitoring paused for the demo",
                        $"Real monitoring on {resume.Name} is paused and its data was cleared so it can't mix with the simulated network. It resumes when you turn the demo off.");
            }
            else
            {
                Selection.Selected = null;
                var resume = _mode.ExitDemo();
                ScanStage = "";
                if (resume is not null && !_startingFromDemo)
                {
                    ShowToast("Monitoring resumed", $"Demo data cleared. Monitoring {resume.Name} again; real devices reappear as they are seen.");
                    _ = ResumeMonitoringAsync(resume);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Demo toggle failed");
            ErrorMessage = "Demo network failed: " + ex.Message;
        }
    }

    /// <summary>Drops every view cache after a demo/real switch (called by <see cref="DataModeController.ViewsReset"/>).</summary>
    private void ResetViews()
    {
        Selection.Selected = null;
        _lastTraffic = null;
        Pps = "0";
        BroadcastPct = "0 %";
        BroadcastBrush = Brushes.White;
        Dropped = "0";
        Toasts.Clear();
        Alerts.Reload();
        Devices.Reset();
        Traffic.Reset();
        Wifi.Reload();
        Segments.Reload();
        Health.Reload();
        Health.RefreshCommands();
        UpdateStats();
        UpdateIncidentBadge();
        Web.RequestFitWhenSettled();
    }

    private async Task ResumeMonitoringAsync(AdapterInfo adapter)
    {
        if (Adapters.FirstOrDefault(a => a.Adapter.Id == adapter.Id) is { } item) SelectedAdapter = item;
        if (CanStartMonitoring()) await StartMonitoring();
    }

    /// <summary>In-app toast that is not an alert (it never enters the alert list of either mode).</summary>
    private void ShowToast(string title, string details)
    {
        var toast = new ToastViewModel(Alert.Create(AlertSeverity.Info, AlertKind.Info, title, details));
        Toasts.Insert(0, toast);
        while (Toasts.Count > 4) Toasts.RemoveAt(Toasts.Count - 1);
        DispatcherTimer.RunOnce(() => Toasts.Remove(toast), TimeSpan.FromSeconds(10));
    }

    /// <summary>
    /// Hidden <c>--demo-toggle-test</c>: seeds a marker "real" device and alert, toggles the demo on/off three times and
    /// logs the counts after every switch. Logs "DemoToggleTest PASS" when the demo never leaked into real mode (and
    /// the real marker never into demo mode), otherwise "DemoToggleTest FAIL".
    /// </summary>
    private async Task RunDemoToggleTestAsync(int seconds)
    {
        var marker = Mac.Parse("02:00:5E:10:00:01");
        bool ok = true;
        void Check(string phase, bool demo)
        {
            var c = _mode.Counts();
            bool markerPresent = _devices.TryGet(marker, out _) || _alerts.Alerts.Any(a => a.Source == marker);
            bool pass = demo ? c.DemoDevices == c.Devices && !markerPresent && _network.IsDemo
                             : c.DemoDevices == 0 && c.DemoAlerts == 0 && c.Segments == 0 && !_network.IsDemo;
            ok &= pass;
            Log.Information("DemoToggleTest {Phase}: devices={Devices} links={Links} alerts={Alerts} demoDevices={DemoDevices} demoAlerts={DemoAlerts} segments={Segments} marker={Marker} navAlertBadge={Badge} rows={Rows} graphNodes={Nodes} -> {Result}",
                phase, c.Devices, c.Links, c.Alerts, c.DemoDevices, c.DemoAlerts, c.Segments, markerPresent, NavItems[2].Badge, Devices.Rows.Count,
                _engine.Snapshot.Nodes.Length, pass ? "ok" : "LEAK");
        }
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(2));
            if (IsDemo) IsDemo = false;
            for (int round = 1; round <= 3; round++)
            {
                // stand-in for real data (no capture needed): one device and one alert
                _devices.Observe(marker, System.Net.IPAddress.Parse("10.99.0.1"), "toggle-test");
                _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.Info, "Toggle test marker", "real-mode marker alert", marker), TimeSpan.Zero);
                await Task.Delay(TimeSpan.FromSeconds(1));
                IsDemo = true;
                await Task.Delay(TimeSpan.FromSeconds(seconds));
                Check($"round {round} demo on", demo: true);
                IsDemo = false;
                await Task.Delay(TimeSpan.FromSeconds(seconds));
                Check($"round {round} demo off", demo: false);
            }
            Log.Information(ok ? "DemoToggleTest PASS" : "DemoToggleTest FAIL");
        }
        catch (Exception ex) { Log.Error(ex, "DemoToggleTest failed"); }
    }

    [RelayCommand] private void ToggleInspector() => InspectorOpen = !InspectorOpen;
    [RelayCommand] private void GoToPath() => SelectedNav = NavItems.FirstOrDefault(n => n.Key == "path") ?? SelectedNav;
    [RelayCommand] private void GoToInternet() => SelectedNav = NavItems.FirstOrDefault(n => n.Key == "internet") ?? SelectedNav;
    [RelayCommand] private void DismissError() => ErrorMessage = null;
    [RelayCommand] private void DismissInfo() => InfoMessage = null;
    [RelayCommand] private void OpenNpcapDownload() => Launcher.Open(NpcapEnvironment.DownloadUrl);
    [RelayCommand] private void DismissToast(ToastViewModel t) => Toasts.Remove(t);
    [RelayCommand] private void ShowToastSource(ToastViewModel t)
    {
        Toasts.Remove(t);
        if (t.OnShow is { } show) { show(); return; }
        if (t.Alert.Source is { } m) Alerts.NavigateToDevice?.Invoke(m);
        else SelectedNav = NavItems[2];
    }

    [RelayCommand]
    private void RefreshAdapters()
    {
        var keep = SelectedAdapter?.Adapter.Id;
        Adapters.Clear();
        foreach (var a in _frames.ListAdapters()) Adapters.Add(new AdapterItem(a));
        SelectedAdapter = Adapters.FirstOrDefault(a => a.Adapter.Id == keep) ?? Adapters.FirstOrDefault();
        OnPropertyChanged(nameof(HasAdapters));
    }

    public async Task ExportAsync(IExporter exporter)
    {
        try
        {
            var ext = exporter.FileExtension.TrimStart('.');
            var path = await Dialogs.SaveFileAsync($"Export {exporter.Name}", ext, $"netspider-{DateTime.Now:yyyyMMdd-HHmm}.{ext}");
            if (path is null) return;
            byte[]? png = null;
            try { png = Web.RenderPng(1600, 1000); }
            catch (Exception ex) { Log.Warning(ex, "Rendering topology PNG failed"); }
            var data = new ExportData(_devices.All, _topology.Links, _alerts.Alerts, _network, png, SelectedAdapter?.Adapter ?? _frames.Adapter);
            await Task.Run(() => exporter.ExportAsync(path, data));
            InfoMessage = $"Exported {exporter.Name} to {path}";
            DispatcherTimer.RunOnce(() => { if (InfoMessage?.StartsWith("Exported") == true) InfoMessage = null; }, TimeSpan.FromSeconds(8));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Export {Exporter} failed", exporter.Name);
            ErrorMessage = $"Export failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ExportGraphPng()
    {
        var path = await Dialogs.SaveFileAsync("Save topology image", "png", $"netspider-topology-{DateTime.Now:yyyyMMdd-HHmm}.png");
        if (path is null) return;
        try
        {
            await File.WriteAllBytesAsync(path, Web.RenderPng(2400, 1500));
            InfoMessage = $"Saved topology image to {path}";
        }
        catch (Exception ex) { ErrorMessage = "Saving image failed: " + ex.Message; }
    }
}
