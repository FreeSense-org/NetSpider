using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Controls;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

// =========================================================================================================
//  Wi-Fi
// =========================================================================================================

public sealed record WifiRow(WifiNetwork Net)
{
    public string Ssid => string.IsNullOrEmpty(Net.Ssid) ? "(hidden)" : Net.Ssid;
    public string Bssid => Net.Bssid.ToString();
    public string Vendor => Net.Vendor ?? "";
    public int Channel => Net.Channel;
    public string Band => Net.Band;
    public int Rssi => Net.RssiDbm;
    public string RssiText => $"{Net.RssiDbm} dBm";
    public string Security => Net.Security;
    public IBrush SecurityBrush => Net.Security.Contains("open", StringComparison.OrdinalIgnoreCase) || Net.Security.Contains("WEP", StringComparison.OrdinalIgnoreCase) ? Ui.Red
        : Net.Security.Contains("WPA3", StringComparison.OrdinalIgnoreCase) ? Ui.Green : Ui.Text;
    public string Phy => Net.Phy;
    public string Width => Net.ChannelWidthMhz is { } w ? $"{w} MHz" : "";
    public bool Connected => Net.Connected;
    public IBrush SsidBrush => new SolidColorBrush(ChannelChart.ColorFor(Net.Ssid));
}

public sealed partial class WifiViewModel : ObservableObject
{
    private readonly INetworkState _network;
    private readonly IWifiScanner? _scanner;

    public WifiViewModel(IServiceProvider sp, INetworkState network)
    {
        _network = network;
        _scanner = sp.GetService<IWifiScanner>();
        Link = sp.GetRequiredService<WifiLinkViewModel>();
        network.Changed += w => { if (w == "wifi") Dispatcher.UIThread.Post(Reload); };
        Dispatcher.UIThread.Post(Reload);
    }

    /// <summary>"Link diagnostics" section: this host's radio link, events, per-AP health.</summary>
    public WifiLinkViewModel Link { get; }
    public ObservableCollection<WifiRow> Networks { get; } = [];
    [ObservableProperty] private IReadOnlyList<WifiNetwork> _all = [];
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(ScanCommand))] private bool _isScanning;
    [ObservableProperty] private string _status = "";
    public bool CanScanWifi => _scanner is { Available: true };
    public string ScanTooltip => _scanner is null ? "Wi-Fi scanner not available in this build" : !_scanner.Available ? "No wireless adapter / WLAN service" : "Trigger a WLAN scan (takes ~4 s)";
    public bool IsEmpty => Networks.Count == 0;

    public void Reload()
    {
        var nets = _network.WifiNetworks;
        All = nets;
        Networks.Clear();
        foreach (var n in nets.OrderByDescending(n => n.Connected).ThenByDescending(n => n.RssiDbm)) Networks.Add(new WifiRow(n));
        Status = nets.Count == 0 ? "" : $"{nets.Count} BSSIDs · {nets.Select(n => n.Ssid).Distinct().Count()} SSIDs · last seen {nets.Max(n => n.Seen):HH:mm:ss}";
        OnPropertyChanged(nameof(IsEmpty));
    }

    private bool CanScan() => CanScanWifi && !IsScanning;

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task Scan()
    {
        if (_scanner is null) return;
        if (_network.IsDemo) { Status = "Demo network: Wi-Fi networks are simulated (turn the demo off to scan for real)."; return; }
        IsScanning = true;
        Status = "Scanning…";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var nets = await Task.Run(() => _scanner.ScanAsync(cts.Token));
            if (_network.IsDemo) return; // demo switched on while scanning: never mix real networks into it
            _network.WifiNetworks = nets;
            Reload();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Wi-Fi scan failed");
            Status = "Scan failed: " + ex.Message;
        }
        finally { IsScanning = false; }
    }
}

// =========================================================================================================
//  Segments & VLANs
// =========================================================================================================

public sealed partial class SegmentRow(NetworkSegment seg) : ObservableObject
{
    public NetworkSegment Segment { get; } = seg;
    public string Cidr => Segment.Cidr;
    public string Source => Segment.Source;
    public string Vlan => Segment.VlanId is { } v ? (Segment.VlanName is { } n ? $"{v} · {n}" : v.ToString()) : "—";
    public string Gateway => Segment.Gateway?.ToString() ?? "—";
    public bool IsLocal => Segment.IsLocal;
    public string LocalText => Segment.IsLocal ? "local" : "routed";
    public IBrush LocalBrush => Segment.IsLocal ? Ui.Green : Ui.Dim;
    public int HostsFound => Segment.HostsFound;
    public string LastScanned => Segment.LastScanned is { } t ? t.ToString("HH:mm") : "never";
    public bool ScanEnabled { get => Segment.ScanEnabled; set { Segment.ScanEnabled = value; OnPropertyChanged(); } }
}

public sealed record DhcpRow(DhcpServerInfo Info, string Name)
{
    public string Server => $"{Info.ServerIp}";
    public string Mac => Info.ServerMac.ToString();
    public string Offer => Info.OfferedIp?.ToString() ?? "—";
    public string Router => Info.Router?.ToString() ?? "—";
    public string Dns => string.Join(", ", Info.Dns);
    public string Lease => Info.Lease is { } l ? (l.TotalHours >= 1 ? $"{l.TotalHours:0} h" : $"{l.TotalMinutes:0} min") : "—";
    public bool IsRogue => Info.IsRogue;
    public string Status => Info.IsRogue ? "ROGUE" : "authorized";
    public IBrush Brush => Info.IsRogue ? Ui.Red : Ui.Green;
    public IBrush Background => Info.IsRogue ? new SolidColorBrush(Color.Parse("#26FF3D5A")) : Brushes.Transparent;
}

public sealed record StpRow(StpInfo Info, string Name, bool IsRoot)
{
    public string Bridge => Info.BridgeId;
    public string Root => Info.RootBridgeId;
    public string Protocol => Info.Protocol;
    public string Cost => Info.RootPathCost.ToString();
    public string Priority => Info.RootPriority.ToString();
    public string RootText => IsRoot ? "ROOT" : "";
}

public sealed record HopRow(TracerouteHop Hop, IBrush Brush, double Bar)
{
    public int Ttl => Hop.Ttl;
    public string Address => Hop.Address?.ToString() ?? "*";
    public string Host => Hop.Hostname ?? "";
    public string Rtt => Neon.FormatMs(Hop.RttMs);
}

public sealed partial class SegmentsViewModel : ObservableObject
{
    private readonly INetworkState _network;
    private readonly IDeviceStore _devices;
    private readonly AppSettings _settings;
    private Throttler? _throttle;

    public SegmentsViewModel(INetworkState network, IDeviceStore devices, AppSettings settings)
    {
        _network = network;
        _devices = devices;
        _settings = settings;
        network.Changed += w => { if (w is not ("health" or "wifi")) _throttle?.Signal(); };
        Dispatcher.UIThread.Post(() => { _throttle = new Throttler(TimeSpan.FromMilliseconds(600), Reload); Reload(); });
    }

    public ObservableCollection<SegmentRow> Subnets { get; } = [];
    public ObservableCollection<VlanInfo> Vlans { get; } = [];
    public ObservableCollection<DhcpRow> DhcpServers { get; } = [];
    public ObservableCollection<StpRow> Stp { get; } = [];
    public ObservableCollection<PortMapping> PortMappings { get; } = [];
    public ObservableCollection<HopRow> InternetPath { get; } = [];

    [ObservableProperty] private string _igmpQuerier = "—";
    [ObservableProperty] private IBrush _igmpBrush = Ui.Dim;
    [ObservableProperty] private string _stpRoot = "—";
    [ObservableProperty] private string _tagHint = "";
    [ObservableProperty] private IBrush _tagBrush = Ui.Dim;
    [ObservableProperty] private string _tagTitle = "";
    [ObservableProperty] private bool _hasWan;
    [ObservableProperty] private string _wanIp = "—";
    [ObservableProperty] private string _wanStatus = "";
    [ObservableProperty] private IBrush _wanStatusBrush = Ui.Dim;
    [ObservableProperty] private string _wanUptime = "";
    [ObservableProperty] private string _wanMethod = "";
    [ObservableProperty] private string _wanModel = "";
    [ObservableProperty] private bool _hasRogueDhcp;

    private string Name(Mac m) => _devices.TryGet(m, out var d) ? d.DisplayName : m.ToString();

    public void Reload()
    {
        Subnets.Clear();
        foreach (var s in _network.Segments.OrderByDescending(s => s.IsLocal).ThenBy(s => s.VlanId ?? 0)) Subnets.Add(new SegmentRow(s));
        Vlans.Clear();
        foreach (var v in _network.Vlans) Vlans.Add(v);
        DhcpServers.Clear();
        foreach (var d in _network.DhcpServers.OrderBy(d => d.IsRogue)) DhcpServers.Add(new DhcpRow(d, Name(d.ServerMac)));
        HasRogueDhcp = DhcpServers.Any(d => d.IsRogue);
        Stp.Clear();
        var bridges = _network.StpBridges;
        var roots = bridges.Select(b => b.RootMac).Distinct().ToList();
        foreach (var b in bridges) Stp.Add(new StpRow(b, Name(b.SenderMac), b.SenderMac == b.RootMac));
        StpRoot = roots.Count switch
        {
            0 => "No BPDUs seen (STP disabled or not visible on this port)",
            1 => $"{Name(roots[0])} ({bridges[0].RootBridgeId})",
            _ => $"⚠ {roots.Count} different roots: " + string.Join(", ", roots.Select(Name)),
        };
        if (_network.IgmpQuerier is { } q) { IgmpQuerier = Name(q); IgmpBrush = Ui.Green; }
        else { IgmpQuerier = "No IGMP querier detected — multicast (Sonos, Chromecast, IPTV) may be flooded or time out"; IgmpBrush = Ui.Amber; }

        switch (_network.NicPassesVlanTags)
        {
            case true:
                TagTitle = "Your NIC passes 802.1Q tags";
                TagHint = "Tagged frames are visible, so VLANs on a trunk/mirror port are discovered directly.";
                TagBrush = Ui.Green;
                break;
            case false:
                TagTitle = "Your NIC strips 802.1Q tags";
                TagHint = "Windows drivers usually remove VLAN tags. VLANs are still learned from LLDP/CDP/SNMP. To see tags directly: Device Manager → adapter → Advanced → set \"Priority & VLAN\" to \"Priority & VLAN Enabled\"; on Intel NICs add HKLM\\…\\Class\\{4d36e972…}\\<n>\\MonitorModeEnabled = 1; on Realtek disable \"VLAN tagging offload\". Then connect to a trunk or SPAN port.";
                TagBrush = Ui.Amber;
                break;
            default:
                TagTitle = "VLAN tag passthrough unknown";
                TagHint = "Start monitoring on a trunk or mirror port to find out whether your NIC delivers 802.1Q tags.";
                TagBrush = Ui.Dim;
                break;
        }

        var wan = _network.Wan;
        HasWan = wan is not null;
        PortMappings.Clear();
        if (wan is not null)
        {
            WanIp = wan.ExternalIp?.ToString() ?? "unknown";
            WanStatus = wan.ConnectionStatus ?? "unknown";
            WanStatusBrush = string.Equals(wan.ConnectionStatus, "Connected", StringComparison.OrdinalIgnoreCase) ? Ui.Green : Ui.Amber;
            WanUptime = wan.Uptime is { } u ? $"{(int)u.TotalDays}d {u.Hours}h {u.Minutes}m" : "—";
            WanMethod = wan.Method + (wan.ConnectionType is { } ct ? $" · {ct}" : "");
            WanModel = wan.GatewayModel ?? "";
            foreach (var m in wan.PortMappings) PortMappings.Add(m);
        }

        InternetPath.Clear();
        var path = _network.InternetPath;
        double maxRtt = Math.Max(1, path.Select(h => h.RttMs ?? 0).DefaultIfEmpty(0).Max());
        foreach (var h in path) InternetPath.Add(new HopRow(h, Ui.LatencyBrush(h.RttMs, _settings), 140 * (h.RttMs ?? 0) / maxRtt));
    }
}

// =========================================================================================================
//  Health
// =========================================================================================================

public sealed record CheckRow(HealthCheckResult Check, string? DeviceName)
{
    public string Name => Check.Name;
    public string Summary => Check.Summary;
    public string? Details => Check.Details;
    public bool HasDetails => !string.IsNullOrWhiteSpace(Check.Details);
    public string Status => Check.Status.ToString().ToUpperInvariant();
    public string Score => Check.Status == HealthStatus.Skipped ? "—" : Check.Score.ToString();
    public IBrush Brush => Check.Status switch { HealthStatus.Pass => Ui.Green, HealthStatus.Warn => Ui.Amber, HealthStatus.Fail => Ui.Red, _ => Ui.Grey };
    public IBrush Soft => new SolidColorBrush(((ISolidColorBrush)Brush).Color, 0.12);
    public Geometry Icon => Lookup(Check.Status switch { HealthStatus.Pass => "IconCheck", HealthStatus.Warn => "IconWarn", HealthStatus.Fail => "IconCritical", _ => "IconInfo" });
    public bool HasDevice => DeviceName is not null;

    private static Geometry Lookup(string key) =>
        Avalonia.Application.Current?.TryGetResource(key, null, out var g) == true && g is Geometry geo ? geo : new StreamGeometry();
}

public sealed partial class HealthViewModel : ObservableObject
{
    private readonly INetworkState _network;
    private readonly IDeviceStore _devices;
    private readonly IHealthService? _health;
    private readonly IScanOrchestrator? _orchestrator;

    public HealthViewModel(IServiceProvider sp, INetworkState network, IDeviceStore devices)
    {
        _network = network;
        _devices = devices;
        _health = sp.GetService<IHealthService>();
        _orchestrator = sp.GetService<IScanOrchestrator>();
        network.Changed += w => { if (w == "health") Dispatcher.UIThread.Post(Reload); };
        Dispatcher.UIThread.Post(Reload);
    }

    public ObservableCollection<CheckRow> Checks { get; } = [];
    [ObservableProperty] private double _score;
    [ObservableProperty] private string _grade = "";
    [ObservableProperty] private string _lastRun = "never";
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCommand), nameof(RunBufferbloatCommand))] private bool _isRunning;
    [ObservableProperty] private string _status = "";
    public bool HasReport => Checks.Count > 0;
    public string RunTooltip => _health is null ? "Health suite not available in this build" : _orchestrator?.Context is null ? "Start monitoring first (needs an adapter context)" : "Run MTU, DNS, cleartext, certificate, IGMP and DHCP checks";

    public void Reload()
    {
        var r = _network.Health;
        Checks.Clear();
        foreach (var c in r.Checks.OrderBy(c => c.Status switch { HealthStatus.Fail => 0, HealthStatus.Warn => 1, HealthStatus.Pass => 2, _ => 3 }))
            Checks.Add(new CheckRow(c, c.Device is { } m && _devices.TryGet(m, out var d) ? d.DisplayName : null));
        Score = r.Checks.Count == 0 ? 0 : r.OverallScore;
        Grade = r.Checks.Count == 0 ? "" : r.OverallScore >= 90 ? "Excellent" : r.OverallScore >= 75 ? "Good" : r.OverallScore >= 50 ? "Needs attention" : "Poor";
        LastRun = r.Time == DateTimeOffset.MinValue ? "never" : r.Time.ToString("yyyy-MM-dd HH:mm");
        Summary = r.Checks.Count == 0 ? "No health report yet"
            : $"{r.Checks.Count(c => c.Status == HealthStatus.Pass)} passed · {r.Checks.Count(c => c.Status == HealthStatus.Warn)} warnings · {r.Checks.Count(c => c.Status == HealthStatus.Fail)} failed";
        OnPropertyChanged(nameof(HasReport));
        OnPropertyChanged(nameof(RunTooltip));
    }

    public void RefreshCommands()
    {
        RunCommand.NotifyCanExecuteChanged();
        RunBufferbloatCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(RunTooltip));
    }

    private bool CanRun() => _health is not null && _orchestrator?.Context is not null && !IsRunning && !_network.IsDemo;

    [RelayCommand(CanExecute = nameof(CanRun))] private Task Run() => RunCore(false);
    [RelayCommand(CanExecute = nameof(CanRun))] private Task RunBufferbloat() => RunCore(true);

    private async Task RunCore(bool bufferbloat)
    {
        if (_health is null || _orchestrator?.Context is not { } ctx) return;
        IsRunning = true;
        Status = bufferbloat ? "Running bufferbloat test (loads your connection for ~20 s)…" : "Running health checks…";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var report = await Task.Run(() => _health.RunAsync(ctx, bufferbloat, cts.Token));
            if (_network.IsDemo) { Status = "Discarded: the demo network was switched on during the check"; return; }
            _network.Health = report;
            Reload();
            Status = "Done";
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Health check failed");
            Status = "Health check failed: " + ex.Message;
        }
        finally { IsRunning = false; }
    }
}
