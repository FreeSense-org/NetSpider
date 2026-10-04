using System.Collections.ObjectModel;
using System.Net;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed record KeyValueRow(string Key, string Value, IBrush? Brush = null)
{
    public IBrush ValueBrush => Brush ?? Ui.Text;
}

public sealed record ChipItem(string Text, IBrush Foreground)
{
    public IBrush Background => new SolidColorBrush(((ISolidColorBrush)Foreground).Color, 0.14);
    public IBrush BorderBrush => new SolidColorBrush(((ISolidColorBrush)Foreground).Color, 0.5);
}

public sealed record PortRow(int Port, string Protocol, string State, string Service, string? Banner, IBrush StateBrush);

public sealed record EvidenceRow(string Source, string Field, string Value, double Confidence, DateTimeOffset Time)
{
    public string ConfidenceText => $"{Confidence:P0}";
    public double ConfidenceWidth => 50 * Math.Clamp(Confidence, 0, 1);
    public IBrush ConfidenceBrush => Confidence >= 0.85 ? Ui.Green : Confidence >= 0.6 ? Ui.Amber : Ui.Dim;
}

public sealed record CertRow(int Port, string Subject, string Issuer, string Validity, string Sans, IBrush StateBrush, string State);

public sealed record TargetOption(Device Device)
{
    public override string ToString() => $"{Device.DisplayName}  ({Device.PrimaryIPv4?.ToString() ?? Device.Mac.ToString()})";
}

/// <summary>Shared brushes for view models.</summary>
public static class Ui
{
    public static readonly IBrush Text = new SolidColorBrush(Color.Parse("#E8F1FF"));
    public static readonly IBrush Dim = new SolidColorBrush(Color.Parse("#8A9BB8"));
    public static readonly IBrush Faint = new SolidColorBrush(Color.Parse("#56657F"));
    public static readonly IBrush Cyan = new SolidColorBrush(Color.Parse("#00E5FF"));
    public static readonly IBrush Magenta = new SolidColorBrush(Color.Parse("#FF2BD6"));
    public static readonly IBrush Green = new SolidColorBrush(Color.Parse("#3DFF8B"));
    public static readonly IBrush Amber = new SolidColorBrush(Color.Parse("#FFC23D"));
    public static readonly IBrush Red = new SolidColorBrush(Color.Parse("#FF3D5A"));
    public static readonly IBrush Violet = new SolidColorBrush(Color.Parse("#9B7BFF"));
    public static readonly IBrush Grey = new SolidColorBrush(Color.Parse("#5A6478"));

    public static Color ToColor(SkiaSharp.SKColor c) => Color.FromArgb(c.Alpha, c.Red, c.Green, c.Blue);
    public static IBrush LatencyBrush(double? ms, AppSettings s) => new SolidColorBrush(ToColor(Neon.Latency(ms, s)));
}

/// <summary>Everything about the selected device, plus the per-device actions.</summary>
public sealed partial class InspectorViewModel : ObservableObject
{
    private readonly IDeviceStore _store;
    private readonly ITopologyStore _topology;
    private readonly AppSettings _settings;
    private readonly IDeviceRepository? _repo;
    private readonly ILatencyEngine? _latency;
    private readonly IWakeOnLan? _wol;
    private readonly IScanOrchestrator? _orchestrator;
    private readonly ITracerouter? _tracer;
    private readonly ILatencyProber? _prober;
    private Throttler? _throttle;
    private DispatcherTimer? _tick;

    private readonly INetworkState _network;

    public InspectorViewModel(IServiceProvider sp, SelectionService selection, IDeviceStore store, ITopologyStore topology, INetworkState network, AppSettings settings)
    {
        _network = network;
        Selection = selection;
        _store = store;
        _topology = topology;
        _settings = settings;
        _repo = sp.GetService<IDeviceRepository>();
        _latency = sp.GetService<ILatencyEngine>();
        _wol = sp.GetService<IWakeOnLan>();
        _orchestrator = sp.GetService<IScanOrchestrator>();
        _tracer = sp.GetService<ITracerouter>();
        _prober = sp.GetService<ILatencyProber>();
        selection.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(SelectionService.Selected)) Device = selection.Selected; };
        store.DeviceChanged += (d, _) => { if (d == Device) _throttle?.Signal(); };
    }

    public SelectionService Selection { get; }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasDevice))] private Device? _device;
    public bool HasDevice => Device is not null;

    partial void OnDeviceChanged(Device? value)
    {
        _throttle ??= new Throttler(TimeSpan.FromMilliseconds(500), Refresh);
        _tick ??= new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) => { if (Device is not null) _throttle.Signal(); });
        _tick.Start();
        PairResult = null;
        EditName = value?.UserLabel ?? value?.DisplayName ?? "";
        Refresh();
        RefreshTargets();
        foreach (var c in new IRelayCommand[] { OpenWebUiCommand, SshCommand, RdpCommand, WakeOnLanCommand, MtrCommand, ReprobeCommand, CopyIpCommand, CopyMacCommand, MeasureCommand, RenameCommand })
            c.NotifyCanExecuteChanged();
    }

    // ---- header ----
    [ObservableProperty] private string _displayName = "";
    [ObservableProperty] private string _editName = "";
    [ObservableProperty] private string _brandModel = "";
    [ObservableProperty] private string _typeText = "";
    [ObservableProperty] private DeviceType _deviceType;
    [ObservableProperty] private string? _logoPath;
    [ObservableProperty] private Color _ringColor;
    [ObservableProperty] private double _confidence;
    [ObservableProperty] private string _confidenceText = "";
    [ObservableProperty] private string _stateText = "";
    [ObservableProperty] private IBrush _stateBrush = Ui.Green;
    [ObservableProperty] private string _seenText = "";

    // ---- sections ----
    public ObservableCollection<KeyValueRow> Addresses { get; } = [];
    public ObservableCollection<KeyValueRow> LatencyRows { get; } = [];
    [ObservableProperty] private IReadOnlyList<double?> _l2Series = [];
    [ObservableProperty] private IReadOnlyList<double?> _l3Series = [];
    public ObservableCollection<PortRow> Ports { get; } = [];
    public ObservableCollection<KeyValueRow> Services { get; } = [];
    public ObservableCollection<CertRow> Certificates { get; } = [];
    public ObservableCollection<EvidenceRow> Evidence { get; } = [];
    public ObservableCollection<KeyValueRow> Network { get; } = [];
    public ObservableCollection<KeyValueRow> Properties { get; } = [];
    public ObservableCollection<ChipItem> Flags { get; } = [];
    [ObservableProperty] private bool _hasPorts;
    [ObservableProperty] private bool _hasServices;
    [ObservableProperty] private bool _hasCerts;
    [ObservableProperty] private bool _hasProperties;
    [ObservableProperty] private bool _hasFlags;

    // ---- latency to ----
    public ObservableCollection<TargetOption> Targets { get; } = [];
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(MeasureCommand))] private TargetOption? _selectedTarget;
    [ObservableProperty] private string? _pairResult;
    [ObservableProperty] private string? _pairDetail;
    [ObservableProperty] private IBrush _pairBrush = Ui.Text;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(MeasureCommand))] private bool _isMeasuring;

    partial void OnSelectedTargetChanged(TargetOption? value) => ShowKnownPair();

    public string MeasureTooltip => _latency is null ? "Latency engine not available — showing the topology estimate" : "Ask the network for device↔device latency (SNMP ping / passive TCP / path estimate)";
    public string WolTooltip => _wol is null ? "Wake-on-LAN service not available" : "Send a magic packet (raw 0x0842 + UDP 7/9)";
    public string MtrTooltip => _tracer is null || _prober is null ? "Traceroute / ICMP prober not available" : "Live traceroute with per-hop loss and latency";
    public string ReprobeTooltip => _orchestrator is null ? "Scan engine not available" : "Re-run every deep probe for this device only";
    public string RenameTooltip => _repo is null ? "Sets the label for this session (persistence not available)" : "Rename (saved to the device history)";

    public void RefreshTargets()
    {
        var keep = SelectedTarget?.Device.Mac;
        Targets.Clear();
        if (Device is null) return;
        foreach (var d in _store.All.Where(x => x != Device && !SyntheticNodes.IsSynthetic(x.Mac) || x.Type == DeviceType.Internet && x != Device)
                     .OrderBy(x => x.Has(DeviceFlags.Gateway) ? 0 : 1).ThenBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase))
            Targets.Add(new TargetOption(d));
        SelectedTarget = Targets.FirstOrDefault(t => t.Device.Mac == keep) ?? Targets.FirstOrDefault(t => t.Device.Has(DeviceFlags.Gateway)) ?? Targets.FirstOrDefault();
    }

    private void ShowKnownPair()
    {
        if (Device is null || SelectedTarget is null) { PairResult = null; return; }
        var p = _topology.GetPairLatency(Device.Mac, SelectedTarget.Device.Mac);
        if (p is not null) ShowPair(p, "from topology");
        else { PairResult = "—"; PairDetail = "No measurement yet"; PairBrush = Ui.Dim; }
    }

    private void ShowPair(PairLatency p, string? note = null)
    {
        PairResult = Neon.FormatMs(p.Ms);
        PairDetail = $"{(p.Origin == LatencyOrigin.Measured ? "measured" : "estimated")} · {p.Method} · {p.Time:HH:mm:ss}{(note is null ? "" : " · " + note)}";
        PairBrush = Ui.LatencyBrush(p.Ms, _settings);
    }

    private void Refresh()
    {
        var d = Device;
        if (d is null) return;
        DisplayName = d.DisplayName;
        var bm = string.Join(" ", new[] { d.Brand, d.Model }.Where(s => !string.IsNullOrWhiteSpace(s)));
        BrandModel = bm.Length > 0 ? bm : d.OuiVendor ?? "Unknown vendor";
        DeviceType = d.Type;
        TypeText = d.Type + (d.OsGuess is { } os ? $" · {os}" : "") + (d.Firmware is { } fw ? $" · fw {fw}" : "");
        LogoPath = d.LogoPath;
        Confidence = Math.Clamp(Math.Max(d.IdentityConfidence, d.TypeConfidence) * 100, 0, 100);
        ConfidenceText = $"{Confidence:0}% confident";
        var best = d.Latency.BestLast;
        RingColor = d.State == DeviceState.Offline ? Ui.ToColor(Neon.Grey) : Ui.ToColor(Neon.Latency(best, _settings));
        StateText = d.State switch { DeviceState.Offline => "Offline", DeviceState.Flapping => "Flapping", _ => "Online" };
        StateBrush = d.State switch { DeviceState.Offline => Ui.Grey, DeviceState.Flapping => Ui.Amber, _ => Ui.Green };
        SeenText = $"first seen {d.FirstSeen:yyyy-MM-dd HH:mm} · last seen {Ago(d.LastSeen)}";

        // addresses
        var addr = new List<KeyValueRow>();
        foreach (var ip in d.IPv4.OrderBy(i => i.ToString())) addr.Add(new("IPv4", ip.ToString(), Ui.Cyan));
        foreach (var v6 in d.IPv6)
            addr.Add(new("IPv6", $"{v6.Address}  ({KindText(v6.Kind)}, {IdText(v6.InterfaceId)})", Ui.Text));
        bool synthetic = SyntheticNodes.IsSynthetic(d.Mac);
        if (!synthetic)
        {
            addr.Add(new("MAC", d.Mac.ToString(), Ui.Text));
            addr.Add(new("OUI vendor", d.Mac.IsRandomized ? "Private / randomized MAC (locally administered)" : d.OuiVendor ?? "unknown", d.Mac.IsRandomized ? Ui.Magenta : Ui.Text));
        }
        else addr.Add(new("Node", d.Type == DeviceType.Internet ? "Synthetic Internet node" : "Synthetic (inferred) node", Ui.Dim));
        foreach (var (src, h) in d.Hostnames) addr.Add(new($"Name ({src})", h, Ui.Text));
        Replace(Addresses, addr);

        // latency
        var arp = d.Latency.GetSeries(LatencyKind.Arp, 90);
        var ndp = arp.Length == 0 ? d.Latency.GetSeries(LatencyKind.Ndp, 90) : [];
        var icmp = d.Latency.GetSeries(LatencyKind.Icmp, 90);
        L2Series = (arp.Length > 0 ? arp : ndp).Select(s => s.Ms).ToArray();
        L3Series = icmp.Select(s => s.Ms).ToArray();
        var rows = new List<KeyValueRow>();
        void Sum(string name, LatencyKind k)
        {
            var s = d.Latency.Summarize(k, 60);
            if (s.Count == 0) return;
            rows.Add(new(name, $"last {Neon.FormatMs(s.Last)} · min {Neon.FormatMs(s.Min)} · avg {Neon.FormatMs(s.Avg)} · max {Neon.FormatMs(s.Max)}", Ui.LatencyBrush(s.Avg, _settings)));
            rows.Add(new("", $"jitter {Neon.FormatMs(s.Jitter)} · loss {s.LossPercent:0.#}% · {s.Count} samples", s.LossPercent > 0 ? Ui.Amber : Ui.Dim));
        }
        Sum("L2 ARP", LatencyKind.Arp);
        Sum("L2 NDP", LatencyKind.Ndp);
        Sum("L3 ICMP", LatencyKind.Icmp);
        Sum("L4 TCP", LatencyKind.Tcp);
        if (rows.Count == 0) rows.Add(new("", "No latency samples yet", Ui.Dim));
        Replace(LatencyRows, rows);

        // ports + services
        Replace(Ports, d.Ports.Select(p => new PortRow(p.Port, p.Protocol, p.State.ToString().ToLowerInvariant(), p.ServiceName ?? "", p.Banner,
            p.State switch { PortState.Open => Ui.Green, PortState.Filtered => Ui.Amber, _ => Ui.Grey })).ToList());
        HasPorts = Ports.Count > 0;
        Replace(Services, d.Services.OrderBy(s => s.Name).Select(s => new KeyValueRow(s.Type ?? $"{s.Protocol}/{s.Port}",
            s.Name + (s.Txt is { Count: > 0 } t ? "  " + string.Join(" ", t.Take(4).Select(kv => $"{kv.Key}={kv.Value}")) : ""), Ui.Text)).ToList());
        HasServices = Services.Count > 0;
        Replace(Certificates, d.Certificates.Select(c => new CertRow(c.Port, c.CommonName ?? c.Subject, c.IssuerOrganization ?? c.Issuer,
            $"{c.NotBefore:yyyy-MM-dd} → {c.NotAfter:yyyy-MM-dd}", string.Join(", ", c.SubjectAltNames.Take(6)),
            c.Expired ? Ui.Red : c.SelfSigned ? Ui.Amber : Ui.Green, c.Expired ? "expired" : c.SelfSigned ? "self-signed" : "valid")).ToList());
        HasCerts = Certificates.Count > 0;
        Replace(Evidence, d.Evidence.OrderByDescending(e => e.Confidence).ThenBy(e => e.Source)
            .Select(e => new EvidenceRow(e.Source, e.Field, e.Value, e.Confidence, e.Timestamp)).ToList());

        // network
        var net = new List<KeyValueRow>();
        var vl = d.Vlans;
        if (vl.Length > 0 || d.NativeVlan is not null)
            net.Add(new("VLANs", string.Join(", ", vl.Select(v => v == d.NativeVlan ? $"{v} (native)" : v.ToString())) + (vl.Length == 0 ? $"{d.NativeVlan} (native)" : ""), Ui.Text));
        var groups = d.MulticastGroups;
        if (groups.Length > 0) net.Add(new("Multicast", string.Join(", ", groups.Select(g => g.ToString())), Ui.Magenta));
        if (d.UpstreamMac is { } up)
        {
            var upName = _store.TryGet(up, out var ud) ? ud.DisplayName : up.ToString();
            net.Add(new("Upstream", upName + (d.UpstreamPort is { } port ? $"  port {port}" : ""), Ui.Cyan));
        }
        foreach (var l in _topology.LinksOf(d.Mac).Take(8))
        {
            var other = l.Other(d.Mac);
            var on = _store.TryGet(other, out var od) ? od.DisplayName : other.ToString();
            net.Add(new("Link", $"{on} · {Controls.Graph.GraphRenderer.KindText(l.Kind)}{(l.SpeedMbps is { } sp ? $" · {Neon.FormatSpeed(sp)}" : "")}{(l.LatencyMs is { } lm ? $" · {Neon.FormatMs(lm)}" : "")}", Ui.Text));
        }
        if (d.Wifi is { } w) net.Add(new("Wi-Fi", $"{w.Ssid} · ch {w.Channel} ({w.Band}) · {w.RssiDbm} dBm · {w.Phy} · BSSID {w.Bssid}", Ui.Cyan));
        if (d.Ttl is { } ttl) net.Add(new("TTL", ttl.ToString(), Ui.Text));
        Replace(Network, net);
        Replace(Properties, d.Properties.OrderBy(kv => kv.Key).Select(kv => new KeyValueRow(kv.Key, kv.Value, Ui.Text)).ToList());
        HasProperties = Properties.Count > 0;

        var flags = new List<ChipItem>();
        void Flag(DeviceFlags f, string text, IBrush b) { if (d.Has(f)) flags.Add(new ChipItem(text, b)); }
        Flag(DeviceFlags.Gateway, "Gateway", Ui.Cyan);
        Flag(DeviceFlags.ThisHost, "This PC", Ui.Cyan);
        Flag(DeviceFlags.Infrastructure, "Infrastructure", Ui.Cyan);
        Flag(DeviceFlags.New, "New", Ui.Green);
        Flag(DeviceFlags.RandomizedMac, "Private MAC", Ui.Magenta);
        Flag(DeviceFlags.Virtual, "Virtual", Ui.Violet);
        Flag(DeviceFlags.Inferred, "Inferred", Ui.Dim);
        Flag(DeviceFlags.DhcpServer, "DHCP server", Ui.Violet);
        Flag(DeviceFlags.StpRoot, "STP root", Ui.Violet);
        Flag(DeviceFlags.IgmpQuerier, "IGMP querier", Ui.Violet);
        Flag(DeviceFlags.WifiClient, "Wi-Fi client", Ui.Cyan);
        Flag(DeviceFlags.PoePowered, "PoE powered", Ui.Amber);
        Flag(DeviceFlags.WakeOnLanCapable, "WoL", Ui.Green);
        Flag(DeviceFlags.MulticastSource, "Multicast source", Ui.Magenta);
        Flag(DeviceFlags.OffSubnet, "Off-subnet", Ui.Dim);
        Flag(DeviceFlags.RogueDhcp, "Rogue DHCP", Ui.Red);
        Flag(DeviceFlags.RogueRouterAdvert, "Rogue RA", Ui.Red);
        Flag(DeviceFlags.IpConflict, "IP conflict", Ui.Red);
        Flag(DeviceFlags.StormSource, "Storm source", Ui.Red);
        Flag(DeviceFlags.CleartextManagement, "Cleartext mgmt", Ui.Amber);
        Flag(DeviceFlags.ExpiredCertificate, "Expired cert", Ui.Amber);
        Flag(DeviceFlags.SelfSignedCertificate, "Self-signed cert", Ui.Amber);
        Flag(DeviceFlags.SmbV1, "SMBv1", Ui.Amber);
        Flag(DeviceFlags.DefaultSnmpCommunity, "Default SNMP", Ui.Amber);
        Replace(Flags, flags);
        HasFlags = flags.Count > 0;
    }

    private static void Replace<T>(ObservableCollection<T> target, IList<T> items)
    {
        // cheap in-place update to avoid flicker/scroll resets
        int i = 0;
        for (; i < items.Count; i++)
        {
            if (i < target.Count) { if (!Equals(target[i], items[i])) target[i] = items[i]; }
            else target.Add(items[i]);
        }
        while (target.Count > items.Count) target.RemoveAt(target.Count - 1);
    }

    private static string KindText(Ipv6Kind k) => k switch
    {
        Ipv6Kind.LinkLocal => "link-local", Ipv6Kind.GlobalUnicast => "global", Ipv6Kind.UniqueLocal => "ULA", _ => k.ToString().ToLowerInvariant(),
    };

    private static string IdText(Ipv6InterfaceIdKind k) => k switch
    {
        Ipv6InterfaceIdKind.Eui64 => "EUI-64", Ipv6InterfaceIdKind.StablePrivacy => "stable privacy", Ipv6InterfaceIdKind.Temporary => "temporary", _ => "unknown id",
    };

    public static string Ago(DateTimeOffset t)
    {
        var d = DateTimeOffset.Now - t;
        if (d.TotalSeconds < 60) return $"{Math.Max(0, d.TotalSeconds):0}s ago";
        if (d.TotalMinutes < 60) return $"{d.TotalMinutes:0}m ago";
        if (d.TotalHours < 48) return $"{d.TotalHours:0}h ago";
        return $"{d.TotalDays:0}d ago";
    }

    // =====================================================================================================
    //  actions
    // =====================================================================================================

    private IPAddress? Ip => Device?.PrimaryIPv4 ?? Device?.IPv6.FirstOrDefault(v => v.Kind != Ipv6Kind.LinkLocal)?.Address;

    private (string Scheme, int Port)? WebPort()
    {
        var open = Device?.Ports.Where(p => p.State == PortState.Open && p.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)).Select(p => p.Port).ToHashSet();
        if (open is null || open.Count == 0) return null;
        foreach (var p in new[] { 443, 8443, 5001, 8006, 9443, 4443, 10443 }) if (open.Contains(p)) return ("https", p);
        foreach (var p in new[] { 80, 8080, 5000, 8000, 8081, 8888, 81, 1400, 8008 }) if (open.Contains(p)) return ("http", p);
        return null;
    }

    public string WebTooltip => WebPort() is { } w ? $"Open {w.Scheme}://{Ip}:{w.Port}" : "No HTTP(S) port found on this device";

    private bool HasWeb() => Ip is not null && WebPort() is not null;
    private bool HasIp() => Ip is not null;

    [RelayCommand(CanExecute = nameof(HasWeb))]
    private void OpenWebUi()
    {
        if (WebPort() is not { } w || Ip is not { } ip) return;
        var host = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]" : ip.ToString();
        bool std = (w.Scheme == "https" && w.Port == 443) || (w.Scheme == "http" && w.Port == 80);
        Launcher.Open(std ? $"{w.Scheme}://{host}/" : $"{w.Scheme}://{host}:{w.Port}/");
    }

    [RelayCommand(CanExecute = nameof(HasIp))] private void Ssh() { if (Ip is { } ip) Launcher.Ssh(ip.ToString()); }
    [RelayCommand(CanExecute = nameof(HasIp))] private void Rdp() { if (Ip is { } ip) Launcher.Rdp(ip.ToString()); }
    [RelayCommand(CanExecute = nameof(HasIp))] private Task CopyIp() => Dialogs.CopyAsync(Ip?.ToString());
    [RelayCommand(CanExecute = nameof(HasDevice))] private Task CopyMac() => Dialogs.CopyAsync(Device?.Mac.ToString());

    private bool CanWol() => _wol is not null && Device is not null && !SyntheticNodes.IsSynthetic(Device.Mac);

    [RelayCommand(CanExecute = nameof(CanWol))]
    private async Task WakeOnLan()
    {
        if (_wol is null || Device is null) return;
        try { await _wol.SendAsync(Device.Mac); PairDetail = $"Magic packet sent to {Device.Mac}"; }
        catch (Exception ex) { Log.Warning(ex, "WoL failed"); PairDetail = "Wake-on-LAN failed: " + ex.Message; }
    }

    private bool CanMtr() => _tracer is not null && _prober is not null && Ip is not null;

    [RelayCommand(CanExecute = nameof(CanMtr))]
    private void Mtr()
    {
        if (_tracer is null || _prober is null || Ip is not { } ip || Device is null) return;
        MtrViewModel.Open(ip, Device.DisplayName, _tracer, _prober);
    }

    // demo devices are simulated: never probe their addresses on the real network
    private bool CanReprobe() => _orchestrator is not null && Device is not null && !_network.IsDemo;

    [RelayCommand(CanExecute = nameof(CanReprobe))]
    private async Task Reprobe()
    {
        if (_orchestrator is null || Device is null) return;
        var d = Device;
        try
        {
            PairDetail = $"Deep re-probe of {d.DisplayName} running…";
            await Task.Run(() => _orchestrator.ReprobeDeviceAsync(d));
            PairDetail = $"Deep re-probe of {d.DisplayName} finished";
        }
        catch (Exception ex) { Log.Warning(ex, "Re-probe failed"); PairDetail = "Re-probe failed: " + ex.Message; }
    }

    private bool CanMeasure() => Device is not null && SelectedTarget is not null && !IsMeasuring;

    [RelayCommand(CanExecute = nameof(CanMeasure))]
    private async Task Measure()
    {
        if (Device is null || SelectedTarget is null) return;
        var from = Device.Mac;
        var to = SelectedTarget.Device.Mac;
        IsMeasuring = true;
        PairResult = "…";
        PairDetail = "measuring";
        try
        {
            PairLatency? p = null;
            if (_latency is not null && !_network.IsDemo)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                p = await Task.Run(() => _latency.MeasurePairAsync(from, to, cts.Token));
            }
            p ??= _topology.GetPairLatency(from, to);
            if (p is null)
            {
                // estimate from the host's view: path through the topology tree
                var snap = Controls.Graph.GraphBuilder.Build(_store, _topology, _network, _settings, 0);
                if (snap.Index.TryGetValue(from, out var a) && snap.Index.TryGetValue(to, out var b) && snap.GetPair(a, b) is { } pi)
                    p = new PairLatency(from, to, pi.Ms, pi.Origin, pi.Method, DateTimeOffset.Now);
            }
            if (p is not null) ShowPair(p, _latency is null ? "engine unavailable" : null);
            else { PairResult = "n/a"; PairDetail = "No path or samples to estimate from"; PairBrush = Ui.Dim; }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Pair latency measurement failed");
            PairResult = "error";
            PairDetail = ex.Message;
            PairBrush = Ui.Red;
        }
        finally { IsMeasuring = false; }
    }

    [RelayCommand(CanExecute = nameof(HasDevice))]
    private async Task Rename()
    {
        if (Device is null) return;
        var label = string.IsNullOrWhiteSpace(EditName) || EditName == Device.Hostname ? null : EditName.Trim();
        Device.UserLabel = label;
        _store.NotifyChanged(Device, "user-label");
        DisplayName = Device.DisplayName;
        if (_repo is not null && !_network.IsDemo) // demo labels live only as long as the demo
        {
            try { await _repo.SetUserLabelAsync(Device.Mac, label); }
            catch (Exception ex) { Log.Warning(ex, "Saving user label failed"); }
        }
    }
}
