using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Controls;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Model;

namespace NetSpider.App.ViewModels;

/// <summary>Small formatting/color helpers shared by the diagnostics pages.</summary>
public static class Diag
{
    public static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static IBrush HealthBrush(HopHealth h) => h switch
    {
        HopHealth.Up => Ui.Green,
        HopHealth.Degraded => Ui.Amber,
        HopHealth.Down => Ui.Red,
        _ => Ui.Grey,
    };

    public static string HealthText(HopHealth h) => h switch
    {
        HopHealth.Up => "Up",
        HopHealth.Degraded => "Degraded",
        HopHealth.Down => "Down",
        _ => "Unknown",
    };

    /// <summary>"Wi-Fi", "WiFi", "Wireless", "WLAN" — but not "Wired".</summary>
    public static bool IsWifiMedium(string? m) => m is not null && (m.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) || m.Contains("WiFi", StringComparison.OrdinalIgnoreCase) || m.Contains("Wireless", StringComparison.OrdinalIgnoreCase) || m.Contains("WLAN", StringComparison.OrdinalIgnoreCase));

    public static string Pct(double v) => v.ToString(v < 10 && v % 1 != 0 ? "0.#" : "0", Inv) + " %";

    public static string Duration(TimeSpan d) =>
        d.TotalDays >= 1 ? $"{(int)d.TotalDays}d {d.Hours}h" : d.TotalHours >= 1 ? $"{(int)d.TotalHours}h {d.Minutes}m"
        : d.TotalMinutes >= 1 ? $"{d.Minutes}m {d.Seconds:00}s" : $"{Math.Max(1, (int)d.TotalSeconds)}s";

    public static string Pps(double v) => v >= 10000 ? (v / 1000).ToString("0.#", Inv) + "k" : v >= 1000 ? (v / 1000).ToString("0.0", Inv) + "k" : v.ToString(v < 10 ? "0.#" : "0", Inv);

    public static string Bps(double bps) =>
        bps >= 1e9 ? (bps / 1e9).ToString("0.##", Inv) + " Gb/s" : bps >= 1e6 ? (bps / 1e6).ToString("0.#", Inv) + " Mb/s"
        : bps >= 1e3 ? (bps / 1e3).ToString("0", Inv) + " kb/s" : bps.ToString("0", Inv) + " b/s";

    public static string When(DateTimeOffset t) => t.Date == DateTime.Today ? t.ToString("HH:mm:ss") : t.ToString("MMM d HH:mm");

    public static Geometry Icon(string key) =>
        Avalonia.Application.Current?.TryGetResource(key, null, out var g) == true && g is Geometry geo ? geo : new StreamGeometry();

    public static readonly Color[] Palette =
        new[] { "#00E5FF", "#FF2BD6", "#3DFF8B", "#FFC23D", "#9B7BFF", "#FF8A3D", "#4DD8FF", "#FF7AB8", "#E9F542" }
            .Select(Color.Parse).ToArray();
}

public sealed partial class PathHopRow : ObservableObject
{
    public required int Index { get; init; }
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _role = "";
    [ObservableProperty] private string _ip = "";
    [ObservableProperty] private string _probe = "";
    [ObservableProperty] private string _portIn = "";
    [ObservableProperty] private string _health = "";
    [ObservableProperty] private IBrush _healthBrush = Ui.Grey;
    [ObservableProperty] private string _rtt = "";
    [ObservableProperty] private string _added = "";
    [ObservableProperty] private string _jitter = "";
    [ObservableProperty] private string _loss = "";
    [ObservableProperty] private string _arp = "";
    [ObservableProperty] private IBrush _arpBrush = Ui.Dim;
    [ObservableProperty] private string _icmp = "";
    [ObservableProperty] private IBrush _icmpBrush = Ui.Dim;
    [ObservableProperty] private string _note = "";
    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private IBrush _rowBackground = Brushes.Transparent;
    partial void OnIsSelectedChanged(bool value) => RowBackground = value ? new SolidColorBrush(Color.Parse("#2200E5FF")) : Brushes.Transparent;
}

/// <summary>Path Doctor page: the live hop chain from this PC to the internet, verdict, per-hop timeline and table.</summary>
public sealed partial class PathViewModel : ObservableObject
{
    private readonly DiagnosticsFeed _feed;
    private readonly Throttler _throttle;

    public PathViewModel(DiagnosticsFeed feed, AgentsViewModel agents)
    {
        _feed = feed;
        Agents = agents;
        Dual = new DualInterfaceViewModel(feed);
        _throttle = new Throttler(TimeSpan.FromMilliseconds(500), Refresh);
        feed.PathChanged += _throttle.Signal;
        feed.IncidentsChanged += _throttle.Signal;
        feed.SourceChanged += _throttle.Signal;
        feed.AgentsChanged += _throttle.Signal;
        Refresh();
    }

    public AgentsViewModel Agents { get; }
    public DualInterfaceViewModel Dual { get; }
    /// <summary>Set by the shell: navigate to a page key.</summary>
    public Action<string>? Navigate { get; set; }

    public ObservableCollection<PathHopRow> Rows { get; } = [];
    [ObservableProperty] private IReadOnlyList<HopVisual> _hops = [];
    [ObservableProperty] private IReadOnlyList<ChartSeries> _series = [];
    [ObservableProperty] private int _selectedHop = -1;
    [ObservableProperty] private bool _hasPath;
    [ObservableProperty] private string _verdict = "No path yet";
    [ObservableProperty] private string _verdictDetail = "";
    [ObservableProperty] private IBrush _verdictBrush = Ui.Grey;
    [ObservableProperty] private string _medium = "";
    [ObservableProperty] private bool _isWifi;
    [ObservableProperty] private string _builtText = "";
    [ObservableProperty] private string _emptyTitle = "";
    [ObservableProperty] private string _emptyText = "";
    [ObservableProperty] private string _incidentText = "";
    [ObservableProperty] private bool _hasIncident;
    [ObservableProperty] private string _chartTitle = "PER-HOP LATENCY";
    [ObservableProperty] private bool _canRebuild;

    // ---- top-bar chip ----
    [ObservableProperty] private string _chipText = "Path —";
    [ObservableProperty] private IBrush _chipBrush = Ui.Grey;
    [ObservableProperty] private string _chipTooltip = "Path Doctor — hop-by-hop path from this PC to the internet";

    partial void OnSelectedHopChanged(int value)
    {
        foreach (var r in Rows) r.IsSelected = r.Index == value;
        Refresh();
    }

    [RelayCommand]
    private void Rebuild()
    {
        try { _feed.Path?.Rebuild(); BuiltText = "Rebuilding path…"; }
        catch (Exception ex) { BuiltText = "Rebuild failed: " + ex.Message; }
    }

    [RelayCommand] private void OpenIncidents() => Navigate?.Invoke("incidents");
    [RelayCommand] private void OpenSettings() => Navigate?.Invoke("settings");
    [RelayCommand] private void ClearSelection() => SelectedHop = -1;

    private static DeviceType GlyphFor(PathHop h) => h.Role switch
    {
        HopRole.ThisHost => DeviceType.ThisComputer,
        HopRole.AccessPoint => DeviceType.AccessPoint,
        HopRole.Switch => h.Index <= 1 ? DeviceType.AccessSwitch : DeviceType.CoreSwitch,
        HopRole.UnmanagedSwitch => DeviceType.UnmanagedSwitch,
        HopRole.Router => DeviceType.Router,
        HopRole.Firewall => DeviceType.Firewall,
        HopRole.Modem => DeviceType.Router,
        HopRole.IspHop => DeviceType.Server,
        _ => DeviceType.Internet,
    };

    private static string RoleText(PathHop h)
    {
        string role = h.Role switch
        {
            HopRole.ThisHost => "This PC",
            HopRole.AccessPoint => "Access point",
            HopRole.Switch => "Switch",
            HopRole.UnmanagedSwitch => "Unmanaged switch",
            HopRole.Router => "Router / gateway",
            HopRole.Firewall => "Firewall",
            HopRole.Modem => "ISP modem",
            HopRole.IspHop => "ISP hop",
            _ => "Internet target",
        };
        return h.PortIn is { } p ? $"{role} · in {p}" : role;
    }

    private void Refresh()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }
        var monitor = _feed.Path;
        var path = monitor?.Path;
        CanRebuild = monitor is not null;
        var active = _feed.Incidents?.Active ?? [];
        Dual.Refresh();

        if (path is null || path.Hops.Count == 0)
        {
            HasPath = false;
            Hops = [];
            Rows.Clear();
            Series = [];
            Verdict = "No path yet";
            VerdictBrush = Ui.Grey;
            Medium = "";
            (EmptyTitle, EmptyText) = monitor is null
                ? ("Path Doctor isn't available in this build", "The path monitor engine isn't installed yet. Turn on \"Demo network\" to see Path Doctor with a simulated home/office network.")
                : ("No path built yet", "Path Doctor builds the hop chain from the topology and a traceroute. Start monitoring or run a full scan, then press \"Rebuild path\". Make sure it's enabled under Settings → Path Doctor.");
            ChipText = monitor is null ? "Path —" : "Path …";
            ChipBrush = Ui.Grey;
            ChipTooltip = "Path Doctor — no path yet. Click for details.";
            BuiltText = "";
            SetIncidentBanner(active);
            return;
        }

        HasPath = true;
        Medium = path.Medium;
        IsWifi = Diag.IsWifiMedium(path.Medium);
        var hops = path.Hops;
        int fault = -1;
        for (int i = 1; i < hops.Count; i++)
            if (hops[i].Health == HopHealth.Down && hops[i - 1].Health != HopHealth.Down) { fault = i; break; }

        // ---- chain visuals ----
        var visuals = new List<HopVisual>(hops.Count);
        for (int i = 0; i < hops.Count; i++)
        {
            var h = hops[i];
            bool beyond = fault >= 0 && i > fault;
            string rtt = h.Role == HopRole.ThisHost ? "origin" : h.Health == HopHealth.Down ? (beyond ? "no reply" : "DOWN") : Neon.FormatMs(h.RttMs);
            string? added = h.AddedMs is { } a && h.Role != HopRole.ThisHost && h.Health != HopHealth.Down ? "+" + Neon.FormatMs(a) : null;
            string loss = h.Role == HopRole.ThisHost ? "local adapter" : $"loss {Diag.Pct(h.LossPercent)}" + (h.JitterMs is { } j ? $" · jitter {Neon.FormatMs(j)}" : "");
            string? logo = h.Mac is { } m ? _feed.Device(m)?.LogoPath : null;
            visuals.Add(new HopVisual(h.Index, h.Role, GlyphFor(h), h.Name, h.Ip?.ToString(), RoleText(h), h.Health, rtt, added, loss,
                h.ArpOk, h.IcmpOk, h.Note, logo, i == fault, beyond, h.Recent.ToArray()));
        }
        Hops = visuals;

        // ---- table (update in place) ----
        while (Rows.Count > hops.Count) Rows.RemoveAt(Rows.Count - 1);
        for (int i = 0; i < hops.Count; i++)
        {
            var h = hops[i];
            if (i >= Rows.Count) Rows.Add(new PathHopRow { Index = h.Index, IsSelected = h.Index == SelectedHop });
            var r = Rows[i];
            r.Name = h.Name;
            r.Role = RoleText(h);
            r.Ip = h.Ip?.ToString() ?? "—";
            r.Probe = h.Probe switch { HopProbe.Self => "self", HopProbe.ArpIcmp => "ARP + ICMP", HopProbe.IcmpOnly => "ICMP", HopProbe.Anchors => $"{h.Anchors.Count} anchors", _ => "—" };
            r.PortIn = h.PortIn ?? "—";
            r.Health = fault >= 0 && i > fault ? "Unreachable" : Diag.HealthText(h.Health);
            r.HealthBrush = fault >= 0 && i > fault ? Ui.Grey : Diag.HealthBrush(h.Health);
            r.Rtt = h.Role == HopRole.ThisHost ? "—" : Neon.FormatMs(h.RttMs);
            r.Added = h.AddedMs is { } a && h.Role != HopRole.ThisHost ? "+" + Neon.FormatMs(a) : "—";
            r.Jitter = Neon.FormatMs(h.JitterMs);
            r.Loss = h.Role == HopRole.ThisHost ? "—" : Diag.Pct(h.LossPercent);
            (r.Arp, r.ArpBrush) = h.ArpOk switch { true => ("ok", Ui.Green), false => ("fail", Ui.Red), _ => ("—", Ui.Faint) };
            (r.Icmp, r.IcmpBrush) = h.IcmpOk switch { true => ("ok", Ui.Green), false => ("fail", Ui.Red), _ => ("—", Ui.Faint) };
            r.Note = h.Note ?? "";
        }

        // ---- per-hop timeline ----
        var series = new List<ChartSeries>();
        for (int i = 0; i < hops.Count; i++)
        {
            var h = hops[i];
            if (h.Role == HopRole.ThisHost) continue;
            if (SelectedHop >= 0 && h.Index != SelectedHop) continue;
            series.Add(new ChartSeries(Short(h.Name), Diag.Palette[(i - 1 + Diag.Palette.Length) % Diag.Palette.Length],
                h.Recent.Select(v => v ?? double.NaN).ToArray(), Fill: SelectedHop >= 0));
        }
        Series = series;
        ChartTitle = SelectedHop >= 0 && hops.FirstOrDefault(h => h.Index == SelectedHop) is { } sel
            ? $"LATENCY · {sel.Name.ToUpperInvariant()}" : "PER-HOP LATENCY";

        // ---- verdict + chip ----
        var target = hops[^1];
        if (fault >= 0)
        {
            var bad = hops[fault];
            var prev = hops[fault - 1];
            var match = active.FirstOrDefault(a => a.Category is not (IncidentCategory.Storm or IncidentCategory.Loop)
                && (a.SuspectDevice is { } sd && (sd == bad.Mac || bad.Mac is null) || a.Category is IncidentCategory.Modem or IncidentCategory.Isp or IncidentCategory.Router or IncidentCategory.OwnLink));
            Verdict = match?.RootCause ?? $"Fault between {prev.Name} and {bad.Name}";
            VerdictDetail = $"{prev.Name} answers ({Neon.FormatMs(prev.RttMs)}) — {bad.Name} and {hops.Count - fault - 1} hop(s) beyond it stopped replying.";
            VerdictBrush = Ui.Red;
            ChipText = $"Fault: {bad.Name}";
            ChipBrush = Ui.Red;
            ChipTooltip = $"Path Doctor: {Verdict}. Click for details.";
        }
        else if (hops.FirstOrDefault(h => h.Health == HopHealth.Degraded) is { } deg)
        {
            Verdict = $"Path degraded at {deg.Name}";
            VerdictDetail = $"{Diag.Pct(deg.LossPercent)} loss · {Neon.FormatMs(deg.RttMs)} (+{Neon.FormatMs(deg.AddedMs)}) · the hops before it are healthy.";
            VerdictBrush = Ui.Amber;
            ChipText = "Path slow";
            ChipBrush = Ui.Amber;
            ChipTooltip = $"Path Doctor: {Verdict}. Click for details.";
        }
        else
        {
            Verdict = "All hops healthy";
            VerdictDetail = $"{hops.Count} hops to {target.Name} · {Neon.FormatMs(target.RttMs)} end-to-end · every hop answers ARP/ICMP.";
            VerdictBrush = Ui.Green;
            ChipText = "Path OK";
            ChipBrush = Ui.Green;
            ChipTooltip = $"Path Doctor: all {hops.Count} hops healthy ({Neon.FormatMs(target.RttMs)} to {target.Name}). Click for details.";
        }
        BuiltText = $"Built {path.Built:HH:mm:ss} · updated {path.Updated:HH:mm:ss}";
        SetIncidentBanner(active);
    }

    /// <summary>"Active incident" strip: the most severe ongoing incident that isn't already the headline verdict.</summary>
    private void SetIncidentBanner(IReadOnlyList<Incident> active)
    {
        var others = active.Where(i => i.RootCause != Verdict).OrderByDescending(i => i.Severity).ThenByDescending(i => i.Start).ToList();
        HasIncident = others.Count > 0;
        IncidentText = others.Count == 0 ? "" : others.Count > 1 ? $"{others[0].RootCause}  (+{others.Count - 1} more)" : others[0].RootCause;
    }

    private static string Short(string s) => s.Length <= 22 ? s : s[..21] + "…";
}

// =========================================================================================================
//  dual-interface self-test (this PC's wired + Wi-Fi adapters as built-in "local:" agents)
// =========================================================================================================

public sealed partial class DualCell : ObservableObject
{
    [ObservableProperty] private string _value = "—";
    [ObservableProperty] private string _sub = "";
    [ObservableProperty] private IBrush _brush = Ui.Grey;
    [ObservableProperty] private IBrush _background = Brushes.Transparent;

    public void Set(ProbeTargetResult? r)
    {
        if (r is null) { Value = "—"; Sub = "not tested"; Brush = Ui.Grey; Background = new SolidColorBrush(Color.Parse("#0A1020")); return; }
        bool fail = r.RttMs is null && r.AvgMs is null || r.LossPercent >= 50;
        bool warn = !fail && (r.LossPercent > 2 || (r.AvgMs ?? r.RttMs) > 50);
        Value = fail ? (r.Error ?? "no reply") : Neon.FormatMs(r.AvgMs ?? r.RttMs);
        Sub = $"loss {Diag.Pct(r.LossPercent)}" + (r.Ip is { } ip ? $" · {ip}" : "");
        var c = fail ? Color.Parse("#FF3D5A") : warn ? Color.Parse("#FFC23D") : Color.Parse("#3DFF8B");
        Brush = new SolidColorBrush(c);
        Background = new SolidColorBrush(c, 0.10);
    }

    public static bool Ok(ProbeTargetResult? r) => r is not null && (r.RttMs is not null || r.AvgMs is not null) && r.LossPercent < 50;
}

public sealed partial class DualInterfaceViewModel(DiagnosticsFeed feed) : ObservableObject
{
    [ObservableProperty] private bool _visible;
    [ObservableProperty] private bool _hasMatrix;
    [ObservableProperty] private string _wiredName = "Wired adapter";
    [ObservableProperty] private string _wifiName = "Wi-Fi adapter";
    [ObservableProperty] private string _wiredIp = "";
    [ObservableProperty] private string _wifiIp = "";
    [ObservableProperty] private string _verdict = "";
    [ObservableProperty] private IBrush _verdictBrush = Ui.Dim;
    public DualCell WiredGateway { get; } = new();
    public DualCell WiredCross { get; } = new();
    public DualCell WiredInternet { get; } = new();
    public DualCell WifiGateway { get; } = new();
    public DualCell WifiCross { get; } = new();
    public DualCell WifiInternet { get; } = new();

    public void Refresh()
    {
        var locals = (feed.Agents?.Agents ?? []).Where(a => a.AgentId.StartsWith("local:", StringComparison.OrdinalIgnoreCase) && a.Online).ToList();
        Visible = locals.Count >= 1 || feed.IsDemo;
        var wired = locals.FirstOrDefault(a => !IsWifi(a));
        var wifi = locals.FirstOrDefault(a => IsWifi(a));
        HasMatrix = wired is not null && wifi is not null;
        if (!HasMatrix) return;

        WiredName = wired!.Hostname;
        WifiName = wifi!.Hostname;
        WiredIp = wired.Ip ?? "";
        WifiIp = wifi.Ip ?? "";
        var (eg, ec, ei) = Classify(wired, wifi);
        var (wg, wc, wi) = Classify(wifi, wired);
        WiredGateway.Set(eg); WiredCross.Set(ec); WiredInternet.Set(ei);
        WifiGateway.Set(wg); WifiCross.Set(wc); WifiInternet.Set(wi);

        bool egOk = DualCell.Ok(eg), wgOk = DualCell.Ok(wg);
        bool crossTested = ec is not null || wc is not null;
        bool crossOk = (ec is null || DualCell.Ok(ec)) && (wc is null || DualCell.Ok(wc));
        bool inetOk = DualCell.Ok(ei) && DualCell.Ok(wi);
        (Verdict, VerdictBrush) = (egOk, wgOk) switch
        {
            (true, false) => ("Wi-Fi side broken: the Wi-Fi adapter can't reach the gateway but the wired one can → AP / radio or the AP's uplink.", Ui.Red),
            (false, true) => ("Wired side broken: the wired adapter can't reach the gateway but Wi-Fi can → this PC's cable, switch port or access switch.", Ui.Red),
            (false, false) => ("Both adapters fail to reach the gateway → upstream: router/gateway or the shared core.", Ui.Red),
            _ when crossTested && !crossOk => ("LAN ↔ Wi-Fi bridging blocked: both sides reach the gateway but not each other → client/AP isolation, guest SSID or a firewall between VLANs.", Ui.Amber),
            _ when !inetOk => ("LAN and Wi-Fi are fine locally, but the internet isn't reachable from both → router WAN / ISP.", Ui.Amber),
            _ => ("Both directions healthy: wired ↔ Wi-Fi crossover and both gateways answer.", Ui.Green),
        };
    }

    private static bool IsWifi(ProbeAgentInfo a) => Diag.IsWifiMedium(a.Medium);

    /// <summary>Maps an agent's results to (own gateway, the other local adapter, internet).</summary>
    private static (ProbeTargetResult? Gw, ProbeTargetResult? Cross, ProbeTargetResult? Inet) Classify(ProbeAgentInfo self, ProbeAgentInfo other)
    {
        var res = self.Latest?.Results ?? [];
        var cross = res.FirstOrDefault(r => other.Ip is { } oip && (r.Ip == oip || r.Target == oip))
                    ?? res.FirstOrDefault(r => r.Target.Contains("other adapter", StringComparison.OrdinalIgnoreCase) || r.Target.Contains("crossover", StringComparison.OrdinalIgnoreCase));
        var inet = res.FirstOrDefault(r => r != cross && (r.Ip == "1.1.1.1" || r.Target.Contains("1.1.1.1") || r.Target.Contains("internet", StringComparison.OrdinalIgnoreCase)));
        var gwIp = self.Latest?.Gateway;
        var gw = res.FirstOrDefault(r => r != cross && r != inet && gwIp is not null && (r.Ip == gwIp || r.Target == gwIp))
                 ?? res.FirstOrDefault(r => r != cross && r != inet && r.Target.Contains("gateway", StringComparison.OrdinalIgnoreCase));
        return (gw, cross, inet);
    }
}
