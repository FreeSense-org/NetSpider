using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using NetSpider.App.Controls;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.App.ViewModels;

public sealed record WifiEventRow(string Time, string Date, string Kind, string Detail, IBrush Brush, Geometry Icon);

public sealed record ApCardRow(string Name, string Ip, string Health, IBrush HealthBrush, IBrush Border, string Mgmt, IBrush MgmtBrush,
    string Clients, double ClientFraction, IBrush ClientBrush, string ClientRtt, string Loss, IBrush LossBrush, string? Diagnosis, IBrush DiagnosisBrush)
{
    public bool HasDiagnosis => !string.IsNullOrEmpty(Diagnosis);
}

/// <summary>Wi-Fi page "Link diagnostics": this host's radio link over time, events, and per-AP health.</summary>
public sealed partial class WifiLinkViewModel : ObservableObject
{
    private readonly DiagnosticsFeed _feed;
    private readonly ISettingsStore _store;
    private readonly IDeviceStore _devices;
    private readonly Throttler _throttle;

    public WifiLinkViewModel(DiagnosticsFeed feed, ISettingsStore store, IDeviceStore devices)
    {
        _feed = feed;
        _store = store;
        _devices = devices;
        _throttle = new Throttler(TimeSpan.FromMilliseconds(700), Refresh);
        feed.WifiChanged += _throttle.Signal;
        feed.ApsChanged += _throttle.Signal;
        feed.SourceChanged += _throttle.Signal;
        Refresh();
    }

    public ObservableCollection<WifiEventRow> Events { get; } = [];
    public ObservableCollection<ApCardRow> Aps { get; } = [];

    [ObservableProperty] private bool _connected;
    [ObservableProperty] private bool _showEmpty = true;
    [ObservableProperty] private string _emptyTitle = "";
    [ObservableProperty] private string _emptyText = "";
    [ObservableProperty] private string _ssid = "";
    [ObservableProperty] private string _bssid = "";
    [ObservableProperty] private string _apName = "";
    [ObservableProperty] private string _channel = "";
    [ObservableProperty] private string _phy = "";
    [ObservableProperty] private double _rssiGauge;
    [ObservableProperty] private string _rssiText = "";
    [ObservableProperty] private string _quality = "";
    [ObservableProperty] private string _txRate = "";
    [ObservableProperty] private string _rxRate = "";
    [ObservableProperty] private string _apRtt = "";
    [ObservableProperty] private string _gwRtt = "";
    [ObservableProperty] private string _hopSplit = "";
    [ObservableProperty] private IBrush _hopSplitBrush = Ui.Dim;
    [ObservableProperty] private IReadOnlyList<ChartSeries> _rssiSeries = [];
    [ObservableProperty] private IReadOnlyList<ChartSeries> _rttSeries = [];
    [ObservableProperty] private bool _hasEvents;
    [ObservableProperty] private bool _hasAps;
    [ObservableProperty] private string _apEmptyText = "";

    private void Refresh()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }
        var mon = _feed.Wifi;
        var cur = mon?.Current;
        Connected = cur is { Connected: true };
        ShowEmpty = !Connected;
        (EmptyTitle, EmptyText) = mon is null
            ? ("Wi-Fi link diagnostics aren't available in this build", "The Wi-Fi link monitor engine isn't installed yet. Turn on \"Demo network\" to see it in action.")
            : !_store.Settings.WifiLinkMonitorEnabled ? ("Wi-Fi link monitoring is off", "Enable it under Settings → Wi-Fi diagnostics to record RSSI, rates, roams and disconnect reasons.")
            : !mon.Available ? ("No wireless adapter", "This PC has no Wi-Fi adapter (or the WLAN service isn't running). Per-AP health below still works from a wired PC.")
            : ("This PC isn't connected to Wi-Fi", "Connect to a wireless network to see signal, rates, roams and the radio-hop vs backhaul split. Per-AP health below still works from a wired PC.");

        if (cur is { Connected: true })
        {
            Ssid = cur.Ssid ?? "(hidden)";
            Bssid = cur.Bssid?.ToString() ?? "—";
            ApName = cur.Bssid is { } b ? ApFor(b) : "";
            Channel = $"ch {cur.Channel} · {cur.Band ?? "?"}";
            Phy = cur.Phy ?? "";
            RssiGauge = Math.Clamp(cur.RssiDbm + 100, 0, 70);
            RssiText = cur.RssiDbm.ToString(Diag.Inv);
            Quality = $"dBm · {cur.SignalQuality} % quality";
            TxRate = $"{cur.TxRateMbps:0} Mbps";
            RxRate = $"{cur.RxRateMbps:0} Mbps";
            ApRtt = Neon.FormatMs(cur.ApRttMs);
            GwRtt = Neon.FormatMs(cur.GatewayRttMs);
            if (cur.ApRttMs is { } ap && cur.GatewayRttMs is { } gw)
            {
                double backhaul = Math.Max(0, gw - ap);
                bool radio = ap > backhaul * 2 && ap > 5;
                HopSplit = radio ? $"Radio hop dominates: {Neon.FormatMs(ap)} to the AP vs {Neon.FormatMs(backhaul)} backhaul — signal / interference"
                    : backhaul > 5 ? $"Backhaul is slow: +{Neon.FormatMs(backhaul)} from AP to gateway — AP uplink / switch"
                    : $"Radio {Neon.FormatMs(ap)} · backhaul +{Neon.FormatMs(backhaul)} — both healthy";
                HopSplitBrush = radio || backhaul > 5 ? Ui.Amber : Ui.Green;
            }
            else { HopSplit = "AP or gateway ping lost"; HopSplitBrush = Ui.Red; }

            var hist = mon!.History.TakeLast(300).ToList();
            RssiSeries = [new ChartSeries("RSSI (dBm)", Color.Parse("#00E5FF"), hist.Select(s => s.Connected ? s.RssiDbm : double.NaN).ToArray(), Fill: false),
                          new ChartSeries($"weak ({_store.Settings.WifiWeakRssiDbm} dBm)", Color.Parse("#FF3D5A"), hist.Select(_ => (double)_store.Settings.WifiWeakRssiDbm).ToArray(), Fill: false)];
            RttSeries = [new ChartSeries("AP (radio hop)", Color.Parse("#FF2BD6"), hist.Select(s => s.ApRttMs ?? double.NaN).ToArray(), Fill: false),
                         new ChartSeries("Gateway (radio + backhaul)", Color.Parse("#3DFF8B"), hist.Select(s => s.GatewayRttMs ?? double.NaN).ToArray(), Fill: false)];
        }

        Events.Clear();
        foreach (var e in (mon?.Events ?? []).OrderByDescending(e => e.Time).Take(20))
        {
            var (brush, icon) = e.Kind.ToLowerInvariant() switch
            {
                var k when k.Contains("disconnect") => (Ui.Red, "IconClose"),
                var k when k.Contains("auth") || k.Contains("fail") => (Ui.Red, "IconShield"),
                var k when k.Contains("roam") => (Ui.Cyan, "IconWifi"),
                var k when k.Contains("weak") => (Ui.Amber, "IconWarn"),
                var k when k.Contains("connect") || k.Contains("recover") => (Ui.Green, "IconCheck"),
                _ => (Ui.Dim, "IconInfo"),
            };
            string detail = string.Join(" · ", new[] { e.Reason, e.Ssid is null ? null : $"SSID {e.Ssid}", e.Bssid is { } b ? $"BSSID {b}{(ApFor(b) is { Length: > 0 } n ? $" ({n})" : "")}" : null }.Where(s => !string.IsNullOrEmpty(s)));
            Events.Add(new WifiEventRow(e.Time.ToString("HH:mm:ss"), e.Time.Date == DateTime.Today ? "today" : e.Time.ToString("MMM d"), Pretty(e.Kind), detail, brush, Diag.Icon(icon)));
        }
        HasEvents = Events.Count > 0;

        Aps.Clear();
        foreach (var a in (_feed.Aps?.AccessPoints ?? []).OrderBy(a => a.Name))
        {
            var hb = Diag.HealthBrush(a.Health);
            double frac = a.Clients == 0 ? 0 : (double)a.ClientsReachable / a.Clients;
            Aps.Add(new ApCardRow(a.Name, a.Ip?.ToString() ?? "no IP", Diag.HealthText(a.Health), hb, new SolidColorBrush(((ISolidColorBrush)hb).Color, 0.45),
                a.MgmtUp switch { true => $"Management up · {Neon.FormatMs(a.MgmtRttMs)}", false => "Management DOWN", _ => "Management unknown" },
                a.MgmtUp switch { true => Ui.Green, false => Ui.Red, _ => Ui.Grey },
                $"{a.ClientsReachable} / {a.Clients} clients reachable", frac, frac >= 0.99 ? Ui.Green : frac >= 0.6 ? Ui.Amber : Ui.Red,
                Neon.FormatMs(a.AvgClientRttMs), Diag.Pct(a.ClientLossPercent), a.ClientLossPercent >= 5 ? Ui.Red : a.ClientLossPercent >= 1 ? Ui.Amber : Ui.Text,
                a.Diagnosis, a.Health == HopHealth.Down ? Ui.Red : Ui.Amber));
        }
        HasAps = Aps.Count > 0;
        ApEmptyText = _feed.Aps is null ? "Per-AP health isn't available in this build." : "No access points discovered yet — they appear after a scan finds APs (LLDP, vendor discovery or Wi-Fi associations).";
    }

    private static string Pretty(string kind) => kind switch
    {
        "AuthFailed" => "Authentication failed",
        "SignalWeak" => "Weak signal",
        "SignalRecovered" => "Signal recovered",
        _ => kind,
    };

    /// <summary>BSSIDs are usually the AP's base MAC + a small offset per radio/SSID.</summary>
    private string ApFor(Mac bssid)
    {
        foreach (var d in _devices.All)
            if (d.Type == DeviceType.AccessPoint && Math.Abs((long)d.Mac.Value - (long)bssid.Value) <= 8) return d.DisplayName;
        return "";
    }
}
