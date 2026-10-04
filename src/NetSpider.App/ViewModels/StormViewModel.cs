using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Controls;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed record ProtocolRow(string Name, string Pps, double Fraction, IBrush Brush);
public sealed record StormSourceRow(string Name, string Mac, string Pps, string Bcast, string Mcast, string Protocol, string Location, IBrush Brush);
public sealed record IngressRow(string Switch, string Port, string Bcast, string Mcast, string Note, IBrush Brush);
public sealed record LoopRow(string Description, string Ports, string Macs, string Confidence, string Time);
public sealed record StormHistoryRow(string Start, string Duration, string Level, IBrush LevelBrush, string Peak, string Protocol, string Summary, string? PcapPath)
{
    public bool HasPcap => !string.IsNullOrEmpty(PcapPath);
    public string PcapName => System.IO.Path.GetFileName(PcapPath ?? "");
}
public sealed record PortHealthRow(string Switch, string Port, string Status, IBrush StatusBrush, string Link, string In, string Out,
    string Errors, string Fcs, string Flaps, string Bcast, string Problem, IBrush ProblemBrush, IBrush RowBackground);

/// <summary>Storm Center: live broadcast/multicast/unknown-unicast rates, sources and where they enter, loops, history, storm-control check.</summary>
public sealed partial class StormViewModel : ObservableObject
{
    private const int Window = 300;
    private readonly DiagnosticsFeed _feed;
    private readonly ISettingsStore _store;
    private readonly Throttler _throttle;
    private readonly Throttler _portThrottle;
    private readonly List<(long Sec, double B, double M, double U)> _ring = [];

    public StormViewModel(DiagnosticsFeed feed, ISettingsStore store, IServiceProvider sp)
    {
        _feed = feed;
        _recorder = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetService<IPacketRecorder>(sp);
        if (_recorder is not null) _recorder.Changed += () => Dispatcher.UIThread.Post(UpdateRecording);
        _recTimer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) => UpdateRecording());
        _store = store;
        _throttle = new Throttler(TimeSpan.FromMilliseconds(500), Refresh);
        _portThrottle = new Throttler(TimeSpan.FromSeconds(1), RefreshPorts);
        feed.StormChanged += () => { Capture(); _throttle.Signal(); };
        feed.PortsChanged += _portThrottle.Signal;
        feed.SourceChanged += () => { lock (_ring) _ring.Clear(); Seed(); _throttle.Signal(); _portThrottle.Signal(); };
        store.Saved += () => Dispatcher.UIThread.Post(UpdateCheckAvailability);
        Seed();
        Refresh();
        RefreshPorts();
    }

    private AppSettings S => _store.Settings;

    public ObservableCollection<ProtocolRow> Protocols { get; } = [];
    public ObservableCollection<StormSourceRow> Sources { get; } = [];
    public ObservableCollection<IngressRow> Ingress { get; } = [];
    public ObservableCollection<LoopRow> Loops { get; } = [];
    public ObservableCollection<StormHistoryRow> History { get; } = [];
    public ObservableCollection<PortHealthRow> PortRows { get; } = [];
    public ObservableCollection<string> CheckDetails { get; } = [];

    [ObservableProperty] private bool _available;
    [ObservableProperty] private double _broadcast;
    [ObservableProperty] private double _multicast;
    [ObservableProperty] private double _unknownUnicast;
    [ObservableProperty] private double _baselineBroadcast;
    [ObservableProperty] private double _baselineMulticast;
    [ObservableProperty] private double _broadcastThreshold = 500;
    [ObservableProperty] private double _multicastThreshold = 2000;
    [ObservableProperty] private string _levelText = "NORMAL";
    [ObservableProperty] private IBrush _levelBrush = Ui.Green;
    [ObservableProperty] private IBrush _levelBackground = new SolidColorBrush(Color.Parse("#1A3DFF8B"));
    [ObservableProperty] private bool _isStorm;
    [ObservableProperty] private string _levelDetail = "";
    [ObservableProperty] private string _totalText = "";
    [ObservableProperty] private IReadOnlyList<ChartSeries> _series = [];
    [ObservableProperty] private bool _hasSources;
    [ObservableProperty] private bool _hasIngress;
    [ObservableProperty] private bool _hasLoops;
    [ObservableProperty] private bool _hasHistory;
    [ObservableProperty] private bool _hasPorts;
    [ObservableProperty] private string _portSummary = "";
    /// <summary>false: hide ports that are down and have no problem (unused sockets).</summary>
    [ObservableProperty] private bool _showAllPorts;
    partial void OnShowAllPortsChanged(bool value) => RefreshPorts();
    [ObservableProperty] private string? _message;
    [ObservableProperty] private string _emptyText = "";

    // ---- storm-control check ----
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCheckCommand))] private bool _checkAvailable;
    [ObservableProperty] private string _checkReason = "";
    [ObservableProperty] private decimal? _checkPps = 2000;
    [ObservableProperty] private decimal? _checkSeconds = 2;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCheckCommand))] private bool _isChecking;
    [ObservableProperty] private bool _hasCheckResult;
    [ObservableProperty] private string _checkVerdict = "";
    [ObservableProperty] private IBrush _checkBrush = Ui.Dim;

    private void Seed()
    {
        // the demo storm center keeps its own pps history so the chart starts full
        if (_feed.Storm is DemoDiagnostics.DemoStormCenter d)
            lock (_ring)
            {
                _ring.Clear();
                foreach (var (t, b, m, u) in d.Rates.TakeLast(Window)) _ring.Add((t.ToUnixTimeSeconds(), b, m, u));
            }
    }

    private void Capture()
    {
        var st = _feed.Storm?.Status;
        if (st is null || st.Time == DateTimeOffset.MinValue) return;
        long sec = st.Time.ToUnixTimeSeconds();
        lock (_ring)
        {
            if (_ring.Count > 0 && _ring[^1].Sec == sec) _ring[^1] = (sec, st.BroadcastPps, st.MulticastPps, st.UnknownUnicastPps);
            else _ring.Add((sec, st.BroadcastPps, st.MulticastPps, st.UnknownUnicastPps));
            while (_ring.Count > Window) _ring.RemoveAt(0);
        }
    }

    private void UpdateCheckAvailability()
    {
        if (_feed.Storm is null) { CheckAvailable = false; CheckReason = "The storm center engine isn't available in this build."; return; }
        if (!S.StormControlCheckEnabled) { CheckAvailable = false; CheckReason = "Disabled. Enable \"Allow the storm-control check\" under Settings → Storm Center to unlock this active test."; return; }
        if (!_feed.CaptureRunning) { CheckAvailable = false; CheckReason = "Start monitoring first — the check watches the capture and switch counters while it runs."; return; }
        CheckAvailable = true;
        CheckReason = _feed.IsDemo ? "Ready (demo: simulated — nothing is transmitted)." : "Ready. Runs only when you press the button, never automatically.";
    }

    private void Refresh()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }
        UpdateCheckAvailability();
        var center = _feed.Storm;
        Available = center is not null;
        var st = center?.Status ?? StormStatus.Empty;
        EmptyText = center is null
            ? "The Storm Center engine isn't installed yet. Turn on \"Demo network\" to see it with simulated traffic."
            : st.Time == DateTimeOffset.MinValue ? "Waiting for traffic — start monitoring to see live broadcast / multicast rates." : "";

        Broadcast = st.BroadcastPps;
        Multicast = st.MulticastPps;
        UnknownUnicast = st.UnknownUnicastPps;
        BaselineBroadcast = st.BaselineBroadcastPps;
        BaselineMulticast = st.BaselineMulticastPps;
        BroadcastThreshold = S.StormBroadcastPps;
        MulticastThreshold = S.StormMulticastPps;
        TotalText = st.TotalPps > 0 ? $"{Diag.Pps(st.TotalPps)} pps total · broadcast {st.BroadcastPps / Math.Max(1, st.TotalPps) * 100:0.0} %" : "";
        (LevelText, LevelBrush, IsStorm) = st.Level switch
        {
            StormLevel.Storm => ("STORM", Ui.Red, true),
            StormLevel.Elevated => ("ELEVATED", Ui.Amber, false),
            _ => ("NORMAL", Ui.Green, false),
        };
        LevelBackground = new SolidColorBrush(((ISolidColorBrush)LevelBrush).Color, 0.12);
        var dominant = st.PpsByProtocol.OrderByDescending(p => p.Value).FirstOrDefault();
        LevelDetail = st.Level switch
        {
            StormLevel.Storm => $"Broadcast {Diag.Pps(st.BroadcastPps)} pps = ×{st.BroadcastPps / Math.Max(1, st.BaselineBroadcastPps):0} baseline · dominant {dominant.Key}"
                                + (st.Sources.FirstOrDefault() is { } s ? $" · top source {s.Name ?? s.Mac.ToString()} ({s.Location ?? "location unknown"})" : ""),
            StormLevel.Elevated => FormattableString.Invariant($"Above baseline: broadcast ×{st.BroadcastPps / Math.Max(1, st.BaselineBroadcastPps):0.0}, multicast ×{st.MulticastPps / Math.Max(1, st.BaselineMulticastPps):0.0} · dominant {dominant.Key}"),
            _ when st.Time == DateTimeOffset.MinValue => "No data yet",
            _ => $"Broadcast and multicast within the learned baseline ({Diag.Pps(st.BaselineBroadcastPps)} / {Diag.Pps(st.BaselineMulticastPps)} pps).",
        };

        // pps history chart
        double[] b, m, u;
        lock (_ring)
        {
            b = _ring.Select(x => x.B).ToArray();
            m = _ring.Select(x => x.M).ToArray();
            u = _ring.Select(x => x.U).ToArray();
        }
        Series =
        [
            new ChartSeries("Broadcast", Color.Parse("#FF3D5A"), b),
            new ChartSeries("Multicast", Color.Parse("#FF2BD6"), m),
            new ChartSeries("Unknown unicast", Color.Parse("#FFC23D"), u),
        ];

        // protocols
        double pmax = Math.Max(1, st.PpsByProtocol.Values.DefaultIfEmpty(0).Max());
        Protocols.Clear();
        foreach (var (name, pps) in st.PpsByProtocol.OrderByDescending(p => p.Value))
            Protocols.Add(new ProtocolRow(name, Diag.Pps(pps) + " pps", pps / pmax, new SolidColorBrush(Ui.ToColor(Neon.Protocol(ProtoKey(name))))));

        Sources.Clear();
        foreach (var s in st.Sources.Take(10))
            Sources.Add(new StormSourceRow(s.Name ?? _feed.NameOf(s.Mac), s.Mac.ToString(), Diag.Pps(s.Pps), Diag.Pps(s.BroadcastPps), Diag.Pps(s.MulticastPps),
                s.DominantProtocol, s.Location ?? (s.SwitchName is { } sw ? $"{sw} {s.Port}" : "unknown"),
                s.Pps >= S.StormPerMacPps ? Ui.Red : s.Pps >= S.StormPerMacPps * 0.3 ? Ui.Amber : Ui.Text));
        HasSources = Sources.Count > 0;

        Ingress.Clear();
        foreach (var i in st.Ingress.Take(8))
            Ingress.Add(new IngressRow(i.SwitchName, i.Port, Diag.Pps(i.BroadcastPps), Diag.Pps(i.MulticastPps), i.Note ?? "",
                i.BroadcastPps >= S.StormBroadcastPps * 0.8 ? Ui.Red : i.BroadcastPps + i.MulticastPps >= 100 ? Ui.Amber : Ui.Text));
        HasIngress = Ingress.Count > 0;

        Loops.Clear();
        foreach (var l in st.Loops)
            Loops.Add(new LoopRow(l.Description, l.Ports.Count == 0 ? "" : $"{(l.Switch is { } sw ? _feed.NameOf(sw) + " " : "")}ports {string.Join(" ↔ ", l.Ports)}",
                l.FlappingMacs.Count == 0 ? "" : "flapping: " + string.Join(", ", l.FlappingMacs.Select(_feed.NameOf)), $"{l.Confidence * 100:0} %", l.Time.ToString("HH:mm:ss")));
        HasLoops = Loops.Count > 0;

        History.Clear();
        foreach (var e in (center?.History ?? []).Take(30))
            History.Add(new StormHistoryRow(Diag.When(e.Start), e.End is { } end ? Diag.Duration(end - e.Start) : "ongoing",
                e.PeakLevel.ToString(), e.PeakLevel == StormLevel.Storm ? Ui.Red : e.PeakLevel == StormLevel.Elevated ? Ui.Amber : Ui.Green,
                Diag.Pps(e.PeakPps) + " pps", e.DominantProtocol, e.Summary, e.PcapPath));
        HasHistory = History.Count > 0;
    }

    private static string ProtoKey(string name) => name.Replace(" ", "").ToUpperInvariant() switch { "IPV6ND" => "ICMPV6", var k => k };

    private void RefreshPorts()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(RefreshPorts); return; }
        var ports = _feed.Ports?.Ports ?? [];
        var ordered = ports.Where(p => ShowAllPorts || p.OperUp || p.Problem is not null)
            .OrderByDescending(p => p.Problem is not null)
            .ThenByDescending(p => p.Health == HopHealth.Down ? 3 : p.Health == HopHealth.Degraded ? 2 : p.OperUp ? 1 : 0)
            .ThenBy(p => _feed.NameOf(p.Switch)).ThenBy(p => p.IfIndex)
            .Take(60).ToList();
        PortRows.Clear();
        var alt = new SolidColorBrush(Color.Parse("#14FF3D5A"));
        foreach (var p in ordered)
        {
            bool problem = p.Problem is not null;
            bool red = p.Health == HopHealth.Down || p.FcsPerSec > 0.1 || p.FlapsLastHour >= 3;
            var pb = problem ? (red ? Ui.Red : Ui.Amber) : Ui.Dim;
            PortRows.Add(new PortHealthRow(_feed.NameOf(p.Switch), p.Name,
                p.OperUp ? (problem ? Diag.HealthText(p.Health) : "up") : "down", p.OperUp ? (problem ? pb : Ui.Green) : Ui.Grey,
                p.OperUp ? $"{Neon.FormatSpeed(p.SpeedMbps)} · {p.Duplex ?? "?"}" : "—",
                p.OperUp ? Diag.Bps(p.InBps) : "—", p.OperUp ? Diag.Bps(p.OutBps) : "—",
                p.ErrorsPerSec.ToString("0.##", Diag.Inv), p.FcsPerSec.ToString("0.##", Diag.Inv), p.FlapsLastHour.ToString(),
                Diag.Pps(p.BroadcastPps), p.Problem ?? "", pb, problem ? alt : Brushes.Transparent));
        }
        HasPorts = PortRows.Count > 0;
        int probs = ports.Count(p => p.Problem is not null);
        PortSummary = ports.Count == 0
            ? (_feed.Ports is null ? "Switch-port diagnostics aren't available in this build." : "No SNMP port counters yet — managed switches appear here once SNMP polling succeeds.")
            : $"{ports.Count} ports on {ports.Select(p => p.Switch).Distinct().Count()} switch(es) · {probs} with problems" + (ports.Count > 60 ? " · showing 60" : "");
    }

    /// <summary>Saves the rolling buffer (the last ~30 000 captured frames) to a pcapng file — instant, nothing to stop.</summary>
    [RelayCommand]
    private void RecordNow()
    {
        try
        {
            var path = _feed.Storm?.RecordNow();
            Message = path is null ? "Nothing saved — capture isn't running (press Monitor first)." : $"Saved the last captured packets to {path}" + (_feed.IsDemo ? " (demo — no file written)" : "");
            LastRecording = _feed.IsDemo ? null : path;
        }
        catch (Exception ex) { Log.Warning(ex, "Saving capture snapshot failed"); Message = "Saving failed: " + ex.Message; }
    }

    // ---- continuous start/stop recording ----
    private readonly IPacketRecorder? _recorder;
    private readonly DispatcherTimer _recTimer;
    private DateTimeOffset? _demoRecStart;

    [ObservableProperty] private bool _isRecording;
    [ObservableProperty] private string _recordButtonText = "Record";
    [ObservableProperty] private string _recordStatus = "";
    [ObservableProperty] private string? _lastRecording;

    [RelayCommand]
    private void ToggleRecording()
    {
        try
        {
            if (_feed.IsDemo)
            {
                _demoRecStart = _demoRecStart is null ? DateTimeOffset.Now : null;
                if (_demoRecStart is null) Message = "Demo recording stopped (demo — no file written).";
                UpdateRecording();
                return;
            }
            if (_recorder is null) { Message = "Recording isn't available in this build."; return; }
            if (_recorder.IsRecording)
            {
                var path = _recorder.Stop();
                LastRecording = path;
                Message = $"Recording saved: {path} ({_recorder.Frames:N0} packets, {FormatBytes(_recorder.Bytes)}).";
            }
            else
            {
                var path = _recorder.Start("recording");
                Message = path is null ? "Can't record — capture isn't running. Press Monitor first." : null;
            }
        }
        catch (Exception ex) { Log.Warning(ex, "Toggle recording failed"); Message = "Recording failed: " + ex.Message; }
        UpdateRecording();
    }

    [RelayCommand]
    private void OpenCaptures()
    {
        var target = LastRecording is { } p && File.Exists(p) ? Path.GetDirectoryName(p)! : NetSpider.Core.Services.AppPaths.Captures;
        Launcher.Open(target);
    }

    private void UpdateRecording()
    {
        bool recording = _feed.IsDemo ? _demoRecStart is not null : _recorder?.IsRecording == true;
        IsRecording = recording;
        RecordButtonText = recording ? "Stop" : "Record";
        if (recording) { if (!_recTimer.IsEnabled) _recTimer.Start(); }
        else _recTimer.Stop();

        if (_feed.IsDemo && _demoRecStart is { } ds)
        {
            var el = DateTimeOffset.Now - ds;
            RecordStatus = $"● REC {el:mm\\:ss} · {(long)(el.TotalSeconds * 275):N0} packets · {FormatBytes((long)(el.TotalSeconds * 275 * 180))} (demo)";
        }
        else if (recording && _recorder is { Started: { } st })
            RecordStatus = $"● REC {DateTimeOffset.Now - st:mm\\:ss} · {_recorder.Frames:N0} packets · {FormatBytes(_recorder.Bytes)}";
        else if (_recorder?.StopReason is { } reason && reason != "stopped" && LastRecording is null && _recorder.Path is { } p)
        {
            LastRecording = p;
            Message = $"Recording ended ({reason}): {p}";
            RecordStatus = "";
        }
        else RecordStatus = "";
    }

    private static string FormatBytes(long b) => b >= 1 << 30 ? $"{b / (double)(1 << 30):0.0} GB" : b >= 1 << 20 ? $"{b / (double)(1 << 20):0.0} MB" : $"{b / 1024.0:0} KB";

    [RelayCommand]
    private void OpenPcap(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (File.Exists(path)) Launcher.Open(path);
        else Message = _feed.IsDemo ? $"Demo storm — {System.IO.Path.GetFileName(path)} doesn't exist." : $"Capture not found: {path}";
    }

    private bool CanRunCheck() => CheckAvailable && !IsChecking;

    [RelayCommand(CanExecute = nameof(CanRunCheck))]
    private async Task RunCheck()
    {
        var center = _feed.Storm;
        if (center is null) return;
        int pps = Math.Clamp((int)(CheckPps ?? 2000), 100, 5000);
        int ms = Math.Clamp((int)((CheckSeconds ?? 2) * 1000), 500, 5000);
        CheckPps = pps;
        CheckSeconds = ms / 1000m;
        bool ok = await ConfirmDialog.ShowAsync("Run the storm-control check?",
            $"This sends a short broadcast burst of {pps:N0} pps for {ms / 1000.0:0.#} s on your network ({pps * ms / 1000:N0} frames) and watches whether your switches' storm control limits it.",
            "It may briefly affect other devices (busy CPUs on IoT gear, VoIP glitches). Safety-capped at 5 000 pps / 5 s. Never runs automatically.",
            "Send the burst");
        if (!ok) return;
        IsChecking = true;
        HasCheckResult = false;
        CheckDetails.Clear();
        CheckVerdict = "Running…";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var r = await Task.Run(() => center.RunStormControlCheckAsync(new StormControlOptions(ms, pps), cts.Token));
            CheckVerdict = r.Verdict;
            CheckBrush = !r.Ran ? Ui.Dim : r.StormControlTriggered switch { true => Ui.Green, false => Ui.Red, _ => Ui.Amber };
            if (r.Details.Count == 0) CheckDetails.Add($"Sent {r.Sent:N0} frames in {r.Duration.TotalSeconds:0.0} s");
            foreach (var d in r.Details) CheckDetails.Add(d);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Storm-control check failed");
            CheckVerdict = "Check failed: " + ex.Message;
            CheckBrush = Ui.Red;
        }
        finally
        {
            IsChecking = false;
            HasCheckResult = true;
        }
    }
}
