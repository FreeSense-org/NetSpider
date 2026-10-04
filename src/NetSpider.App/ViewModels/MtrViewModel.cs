using System.Collections.ObjectModel;
using System.Net;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Rendering;
using NetSpider.Core.Abstractions;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class MtrHop : ObservableObject
{
    private readonly List<double> _ok = [];
    public required int Ttl { get; init; }
    public IPAddress? Address { get; set; }
    [ObservableProperty] private string _host = "*";
    [ObservableProperty] private int _sent;
    [ObservableProperty] private int _lost;
    [ObservableProperty] private string _loss = "0 %";
    [ObservableProperty] private string _last = "—";
    [ObservableProperty] private string _avg = "—";
    [ObservableProperty] private string _best = "—";
    [ObservableProperty] private string _worst = "—";
    [ObservableProperty] private string _jitter = "—";
    [ObservableProperty] private IBrush _lossBrush = Ui.Green;
    [ObservableProperty] private double _lossBar;

    public void Add(double? ms)
    {
        Sent++;
        if (ms is { } v) { _ok.Add(v); if (_ok.Count > 500) _ok.RemoveAt(0); Last = Neon.FormatMs(v); }
        else { Lost++; Last = "lost"; }
        double loss = 100.0 * Lost / Math.Max(1, Sent);
        Loss = $"{loss:0.#} %";
        LossBar = loss;
        LossBrush = loss == 0 ? Ui.Green : loss < 10 ? Ui.Amber : Ui.Red;
        if (_ok.Count > 0)
        {
            Avg = Neon.FormatMs(_ok.Average());
            Best = Neon.FormatMs(_ok.Min());
            Worst = Neon.FormatMs(_ok.Max());
            double j = 0;
            for (int i = 1; i < _ok.Count; i++) j += Math.Abs(_ok[i] - _ok[i - 1]);
            Jitter = _ok.Count > 1 ? Neon.FormatMs(j / (_ok.Count - 1)) : "—";
        }
    }
}

/// <summary>Live MTR: traceroute once (and every 30 cycles), then ICMP-ping every hop each second.</summary>
public sealed partial class MtrViewModel(IPAddress target, string name, ITracerouter tracer, ILatencyProber prober) : ObservableObject
{
    private CancellationTokenSource? _cts;

    /// <summary>Opens a Live MTR window for the target and starts it; the loop stops when the window closes.</summary>
    public static void Open(IPAddress target, string name, ITracerouter tracer, ILatencyProber prober)
    {
        var vm = new MtrViewModel(target, name, tracer, prober);
        var w = new NetSpider.App.Views.MtrWindow { DataContext = vm };
        w.Title = NetSpider.Core.AppInfo.WindowTitle("Live MTR") + $" → {name}"; // branding: "FreeSense – NetSpider 1.2.3 · Live MTR → host"
        w.Closed += (_, _) => vm.Stop();
        NetSpider.App.Services.Dialogs.ShowWindow(w);
        vm.Start();
    }

    public string Title => $"Live MTR → {name} ({target})";
    public ObservableCollection<MtrHop> Hops { get; } = [];
    [ObservableProperty] private string _status = "Tracing route… (a few seconds)";
    [ObservableProperty] private bool _running;
    [ObservableProperty] private int _cycles;

    public void Start()
    {
        if (Running) return;
        _cts = new CancellationTokenSource();
        Running = true;
        _ = Task.Run(() => Loop(_cts.Token));
    }

    [RelayCommand]
    public void Stop()
    {
        _cts?.Cancel();
        Running = false;
        Status = "Stopped";
    }

    [RelayCommand] private void Toggle() { if (Running) Stop(); else Start(); }

    private async Task Loop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (Cycles % 30 == 0)
                {
                    var hops = await tracer.TraceAsync(target, 30, ct);
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        foreach (var h in hops)
                        {
                            var row = Hops.FirstOrDefault(x => x.Ttl == h.Ttl);
                            if (row is null) { row = new MtrHop { Ttl = h.Ttl }; Hops.Add(row); }
                            row.Address = h.Address;
                            row.Host = h.Address is null ? "*" : h.Hostname is { } hn ? $"{hn} ({h.Address})" : h.Address.ToString();
                        }
                        Status = $"{hops.Count} hops";
                    });
                }
                var snapshot = await Dispatcher.UIThread.InvokeAsync(() => Hops.ToList());
                var results = await Task.WhenAll(snapshot.Select(async h =>
                    h.Address is null ? (h, (double?)null) : (h, await prober.IcmpPingAsync(h.Address, TimeSpan.FromSeconds(1), ct))));
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    foreach (var (h, ms) in results) h.Add(ms);
                    Cycles++;
                    Status = $"{Hops.Count} hops · {Cycles} cycles";
                });
                await Task.Delay(1000, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Warning(ex, "MTR loop failed");
            await Dispatcher.UIThread.InvokeAsync(() => { Status = "Error: " + ex.Message; Running = false; });
        }
    }
}
