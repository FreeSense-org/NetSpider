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

public sealed record TalkerRow(int Rank, string Name, string Mac, string Pps, string Broadcast, string Multicast, string Bandwidth, double Share, IBrush Brush)
{
    public double ShareWidth => 120 * Share;
}

/// <summary>Live traffic over the last 120 s from <see cref="TrafficSnapshot"/>s on the event bus.</summary>
public sealed partial class TrafficViewModel : ObservableObject
{
    public const int Window = 120;
    private readonly IDeviceStore _devices;
    private readonly AppSettings _settings;
    private readonly object _sync = new();
    private readonly Queue<TrafficSnapshot> _history = new();
    private Throttler? _throttle;

    private static readonly Color[] ProtoColors =
        new[] { "#00E5FF", "#FF2BD6", "#FFC23D", "#3DFF8B", "#9B7BFF", "#FF8A3D", "#4DD8FF", "#E9F542" }.Select(Color.Parse).ToArray();

    public TrafficViewModel(IEventBus bus, IDeviceStore devices, AppSettings settings)
    {
        _devices = devices;
        _settings = settings;
        bus.Subscribe<TrafficSnapshot>(OnSnapshot);
        Dispatcher.UIThread.Post(() => _throttle = new Throttler(TimeSpan.FromMilliseconds(1000), Refresh));
    }

    [ObservableProperty] private IReadOnlyList<ChartSeries> _totals = [];
    [ObservableProperty] private IReadOnlyList<ChartSeries> _protocols = [];
    [ObservableProperty] private double _broadcastPercent;
    [ObservableProperty] private string _broadcastText = "0 %";
    [ObservableProperty] private string _multicastText = "0 %";
    [ObservableProperty] private string _totalPps = "0";
    [ObservableProperty] private string _bandwidth = "0 kbit/s";
    [ObservableProperty] private string _dropped = "0";
    [ObservableProperty] private string _droppedDelta = "";
    [ObservableProperty] private IBrush _droppedBrush = Ui.Green;
    [ObservableProperty] private bool _hasData;
    public string StormThreshold => $"Storm threshold {_settings.StormBroadcastRatio * 100:0} % or {_settings.StormBroadcastPps:0} pps broadcast";
    public ObservableCollection<TalkerRow> TopTalkers { get; } = [];

    private void OnSnapshot(TrafficSnapshot s)
    {
        lock (_sync)
        {
            _history.Enqueue(s);
            while (_history.Count > Window) _history.Dequeue();
        }
        _throttle?.Signal();
    }

    /// <summary>Forgets the history ring (demo/real switch) so charts never show the other mode's traffic.</summary>
    public void Reset()
    {
        lock (_sync) _history.Clear();
        Totals = [];
        Protocols = [];
        BroadcastPercent = 0;
        BroadcastText = "0 %";
        MulticastText = "0 %";
        TotalPps = "0";
        Bandwidth = "0 kbit/s";
        Dropped = "0";
        DroppedDelta = "";
        DroppedBrush = Ui.Green;
        HasData = false;
        TopTalkers.Clear();
    }

    private void Refresh()
    {
        TrafficSnapshot[] h;
        lock (_sync) h = _history.ToArray();
        HasData = h.Length > 0;
        if (h.Length == 0) return;
        var last = h[^1];

        Totals =
        [
            new("Unicast", Color.Parse("#00E5FF"), h.Select(x => x.UnicastPps).ToArray()),
            new("Multicast", Color.Parse("#FF2BD6"), h.Select(x => x.MulticastPps).ToArray()),
            new("Broadcast", Color.Parse("#FFC23D"), h.Select(x => x.BroadcastPps).ToArray()),
        ];

        var top = h.SelectMany(x => x.PpsByProtocol).GroupBy(kv => kv.Key).OrderByDescending(g => g.Sum(kv => kv.Value)).Take(8).Select(g => g.Key).ToList();
        Protocols = top.Select((p, i) => new ChartSeries(p, ProtoColors[i % ProtoColors.Length],
            h.Select(x => x.PpsByProtocol.TryGetValue(p, out var v) ? v : 0).ToArray(), Fill: false)).ToArray();

        BroadcastPercent = last.BroadcastRatio * 100;
        BroadcastText = $"{last.BroadcastRatio * 100:0.0} %";
        MulticastText = $"{last.MulticastRatio * 100:0.0} %";
        TotalPps = $"{last.TotalPps:N0}";
        Bandwidth = last.BytesPerSecond * 8 >= 1_000_000 ? $"{last.BytesPerSecond * 8 / 1_000_000:0.0} Mbit/s" : $"{last.BytesPerSecond * 8 / 1000:0} kbit/s";
        Dropped = last.Dropped.ToString("N0");
        long delta = h.Length > 1 ? last.Dropped - h[0].Dropped : 0;
        DroppedDelta = delta > 0 ? $"+{delta:N0} in the last {h.Length}s" : "no drops in this window";
        DroppedBrush = delta > 0 ? Ui.Amber : Ui.Green;

        var total = Math.Max(1, last.TotalPps);
        var rows = last.TopTalkers.OrderByDescending(t => t.Pps).Take(10).Select((t, i) =>
        {
            var name = _devices.TryGet(t.Mac, out var d) ? d.DisplayName : t.Mac.ToString();
            var share = t.Pps / total;
            return new TalkerRow(i + 1, name, t.Mac.ToString(), $"{t.Pps:0.#}", $"{t.BroadcastPps:0.#}", $"{t.MulticastPps:0.#}",
                t.Bps * 8 >= 1_000_000 ? $"{t.Bps * 8 / 1_000_000:0.0} Mbit/s" : $"{t.Bps * 8 / 1000:0.#} kbit/s",
                share, t.Pps >= _settings.TopTalkerPps ? Ui.Red : t.BroadcastPps > _settings.StormPerMacPps * 0.5 ? Ui.Amber : Ui.Cyan);
        }).ToList();
        TopTalkers.Clear();
        foreach (var r in rows) TopTalkers.Add(r);
    }
}
