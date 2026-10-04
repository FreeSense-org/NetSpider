using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Anomaly;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics.Storm;

/// <summary>DiagnosticSignal publishing and state exposure added to the AnomalyEngine for the Storm Center.</summary>
public sealed class AnomalySignalTests : IDisposable
{
    private readonly EventBus _bus = new();
    private readonly NetworkState _network = new();
    private readonly AnomalyEngine _engine;
    private readonly List<DiagnosticSignal> _signals = new();
    private readonly DateTime _t0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    public AnomalySignalTests()
    {
        _engine = new AnomalyEngine(NullLogger<AnomalyEngine>.Instance, _bus, new AlertService(), new DeviceStore(), _network,
            new FakeFrameSource { Adapter = Adapter() }, new AppSettings { DumpPcapOnAlert = false });
        _engine.Start();
        _bus.Subscribe<DiagnosticSignal>(_signals.Add);
    }

    public void Dispose() => _engine.Dispose();

    private static TrafficSnapshot Snap(DateTime t, double total, double bcast, params TalkerStat[] talkers) =>
        new(new DateTimeOffset(t), total, bcast, 0, total - bcast, total * 200, new Dictionary<string, double>(), talkers, 0);

    private IEnumerable<DiagnosticSignal> Of(SignalKind k) => _signals.Where(s => s.Kind == k);

    [Fact]
    public void Storm_detected_once_then_ended_after_quiet_seconds()
    {
        var src = Mac.Parse("00:11:22:33:44:55");
        _bus.Publish(Snap(_t0, 2000, 1000, new TalkerStat(src, 900, 900, 0, 0)));
        Assert.Empty(Of(SignalKind.StormDetected));
        _bus.Publish(Snap(_t0.AddSeconds(1), 2000, 1000, new TalkerStat(src, 900, 900, 0, 0)));
        _bus.Publish(Snap(_t0.AddSeconds(2), 2000, 1000));
        var s = Assert.Single(Of(SignalKind.StormDetected));
        Assert.Equal(src, s.Device);
        Assert.Equal("anomaly", s.Source);
        Assert.True(_engine.GetState().StormActive);

        for (int i = 3; i < 3 + AnomalyEngine.StormEndQuietSeconds - 1; i++) _bus.Publish(Snap(_t0.AddSeconds(i), 2000, 10));
        Assert.Empty(Of(SignalKind.StormEnded));
        _bus.Publish(Snap(_t0.AddSeconds(10), 2000, 10));
        Assert.Single(Of(SignalKind.StormEnded));
        Assert.False(_engine.GetState().StormActive);
    }

    [Fact]
    public void Stp_topology_change_and_loop_signals()
    {
        var b1 = Mac.Parse("00:1B:21:00:00:01");
        _engine.OnFrame(Frame(Bpdu(b1, tc: true), _t0));
        var tc = Assert.Single(Of(SignalKind.StpTopologyChange));
        Assert.Equal(b1, tc.Device);

        var f = FrameBuilder.ArpRequest(Mac.Parse("00:11:22:AA:00:01"), IPAddress.Parse("192.168.1.66"), IPAddress.Parse("192.168.1.1"));
        for (int burst = 0; burst < 3; burst++)
            for (int i = 0; i < 3; i++) _engine.OnFrame(Frame(f, _t0.AddMilliseconds(100 * burst + i * 10)));
        Assert.Single(Of(SignalKind.LoopSuspected)); // cooldown: one signal for the ongoing loop
        var st = _engine.GetState();
        Assert.True(st.LoopBursts5s >= 2);
        Assert.Equal(Mac.Parse("00:11:22:AA:00:01"), st.LastLoopSource);
    }

    [Fact]
    public void Mac_flapping_signal_names_switch_port_and_state_lists_ports()
    {
        var sw = Mac.Parse("00:1B:21:00:00:01");
        var mac = Mac.Parse("00:11:22:33:44:55");
        foreach (var p in new[] { "Gi1/0/5", "Gi1/0/9", "Gi1/0/5", "Gi1/0/9" })
            _network.SetFdb(sw, [new FdbEntry(sw, p, null, mac, 1, DateTimeOffset.Now)]);
        var s = Assert.Single(Of(SignalKind.LoopSuspected));
        Assert.Equal(sw, s.Device);
        Assert.Equal("Gi1/0/9", s.Port);
        Assert.Contains(mac, s.Affected!);
        var flap = Assert.Single(_engine.GetState().FlappingMacs);
        Assert.Equal(3, flap.Moves);
        Assert.Equal(2, flap.Ports.Count);
    }
}
