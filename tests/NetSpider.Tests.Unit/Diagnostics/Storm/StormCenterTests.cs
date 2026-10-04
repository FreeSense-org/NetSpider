using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Anomaly;
using NetSpider.Diagnostics.Storm;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics.Storm;

public sealed class StormCenterTests : IDisposable
{
    private static readonly Mac Sw = Mac.Parse("00:1B:21:00:00:01");
    private static readonly Mac Printer = Mac.Parse("00:11:22:33:44:55");
    private static readonly DateTime T0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    private readonly EventBus _bus = new();
    private readonly DeviceStore _devices = new();
    private readonly NetworkState _network = new();
    private readonly TopologyStore _topology = new();
    private readonly StormFakeFrameSource _source = new() { Adapter = Adapter(), IsRunning = true };
    private readonly AppSettings _settings = new() { DumpPcapOnAlert = true };
    private readonly FakePortHealthMonitor _ports = new();
    private readonly FakeServiceProvider _sp = new();
    private readonly StormFrameTally _tally;
    private readonly StormCenter _center;

    public StormCenterTests()
    {
        _tally = new StormFrameTally(_source, _devices);
        _sp.Add<IPortHealthMonitor>(_ports);
        _center = new StormCenter(NullLogger<StormCenter>.Instance, _bus, _devices, _network, _topology, _source, _settings, _tally, _sp)
        {
            CounterSettleDelay = TimeSpan.Zero,
            CounterRecheckDelay = TimeSpan.Zero,
        };
        _center.Start();
        AddDevice(_devices, Sw.ToString(), "192.168.1.2", name: "core-sw-01");
        AddDevice(_devices, Printer.ToString(), "192.168.1.50", name: "printer");
    }

    public void Dispose()
    {
        _center.Dispose();
        try { Directory.Delete(_source.DumpDir, true); } catch { }
    }

    private static TrafficSnapshot Snap(DateTime t, double total, double bcast, double mcast = 0) =>
        new(new DateTimeOffset(t), total, bcast, mcast, total - bcast - mcast, total * 200, new Dictionary<string, double> { ["TCP"] = total - bcast - mcast }, [], 0);

    private void ArpFlood(Mac src, int n)
    {
        for (int i = 0; i < n; i++)
            _tally.OnFrame(Frame(FrameBuilder.ArpRequest(src, IPAddress.Parse("192.168.1.50"), IPAddress.Parse($"192.168.1.{i % 200 + 1}")), T0));
    }

    [Fact]
    public void Storm_status_lists_sources_with_dominant_protocol_and_fdb_location()
    {
        _network.SetFdb(Sw, [new FdbEntry(Sw, "7", null, Printer, 1, DateTimeOffset.Now)]);
        ArpFlood(Printer, 300);
        var other = Mac.Parse("00:11:22:33:44:66");
        for (int i = 0; i < 20; i++)
            _tally.OnFrame(Frame(Udp4(other, Mac.Parse("01:00:5E:00:00:FB"), "192.168.1.60", "224.0.0.251", 5353, 5353), T0));
        // unknown unicast: to a MAC nobody knows
        _tally.OnFrame(Frame(Udp4(other, Mac.Parse("00:99:99:99:99:99"), "192.168.1.60", "192.168.1.99", 1, 2), T0));

        StormStatus? updated = null;
        _center.Updated += s => updated = s;
        _bus.Publish(Snap(T0, 1000, 600));

        var s = _center.Status;
        Assert.Same(s, updated);
        Assert.Equal(StormLevel.Storm, s.Level);
        Assert.True(s.UnknownUnicastPps > 0);
        var top = s.Sources[0];
        Assert.Equal(Printer, top.Mac);
        Assert.Equal("printer", top.Name);
        Assert.Equal("ARP", top.DominantProtocol);
        Assert.Equal(Sw, top.Switch);
        Assert.Equal("7", top.Port);
        Assert.Equal("core-sw-01 port 7", top.Location);
        Assert.Equal("mDNS", s.Sources[1].DominantProtocol);
        Assert.True(s.PpsByProtocol["ARP"] > s.PpsByProtocol["mDNS"]);
    }

    [Fact]
    public void Storm_event_starts_after_two_seconds_dumps_pcap_and_ends_after_calm()
    {
        _bus.Publish(Snap(T0, 1000, 600));
        Assert.Empty(_center.History);
        _bus.Publish(Snap(T0.AddSeconds(1), 1000, 700));
        var ev = Assert.Single(_center.History);
        Assert.Null(ev.End);
        Assert.Equal(700, ev.PeakPps);
        Assert.Contains("Broadcast storm", ev.Summary);

        SpinWait.SpinUntil(() => _center.History[0].PcapPath is not null, 2000);
        Assert.Equal(1, _source.Dumps);
        Assert.Contains("storm", _center.History[0].PcapPath);

        for (int i = 2; i < 2 + StormCenter.StormEndSeconds; i++) _bus.Publish(Snap(T0.AddSeconds(i), 1000, 5));
        Assert.NotNull(Assert.Single(_center.History).End);
        Assert.Equal(StormLevel.Normal, _center.Status.Level);
    }

    [Fact]
    public void No_pcap_dump_when_disabled()
    {
        _settings.DumpPcapOnAlert = false;
        _bus.Publish(Snap(T0, 1000, 600));
        _bus.Publish(Snap(T0.AddSeconds(1), 1000, 600));
        Thread.Sleep(50);
        Assert.Single(_center.History);
        Assert.Equal(0, _source.Dumps);
    }

    [Fact]
    public void Ingress_ports_are_ordered_and_uplinks_annotated()
    {
        var fdb = Enumerable.Range(0, 12).Select(i => new FdbEntry(Sw, "24", null, Mac.Parse($"00:AA:00:00:00:{i:X2}"), 1, DateTimeOffset.Now))
            .Append(new FdbEntry(Sw, "7", null, Printer, 1, DateTimeOffset.Now)).ToArray();
        _network.SetFdb(Sw, fdb);
        _ports.List.Add(FakePortHealthMonitor.Port(Sw, "24", 300));
        _ports.List.Add(FakePortHealthMonitor.Port(Sw, "7", 3000));
        _ports.List.Add(FakePortHealthMonitor.Port(Sw, "3", 1));
        _bus.Publish(Snap(T0, 1000, 10));
        var ingress = _center.Status.Ingress;
        Assert.Equal(2, ingress.Count);
        Assert.Equal("7", ingress[0].Port);
        Assert.Equal("core-sw-01", ingress[0].SwitchName);
        Assert.Contains("printer", ingress[0].Note);
        Assert.Contains("uplink", ingress[1].Note);
    }

    [Fact]
    public void Loop_suspects_from_port_ingress_and_anomaly_state_publish_a_signal()
    {
        var anomaly = new AnomalyEngine(NullLogger<AnomalyEngine>.Instance, _bus, new AlertService(), _devices, _network, _source, _settings);
        _sp.Add(anomaly);
        var signals = new List<DiagnosticSignal>();
        _bus.Subscribe<DiagnosticSignal>(signals.Add);
        _ports.List.Add(FakePortHealthMonitor.Port(Sw, "5", 4200));
        _ports.List.Add(FakePortHealthMonitor.Port(Sw, "9", 4000));
        // MAC flapping between the same ports, via the anomaly engine's FDB tracking
        anomaly.Start();
        foreach (var p in new[] { "5", "9", "5", "9" }) _network.SetFdb(Sw, [new FdbEntry(Sw, p, null, Printer, 1, DateTimeOffset.Now)]);

        _bus.Publish(Snap(T0, 1000, 10));
        var loop = _center.Status.Loops[0];
        Assert.Equal(Sw, loop.Switch);
        Assert.Equal(["5", "9"], loop.Ports.Order().ToArray());
        Assert.Contains(Printer, loop.FlappingMacs);
        Assert.StartsWith("Loop suspected between core-sw-01 port", loop.Description);
        Assert.True(loop.Confidence >= 0.6);
        Assert.Contains(signals, s => s.Kind == SignalKind.LoopSuspected && s.Source == "storm-center" && s.Device == Sw);
        anomaly.Dispose();
    }

    [Fact]
    public void Record_now_dumps_and_writes_summary_only_while_capturing()
    {
        _bus.Publish(Snap(T0, 1000, 600));
        var path = _center.RecordNow();
        Assert.NotNull(path);
        Assert.True(File.Exists(Path.ChangeExtension(path, ".summary.txt")));
        _source.IsRunning = false;
        Assert.Null(_center.RecordNow());
    }

    // ---------------------------------------------------------------- storm-control check

    [Fact]
    public async Task Storm_control_check_is_gated_by_setting_and_capture()
    {
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(200, 1000), CancellationToken.None);
        Assert.False(r.Ran);
        Assert.Contains("disabled", r.Verdict);
        Assert.Equal(0, _source.SentCount);

        _settings.StormControlCheckEnabled = true;
        _source.IsRunning = false;
        r = await _center.RunStormControlCheckAsync(new StormControlOptions(200, 1000), CancellationToken.None);
        Assert.False(r.Ran);
        Assert.Contains("Capture is not running", r.Verdict);
        Assert.Equal(0, _source.SentCount);
        Assert.Contains(r.Details, d => d.Contains("5000 pps"));
    }

    private void OnSwitchPort7(Func<int, PortCounterSample> afterBurst)
    {
        _settings.StormControlCheckEnabled = true;
        _network.SetFdb(Sw, [new FdbEntry(Sw, "7", null, LocalMac, 1, DateTimeOffset.Now)]);
        int calls = 0;
        Func<Mac, string, CancellationToken, Task<PortCounterSample?>> reader = (sw, port, ct) =>
        {
            Assert.Equal(Sw, sw);
            Assert.Equal("7", port);
            var s = calls++ == 0 ? Counters(0, 0) : afterBurst(_source.SentCount);
            return Task.FromResult<PortCounterSample?>(s);
        };
        _sp.Add(reader);
    }

    private static PortCounterSample Counters(ulong bcast, ulong discards, bool up = true) =>
        new(Sw, 7, "7", DateTimeOffset.Now, up, 1000, "full", null, 0, 0, 0, 0, 1000 + discards, 0, 50_000 + bcast, 0, 0, 0, 0, 0, 0);

    [Fact]
    public async Task Storm_control_triggered_when_switch_discards_the_burst()
    {
        OnSwitchPort7(sent => Counters((ulong)sent, (ulong)(sent * 0.7)));
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(DurationMs: 200, Pps: 1000), CancellationToken.None);
        Assert.True(r.Ran);
        Assert.Equal(200, r.Sent);
        Assert.True(r.StormControlTriggered);
        Assert.Contains("discarded", r.Verdict);
        Assert.Contains(r.Details, d => d.Contains("core-sw-01 port 7"));
        Assert.Contains(r.Details, d => d.StartsWith("Safety limits"));
    }

    [Fact]
    public async Task Storm_control_not_triggered_when_switch_accepts_everything()
    {
        OnSwitchPort7(sent => Counters((ulong)sent + 3, 0));
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(DurationMs: 200, Pps: 1000), CancellationToken.None);
        Assert.True(r.Ran);
        Assert.False(r.StormControlTriggered);
        Assert.StartsWith("No storm-control reaction", r.Verdict);
    }

    [Fact]
    public async Task Storm_control_triggered_when_the_port_shuts()
    {
        OnSwitchPort7(sent => Counters(10, 0, up: false));
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(DurationMs: 200, Pps: 1000), CancellationToken.None);
        Assert.True(r.StormControlTriggered);
        Assert.Contains("err-disable", r.Verdict);
    }

    [Fact]
    public async Task Storm_control_verdict_is_unknown_without_snmp_data()
    {
        _settings.StormControlCheckEnabled = true;
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(DurationMs: 200, Pps: 1000), CancellationToken.None);
        Assert.True(r.Ran);
        Assert.Null(r.StormControlTriggered);
        Assert.StartsWith("Unknown", r.Verdict);
    }

    [Fact]
    public async Task Storm_control_burst_is_capped_and_uses_harmless_arp_for_an_unused_address()
    {
        _settings.StormControlCheckEnabled = true;
        var r = await _center.RunStormControlCheckAsync(new StormControlOptions(DurationMs: 300, Pps: 1_000_000, VlanId: 20), CancellationToken.None);
        Assert.True(r.Ran);
        Assert.InRange(r.Sent, 1, 5000 * 300 / 1000);
        Assert.Contains(r.Details, d => d.Contains("capped to 5000 pps"));

        var used = new HashSet<IPAddress>(_devices.All.SelectMany(d => d.IPv4)) { IPAddress.Parse("192.168.1.10"), IPAddress.Parse("192.168.1.1") };
        foreach (var f in _source.Sent.Take(20))
        {
            var eth = EthernetView.Parse(f);
            Assert.True(eth.Destination.IsBroadcast);
            Assert.Equal(LocalMac, eth.Source);
            Assert.Equal(EthernetView.Arp, eth.EtherType);
            Assert.Equal(20, eth.VlanId);
            var target = new IPAddress(f.AsSpan(eth.PayloadOffset + 24, 4));
            Assert.DoesNotContain(target, used);
            Assert.StartsWith("192.168.1.", target.ToString());
        }
    }

    [Fact]
    public void Unused_address_skips_known_devices_and_gateway()
    {
        AddDevice(_devices, "00:11:22:33:44:01", "192.168.1.254");
        var a = _center.PickUnusedAddress(new IpWithPrefix(IPAddress.Parse("192.168.1.10"), 24), IPAddress.Parse("192.168.1.253"));
        Assert.Equal(IPAddress.Parse("192.168.1.252"), a);
        Assert.Null(_center.PickUnusedAddress(new IpWithPrefix(IPAddress.Parse("10.0.0.1"), 31), null));
    }
}
