using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.App.Controls.Graph;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.PathDoctor;
using NetSpider.Export.Persistence;
using NetSpider.Tests.Unit.Diagnostics.PathDoctor;

namespace NetSpider.Tests.Unit.App;

/// <summary>Demo ↔ real switching: <see cref="DataModeController"/> must never let the two data sets mix.</summary>
public sealed class DataModeControllerTests : IDisposable
{
    private static readonly Mac RealMac = Mac.Parse("02:00:5E:10:00:01");
    private static readonly Mac RealMac2 = Mac.Parse("02:00:5E:10:00:02");

    private readonly DeviceStore _devices = new();
    private readonly TopologyStore _topology = new();
    private readonly AlertService _alerts = new();
    private readonly NetworkState _network = new();
    private readonly EventBus _bus = new();
    private readonly AppSettings _settings = new();
    private readonly DemoNetwork _demo;
    private readonly DiagnosticsFeed _feed;
    private readonly GraphEngine _engine;
    private readonly DataModeController _mode;
    private readonly ServiceProvider _sp;

    public DataModeControllerTests()
    {
        _sp = new ServiceCollection().AddSingleton<INetworkState>(_network).BuildServiceProvider();
        _demo = new DemoNetwork(_devices, _topology, _alerts, _network, _bus, _settings);
        _engine = new GraphEngine(_devices, _topology, _network, _alerts, _bus, _settings);
        _feed = new DiagnosticsFeed(_sp, new DemoDiagnostics(_devices, _network, _settings), _engine, _devices, _bus);
        _mode = new DataModeController(_devices, _topology, _alerts, _network, _demo, _feed, _engine);
    }

    public void Dispose()
    {
        _demo.Stop();
        _feed.Dispose();
        _engine.Dispose();
        _sp.Dispose();
    }

    /// <summary>What real monitoring would have collected: devices, a link with pair latency, alerts and network facts.</summary>
    private void SeedRealData()
    {
        _devices.Observe(RealMac, IPAddress.Parse("10.99.0.1"), "arp");
        _devices.Observe(RealMac2, IPAddress.Parse("10.99.0.2"), "arp");
        _topology.Upsert(RealMac, RealMac2, LinkKind.LldpCdp);
        _topology.SetPairLatency(new PairLatency(RealMac, RealMac2, 0.4, LatencyOrigin.Measured, "arp", DateTimeOffset.Now));
        _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.Info, "real alert", "from real monitoring", RealMac), TimeSpan.Zero);
        _network.AddOrGetSegment(IPAddress.Parse("10.99.0.0"), 24, "adapter");
        _network.AddVlan(new VlanInfo(99, "Real", "lldp", false, false));
        _network.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("10.99.0.1"), RealMac, IPAddress.Parse("10.99.0.50"), IPAddress.Parse("10.99.0.1"),
            [], null, null, DateTimeOffset.Now, false));
        _network.Wan = new WanInfo(IPAddress.Parse("203.0.113.9"), "Connected", "IP_Routed", null, null, "real", [], DateTimeOffset.Now);
        _network.WifiNetworks = [new WifiNetwork("RealSSID", Mac.Parse("02:00:5E:10:00:AA"), 6, 2437, "2.4 GHz", -50, 80, "WPA2", "n", null, true, 20, DateTimeOffset.Now)];
    }

    [Fact]
    public void Entering_demo_with_real_data_present_leaves_only_demo_data()
    {
        SeedRealData();

        _mode.EnterDemo();

        var demoMacs = _demo.BuiltMacs.ToHashSet();
        Assert.True(_network.IsDemo);
        Assert.True(_feed.IsDemo);
        Assert.True(_devices.Count > 20);
        Assert.All(_devices.All, d => Assert.Contains(d.Mac, demoMacs));
        Assert.False(_devices.TryGet(RealMac, out _));
        Assert.DoesNotContain(_alerts.Alerts, a => a.Source == RealMac || a.Title == "real alert");
        Assert.DoesNotContain(_topology.Links, l => l.Touches(RealMac));
        Assert.Null(_topology.GetPairLatency(RealMac, RealMac2));
        Assert.DoesNotContain(_network.Segments, s => s.Network.Equals(IPAddress.Parse("10.99.0.0")));
        Assert.DoesNotContain(_network.Vlans, v => v.Id == 99);
        Assert.DoesNotContain(_network.DhcpServers, d => d.ServerIp.Equals(IPAddress.Parse("10.99.0.1")));
        Assert.DoesNotContain(_network.WifiNetworks, w => w.Ssid == "RealSSID");
        Assert.NotEqual("real", _network.Wan?.Method);
    }

    [Fact]
    public void Exiting_demo_removes_every_demo_artifact()
    {
        _mode.EnterDemo();
        for (int i = 0; i < 30; i++) _demo.Tick(); // let the simulation add devices, alerts and pair latencies
        Assert.NotEmpty(_alerts.Alerts);
        Assert.NotEmpty(_topology.PairLatencies);

        var resume = _mode.ExitDemo();

        Assert.Null(resume);
        Assert.False(_network.IsDemo);
        Assert.False(_feed.IsDemo);
        Assert.False(_mode.IsDemo);
        Assert.Equal(0, _devices.Count);
        Assert.Empty(_topology.Links);
        Assert.Empty(_topology.PairLatencies);
        Assert.Empty(_alerts.Alerts);
        Assert.Empty(_network.Segments);
        Assert.Empty(_network.Vlans);
        Assert.Empty(_network.DhcpServers);
        Assert.Empty(_network.StpBridges);
        Assert.Empty(_network.Neighbors);
        Assert.Empty(_network.Fdb);
        Assert.Empty(_network.SwitchPorts);
        Assert.Empty(_network.WifiNetworks);
        Assert.Empty(_network.InternetPath);
        Assert.Null(_network.Wan);
        Assert.Null(_network.IgmpQuerier);
        Assert.Null(_network.LastTraffic);
        Assert.Empty(_network.Health.Checks);
        var c = _mode.Counts();
        Assert.Equal(0, c.DemoDevices);
        Assert.Equal(0, c.DemoAlerts);
    }

    [Fact]
    public async Task Running_demo_timers_never_rebuild_the_demo_after_exit()
    {
        _mode.EnterDemo();
        await Task.Delay(1300); // the 1 s tick and the 120 ms packet timer are running
        _mode.ExitDemo();

        // real data arriving after the switch
        _devices.Observe(RealMac, IPAddress.Parse("10.99.0.1"), "arp");
        await Task.Delay(1500);

        var d = Assert.Single(_devices.All);
        Assert.Equal(RealMac, d.Mac);
        Assert.Empty(_alerts.Alerts);
        Assert.Empty(_network.Segments);
        Assert.False(_network.IsDemo);
    }

    [Fact]
    public void Repeated_toggles_stay_clean_and_resume_adapter_is_returned_once()
    {
        var adapter = new AdapterInfo { Id = "eth", PcapName = "eth", Name = "Ethernet" };
        int resets = 0;
        _mode.ViewsReset += () => resets++;
        for (int i = 0; i < 3; i++)
        {
            SeedRealData();
            _mode.EnterDemo(i == 1 ? adapter : null);
            _mode.EnterDemo(); // idempotent
            Assert.False(_devices.TryGet(RealMac, out _));
            var demoCount = _devices.Count;
            var resume = _mode.ExitDemo();
            Assert.Null(_mode.ExitDemo()); // idempotent
            Assert.Equal(i == 1 ? adapter : null, resume);
            Assert.True(demoCount > 20);
            Assert.Equal(0, _devices.Count);
            Assert.Empty(_alerts.Alerts);
        }
        Assert.Equal(6, resets);
    }

    [Fact]
    public void Graph_layout_and_signals_are_reset_on_every_switch()
    {
        _engine.Rebuild();
        _bus.Publish(DiagnosticSignal.Create(SignalKind.LocalLinkDown, "test", "real signal"));
        Assert.Single(_feed.Signals);

        _mode.EnterDemo();
        Assert.True(_engine.Snapshot.Nodes.Length > 20);
        _bus.Publish(DiagnosticSignal.Create(SignalKind.LocalLinkDown, "test", "real signal during demo"));
        _mode.ExitDemo();

        Assert.Empty(_feed.Signals); // neither the pre-demo signal nor the one received during the demo survives
        Assert.DoesNotContain(_engine.Snapshot.Nodes, n => !SyntheticNodes.IsSynthetic(n.Mac));
        Assert.Empty(_engine.Diagnostics.Faults);
    }

    [Fact]
    public async Task Persistence_never_sees_demo_devices()
    {
        var repo = new RecordingRepository();
        using var persistence = new DevicePersistenceService(repo, _devices, _alerts, NullLogger<DevicePersistenceService>.Instance, TimeSpan.FromHours(1))
        {
            Network = _network,
            NewDeviceAlertDelay = TimeSpan.Zero,
        };
        persistence.Start();
        await persistence.Ready;

        _mode.EnterDemo();
        for (int i = 0; i < 5; i++) _demo.Tick();
        _mode.ExitDemo();
        _devices.Observe(RealMac, IPAddress.Parse("10.99.0.1"), "arp");
        await persistence.FlushAsync();

        var demoMacs = _demo.BuiltMacs.ToHashSet();
        Assert.DoesNotContain(repo.Saved.Keys, demoMacs.Contains);
        Assert.Contains(RealMac, repo.Saved.Keys);
    }

    private sealed class RecordingRepository : IDeviceRepository
    {
        public readonly ConcurrentDictionary<Mac, Device> Saved = new();
        public Task InitializeAsync(CancellationToken ct = default) => Task.CompletedTask;
        public Task<IReadOnlyList<KnownDevice>> LoadKnownAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<KnownDevice>>([]);
        public Task SaveAsync(IEnumerable<Device> devices, CancellationToken ct = default) { foreach (var d in devices) Saved[d.Mac] = d; return Task.CompletedTask; }
        public Task SaveAlertAsync(Alert alert, CancellationToken ct = default) => Task.CompletedTask;
        public Task SetUserLabelAsync(Mac mac, string? label, CancellationToken ct = default) => Task.CompletedTask;
    }
}

public sealed class DataModeStoreResetTests
{
    [Fact]
    public void NetworkState_Reset_clears_everything_raises_changes_and_keeps_IsDemo()
    {
        var n = new NetworkState { IsDemo = true };
        var mac = Mac.Parse("02:00:5E:10:00:01");
        n.AddOrGetSegment(IPAddress.Parse("10.1.0.0"), 24, "adapter");
        n.AddVlan(new VlanInfo(10, "x", "lldp", false, false));
        n.AddStp(new StpInfo("8000.1", mac, 32768, 0, "8000.1", mac, "RSTP", DateTimeOffset.Now));
        n.AddNeighbor(new NeighborEntry(mac, "p1", mac, null, "p2", "sw", null, null, null, "lldp", DateTimeOffset.Now));
        n.SetFdb(mac, [new FdbEntry(mac, "p1", 1, mac, 1, DateTimeOffset.Now)]);
        n.IgmpQuerier = mac;
        n.NicPassesVlanTags = true;
        n.InternetPath = [new TracerouteHop(1, IPAddress.Parse("10.1.0.1"), 1, null, null)];
        n.LastTraffic = new TrafficSnapshot(DateTimeOffset.Now, 1, 0, 0, 1, 64, new Dictionary<string, double>(), [], 0);
        var raised = new List<string>();
        n.Changed += raised.Add;

        n.Reset();

        Assert.Empty(n.Segments);
        Assert.Empty(n.Vlans);
        Assert.Empty(n.StpBridges);
        Assert.Empty(n.Neighbors);
        Assert.Empty(n.Fdb);
        Assert.Empty(n.InternetPath);
        Assert.Null(n.IgmpQuerier);
        Assert.Null(n.NicPassesVlanTags);
        Assert.Null(n.LastTraffic);
        Assert.True(n.IsDemo);
        Assert.Contains("segments", raised);
        Assert.Contains("wifi", raised);
        Assert.Contains("health", raised);
    }

    [Fact]
    public void TopologyStore_Clear_removes_links_and_pair_latencies()
    {
        var t = new TopologyStore();
        var a = Mac.Parse("02:00:5E:10:00:01");
        var b = Mac.Parse("02:00:5E:10:00:02");
        t.Upsert(a, b, LinkKind.LldpCdp);
        t.SetPairLatency(new PairLatency(a, b, 1, LatencyOrigin.Measured, "arp", DateTimeOffset.Now));
        int changed = 0;
        t.Changed += () => changed++;

        t.Clear();

        Assert.Empty(t.Links);
        Assert.Empty(t.PairLatencies);
        Assert.Equal(1, changed);
    }

    [Fact]
    public void Real_incident_service_ignores_input_while_the_demo_is_shown()
    {
        var o = new Office();
        var bus = new EventBus();
        var alerts = new AlertService();
        var network = new NetworkState();
        var time = new ManualTime();
        var settings = new SettingsStore(Path.Combine(Path.GetTempPath(), $"ns-mode-{Guid.NewGuid():N}.json"));
        using var svc = new IncidentService(bus, alerts, o.Devices, o.Topology, settings, NullLogger<IncidentService>.Instance, time: time, network: network);
        svc.Start(autoTick: false);

        network.IsDemo = true;
        bus.Publish(Office.Sig(SignalKind.LocalLinkDown, "Cable unplugged on Ethernet", o.Me.Mac, "Ethernet", time: time.Now));
        time.Advance(1);
        svc.Tick();
        Assert.Empty(svc.Incidents);
        Assert.Empty(alerts.Alerts);

        // back to real: a real signal opens an incident again (the demo-time signal was never recorded)
        network.IsDemo = false;
        svc.Tick();
        Assert.Empty(svc.Incidents);
        bus.Publish(Office.Sig(SignalKind.LocalLinkDown, "Cable unplugged on Ethernet", o.Me.Mac, "Ethernet", time: time.Now));
        time.Advance(1);
        svc.Tick();
        Assert.Single(svc.Active);
    }
}
