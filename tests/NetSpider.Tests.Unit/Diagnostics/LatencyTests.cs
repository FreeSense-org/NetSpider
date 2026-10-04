using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Latency;
using NetSpider.Diagnostics.Topology;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics;

public sealed class PairLatencyTests
{
    private static readonly Mac A = Mac.Parse("00:11:22:00:00:01"), B = Mac.Parse("00:11:22:00:00:02"),
        C = Mac.Parse("00:11:22:00:00:03"), D = Mac.Parse("00:11:22:00:00:04"), E = Mac.Parse("00:11:22:00:00:05");

    private static Link L(Mac a, Mac b, double? ms, LinkKind k = LinkKind.BridgeFdb) => new(a, b, k) { LatencyMs = ms };

    [Fact]
    public void Path_sum_picks_cheapest_route()
    {
        // A-B-D costs 0.3+0.4 = 0.7; A-C-D costs 0.1+0.2 = 0.3
        var links = new[] { L(A, B, 0.3), L(B, D, 0.4), L(A, C, 0.1), L(C, D, 0.2) };
        var r = PathLatency.ShortestPath(links, A, D);
        Assert.NotNull(r);
        Assert.Equal(0.3, r!.Ms, 6);
        Assert.Equal(2, r.Hops);
        Assert.Equal([A, C, D], r.Path);
    }

    [Fact]
    public void Path_sum_uses_default_for_unknown_links_and_null_when_disconnected()
    {
        var links = new[] { L(A, B, 1.0), L(B, C, null) };
        Assert.Equal(1.1, PathLatency.ShortestPath(links, A, C)!.Ms, 6);
        Assert.Null(PathLatency.ShortestPath(links, A, E));
        Assert.Equal(0, PathLatency.ShortestPath(links, A, A)!.Ms);
    }

    [Fact]
    public void Edge_estimate_is_rtt_difference_with_floor_and_this_host_counts_as_zero()
    {
        var parent = new Device(A); parent.Latency.Add(LatencyKind.Arp, 0.30);
        var child = new Device(B); child.Latency.Add(LatencyKind.Arp, 1.25);
        var twin = new Device(C); twin.Latency.Add(LatencyKind.Arp, 0.31);
        var me = new Device(LocalMac);
        Assert.Equal(0.95, LinkLatencyCalculator.EstimateEdge(parent, child, LocalMac)!.Value, 6);
        Assert.Equal(LinkLatencyCalculator.FloorMs, LinkLatencyCalculator.EstimateEdge(parent, twin, LocalMac));
        Assert.Equal(0.30, LinkLatencyCalculator.EstimateEdge(me, parent, LocalMac)!.Value, 6);
        Assert.Null(LinkLatencyCalculator.EstimateEdge(parent, new Device(D), LocalMac));
    }

    [Fact]
    public void Measured_pair_latency_overrides_estimate()
    {
        var a = new Device(A); a.Latency.Add(LatencyKind.Icmp, 1);
        var b = new Device(B); b.Latency.Add(LatencyKind.Icmp, 5);
        var map = new Dictionary<Mac, Device> { [A] = a, [B] = b };
        var link = L(A, B, null);
        var measured = new PairLatency(A, B, 0.7, LatencyOrigin.Measured, "snmp-ping", DateTimeOffset.Now);

        LinkLatencyCalculator.Apply([link], m => map.GetValueOrDefault(m), LocalMac, (_, _) => null);
        Assert.Equal(4, link.LatencyMs);
        Assert.Equal(LatencyOrigin.Estimated, link.LatencyOrigin);

        Assert.True(LinkLatencyCalculator.Apply([link], m => map.GetValueOrDefault(m), LocalMac, (_, _) => measured));
        Assert.Equal(0.7, link.LatencyMs);
        Assert.Equal(LatencyOrigin.Measured, link.LatencyOrigin);
    }

    private sealed class FakeRemotePinger(double? ms) : IRemotePinger
    {
        public int Calls;
        public Task<double?> PingFromAsync(Device from, IPAddress target, CancellationToken ct) { Calls++; return Task.FromResult(ms); }
    }

    private static (LatencyEngine Engine, DeviceStore Devices, TopologyStore Topo) Engine(IRemotePinger? pinger = null)
    {
        var devices = new DeviceStore();
        var topo = new TopologyStore();
        var sp = new FakeServiceProvider();
        if (pinger is not null) sp.Add(pinger);
        var e = new LatencyEngine(NullLogger<LatencyEngine>.Instance, sp, devices, topo, new AlertService(), new AppSettings());
        return (e, devices, topo);
    }

    [Fact]
    public async Task MeasurePair_falls_back_to_topology_estimate_and_stores_it()
    {
        var (engine, devices, topo) = Engine();
        devices.GetOrAdd(A); devices.GetOrAdd(B); devices.GetOrAdd(C);
        topo.ReplaceAll([L(A, B, 0.4), L(B, C, 1.6)]);

        var p = await engine.MeasurePairAsync(A, C, CancellationToken.None);
        Assert.NotNull(p);
        Assert.Equal(LatencyOrigin.Estimated, p!.Origin);
        Assert.Equal(2.0, p.Ms, 6);
        Assert.Same(p, topo.GetPairLatency(C, A));
    }

    [Fact]
    public async Task MeasurePair_uses_remote_pinger_when_source_speaks_snmp()
    {
        var pinger = new FakeRemotePinger(0.42);
        var (engine, devices, topo) = Engine(pinger);
        var sw = devices.GetOrAdd(A);
        sw.AddEvidence("snmp", Fields.Description, "Cisco IOS Software", Confidence.Snmp);
        devices.Observe(B, IPAddress.Parse("192.168.1.20"), "arp");
        topo.ReplaceAll([L(A, B, 3)]);

        var p = await engine.MeasurePairAsync(A, B, CancellationToken.None);
        Assert.Equal(1, pinger.Calls);
        Assert.Equal(LatencyOrigin.Measured, p!.Origin);
        Assert.Equal("snmp-ping", p.Method);
        Assert.Equal(0.42, p.Ms);
    }

    [Fact]
    public async Task MeasurePair_does_not_overwrite_recent_measurement_with_estimate()
    {
        var (engine, devices, topo) = Engine();
        devices.GetOrAdd(A); devices.GetOrAdd(B);
        topo.ReplaceAll([L(A, B, 5)]);
        topo.SetPairLatency(new PairLatency(A, B, 0.9, LatencyOrigin.Measured, "passive-tcp", DateTimeOffset.Now));
        var p = await engine.MeasurePairAsync(A, B, CancellationToken.None);
        Assert.Equal(0.9, p!.Ms);
        Assert.Equal(LatencyOrigin.Measured, topo.GetPairLatency(A, B)!.Origin);
    }

    private sealed class FakeProber : ILatencyProber
    {
        public Func<IPAddress, double?> Arp = _ => 0.3, Icmp = _ => 0.8;
        public int ArpCalls, IcmpCalls, NdpCalls;
        public Task<(double? Ms, Mac? Mac)> ArpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct) { Interlocked.Increment(ref ArpCalls); return Task.FromResult<(double?, Mac?)>((Arp(ip), null)); }
        public Task<double?> NdpPingAsync(IPAddress ipv6, Mac? knownMac, TimeSpan timeout, CancellationToken ct) { Interlocked.Increment(ref NdpCalls); return Task.FromResult<double?>(0.2); }
        public Task<double?> IcmpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct, int payloadSize = 32, bool dontFragment = false) { Interlocked.Increment(ref IcmpCalls); return Task.FromResult(Icmp(ip)); }
        public Task<double?> TcpPingAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct) => Task.FromResult<double?>(1.0);
    }

    [Fact]
    public async Task Cycle_uses_arp_and_icmp_on_subnet_icmp_only_off_subnet_and_ndp_for_ipv6_only()
    {
        var devices = new DeviceStore();
        var topo = new TopologyStore();
        var alerts = new AlertService();
        var prober = new FakeProber();
        var sp = new FakeServiceProvider().Add<ILatencyProber>(prober);
        var engine = new LatencyEngine(NullLogger<LatencyEngine>.Instance, sp, devices, topo, alerts, new AppSettings());
        var local = AddDevice(devices, "00:11:22:00:00:10", "192.168.1.20");
        var remote = AddDevice(devices, "00:11:22:00:00:11", "10.9.9.9");
        var v6 = devices.GetOrAdd(Mac.Parse("00:11:22:00:00:12"));
        v6.AddIp(IPAddress.Parse("fe80::211:22ff:fe00:12"));
        devices.GetOrAdd(SyntheticNodes.Internet).Type = DeviceType.Internet;

        var ctx = Context();
        await engine.RunCycleAsync(ctx, CancellationToken.None);

        Assert.Equal(0.3, local.Latency.Last(LatencyKind.Arp));
        Assert.Equal(0.8, local.Latency.Last(LatencyKind.Icmp));
        Assert.Empty(remote.Latency.GetSeries(LatencyKind.Arp));
        Assert.Equal(0.8, remote.Latency.Last(LatencyKind.Icmp));
        Assert.Equal(0.2, v6.Latency.Last(LatencyKind.Ndp));
        Assert.Equal(1, prober.ArpCalls);
        Assert.Equal(2, prober.IcmpCalls);
        Assert.Equal(1, prober.NdpCalls);
    }

    [Fact]
    public async Task Lost_probes_are_recorded_and_raise_packet_loss_and_count_failed_cycles()
    {
        var devices = new DeviceStore();
        var alerts = new AlertService();
        int n = 0;
        var prober = new FakeProber { Arp = _ => Interlocked.Increment(ref n) % 2 == 0 ? null : 0.4, Icmp = _ => null };
        var engine = new LatencyEngine(NullLogger<LatencyEngine>.Instance, new FakeServiceProvider().Add<ILatencyProber>(prober), devices, new TopologyStore(), alerts, new AppSettings());
        var d = AddDevice(devices, "00:11:22:00:00:20", "192.168.1.30");
        var ctx = Context();
        for (int i = 0; i < 20; i++) await engine.RunCycleAsync(ctx, CancellationToken.None);

        var arp = d.Latency.Summarize(LatencyKind.Arp, 20);
        Assert.Equal(50, arp.LossPercent);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.PacketLoss && a.Source == d.Mac);

        prober.Arp = _ => null;
        for (int i = 0; i < 3; i++) await engine.RunCycleAsync(ctx, CancellationToken.None);
        Assert.True(engine.ConsecutiveFailedCycles(d.Mac) >= 3);
    }

    [Fact]
    public void Spike_and_loss_rules()
    {
        var t = DateTimeOffset.Now;
        LatencySample S(double? ms) => new(t, LatencyKind.Icmp, ms);
        var calm = Enumerable.Repeat(S(10), 10).ToList();
        Assert.Null(LatencyAlerts.Evaluate([.. calm, S(25)], 50).Spike);       // < 3x median
        Assert.Null(LatencyAlerts.Evaluate([.. calm, S(40)], 50).Spike);       // 4x but below LatencyBadMs
        var spike = LatencyAlerts.Evaluate([.. calm, S(120)], 50).Spike;
        Assert.NotNull(spike);
        Assert.Equal(10, spike!.Value.Median);

        var lossy = Enumerable.Range(0, 20).Select(i => S(i % 4 == 0 ? null : 1.0)).ToList(); // 25% loss
        Assert.Equal(25, LatencyAlerts.Evaluate(lossy, 50).LossPercent);
        var ok = Enumerable.Range(0, 20).Select(i => S(i % 10 == 0 ? null : 1.0)).ToList();  // 10% loss
        Assert.Null(LatencyAlerts.Evaluate(ok, 50).LossPercent);
        Assert.Null(LatencyAlerts.Evaluate(Enumerable.Repeat(S(null), 20).ToList(), 50).LossPercent); // filtered
    }
}

public sealed class PassiveTcpRttTrackerTests
{
    private static readonly Mac Client = Mac.Parse("00:11:22:33:44:01"), Server = Mac.Parse("00:11:22:33:44:02");
    private readonly TopologyStore _topology = new();
    private readonly DeviceStore _devices = new();
    private readonly NetworkState _network = new();
    private readonly FakeFrameSource _source = new() { Adapter = Adapter() };
    private readonly PassiveTcpRttTracker _tracker;
    private readonly DateTime _t0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    public PassiveTcpRttTrackerTests()
    {
        _tracker = new PassiveTcpRttTracker(NullLogger<PassiveTcpRttTracker>.Instance, _topology, _devices, _network, _source);
    }

    private void Handshake(Mac cm, Mac sm, string cip, string sip, double serverMs, double clientMs, bool v6 = false, int cport = 50123)
    {
        Func<Mac, Mac, string, string, int, int, uint, uint, byte, byte[]> mk = v6 ? Tcp6 : Tcp4;
        var t1 = _t0;
        var t2 = t1.AddTicks((long)(serverMs * TimeSpan.TicksPerMillisecond));
        var t3 = t2.AddTicks((long)(clientMs * TimeSpan.TicksPerMillisecond));
        _tracker.OnFrame(Frame(mk(cm, sm, cip, sip, cport, 443, 1000, 0, 0x02), t1));
        _tracker.OnFrame(Frame(mk(sm, cm, sip, cip, 443, cport, 5000, 1001, 0x12), t2));
        _tracker.OnFrame(Frame(mk(cm, sm, cip, sip, cport, 443, 1001, 5001, 0x10), t3));
    }

    [Fact]
    public void Third_party_handshake_yields_measured_pair_latency_as_sum_of_both_halves()
    {
        Handshake(Client, Server, "192.168.1.20", "192.168.1.30", serverMs: 0.4, clientMs: 0.6);
        var p = _topology.GetPairLatency(Server, Client);
        Assert.NotNull(p);
        Assert.Equal(LatencyOrigin.Measured, p!.Origin);
        Assert.Equal("passive-tcp", p.Method);
        Assert.Equal(1.0, p.Ms, 3);
        Assert.Equal(0, _tracker.PendingCount);
        Assert.Equal(p, _tracker.TryGet(Client, Server));
    }

    [Fact]
    public void Ipv6_handshake_is_timed()
    {
        Handshake(Client, Server, "fe80::1", "fe80::2", 1.5, 0.5, v6: true);
        Assert.Equal(2.0, _topology.GetPairLatency(Client, Server)!.Ms, 3);
    }

    [Fact]
    public void Handshake_involving_this_host_is_not_stored_as_pair()
    {
        double? serverRtt = null;
        _tracker.HandshakeTimed += (_, _, s, _) => serverRtt = s;
        Handshake(LocalMac, Server, "192.168.1.10", "192.168.1.30", 0.7, 0.01);
        Assert.Equal(0.7, serverRtt!.Value, 3);
        Assert.Empty(_topology.PairLatencies);
    }

    [Fact]
    public void Off_subnet_server_behind_router_is_ignored_unless_it_is_the_gateway()
    {
        var gw = AddDevice(_devices, "00:0D:B9:00:00:01", "192.168.1.1", DeviceType.Router, DeviceFlags.Gateway);
        Handshake(Client, gw.Mac, "192.168.1.20", "142.250.1.1", 12, 0.5); // Internet server via router MAC
        Assert.Empty(_topology.PairLatencies);
        Handshake(Client, gw.Mac, "192.168.1.20", "192.168.1.1", 0.8, 0.5, cport: 50200); // the gateway itself
        Assert.Equal(1.3, _topology.GetPairLatency(Client, gw.Mac)!.Ms, 3);
    }

    [Fact]
    public void Retransmitted_syn_is_not_measured()
    {
        var t = _t0;
        _tracker.OnFrame(Frame(Tcp4(Client, Server, "192.168.1.20", "192.168.1.30", 40000, 80, 7, 0, 0x02), t));
        _tracker.OnFrame(Frame(Tcp4(Client, Server, "192.168.1.20", "192.168.1.30", 40000, 80, 7, 0, 0x02), t.AddSeconds(1)));
        _tracker.OnFrame(Frame(Tcp4(Server, Client, "192.168.1.30", "192.168.1.20", 80, 40000, 99, 8, 0x12), t.AddSeconds(1.001)));
        _tracker.OnFrame(Frame(Tcp4(Client, Server, "192.168.1.20", "192.168.1.30", 40000, 80, 8, 100, 0x10), t.AddSeconds(1.002)));
        Assert.Empty(_topology.PairLatencies);
    }

    [Fact]
    public void Half_open_table_is_bounded()
    {
        for (int i = 0; i < PassiveTcpRttTracker.MaxHalfOpen + 500; i++)
            _tracker.OnFrame(Frame(Tcp4(Client, Server, "192.168.1.20", "192.168.1.30", 1024 + i % 60000, 80 + i / 60000, (uint)i, 0, 0x02), _t0));
        Assert.Equal(PassiveTcpRttTracker.MaxHalfOpen, _tracker.PendingCount);
    }
}
