using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Wifi;

namespace NetSpider.Tests.Unit.Diagnostics.WifiDiag;

public sealed class ApDiagnosisTests
{
    private static ApObservation Obs(bool? mgmt = true, bool? upstream = true, int seen = 5, int unreachable = 0, int outageSec = 0,
        double loss = 0, double? jitter = null, int? channel = 6, int otherBss = 0, bool hostOnAp = false, bool? radioOk = null, bool? gwOk = null) =>
        new("ap-office", mgmt, mgmt == true ? 1.2 : null, upstream, "core-sw-01", "Gi1/0/7", seen, unreachable, seen - unreachable, TimeSpan.FromSeconds(outageSec),
            loss, jitter, 12, channel, otherBss, hostOnAp, radioOk, gwOk);

    [Fact]
    public void Healthy_ap_is_up() =>
        Assert.Equal(new ApVerdict(HopHealth.Up, null, null), ApDiagnosis.Evaluate(Obs()));

    [Fact]
    public void Ap_up_with_most_clients_unreachable_for_30s_is_a_radio_problem()
    {
        var v = ApDiagnosis.Evaluate(Obs(seen: 5, unreachable: 4, outageSec: 30));
        Assert.Equal(HopHealth.Down, v.Health);
        Assert.Equal(SignalKind.ApClientsUnreachable, v.Signal);
        Assert.StartsWith("AP radio/SSID problem — wired side OK", v.Diagnosis);
        Assert.Contains("4 of 5", v.Diagnosis);
    }

    [Theory]
    [InlineData(5, 4, 29)] // not long enough
    [InlineData(5, 3, 60)] // 60% < 70%
    [InlineData(1, 1, 60)] // a single (sleeping?) phone is not evidence
    public void Client_outage_needs_fraction_hold_and_enough_clients(int seen, int unreachable, int sec) =>
        Assert.NotEqual(SignalKind.ApClientsUnreachable, ApDiagnosis.Evaluate(Obs(seen: seen, unreachable: unreachable, outageSec: sec)).Signal);

    [Fact]
    public void Ap_down_with_upstream_up_points_at_power_or_port()
    {
        var v = ApDiagnosis.Evaluate(Obs(mgmt: false, unreachable: 5));
        Assert.Equal(HopHealth.Down, v.Health);
        Assert.Equal(SignalKind.ApDown, v.Signal);
        Assert.Equal("AP down — check AP power/PoE or its switch port core-sw-01 Gi1/0/7", v.Diagnosis);
        Assert.True(v.Weight >= 0.8);
    }

    [Fact]
    public void Ap_down_with_upstream_down_does_not_blame_the_ap()
    {
        var v = ApDiagnosis.Evaluate(Obs(mgmt: false, upstream: false, unreachable: 5));
        Assert.Equal(HopHealth.Down, v.Health);
        Assert.Null(v.Signal);
        Assert.Contains("upstream core-sw-01 is down", v.Diagnosis);
    }

    [Fact]
    public void Silent_management_with_reachable_clients_is_filtered_ping()
    {
        var v = ApDiagnosis.Evaluate(Obs(mgmt: false, seen: 4, unreachable: 1));
        Assert.Equal(HopHealth.Up, v.Health);
        Assert.Null(v.Signal);
    }

    [Fact]
    public void High_loss_is_rf_or_congestion_with_channel_evidence()
    {
        var v = ApDiagnosis.Evaluate(Obs(loss: 40, jitter: 90, otherBss: 9));
        Assert.Equal(HopHealth.Degraded, v.Health);
        Assert.Equal(SignalKind.ApDegraded, v.Signal);
        Assert.Equal("RF/interference or congestion: 40% client loss, 90 ms jitter, channel 6 shared with 9 other BSSIDs (congested)", v.Diagnosis);
    }

    [Fact]
    public void Host_radio_ok_but_gateway_unreachable_is_backhaul()
    {
        var v = ApDiagnosis.Evaluate(Obs(hostOnAp: true, radioOk: true, gwOk: false));
        Assert.Equal(HopHealth.Degraded, v.Health);
        Assert.Equal(SignalKind.ApDegraded, v.Signal);
        Assert.Equal("Wireless OK, backhaul from AP to router failing", v.Diagnosis);
        // not on this AP: rule does not apply
        Assert.Null(ApDiagnosis.Evaluate(Obs(hostOnAp: false, radioOk: true, gwOk: false)).Signal);
    }

    [Fact]
    public void Nothing_to_probe_is_unknown() =>
        Assert.Equal(HopHealth.Unknown, ApDiagnosis.Evaluate(Obs(mgmt: null, seen: 0)).Health);
}

public sealed class ApHealthMonitorTests
{
    private static readonly Mac ApMac = Mac.Parse("74:83:C2:00:00:A0");
    private static readonly Mac SwitchMac = Mac.Parse("00:11:22:00:00:01");

    private sealed class FakeProber : ILatencyProber
    {
        public readonly HashSet<string> Down = new();
        public Task<(double? Ms, Mac? Mac)> ArpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct) =>
            Task.FromResult<(double?, Mac?)>(Down.Contains(ip.ToString()) ? (null, null) : (0.5, null));
        public Task<double?> NdpPingAsync(IPAddress ipv6, Mac? knownMac, TimeSpan timeout, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<double?> IcmpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct, int payloadSize = 32, bool dontFragment = false) =>
            Task.FromResult<double?>(Down.Contains(ip.ToString()) ? null : 3.0);
        public Task<double?> TcpPingAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct) => Task.FromResult<double?>(null);
    }

    private static (ApHealthMonitor Mon, FakeProber Prober, List<DiagnosticSignal> Signals, DeviceStore Devices, TopologyStore Topo, NetworkState Net) Create(int clients = 4)
    {
        var devices = new DeviceStore();
        var topo = new TopologyStore();
        var net = new NetworkState();
        var bus = new EventBus();
        var signals = new List<DiagnosticSignal>();
        bus.Subscribe<DiagnosticSignal>(signals.Add);

        var sw = devices.Observe(SwitchMac, IPAddress.Parse("10.40.0.2"), "test");
        sw.Type = DeviceType.AccessSwitch;
        var ap = devices.Observe(ApMac, IPAddress.Parse("10.40.0.10"), "test");
        ap.Type = DeviceType.AccessPoint;
        ap.UpstreamMac = SwitchMac;
        topo.Upsert(SwitchMac, ApMac, LinkKind.LldpCdp, l => l.SetPort(SwitchMac, "Gi1/0/7"));
        for (int i = 0; i < clients; i++)
        {
            var c = devices.Observe(Mac.Parse($"02:00:00:00:00:{i + 1:X2}"), IPAddress.Parse($"10.40.5.{i + 1}"), "test");
            c.SetFlag(DeviceFlags.WifiClient);
            if (i % 2 == 0) topo.Upsert(ApMac, c.Mac, LinkKind.WifiAssoc);
            else c.UpstreamMac = ApMac;
        }
        net.WifiNetworks =
        [
            new WifiNetwork("Office", Mac.Parse("74:83:C2:00:00:A1"), 6, 2437, "2.4 GHz", -50, 80, "WPA2", "Wi-Fi 6", null, false, 20, DateTimeOffset.Now),
            new WifiNetwork("Neighbour", Mac.Parse("AA:BB:CC:00:00:01"), 6, 2437, "2.4 GHz", -80, 30, "WPA2", "Wi-Fi 5", null, false, 20, DateTimeOffset.Now),
            new WifiNetwork("Other", Mac.Parse("AA:BB:CC:00:00:02"), 11, 2462, "2.4 GHz", -80, 30, "WPA2", "Wi-Fi 5", null, false, 20, DateTimeOffset.Now),
        ];

        var prober = new FakeProber();
        var sp = new FakeServiceProvider().Add<ILatencyProber>(prober);
        var mon = new ApHealthMonitor(devices, topo, net, bus, NullLogger<ApHealthMonitor>.Instance, sp);
        return (mon, prober, signals, devices, topo, net);
    }

    [Fact]
    public void Finds_aps_and_their_clients_from_links_and_upstream()
    {
        var (_, _, _, devices, topo, _) = Create(clients: 4);
        var groups = ApHealthMonitor.FindAccessPoints(devices.All, topo.Links);
        var g = Assert.Single(groups);
        Assert.Equal(ApMac, g.Ap.Mac);
        Assert.Equal(4, g.Clients.Count);
    }

    [Fact]
    public void Ap_end_of_wifi_assoc_link_is_found_without_ap_type()
    {
        var devices = new DeviceStore();
        var topo = new TopologyStore();
        var ap = devices.Observe(Mac.Parse("10:00:00:00:00:01"), IPAddress.Parse("10.0.0.2"), "t");
        var client = devices.Observe(Mac.Parse("10:00:00:00:00:02"), IPAddress.Parse("10.0.0.3"), "t");
        client.SetFlag(DeviceFlags.WifiClient);
        topo.Upsert(client.Mac, ap.Mac, LinkKind.WifiAssoc);
        var g = Assert.Single(ApHealthMonitor.FindAccessPoints(devices.All, topo.Links));
        Assert.Equal(ap.Mac, g.Ap.Mac);
        Assert.Equal(client.Mac, Assert.Single(g.Clients).Mac);
    }

    [Fact]
    public void Channel_congestion_counts_other_bssids_only()
    {
        var (_, _, _, _, _, net) = Create();
        Assert.Equal((6, 1), ApHealthMonitor.ChannelOf(ApMac, net.WifiNetworks));
        Assert.Equal(((int?)null, 0), ApHealthMonitor.ChannelOf(Mac.Parse("00:00:5E:00:00:01"), net.WifiNetworks));
    }

    [Fact]
    public async Task Healthy_ap_reports_up_with_all_clients()
    {
        var (mon, _, signals, _, _, _) = Create();
        await mon.RunCycleAsync(DateTimeOffset.Now, CancellationToken.None);
        var h = Assert.Single(mon.AccessPoints);
        Assert.Equal(HopHealth.Up, h.Health);
        Assert.True(h.MgmtUp);
        Assert.Equal(4, h.Clients);
        Assert.Equal(4, h.ClientsReachable);
        Assert.Empty(signals);
    }

    [Fact]
    public async Task Clients_unreachable_for_30s_signals_radio_problem_once()
    {
        var (mon, prober, signals, devices, _, _) = Create();
        var t = DateTimeOffset.Now;
        foreach (var d in devices.All) d.LastSeen = t;
        await mon.RunCycleAsync(t, CancellationToken.None);
        for (int i = 1; i <= 4; i++) prober.Down.Add($"10.40.5.{i}");

        for (int k = 1; k <= 12; k++) await mon.RunCycleAsync(t.AddSeconds(5 * k), CancellationToken.None);

        var s = Assert.Single(signals);
        Assert.Equal(SignalKind.ApClientsUnreachable, s.Kind);
        Assert.Equal(ApMac, s.Device);
        Assert.Equal(4, s.Affected!.Count);
        var h = Assert.Single(mon.AccessPoints);
        Assert.Equal(HopHealth.Down, h.Health);
        Assert.StartsWith("AP radio/SSID problem — wired side OK", h.Diagnosis);

        // recovery clears the state; a new outage would signal again
        prober.Down.Clear();
        await mon.RunCycleAsync(t.AddSeconds(70), CancellationToken.None);
        Assert.Equal(HopHealth.Up, mon.AccessPoints[0].Health);
        Assert.Single(signals);
    }

    [Fact]
    public async Task Ap_down_with_switch_up_names_the_switch_port()
    {
        var (mon, prober, signals, _, _, _) = Create();
        prober.Down.Add("10.40.0.10");
        for (int i = 1; i <= 4; i++) prober.Down.Add($"10.40.5.{i}");
        var t = DateTimeOffset.Now;
        await mon.RunCycleAsync(t, CancellationToken.None);
        await mon.RunCycleAsync(t.AddSeconds(5), CancellationToken.None);

        var s = Assert.Single(signals);
        Assert.Equal(SignalKind.ApDown, s.Kind);
        Assert.Equal("Gi1/0/7", s.Port);
        Assert.Contains("check AP power/PoE or its switch port", s.Summary);
    }

    [Fact]
    public async Task Flaky_clients_are_rf_degradation_not_an_outage()
    {
        var (mon, prober, signals, _, _, _) = Create();
        var t = DateTimeOffset.Now;
        for (int k = 0; k < 8; k++)
        {
            // every other probe of every client is lost: never 2 in a row, so nobody is "unreachable"
            prober.Down.Clear();
            if (k % 2 == 1) for (int i = 1; i <= 4; i++) prober.Down.Add($"10.40.5.{i}");
            await mon.RunCycleAsync(t.AddSeconds(5 * k), CancellationToken.None);
            if (k < 3) Assert.Empty(signals); // not enough samples yet
        }
        var s = Assert.Single(signals);
        Assert.Equal(SignalKind.ApDegraded, s.Kind);
        Assert.Contains("client loss", s.Summary);
        Assert.Contains("channel 6 shared with 1 other BSSIDs", s.Summary);
        Assert.Equal(HopHealth.Degraded, mon.AccessPoints[0].Health);
        Assert.Equal(4, mon.AccessPoints[0].ClientsReachable);
    }

    [Fact]
    public async Task Demo_mode_is_ignored()
    {
        var (mon, _, _, _, _, net) = Create();
        net.IsDemo = true;
        await mon.RunCycleAsync(DateTimeOffset.Now, CancellationToken.None);
        Assert.Empty(mon.AccessPoints);
    }
}
