using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Anomaly;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics;

public sealed class AnomalyEngineTests : IDisposable
{
    private readonly EventBus _bus = new();
    private readonly AlertService _alerts = new();
    private readonly DeviceStore _devices = new();
    private readonly NetworkState _network = new();
    private readonly FakeFrameSource _source = new() { Adapter = Adapter() };
    private readonly AppSettings _settings = new() { DumpPcapOnAlert = false };
    private readonly AnomalyEngine _engine;
    private readonly DateTime _t0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    private static readonly Mac Chatty = Mac.Parse("00:11:22:AA:00:01");
    private static readonly Mac Other = Mac.Parse("00:11:22:AA:00:02");

    public AnomalyEngineTests()
    {
        _engine = new AnomalyEngine(NullLogger<AnomalyEngine>.Instance, _bus, _alerts, _devices, _network, _source, _settings);
        _engine.Start();
    }

    public void Dispose() => _engine.Dispose();

    private static TrafficSnapshot Snap(DateTime t, double total, double bcast, double mcast = 0, params TalkerStat[] talkers) =>
        new(new DateTimeOffset(t), total, bcast, mcast, total - bcast - mcast, total * 200, new Dictionary<string, double>(), talkers, 0);

    private IEnumerable<Alert> Of(AlertKind k) => _alerts.Alerts.Where(a => a.Kind == k);

    // ---------------------------------------------------------------- storms

    [Fact]
    public void Broadcast_storm_requires_ratio_rate_and_two_sustained_seconds()
    {
        _bus.Publish(Snap(_t0, 2000, 1000));
        Assert.Empty(Of(AlertKind.BroadcastStorm));
        _bus.Publish(Snap(_t0.AddSeconds(1), 2000, 1000));
        var a = Assert.Single(Of(AlertKind.BroadcastStorm));
        Assert.Equal(AlertSeverity.Warning, a.Severity);
        Assert.Equal(1000, a.Rate);
    }

    [Fact]
    public void High_broadcast_rate_with_low_ratio_is_not_a_storm()
    {
        for (int i = 0; i < 5; i++) _bus.Publish(Snap(_t0.AddSeconds(i), 20000, 900)); // 4.5 %
        Assert.Empty(Of(AlertKind.BroadcastStorm));
    }

    [Fact]
    public void Learned_baseline_catches_surge_below_absolute_threshold()
    {
        // without a baseline 300 pps (< 500) is fine
        var freshAlerts = new AlertService();
        var fresh = new AnomalyEngine(NullLogger<AnomalyEngine>.Instance, new EventBus(), freshAlerts, _devices, _network, _source, _settings);
        fresh.OnTraffic(Snap(_t0, 600, 300)); fresh.OnTraffic(Snap(_t0.AddSeconds(1), 600, 300));
        Assert.Empty(freshAlerts.Alerts);

        for (int i = 0; i < 60; i++) _bus.Publish(Snap(_t0.AddSeconds(i), 400, 20));
        Assert.Empty(Of(AlertKind.BroadcastStorm));
        _bus.Publish(Snap(_t0.AddSeconds(60), 600, 300));
        _bus.Publish(Snap(_t0.AddSeconds(61), 600, 300));
        Assert.Single(Of(AlertKind.BroadcastStorm));
    }

    [Fact]
    public void Multicast_storm_detected()
    {
        _bus.Publish(Snap(_t0, 5000, 0, 3000));
        _bus.Publish(Snap(_t0.AddSeconds(1), 5000, 0, 3000));
        Assert.Single(Of(AlertKind.MulticastStorm));
    }

    [Fact]
    public void Per_mac_storm_flags_the_source_and_clears_after_quiet_period()
    {
        var dev = AddDevice(_devices, Chatty.ToString(), "192.168.1.66");
        _bus.Publish(Snap(_t0, 800, 450, 0, new TalkerStat(Chatty, 460, 450, 0, 30000)));
        Assert.True(dev.Has(DeviceFlags.StormSource));
        var a = Assert.Single(Of(AlertKind.BroadcastStorm));
        Assert.Equal(Chatty, a.Source);

        for (int i = 1; i <= 10; i++) _bus.Publish(Snap(_t0.AddSeconds(i), 100, 5, 0, new TalkerStat(Chatty, 10, 1, 0, 1000)));
        Assert.False(dev.Has(DeviceFlags.StormSource));
    }

    [Fact]
    public void Top_talker_raises_info_but_ignores_this_host()
    {
        _bus.Publish(Snap(_t0, 5000, 0, 0, new TalkerStat(LocalMac, 3000, 0, 0, 1e6), new TalkerStat(Other, 1500, 0, 0, 1e6)));
        var a = Assert.Single(Of(AlertKind.TopTalker));
        Assert.Equal(Other, a.Source);
        Assert.Equal(AlertSeverity.Info, a.Severity);
    }

    [Fact]
    public async Task Storm_alert_includes_pcap_dump_path_when_enabled()
    {
        _settings.DumpPcapOnAlert = true;
        _bus.Publish(Snap(_t0, 2000, 1000));
        _bus.Publish(Snap(_t0.AddSeconds(1), 2000, 1000));
        for (int i = 0; i < 100 && !Of(AlertKind.BroadcastStorm).Any(); i++) await Task.Delay(20);
        var a = Assert.Single(Of(AlertKind.BroadcastStorm));
        Assert.Contains("Capture: C:\\dumps\\BroadcastStorm.pcapng", a.Details);
        Assert.Equal(1, _source.Dumps);
    }

    // ---------------------------------------------------------------- loops

    private byte[] ArpBroadcast(int n = 1) => FrameBuilder.ArpRequest(Chatty, IPAddress.Parse("192.168.1.66"), IPAddress.Parse($"192.168.1.{n}"));

    [Fact]
    public void Repeated_identical_broadcasts_within_50ms_indicate_a_loop()
    {
        var f = ArpBroadcast();
        // first burst: 3 copies within 20 ms (could be a chatty host)
        for (int i = 0; i < 3; i++) _engine.OnFrame(Frame(f, _t0.AddMilliseconds(i * 10)));
        Assert.Empty(Of(AlertKind.L2Loop));
        // the same frame keeps circulating
        for (int i = 0; i < 3; i++) _engine.OnFrame(Frame(f, _t0.AddMilliseconds(100 + i * 10)));
        var a = Assert.Single(Of(AlertKind.L2Loop));
        Assert.Equal(Chatty, a.Source);
    }

    [Fact]
    public void Same_frame_spaced_out_or_outbound_is_not_a_loop()
    {
        var f = ArpBroadcast();
        for (int i = 0; i < 20; i++) _engine.OnFrame(Frame(f, _t0.AddMilliseconds(i * 60)));
        for (int i = 0; i < 20; i++) _engine.OnFrame(Frame(ArpBroadcast(2), _t0.AddMilliseconds(i), outbound: true));
        Assert.Empty(Of(AlertKind.L2Loop));
    }

    [Fact]
    public void Unicast_copies_differing_only_in_ttl_count_as_duplicates()
    {
        var a = Udp4(Chatty, Other, "192.168.1.66", "192.168.1.67", 5000, 6000);
        for (int burst = 0; burst < 2; burst++)
            for (int i = 0; i < 3; i++)
            {
                var copy = (byte[])a.Clone();
                copy[14 + 8] = (byte)(64 - i); // TTL
                _engine.OnFrame(Frame(copy, _t0.AddMilliseconds(burst * 200 + i)));
            }
        Assert.Single(Of(AlertKind.L2Loop));
    }

    [Fact]
    public void Stp_topology_change_burst_raises_loop_alert_and_repeated_tc_flag_counts_once()
    {
        // one bridge keeps the TC flag set for many BPDUs: a single topology change
        var b1 = Mac.Parse("00:1B:21:00:00:01");
        for (int i = 0; i < 10; i++) _engine.OnFrame(Frame(Bpdu(b1, tc: true), _t0.AddSeconds(i * 2)));
        Assert.Single(Of(AlertKind.StpTopologyChange));
        Assert.Empty(Of(AlertKind.L2Loop));

        // five distinct topology changes within 30 s (the first one above, three more bridges, then a TCN)
        for (int i = 2; i <= 4; i++) _engine.OnFrame(Frame(Bpdu(Mac.Parse($"00:1B:21:00:00:0{i}"), tc: true), _t0.AddSeconds(20 + i)));
        Assert.Empty(Of(AlertKind.L2Loop));
        _engine.OnFrame(Frame(Bpdu(Mac.Parse("00:1B:21:00:00:09"), tc: false, tcn: true), _t0.AddSeconds(27)));
        var a = Assert.Single(Of(AlertKind.L2Loop));
        Assert.Contains("topology", a.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Multiple_stp_roots_are_reported()
    {
        _network.AddStp(new StpInfo("8000.001b21000001", Mac.Parse("00:1B:21:00:00:01"), 32768, 0, "8000.001b21000001", Mac.Parse("00:1B:21:00:00:01"), "RSTP", DateTimeOffset.Now));
        _bus.Publish(Snap(_t0, 100, 1));
        Assert.Empty(Of(AlertKind.MultipleStpRoots));
        _network.AddStp(new StpInfo("1000.00aabb000001", Mac.Parse("00:AA:BB:00:00:01"), 4096, 0, "8000.001b21000002", Mac.Parse("00:1B:21:00:00:02"), "RSTP", DateTimeOffset.Now));
        _bus.Publish(Snap(_t0.AddSeconds(11), 100, 1));
        Assert.Single(Of(AlertKind.MultipleStpRoots));
    }

    [Fact]
    public void Mac_flapping_between_ports_is_detected_from_fdb_snapshots()
    {
        var sw = Mac.Parse("00:1B:21:00:00:01");
        FdbEntry E(string port) => new(sw, port, null, Chatty, 1, DateTimeOffset.Now);
        _network.SetFdb(sw, [E("Gi1/0/1")]);
        _network.SetFdb(sw, [E("Gi1/0/2")]);
        _network.SetFdb(sw, [E("Gi1/0/1")]);
        Assert.Empty(Of(AlertKind.MacFlapping));
        _network.SetFdb(sw, [E("Gi1/0/2")]);
        var a = Assert.Single(Of(AlertKind.MacFlapping));
        Assert.Equal(Chatty, a.Source);
    }

    // ---------------------------------------------------------------- protocol noise

    [Fact]
    public void Mdns_spam_from_one_source_is_reported_when_the_second_closes()
    {
        var mdns = IPAddress.Parse("224.0.0.251");
        for (int i = 0; i < 60; i++)
        {
            var f = FrameBuilder.Udp4(Chatty, IpUtil.MulticastMac(mdns), IPAddress.Parse("192.168.1.66"), mdns, 5353, 5353, new byte[20 + i]);
            _engine.OnFrame(Frame(f, _t0.AddMilliseconds(i * 15)));
        }
        for (int i = 0; i < 10; i++)
        {
            var f = FrameBuilder.Udp4(Other, IpUtil.MulticastMac(mdns), IPAddress.Parse("192.168.1.67"), mdns, 5353, 5353, new byte[20 + i]);
            _engine.OnFrame(Frame(f, _t0.AddMilliseconds(i * 15)));
        }
        Assert.Empty(Of(AlertKind.MdnsSpam));
        _engine.OnFrame(Frame(ArpBroadcast(), _t0.AddSeconds(1.2)));
        var a = Assert.Single(Of(AlertKind.MdnsSpam));
        Assert.Equal(Chatty, a.Source);
    }

    [Fact]
    public void Ssdp_spam_detected()
    {
        var ssdp = IPAddress.Parse("239.255.255.250");
        for (int i = 0; i < 80; i++)
            _engine.OnFrame(Frame(FrameBuilder.Udp4(Chatty, IpUtil.MulticastMac(ssdp), IPAddress.Parse("192.168.1.66"), ssdp, 40000 + i, 1900, new byte[100]), _t0.AddMilliseconds(i * 10)));
        _engine.OnFrame(Frame(ArpBroadcast(), _t0.AddSeconds(1.5)));
        Assert.Single(Of(AlertKind.SsdpSpam));
    }

    [Fact]
    public void Unknown_unicast_flooding_detected_when_one_directional()
    {
        var victim = Mac.Parse("00:11:22:BB:00:09");
        for (int s = 0; s < 3; s++)
            for (int i = 0; i < 300; i++)
                _engine.OnFrame(Frame(Udp4(Chatty, victim, "192.168.1.66", "192.168.1.99", 1000 + i, 9000), _t0.AddSeconds(s).AddMilliseconds(i * 3)));
        _engine.OnFrame(Frame(ArpBroadcast(), _t0.AddSeconds(3.5)));
        var a = Assert.Single(Of(AlertKind.UnknownUnicastFlood));
        Assert.Contains(victim.ToString(), a.Details);
        Assert.False(_engine.SpanModeDetected);
    }

    [Fact]
    public void Span_port_traffic_is_not_reported_as_flooding()
    {
        // bidirectional conversations between many pairs: we sit on a mirror port
        for (int s = 0; s < 25; s++)
            for (int i = 0; i < 300; i++)
            {
                var x = Mac.Parse($"00:11:22:CC:00:{i / 2 % 20:X2}");
                var y = Mac.Parse($"00:11:22:DD:00:{i / 2 % 20:X2}");
                var (src, dst) = i % 2 == 0 ? (x, y) : (y, x);
                _engine.OnFrame(Frame(Udp4(src, dst, "192.168.1.70", "192.168.1.71", 1000 + i, 9000 + s), _t0.AddSeconds(s).AddMilliseconds(i * 3)));
            }
        Assert.True(_engine.SpanModeDetected);
        // only the first seconds before the 10 s detection window closed may have been counted
        Assert.True(Of(AlertKind.UnknownUnicastFlood).Count() <= 1);
    }

    [Fact]
    public void Missing_igmp_querier_is_reported_when_groups_exist()
    {
        var dev = AddDevice(_devices, Other.ToString(), "192.168.1.67");
        dev.AddMulticastGroup(IPAddress.Parse("239.255.255.250"));
        _bus.Publish(Snap(_t0, 100, 1));
        _bus.Publish(Snap(_t0.AddSeconds(200), 100, 1));
        Assert.Empty(Of(AlertKind.IgmpQuerierMissing));
        _bus.Publish(Snap(_t0.AddSeconds(300), 100, 1));
        Assert.Single(Of(AlertKind.IgmpQuerierMissing));
    }

    [Fact]
    public void Igmp_query_on_the_wire_satisfies_querier_check()
    {
        var dev = AddDevice(_devices, Other.ToString(), "192.168.1.67");
        dev.AddMulticastGroup(IPAddress.Parse("239.1.2.3"));
        var allHosts = IPAddress.Parse("224.0.0.1");
        var query = FrameBuilder.Ip4Frame(Mac.Parse("00:0D:B9:00:00:01"), IpUtil.MulticastMac(allHosts), IPAddress.Parse("192.168.1.1"), allHosts, 2,
            [0x11, 100, 0, 0, 0, 0, 0, 0], ttl: 1);
        _bus.Publish(Snap(_t0, 100, 1));
        _engine.OnFrame(Frame(query, _t0.AddSeconds(200)));
        _bus.Publish(Snap(_t0.AddSeconds(300), 100, 1));
        Assert.Empty(Of(AlertKind.IgmpQuerierMissing));
    }
}
