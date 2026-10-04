using NetSpider.Core.Model;
using NetSpider.Diagnostics.Anomaly;
using NetSpider.Diagnostics.Storm;

namespace NetSpider.Tests.Unit.Diagnostics.Storm;

public sealed class StormClassifierTests
{
    private readonly AppSettings _s = new(); // ratio 0.15, bcast 500 pps, mcast 2000 pps

    [Theory]
    [InlineData(10, 20, 1000, StormLevel.Normal)]
    [InlineData(600, 0, 2000, StormLevel.Storm)]       // 30 % and > 500 pps
    [InlineData(900, 0, 20000, StormLevel.Normal)]     // 4.5 %: a busy network, not a storm
    [InlineData(0, 2500, 5000, StormLevel.Storm)]      // multicast over threshold
    [InlineData(100, 0, 1000, StormLevel.Elevated)]    // 10 % > half of 15 %
    [InlineData(30, 0, 100, StormLevel.Normal)]        // 30 % but below the 50 pps floor
    [InlineData(0, 1200, 5000, StormLevel.Elevated)]   // multicast above half the threshold
    public void Level_from_thresholds(double bcast, double mcast, double total, StormLevel expected) =>
        Assert.Equal(expected, StormClassifier.Classify(bcast, mcast, total, 0, 0, false, _s));

    [Fact]
    public void Baseline_times_three_is_elevated_only_once_warmed()
    {
        // 60 bcast pps of 2000 = 3 %: below half the ratio threshold
        Assert.Equal(StormLevel.Normal, StormClassifier.Classify(60, 0, 2000, 10, 0, false, _s));
        Assert.Equal(StormLevel.Elevated, StormClassifier.Classify(60, 0, 2000, 10, 0, true, _s));
        Assert.Equal(StormLevel.Normal, StormClassifier.Classify(60, 0, 2000, 25, 0, true, _s));
    }

    [Fact]
    public void Ewma_learns_and_warms_up()
    {
        var b = new EwmaBaseline(alpha: 0.5, warmupSamples: 3);
        b.Add(10);
        Assert.Equal(10, b.Value);
        b.Add(20);
        Assert.Equal(15, b.Value);
        Assert.False(b.Warmed);
        b.Add(15);
        Assert.True(b.Warmed);
    }
}

public sealed class StormLocatorTests
{
    private static readonly Mac Core = Mac.Parse("00:1B:21:00:00:01");
    private static readonly Mac Access = Mac.Parse("00:1B:21:00:00:02");
    private static readonly Mac Source = Mac.Parse("00:11:22:33:44:55");

    private static FdbEntry E(Mac sw, string port, Mac mac, int? ifIndex = null, int? vlan = 1) => new(sw, port, ifIndex, mac, vlan, DateTimeOffset.Now);

    private static string? Names(Mac m) => m == Core ? "core-sw-01" : m == Access ? "access-sw-02" : null;

    [Fact]
    public void Picks_the_edge_port_with_the_fewest_macs_and_uses_ifname()
    {
        var fdb = new List<FdbEntry>();
        // core learns the source (and 30 others) on its uplink port 24
        fdb.Add(E(Core, "24", Source));
        for (int i = 0; i < 30; i++) fdb.Add(E(Core, "24", Mac.Parse($"00:AA:00:00:00:{i:X2}")));
        // access switch: the source alone on bridge port 7 (ifIndex 10007)
        fdb.Add(E(Access, "7", Source, 10007));
        var ports = new[] { new SwitchPortInfo(Access, 10007, "Gi1/0/7", null, 1000, true, "full", null, null) };

        var loc = new StormLocator(fdb, ports, [], Names).Locate(Source);
        Assert.NotNull(loc);
        Assert.Equal(Access, loc!.Switch);
        Assert.Equal("Gi1/0/7", loc.Port);
        Assert.Equal(1, loc.MacsOnPort);
        Assert.Equal("access-sw-02 port Gi1/0/7", loc.Location);
    }

    [Fact]
    public void Names_the_inferred_switch_behind_the_port()
    {
        var other = Mac.Parse("00:11:22:33:44:66");
        var fdb = new[] { E(Core, "7", Source), E(Core, "7", other) };
        var inferred = Mac.Parse("02:00:00:00:07:07");
        var link = new Link(Core, inferred, LinkKind.InferredUnmanagedSwitch);
        link.SetPort(Core, "7");
        var loc = new StormLocator(fdb, [], [link], m => m == inferred ? "TV rack" : Names(m)).Locate(Source);
        Assert.Equal("core-sw-01 port 7 → behind inferred switch 'TV rack'", loc!.Location);
    }

    [Fact]
    public void Shared_port_without_topology_says_so_and_unknown_mac_is_null()
    {
        var fdb = new[] { E(Core, "7", Source), E(Core, "7", Mac.Parse("00:11:22:33:44:66")) };
        var locator = new StormLocator(fdb, [], [], Names);
        Assert.Contains("shared by 2 MACs", locator.Locate(Source)!.Location);
        Assert.Null(locator.Locate(Mac.Parse("00:00:00:00:00:42")));
    }
}

public sealed class LoopFinderTests
{
    private static readonly Mac Sw = Mac.Parse("00:1B:21:00:00:01");
    private static readonly Mac Flapper = Mac.Parse("00:11:22:33:44:55");
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static string Name(Mac m) => m == Sw ? "core-sw-01" : m.ToString();

    private static FdbEntry E(string port, Mac? mac = null, int? vlan = 1) => new(Sw, port, null, mac ?? Flapper, vlan, T0);

    [Fact]
    public void Same_mac_alternating_between_ports_names_both_ports()
    {
        var f = new LoopFinder();
        f.ObserveFdb([E("5")], T0);
        f.ObserveFdb([E("9")], T0.AddSeconds(30));
        f.ObserveFdb([E("5")], T0.AddSeconds(60));
        var l = Assert.Single(f.Evaluate(AnomalyState.Empty, [], Name, T0.AddSeconds(60)));
        Assert.Equal(Sw, l.Switch);
        Assert.Equal(["5", "9"], l.Ports);
        Assert.Contains(Flapper, l.FlappingMacs);
        Assert.StartsWith("Loop suspected between core-sw-01 port 5 and port 9", l.Description);
    }

    [Fact]
    public void A_single_move_is_not_a_loop_and_different_vlans_on_two_ports_are_fine()
    {
        var f = new LoopFinder();
        f.ObserveFdb([E("5")], T0);
        f.ObserveFdb([E("9")], T0.AddSeconds(30)); // device re-cabled once
        f.ObserveFdb([E("1", Mac.Parse("00:11:22:33:44:77"), 10), E("2", Mac.Parse("00:11:22:33:44:77"), 20)], T0.AddSeconds(30));
        Assert.Empty(f.Evaluate(AnomalyState.Empty, [], Name, T0.AddSeconds(30)));
    }

    [Fact]
    public void Same_mac_on_two_ports_in_one_snapshot_is_suspect()
    {
        var f = new LoopFinder();
        f.ObserveFdb([E("5"), E("9")], T0);
        var l = Assert.Single(f.Evaluate(AnomalyState.Empty, [], Name, T0));
        Assert.Equal(0.5, l.Confidence, 3);
    }

    [Fact]
    public void Two_ports_with_simultaneous_high_broadcast_ingress()
    {
        var f = new LoopFinder();
        var ports = new[]
        {
            FakePortHealthMonitor.Port(Sw, "5", 4200), FakePortHealthMonitor.Port(Sw, "9", 4000), FakePortHealthMonitor.Port(Sw, "3", 10),
        };
        var l = Assert.Single(f.Evaluate(AnomalyState.Empty, ports, Name, T0));
        Assert.Equal(["5", "9"], l.Ports);
        Assert.Contains("both ports ingest 4k broadcast pps", l.Description);

        // dissimilar ingress (one port floods, the other barely) is not a loop pattern
        var lopsided = new[] { FakePortHealthMonitor.Port(Sw, "5", 4200), FakePortHealthMonitor.Port(Sw, "9", 300) };
        Assert.Empty(f.Evaluate(AnomalyState.Empty, lopsided, Name, T0));
    }

    [Fact]
    public void Combined_evidence_raises_confidence_and_global_evidence_boosts_it()
    {
        var f = new LoopFinder();
        var flap = new MacFlapInfo(Sw, Flapper, ["5", "9"], 4, T0);
        var anomaly = AnomalyState.Empty with { FlappingMacs = [flap] };
        var ports = new[] { FakePortHealthMonitor.Port(Sw, "5", 4200), FakePortHealthMonitor.Port(Sw, "9", 4000) };

        double flapOnly = f.Evaluate(anomaly, [], Name, T0)[0].Confidence;
        var both = f.Evaluate(anomaly, ports, Name, T0)[0];
        Assert.True(both.Confidence > flapOnly);
        Assert.Contains($"MAC {Flapper} flapping", both.Description);
        Assert.Contains("both ports ingest", both.Description);

        var withDup = anomaly with { LoopBursts5s = 12, LastLoopTimeUtc = T0.UtcDateTime.AddSeconds(-2) };
        var boosted = f.Evaluate(withDup, ports, Name, T0)[0];
        Assert.True(boosted.Confidence > both.Confidence);
        Assert.True(boosted.Confidence <= 0.95);
        Assert.Contains("duplicate-frame bursts", boosted.Description);
    }

    [Fact]
    public void Network_wide_evidence_alone_gives_a_generic_suspect_and_stale_evidence_none()
    {
        var f = new LoopFinder();
        var src = Mac.Parse("00:11:22:33:44:88");
        var anomaly = AnomalyState.Empty with { LoopBursts5s = 6, LastLoopSource = src, LastLoopTimeUtc = T0.UtcDateTime };
        var l = Assert.Single(f.Evaluate(anomaly, [], Name, T0));
        Assert.Null(l.Switch);
        Assert.Contains(src, l.FlappingMacs);
        Assert.Contains("no switch FDB/counters", l.Description);

        Assert.Empty(f.Evaluate(anomaly, [], Name, T0.AddMinutes(5)));
    }
}

public sealed class BroadcastBurstTests
{
    [Fact]
    public void Options_are_hard_capped()
    {
        var (pps, dur, vlan) = BroadcastBurst.Clamp(new StormControlOptions(DurationMs: 600_000, Pps: 1_000_000, VlanId: 9999));
        Assert.Equal(BroadcastBurst.MaxPps, pps);
        Assert.Equal(BroadcastBurst.MaxDurationMs, dur);
        Assert.Null(vlan);
        Assert.Equal(5000, BroadcastBurst.MaxPps);
        Assert.Equal(5000, BroadcastBurst.MaxDurationMs);
        Assert.Equal((1, BroadcastBurst.MinDurationMs, (int?)10), BroadcastBurst.Clamp(new StormControlOptions(-5, 0, 10)));
    }

    [Fact]
    public void Run_recaps_rate_even_when_called_directly()
    {
        var src = new StormFakeFrameSource();
        int sent = BroadcastBurst.Run(src, new byte[60], pps: 1_000_000, durationMs: 200, CancellationToken.None);
        Assert.Equal(src.SentCount, sent);
        Assert.InRange(sent, 1, 5000 * 200 / 1000);
    }

    [Fact]
    public void Run_paces_to_the_requested_rate()
    {
        var src = new StormFakeFrameSource();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        int sent = BroadcastBurst.Run(src, new byte[60], pps: 1000, durationMs: 300, CancellationToken.None);
        Assert.Equal(300, sent);
        Assert.True(sw.ElapsedMilliseconds >= 250, $"burst finished too fast: {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Run_stops_on_cancellation()
    {
        var src = new StormFakeFrameSource();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Equal(0, BroadcastBurst.Run(src, new byte[60], 1000, 1000, cts.Token));
    }
}
