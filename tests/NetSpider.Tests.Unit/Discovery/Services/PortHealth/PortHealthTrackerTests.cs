using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Snmp;

namespace NetSpider.Tests.Unit.Discovery.Services.PortHealth;

public sealed class PortHealthTrackerTests
{
    private static readonly Mac Sw = Mac.Parse("00:1B:21:00:00:01");
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private const double Warn = 10;

    private sealed class Port
    {
        public bool Up = true;
        public long? Speed = 1000;
        public string? Duplex = "full";
        public TimeSpan LastChange = TimeSpan.FromSeconds(100);
        public ulong InOct, OutOct, InErr, Fcs, Late, Bcast, Mcast;
        public TimeSpan UpTime = TimeSpan.FromHours(1);
        public DateTimeOffset Time = T0;

        public PortCounterSample Sample() => new(Sw, 7, "Gi1/0/7", Time, Up, Speed, Duplex, LastChange,
            InOct, OutOct, InErr, 0, 0, 0, Bcast, Mcast, 0, Fcs, 0, Late, 0);

        /// <summary>Advances time and agent uptime by <paramref name="seconds"/>.</summary>
        public Port Tick(double seconds = 60)
        {
            Time += TimeSpan.FromSeconds(seconds);
            UpTime += TimeSpan.FromSeconds(seconds);
            return this;
        }
    }

    private static PortUpdate Feed(PortHealthTracker t, Port p) => t.Update(p.Sample(), p.UpTime, Warn);

    private static PortHealthTracker NewTracker() => new(Sw, 7);

    [Fact]
    public void First_sample_has_no_rates_second_sample_computes_bps_and_pps()
    {
        var t = NewTracker();
        var p = new Port();
        var first = Feed(t, p).Health;
        Assert.Equal(0, first.InBps);
        Assert.Equal(HopHealth.Up, first.Health);

        p.Tick(60);
        p.InOct += 7_500_000;   // 1 Mbit/s
        p.OutOct += 15_000_000; // 2 Mbit/s
        p.Bcast += 6000;        // 100 pps
        p.Mcast += 1200;        // 20 pps
        var h = Feed(t, p).Health;
        Assert.Equal(1_000_000, h.InBps, 3);
        Assert.Equal(2_000_000, h.OutBps, 3);
        Assert.Equal(100, h.BroadcastPps, 3);
        Assert.Equal(20, h.MulticastPps, 3);
        Assert.Null(h.Problem);
    }

    [Fact]
    public void Delta_handles_32bit_wrap_and_rejects_implausible_wraps()
    {
        Assert.Equal(5001UL, PortHealthTracker.Delta(uint.MaxValue - 1000UL, 4000, 1e9));
        Assert.Equal(0UL, PortHealthTracker.Delta(100, 50, 1e6));                     // a counter clear, not a wrap
        Assert.Equal(0UL, PortHealthTracker.Delta(10_000_000_000UL, 5, double.MaxValue)); // 64-bit counter going back = reset
        Assert.Equal(10UL, PortHealthTracker.Delta(5, 15, 0));
    }

    [Fact]
    public void Wrapped_32bit_octet_counter_gives_the_right_rate()
    {
        var t = NewTracker();
        var p = new Port { InOct = uint.MaxValue - 999_999UL };
        Feed(t, p);
        p.Tick(60);
        p.InOct = 6_500_000; // wrapped: 1,000,000 + 6,500,000 = 7.5 MB in 60 s
        var h = Feed(t, p).Health;
        Assert.Equal(1_000_000, h.InBps, 0);
    }

    [Fact]
    public void Agent_reboot_resets_the_baseline_without_rates_flaps_or_events()
    {
        var t = NewTracker();
        var p = new Port { InOct = 5_000_000_000, Bcast = 900_000 };
        Feed(t, p);
        p.Tick(60);
        p.InOct += 1000;
        Feed(t, p);

        // reboot: uptime back to 30 s, counters restart, last change moved, port briefly seen down
        p.Time += TimeSpan.FromSeconds(60);
        p.UpTime = TimeSpan.FromSeconds(30);
        p.InOct = 10; p.Bcast = 5; p.LastChange = TimeSpan.FromSeconds(20); p.Up = false;
        var u = Feed(t, p);
        Assert.Empty(u.Events);
        Assert.Equal(0, u.Health.InBps);
        Assert.Equal(0, u.Health.BroadcastPps);
        Assert.Equal(0, u.Health.FlapsLastHour);

        // and the next poll uses the new baseline
        p.Tick(60);
        p.Up = true;
        p.InOct += 750_000;
        var next = Feed(t, p).Health;
        Assert.Equal(100_000, next.InBps, 0);
    }

    [Fact]
    public void Down_up_down_signals_port_down_up_and_then_flapping()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.InOct += 1000; // traffic → established
        Assert.Empty(Feed(t, p).Events);

        p.Tick(); p.Up = false; p.LastChange = TimeSpan.FromSeconds(150);
        var down = Feed(t, p);
        Assert.Equal(SignalKind.PortDown, Assert.Single(down.Events).Kind);
        Assert.Equal(HopHealth.Down, down.Health.Health);
        Assert.Contains("down", down.Health.Problem, StringComparison.OrdinalIgnoreCase);

        p.Tick(); p.Up = true; p.LastChange = TimeSpan.FromSeconds(200);
        var up = Feed(t, p);
        Assert.Equal(SignalKind.PortUp, Assert.Single(up.Events).Kind);

        p.Tick(); p.Up = false; p.LastChange = TimeSpan.FromSeconds(250);
        var third = Feed(t, p);
        Assert.Contains(third.Events, e => e.Kind == SignalKind.PortFlapping);
        Assert.Contains(third.Events, e => e.Kind == SignalKind.PortDown);
        Assert.Equal(3, third.Health.FlapsLastHour);

        // still flapping on the next poll: no repeat event
        p.Tick(); p.Up = true; p.LastChange = TimeSpan.FromSeconds(300);
        Assert.DoesNotContain(Feed(t, p).Events, e => e.Kind == SignalKind.PortFlapping);
    }

    [Fact]
    public void Moving_last_change_with_same_state_counts_as_a_down_up_cycle()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.LastChange = TimeSpan.FromSeconds(500);
        var u1 = Feed(t, p);
        Assert.Equal(2, u1.Health.FlapsLastHour);
        Assert.Empty(u1.Events);
        p.Tick(); p.LastChange = TimeSpan.FromSeconds(560);
        var u2 = Feed(t, p);
        Assert.Contains(u2.Events, e => e.Kind == SignalKind.PortFlapping);
        Assert.Equal(HopHealth.Degraded, u2.Health.Health);
    }

    [Fact]
    public void Flaps_older_than_the_window_do_not_count_as_flapping()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.LastChange = TimeSpan.FromSeconds(500); Feed(t, p);   // 2 changes
        p.Tick(11 * 60); p.LastChange = TimeSpan.FromSeconds(1500);       // 2 more, but 11 min later
        var u = Feed(t, p);
        Assert.DoesNotContain(u.Events, e => e.Kind == SignalKind.PortFlapping);
        Assert.Equal(4, u.Health.FlapsLastHour);
    }

    [Fact]
    public void Down_on_a_port_that_never_carried_traffic_is_not_signalled()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.Up = false; p.LastChange = TimeSpan.FromSeconds(130);
        var u = Feed(t, p);
        Assert.Empty(u.Events);
        Assert.Equal(HopHealth.Unknown, u.Health.Health);
    }

    [Fact]
    public void Crc_errors_above_threshold_raise_port_errors_once_with_a_cable_hint()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.Fcs += 1200; p.InErr += 1200; // 20/s = 1200/min
        var u = Feed(t, p);
        var e = Assert.Single(u.Events);
        Assert.Equal(SignalKind.PortErrors, e.Kind);
        Assert.Contains("CRC", e.Summary);
        Assert.Equal(20, u.Health.FcsPerSec, 3);
        Assert.Equal(HopHealth.Degraded, u.Health.Health);
        Assert.Contains("cable", u.Health.Problem);

        p.Tick(); p.Fcs += 1200; p.InErr += 1200;
        Assert.Empty(Feed(t, p).Events); // still erroring: edge-triggered

        p.Tick();
        var clean = Feed(t, p).Health;
        Assert.Equal(HopHealth.Up, clean.Health);
        Assert.Null(clean.Problem);
    }

    [Fact]
    public void Few_errors_below_threshold_are_not_a_problem()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.InErr += 5; // 5/min < 10
        var u = Feed(t, p);
        Assert.Empty(u.Events);
        Assert.Equal(HopHealth.Up, u.Health.Health);
    }

    [Fact]
    public void Late_collisions_flag_duplex_mismatch()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.Late += 3;
        var u = Feed(t, p);
        Assert.Equal(SignalKind.PortDuplexMismatch, Assert.Single(u.Events).Kind);
        Assert.True(u.Health.DuplexSuspect);
        Assert.Contains("duplex", u.Health.Problem, StringComparison.OrdinalIgnoreCase);

        // stays suspect for a while even without new late collisions
        p.Tick();
        Assert.True(Feed(t, p).Health.DuplexSuspect);
    }

    [Theory]
    [InlineData(100, "half", true)]
    [InlineData(1000, "half", true)]
    [InlineData(10, "half", false)]
    [InlineData(100, "full", false)]
    public void Half_duplex_at_100_mbps_or_more_is_suspect(long speed, string duplex, bool suspect)
    {
        var t = NewTracker();
        var p = new Port { Speed = speed, Duplex = duplex };
        Assert.Equal(suspect, Feed(t, p).Health.DuplexSuspect);
    }

    [Fact]
    public void Relink_at_100_after_1000_is_a_speed_downgrade()
    {
        var t = NewTracker();
        var p = new Port();
        Feed(t, p);
        p.Tick(); p.InOct += 1000; Feed(t, p);
        p.Tick(); p.Up = false; p.LastChange = TimeSpan.FromSeconds(200); Feed(t, p);
        p.Tick(); p.Up = true; p.Speed = 100; p.LastChange = TimeSpan.FromSeconds(260);
        var u = Feed(t, p);
        Assert.Contains(u.Events, e => e.Kind == SignalKind.PortSpeedDowngrade);
        Assert.True(u.Health.SpeedDowngraded);
        Assert.Contains("100 Mbps", u.Health.Problem);
        Assert.Contains("1 Gbps", u.Health.Problem);

        p.Tick(); p.Speed = 1000; p.LastChange = TimeSpan.FromSeconds(320);
        Assert.False(Feed(t, p).Health.SpeedDowngraded);
    }

    [Fact]
    public void Speed_drop_while_up_is_a_downgrade_even_above_100()
    {
        var t = NewTracker();
        var p = new Port { Speed = 10000 };
        Feed(t, p);
        p.Tick(); p.Speed = 1000;
        var u = Feed(t, p);
        Assert.True(u.Health.SpeedDowngraded);
        Assert.Contains(u.Events, e => e.Kind == SignalKind.PortSpeedDowngrade);
    }

    [Fact]
    public void History_is_capped()
    {
        var t = NewTracker();
        var p = new Port();
        for (int i = 0; i < PortHealthTracker.HistorySize + 15; i++) { Feed(t, p); p.Tick(); }
        Assert.Equal(PortHealthTracker.HistorySize, t.History.Count);
    }

    [Theory]
    [InlineData(6, "Gi1/0/1", true)]
    [InlineData(117, "ge-0/0/3", true)]
    [InlineData(53, "Vlan10", false)]   // propVirtual
    [InlineData(24, "lo0", false)]      // softwareLoopback
    [InlineData(6, "vlan1", false)]     // some agents type SVIs as ethernet
    [InlineData(6, "cpu", false)]
    [InlineData(6, "br0", false)]
    [InlineData(6, "port 5", true)]
    [InlineData(6, "Port-channel1", false)]
    [InlineData(6, "po1", false)]
    [InlineData(null, "eth3", true)]
    public void Only_physical_ethernet_ports_are_polled(int? ifType, string name, bool physical) =>
        Assert.Equal(physical, PortCounterPoller.IsPhysical(ifType, name));
}
