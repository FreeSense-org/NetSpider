using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.PathDoctor;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

internal sealed class FakeHopProber : IHopProber
{
    /// <summary>ip → result; missing IPs answer ICMP in 1 ms.</summary>
    public readonly ConcurrentDictionary<string, HopProbeResult> Results = new();
    public readonly ConcurrentBag<string> Probed = [];

    public Task<HopProbeResult> ProbeAsync(IPAddress ip, bool arp, TimeSpan timeout, CancellationToken ct)
    {
        Probed.Add(ip.ToString());
        return Task.FromResult(Results.TryGetValue(ip.ToString(), out var r) ? r : new HopProbeResult(arp ? true : null, true, 1));
    }

    public void Up(string ip, double ms, bool arp = false) => Results[ip] = new HopProbeResult(arp ? true : null, true, ms);
    public void Down(string ip, bool arp = false) => Results[ip] = new HopProbeResult(arp ? false : null, false, null);
}

public sealed class HopTrackerTests
{
    [Fact]
    public void Goes_down_only_after_n_consecutive_failures_and_recovers()
    {
        var t = new HopTracker();
        Assert.Equal(HopHealth.Up, t.Record(new(null, true, 1), 3, HopProbe.IcmpOnly));
        Assert.Equal(HopHealth.Up, t.Record(new(null, false, null), 3, HopProbe.IcmpOnly));
        Assert.Equal(HopHealth.Up, t.Record(new(null, false, null), 3, HopProbe.IcmpOnly));
        Assert.Equal(HopHealth.Down, t.Record(new(null, false, null), 3, HopProbe.IcmpOnly));
        Assert.Contains("3 rounds", t.Note);
        // back up, but 3/5 lost in the window → degraded by loss
        Assert.Equal(HopHealth.Degraded, t.Record(new(null, true, 1), 3, HopProbe.IcmpOnly));
        Assert.Equal(60, t.LossPercent, 3);
    }

    [Fact]
    public void Arp_ok_icmp_failing_is_degraded_not_down()
    {
        var t = new HopTracker();
        for (int i = 0; i < 5; i++) t.Record(new(true, false, 0.3), 2, HopProbe.ArpIcmp);
        Assert.Equal(HopHealth.Degraded, t.Health);
        Assert.Equal(0, t.LossPercent);
        Assert.Contains("answers ARP but not ICMP", t.Note);
        Assert.True(t.ArpOk);
        Assert.False(t.IcmpOk);
    }

    [Fact]
    public void Rtt_spike_over_three_times_median_is_degraded()
    {
        var t = new HopTracker();
        for (int i = 0; i < 10; i++) Assert.Equal(HopHealth.Up, t.Record(new(null, true, 2), 3, HopProbe.IcmpOnly));
        Assert.Equal(HopHealth.Degraded, t.Record(new(null, true, 9), 3, HopProbe.IcmpOnly));
        Assert.Contains("usual 2 ms", t.Note);
        Assert.Equal(HopHealth.Up, t.Record(new(null, true, 2.1), 3, HopProbe.IcmpOnly));
    }

    [Fact]
    public void Recent_ring_is_capped()
    {
        var t = new HopTracker();
        for (int i = 0; i < HopTracker.RecentCapacity + 20; i++) t.Record(new(null, true, i % 3), 3, HopProbe.IcmpOnly);
        Assert.Equal(HopTracker.RecentCapacity, t.Recent.Count);
        Assert.NotNull(t.Jitter);
    }
}

public sealed class PathMonitorTests : IDisposable
{
    private readonly Office _o = new();
    private readonly SettingsStore _settings = new(Path.Combine(Path.GetTempPath(), $"ns-path-{Guid.NewGuid():N}.json"));
    private readonly EventBus _bus = new();
    private readonly FakeHopProber _prober = new();
    private readonly List<DiagnosticSignal> _signals = [];
    private readonly PathMonitor _mon;

    public PathMonitorTests()
    {
        _settings.Settings.HopDownRounds = 2;
        _bus.Subscribe<DiagnosticSignal>(s => { lock (_signals) _signals.Add(s); });
        _mon = new PathMonitor(_settings, _o.Devices, _o.Topology, _o.Network, _bus, _prober, NullLogger<PathMonitor>.Instance,
            adapterProvider: () => _o.Adapter());
        _prober.Up("10.40.0.3", 0.4, arp: true);
        _prober.Up("10.40.0.2", 0.5, arp: true);
        _prober.Up("10.40.0.1", 0.7, arp: true);
        _prober.Up("10.255.104.1", 1.5);
        _prober.Up("62.1.1.1", 8);
        _prober.Up("62.1.2.1", 7.5); // faster than the previous hop: added latency clamps at 0
        _prober.Up("62.1.3.1", 10);
        _prober.Up("1.1.1.1", 12);
    }

    [Fact]
    public async Task Probes_all_hops_and_computes_added_latency()
    {
        NetworkPath? published = null;
        _mon.Updated += p => published = p;
        _mon.Rebuild();
        await _mon.ProbeOnceAsync();
        var p = _mon.Path!;
        Assert.Same(p, published);
        Assert.All(p.Hops, h => Assert.Equal(HopHealth.Up, h.Health));
        var gw = p.Hops.Single(h => h.Role == HopRole.Firewall);
        Assert.Equal(0.7, gw.RttMs);
        Assert.Equal(0.2, gw.AddedMs!.Value, 3);
        Assert.True(gw.ArpOk);
        Assert.True(gw.IcmpOk);
        Assert.Equal(0, p.Hops.Single(h => h.Ip?.ToString() == "62.1.2.1").AddedMs);
        Assert.Equal(0.4, p.Hops[1].AddedMs!.Value, 3);
        Assert.Single(p.Hops[1].Recent);
        Assert.Empty(_signals);
    }

    [Fact]
    public async Task Hop_down_after_configured_rounds_publishes_signals_and_recovers()
    {
        string[] wan = ["10.255.104.1", "62.1.1.1", "62.1.2.1", "62.1.3.1", "1.1.1.1"];
        _mon.Rebuild();
        await _mon.ProbeOnceAsync();
        foreach (var ip in wan) _prober.Down(ip);
        await _mon.ProbeOnceAsync();
        Assert.Empty(_signals);
        await _mon.ProbeOnceAsync();
        Assert.Equal(wan.Length, _signals.Count(s => s.Kind == SignalKind.HopDown));
        var down = _signals.First(s => s.Summary.Contains("10.255.104.1"));
        Assert.Equal(HopHealth.Down, _mon.Path!.Hops.Single(h => h.Role == HopRole.Modem).Health);
        Assert.Equal(_mon.Path.Hops.Single(h => h.Role == HopRole.Modem), _mon.Path.FirstFailing);

        foreach (var ip in wan) _prober.Up(ip, 2);
        await _mon.ProbeOnceAsync();
        Assert.Contains(_signals, s => s.Kind == SignalKind.HopUp && s.Source == down.Source);
    }

    [Fact]
    public async Task Hop_that_ignores_pings_while_later_hops_answer_is_not_down()
    {
        _prober.Down("62.1.2.1"); // never answers
        _mon.Rebuild();
        for (int i = 0; i < 3; i++) await _mon.ProbeOnceAsync();
        var hop = _mon.Path!.Hops.Single(h => h.Ip?.ToString() == "62.1.2.1");
        Assert.Equal(HopHealth.Unknown, hop.Health);
        Assert.Contains("does not answer pings", hop.Note);
        Assert.Null(_mon.Path.FirstFailing);

        // a hop that used to answer and stops while later hops answer is only degraded
        _prober.Down("10.255.104.1");
        for (int i = 0; i < 3; i++) await _mon.ProbeOnceAsync();
        Assert.Equal(HopHealth.Degraded, _mon.Path!.Hops.Single(h => h.Role == HopRole.Modem).Health);
        Assert.DoesNotContain(_signals, s => s.Kind == SignalKind.HopDown);
    }

    [Fact]
    public async Task Gateway_answering_arp_but_not_icmp_is_degraded_with_note_and_device_mac()
    {
        _mon.Rebuild();
        await _mon.ProbeOnceAsync();
        _prober.Results["10.40.0.1"] = new HopProbeResult(true, false, 0.3);
        await _mon.ProbeOnceAsync();
        var gw = _mon.Path!.Hops.Single(h => h.Role == HopRole.Firewall);
        Assert.Equal(HopHealth.Degraded, gw.Health);
        Assert.Contains("answers ARP but not ICMP", gw.Note);
        var sig = Assert.Single(_signals);
        Assert.Equal(SignalKind.HopDegraded, sig.Kind);
        Assert.Equal(_o.Gw.Mac, sig.Device);
    }

    [Fact]
    public async Task Anchor_hop_is_up_when_any_anchor_answers()
    {
        _o.Topology.RemoveWhere(l => l.Touches(_o.Me.Mac));
        _o.Topology.Upsert(_o.TvRack.Mac, _o.Me.Mac, LinkKind.InferredUnmanagedSwitch);
        _prober.Down("10.40.7.1");
        _prober.Down("10.40.7.2");
        _prober.Up("10.40.7.3", 0.9);
        _mon.Rebuild();
        await _mon.ProbeOnceAsync();
        var hop = _mon.Path!.Hops[1];
        Assert.Equal(HopProbe.Anchors, hop.Probe);
        Assert.Equal(HopHealth.Up, hop.Health);
        Assert.Contains("1/3 anchor devices answer", hop.Note);

        // anchors gone while the rest of the path still answers: the anchors are offline, the switch still forwards
        _prober.Down("10.40.7.3");
        await _mon.ProbeOnceAsync();
        await _mon.ProbeOnceAsync();
        Assert.Equal(HopHealth.Degraded, _mon.Path!.Hops[1].Health);

        // the switch really died: nothing behind it answers either
        foreach (var ip in new[] { "10.40.0.2", "10.40.0.1", "10.255.104.1", "62.1.1.1", "62.1.2.1", "62.1.3.1", "1.1.1.1" }) _prober.Down(ip, arp: true);
        await _mon.ProbeOnceAsync();
        await _mon.ProbeOnceAsync();
        Assert.Equal(HopHealth.Down, _mon.Path!.Hops[1].Health);
        Assert.Equal(_o.TvRack.Mac, _mon.Path.FirstFailing!.Mac);
    }

    [Fact]
    public async Task Rebuild_keeps_history_for_surviving_hops()
    {
        _mon.Rebuild();
        await _mon.ProbeOnceAsync();
        await _mon.ProbeOnceAsync();
        _mon.Rebuild();
        Assert.Equal(2, _mon.Path!.Hops.Single(h => h.Role == HopRole.Firewall).Recent.Count);
    }

    [Fact]
    public void Disabled_monitor_does_not_run()
    {
        _settings.Settings.PathMonitorEnabled = false;
        _mon.Start();
        Assert.False(_mon.IsRunning);
        _settings.Settings.PathMonitorEnabled = true;
        _settings.Save();
        Assert.True(_mon.IsRunning);
        _settings.Settings.PathMonitorEnabled = false;
        _settings.Save();
        Assert.False(_mon.IsRunning);
    }

    public void Dispose() => _mon.Dispose();
}
