using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class LocalVantageTests
{
    private static ProbeTargetResult Up(string target, string ip) => new(target, ip, 2, 2, 0, 10, null);
    private static ProbeTargetResult Down(string target, string ip) => new(target, ip, null, null, 100, 10, "TimedOut");

    private static List<ProbeTargetResult> Side(bool gw, bool net, bool peer, string peerIp) =>
    [
        gw ? Up("gw", "10.40.0.1") : Down("gw", "10.40.0.1"),
        net ? Up("internet", "1.1.1.1") : Down("internet", "1.1.1.1"),
        peer ? Up("peer:x", peerIp) : Down("peer:x", peerIp),
    ];

    private static DualPathVerdictResult V(bool wGw, bool wNet, bool wPeer, bool fGw, bool fNet, bool fPeer) =>
        DualPathVerdict.Evaluate(Side(wGw, wNet, wPeer, "10.40.211.5"), Side(fGw, fNet, fPeer, "10.40.210.17"), "10.40.210.17", "10.40.211.5");

    [Fact]
    public void All_good_is_ok()
    {
        var v = V(true, true, true, true, true, true);
        Assert.Equal(DualPathSuspect.Ok, v.Suspect);
        Assert.Contains("crossover works both ways", v.Sentence);
    }

    [Fact]
    public void Wifi_side()
    {
        var v = V(true, true, true, false, false, false);
        Assert.Equal(DualPathSuspect.WifiSide, v.Suspect);
        Assert.Equal("Wi-Fi adapter (10.40.211.5) cannot reach gateway 10.40.0.1, wired adapter can → problem on the Wi-Fi side (AP/radio or AP uplink)", v.Sentence);
    }

    [Fact]
    public void Wired_side() => Assert.Equal(DualPathSuspect.WiredSide, V(false, false, false, true, true, true).Suspect);

    [Fact]
    public void Crossover_failure_is_bridge_or_isolation()
    {
        var v = V(true, true, false, true, true, true);
        Assert.Equal(DualPathSuspect.ApLanBridge, v.Suspect);
        Assert.Equal("wired → own Wi-Fi IP fails but both reach the gateway → AP/LAN bridging or client isolation", v.Sentence);
        Assert.Contains("both directions", V(true, true, false, true, true, false).Sentence);
    }

    [Fact]
    public void Upstream_cases()
    {
        Assert.Equal(DualPathSuspect.Upstream, V(false, false, true, false, false, true).Suspect); // no gateway from either side
        var wan = V(true, false, true, true, false, true);
        Assert.Equal(DualPathSuspect.Upstream, wan.Suspect);
        Assert.Contains("router WAN, modem or ISP", wan.Sentence);
    }

    [Fact]
    public void Internet_only_from_one_side() => Assert.Equal(DualPathSuspect.WifiSide, V(true, true, true, true, false, true).Suspect);

    [Fact]
    public void No_samples_is_inconclusive() =>
        Assert.Equal(DualPathSuspect.Inconclusive, DualPathVerdict.Evaluate([], []).Suspect);

    [Fact]
    public void Eligibility_and_targets()
    {
        var wired = new LocalVantage("Ethernet 2", "Wired", IPAddress.Parse("10.40.210.17"), 16, IPAddress.Parse("10.40.0.1"), "AA:00:00:00:00:01");
        var wifi = new LocalVantage("Wi-Fi", "Wi-Fi", IPAddress.Parse("10.40.211.5"), 16, null, "AA:00:00:00:00:02"); // same subnet, no gateway
        var lonely = new LocalVantage("USB", "Wired", IPAddress.Parse("192.168.50.2"), 24, null, null);           // no gateway, no shared subnet
        var eligible = LocalVantageMonitor.Eligible([wifi, lonely, wired]);
        Assert.Equal([wired, wifi], eligible);

        var t = LocalVantageMonitor.TargetsFor(wired, eligible).Select(x => (x.Target, x.Ip.ToString())).ToList();
        Assert.Equal([("gw", "10.40.0.1"), ("peer:Wi-Fi", "10.40.211.5"), ("internet", "1.1.1.1")], t);
        var w = LocalVantageMonitor.TargetsFor(wifi, eligible).Select(x => x.Target).ToList();
        Assert.Equal(["gw:Ethernet 2", "peer:Ethernet 2", "internet"], w);
    }

    [Fact]
    public void Local_reports_appear_as_agents_with_custom_summaries()
    {
        var store = new SettingsStore(Path.Combine(Path.GetTempPath(), $"ns-local-{Guid.NewGuid():N}.json"));
        var bus = new EventBus();
        var signals = new ConcurrentQueue<DiagnosticSignal>();
        bus.Subscribe<DiagnosticSignal>(signals.Enqueue);
        var alerts = new AlertService();
        using var hub = new ProbeAgentHub(store, new DeviceStore(), bus, alerts, NullLogger<ProbeAgentHub>.Instance);
        var t0 = DateTimeOffset.Now;
        ProbeAgentReport R(DateTimeOffset t, ProbeTargetResult r) => new("local:Wi-Fi", "This PC (Wi-Fi)", "10.40.211.5", "AA:00:00:00:00:02", "Wi-Fi", t, [r], null, "10.40.0.1", "local");

        hub.IngestLocal(R(t0, Up("gw", "10.40.0.1")), (r, f) => ("custom " + f, 0.6));
        hub.IngestLocal(R(t0.AddSeconds(2), Down("gw", "10.40.0.1")), (r, f) => ("custom " + f, 0.6));
        hub.IngestLocal(R(t0.AddSeconds(4), Up("gw", "10.40.0.1")), (r, f) => ("custom " + f, 0.6));

        var a = Assert.Single(hub.Agents);
        Assert.Equal("local:Wi-Fi", a.AgentId);
        Assert.Equal(["custom True", "custom False"], signals.Select(s => s.Summary));
        Assert.Equal([SignalKind.AgentReportFailure, SignalKind.AgentReportRecovered], signals.Select(s => s.Kind));
        Assert.Empty(alerts.Alerts); // no "agent registered" alert for this PC's own adapters
        Assert.True(hub.RemoveAgent("local:Wi-Fi"));
        Assert.Empty(hub.Agents);
    }

    [Fact]
    public async Task Source_bound_icmp_over_loopback()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (ms, err) = await SourceBoundPing.IcmpAsync(IPAddress.Loopback, IPAddress.Loopback, 1000);
        Assert.Null(err);
        Assert.NotNull(ms);
    }
}
