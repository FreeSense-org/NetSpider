using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class ProbeAgentHubTests
{
    private static SettingsStore TempSettings() => new(Path.Combine(Path.GetTempPath(), $"ns-agent-{Guid.NewGuid():N}.json"));

    private sealed class Rig : IDisposable
    {
        public SettingsStore Settings { get; } = TempSettings();
        public DeviceStore Devices { get; } = new();
        public EventBus Bus { get; } = new();
        public AlertService Alerts { get; } = new();
        public ConcurrentQueue<DiagnosticSignal> Signals { get; } = new();
        public ProbeAgentHub Hub { get; }

        public Rig(bool enabled)
        {
            Settings.Settings.ProbeAgentHubEnabled = enabled;
            Settings.Settings.ProbeAgentPort = 0; // ephemeral
            Bus.Subscribe<DiagnosticSignal>(Signals.Enqueue);
            Hub = new ProbeAgentHub(Settings, Devices, Bus, Alerts, NullLogger<ProbeAgentHub>.Instance) { DiscoveryPort = 0 };
            Hub.Start();
        }

        public byte[] Key => Convert.FromBase64String(Settings.Settings.ProbeAgentKey!);
        public void Dispose() => Hub.Dispose();
    }

    [Fact]
    public void Disabled_by_default_and_no_key_generated()
    {
        var store = TempSettings();
        Assert.False(store.Settings.ProbeAgentHubEnabled);
        Assert.Equal(47810, store.Settings.ProbeAgentPort);
        using var hub = new ProbeAgentHub(store, new DeviceStore(), new EventBus(), new AlertService(), NullLogger<ProbeAgentHub>.Instance);
        hub.Start();
        Assert.False(hub.IsListening);
        Assert.Null(store.Settings.ProbeAgentKey);
    }

    [Fact]
    public async Task Signed_datagram_over_udp_registers_the_agent()
    {
        using var rig = new Rig(enabled: true);
        Assert.True(rig.Hub.IsListening);
        Assert.True(AgentProtocol.TryParseKey(rig.Settings.Settings.ProbeAgentKey, out var key)); // generated + saved
        Assert.Equal(32, key.Length);
        Assert.NotEqual(0, rig.Hub.Port);

        int updates = 0;
        rig.Hub.Updated += () => Interlocked.Increment(ref updates);

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var hubEp = new IPEndPoint(IPAddress.Loopback, rig.Hub.Port);
        // a forged datagram is ignored
        await udp.SendAsync(AgentProtocol.Seal(AgentProtocolTests.Report("EVIL"), Convert.FromBase64String(AgentProtocol.GenerateKey())), hubEp);
        await udp.SendAsync(AgentProtocol.Seal(AgentProtocolTests.Report("LAPTOP-WIFI"), key), hubEp);

        await WaitFor(() => rig.Hub.Agents.Count == 1);
        var agent = Assert.Single(rig.Hub.Agents);
        Assert.Equal("LAPTOP-WIFI", agent.AgentId);
        Assert.True(agent.Online);
        Assert.Equal("Wi-Fi", agent.Medium);
        Assert.NotNull(agent.Latest);
        Assert.Equal(1, rig.Hub.ReportsRejected);
        Assert.True(updates > 0);

        Assert.True(rig.Devices.TryGet(Mac.Parse("60:FF:9E:10:20:30"), out var device));
        Assert.Equal("LAPTOP-WIFI", device.Properties["agent.id"]);
        Assert.Contains(rig.Alerts.Alerts, a => a.Kind == AlertKind.Info && a.Title == "Probe agent registered");

        // discovery over real UDP: valid request answered with the report port
        using var disc = new UdpClient(AddressFamily.InterNetwork);
        var req = AgentProtocol.BuildDiscoveryRequest(key, out var challenge);
        await disc.SendAsync(req, new IPEndPoint(IPAddress.Loopback, rig.Hub.BoundDiscoveryPort));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply = await disc.ReceiveAsync(cts.Token);
        Assert.True(AgentProtocol.TryParseDiscoveryReply(reply.Buffer, key, challenge, out var port));
        Assert.Equal(rig.Hub.Port, port);

        // turning the hub off closes the socket
        rig.Settings.Settings.ProbeAgentHubEnabled = false;
        rig.Settings.Save();
        Assert.False(rig.Hub.IsListening);
    }

    [Fact]
    public async Task Failure_and_recovery_signals()
    {
        using var rig = new Rig(enabled: true);
        var target = rig.Devices.GetOrAdd(Mac.Parse("02:00:00:00:00:99"));
        rig.Devices.Observe(target.Mac, IPAddress.Parse("192.0.2.1"), "test");
        var from = new IPEndPoint(IPAddress.Loopback, 5555);
        var t0 = DateTimeOffset.Now;
        ProbeTargetResult R(double loss, double? rtt) => new("192.0.2.1", "192.0.2.1", rtt, rtt, loss, 10, rtt is null ? "TimedOut" : null);

        Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(AgentProtocol.Seal(AgentProtocolTests.Report(time: t0, results: R(0, 2)), rig.Key), from));
        Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(AgentProtocol.Seal(AgentProtocolTests.Report(time: t0.AddSeconds(2), results: R(60, null)), rig.Key), from));

        // failure publishing cross-checks from the hub (192.0.2.1 is TEST-NET, so "cannot either") and runs async
        await WaitFor(() => rig.Signals.Any(s => s.Kind == SignalKind.AgentReportFailure), TimeSpan.FromSeconds(10));
        var fail = rig.Signals.Single(s => s.Kind == SignalKind.AgentReportFailure);
        Assert.StartsWith("agent LAPTOP-WIFI cannot reach 192.0.2.1 (", fail.Summary);
        Assert.Contains("cannot either", fail.Summary);
        Assert.Equal(target.Mac, fail.Device);
        Assert.Equal([Mac.Parse("60:FF:9E:10:20:30")], fail.Affected);

        Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(AgentProtocol.Seal(AgentProtocolTests.Report(time: t0.AddSeconds(4), results: R(100, null)), rig.Key), from));
        Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(AgentProtocol.Seal(AgentProtocolTests.Report(time: t0.AddSeconds(6), results: R(10, 3)), rig.Key), from));
        Assert.Single(rig.Signals, s => s.Kind == SignalKind.AgentReportFailure);
        var rec = Assert.Single(rig.Signals, s => s.Kind == SignalKind.AgentReportRecovered);
        Assert.Contains("reaches 192.0.2.1 again", rec.Summary);

        // a replayed datagram is rejected
        var d = AgentProtocol.Seal(AgentProtocolTests.Report(time: t0.AddSeconds(8)), rig.Key);
        Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(d, from));
        Assert.Equal(AgentOpenResult.Replay, rig.Hub.Ingest(d, from));
    }

    [Fact]
    public void Chunks_of_one_round_are_merged()
    {
        using var rig = new Rig(enabled: true);
        var results = Enumerable.Range(0, 300).Select(i => new ProbeTargetResult($"host-{i}.example.internal", $"10.1.{i / 256}.{i % 256}", 1, 1, 0, 10, null)).ToArray();
        var from = new IPEndPoint(IPAddress.Loopback, 5555);
        foreach (var d in AgentProtocol.SealChunked(AgentProtocolTests.Report(results: results), rig.Key))
            Assert.Equal(AgentOpenResult.Ok, rig.Hub.Ingest(d, from));
        Assert.Equal(300, Assert.Single(rig.Hub.Agents).Latest!.Results.Count);
    }

    private static async Task WaitFor(Func<bool> cond, TimeSpan? timeout = null)
    {
        var end = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (!cond())
        {
            if (DateTime.UtcNow > end) Assert.Fail("condition not reached in time");
            await Task.Delay(50);
        }
    }
}
