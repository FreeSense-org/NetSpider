using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics;
using NetSpider.Diagnostics.Health;
using NetSpider.Diagnostics.Topology;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics;

public sealed class HealthServiceTests
{
    [Theory]
    [InlineData(2, 'A')]
    [InlineData(12, 'B')]
    [InlineData(45, 'C')]
    [InlineData(150, 'D')]
    [InlineData(450, 'F')]
    public void Bufferbloat_grades(double increase, char grade) => Assert.Equal(grade, HealthService.GradeBufferbloat(increase));

    [Fact]
    public void Dns_query_encoding_matches_wire_format()
    {
        var q = DnsWire.EncodeQuery(0xBEEF, "www.example.com");
        Assert.Equal(new byte[] { 0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }, q[..12]);
        Assert.Equal(new byte[] { 3, (byte)'w', (byte)'w', (byte)'w', 7 }, q[12..17]);
        Assert.Equal(new byte[] { 0, 0, 1, 0, 1 }, q[^5..]); // root, QTYPE A, QCLASS IN
    }

    [Fact]
    public void Dns_response_with_compression_cname_and_two_a_records_decodes()
    {
        var q = DnsWire.EncodeQuery(0x1234, "example.com");
        var resp = new List<byte>(q);
        resp[2] = 0x81; resp[3] = 0x80;          // response, RD, RA, NOERROR
        resp[7] = 3;                              // ANCOUNT
        // CNAME answer (skipped), name = pointer to question
        resp.AddRange([0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, (byte)'x', 0xC0, 0x0C]);
        resp.AddRange([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        resp.AddRange([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 35]);
        var r = DnsWire.Decode(resp.ToArray());
        Assert.NotNull(r);
        Assert.Equal(0x1234, r!.Id);
        Assert.Equal(DnsWire.RcodeNoError, r.Rcode);
        Assert.Equal([IPAddress.Parse("93.184.216.34"), IPAddress.Parse("93.184.216.35")], r.Addresses);

        var nx = q.ToArray();
        nx[2] = 0x81; nx[3] = 0x83;
        Assert.Equal(DnsWire.RcodeNxDomain, DnsWire.Decode(nx)!.Rcode);
        Assert.Null(DnsWire.Decode(q)); // a query is not a response
    }

    [Fact]
    public void Device_checks_derive_findings_from_flags_ports_and_certificates()
    {
        var devices = new DeviceStore();
        var network = new NetworkState();
        var alerts = new AlertService();
        var svc = new HealthService(NullLogger<HealthService>.Instance, network, devices, alerts, new AppSettings());

        var sw = AddDevice(devices, "00:1B:21:00:00:01", "192.168.1.2", DeviceType.AccessSwitch);
        sw.SetPort(new PortInfo(23, "tcp", PortState.Open, "telnet"));
        sw.SetFlag(DeviceFlags.DefaultSnmpCommunity);
        var nas = AddDevice(devices, "00:11:32:00:00:01", "192.168.1.5", DeviceType.Nas, DeviceFlags.SmbV1);
        nas.SetCertificate(new TlsCertInfo(5001, "CN=synology", "synology", [], "CN=synology", null, DateTime.UtcNow.AddYears(-3), DateTime.UtcNow.AddDays(-5), "01", "AB", true));
        AddDevice(devices, "00:50:B6:00:00:01", "192.168.1.20");

        var results = svc.RunDeviceChecks().ToDictionary(r => r.Id);
        Assert.True(sw.Has(DeviceFlags.CleartextManagement));
        Assert.True(nas.Has(DeviceFlags.ExpiredCertificate));
        Assert.Equal(HealthStatus.Warn, results["cleartext"].Status);
        Assert.Equal(sw.Mac, results["cleartext"].Device);
        Assert.NotEqual(HealthStatus.Pass, results["snmp"].Status);
        Assert.NotEqual(HealthStatus.Pass, results["smbv1"].Status);
        Assert.NotEqual(HealthStatus.Pass, results["certs"].Status);
        Assert.Contains("self-signed", results["certs"].Details);
        Assert.Equal(HealthStatus.Pass, results["rogue"].Status);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.CleartextManagement && a.Source == sw.Mac);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.DefaultSnmpCommunity);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.SmbV1 && a.Source == nas.Mac);
    }

    [Fact]
    public void Rogue_dhcp_fails_and_raises_critical()
    {
        var devices = new DeviceStore();
        var network = new NetworkState();
        var alerts = new AlertService();
        var rogue = AddDevice(devices, "00:50:B6:00:00:66", "192.168.1.66");
        network.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("192.168.1.66"), rogue.Mac, IPAddress.Parse("192.168.1.200"), null, [], null, null, DateTimeOffset.Now, true));
        var svc = new HealthService(NullLogger<HealthService>.Instance, network, devices, alerts, new AppSettings());
        var r = svc.RunDeviceChecks().Single(x => x.Id == "rogue");
        Assert.Equal(HealthStatus.Fail, r.Status);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.RogueDhcp && a.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void Overall_score_is_weighted_and_ignores_skipped()
    {
        var checks = new[]
        {
            new HealthCheckResult("gateway", "Gateway", HealthStatus.Pass, 100, ""),   // weight 3
            new HealthCheckResult("ipv6", "IPv6", HealthStatus.Warn, 60, ""),          // weight 0.5
            new HealthCheckResult("dns", "DNS", HealthStatus.Fail, 0, ""),             // weight 2
            new HealthCheckResult("bufferbloat", "B", HealthStatus.Skipped, 0, ""),
        };
        Assert.Equal((int)Math.Round((300 + 30 + 0) / 5.5), HealthService.OverallScore(checks));
        Assert.Equal(100, HealthService.OverallScore([]));
    }
}

public sealed class ScanOrchestratorTests
{
    private sealed class RecordingProbe(string name, int order, List<string> log, bool fail = false) : IActiveProbe
    {
        public string Name => name;
        public ProbeLayer Layer => ProbeLayer.L2;
        public int Order => order;
        public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            lock (log) log.Add(name);
            progress?.Report(new ScanProgress(name, 0.5));
            await Task.Yield();
            if (fail) throw new InvalidOperationException("boom");
        }
    }

    private sealed class DiscoveringProbe(IDeviceStore store) : IActiveProbe
    {
        public string Name => "arp-sweep";
        public ProbeLayer Layer => ProbeLayer.L2;
        public int Order => 10;
        public Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
        {
            store.Observe(Mac.Parse("00:0D:B9:00:00:01"), IPAddress.Parse("192.168.1.1"), "arp");
            store.Observe(Mac.Parse("00:50:B6:00:00:01"), IPAddress.Parse("192.168.1.20"), "arp");
            return Task.CompletedTask;
        }
    }

    private sealed class CountingDeviceProbe(string name, int order, List<string> log) : IDeviceProbe
    {
        public string Name => name;
        public int Order => order;
        public bool AppliesTo(Device device, ScanContext ctx) => true;
        public Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
        {
            lock (log) log.Add($"{name}:{device.Mac}");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeClassifier : IDeviceClassifier
    {
        public int Calls;
        public bool Classify(Device device)
        {
            Interlocked.Increment(ref Calls);
            if (device.PrimaryIPv4?.ToString() == "192.168.1.1" && device.Type != DeviceType.Router) { device.Type = DeviceType.Router; return true; }
            return false;
        }
    }

    private sealed class FakeOui : IOuiLookup
    {
        public string? Lookup(Mac mac) => mac.Oui24 == 0x000DB9 ? "PC Engines" : null;
        public int Count => 1;
        public Task EnsureLoadedAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    [Fact]
    public async Task Start_monitoring_without_npcap_throws_clear_error()
    {
        var sp = new FakeServiceProvider().Add<IFrameSource>(new FakeFrameSource { PcapAvailable = false });
        var alerts = new AlertService();
        var o = new ScanOrchestrator(NullLogger<ScanOrchestrator>.Instance, sp, new DeviceStore(), new TopologyStore(), new NetworkState(), alerts, new EventBus(), new AppSettings());
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => o.StartMonitoringAsync(Adapter()));
        Assert.Contains("Npcap", ex.Message);
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.NpcapMissing);
        Assert.False(o.IsMonitoring);
        await Assert.ThrowsAsync<InvalidOperationException>(() => o.RunFullScanAsync());
    }

    [Fact]
    public async Task Full_scan_runs_probes_in_order_isolates_failures_and_completes()
    {
        var devices = new DeviceStore();
        var topology = new TopologyStore();
        var network = new NetworkState();
        var log = new List<string>();
        var source = new FakeFrameSource();
        var classifier = new FakeClassifier();
        var handler = new PassiveHandler();
        var sp = new FakeServiceProvider()
            .Add<IFrameSource>(source)
            .Add<IFrameHandler>(handler)
            .Add<IOuiLookup>(new FakeOui())
            .Add<IDeviceClassifier>(classifier)
            .Add<ITopologyBuilder>(new TopologyBuilder(NullLogger<TopologyBuilder>.Instance, devices, topology, network))
            .Add<IActiveProbe>(new RecordingProbe("mdns", 200, log))
            .Add<IActiveProbe>(new RecordingProbe("broken", 150, log, fail: true))
            .Add<IActiveProbe>(new DiscoveringProbe(devices))
            .Add<IActiveProbe>(new RecordingProbe("icmp", 100, log))
            .Add<IDeviceProbe>(new CountingDeviceProbe("tls", 20, log))
            .Add<IDeviceProbe>(new CountingDeviceProbe("ports", 10, log));
        var o = new ScanOrchestrator(NullLogger<ScanOrchestrator>.Instance, sp, devices, topology, network, new AlertService(), new EventBus(), new AppSettings());

        await o.StartMonitoringAsync(Adapter());
        Assert.True(o.IsMonitoring);
        Assert.True(source.IsRunning);
        Assert.Contains(handler, source.Handlers);
        Assert.Contains(network.Segments, s => s.IsLocal && s.Cidr == "192.168.1.0/24");
        Assert.True(devices.TryGet(LocalMac, out var me) && me.Has(DeviceFlags.ThisHost));

        var progress = new List<ScanProgress>();
        int completed = 0;
        o.Progress += p => { lock (progress) progress.Add(p); };
        o.ScanCompleted += () => completed++;
        await o.RunFullScanAsync();

        Assert.Equal(["icmp", "broken", "mdns"], log.Where(x => !x.Contains(':')).ToList());
        var gwMac = Mac.Parse("00:0D:B9:00:00:01");
        var perDevice = log.Where(x => x.EndsWith(gwMac.ToString())).ToList();
        Assert.Equal([$"ports:{gwMac}", $"tls:{gwMac}"], perDevice);
        Assert.DoesNotContain(log, x => x.EndsWith(LocalMac.ToString())); // this host is not probed
        Assert.Equal(1, completed);
        Assert.Equal(1.0, progress[^1].Fraction);
        Assert.True(progress.Select(p => p.Fraction).Zip(progress.Skip(1).Select(p => p.Fraction)).All(z => z.Second >= z.First - 1e-9));

        Assert.True(devices.TryGet(gwMac, out var gw));
        Assert.True(gw.Has(DeviceFlags.Gateway));
        Assert.Equal("PC Engines", gw.OuiVendor);
        Assert.Equal(DeviceType.Router, gw.Type);
        Assert.True(classifier.Calls > 0);
        Assert.NotEmpty(topology.Links);
        Assert.Contains(topology.PairLatencies, p => p.Origin == LatencyOrigin.Estimated);

        o.StopAll();
        Assert.False(o.IsMonitoring);
        Assert.False(source.IsRunning);
        Assert.Empty(source.Handlers);
    }

    private sealed class PassiveHandler : IFrameHandler
    {
        public void OnFrame(CapturedFrame frame) { }
    }
}
