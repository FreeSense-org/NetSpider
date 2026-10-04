using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class LatencyProberTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    private static (L2TestKit Kit, LatencyProber Prober) Create()
    {
        var kit = new L2TestKit();
        var prober = new LatencyProber(NullLogger<LatencyProber>.Instance, kit.Frames, kit.Store, kit.Activity);
        kit.Frames.Subscribe(prober);
        return (kit, prober);
    }

    private static Mac MacFor(IPAddress ip) => new(0x00163E000000UL | IpUtil.ToUInt32(ip) & 0xFF);

    /// <summary>
    /// Simulates Npcap: loops the sent ARP request back (outbound, timestamp T) and, after <paramref name="rttMs"/>(ip),
    /// injects the target's reply with timestamp T + rtt. Replies can be delivered in any order.
    /// </summary>
    private static void ArpResponder(L2TestKit kit, Func<IPAddress, double?> rttMs, bool loopback = true, int replyDelayMs = 5, Mac? replyTo = null)
    {
        int seq = 0;
        kit.Frames.OnSend = (frame, sendTicks) =>
        {
            var f = Frame(frame);
            if (f.Eth.EtherType != EthernetView.Arp) return;
            var arp = ArpPacket.Parse(f.Payload)!;
            var target = arp.TargetIp;
            var rtt = rttMs(target);
            var sentAt = T0.AddSeconds(Interlocked.Increment(ref seq));
            Task.Run(async () =>
            {
                if (loopback) kit.Frames.Deliver(Frame(frame, outbound: true, ts: sentAt, ticks: sendTicks + 10));
                if (rtt is not { } ms) return;
                await Task.Delay(replyDelayMs);
                var reply = FrameBuilder.ArpReply(MacFor(target), target, replyTo ?? LocalMac, LocalIp);
                long arrival = sendTicks + (long)(ms * Stopwatch.Frequency / 1000.0);
                kit.Frames.Deliver(Frame(reply, ts: sentAt.AddTicks((long)(ms * TimeSpan.TicksPerMillisecond)), ticks: arrival));
            });
        };
    }

    [Fact]
    public async Task Arp_rtt_uses_pcap_timestamps_of_loopback_and_reply()
    {
        var (kit, prober) = Create();
        ArpResponder(kit, _ => 0.25);
        var ip = IPAddress.Parse("192.168.1.10");
        var (ms, mac) = await prober.ArpPingAsync(ip, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.NotNull(ms);
        Assert.Equal(0.25, ms.Value, 6);
        Assert.Equal(MacFor(ip), mac);
    }

    [Fact]
    public async Task Concurrent_pings_to_different_ips_are_matched_independently()
    {
        var (kit, prober) = Create();
        var rtts = new Dictionary<string, double> { ["192.168.1.11"] = 0.08, ["192.168.1.12"] = 0.6, ["192.168.1.13"] = 3.2, ["192.168.1.14"] = 12.5 };
        ArpResponder(kit, ip => rtts[ip.ToString()], replyDelayMs: 1);
        var tasks = rtts.Keys.Select(k => (k, prober.ArpPingAsync(IPAddress.Parse(k), TimeSpan.FromSeconds(2), CancellationToken.None))).ToList();
        foreach (var (k, t) in tasks)
        {
            var (ms, mac) = await t;
            Assert.Equal(rtts[k], ms!.Value, 6);
            Assert.Equal(MacFor(IPAddress.Parse(k)), mac);
        }
    }

    [Fact]
    public async Task Falls_back_to_stopwatch_ticks_without_loopback_copy()
    {
        var (kit, prober) = Create();
        ArpResponder(kit, _ => 1.5, loopback: false);
        var (ms, _) = await prober.ArpPingAsync(IPAddress.Parse("192.168.1.20"), TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.NotNull(ms);
        Assert.InRange(ms.Value, 1.49, 1.51);
    }

    [Fact]
    public async Task Timeout_and_foreign_replies_return_null()
    {
        var (kit, prober) = Create();
        ArpResponder(kit, _ => null);
        var sw = Stopwatch.StartNew();
        var (ms, mac) = await prober.ArpPingAsync(IPAddress.Parse("192.168.1.21"), TimeSpan.FromMilliseconds(150), CancellationToken.None);
        Assert.Null(ms);
        Assert.Null(mac);
        Assert.True(sw.ElapsedMilliseconds < 10_000, "timed-out ping must return promptly (generous bound for loaded CI machines)");

        // a reply addressed to some other host must not complete our ping
        var (kit2, prober2) = Create();
        ArpResponder(kit2, _ => 0.3, replyTo: Mac.Parse("00:11:22:33:44:55"));
        var r = await prober2.ArpPingAsync(IPAddress.Parse("192.168.1.22"), TimeSpan.FromMilliseconds(200), CancellationToken.None);
        Assert.Null(r.Ms);
    }

    [Fact]
    public async Task Concurrent_pings_to_same_ip_share_one_request()
    {
        var (kit, prober) = Create();
        ArpResponder(kit, _ => 0.4, replyDelayMs: 50);
        var ip = IPAddress.Parse("192.168.1.30");
        var a = prober.ArpPingAsync(ip, TimeSpan.FromSeconds(2), CancellationToken.None);
        var b = prober.ArpPingAsync(ip, TimeSpan.FromSeconds(2), CancellationToken.None);
        var ra = await a;
        var rb = await b;
        Assert.Single(kit.Frames.Sent);
        Assert.Equal(0.4, ra.Ms!.Value, 6);
        Assert.Equal(0.4, rb.Ms!.Value, 6);
        Assert.Equal(ra.Mac, rb.Mac);
    }

    [Fact]
    public async Task Not_running_returns_null_without_sending()
    {
        var (kit, prober) = Create();
        kit.Frames.IsRunning = false;
        var (ms, mac) = await prober.ArpPingAsync(IPAddress.Parse("192.168.1.10"), TimeSpan.FromMilliseconds(100), CancellationToken.None);
        Assert.Null(ms);
        Assert.Null(mac);
        Assert.Empty(kit.Frames.Sent);
    }

    [Fact]
    public async Task Ndp_ping_matches_neighbor_advertisement()
    {
        var (kit, prober) = Create();
        var target = IPAddress.Parse("fe80::20c:29ff:feaa:1");
        var targetMac = Mac.Parse("00:0C:29:AA:00:01");
        kit.Frames.OnSend = (frame, ticks) =>
        {
            var f = Frame(frame);
            Assert.Equal(EthernetView.Ipv6, f.Eth.EtherType);
            Task.Run(async () =>
            {
                kit.Frames.Deliver(Frame(frame, outbound: true, ts: T0, ticks: ticks));
                await Task.Delay(5);
                byte[] body = [0x60, 0, 0, 0, .. target.GetAddressBytes(), 2, 1, .. targetMac.ToBytes()];
                var na = FrameBuilder.Icmp6Frame(targetMac, LocalMac, target, LocalLinkLocal, 136, 0, body);
                kit.Frames.Deliver(Frame(na, ts: T0.AddTicks(7), ticks: ticks + 1000)); // 0.7 µs
            });
        };
        var ms = await prober.NdpPingAsync(target, targetMac, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.NotNull(ms);
        Assert.Equal(0.0007, ms.Value, 9);
        var ns = Frame(kit.Frames.Sent.Single());
        Assert.Equal(targetMac, ns.Eth.Destination); // unicast NS when the MAC is known
    }

    [Fact]
    public async Task Tcp_ping_counts_refused_as_alive()
    {
        var (_, prober) = Create();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var open = await prober.TcpPingAsync(IPAddress.Loopback, port, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.NotNull(open);
        listener.Stop();
        var refused = await prober.TcpPingAsync(IPAddress.Loopback, port, TimeSpan.FromSeconds(3), CancellationToken.None);
        Assert.NotNull(refused);
    }

    [Fact]
    public async Task Arp_sweep_collects_replies_and_flags_gateway_and_local_host()
    {
        var kit = new L2TestKit();
        kit.Settings.MinSweepPrefix = 24;
        var prober = new LatencyProber(NullLogger<LatencyProber>.Instance, kit.Frames, kit.Store, kit.Activity);
        kit.Frames.Subscribe(prober);
        var alive = new HashSet<string> { "192.168.1.1", "192.168.1.10", "192.168.1.200" };
        ArpResponder(kit, ip => alive.Contains(ip.ToString()) ? 0.3 : null, replyDelayMs: 1);
        var sweep = new ArpSweepProbe(NullLogger<ArpSweepProbe>.Instance, kit.Frames, kit.Store, prober, kit.Ctx);
        var reports = new List<ScanProgress>();

        await sweep.RunAsync(kit.ScanContext(), new SyncProgress(reports.Add), CancellationToken.None);

        foreach (var a in alive)
        {
            var d = kit.Store.FindByIp(IPAddress.Parse(a));
            Assert.NotNull(d);
            Assert.Equal(0.3, d.Latency.Last(LatencyKind.Arp)!.Value, 6);
        }
        Assert.True(kit.Store.FindByIp(GatewayIp)!.Has(DeviceFlags.Gateway));
        Assert.True(kit.Store.TryGet(LocalMac, out var me));
        Assert.True(me.Has(DeviceFlags.ThisHost));
        Assert.Equal(DeviceType.ThisComputer, me.Type);
        // 253 targets (254 hosts minus our own address), unanswered ones probed twice
        Assert.Equal(253 + 250, kit.Frames.Sent.Count);
        var seg = kit.Network.Segments.Single(s => s.IsLocal);
        Assert.Equal(3, seg.HostsFound);
        Assert.NotNull(seg.LastScanned);
        Assert.Equal(1.0, reports[^1].Fraction);
    }

    [Fact]
    public void Sweep_targets_are_capped_to_min_prefix_around_local_address()
    {
        var hosts = ArpSweepProbe.SweepTargets(IPAddress.Parse("10.0.0.0"), 16, 22, IPAddress.Parse("10.0.9.7")).ToList();
        Assert.Equal(1022, hosts.Count);
        Assert.Equal(IPAddress.Parse("10.0.8.1"), hosts[0]);
        Assert.Equal(IPAddress.Parse("10.0.11.254"), hosts[^1]);
    }

    private sealed class SyncProgress(Action<ScanProgress> a) : IProgress<ScanProgress>
    {
        private readonly object _sync = new();
        public void Report(ScanProgress value) { lock (_sync) a(value); }
    }
}
