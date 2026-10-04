using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Host→device latency primitives.
/// <para>
/// ARP/NDP RTTs are measured on the wire: Npcap loops our injected request back to us with a HIPREC timestamp, and the
/// reply carries a timestamp from the same clock, so RTT = reply.TimestampUtc − outbound.TimestampUtc. If the looped-back
/// copy is not seen (driver quirk), the fallback is reply.ArrivalTicks − Stopwatch ticks taken just before sending.
/// </para>
/// Pending requests live in a table keyed by target IP; concurrent pings to different IPs are independent and a second
/// ping to an IP that is already pending piggybacks on the in-flight request.
/// </summary>
public sealed class LatencyProber : ILatencyProber, IFrameHandler
{
    private readonly ILogger<LatencyProber> _log;
    private readonly IFrameSource _frames;
    private readonly IDeviceStore _store;
    private readonly ActivityPublisher _activity;
    private readonly ConcurrentDictionary<IPAddress, Pending> _arp = new();
    private readonly ConcurrentDictionary<IPAddress, Pending> _ndp = new();

    public LatencyProber(ILogger<LatencyProber> log, IFrameSource frames, IDeviceStore store, ActivityPublisher activity)
    {
        _log = log;
        _frames = frames;
        _store = store;
        _activity = activity;
    }

    /// <summary>A reply as seen by the capture thread.</summary>
    internal readonly record struct Reply(Mac Mac, DateTime TimestampUtc, long ArrivalTicks);

    internal sealed class Pending
    {
        public readonly TaskCompletionSource<Reply> Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>Stopwatch ticks right before the send (0 until the send returned).</summary>
        public long SendTicks;
        /// <summary>pcap timestamp of the looped-back copy of our request; written by the capture thread.</summary>
        public DateTime? OutboundTimestamp;

        public double? RttMs(Reply r)
        {
            if (OutboundTimestamp is { } o && r.TimestampUtc >= o && r.TimestampUtc - o < TimeSpan.FromSeconds(30))
                return (r.TimestampUtc - o).TotalMilliseconds;
            long send = Volatile.Read(ref SendTicks);
            if (send != 0 && r.ArrivalTicks >= send) return (r.ArrivalTicks - send) * 1000.0 / Stopwatch.Frequency;
            return null;
        }
    }

    // ============================================================ ARP

    public Task<(double? Ms, Mac? Mac)> ArpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct) =>
        ArpPingCoreAsync(ip, timeout, paced: false, vlanId: null, ct);

    /// <summary>ARP ping; <paramref name="paced"/> routes the send through the global injection rate limiter (bulk sweeps).</summary>
    public async Task<(double? Ms, Mac? Mac)> ArpPingCoreAsync(IPAddress ip, TimeSpan timeout, bool paced, int? vlanId, CancellationToken ct)
    {
        try
        {
            ip = DeviceHints.Normalize(ip);
            var adapter = _frames.Adapter;
            if (!_frames.IsRunning || adapter is null || ip.AddressFamily != AddressFamily.InterNetwork) return (null, null);
            var src = adapter.IPv4.FirstOrDefault(a => IpUtil.InSubnet(ip, a.Address, a.PrefixLength))?.Address ?? adapter.PrimaryV4?.Address;
            if (src is null) return (null, null);

            var pending = new Pending();
            var existing = _arp.GetOrAdd(ip, pending);
            if (!ReferenceEquals(existing, pending))
            {
                // Another ping to this IP is in flight: share its outcome.
                var shared = await WaitAsync(existing.Tcs.Task, timeout, ct).ConfigureAwait(false);
                return shared is { } sr ? (existing.RttMs(sr), sr.Mac) : (null, null);
            }

            try
            {
                var frame = FrameBuilder.ArpRequest(adapter.Mac, src, ip, vlanId);
                long ticks = paced ? await _frames.SendPacedAsync(frame, ct).ConfigureAwait(false) : _frames.Send(frame);
                Volatile.Write(ref pending.SendTicks, ticks);
                var reply = await WaitAsync(pending.Tcs.Task, timeout, ct).ConfigureAwait(false);
                if (reply is not { } r) return (null, null);
                return (pending.RttMs(r), r.Mac);
            }
            finally
            {
                _arp.TryRemove(new KeyValuePair<IPAddress, Pending>(ip, pending));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ARP ping {Ip} failed", ip);
            return (null, null);
        }
    }

    // ============================================================ NDP

    public Task<double?> NdpPingAsync(IPAddress ipv6, Mac? knownMac, TimeSpan timeout, CancellationToken ct) =>
        NdpPingCoreAsync(ipv6, knownMac, timeout, paced: false, ct);

    public async Task<double?> NdpPingCoreAsync(IPAddress ipv6, Mac? knownMac, TimeSpan timeout, bool paced, CancellationToken ct)
    {
        try
        {
            ipv6 = DeviceHints.Normalize(ipv6);
            var adapter = _frames.Adapter;
            if (!_frames.IsRunning || adapter is null || ipv6.AddressFamily != AddressFamily.InterNetworkV6) return null;
            var src = SourceV6For(adapter, ipv6);
            if (src is null) return null;

            var pending = new Pending();
            var existing = _ndp.GetOrAdd(ipv6, pending);
            if (!ReferenceEquals(existing, pending))
            {
                var shared = await WaitAsync(existing.Tcs.Task, timeout, ct).ConfigureAwait(false);
                return shared is { } sr ? existing.RttMs(sr) : null;
            }
            try
            {
                var frame = FrameBuilder.NeighborSolicitation(adapter.Mac, src, ipv6, knownMac);
                long ticks = paced ? await _frames.SendPacedAsync(frame, ct).ConfigureAwait(false) : _frames.Send(frame);
                Volatile.Write(ref pending.SendTicks, ticks);
                var reply = await WaitAsync(pending.Tcs.Task, timeout, ct).ConfigureAwait(false);
                return reply is { } r ? pending.RttMs(r) : null;
            }
            finally
            {
                _ndp.TryRemove(new KeyValuePair<IPAddress, Pending>(ipv6, pending));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "NDP ping {Ip} failed", ipv6);
            return null;
        }
    }

    /// <summary>Link-local targets use our link-local source; global targets prefer a global source.</summary>
    internal static IPAddress? SourceV6For(AdapterInfo adapter, IPAddress target)
    {
        if (target.IsIPv6LinkLocal) return adapter.LinkLocalV6 is { } ll ? DeviceHints.Normalize(ll) : null;
        var global = adapter.IPv6.FirstOrDefault(a => !a.IsIPv6LinkLocal && !a.IsIPv6Multicast);
        return DeviceHints.Normalize(global ?? adapter.LinkLocalV6 ?? IPAddress.IPv6None);
    }

    // ============================================================ ICMP / TCP

    public async Task<double?> IcmpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct, int payloadSize = 32, bool dontFragment = false)
    {
        try
        {
            using var ping = new Ping();
            var buffer = new byte[Math.Clamp(payloadSize, 0, 65500)];
            for (int i = 0; i < buffer.Length; i++) buffer[i] = (byte)('a' + i % 23);
            var options = new PingOptions(128, dontFragment);
            long t0 = Stopwatch.GetTimestamp();
            var reply = await ping.SendPingAsync(ip, timeout, buffer, options, ct).ConfigureAwait(false);
            double elapsed = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
            if (reply.Status != IPStatus.Success) return null;
            if (reply.Options?.Ttl is int ttl and > 0) RecordTtl(ip, ttl);
            // RoundtripTime is integer ms; prefer our stopwatch unless it is clearly inflated by scheduling.
            double rtt = reply.RoundtripTime > 0 && elapsed > reply.RoundtripTime + 1 ? reply.RoundtripTime : elapsed;
            return rtt;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ICMP ping {Ip} failed", ip);
            return null;
        }
    }

    private void RecordTtl(IPAddress ip, int ttl)
    {
        var d = _store.FindByIp(ip);
        if (d is null || d.Ttl == ttl) return;
        d.Ttl = ttl;
        d.AddEvidence("icmp", Fields.Ttl, ttl.ToString(System.Globalization.CultureInfo.InvariantCulture), Confidence.Ttl);
        _store.NotifyChanged(d, "ttl");
    }

    public async Task<double?> TcpPingAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, LingerState = new LingerOption(true, 0) };
        long t0 = Stopwatch.GetTimestamp();
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            return Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        }
        catch (SocketException se) when (se.SocketErrorCode == SocketError.ConnectionRefused)
        {
            // RST is a valid round trip: the host is alive and answered.
            return Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "TCP ping {Ip}:{Port} failed", ip, port);
            return null;
        }
    }

    // ============================================================ frame matching (capture thread)

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            var eth = frame.Eth;
            if (!eth.Valid) return;
            if (eth.EtherType == EthernetView.Arp) { if (!_arp.IsEmpty) OnArp(frame); }
            else if (eth.EtherType == EthernetView.Ipv6 && !_ndp.IsEmpty) OnIpv6(frame);
        }
        catch (Exception ex) { _log.LogDebug(ex, "LatencyProber frame"); }
    }

    private void OnArp(CapturedFrame frame)
    {
        var p = frame.Payload;
        if (!ArpPacket.TryPeek(p, out var op, out var spa, out var tpa)) return;
        if (frame.IsOutbound)
        {
            if (op == ArpPacket.Request && _arp.TryGetValue(IpUtil.FromUInt32(tpa), out var pend) && pend.OutboundTimestamp is null)
                pend.OutboundTimestamp = frame.TimestampUtc;
            return;
        }
        if (op != ArpPacket.Reply) return;
        if (!_arp.TryGetValue(IpUtil.FromUInt32(spa), out var pending)) return;
        var arp = ArpPacket.Parse(p);
        var local = _frames.Adapter?.Mac ?? Mac.Zero;
        if (arp is null || (arp.TargetMac != local && frame.Eth.Destination != local)) return;
        pending.Tcs.TrySetResult(new Reply(arp.SenderMac, frame.TimestampUtc, frame.ArrivalTicks));
    }

    private void OnIpv6(CapturedFrame frame)
    {
        var p = frame.Payload;
        if (!IpView.TryParse(p, EthernetView.Ipv6, out var ip) || ip.Protocol != IpView.Icmp6) return;
        var icmp = ip.L4(p);
        if (icmp.Length < 24 || icmp[0] is not (NdpParser.NeighborSolicitation or NdpParser.NeighborAdvertisement)) return;
        var target = new IPAddress(icmp.Slice(8, 16));
        if (!_ndp.TryGetValue(target, out var pending)) return;
        if (frame.IsOutbound)
        {
            if (icmp[0] == NdpParser.NeighborSolicitation && pending.OutboundTimestamp is null) pending.OutboundTimestamp = frame.TimestampUtc;
            return;
        }
        if (icmp[0] != NdpParser.NeighborAdvertisement) return;
        var na = NdpParser.ParseNeighbor(icmp);
        pending.Tcs.TrySetResult(new Reply(na?.LinkLayer ?? frame.Eth.Source, frame.TimestampUtc, frame.ArrivalTicks));
        _activity.Publish(frame.Eth.Source, "NDP");
    }

    private static async Task<Reply?> WaitAsync(Task<Reply> task, TimeSpan timeout, CancellationToken ct)
    {
        try { return await task.WaitAsync(timeout, ct).ConfigureAwait(false); }
        catch (TimeoutException) { return null; }
    }
}
