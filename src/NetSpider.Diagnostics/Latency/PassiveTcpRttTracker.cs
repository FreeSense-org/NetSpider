using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Latency;

/// <summary>
/// Times TCP three-way handshakes seen on the wire (IPv4 and IPv6). From the capture point:
/// server RTT = t(SYN/ACK) − t(SYN), client RTT = t(ACK) − t(SYN/ACK). When neither endpoint is this host
/// (SPAN/mirror port or shared medium) their sum is the client↔server RTT, stored as a measured "passive-tcp" pair latency.
/// </summary>
public sealed class PassiveTcpRttTracker : IFrameHandler
{
    public const string Method = "passive-tcp";
    public const int MaxHalfOpen = 10_000;
    private static readonly TimeSpan MaxHandshake = TimeSpan.FromSeconds(3);

    private readonly ILogger<PassiveTcpRttTracker> _log;
    private readonly ITopologyStore _topology;
    private readonly IDeviceStore _devices;
    private readonly INetworkState _network;
    private readonly IFrameSource _source;

    // touched only on the capture dispatch thread
    private readonly Dictionary<FlowKey, LinkedListNode<HalfOpen>> _pending = new();
    private readonly LinkedList<HalfOpen> _lru = new();

    private readonly ConcurrentDictionary<(Mac, Mac), PairLatency> _measured = new();
    private long _handshakes;

    public PassiveTcpRttTracker(ILogger<PassiveTcpRttTracker> log, ITopologyStore topology, IDeviceStore devices, INetworkState network, IFrameSource source)
    {
        _log = log;
        _topology = topology;
        _devices = devices;
        _network = network;
        _source = source;
    }

    public int PendingCount => _pending.Count;
    public long CompletedHandshakes => Interlocked.Read(ref _handshakes);

    /// <summary>Latest passively measured client↔server RTT between two MACs (order-independent).</summary>
    public PairLatency? TryGet(Mac a, Mac b) => _measured.TryGetValue(Key(a, b), out var p) ? p : null;

    /// <summary>Raised (on the capture thread) for every completed handshake: (client MAC, server MAC, capture→server ms, capture→client ms).</summary>
    public event Action<Mac, Mac, double, double>? HandshakeTimed;

    private readonly record struct FlowKey(IPAddress Client, int ClientPort, IPAddress Server, int ServerPort);

    private sealed class HalfOpen
    {
        public required FlowKey Key;
        public DateTime SynTime;
        public DateTime? SynAckTime;
        public uint ClientIsn;
        public uint ServerIsn;
        public Mac ClientMac;
        public Mac ServerMac;
        public bool Ambiguous;
    }

    public void OnFrame(CapturedFrame frame)
    {
        try { Process(frame); }
        catch (Exception ex) { _log.LogDebug(ex, "passive tcp rtt"); }
    }

    private void Process(CapturedFrame frame)
    {
        var eth = frame.Eth;
        if (!eth.Valid || eth.IsLlc) return;
        var p = frame.Payload;
        IPAddress src, dst;
        int l4;
        if (eth.EtherType == EthernetView.Ipv4)
        {
            if (p.Length < 20 || (p[0] >> 4) != 4 || p[9] != 6) return;
            if ((BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x1FFF) != 0) return; // fragment
            l4 = (p[0] & 0x0F) * 4;
            src = new IPAddress(p.Slice(12, 4));
            dst = new IPAddress(p.Slice(16, 4));
        }
        else if (eth.EtherType == EthernetView.Ipv6)
        {
            if (p.Length < 40 || (p[0] >> 4) != 6 || p[6] != 6) return;
            l4 = 40;
            src = new IPAddress(p.Slice(8, 16));
            dst = new IPAddress(p.Slice(24, 16));
        }
        else return;
        if (p.Length < l4 + 14) return;
        var tcp = p[l4..];
        int sport = BinaryPrimitives.ReadUInt16BigEndian(tcp);
        int dport = BinaryPrimitives.ReadUInt16BigEndian(tcp[2..]);
        uint seq = BinaryPrimitives.ReadUInt32BigEndian(tcp[4..]);
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(tcp[8..]);
        byte flags = tcp[13];
        bool syn = (flags & 0x02) != 0, ackf = (flags & 0x10) != 0, rst = (flags & 0x04) != 0, fin = (flags & 0x01) != 0;
        var t = frame.TimestampUtc;

        if (syn && !ackf)
        {
            var key = new FlowKey(src, sport, dst, dport);
            if (_pending.TryGetValue(key, out var existing))
            {
                // retransmitted SYN: the RTT would be ambiguous (Karn), keep the entry but do not measure it
                existing.Value.Ambiguous = true;
                Touch(existing);
                return;
            }
            var h = new HalfOpen { Key = key, SynTime = t, ClientIsn = seq, ClientMac = eth.Source, ServerMac = eth.Destination };
            var node = _lru.AddFirst(h);
            _pending[key] = node;
            while (_pending.Count > MaxHalfOpen && _lru.Last is { } last)
            {
                _pending.Remove(last.Value.Key);
                _lru.RemoveLast();
            }
            return;
        }

        if (syn && ackf)
        {
            var key = new FlowKey(dst, dport, src, sport);
            if (!_pending.TryGetValue(key, out var node)) return;
            var h = node.Value;
            if (ack != h.ClientIsn + 1) return;
            if (h.SynAckTime is not null) { h.Ambiguous = true; return; } // retransmitted SYN/ACK
            h.SynAckTime = t;
            h.ServerIsn = seq;
            if (h.ServerMac != eth.Source) h.ServerMac = eth.Source;
            Touch(node);
            return;
        }

        if (rst || fin)
        {
            var k1 = new FlowKey(src, sport, dst, dport);
            var k2 = new FlowKey(dst, dport, src, sport);
            Drop(k1); Drop(k2);
            return;
        }

        if (ackf)
        {
            var key = new FlowKey(src, sport, dst, dport);
            if (!_pending.TryGetValue(key, out var node)) return;
            var h = node.Value;
            if (h.SynAckTime is not { } synAck || ack != h.ServerIsn + 1) return;
            Drop(key);
            if (h.Ambiguous) return;
            double serverMs = (synAck - h.SynTime).TotalMilliseconds;
            double clientMs = (t - synAck).TotalMilliseconds;
            if (serverMs < 0 || clientMs < 0 || (t - h.SynTime) > MaxHandshake) return;
            Interlocked.Increment(ref _handshakes);
            try { HandshakeTimed?.Invoke(h.ClientMac, h.ServerMac, serverMs, clientMs); } catch { }
            Record(h, serverMs + clientMs);
        }
    }

    private void Record(HalfOpen h, double totalMs)
    {
        var local = _source.Adapter?.Mac;
        if (local is { } lm && (h.ClientMac == lm || h.ServerMac == lm)) return; // host→device RTT is the latency engine's job
        if (!Acceptable(h.Key.Client, h.ClientMac) || !Acceptable(h.Key.Server, h.ServerMac)) return;
        if (h.ClientMac == h.ServerMac) return;
        var pl = new PairLatency(h.ClientMac, h.ServerMac, Math.Round(Math.Max(0.001, totalMs), 3), LatencyOrigin.Measured, Method, DateTimeOffset.Now);
        _measured[Key(h.ClientMac, h.ServerMac)] = pl;
        _topology.SetPairLatency(pl);
    }

    /// <summary>
    /// The Ethernet MAC identifies the endpoint only when the IP is on a local subnet. For off-subnet IPs the MAC is the
    /// router's, which is only meaningful when the IP is the gateway itself.
    /// </summary>
    private bool Acceptable(IPAddress ip, Mac mac)
    {
        if (mac.IsMulticast || mac.IsZero) return false;
        var segs = _network.Segments;
        var adapter = _source.Adapter;
        bool anyInfo = segs.Count > 0 || adapter is { IPv4.Count: > 0 };
        bool local = ip.IsIPv6LinkLocal;
        if (!local && adapter is not null)
            foreach (var a in adapter.IPv4) if (IpUtil.InSubnet(ip, a.Address, a.PrefixLength)) { local = true; break; }
        if (!local) foreach (var s in segs) if (s.IsLocal && s.Contains(ip)) { local = true; break; }
        if (!local && !anyInfo) local = IpUtil.IsPrivate(ip);
        if (local) return true;
        // off-subnet: accept only the gateway talking from its own address
        var dev = _devices.FindByIp(ip);
        return dev is not null && dev.Mac == mac && dev.Has(DeviceFlags.Gateway);
    }

    private void Touch(LinkedListNode<HalfOpen> node)
    {
        if (node.List is null) return;
        _lru.Remove(node);
        _lru.AddFirst(node);
    }

    private void Drop(FlowKey key)
    {
        if (_pending.Remove(key, out var node) && node.List is not null) _lru.Remove(node);
    }

    private static (Mac, Mac) Key(Mac a, Mac b) => a.Value <= b.Value ? (a, b) : (b, a);
}
