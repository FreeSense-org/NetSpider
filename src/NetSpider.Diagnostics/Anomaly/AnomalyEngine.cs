using System.Buffers.Binary;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Anomaly;

/// <summary>A MAC that moved between ports of one switch (FDB snapshots) within <see cref="AnomalyEngine.MacFlapWindow"/>.</summary>
public sealed record MacFlapInfo(Mac Switch, Mac Mac, IReadOnlyList<string> Ports, int Moves, DateTimeOffset Last);

/// <summary>Point-in-time view of the anomaly engine's detector state (consumed by the Storm Center).</summary>
public sealed record AnomalyState(
    double BroadcastBaseline, double MulticastBaseline, bool BaselineWarmed, bool BroadcastStorm, bool MulticastStorm, bool StormActive,
    int LoopBursts5s, Mac? LastLoopSource, DateTime? LastLoopTimeUtc, int TcEventsInWindow, DateTime? LastTcTimeUtc,
    IReadOnlyList<MacFlapInfo> FlappingMacs, bool SpanModeDetected, double UnknownUnicastPps)
{
    public static readonly AnomalyState Empty = new(0, 0, false, false, false, false, 0, null, null, 0, null, [], false, 0);
}

/// <summary>
/// Network chaos detectors: broadcast/multicast/per-MAC storms (with a learned EWMA baseline), unknown-unicast flooding,
/// L2 loops (duplicate frames, STP topology-change bursts), multiple STP roots, MAC flapping (FDB), mDNS/SSDP spam,
/// top talkers and a missing IGMP querier. Frame-level work happens on the capture thread and is O(1) per frame;
/// rate-based work runs on the one-second <see cref="TrafficSnapshot"/>.
/// Publishes <see cref="DiagnosticSignal"/>s (StormDetected/StormEnded/LoopSuspected/StpTopologyChange) on the event bus
/// (always outside the engine lock) and exposes <see cref="GetState"/> for the Storm Center.
/// </summary>
public sealed class AnomalyEngine : IFrameHandler, IStartable, IDisposable
{
    // ---- tunables (constants where AppSettings has no knob) ----
    public static readonly TimeSpan LoopWindow = TimeSpan.FromMilliseconds(50);
    public const int LoopDuplicateCount = 3;
    public static readonly TimeSpan TcBurstWindow = TimeSpan.FromSeconds(30);
    public const int TcBurstCount = 5;
    public static readonly TimeSpan MacFlapWindow = TimeSpan.FromMinutes(5);
    public const double ProtocolSpamPps = 50;
    public static readonly TimeSpan QuerierTimeout = TimeSpan.FromSeconds(260); // 2 x default 125 s query interval + slack
    public const int StormSustainSeconds = 2;
    /// <summary>Calm seconds after which an active storm is reported as ended.</summary>
    public const int StormEndQuietSeconds = 5;
    private const string SignalSource = "anomaly";

    /// <summary>Foreign unicast frames per second (not to/from us) that indicate flooding when not on a SPAN port.</summary>
    public double UnknownUnicastPps { get; set; } = 200;

    private readonly ILogger<AnomalyEngine> _log;
    private readonly IEventBus _bus;
    private readonly IAlertService _alerts;
    private readonly IDeviceStore _devices;
    private readonly INetworkState _network;
    private readonly IFrameSource _source;
    private readonly AppSettings _settings;
    private readonly object _sync = new();
    private IDisposable? _busSub;
    private bool _started;

    // loop detection
    private readonly Dictionary<(int Hash, int Len), DupEntry> _dups = new();
    private DateTime _lastPrune;
    private readonly Queue<DateTime> _loopEvents = new();
    private Mac? _lastLoopSource;
    private DateTime? _lastLoopTime;
    private DateTime _lastFrameTime;
    private struct DupEntry { public DateTime First; public int Count; public Mac Source; }

    // STP topology changes
    private readonly Dictionary<Mac, (bool Tc, DateTime Last)> _stpSenders = new();
    private readonly Queue<DateTime> _tcEvents = new();
    private DateTime? _lastTcTime;

    // per-second frame buckets
    private long _bucketSecond = -1;
    private int _foreignUnicast;
    private readonly Dictionary<Mac, int> _foreignDst = new();
    private readonly Dictionary<Mac, int> _mdnsBySrc = new();
    private readonly Dictionary<Mac, int> _ssdpBySrc = new();
    private int _floodSeconds;
    private double _lastForeignUnicastPps;

    // SPAN / mirror detection: share of foreign unicast conversations seen in both directions
    private readonly HashSet<(Mac, Mac)> _pairs = new();
    private long _pairWindow = -1;
    private DateTime _spanUntil;

    // IGMP / MLD
    private DateTime? _lastQuery;
    private Mac? _querierMac;
    private bool _groupsSeen;
    private DateTime? _monitorStart;

    // snapshot-level state
    private double _bcastBaseline, _mcastBaseline;
    private int _baselineSamples;
    private int _bcastStormSeconds, _mcastStormSeconds;
    private bool _stormActive;
    private int _stormQuietSeconds;
    private double _stormPeakPps;
    private readonly Dictionary<Mac, int> _stormQuiet = new();
    private DateTime _lastPeriodic;

    // FDB flapping
    private readonly Dictionary<(Mac Sw, Mac Mac), FdbTrack> _fdbHistory = new();
    private readonly Dictionary<(Mac Sw, Mac Mac), FdbTrack> _flapping = new();
    private sealed class FdbTrack
    {
        public FdbTrack(string port) { Port = port; }
        public string Port;
        public readonly List<DateTimeOffset> Moves = new();
        public readonly Dictionary<string, DateTimeOffset> Ports = new(StringComparer.OrdinalIgnoreCase);
    }

    // diagnostic signals are queued under the lock and published after it is released
    private List<DiagnosticSignal> _pendingSignals = new();
    private readonly Dictionary<string, DateTimeOffset> _lastSignal = new();

    // own cooldown so we do not write pcap dumps for alerts the alert service would suppress anyway
    private readonly Dictionary<(AlertKind, Mac?), DateTimeOffset> _lastRaise = new();

    public AnomalyEngine(ILogger<AnomalyEngine> log, IEventBus bus, IAlertService alerts, IDeviceStore devices, INetworkState network, IFrameSource source, AppSettings settings)
    {
        _log = log;
        _bus = bus;
        _alerts = alerts;
        _devices = devices;
        _network = network;
        _source = source;
        _settings = settings;
    }

    /// <summary>true when the capture looks like a SPAN/mirror port (foreign unicast seen in both directions).</summary>
    public bool SpanModeDetected { get; private set; }

    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
        }
        _busSub = _bus.Subscribe<TrafficSnapshot>(OnTraffic);
        _network.Changed += OnNetworkChanged;
    }

    public void Dispose()
    {
        _busSub?.Dispose();
        _network.Changed -= OnNetworkChanged;
    }

    private Mac LocalMac => _source.Adapter?.Mac ?? Mac.Zero;

    // =========================================================================================================
    //  Frame path (capture thread)
    // =========================================================================================================

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            var eth = frame.Eth;
            if (!eth.Valid) return;
            var t = frame.TimestampUtc;
            List<DiagnosticSignal>? signals;
            lock (_sync)
            {
                _lastFrameTime = t;
                try { ProcessFrame(frame, eth, t); }
                finally { signals = TakeSignals(); }
            }
            Flush(signals);
        }
        catch (Exception ex) { _log.LogDebug(ex, "anomaly frame handler"); }
    }

    private void ProcessFrame(CapturedFrame frame, EthernetView eth, DateTime t)
    {
        RollBucket(t);
        if (!frame.IsOutbound) DetectLoop(frame, t);
        if (eth.IsStp) { OnStp(frame, t); return; }

        var dst = eth.Destination;
        var local = LocalMac;
        if (!dst.IsMulticast && dst != local && eth.Source != local && !frame.IsOutbound)
        {
            _foreignUnicast++;
            _foreignDst[dst] = _foreignDst.GetValueOrDefault(dst) + 1;
            TrackPair(eth.Source, dst, t);
        }

        if (eth.EtherType == EthernetView.Ipv4) InspectIpv4(frame, t);
        else if (eth.EtherType == EthernetView.Ipv6) InspectIpv6(frame, t);
    }

    private void DetectLoop(CapturedFrame frame, DateTime t)
    {
        var data = frame.Data;
        var eth = frame.Eth;
        var h = new HashCode();
        if (!eth.Destination.IsMulticast && eth.EtherType == EthernetView.Ipv4 && data.Length >= eth.PayloadOffset + 20)
        {
            // unicast IPv4: ignore TTL (offset 8) and header checksum (10-11), which routers rewrite
            int ip = eth.PayloadOffset;
            h.AddBytes(data.AsSpan(0, ip + 8));
            h.Add(data[ip + 9]);
            h.AddBytes(data.AsSpan(ip + 12));
        }
        else if (!eth.Destination.IsMulticast && eth.EtherType == EthernetView.Ipv6 && data.Length >= eth.PayloadOffset + 40)
        {
            int ip = eth.PayloadOffset;
            h.AddBytes(data.AsSpan(0, ip + 7)); // skip hop limit
            h.AddBytes(data.AsSpan(ip + 8));
        }
        else h.AddBytes(data); // L2 broadcast/multicast: the full frame
        var key = (h.ToHashCode(), data.Length);

        if (_dups.TryGetValue(key, out var e) && t - e.First <= LoopWindow)
        {
            e.Count++;
            int threshold = SpanModeDetected ? LoopDuplicateCount + 2 : LoopDuplicateCount;
            if (e.Count == threshold) OnLoopEvent(e.Source, t);
            _dups[key] = e;
        }
        else _dups[key] = new DupEntry { First = t, Count = 1, Source = eth.Source };

        if (_dups.Count > 4096 && t - _lastPrune > TimeSpan.FromMilliseconds(100))
        {
            _lastPrune = t;
            var cutoff = t - TimeSpan.FromMilliseconds(100);
            foreach (var k in _dups.Where(kv => kv.Value.First < cutoff).Select(kv => kv.Key).ToList()) _dups.Remove(k);
        }
    }

    private void OnLoopEvent(Mac source, DateTime t)
    {
        _loopEvents.Enqueue(t);
        while (_loopEvents.Count > 0 && t - _loopEvents.Peek() > TimeSpan.FromSeconds(5)) _loopEvents.Dequeue();
        int recent2s = _loopEvents.Count(x => t - x <= TimeSpan.FromSeconds(2));
        if (recent2s < 2) return; // a single triple burst can be a chatty host; a loop repeats
        _lastLoopSource = source;
        _lastLoopTime = t;
        var sev = _loopEvents.Count >= 20 ? AlertSeverity.Critical : AlertSeverity.Warning;
        string name = DeviceName(source);
        RaiseStorm(Alert.Create(sev, AlertKind.L2Loop, "Possible layer-2 loop",
            $"Identical frames from {name} seen {LoopDuplicateCount}+ times within {LoopWindow.TotalMilliseconds:0} ms ({_loopEvents.Count} duplicate bursts in 5 s).",
            source, _loopEvents.Count / 5.0), TimeSpan.FromMinutes(2));
        Signal("loop:dup", new DateTimeOffset(t), TimeSpan.FromMinutes(2), SignalKind.LoopSuspected,
            $"Possible layer-2 loop: identical frames from {name} repeat ({_loopEvents.Count} duplicate bursts in 5 s).",
            source, null, _loopEvents.Count >= 20 ? 0.8 : 0.6);
    }

    private void OnStp(CapturedFrame frame, DateTime t)
    {
        var p = frame.Payload;
        if (p.Length < 4 || p[0] != 0 || p[1] != 0) return;
        byte type = p[3];
        bool tc = type == 0x80 || (p.Length >= 5 && (type == 0x00 || type == 0x02) && (p[4] & 0x01) != 0);
        var src = frame.Eth.Source;
        var prev = _stpSenders.GetValueOrDefault(src);
        _stpSenders[src] = (tc, tc ? t : prev.Last);
        if (!tc) return;
        // a single topology change is flagged in every BPDU for ~35 s; count rising edges only
        if (prev.Tc && t - prev.Last < TimeSpan.FromSeconds(10)) return;

        _tcEvents.Enqueue(t);
        _lastTcTime = t;
        while (_tcEvents.Count > 0 && t - _tcEvents.Peek() > TcBurstWindow) _tcEvents.Dequeue();
        Signal($"tc:{src}", new DateTimeOffset(t), TimeSpan.Zero, SignalKind.StpTopologyChange,
            $"STP topology change announced by {DeviceName(src)}.", src, null, 0.3);
        Raise(Alert.Create(AlertSeverity.Info, AlertKind.StpTopologyChange, "STP topology change",
            $"Topology-change BPDU from {DeviceName(src)}.", src), TimeSpan.FromMinutes(5));
        if (_tcEvents.Count >= TcBurstCount)
        {
            RaiseStorm(Alert.Create(AlertSeverity.Warning, AlertKind.L2Loop, "STP topology-change burst",
                $"{_tcEvents.Count} STP topology changes within {TcBurstWindow.TotalSeconds:0} s: a flapping link or a loop is likely.",
                null, _tcEvents.Count), TimeSpan.FromMinutes(2));
            Signal("loop:tc", new DateTimeOffset(t), TimeSpan.FromMinutes(2), SignalKind.LoopSuspected,
                $"{_tcEvents.Count} STP topology changes within {TcBurstWindow.TotalSeconds:0} s: a flapping link or a loop is likely.", null, null, 0.5);
        }
    }

    private void InspectIpv4(CapturedFrame frame, DateTime t)
    {
        var p = frame.Payload;
        if (p.Length < 20 || (p[0] >> 4) != 4) return;
        int ihl = (p[0] & 0x0F) * 4;
        if (p.Length < ihl + 4) return;
        byte proto = p[9];
        if (proto == 17 && p.Length >= ihl + 4)
        {
            int sport = BinaryPrimitives.ReadUInt16BigEndian(p[ihl..]);
            int dport = BinaryPrimitives.ReadUInt16BigEndian(p[(ihl + 2)..]);
            CountUdp(frame.Eth.Source, sport, dport);
        }
        else if (proto == 2)
        {
            byte type = p[ihl];
            if (type == 0x11) { _lastQuery = t; _querierMac = frame.Eth.Source; }
            else if (type is 0x12 or 0x16 or 0x22) _groupsSeen = true;
        }
    }

    private void InspectIpv6(CapturedFrame frame, DateTime t)
    {
        var p = frame.Payload;
        if (p.Length < 40 || (p[0] >> 4) != 6) return;
        int off = 40;
        byte next = p[6];
        // skip a hop-by-hop header (MLD carries the router-alert option)
        if (next == 0 && p.Length >= off + 8) { next = p[off]; off += (p[off + 1] + 1) * 8; }
        if (p.Length < off + 4) return;
        if (next == 17)
        {
            int sport = BinaryPrimitives.ReadUInt16BigEndian(p[off..]);
            int dport = BinaryPrimitives.ReadUInt16BigEndian(p[(off + 2)..]);
            CountUdp(frame.Eth.Source, sport, dport);
        }
        else if (next == 58)
        {
            byte type = p[off];
            if (type == 130) { _lastQuery = t; _querierMac = frame.Eth.Source; }
            else if (type is 131 or 143) _groupsSeen = true;
        }
    }

    private void CountUdp(Mac src, int sport, int dport)
    {
        if (dport == 5353 || sport == 5353) _mdnsBySrc[src] = _mdnsBySrc.GetValueOrDefault(src) + 1;
        else if (dport == 1900 || sport == 1900) _ssdpBySrc[src] = _ssdpBySrc.GetValueOrDefault(src) + 1;
    }

    private void TrackPair(Mac src, Mac dst, DateTime t)
    {
        long window = t.Ticks / (TimeSpan.TicksPerSecond * 10);
        if (window != _pairWindow)
        {
            if (_pairs.Count >= 10)
            {
                int both = _pairs.Count(pp => _pairs.Contains((pp.Item2, pp.Item1)));
                if ((double)both / _pairs.Count >= 0.3) _spanUntil = t + TimeSpan.FromSeconds(60);
            }
            SpanModeDetected = t < _spanUntil;
            _pairs.Clear();
            _pairWindow = window;
        }
        if (_pairs.Count < 5000) _pairs.Add((src, dst));
    }

    /// <summary>Closes the per-second frame bucket when a frame from the next second arrives.</summary>
    private void RollBucket(DateTime t)
    {
        long sec = t.Ticks / TimeSpan.TicksPerSecond;
        if (sec == _bucketSecond) return;
        if (_bucketSecond >= 0) EvaluateBucket(t, (double)Math.Max(1, sec - _bucketSecond));
        _bucketSecond = sec;
        _foreignUnicast = 0;
        _foreignDst.Clear();
        _mdnsBySrc.Clear();
        _ssdpBySrc.Clear();
    }

    private void EvaluateBucket(DateTime t, double seconds)
    {
        // a gap of several seconds means the counts are spread over a longer period
        double pps = _foreignUnicast / seconds;
        _lastForeignUnicastPps = pps;
        if (!SpanModeDetected && pps > UnknownUnicastPps) _floodSeconds++;
        else _floodSeconds = 0;
        if (_floodSeconds >= StormSustainSeconds)
        {
            var top = _foreignDst.OrderByDescending(kv => kv.Value).Take(3).Select(kv => $"{DeviceName(kv.Key)} ({kv.Value / seconds:0} pps)");
            RaiseStorm(Alert.Create(AlertSeverity.Warning, AlertKind.UnknownUnicastFlood, "Unknown-unicast flooding",
                $"{pps:0} unicast frames/s for other hosts reach this port (switch MAC table overflow or aging). Top destinations: {string.Join(", ", top)}.",
                null, pps), TimeSpan.FromMinutes(5));
        }

        foreach (var (src, n) in _mdnsBySrc)
            if (n / seconds > ProtocolSpamPps)
                Raise(Alert.Create(AlertSeverity.Warning, AlertKind.MdnsSpam, "mDNS spam", $"{DeviceName(src)} sends {n / seconds:0} mDNS packets/s.", src, n / seconds), TimeSpan.FromMinutes(10));
        foreach (var (src, n) in _ssdpBySrc)
            if (n / seconds > ProtocolSpamPps)
                Raise(Alert.Create(AlertSeverity.Warning, AlertKind.SsdpSpam, "SSDP spam", $"{DeviceName(src)} sends {n / seconds:0} SSDP packets/s.", src, n / seconds), TimeSpan.FromMinutes(10));
    }

    // =========================================================================================================
    //  Snapshot path (once per second)
    // =========================================================================================================

    public void OnTraffic(TrafficSnapshot snap)
    {
        if (_network.IsDemo) return; // the demo network publishes synthetic snapshots: never alert/learn baselines on them
        try
        {
            List<DiagnosticSignal>? signals;
            lock (_sync)
            {
                try { EvaluateSnapshot(snap); }
                finally { signals = TakeSignals(); }
            }
            Flush(signals);
        }
        catch (Exception ex) { _log.LogDebug(ex, "anomaly snapshot"); }
    }

    private void EvaluateSnapshot(TrafficSnapshot snap)
    {
        var now = snap.Time.UtcDateTime;
        _monitorStart ??= now;

        // ---- broadcast storm ----
        bool warmed = _baselineSamples >= 60;
        bool bStorm = snap.BroadcastRatio > _settings.StormBroadcastRatio &&
                      (snap.BroadcastPps > _settings.StormBroadcastPps ||
                       (warmed && snap.BroadcastPps > Math.Max(_settings.StormBroadcastPps / 2, _bcastBaseline * 8)));
        _bcastStormSeconds = bStorm ? _bcastStormSeconds + 1 : 0;
        if (_bcastStormSeconds >= StormSustainSeconds)
        {
            var sev = snap.BroadcastPps > 5 * _settings.StormBroadcastPps || snap.BroadcastRatio > 0.5 ? AlertSeverity.Critical : AlertSeverity.Warning;
            var top = snap.TopTalkers.OrderByDescending(x => x.BroadcastPps).FirstOrDefault();
            RaiseStorm(Alert.Create(sev, AlertKind.BroadcastStorm, "Broadcast storm",
                $"{snap.BroadcastPps:0} broadcast pps ({snap.BroadcastRatio:P0} of traffic, baseline {_bcastBaseline:0} pps)." +
                (top is { BroadcastPps: > 0 } ? $" Top source: {DeviceName(top.Mac)} ({top.BroadcastPps:0} pps)." : ""),
                null, snap.BroadcastPps), TimeSpan.FromMinutes(2));
        }

        // ---- multicast storm ----
        bool mStorm = snap.MulticastPps > _settings.StormMulticastPps ||
                      (warmed && snap.MulticastPps > Math.Max(_settings.StormMulticastPps / 2, _mcastBaseline * 8));
        _mcastStormSeconds = mStorm ? _mcastStormSeconds + 1 : 0;
        if (_mcastStormSeconds >= StormSustainSeconds)
        {
            var top = snap.TopTalkers.OrderByDescending(x => x.MulticastPps).FirstOrDefault();
            RaiseStorm(Alert.Create(AlertSeverity.Warning, AlertKind.MulticastStorm, "Multicast storm",
                $"{snap.MulticastPps:0} multicast pps ({snap.MulticastRatio:P0} of traffic, baseline {_mcastBaseline:0} pps)." +
                (top is { MulticastPps: > 0 } ? $" Top source: {DeviceName(top.Mac)} ({top.MulticastPps:0} pps)." : ""),
                null, snap.MulticastPps), TimeSpan.FromMinutes(2));
        }

        // ---- storm start/end signals ----
        bool stormNow = _bcastStormSeconds >= StormSustainSeconds || _mcastStormSeconds >= StormSustainSeconds;
        if (stormNow && !_stormActive)
        {
            _stormActive = true;
            _stormQuietSeconds = 0;
            _stormPeakPps = snap.BroadcastPps + snap.MulticastPps;
            bool b = _bcastStormSeconds >= StormSustainSeconds;
            var top = snap.TopTalkers.Where(x => x.Mac != LocalMac).OrderByDescending(x => b ? x.BroadcastPps : x.MulticastPps).FirstOrDefault();
            bool hasTop = top is not null && (b ? top.BroadcastPps : top.MulticastPps) > 0;
            Signal("storm:start", snap.Time, TimeSpan.Zero, SignalKind.StormDetected,
                $"{(b ? "Broadcast" : "Multicast")} storm: {snap.BroadcastPps:0} broadcast pps, {snap.MulticastPps:0} multicast pps ({snap.BroadcastRatio:P0} broadcast)." +
                (hasTop ? $" Top source: {DeviceName(top!.Mac)}." : ""),
                hasTop ? top!.Mac : null, null, 0.6);
        }
        else if (_stormActive)
        {
            _stormPeakPps = Math.Max(_stormPeakPps, snap.BroadcastPps + snap.MulticastPps);
            if (!bStorm && !mStorm)
            {
                if (++_stormQuietSeconds >= StormEndQuietSeconds)
                {
                    _stormActive = false;
                    Signal("storm:end", snap.Time, TimeSpan.Zero, SignalKind.StormEnded,
                        $"Storm ended (peak {_stormPeakPps:0} broadcast+multicast pps).", null, null, 0.2);
                }
            }
            else _stormQuietSeconds = 0;
        }

        // learn the baseline only from calm seconds
        if (!bStorm && !mStorm)
        {
            const double alpha = 0.05;
            if (_baselineSamples == 0) { _bcastBaseline = snap.BroadcastPps; _mcastBaseline = snap.MulticastPps; }
            else
            {
                _bcastBaseline += alpha * (snap.BroadcastPps - _bcastBaseline);
                _mcastBaseline += alpha * (snap.MulticastPps - _mcastBaseline);
            }
            _baselineSamples++;
        }

        // ---- per-MAC storms and top talkers ----
        var local = LocalMac;
        var stormingNow = new HashSet<Mac>();
        foreach (var talker in snap.TopTalkers)
        {
            if (talker.Mac == local) continue;
            if (talker.BroadcastPps > _settings.StormPerMacPps || talker.MulticastPps > _settings.StormPerMacPps * 2)
            {
                stormingNow.Add(talker.Mac);
                _stormQuiet[talker.Mac] = 0;
                bool bcast = talker.BroadcastPps > _settings.StormPerMacPps;
                if (_devices.TryGet(talker.Mac, out var dev) && !dev.Has(DeviceFlags.StormSource))
                {
                    dev.SetFlag(DeviceFlags.StormSource);
                    _devices.NotifyChanged(dev, "storm");
                }
                RaiseStorm(Alert.Create(AlertSeverity.Warning, bcast ? AlertKind.BroadcastStorm : AlertKind.MulticastStorm,
                    $"{(bcast ? "Broadcast" : "Multicast")} storm source",
                    $"{DeviceName(talker.Mac)} sends {(bcast ? talker.BroadcastPps : talker.MulticastPps):0} {(bcast ? "broadcast" : "multicast")} pps.",
                    talker.Mac, bcast ? talker.BroadcastPps : talker.MulticastPps), TimeSpan.FromMinutes(2));
            }
            if (talker.Pps > _settings.TopTalkerPps)
            {
                Raise(Alert.Create(AlertSeverity.Info, AlertKind.TopTalker, "Top talker",
                    $"{DeviceName(talker.Mac)} sends {talker.Pps:0} pps ({talker.Bps * 8 / 1e6:0.0} Mbit/s).", talker.Mac, talker.Pps), TimeSpan.FromMinutes(10));
            }
        }
        // clear StormSource after 10 quiet seconds
        foreach (var mac in _stormQuiet.Keys.ToList())
        {
            if (stormingNow.Contains(mac)) continue;
            var quiet = _stormQuiet[mac] + 1;
            if (quiet >= 10)
            {
                _stormQuiet.Remove(mac);
                if (_devices.TryGet(mac, out var dev) && dev.Has(DeviceFlags.StormSource))
                {
                    dev.SetFlag(DeviceFlags.StormSource, false);
                    _devices.NotifyChanged(dev, "storm");
                }
            }
            else _stormQuiet[mac] = quiet;
        }

        // ---- slower checks every 10 s ----
        if (now - _lastPeriodic >= TimeSpan.FromSeconds(10))
        {
            _lastPeriodic = now;
            CheckStpRoots(DateTimeOffset.Now); // StpInfo.Seen is wall-clock time
            CheckQuerier(now);
        }
    }

    private void CheckStpRoots(DateTimeOffset now)
    {
        var roots = _network.StpBridges
            .Where(s => now - s.Seen < TimeSpan.FromMinutes(5) && !s.Protocol.Contains("PVST", StringComparison.OrdinalIgnoreCase))
            .GroupBy(s => s.RootBridgeId, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (roots.Count <= 1) return;
        Raise(Alert.Create(AlertSeverity.Warning, AlertKind.MultipleStpRoots, "Multiple STP root bridges",
            $"{roots.Count} different root bridges are advertised: {string.Join(", ", roots.Select(g => $"{g.Key} (via {string.Join("/", g.Select(x => DeviceName(x.SenderMac)))})"))}. " +
            "STP domains are split or a device is injecting BPDUs.", null, roots.Count), TimeSpan.FromMinutes(30));
    }

    private void CheckQuerier(DateTime now)
    {
        bool groups = _groupsSeen || _devices.All.Any(d => d.MulticastGroups.Length > 0);
        if (!groups || _monitorStart is not { } start || now - start < QuerierTimeout) return;
        if (_lastQuery is { } q && now - q < QuerierTimeout) return;
        Raise(Alert.Create(AlertSeverity.Warning, AlertKind.IgmpQuerierMissing, "No IGMP/MLD querier",
            $"Multicast group members exist but no IGMP/MLD query was seen for {QuerierTimeout.TotalMinutes:0} min" +
            (_querierMac is { } m ? $" (last querier {DeviceName(m)})" : "") +
            ". IGMP-snooping switches will eventually stop forwarding multicast (Sonos/AirPlay/IPTV drop-outs).", _querierMac), TimeSpan.FromMinutes(30));
    }

    // =========================================================================================================
    //  FDB-based MAC flapping
    // =========================================================================================================

    private void OnNetworkChanged(string what)
    {
        if (what != "fdb") return;
        try
        {
            List<DiagnosticSignal>? signals;
            lock (_sync)
            {
                try { CheckFdb(DateTimeOffset.Now); }
                finally { signals = TakeSignals(); }
            }
            Flush(signals);
        }
        catch (Exception ex) { _log.LogDebug(ex, "fdb flap check"); }
    }

    private void CheckFdb(DateTimeOffset now)
    {
        foreach (var e in _network.Fdb)
        {
            if (e.Mac.IsMulticast) continue;
            var key = (e.Switch, e.Mac);
            if (!_fdbHistory.TryGetValue(key, out var h))
            {
                _fdbHistory[key] = h = new FdbTrack(e.Port);
                h.Ports[e.Port] = now;
                continue;
            }
            if (string.Equals(h.Port, e.Port, StringComparison.OrdinalIgnoreCase)) { h.Ports[e.Port] = now; continue; }
            var moves = h.Moves;
            moves.Add(now);
            moves.RemoveAll(x => now - x > MacFlapWindow);
            h.Port = e.Port;
            h.Ports[e.Port] = now;
            foreach (var stale in h.Ports.Where(kv => now - kv.Value > MacFlapWindow).Select(kv => kv.Key).ToList()) h.Ports.Remove(stale);
            if (moves.Count >= 2) _flapping[key] = h;
            if (moves.Count >= _settings.MacFlapThreshold)
            {
                RaiseStorm(Alert.Create(AlertSeverity.Warning, AlertKind.MacFlapping, "MAC address flapping",
                    $"{DeviceName(e.Mac)} moved between ports of {DeviceName(e.Switch)} {moves.Count} times in {MacFlapWindow.TotalMinutes:0} min (now on {e.Port}). Loop or duplicate MAC likely.",
                    e.Mac, moves.Count), TimeSpan.FromMinutes(10));
                Signal($"flap:{e.Switch}:{e.Mac}", now, TimeSpan.FromMinutes(10), SignalKind.LoopSuspected,
                    $"{DeviceName(e.Mac)} flaps between ports {string.Join(", ", h.Ports.Keys)} of {DeviceName(e.Switch)} ({moves.Count} moves in {MacFlapWindow.TotalMinutes:0} min).",
                    e.Switch, e.Port, 0.6, [e.Mac]);
            }
        }
        foreach (var k in _flapping.Where(kv => kv.Value.Moves.Count(x => now - x <= MacFlapWindow) < 2).Select(kv => kv.Key).ToList()) _flapping.Remove(k);
        if (_fdbHistory.Count > 100_000) { _fdbHistory.Clear(); _flapping.Clear(); }
    }

    // =========================================================================================================
    //  Alert helpers
    // =========================================================================================================

    // =========================================================================================================
    //  State + diagnostic signals
    // =========================================================================================================

    /// <summary>Snapshot of detector state. Loop counts are relative to the latest captured frame's timestamp.</summary>
    public AnomalyState GetState()
    {
        lock (_sync)
        {
            var t = _lastFrameTime;
            int loops = _loopEvents.Count(x => t - x <= TimeSpan.FromSeconds(5));
            var flaps = _flapping.Select(kv => new MacFlapInfo(kv.Key.Sw, kv.Key.Mac, kv.Value.Ports.Keys.ToArray(), kv.Value.Moves.Count,
                kv.Value.Moves.Count > 0 ? kv.Value.Moves[^1] : DateTimeOffset.MinValue)).ToArray();
            return new AnomalyState(_bcastBaseline, _mcastBaseline, _baselineSamples >= 60,
                _bcastStormSeconds >= StormSustainSeconds, _mcastStormSeconds >= StormSustainSeconds, _stormActive,
                loops, _lastLoopSource, _lastLoopTime, _tcEvents.Count, _lastTcTime, flaps, SpanModeDetected, _lastForeignUnicastPps);
        }
    }

    /// <summary>Queues a signal (caller holds the lock); <paramref name="key"/> + <paramref name="cooldown"/> rate-limit repeats.</summary>
    private void Signal(string key, DateTimeOffset time, TimeSpan cooldown, SignalKind kind, string summary, Mac? device, string? port, double weight, IReadOnlyList<Mac>? affected = null)
    {
        if (cooldown > TimeSpan.Zero)
        {
            if (_lastSignal.TryGetValue(key, out var last) && time >= last && time - last < cooldown) return;
            _lastSignal[key] = time;
            if (_lastSignal.Count > 10_000) _lastSignal.Clear();
        }
        _pendingSignals.Add(DiagnosticSignal.Create(kind, SignalSource, summary, device, port, weight, affected));
    }

    private List<DiagnosticSignal>? TakeSignals()
    {
        if (_pendingSignals.Count == 0) return null;
        var list = _pendingSignals;
        _pendingSignals = new();
        return list;
    }

    private void Flush(List<DiagnosticSignal>? signals)
    {
        if (signals is null) return;
        foreach (var s in signals)
        {
            try { _bus.Publish(s); } catch (Exception ex) { _log.LogDebug(ex, "publish signal"); }
        }
    }

    private string DeviceName(Mac mac) => _devices.TryGet(mac, out var d) ? $"{d.DisplayName} [{mac}]" : mac.ToString();

    private bool Due(Alert alert, TimeSpan cooldown)
    {
        var key = (alert.Kind, alert.Source);
        if (_lastRaise.TryGetValue(key, out var last) && alert.Time - last < cooldown) return false;
        _lastRaise[key] = alert.Time;
        return true;
    }

    private void Raise(Alert alert, TimeSpan cooldown)
    {
        if (!Due(alert, cooldown)) return;
        _alerts.Raise(alert, cooldown);
    }

    /// <summary>Storm/loop alerts: Warning+ optionally trigger a pcapng dump of the recent capture (off the capture thread).</summary>
    private void RaiseStorm(Alert alert, TimeSpan cooldown)
    {
        if (!Due(alert, cooldown)) return;
        if (alert.Severity < AlertSeverity.Warning || !_settings.DumpPcapOnAlert)
        {
            _alerts.Raise(alert, cooldown);
            return;
        }
        _ = Task.Run(() =>
        {
            string? path = null;
            try { path = _source.DumpRecent(alert.Kind.ToString()); }
            catch (Exception ex) { _log.LogWarning(ex, "pcap dump for {Kind} failed", alert.Kind); }
            var a = path is null ? alert : alert with { Details = $"{alert.Details}\nCapture: {path}" };
            try { _alerts.Raise(a, cooldown); } catch (Exception ex) { _log.LogDebug(ex, "raise"); }
        });
    }
}
