using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Storm;

/// <summary>One source MAC's broadcast/multicast rate during the last tally window.</summary>
public sealed record TallySource(Mac Mac, double BroadcastPps, double MulticastPps, string DominantProtocol)
{
    public double Pps => BroadcastPps + MulticastPps;
}

/// <summary>Result of one tally window (normally one second).</summary>
public sealed record StormTally(double Seconds, long Frames, IReadOnlyList<TallySource> Sources, IReadOnlyDictionary<string, double> ProtocolPps, double UnknownUnicastPps)
{
    public static readonly StormTally Empty = new(1, 0, [], new Dictionary<string, double>(), 0);
}

/// <summary>
/// Cheap capture-thread tally for the Storm Center: per source MAC × protocol counts of broadcast/multicast frames,
/// broadcast+multicast pps per protocol, and unknown-unicast frames (destination is neither this host nor a known device).
/// <see cref="TakeSecond"/> returns the window and resets it; only the top <see cref="TopN"/> sources are kept.
/// </summary>
public sealed class StormFrameTally : IFrameHandler
{
    public const int TopN = 20;
    /// <summary>Distinct sources tracked per window; further new sources are only counted in the protocol totals.</summary>
    public const int MaxSources = 4096;

    private readonly IFrameSource _source;
    private readonly IDeviceStore _devices;
    private readonly object _sync = new();
    private Dictionary<Mac, SourceAcc> _bySource = new();
    private Dictionary<string, long> _byProto = new();
    private long _unknownUnicast, _frames;
    private DateTime _since = DateTime.UtcNow;

    private sealed class SourceAcc
    {
        public long Bcast, Mcast;
        public readonly Dictionary<string, long> Protocols = new();
    }

    public StormFrameTally(IFrameSource source, IDeviceStore devices)
    {
        _source = source;
        _devices = devices;
    }

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            var eth = frame.Eth;
            if (!eth.Valid || frame.IsOutbound) return;
            var dst = eth.Destination;
            if (dst.IsMulticast)
            {
                bool bcast = dst.IsBroadcast;
                string proto = TrafficCounter.ProtocolName(frame);
                lock (_sync)
                {
                    _frames++;
                    _byProto[proto] = _byProto.GetValueOrDefault(proto) + 1;
                    if (!_bySource.TryGetValue(eth.Source, out var acc))
                    {
                        if (_bySource.Count >= MaxSources) return;
                        _bySource[eth.Source] = acc = new SourceAcc();
                    }
                    if (bcast) acc.Bcast++; else acc.Mcast++;
                    acc.Protocols[proto] = acc.Protocols.GetValueOrDefault(proto) + 1;
                }
                return;
            }
            var local = _source.Adapter?.Mac ?? Mac.Zero;
            bool unknown = dst != local && !_devices.TryGet(dst, out _);
            lock (_sync)
            {
                _frames++;
                if (unknown) _unknownUnicast++;
            }
        }
        catch { /* never throw on the capture thread */ }
    }

    /// <summary>Closes the current window and returns its rates (top <see cref="TopN"/> sources by broadcast+multicast pps).</summary>
    public StormTally TakeSecond(DateTime? nowUtc = null)
    {
        lock (_sync)
        {
            var now = nowUtc ?? DateTime.UtcNow;
            double secs = Math.Max(0.001, (now - _since).TotalSeconds);
            var sources = _bySource
                .OrderByDescending(kv => kv.Value.Bcast + kv.Value.Mcast)
                .Take(TopN)
                .Select(kv => new TallySource(kv.Key, kv.Value.Bcast / secs, kv.Value.Mcast / secs,
                    kv.Value.Protocols.OrderByDescending(p => p.Value).Select(p => p.Key).FirstOrDefault() ?? "?"))
                .ToList();
            var tally = new StormTally(secs, _frames, sources, _byProto.ToDictionary(kv => kv.Key, kv => kv.Value / secs), _unknownUnicast / secs);
            _bySource = new();
            _byProto = new();
            _unknownUnicast = 0;
            _frames = 0;
            _since = now;
            return tally;
        }
    }
}
