using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Anomaly;

namespace NetSpider.Diagnostics.Storm;

/// <summary>
/// Dedicated broadcast-storm tool. Every second (on the <see cref="TrafficSnapshot"/>) it classifies the storm level against
/// an EWMA baseline, lists broadcast/multicast sources with their dominant protocol and FDB location (switch + edge port +
/// what sits behind it), the switch ports where broadcast enters (SNMP per-port counters), loop suspects, and keeps a
/// history of storm events with an automatic pcapng dump at storm start. Also hosts the opt-in storm-control check.
/// </summary>
public sealed class StormCenter : IStormCenter, IStartable, IDisposable
{
    public const int MaxHistory = 200;
    public const int MaxSources = 20;
    public const int MaxIngress = 10;
    public const int StormStartSeconds = 2;
    public const int StormEndSeconds = 5;
    public const double MinIngressBroadcastPps = 20;
    public const double MinIngressMulticastPps = 50;
    /// <summary>A port with this many learned MACs is treated as an uplink/trunk in the ingress notes.</summary>
    public const int UplinkMacCount = 10;
    private const string SignalSource = "storm-center";

    /// <summary>Shown with every storm-control check result; mirrors the limits enforced in <see cref="BroadcastBurst"/>.</summary>
    public const string SafetyText =
        "Safety limits: the burst is hard-capped at 5000 pps and 5 s (at most 25,000 frames) whatever the options say. It consists of " +
        "harmless ARP who-has requests for an unused address in this host's own subnet, sent from this host's real MAC, so no device " +
        "changes state. The check runs only when enabled in Settings, only while capture is running, and never automatically. A switch " +
        "whose storm-control action is 'shutdown' may err-disable this host's port, which then needs an admin (or errdisable recovery) to come back.";

    private readonly ILogger<StormCenter> _log;
    private readonly IEventBus _bus;
    private readonly IDeviceStore _devices;
    private readonly INetworkState _network;
    private readonly ITopologyStore _topology;
    private readonly IFrameSource _source;
    private readonly AppSettings _settings;
    private readonly StormFrameTally _tally;
    private readonly IServiceProvider _services;
    private readonly LoopFinder _loops = new();
    private readonly EwmaBaseline _bcastBaseline = new(), _mcastBaseline = new();
    private readonly object _sync = new();
    private readonly List<EventAcc> _history = new(); // newest first
    private readonly Dictionary<string, DateTimeOffset> _loopSignals = new();
    private IDisposable? _busSub;
    private bool _started;
    private volatile bool _locatorDirty = true;
    private StormLocator _locator = StormLocator.Empty;
    private StormStatus _status = StormStatus.Empty;
    private EventAcc? _current;
    private int _stormSeconds, _calmSeconds;
    private int _checkRunning;

    private sealed class EventAcc
    {
        public DateTimeOffset Start;
        public DateTimeOffset? End;
        public StormLevel PeakLevel = StormLevel.Storm;
        public double PeakPps;
        public string Dominant = "?";
        public string Summary = "";
        public string? PcapPath;
        public StormEvent ToRecord() => new(Start, End, PeakLevel, PeakPps, Dominant, Summary, PcapPath);
    }

    public StormCenter(ILogger<StormCenter> log, IEventBus bus, IDeviceStore devices, INetworkState network, ITopologyStore topology,
        IFrameSource source, AppSettings settings, StormFrameTally tally, IServiceProvider services)
    {
        _log = log;
        _bus = bus;
        _devices = devices;
        _network = network;
        _topology = topology;
        _source = source;
        _settings = settings;
        _tally = tally;
        _services = services;
    }

    public StormStatus Status { get { lock (_sync) return _status; } }
    public IReadOnlyList<StormEvent> History { get { lock (_sync) return _history.Select(e => e.ToRecord()).ToArray(); } }
    public event Action<StormStatus>? Updated;

    /// <summary>Wait after the burst before reading the switch counters again (agents update counters with some lag).</summary>
    public TimeSpan CounterSettleDelay { get; set; } = TimeSpan.FromSeconds(2);
    /// <summary>Extra wait before a second read when the first one looks low (slow counter refresh on cheap switches).</summary>
    public TimeSpan CounterRecheckDelay { get; set; } = TimeSpan.FromSeconds(4);

    private AnomalyEngine? Anomaly => _services.GetService(typeof(AnomalyEngine)) as AnomalyEngine;
    private IPortHealthMonitor? PortHealth => _services.GetService(typeof(IPortHealthMonitor)) as IPortHealthMonitor;
    private Func<Mac, string, CancellationToken, Task<PortCounterSample?>>? PortReader =>
        _services.GetService(typeof(Func<Mac, string, CancellationToken, Task<PortCounterSample?>>)) as Func<Mac, string, CancellationToken, Task<PortCounterSample?>>;

    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
        }
        _busSub = _bus.Subscribe<TrafficSnapshot>(OnTraffic);
        _network.Changed += OnNetworkChanged;
        _topology.Changed += OnTopologyChanged;
    }

    public void Dispose()
    {
        _busSub?.Dispose();
        _network.Changed -= OnNetworkChanged;
        _topology.Changed -= OnTopologyChanged;
    }

    private void OnNetworkChanged(string what)
    {
        if (what is "fdb" or "switchports") _locatorDirty = true;
    }

    private void OnTopologyChanged() => _locatorDirty = true;

    private string? Name(Mac mac) => _devices.TryGet(mac, out var d) ? d.DisplayName : null;

    /// <summary>Current FDB locator (rebuilt after FDB/port/topology changes; also feeds the loop finder's FDB history).</summary>
    public StormLocator Locator()
    {
        if (!_locatorDirty) return _locator;
        _locatorDirty = false;
        try
        {
            var fdb = _network.Fdb;
            var loc = new StormLocator(fdb, _network.SwitchPorts, _topology.Links, Name);
            _loops.ObserveFdb(fdb, DateTimeOffset.Now, loc.PortName);
            _locator = loc;
        }
        catch (Exception ex) { _log.LogDebug(ex, "storm locator rebuild"); _locatorDirty = true; }
        return _locator;
    }

    // =========================================================================================================
    //  Per-second status
    // =========================================================================================================

    public void OnTraffic(TrafficSnapshot snap)
    {
        if (_network.IsDemo) return; // synthetic demo traffic must not enter the real storm history/baselines (the demo has its own storm center)
        StormStatus status;
        List<DiagnosticSignal>? signals = null;
        bool dump = false;
        EventAcc? started = null;
        try
        {
            var tally = _tally.TakeSecond();
            var anomaly = Anomaly?.GetState() ?? AnomalyState.Empty;
            var ports = PortHealth?.Ports ?? [];
            var locator = Locator();
            var local = _source.Adapter?.Mac ?? Mac.Zero;

            lock (_sync)
            {
                // ---- level ----
                var level = StormClassifier.Classify(snap.BroadcastPps, snap.MulticastPps, snap.TotalPps,
                    _bcastBaseline.Value, _mcastBaseline.Value, _bcastBaseline.Warmed, _settings);
                if (anomaly.StormActive && (anomaly.BroadcastStorm || anomaly.MulticastStorm)) level = StormLevel.Storm;
                if (level == StormLevel.Normal)
                {
                    _bcastBaseline.Add(snap.BroadcastPps);
                    _mcastBaseline.Add(snap.MulticastPps);
                }

                // ---- protocols + unknown unicast ----
                IReadOnlyDictionary<string, double> byProto = tally.Frames > 0 || snap.BroadcastPps + snap.MulticastPps <= 0
                    ? tally.ProtocolPps
                    : snap.PpsByProtocol;
                double unknownUnicast = tally.Frames > 0 ? tally.UnknownUnicastPps : anomaly.UnknownUnicastPps;

                // ---- sources ----
                var raw = tally.Sources.Count > 0
                    ? tally.Sources
                    : snap.TopTalkers.Where(t => t.BroadcastPps + t.MulticastPps > 0)
                        .Select(t => new TallySource(t.Mac, t.BroadcastPps, t.MulticastPps, "?")).ToList();
                var sources = raw.Where(s => s.Mac != local)
                    .OrderByDescending(s => s.Pps)
                    .Take(MaxSources)
                    .Select(s => ToSource(s, locator))
                    .ToList();

                // ---- ingress ports + loops ----
                var ingress = Ingress(ports, locator);
                double minLoopIngress = Math.Max(LoopFinder.MinIngressPps, _settings.StormBroadcastPps / 2);
                var loops = _loops.Evaluate(anomaly, ports, sw => locator.SwitchName(sw), snap.Time, minLoopIngress);
                foreach (var l in loops.Where(l => l.Switch is not null && l.Confidence >= 0.6))
                {
                    var key = $"{l.Switch}:{string.Join(",", l.Ports)}";
                    if (_loopSignals.TryGetValue(key, out var last) && snap.Time - last < TimeSpan.FromMinutes(5) && snap.Time >= last) continue;
                    _loopSignals[key] = snap.Time;
                    (signals ??= new()).Add(DiagnosticSignal.Create(SignalKind.LoopSuspected, SignalSource, l.Description, l.Switch,
                        l.Ports.Count > 0 ? l.Ports[0] : null, l.Confidence, l.FlappingMacs));
                }

                status = new StormStatus(snap.Time, level, snap.BroadcastPps, snap.MulticastPps, unknownUnicast, snap.TotalPps,
                    _bcastBaseline.Value, _mcastBaseline.Value, byProto, sources, ingress, loops);

                // ---- storm events ----
                (dump, started) = TrackEvent(status);
                _status = status;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "storm center tick");
            return;
        }

        if (signals is not null)
            foreach (var s in signals)
                try { _bus.Publish(s); } catch (Exception ex) { _log.LogDebug(ex, "publish loop signal"); }

        if (dump && started is not null) _ = Task.Run(() => DumpForEvent(started, "storm"));

        try { Updated?.Invoke(status); } catch (Exception ex) { _log.LogDebug(ex, "storm Updated handler"); }
    }

    private StormSource ToSource(TallySource s, StormLocator locator)
    {
        var loc = locator.Locate(s.Mac);
        return new StormSource(s.Mac, Name(s.Mac), s.Pps, s.BroadcastPps, s.MulticastPps, s.DominantProtocol,
            loc?.Switch, loc?.SwitchName, loc?.Port, loc?.Location);
    }

    private List<StormIngress> Ingress(IReadOnlyList<PortHealth> ports, StormLocator locator)
    {
        var list = new List<StormIngress>();
        foreach (var p in ports.Where(p => p.OperUp && (p.BroadcastPps >= MinIngressBroadcastPps || p.MulticastPps >= MinIngressMulticastPps))
                     .OrderByDescending(p => p.BroadcastPps).ThenByDescending(p => p.MulticastPps).Take(MaxIngress))
        {
            int macs = locator.MacsOnPort(p.Switch, p.Name);
            string? note;
            if (macs >= UplinkMacCount) note = $"uplink/trunk ({macs} MACs): the flood arrives from the neighbouring switch";
            else if (macs > 0)
            {
                var names = locator.MacsOn(p.Switch, p.Name).Take(3).Select(m => Name(m) ?? m.ToString());
                note = $"edge port: {string.Join(", ", names)}{(macs > 3 ? $" +{macs - 3}" : "")}";
            }
            else note = null;
            list.Add(new StormIngress(p.Switch, locator.SwitchName(p.Switch), p.Name, p.BroadcastPps, p.MulticastPps, note));
        }
        return list;
    }

    /// <summary>Starts an event after <see cref="StormStartSeconds"/> storm seconds, ends it after <see cref="StormEndSeconds"/> calm ones.</summary>
    private (bool Dump, EventAcc? Started) TrackEvent(StormStatus s)
    {
        bool dump = false;
        EventAcc? started = null;
        double pps = s.BroadcastPps + s.MulticastPps;
        if (s.Level == StormLevel.Storm)
        {
            _stormSeconds++;
            _calmSeconds = 0;
            if (_current is null && _stormSeconds >= StormStartSeconds)
            {
                _current = started = new EventAcc { Start = s.Time - TimeSpan.FromSeconds(StormStartSeconds - 1) };
                _history.Insert(0, _current);
                if (_history.Count > MaxHistory) _history.RemoveRange(MaxHistory, _history.Count - MaxHistory);
                dump = _settings.DumpPcapOnAlert && _source.IsRunning;
            }
        }
        else
        {
            _stormSeconds = 0;
            if (_current is not null && ++_calmSeconds >= StormEndSeconds)
            {
                _current.End = s.Time;
                _current = null;
            }
        }
        if (_current is not null && s.Level == StormLevel.Storm && pps >= _current.PeakPps)
        {
            _current.PeakPps = pps;
            _current.Dominant = s.PpsByProtocol.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() ?? "?";
            _current.Summary = Summarize(s);
        }
        return (dump, started);
    }

    /// <summary>Why it is a storm: rates, ratio, dominant protocol and top source with its location.</summary>
    public static string Summarize(StormStatus s)
    {
        double ratio = s.TotalPps > 0 ? s.BroadcastPps / s.TotalPps : 0;
        bool bcast = s.BroadcastPps >= s.MulticastPps;
        var dominant = s.PpsByProtocol.OrderByDescending(kv => kv.Value).FirstOrDefault();
        var sb = new StringBuilder();
        sb.Append(bcast ? "Broadcast storm: " : "Multicast storm: ");
        sb.Append($"{s.BroadcastPps:0} broadcast pps ({ratio:P0} of traffic, baseline {s.BaselineBroadcastPps:0}), {s.MulticastPps:0} multicast pps");
        if (dominant.Key is not null) sb.Append($"; dominant protocol {dominant.Key} ({dominant.Value:0} pps)");
        if (s.Sources.FirstOrDefault() is { } top)
        {
            sb.Append($"; top source {top.Name ?? top.Mac.ToString()} [{top.Mac}] {top.Pps:0} pps {top.DominantProtocol}");
            if (top.Location is not null) sb.Append($" on {top.Location}");
        }
        if (s.Ingress.FirstOrDefault() is { } ing) sb.Append($"; enters at {ing.SwitchName} port {ing.Port} ({ing.BroadcastPps:0} bcast pps)");
        if (s.Loops.FirstOrDefault() is { } loop) sb.Append($"; {loop.Description}");
        sb.Append('.');
        return sb.ToString();
    }

    private void DumpForEvent(EventAcc ev, string reason)
    {
        string? path = null;
        try { path = _source.DumpRecent(reason); }
        catch (Exception ex) { _log.LogWarning(ex, "storm pcap dump failed"); }
        if (path is null) return;
        lock (_sync) ev.PcapPath ??= path;
    }

    public string? RecordNow()
    {
        if (!_source.IsRunning) return null;
        string? path;
        try { path = _source.DumpRecent("storm-manual"); }
        catch (Exception ex) { _log.LogWarning(ex, "storm recording failed"); return null; }
        if (path is null) return null;
        StormStatus status;
        lock (_sync)
        {
            if (_current is not null) _current.PcapPath ??= path;
            status = _status;
        }
        try
        {
            var summary = new StringBuilder();
            summary.AppendLine($"NetSpider storm recording {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
            summary.AppendLine($"Level: {status.Level}");
            summary.AppendLine(Summarize(status));
            foreach (var src in status.Sources.Take(10))
                summary.AppendLine($"  source {src.Name ?? "?"} [{src.Mac}] bcast {src.BroadcastPps:0} pps, mcast {src.MulticastPps:0} pps, {src.DominantProtocol}{(src.Location is null ? "" : " @ " + src.Location)}");
            foreach (var i in status.Ingress) summary.AppendLine($"  ingress {i.SwitchName} port {i.Port}: {i.BroadcastPps:0} bcast pps {i.Note}");
            foreach (var l in status.Loops) summary.AppendLine($"  loop ({l.Confidence:P0}): {l.Description}");
            File.WriteAllText(Path.ChangeExtension(path, ".summary.txt"), summary.ToString());
        }
        catch (Exception ex) { _log.LogDebug(ex, "storm summary write"); }
        return path;
    }

    // =========================================================================================================
    //  Opt-in storm-control check
    // =========================================================================================================

    public async Task<StormControlResult> RunStormControlCheckAsync(StormControlOptions options, CancellationToken ct)
    {
        // Gating: explicit opt-in in Settings + running capture. Never invoked automatically.
        if (!_settings.StormControlCheckEnabled)
            return NotRun("Storm-control check is disabled. Enable it in Settings to allow this active test (it sends a short broadcast burst).");
        if (!_source.IsRunning || _source.Adapter is not { } adapter)
            return NotRun("Capture is not running: start monitoring on an adapter first.");
        if (Interlocked.Exchange(ref _checkRunning, 1) == 1)
            return NotRun("A storm-control check is already running.");
        try
        {
            var details = new List<string>();
            var (pps, durationMs, vlan) = BroadcastBurst.Clamp(options);
            if (pps != options.Pps || durationMs != options.DurationMs)
                details.Add($"Requested {options.Pps} pps for {options.DurationMs} ms; capped to {pps} pps for {durationMs} ms.");
            if (adapter.PrimaryV4 is not { } v4) return NotRun("The capture adapter has no IPv4 address to build the ARP probe.");
            var target = PickUnusedAddress(v4, adapter.GatewayV4);
            if (target is null) return NotRun("No unused address found in this host's subnet for the ARP probe.");
            var frame = FrameBuilder.ArpRequest(adapter.Mac, v4.Address, target, vlan);

            // where are we plugged in?
            var loc = Locator().Locate(adapter.Mac);
            var reader = PortReader;
            var health = PortHealth;
            PortCounterSample? before = null;
            if (loc is null) details.Add("This host's switch port is unknown (no SNMP FDB entry for our MAC), so switch counters cannot be checked.");
            else
            {
                details.Add($"This host is connected to {loc.Location}." + (loc.MacsOnPort > 1 ? " Other MACs share that port, so an unmanaged switch may sit in between and absorb or forward the burst." : ""));
                if (reader is not null) before = await SafeRead(reader, loc, ct).ConfigureAwait(false);
                if (before is null) details.Add(reader is null ? "No on-demand SNMP counter reader is registered." : "The switch did not answer the SNMP counter read before the burst.");
            }
            var healthBefore = loc is not null ? health?.Get(loc.Switch, loc.Port) : null;

            var sw = Stopwatch.StartNew();
            int sent = await Task.Factory.StartNew(() => BroadcastBurst.Run(_source, frame, pps, durationMs, ct), ct,
                TaskCreationOptions.LongRunning, TaskScheduler.Default).ConfigureAwait(false);
            var elapsed = sw.Elapsed;
            details.Add($"Sent {sent} ARP broadcast frames (who-has {target}, an unused address) from {adapter.Mac} in {elapsed.TotalMilliseconds:0} ms" +
                        $" (~{sent / Math.Max(0.001, elapsed.TotalSeconds):0} pps){(vlan is { } v ? $", VLAN {v}" : "")}.");

            PortCounterSample? after = null;
            bool readAfter = false;
            if (loc is not null && reader is not null && before is not null)
            {
                await Task.Delay(CounterSettleDelay, ct).ConfigureAwait(false);
                after = await SafeRead(reader, loc, ct).ConfigureAwait(false);
                readAfter = true;
                if (after is not null && after.OperUp && after.InBroadcast >= before.InBroadcast && after.InBroadcast - before.InBroadcast < (ulong)(sent * 0.8))
                {
                    await Task.Delay(CounterRecheckDelay, ct).ConfigureAwait(false);
                    if (await SafeRead(reader, loc, ct).ConfigureAwait(false) is { } again) after = again;
                }
            }
            var healthAfter = loc is not null ? health?.Get(loc.Switch, loc.Port) : null;

            var (triggered, verdict) = EvaluateStormControl(sent, pps, before, after, readAfter, healthBefore, healthAfter, details);
            details.Add(SafetyText);
            return new StormControlResult(true, sent, elapsed, triggered, verdict, details);
        }
        catch (OperationCanceledException)
        {
            return new StormControlResult(false, 0, TimeSpan.Zero, null, "Storm-control check cancelled.", [SafetyText]);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "storm-control check failed");
            return new StormControlResult(false, 0, TimeSpan.Zero, null, $"Storm-control check failed: {ex.Message}", [SafetyText]);
        }
        finally { Interlocked.Exchange(ref _checkRunning, 0); }

        static StormControlResult NotRun(string verdict) => new(false, 0, TimeSpan.Zero, null, verdict, [SafetyText]);
    }

    private async Task<PortCounterSample?> SafeRead(Func<Mac, string, CancellationToken, Task<PortCounterSample?>> reader, SourceLocation loc, CancellationToken ct)
    {
        try { return await reader(loc.Switch, loc.Port, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "storm-control counter read"); return null; }
    }

    /// <summary>
    /// Verdict from the switch-port counters around the burst. Triggered when the port shut, inbound discards jumped by
    /// ≥ 20 % of the burst, or the switch counted far fewer broadcasts (&lt; 50 %) than were sent. Unknown without SNMP data.
    /// </summary>
    public static (bool? Triggered, string Verdict) EvaluateStormControl(int sent, int pps, PortCounterSample? before, PortCounterSample? after,
        bool readAfter, PortHealth? healthBefore, PortHealth? healthAfter, List<string> details)
    {
        if (sent <= 0) return (null, "Unknown: no frames could be sent.");
        if (before is null)
        {
            if (healthBefore is { OperUp: true } && healthAfter is { OperUp: false })
                return (true, "Storm-control likely triggered: the switch port went down after the burst (err-disable/shutdown action).");
            return (null, "Unknown: no SNMP counters are available for this host's switch port, so the switch's reaction cannot be measured.");
        }
        if (after is null)
        {
            details.Add("The switch did not answer after the burst. If storm-control shut this host's port (err-disable), management traffic is cut too.");
            return (null, readAfter
                ? "Unknown: the switch stopped answering SNMP after the burst; check whether this host's port was err-disabled."
                : "Unknown: switch counters could not be read after the burst.");
        }
        if (before.OperUp && !after.OperUp)
            return (true, $"Storm-control triggered: the switch shut port {after.Name} (err-disable/shutdown action) during the burst.");
        if (after.InBroadcast < before.InBroadcast || after.InDiscards < before.InDiscards)
            return (null, "Unknown: the port counters were reset during the test.");

        ulong inDelta = after.InBroadcast - before.InBroadcast;
        ulong discDelta = after.InDiscards - before.InDiscards;
        double share = (double)inDelta / sent;
        details.Add($"Switch port {after.Name}: +{inDelta} inbound broadcasts ({share:P0} of the {sent} sent) and +{discDelta} inbound discards.");
        details.Add("Note: some switches count broadcasts before the storm-control filter and some after; discards and port state are the stronger evidence.");

        if (discDelta >= sent * 0.2)
            return (true, $"Storm-control triggered: the switch discarded {discDelta} of {sent} burst frames at {pps} pps.");
        if (share < 0.5)
            return (true, $"Storm-control likely triggered: the switch counted only {share:P0} of the burst at {pps} pps.");
        if (share >= 0.8)
            return (false, $"No storm-control reaction at {pps} pps: the switch accepted the burst ({inDelta} broadcasts counted, {discDelta} discards). " +
                           "Consider enabling broadcast storm-control below this rate.");
        return (null, $"Inconclusive: the switch counted {share:P0} of the burst without discards; repeat with a higher rate or longer duration.");
    }

    /// <summary>An address in our subnet that no known device uses (searching down from the top of the range).</summary>
    public IPAddress? PickUnusedAddress(IpWithPrefix v4, IPAddress? gateway)
    {
        if (v4.PrefixLength is < 8 or > 30) return null;
        var bytes = v4.Address.GetAddressBytes();
        uint ip = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        uint mask = v4.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - v4.PrefixLength);
        uint net = ip & mask, bcast = net | ~mask;
        for (uint c = bcast - 1, tries = 0; c > net && tries < 256; c--, tries++)
        {
            var addr = new IPAddress(new[] { (byte)(c >> 24), (byte)(c >> 16), (byte)(c >> 8), (byte)c });
            if (c == ip || addr.Equals(gateway) || _devices.FindByIp(addr) is not null) continue;
            return addr;
        }
        return null;
    }
}
