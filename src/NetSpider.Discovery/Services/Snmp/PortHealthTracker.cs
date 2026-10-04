using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>A health transition on one port that should become a <see cref="DiagnosticSignal"/> (and usually an alert).</summary>
public sealed record PortEvent(SignalKind Kind, string Summary, double Weight, AlertSeverity Severity);

/// <summary>Result of feeding one counter sample to a <see cref="PortHealthTracker"/>.</summary>
public sealed record PortUpdate(PortHealth Health, IReadOnlyList<PortEvent> Events);

/// <summary>
/// Per-port state machine: turns consecutive <see cref="PortCounterSample"/>s into rates and a <see cref="PortHealth"/>,
/// handling 32-bit counter wrap, counter clears and agent reboots (sysUpTime going backwards resets the baseline).
/// Emits <see cref="PortEvent"/>s on rising edges only (down/up, flapping, errors, duplex, speed downgrade).
/// Not thread-safe; the monitor serializes updates per port.
/// </summary>
public sealed class PortHealthTracker
{
    public const int HistorySize = 60;
    public const int FlapThreshold = 3;
    public static readonly TimeSpan FlapWindow = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan FlapHistory = TimeSpan.FromHours(1);
    /// <summary>A late collision keeps the duplex-suspect flag set for this long.</summary>
    public static readonly TimeSpan LateCollisionMemory = TimeSpan.FromHours(1);
    /// <summary>Consecutive "up" polls after which a port counts as established even without traffic.</summary>
    public const int EstablishedPolls = 2;

    private PortCounterSample? _prev;
    private TimeSpan? _prevUpTime;
    private readonly List<DateTimeOffset> _changes = new();
    private readonly Queue<PortHealth> _history = new();
    private long? _maxSpeed;
    private bool _downgradedWhileUp;
    private DateTimeOffset? _lastLateCollision;
    private ulong _lastLateDelta;
    private int _upPolls;
    private bool _established, _signaledDown;
    private bool _flapping, _errors, _duplex, _downgraded;

    public PortHealthTracker(Mac switchMac, int ifIndex)
    {
        Switch = switchMac;
        IfIndex = ifIndex;
    }

    public Mac Switch { get; }
    public int IfIndex { get; }
    public string? Name => Latest?.Name ?? _prev?.Name;
    public PortHealth? Latest { get; private set; }
    public PortCounterSample? LastSample => _prev;
    public IReadOnlyList<PortHealth> History => _history.ToArray();

    /// <summary>
    /// Counter delta with 32-bit wrap handling. A decrease is treated as a wrap only when the previous value fits in 32 bits
    /// and the wrapped delta is plausible (≤ <paramref name="maxPlausible"/>); otherwise the counter was cleared or the agent
    /// restarted, and the delta is 0 (new baseline).
    /// </summary>
    public static ulong Delta(ulong prev, ulong cur, double maxPlausible)
    {
        if (cur >= prev) return cur - prev;
        if (prev <= uint.MaxValue)
        {
            ulong wrapped = (1UL << 32) - prev + cur;
            if (wrapped <= maxPlausible) return wrapped;
        }
        return 0;
    }

    public PortUpdate Update(PortCounterSample s, TimeSpan? sysUpTime, double errorsPerMinWarn)
    {
        var events = new List<PortEvent>();
        var prev = _prev;
        bool reboot = prev is null || (sysUpTime is { } up && _prevUpTime is { } pu && up < pu);

        double seconds = 0;
        if (!reboot && prev is not null)
        {
            seconds = sysUpTime is { } u && _prevUpTime is { } p && u > p ? (u - p).TotalSeconds : (s.Time - prev.Time).TotalSeconds;
        }
        bool rates = !reboot && prev is not null && seconds >= 0.5;

        double inBps = 0, outBps = 0, errPs = 0, discPs = 0, fcsPs = 0, bcastPps = 0, mcastPps = 0;
        ulong lateDelta = 0;
        if (rates)
        {
            // plausibility limit for wrap detection: line rate x1.5 (or half the 32-bit range when the speed is unknown)
            double octMax = s.SpeedMbps is > 0 ? s.SpeedMbps.Value * 1e6 / 8 * seconds * 1.5 : uint.MaxValue / 2.0;
            double pktMax = s.SpeedMbps is > 0 ? octMax / 64 : uint.MaxValue / 2.0;
            ulong inOct = Delta(prev!.InOctets, s.InOctets, octMax), outOct = Delta(prev.OutOctets, s.OutOctets, octMax);
            ulong errs = Delta(prev.InErrors, s.InErrors, pktMax) + Delta(prev.OutErrors, s.OutErrors, pktMax);
            ulong disc = Delta(prev.InDiscards, s.InDiscards, pktMax) + Delta(prev.OutDiscards, s.OutDiscards, pktMax);
            ulong fcs = Delta(prev.FcsErrors, s.FcsErrors, pktMax) + Delta(prev.AlignmentErrors, s.AlignmentErrors, pktMax);
            ulong bc = Delta(prev.InBroadcast, s.InBroadcast, pktMax), mc = Delta(prev.InMulticast, s.InMulticast, pktMax);
            lateDelta = Delta(prev.LateCollisions, s.LateCollisions, pktMax);
            inBps = inOct * 8 / seconds; outBps = outOct * 8 / seconds;
            errPs = errs / seconds; discPs = disc / seconds; fcsPs = fcs / seconds;
            bcastPps = bc / seconds; mcastPps = mc / seconds;
            if (s.OperUp && inOct + outOct > 0) _established = true;
        }
        _lastLateDelta = lateDelta;
        if (lateDelta > 0) _lastLateCollision = s.Time;

        // ---- link state changes / flaps (not across a reboot: every port "changed" then) ----
        if (!reboot && prev is not null)
        {
            bool operChanged = prev.OperUp != s.OperUp;
            bool lcChanged = prev.LastChange is { } a && s.LastChange is { } b && a != b;
            int changes = operChanged ? 1 : lcChanged ? 2 : 0; // a moved ifLastChange with the same state = down+up
            for (int i = 0; i < changes; i++) _changes.Add(s.Time);

            if (prev.OperUp && !s.OperUp && _established)
            {
                _signaledDown = true;
                events.Add(new PortEvent(SignalKind.PortDown, "link went down", 0.7, AlertSeverity.Warning));
            }
            else if (!prev.OperUp && s.OperUp && _signaledDown)
            {
                _signaledDown = false;
                events.Add(new PortEvent(SignalKind.PortUp, $"link is up again{(s.SpeedMbps is > 0 ? $" at {SpeedText(s.SpeedMbps.Value)}" : "")}", 0.3, AlertSeverity.Info));
            }
        }
        _changes.RemoveAll(x => s.Time - x > FlapHistory);
        int flapsHour = _changes.Count;
        int flapsWindow = _changes.Count(x => s.Time - x <= FlapWindow);

        _upPolls = s.OperUp ? _upPolls + 1 : 0;
        if (_upPolls >= EstablishedPolls) _established = true;

        // ---- speed ----
        bool downgraded = false;
        if (s.OperUp && s.SpeedMbps is { } sp && sp > 0)
        {
            if (prev is { OperUp: true, SpeedMbps: > 0 } && prev.SpeedMbps > sp) _downgradedWhileUp = true;
            _maxSpeed = Math.Max(_maxSpeed ?? 0, sp);
            if (sp >= _maxSpeed) _downgradedWhileUp = false;
            downgraded = sp < _maxSpeed && (sp <= 100 || _downgradedWhileUp);
        }
        else if (!s.OperUp) downgraded = false;

        // ---- duplex ----
        bool late = _lastLateCollision is { } lc && s.Time - lc <= LateCollisionMemory;
        bool half = s.OperUp && string.Equals(s.Duplex, "half", StringComparison.OrdinalIgnoreCase) && s.SpeedMbps is >= 100;
        bool duplex = late || half;

        double errPerMin = Math.Max(errPs, fcsPs) * 60;
        bool errors = rates && errorsPerMinWarn > 0 && errPerMin >= errorsPerMinWarn;
        bool flapping = flapsWindow >= FlapThreshold;

        // ---- rising-edge events ----
        if (flapping && !_flapping)
            events.Add(new PortEvent(SignalKind.PortFlapping, $"link flapped {flapsWindow} times in {FlapWindow.TotalMinutes:0} min", 0.8, AlertSeverity.Warning));
        if (errors && !_errors)
            events.Add(new PortEvent(SignalKind.PortErrors, ErrorText(errPs, fcsPs), 0.7, AlertSeverity.Warning));
        if (duplex && !_duplex)
            events.Add(new PortEvent(SignalKind.PortDuplexMismatch, DuplexText(late, half, s), 0.7, AlertSeverity.Warning));
        if (downgraded && !_downgraded)
            events.Add(new PortEvent(SignalKind.PortSpeedDowngrade, $"linked at {SpeedText(s.SpeedMbps!.Value)}, earlier {SpeedText(_maxSpeed!.Value)} (bad cable/pair or wrong negotiation)", 0.6, AlertSeverity.Warning));
        _flapping = flapping;
        // hysteresis for errors so a rate hovering at the threshold does not re-alert every poll
        _errors = errors || (_errors && rates && errPerMin >= errorsPerMinWarn / 2);
        _duplex = duplex;
        _downgraded = downgraded;

        // ---- health + problem sentence ----
        var problems = new List<string>();
        HopHealth health;
        if (!s.OperUp)
        {
            health = _established || _signaledDown ? HopHealth.Down : HopHealth.Unknown;
            if (health == HopHealth.Down) problems.Add("link down (was up)");
            if (flapping) problems.Add($"flapped {flapsHour} times in the last hour");
        }
        else
        {
            if (errors) problems.Add(ErrorText(errPs, fcsPs));
            if (flapping) problems.Add($"flapped {flapsHour} times in the last hour");
            if (duplex) problems.Add(DuplexText(late, half, s));
            if (downgraded) problems.Add($"running at {SpeedText(s.SpeedMbps!.Value)}, earlier {SpeedText(_maxSpeed!.Value)}");
            health = problems.Count > 0 ? HopHealth.Degraded : HopHealth.Up;
        }
        string? problem = problems.Count == 0 ? null : Capitalize(string.Join("; ", problems)) + ".";

        var h = new PortHealth(s.Switch, s.IfIndex, s.Name, s.OperUp, s.SpeedMbps, s.Duplex,
            inBps, outBps, errPs, discPs, fcsPs, bcastPps, mcastPps, flapsHour, duplex, downgraded, problem, health, s.Time);

        _prev = s;
        _prevUpTime = sysUpTime;
        Latest = h;
        _history.Enqueue(h);
        while (_history.Count > HistorySize) _history.Dequeue();
        return new PortUpdate(h, events);
    }

    private static string ErrorText(double errPs, double fcsPs) =>
        fcsPs > 0 && fcsPs >= errPs * 0.5
            ? $"{fcsPs * 60:0} CRC/FCS errors/min (bad cable, connector or optic)"
            : $"{errPs * 60:0} interface errors/min";

    private string DuplexText(bool late, bool half, PortCounterSample s) =>
        late ? $"late collisions{(_lastLateDelta > 0 ? $" (+{_lastLateDelta})" : "")}: duplex mismatch likely"
             : half ? $"half duplex at {SpeedText(s.SpeedMbps ?? 0)}: autonegotiation failure / duplex mismatch likely" : "duplex suspect";

    public static string SpeedText(long mbps) => mbps >= 1000 && mbps % 1000 == 0 ? $"{mbps / 1000} Gbps" : $"{mbps} Mbps";

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
