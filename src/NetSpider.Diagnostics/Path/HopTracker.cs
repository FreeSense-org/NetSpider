using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>Outcome of probing one hop once. <see cref="ArpOk"/>/<see cref="IcmpOk"/> are null when that probe was not attempted.</summary>
public sealed record HopProbeResult(bool? ArpOk, bool? IcmpOk, double? RttMs, int AnchorsAnswered = 0, int AnchorsProbed = 0)
{
    public bool Answered => ArpOk == true || IcmpOk == true;
    public static readonly HopProbeResult NotProbed = new(null, null, null);
}

/// <summary>
/// Per-hop rolling state: consecutive failures, loss/jitter over the last 60 probes, a 300-sample ring and the rolling
/// median RTT. Pure and deterministic; <see cref="PathMonitor"/> feeds it one result per round.
/// </summary>
public sealed class HopTracker
{
    public const int RecentCapacity = 300;
    public const int StatsWindow = 60;
    public const double LossDegradedPercent = 20;
    public const double SpikeFactor = 3;
    public const int MinSamplesForMedian = 5;

    private readonly Queue<double?> _recent = new();

    public HopHealth Health { get; private set; } = HopHealth.Unknown;
    public int ConsecutiveFailures { get; private set; }
    public double? LastRtt { get; private set; }
    public double? Median { get; private set; }
    public double LossPercent { get; private set; }
    public double? Jitter { get; private set; }
    public bool? ArpOk { get; private set; }
    public bool? IcmpOk { get; private set; }
    public string? Note { get; private set; }
    public IReadOnlyList<double?> Recent => _recent.ToArray();
    /// <summary>true once the hop has answered at least one probe.</summary>
    public bool EverAnswered { get; private set; }

    /// <summary>Feeds one probe round and returns the new health.</summary>
    public HopHealth Record(HopProbeResult r, int downRounds, HopProbe probe)
    {
        if (probe is HopProbe.None)
        {
            Health = HopHealth.Unknown;
            Note = null;
            return Health;
        }
        if (probe is HopProbe.Self)
        {
            Add(0);
            Health = HopHealth.Up;
            LastRtt = 0;
            return Health;
        }

        ArpOk = r.ArpOk;
        IcmpOk = r.IcmpOk;
        double? rtt = r.Answered ? r.RttMs ?? 0 : null;
        // median of earlier samples, so a spike does not lift its own baseline
        var baseline = Median;
        Add(rtt);
        LastRtt = rtt;
        ConsecutiveFailures = r.Answered ? 0 : ConsecutiveFailures + 1;
        EverAnswered |= r.Answered;
        Compute();

        string? note = null;
        HopHealth h;
        if (!r.Answered)
        {
            h = ConsecutiveFailures >= Math.Max(1, downRounds) ? HopHealth.Down
                : Health == HopHealth.Unknown ? HopHealth.Unknown : Health; // keep state until the threshold is reached
            note = h == HopHealth.Down
                ? probe == HopProbe.Anchors ? $"none of the {r.AnchorsProbed} anchor devices behind it answer ({ConsecutiveFailures} rounds)"
                : $"no answer for {ConsecutiveFailures} rounds"
                : $"missed {ConsecutiveFailures} probe(s)";
        }
        else
        {
            h = HopHealth.Up;
            // anchors judge a switch: any answer (L2 or L3) from any anchor proves it forwards
            if (probe == HopProbe.Anchors) { }
            else if (r.ArpOk == true && r.IcmpOk == false)
            {
                h = HopHealth.Degraded;
                note = "answers ARP but not ICMP — host firewall / CPU (alive at L2)";
            }
            else if (r.ArpOk == false && r.IcmpOk == true)
            {
                note = "answers ICMP but not ARP — proxy ARP or L2 oddity";
            }
            if (LossPercent > LossDegradedPercent)
            {
                h = HopHealth.Degraded;
                note = Join(note, $"loss {LossPercent:0} %");
            }
            if (rtt is { } ms && baseline is { } med && med > 0 && ms > SpikeFactor * med && ms - med >= 1)
            {
                h = HopHealth.Degraded;
                note = Join(note, $"RTT {ms:0.#} ms is >{SpikeFactor:0}× the usual {med:0.#} ms");
            }
            if (probe == HopProbe.Anchors)
                note = Join($"{r.AnchorsAnswered}/{r.AnchorsProbed} anchor devices answer", note);
        }
        Health = h;
        Note = note;
        return h;
    }

    private static string? Join(string? a, string? b) => a is null ? b : b is null ? a : $"{a}; {b}";

    private void Add(double? v)
    {
        _recent.Enqueue(v);
        while (_recent.Count > RecentCapacity) _recent.Dequeue();
    }

    private void Compute()
    {
        var window = _recent.Skip(Math.Max(0, _recent.Count - StatsWindow)).ToArray();
        if (window.Length == 0) { LossPercent = 0; Jitter = null; Median = null; return; }
        var ok = window.Where(x => x.HasValue).Select(x => x!.Value).ToArray();
        LossPercent = 100.0 * (window.Length - ok.Length) / window.Length;
        if (ok.Length > 1)
        {
            double j = 0;
            for (int i = 1; i < ok.Length; i++) j += Math.Abs(ok[i] - ok[i - 1]);
            Jitter = j / (ok.Length - 1);
        }
        else Jitter = null;
        if (ok.Length >= MinSamplesForMedian)
        {
            var sorted = ok.OrderBy(x => x).ToArray();
            Median = sorted.Length % 2 == 1 ? sorted[sorted.Length / 2] : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2;
        }
        else Median = null;
    }
}
