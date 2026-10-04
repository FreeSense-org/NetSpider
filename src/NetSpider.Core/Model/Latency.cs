namespace NetSpider.Core.Model;

/// <summary>One latency probe result; <see cref="Ms"/> null means the probe was lost.</summary>
public readonly record struct LatencySample(DateTimeOffset Time, LatencyKind Kind, double? Ms);

public readonly record struct LatencySummary(double? Last, double? Min, double? Avg, double? Max, double? Jitter, double LossPercent, int Count)
{
    public static readonly LatencySummary Empty = new(null, null, null, null, null, 0, 0);
}

/// <summary>Thread-safe per-device ring buffers of latency samples, one per <see cref="LatencyKind"/>.</summary>
public sealed class LatencyStats
{
    public const int Capacity = 300;
    private readonly object _sync = new();
    private readonly Dictionary<LatencyKind, Queue<LatencySample>> _series = new();

    public void Add(LatencySample sample)
    {
        lock (_sync)
        {
            if (!_series.TryGetValue(sample.Kind, out var q)) _series[sample.Kind] = q = new Queue<LatencySample>(Capacity);
            if (q.Count == Capacity) q.Dequeue();
            q.Enqueue(sample);
        }
    }

    public void Add(LatencyKind kind, double? ms) => Add(new LatencySample(DateTimeOffset.Now, kind, ms));

    public LatencySample[] GetSeries(LatencyKind kind, int max = Capacity)
    {
        lock (_sync)
        {
            if (!_series.TryGetValue(kind, out var q)) return [];
            return q.Skip(Math.Max(0, q.Count - max)).ToArray();
        }
    }

    public LatencySummary Summarize(LatencyKind kind, int window = 60)
    {
        var s = GetSeries(kind, window);
        if (s.Length == 0) return LatencySummary.Empty;
        var ok = s.Where(x => x.Ms.HasValue).Select(x => x.Ms!.Value).ToArray();
        double loss = 100.0 * (s.Length - ok.Length) / s.Length;
        if (ok.Length == 0) return new LatencySummary(null, null, null, null, null, loss, s.Length);
        double jitter = 0;
        for (int i = 1; i < ok.Length; i++) jitter += Math.Abs(ok[i] - ok[i - 1]);
        jitter = ok.Length > 1 ? jitter / (ok.Length - 1) : 0;
        return new LatencySummary(s[^1].Ms, ok.Min(), ok.Average(), ok.Max(), jitter, loss, s.Length);
    }

    /// <summary>Last successful value of the given kind, if any.</summary>
    public double? Last(LatencyKind kind)
    {
        lock (_sync)
        {
            if (!_series.TryGetValue(kind, out var q)) return null;
            foreach (var x in q.Reverse()) if (x.Ms.HasValue) return x.Ms;
            return null;
        }
    }

    /// <summary>Best available host→device latency: L2 first, then L3.</summary>
    public double? BestLast => Last(LatencyKind.Arp) ?? Last(LatencyKind.Ndp) ?? Last(LatencyKind.Icmp) ?? Last(LatencyKind.Tcp);
}
