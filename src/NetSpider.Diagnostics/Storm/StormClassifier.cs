using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Storm;

/// <summary>
/// Classifies one second of traffic as Normal / Elevated / Storm.
/// Storm uses the existing thresholds (<see cref="AppSettings.StormBroadcastRatio"/> together with
/// <see cref="AppSettings.StormBroadcastPps"/>, or <see cref="AppSettings.StormMulticastPps"/>). Elevated means above
/// 3× the learned baseline, or more than half of a storm threshold, with small absolute floors so a quiet network does not
/// flicker at a handful of packets.
/// </summary>
public static class StormClassifier
{
    public const double ElevatedBaselineFactor = 3;
    public const double MinElevatedBroadcastPps = 50;
    public const double MinElevatedMulticastPps = 100;

    public static StormLevel Classify(double broadcastPps, double multicastPps, double totalPps, double baselineBroadcast, double baselineMulticast, bool baselineWarmed, AppSettings s)
    {
        double ratio = totalPps > 0 ? broadcastPps / totalPps : 0;
        if ((ratio > s.StormBroadcastRatio && broadcastPps > s.StormBroadcastPps) || multicastPps > s.StormMulticastPps)
            return StormLevel.Storm;

        bool bElevated = broadcastPps >= MinElevatedBroadcastPps &&
                         (ratio > s.StormBroadcastRatio / 2 || (baselineWarmed && broadcastPps > baselineBroadcast * ElevatedBaselineFactor));
        bool mElevated = multicastPps >= MinElevatedMulticastPps &&
                         (multicastPps > s.StormMulticastPps / 2 || (baselineWarmed && multicastPps > baselineMulticast * ElevatedBaselineFactor));
        return bElevated || mElevated ? StormLevel.Elevated : StormLevel.Normal;
    }
}

/// <summary>Exponentially weighted moving average that learns only from calm samples.</summary>
public sealed class EwmaBaseline
{
    public EwmaBaseline(double alpha = 0.05, int warmupSamples = 60)
    {
        Alpha = alpha;
        WarmupSamples = warmupSamples;
    }

    public double Alpha { get; }
    public int WarmupSamples { get; }
    public double Value { get; private set; }
    public int Samples { get; private set; }
    public bool Warmed => Samples >= WarmupSamples;

    public void Add(double x)
    {
        Value = Samples == 0 ? x : Value + Alpha * (x - Value);
        Samples++;
    }
}
