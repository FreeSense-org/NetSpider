using System.Diagnostics;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Storm;

/// <summary>
/// Paced broadcast burst for the opt-in storm-control check.
/// SAFETY: the rate and duration are hard-capped here (<see cref="MaxPps"/>, <see cref="MaxDurationMs"/>, so at most
/// 25,000 frames) regardless of what the caller asks for, and the cap is re-applied inside <see cref="Run"/> as defense in
/// depth. The frame is supplied by the caller (the Storm Center uses an ARP who-has for an unused address in our own subnet,
/// from our real MAC), so no device changes state. Never called automatically.
/// </summary>
public static class BroadcastBurst
{
    public const int MaxPps = 5000;
    public const int MaxDurationMs = 5000;
    public const int MinDurationMs = 100;
    public const long MaxFrames = (long)MaxPps * MaxDurationMs / 1000;

    public static (int Pps, int DurationMs, int? VlanId) Clamp(StormControlOptions o) =>
        (Math.Clamp(o.Pps, 1, MaxPps), Math.Clamp(o.DurationMs, MinDurationMs, MaxDurationMs), o.VlanId is >= 1 and <= 4094 ? o.VlanId : null);

    /// <summary>
    /// Sends <paramref name="frame"/> at <paramref name="pps"/> for <paramref name="durationMs"/> (both re-capped), paced against a
    /// Stopwatch with SpinWait (no catch-up bursts beyond the schedule). Blocks the calling thread; returns the number of frames sent.
    /// </summary>
    public static int Run(IFrameSource source, byte[] frame, int pps, int durationMs, CancellationToken ct)
    {
        pps = Math.Clamp(pps, 1, MaxPps);
        durationMs = Math.Clamp(durationMs, MinDurationMs, MaxDurationMs);
        long total = Math.Min(MaxFrames, (long)pps * durationMs / 1000);
        double ticksPerFrame = Stopwatch.Frequency / (double)pps;
        long hardStop = Stopwatch.Frequency * durationMs / 1000 + Stopwatch.Frequency / 10; // +100 ms slack, then stop regardless
        long sleepThreshold = Stopwatch.Frequency / 50; // > 20 ms to wait: sleep instead of spinning

        var sw = Stopwatch.StartNew();
        int sent = 0;
        var spinner = new SpinWait();
        for (long i = 0; i < total; i++)
        {
            long due = (long)(i * ticksPerFrame);
            while (true)
            {
                if (ct.IsCancellationRequested) return sent;
                long remain = due - sw.ElapsedTicks;
                if (remain <= 0) break;
                if (remain > sleepThreshold) Thread.Sleep(1);
                else spinner.SpinOnce(sleep1Threshold: -1);
            }
            if (sw.ElapsedTicks > hardStop) break;
            try { source.Send(frame); }
            catch { break; }
            sent++;
        }
        return sent;
    }
}
