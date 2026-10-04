using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

/// <summary>Per agent+target reachability state as seen through agent reports.</summary>
public enum AgentTargetState { Unknown, Reachable, Failing }

public enum AgentTargetTransition { None, Failure, Recovered }

/// <summary>Reverse (hub → agent) reachability, measured by the hub pinging each online agent every 2 s.</summary>
public sealed record AgentReverseProbe(string AgentId, string? Ip, bool Reachable, double? LastRttMs, double? AvgMs,
    double LossPercent, int Sent, DateTimeOffset Updated);

/// <summary>Pure decision rules used by <see cref="ProbeAgentHub"/> (kept separate for unit tests).</summary>
public static class AgentSignalLogic
{
    /// <summary>Loss over the agent's window at or above this marks a previously reached target as failing.</summary>
    public const double FailLossPercent = 50;
    public static readonly TimeSpan MinOfflineAfter = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Failure only fires for a target the agent previously reached (so permanently unreachable targets stay quiet);
    /// recovery needs loss back under the threshold and the latest ping answered.
    /// </summary>
    public static AgentTargetTransition Evaluate(AgentTargetState previous, ProbeTargetResult r, out AgentTargetState next)
    {
        bool sampled = r.Sent > 0;
        bool failing = sampled && r.LossPercent >= FailLossPercent;
        bool healthy = sampled && r.LossPercent < FailLossPercent && r.RttMs is not null;
        switch (previous)
        {
            case AgentTargetState.Unknown:
                next = healthy ? AgentTargetState.Reachable : AgentTargetState.Unknown;
                return AgentTargetTransition.None;
            case AgentTargetState.Reachable when failing:
                next = AgentTargetState.Failing;
                return AgentTargetTransition.Failure;
            case AgentTargetState.Failing when healthy:
                next = AgentTargetState.Reachable;
                return AgentTargetTransition.Recovered;
            default:
                next = previous;
                return AgentTargetTransition.None;
        }
    }

    /// <summary>An agent is offline after 3× its report interval without a report, but never sooner than 30 s.</summary>
    public static TimeSpan OfflineAfter(double? intervalSeconds)
    {
        var three = TimeSpan.FromSeconds(3 * Math.Max(0, intervalSeconds ?? 0));
        return three > MinOfflineAfter ? three : MinOfflineAfter;
    }

    public static bool IsOffline(DateTimeOffset lastSeen, double? intervalSeconds, DateTimeOffset now) =>
        now - lastSeen > OfflineAfter(intervalSeconds);

    /// <summary>"10.40.0.1" or "10.40.0.1 (gw)" when the configured target is a name.</summary>
    public static string TargetLabel(ProbeTargetResult r) =>
        string.IsNullOrEmpty(r.Ip) || r.Ip == r.Target ? r.Target : $"{r.Ip} ({r.Target})";

    /// <summary>
    /// "agent LAPTOP-WIFI cannot reach 10.40.0.1 (wired PC can)". <paramref name="hubCanReach"/> null = not checked;
    /// <paramref name="othersReaching"/> lists other agents that still reach the target.
    /// </summary>
    public static string FailureSummary(string agent, ProbeTargetResult r, string hubName, bool? hubCanReach, IReadOnlyList<string>? othersReaching = null)
    {
        var views = new List<string>();
        if (hubCanReach == true) views.Add($"{hubName} can");
        else if (hubCanReach == false) views.Add($"{hubName} cannot either");
        if (othersReaching is { Count: > 0 }) views.Add($"agent {string.Join(", ", othersReaching)} can");
        var loss = $"{r.LossPercent:0}% loss";
        return views.Count == 0
            ? $"agent {agent} cannot reach {TargetLabel(r)} ({loss})"
            : $"agent {agent} cannot reach {TargetLabel(r)} ({string.Join("; ", views)}; {loss})";
    }

    public static string RecoveredSummary(string agent, ProbeTargetResult r) =>
        $"agent {agent} reaches {TargetLabel(r)} again ({r.LossPercent:0}% loss{(r.RttMs is { } ms ? $", {ms:0.#} ms" : "")})";

    /// <summary>
    /// Signal weight: when the hub (another vantage point) still reaches the target, the fault is most likely on the
    /// agent's side of the path, so the target device itself is a weak suspect.
    /// </summary>
    public static double FailureWeight(bool? hubCanReach) => hubCanReach switch { true => 0.3, false => 0.8, null => 0.5 };
}
