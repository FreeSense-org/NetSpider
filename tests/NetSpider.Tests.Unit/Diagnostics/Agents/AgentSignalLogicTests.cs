using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class AgentSignalLogicTests
{
    private static ProbeTargetResult Ok(double loss = 0) => new("gw", "10.40.0.1", 2, 2, loss, 10, null);
    private static ProbeTargetResult Bad(double loss = 100) => new("gw", "10.40.0.1", null, null, loss, 10, "TimedOut");

    [Fact]
    public void Never_reached_target_stays_quiet()
    {
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(AgentTargetState.Unknown, Bad(), out var s));
        Assert.Equal(AgentTargetState.Unknown, s);
    }

    [Fact]
    public void Reached_then_lost_then_back()
    {
        var state = AgentTargetState.Unknown;
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(state, Ok(), out state));
        Assert.Equal(AgentTargetState.Reachable, state);

        // 40% loss is not yet a failure
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(state, Ok(40), out state));
        Assert.Equal(AgentTargetTransition.Failure, AgentSignalLogic.Evaluate(state, Bad(50), out state));
        Assert.Equal(AgentTargetState.Failing, state);
        // still failing: no repeat
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(state, Bad(), out state));
        // loss dropping but the last ping still failed: not recovered yet
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(state, Bad(30), out state));
        Assert.Equal(AgentTargetTransition.Recovered, AgentSignalLogic.Evaluate(state, Ok(40), out state));
        Assert.Equal(AgentTargetState.Reachable, state);
    }

    [Fact]
    public void Empty_window_changes_nothing()
    {
        var none = new ProbeTargetResult("gw", null, null, null, 0, 0, "no default gateway");
        Assert.Equal(AgentTargetTransition.None, AgentSignalLogic.Evaluate(AgentTargetState.Reachable, none, out var s));
        Assert.Equal(AgentTargetState.Reachable, s);
    }

    [Fact]
    public void Offline_after_three_intervals_or_30s()
    {
        var now = DateTimeOffset.Now;
        Assert.False(AgentSignalLogic.IsOffline(now.AddSeconds(-29), 2, now));
        Assert.True(AgentSignalLogic.IsOffline(now.AddSeconds(-31), 2, now));
        Assert.False(AgentSignalLogic.IsOffline(now.AddSeconds(-50), 20, now));
        Assert.True(AgentSignalLogic.IsOffline(now.AddSeconds(-61), 20, now));
        Assert.True(AgentSignalLogic.IsOffline(now.AddSeconds(-31), null, now));
    }

    [Fact]
    public void Summary_names_both_vantage_points()
    {
        var r = new ProbeTargetResult("10.40.0.1", "10.40.0.1", null, null, 100, 10, "TimedOut");
        Assert.Equal("agent LAPTOP-WIFI cannot reach 10.40.0.1 (wired PC can; 100% loss)",
            AgentSignalLogic.FailureSummary("LAPTOP-WIFI", r, "wired PC", true));
        Assert.Equal("agent LAPTOP-WIFI cannot reach 10.40.0.1 (gw) (wired PC cannot either; agent pi-office can; 80% loss)",
            AgentSignalLogic.FailureSummary("LAPTOP-WIFI", Bad(80) with { Target = "gw" }, "wired PC", false, ["pi-office"]));
        Assert.True(AgentSignalLogic.FailureWeight(false) > AgentSignalLogic.FailureWeight(true));
    }
}
