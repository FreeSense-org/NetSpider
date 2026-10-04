using System.Net;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.LocalLink;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

public sealed class LocalLinkRulesTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Now;

    private static LocalLinkState State(bool up = true, long speed = 1000, string ip = "10.40.210.17", string? gw = "10.40.0.1", bool wifi = false, string id = "A") =>
        new(id, wifi ? "Wi-Fi" : "Ethernet", "Intel NIC", Mac.Parse("AA:00:00:00:00:01"), up, speed, wifi,
            ip.Length == 0 ? [] : [new IpWithPrefix(IPAddress.Parse(ip), ip.StartsWith("169.254") ? 16 : 16)], gw is null ? null : IPAddress.Parse(gw));

    [Fact]
    public void Steady_state_is_silent()
    {
        Assert.Empty(LocalLinkRules.Diff(State(), State(), Now));
        Assert.Empty(LocalLinkRules.Diff(null, State(), Now));
    }

    [Fact]
    public void Cable_unplugged_and_restored()
    {
        var down = Assert.Single(LocalLinkRules.Diff(State(), State(up: false, speed: 0, ip: "", gw: null), Now));
        Assert.Equal(SignalKind.LocalLinkDown, down.Kind);
        Assert.Equal("Cable unplugged or switch port down on Ethernet", down.Summary);
        Assert.Equal("Ethernet", down.Port);
        Assert.Equal(Mac.Parse("AA:00:00:00:00:01"), down.Device);

        var up = LocalLinkRules.Diff(State(up: false, speed: 0, ip: "", gw: null), State(), Now);
        Assert.Contains(up, s => s.Kind == SignalKind.LocalLinkUp && s.Summary.Contains("1 Gbps"));
    }

    [Fact]
    public void Wifi_disconnect_text()
    {
        var s = Assert.Single(LocalLinkRules.Diff(State(wifi: true, speed: 866), State(up: false, wifi: true, speed: 0), Now));
        Assert.Equal("Wi-Fi disconnected on Wi-Fi", s.Summary);
    }

    [Fact]
    public void Speed_drop_is_reported_for_wired_only()
    {
        var s = Assert.Single(LocalLinkRules.Diff(State(speed: 1000), State(speed: 100), Now));
        Assert.Equal(SignalKind.LocalSpeedChanged, s.Kind);
        Assert.Equal("Link speed on Ethernet dropped 1 Gbps → 100 Mbps — possible bad cable or port", s.Summary);
        Assert.Empty(LocalLinkRules.Diff(State(wifi: true, speed: 866), State(wifi: true, speed: 400), Now));
    }

    [Fact]
    public void Apipa_is_dhcp_lease_lost_and_ip_change_is_reported()
    {
        var lost = LocalLinkRules.Diff(State(), State(ip: "169.254.10.20", gw: null), Now);
        Assert.Contains(lost, s => s.Kind == SignalKind.DhcpLeaseLost);
        Assert.Contains(lost, s => s.Kind == SignalKind.LocalGatewayChanged && s.Summary.Contains("disappeared"));

        var changed = LocalLinkRules.Diff(State(), State(ip: "10.40.210.99", gw: "10.40.0.254"), Now);
        Assert.Contains(changed, s => s.Kind == SignalKind.LocalIpChanged && s.Summary.Contains("10.40.210.99"));
        Assert.Contains(changed, s => s.Kind == SignalKind.LocalGatewayChanged && s.Summary.Contains("10.40.0.1 → 10.40.0.254"));
    }

    [Fact]
    public void Adapter_switch_is_reported_as_link_up_on_new_adapter()
    {
        var s = Assert.Single(LocalLinkRules.Diff(State(up: false, id: "A"), State(id: "B", wifi: true), Now));
        Assert.Equal(SignalKind.LocalLinkUp, s.Kind);
        Assert.Contains("Wi-Fi", s.Summary);
    }

    [Fact]
    public void Live_snapshot_of_best_adapter_does_not_throw()
    {
        var nic = LocalAdapters.FindBest();
        if (nic is null) return; // CI without a network
        var s = LocalAdapters.Snapshot(nic);
        Assert.NotNull(s);
        Assert.NotNull(LocalAdapters.ToAdapterInfo(nic));
    }
}
