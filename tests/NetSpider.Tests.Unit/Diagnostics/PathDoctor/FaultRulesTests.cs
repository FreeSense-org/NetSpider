using NetSpider.Core.Model;
using NetSpider.Diagnostics.PathDoctor;
using static NetSpider.Tests.Unit.Diagnostics.PathDoctor.Office;
using H = NetSpider.Core.Model.HopHealth;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

public sealed class FaultRulesTests
{
    private readonly Office _o = new();

    [Fact]
    public void Nothing_wrong_yields_no_verdict()
    {
        Assert.Null(FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Up, H.Up, H.Up, H.Up, H.Up, H.Up))));
    }

    [Fact]
    public void Switch_down_on_the_path_is_a_path_cut()
    {
        var v = FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Up, H.Down, H.Down, H.Down, H.Down, H.Down)));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.LocalNetwork, v.Category);
        Assert.Equal(_o.Core.Mac, v.SuspectDevice);
        Assert.Contains("Everything up to access-sw (10.40.0.3) answers; core-sw-01 (10.40.0.2) does not", v.RootCause);
        Assert.Equal("access-sw ↔ core-sw-01", v.SuspectLink);
    }

    [Fact]
    public void Managed_switch_down_with_its_devices_via_blast_radius()
    {
        // core-sw-01 and everything behind it except our own branch went offline; the gateway still answers
        var gone = new List<Device> { _o.Core, _o.Ap };
        gone.AddRange(_o.Tvs);
        gone.AddRange(_o.Phones);
        _o.Offline(gone);
        var v = FaultRules.Evaluate(_o.Snapshot(unreachable: gone));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.LocalNetwork, v.Category);
        Assert.Equal(_o.Core.Mac, v.SuspectDevice);
        Assert.Equal("igb1", v.SuspectPort);
        Assert.Contains("OPNsense", v.RootCause);
        Assert.True(v.Confidence >= 0.8);
    }

    [Fact]
    public void Unmanaged_switch_down_points_at_inferred_switch_and_its_uplink_port()
    {
        _o.Offline(_o.Tvs);
        var v = FaultRules.Evaluate(_o.Snapshot(unreachable: _o.Tvs));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.LocalNetwork, v.Category);
        Assert.Equal(_o.TvRack.Mac, v.SuspectDevice);
        Assert.Equal("7", v.SuspectPort);
        Assert.Equal("Inferred switch 'TV rack' or its uplink to core-sw-01 (10.40.0.2) port 7 — 4 devices behind it unreachable", v.RootCause);
        Assert.Equal(0.7, v.Confidence, 3);
        Assert.Equal(4, v.Affected.Count);
    }

    [Fact]
    public void Port_errors_on_the_uplink_port_boost_confidence_and_add_evidence()
    {
        _o.Offline(_o.Tvs);
        var crc = Sig(SignalKind.PortErrors, "340 CRC errors/min", _o.Core.Mac, "7", 0.7);
        var other = Sig(SignalKind.PortErrors, "5 errors/min", _o.Core.Mac, "12", 0.7);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [crc, other], unreachable: _o.Tvs));
        Assert.NotNull(v);
        Assert.Equal(_o.TvRack.Mac, v.SuspectDevice);
        Assert.Equal(0.8, v.Confidence, 3);
        Assert.Contains(v.Evidence, e => e.Contains("port 7") && e.Contains("340 CRC errors/min"));
        Assert.DoesNotContain(v.Evidence, e => e.Contains("port 12"));
    }

    [Fact]
    public void Ap_answering_while_all_its_clients_are_unreachable_is_a_radio_problem()
    {
        _o.Offline(_o.Phones);
        var v = FaultRules.Evaluate(_o.Snapshot(unreachable: _o.Phones));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Wifi, v.Category);
        Assert.Equal(_o.Ap.Mac, v.SuspectDevice);
        Assert.Contains("All 3 Wi-Fi clients of ap-upstairs (10.40.0.10) are unreachable while the AP answers → AP radio/SSID problem", v.RootCause);
    }

    [Fact]
    public void Ap_clients_unreachable_signal_alone_triggers_the_radio_rule()
    {
        var sig = Sig(SignalKind.ApClientsUnreachable, "0/3 clients answer", _o.Ap.Mac, affected: _o.Phones.Select(p => p.Mac).ToList());
        var v = FaultRules.Evaluate(_o.Snapshot(active: [sig]));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Wifi, v.Category);
        Assert.Equal(_o.Ap.Mac, v.SuspectDevice);
    }

    [Fact]
    public void Ap_down_with_its_clients_blames_the_ap()
    {
        var gone = _o.Phones.Append(_o.Ap).ToList();
        _o.Offline(gone);
        var v = FaultRules.Evaluate(_o.Snapshot(unreachable: gone));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Wifi, v.Category);
        Assert.Equal(_o.Ap.Mac, v.SuspectDevice);
        Assert.Equal("9", v.SuspectPort);
        Assert.Contains("PoE", v.RootCause);
    }

    [Fact]
    public void Router_up_modem_down_blames_modem_or_wan_link()
    {
        var v = FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Up, H.Up, H.Up, H.Down, H.Down, H.Down)));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Modem, v.Category);
        Assert.Equal("Everything up to OPNsense (10.40.0.1) answers; Modem 10.255.104.1 does not → modem or the router↔modem cable/WAN link", v.RootCause);
        Assert.Equal(AlertSeverity.Critical, v.Severity);
    }

    [Fact]
    public void Modem_up_isp_down_blames_isp()
    {
        var v = FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Up, H.Up, H.Up, H.Up, H.Down, H.Down)));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Isp, v.Category);
        Assert.Contains("Modem 10.255.104.1 answers", v.RootCause);
    }

    [Fact]
    public void Isp_hop_that_ignores_pings_while_the_target_answers_is_not_a_fault()
    {
        Assert.Null(FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Up, H.Up, H.Up, H.Up, H.Down, H.Up))));
    }

    [Fact]
    public void Own_cable_unplugged_is_own_link_with_adapter_and_speed_evidence()
    {
        var speed = Sig(SignalKind.LocalSpeedChanged, "Link speed on Ethernet dropped 1 Gbps → 100 Mbps — possible bad cable or port", _o.Me.Mac, "Ethernet", 0.7);
        var down = Sig(SignalKind.LocalLinkDown, "Cable unplugged or switch port down on Ethernet", _o.Me.Mac, "Ethernet", 1);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [speed, down], path: _o.Path(H.Down, H.Down, H.Down, H.Down, H.Down, H.Down)));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.OwnLink, v.Category);
        Assert.StartsWith("Your own network link is down (cable/port/NIC or Wi-Fi association) on Ethernet", v.RootCause);
        Assert.Contains("1 Gbps → 100 Mbps", v.RootCause);
        Assert.Contains(v.Evidence, e => e.Contains("Cable unplugged"));
        Assert.True(v.Confidence >= 0.9);
    }

    [Fact]
    public void Everything_beyond_this_pc_down_without_nic_event_is_own_link()
    {
        var v = FaultRules.Evaluate(_o.Snapshot(path: _o.Path(H.Down, H.Down, H.Down, H.Down, H.Down, H.Down)));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.OwnLink, v.Category);
        Assert.Equal(0.75, v.Confidence, 3);
    }

    [Fact]
    public void Wifi_disconnect_of_this_host_is_wifi_with_reason()
    {
        var w = Sig(SignalKind.WifiDisconnected, "Disconnected from 'office' (reason 8: deauthenticated, AP left)");
        var down = Sig(SignalKind.LocalLinkDown, "Wi-Fi disconnected on Wi-Fi", _o.Me.Mac, "Wi-Fi", 1);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [down, w]));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Wifi, v.Category);
        Assert.Contains("reason 8", v.RootCause);
    }

    [Fact]
    public void Storm_overrides_blast_radius()
    {
        _o.Offline(_o.Tvs);
        var storm = Sig(SignalKind.StormDetected, "ARP storm 4200 pps from 00:50:B6:00:07:01", _o.Core.Mac, "7", 0.9);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [storm], unreachable: _o.Tvs));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Storm, v.Category);
        Assert.Contains("core-sw-01 (10.40.0.2) port 7", v.RootCause);
        Assert.Equal("7", v.SuspectPort);
    }

    [Fact]
    public void Loop_beats_storm()
    {
        var storm = Sig(SignalKind.StormDetected, "broadcast storm", weight: 0.9);
        var loop = Sig(SignalKind.LoopSuspected, "loop between core-sw-01 port 5 and port 9", _o.Core.Mac, null, 0.8);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [storm, loop]));
        Assert.Equal(IncidentCategory.Loop, v!.Category);
    }

    [Fact]
    public void Internet_down_with_lan_hops_up_is_isp()
    {
        var inet = Sig(SignalKind.InternetDown, "none of 3 targets answer");
        var path = _o.Path(H.Up, H.Up, H.Up, H.Unknown, H.Unknown, H.Unknown);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [inet], path: path));
        Assert.NotNull(v);
        Assert.Equal(IncidentCategory.Isp, v.Category);
        Assert.Contains("All LAN hops up to OPNsense (10.40.0.1) answer", v.RootCause);
    }

    [Fact]
    public void Internet_down_with_modem_down_is_modem()
    {
        var inet = Sig(SignalKind.InternetDown, "none of 3 targets answer");
        // the modem hop is down but the ISP hop happens to answer (asymmetric filtering) → no clean path cut
        var path = _o.Path(H.Up, H.Up, H.Up, H.Down, H.Up, H.Unknown);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [inet], path: path));
        Assert.Equal(IncidentCategory.Modem, v!.Category);
    }

    [Fact]
    public void Agent_and_this_pc_both_failing_blame_the_target()
    {
        _o.Offline([_o.Access]);
        var agent = Sig(SignalKind.AgentReportFailure, "laptop-2: access-sw 100 % loss", _o.Access.Mac, source: "laptop-2");
        var v = FaultRules.Evaluate(_o.Snapshot(active: [agent], unreachable: [_o.Access]));
        Assert.NotNull(v);
        Assert.Equal(_o.Access.Mac, v.SuspectDevice);
        Assert.Contains("Both this PC and probe agent laptop-2", v.RootCause);
    }

    [Fact]
    public void Only_agent_failing_points_at_agent_segment()
    {
        var agent = Sig(SignalKind.AgentReportFailure, "laptop-2: OPNsense 100 % loss", _o.Gw.Mac, source: "laptop-2");
        var v = FaultRules.Evaluate(_o.Snapshot(active: [agent]));
        Assert.NotNull(v);
        Assert.Null(v.SuspectDevice);
        Assert.Contains("agent's segment", v.RootCause);
    }

    [Fact]
    public void Port_signal_alone_is_a_switch_port_incident()
    {
        var flap = Sig(SignalKind.PortFlapping, "port 12 flapped 6× in 10 min", _o.Core.Mac, "12", 0.6);
        var v = FaultRules.Evaluate(_o.Snapshot(active: [flap]));
        Assert.Equal(IncidentCategory.SwitchPort, v!.Category);
        Assert.Equal("12", v.SuspectPort);
    }

    [Fact]
    public void Single_offline_device_is_not_an_incident()
    {
        _o.Offline([_o.Tvs[0]]);
        Assert.Null(FaultRules.Evaluate(_o.Snapshot(unreachable: [_o.Tvs[0]])));
    }

    [Fact]
    public void Signal_activity_clears_on_recovery_and_one_shots_expire()
    {
        var t0 = DateTimeOffset.Now;
        var down = Sig(SignalKind.LocalLinkDown, "down", time: t0);
        var up = Sig(SignalKind.LocalLinkUp, "up", time: t0.AddSeconds(5));
        var err = Sig(SignalKind.PortErrors, "crc", time: t0);
        Assert.Equal(2, SignalActivity.Active([down, err], t0.AddSeconds(1)).Count);
        Assert.Single(SignalActivity.Active([down, up, err], t0.AddSeconds(6)));
        Assert.Empty(SignalActivity.Active([down, up, err], t0.AddSeconds(120)));
    }
}
