using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Topology;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics;

public sealed class TopologyBuilderTests
{
    private readonly DeviceStore _devices = new();
    private readonly TopologyStore _topology = new();
    private readonly NetworkState _network = new();
    private readonly TopologyBuilder _builder;
    private readonly ScanContext _ctx = Context();

    // a small office: gateway, core switch S1 (managed), access switch S2 (managed), PCs, an unmanaged desk switch
    private readonly Device _me, _gw, _s1, _s2, _pc, _a, _b, _c, _d, _orphan;

    public TopologyBuilderTests()
    {
        _builder = new TopologyBuilder(NullLogger<TopologyBuilder>.Instance, _devices, _topology, _network);
        _me = AddDevice(_devices, LocalMac.ToString(), "192.168.1.10", DeviceType.ThisComputer, DeviceFlags.ThisHost);
        _gw = AddDevice(_devices, "00:0D:B9:00:00:01", "192.168.1.1", DeviceType.Router, DeviceFlags.Gateway);
        _s1 = AddDevice(_devices, "00:1B:21:00:00:01", "192.168.1.2", DeviceType.CoreSwitch, name: "core-sw");
        _s2 = AddDevice(_devices, "00:1B:21:00:00:02", "192.168.1.3", DeviceType.AccessSwitch, name: "access-sw");
        _pc = AddDevice(_devices, "00:50:B6:00:00:01", "192.168.1.20");
        _a = AddDevice(_devices, "00:50:B6:00:00:0A", "192.168.1.30");
        _b = AddDevice(_devices, "00:50:B6:00:00:0B", "192.168.1.31");
        _c = AddDevice(_devices, "00:50:B6:00:00:0C", "192.168.1.32");
        _d = AddDevice(_devices, "00:50:B6:00:00:0D", "192.168.1.40");
        _orphan = AddDevice(_devices, "00:50:B6:00:00:FF", "192.168.1.99");
    }

    private static FdbEntry Fdb(Device sw, string port, Device d, int? idx = null) => new(sw.Mac, port, idx, d.Mac, 1, DateTimeOffset.Now);
    private static FdbEntry Fdb(Device sw, string port, Mac m) => new(sw.Mac, port, null, m, 1, DateTimeOffset.Now);

    private void SetupFdb()
    {
        _network.SetFdb(_s1.Mac,
        [
            Fdb(_s1, "Gi1/0/1", _pc, 1),
            Fdb(_s1, "Gi1/0/2", _a), Fdb(_s1, "Gi1/0/2", _b), Fdb(_s1, "Gi1/0/2", _c), // unmanaged switch behind port 2
            Fdb(_s1, "Gi1/0/3", _gw),
            Fdb(_s1, "Gi1/0/10", _me),
            Fdb(_s1, "Gi1/0/24", _s2), Fdb(_s1, "Gi1/0/24", _d),                      // uplink to S2
        ]);
        _network.SetFdb(_s2.Mac,
        [
            Fdb(_s2, "1", _d),
            Fdb(_s2, "48", _s1), Fdb(_s2, "48", _pc), Fdb(_s2, "48", _gw), Fdb(_s2, "48", _a), Fdb(_s2, "48", _me),
        ]);
        _network.SetSwitchPorts(_s1.Mac, [new SwitchPortInfo(_s1.Mac, 1, "Gi1/0/1", "desk-12", 1000, true, "full", 6.5, 1)]);
    }

    private Link? LinkBetween(Mac x, Mac y) => _topology.Links.FirstOrDefault(l => l.Touches(x) && l.Touches(y));

    [Fact]
    public void Fdb_single_mac_port_links_switch_to_device_with_port_details()
    {
        SetupFdb();
        _builder.Rebuild(_ctx);

        var l = LinkBetween(_s1.Mac, _pc.Mac);
        Assert.NotNull(l);
        Assert.Equal(LinkKind.BridgeFdb, l!.Kind);
        Assert.Equal("Gi1/0/1", l.PortOf(_s1.Mac));
        Assert.Equal(1000, l.SpeedMbps);
        Assert.Equal(6.5, l.PoeWatts);
        Assert.Equal(_s1.Mac, _pc.UpstreamMac);
        Assert.Equal("Gi1/0/1", _pc.UpstreamPort);
    }

    [Fact]
    public void Fdb_uplink_between_managed_switches_uses_both_port_names()
    {
        SetupFdb();
        _builder.Rebuild(_ctx);

        var up = LinkBetween(_s1.Mac, _s2.Mac);
        Assert.NotNull(up);
        Assert.Equal(LinkKind.BridgeFdb, up!.Kind);
        Assert.Equal("Gi1/0/24", up.PortOf(_s1.Mac));
        Assert.Equal("48", up.PortOf(_s2.Mac));
        // D is seen on S1's uplink and S2 port 1: the port with the fewest MACs (S2/1) wins
        var dl = LinkBetween(_s2.Mac, _d.Mac);
        Assert.NotNull(dl);
        Assert.Equal("1", dl!.PortOf(_s2.Mac));
        Assert.Null(LinkBetween(_s1.Mac, _d.Mac));
        Assert.Equal(_s2.Mac, _d.UpstreamMac);
    }

    [Fact]
    public void Edge_port_with_several_macs_and_no_lldp_gets_inferred_unmanaged_switch()
    {
        SetupFdb();
        _builder.Rebuild(_ctx);

        var inferredMac = SyntheticNodes.InferredSwitch(_s1.Mac, "Gi1/0/2");
        Assert.True(_devices.TryGet(inferredMac, out var inferred));
        Assert.Equal(DeviceType.UnmanagedSwitch, inferred.Type);
        Assert.True(inferred.Has(DeviceFlags.Inferred));

        var toSwitch = LinkBetween(_s1.Mac, inferredMac);
        Assert.NotNull(toSwitch);
        Assert.Equal(LinkKind.InferredUnmanagedSwitch, toSwitch!.Kind);
        Assert.Equal(0.6, toSwitch.Confidence);
        Assert.Equal("Gi1/0/2", toSwitch.PortOf(_s1.Mac));
        foreach (var d in new[] { _a, _b, _c })
        {
            var l = LinkBetween(inferredMac, d.Mac);
            Assert.NotNull(l);
            Assert.Equal(LinkKind.InferredUnmanagedSwitch, l!.Kind);
            Assert.Equal(inferredMac, d.UpstreamMac);
        }
        Assert.Equal(_s1.Mac, inferred.UpstreamMac);
    }

    [Fact]
    public void Lldp_neighbor_on_port_suppresses_inference_and_links_with_ports()
    {
        SetupFdb();
        // an AP advertises itself via LLDP on Gi1/0/2: A is the AP, B and C are its wireless clients
        _a.Type = DeviceType.AccessPoint;
        _network.AddNeighbor(new NeighborEntry(_s1.Mac, "Gi1/0/2", _a.Mac, null, "eth0", "ap-lobby", null, "UniFi AP", "Bridge, WLAN", "LLDP", DateTimeOffset.Now));
        _builder.Rebuild(_ctx);

        Assert.False(_devices.TryGet(SyntheticNodes.InferredSwitch(_s1.Mac, "Gi1/0/2"), out _));
        var l = LinkBetween(_s1.Mac, _a.Mac);
        Assert.Equal(LinkKind.LldpCdp, l!.Kind);
        Assert.Equal("Gi1/0/2", l.PortOf(_s1.Mac));
        Assert.Equal("eth0", l.PortOf(_a.Mac));
        Assert.Equal(LinkKind.WifiAssoc, LinkBetween(_a.Mac, _b.Mac)!.Kind);
        Assert.Equal(_a.Mac, _c.UpstreamMac);
    }

    [Fact]
    public void Lldp_neighbor_resolved_by_management_ip_and_by_name()
    {
        // this host receives LLDP from S1 (Reporter = S1, Neighbor = this host); S1's LLDP-MIB reports S2 by sysName only
        _network.AddNeighbor(new NeighborEntry(_s1.Mac, "Gi1/0/10", _me.Mac, null, null, null, null, null, null, "LLDP", DateTimeOffset.Now));
        _network.AddNeighbor(new NeighborEntry(_s1.Mac, "Gi1/0/24", null, "some-chassis", "Port 48", "ACCESS-SW.corp.local", null, null, "Bridge", "LLDP", DateTimeOffset.Now));
        _network.AddNeighbor(new NeighborEntry(_s2.Mac, "Port 47", null, "x", "ge-0/0/1", null, IPAddress.Parse("192.168.1.1"), null, "Router", "LLDP", DateTimeOffset.Now));
        _builder.Rebuild(_ctx);

        Assert.Equal("Gi1/0/10", LinkBetween(_s1.Mac, _me.Mac)!.PortOf(_s1.Mac));
        var s1s2 = LinkBetween(_s1.Mac, _s2.Mac);
        Assert.Equal(LinkKind.LldpCdp, s1s2!.Kind);
        Assert.Equal("Port 48", s1s2.PortOf(_s2.Mac));
        Assert.Equal(LinkKind.LldpCdp, LinkBetween(_s2.Mac, _gw.Mac)!.Kind);
    }

    [Fact]
    public void Internet_node_links_to_gateway_with_first_public_hop_rtt()
    {
        _network.InternetPath =
        [
            new TracerouteHop(1, IPAddress.Parse("192.168.1.1"), 0.6, null, _gw.Mac),
            new TracerouteHop(2, IPAddress.Parse("100.64.0.1"), 7.8, null, null),
            new TracerouteHop(3, IPAddress.Parse("62.1.2.3"), 9.1, null, null),
        ];
        _builder.Rebuild(_ctx);

        Assert.True(_devices.TryGet(SyntheticNodes.Internet, out var inet));
        Assert.Equal(DeviceType.Internet, inet.Type);
        var wan = LinkBetween(_gw.Mac, SyntheticNodes.Internet);
        Assert.Equal(LinkKind.Wan, wan!.Kind);
        Assert.Equal(7.8, wan.LatencyMs);
        Assert.Equal(LatencyOrigin.Measured, wan.LatencyOrigin);
        Assert.Equal(SyntheticNodes.Internet, _gw.UpstreamMac);
    }

    [Fact]
    public void Unattached_devices_fall_back_to_gateway_star()
    {
        SetupFdb();
        _builder.Rebuild(_ctx);
        var l = LinkBetween(_gw.Mac, _orphan.Mac);
        Assert.Equal(LinkKind.GatewayStar, l!.Kind);
        Assert.Equal(0.3, l.Confidence);
        Assert.Equal(LatencyOrigin.Estimated, l.LatencyOrigin);
        Assert.Equal(_gw.Mac, _orphan.UpstreamMac);
        // every non-root device is reachable
        Assert.All(_devices.All.Where(d => d.Mac != SyntheticNodes.Internet), d => Assert.NotNull(d.UpstreamMac));
    }

    [Fact]
    public void Without_gateway_this_host_is_the_star_center()
    {
        var devices = new DeviceStore();
        var b = new TopologyBuilder(NullLogger<TopologyBuilder>.Instance, devices, _topology, new NetworkState());
        var me = AddDevice(devices, LocalMac.ToString(), "10.0.0.5", flags: DeviceFlags.ThisHost);
        var x = AddDevice(devices, "00:50:B6:00:01:01", "10.0.0.7");
        b.Rebuild(Context(Adapter("10.0.0.5", 24, "10.0.0.1")));
        Assert.Equal(LinkKind.GatewayStar, _topology.Links.Single(l => l.Touches(x.Mac) && l.Touches(me.Mac)).Kind);
    }

    [Fact]
    public void Vm_sharing_a_port_with_its_host_links_to_the_host()
    {
        var host = AddDevice(_devices, "00:50:B6:00:00:50", "192.168.1.50", DeviceType.Hypervisor);
        var vm1 = AddDevice(_devices, "00:15:5D:01:02:03", "192.168.1.51");
        var vm2 = AddDevice(_devices, "00:0C:29:AA:BB:CC", "192.168.1.52");
        _network.SetFdb(_s1.Mac, [Fdb(_s1, "Gi1/0/5", host), Fdb(_s1, "Gi1/0/5", vm1), Fdb(_s1, "Gi1/0/5", vm2), Fdb(_s1, "Gi1/0/3", _gw)]);
        _builder.Rebuild(_ctx);

        Assert.Equal(LinkKind.BridgeFdb, LinkBetween(_s1.Mac, host.Mac)!.Kind);
        Assert.Equal(LinkKind.VirtualHypervisor, LinkBetween(host.Mac, vm1.Mac)!.Kind);
        Assert.Equal(LinkKind.VirtualHypervisor, LinkBetween(host.Mac, vm2.Mac)!.Kind);
        Assert.Equal(host.Mac, vm1.UpstreamMac);
    }

    [Fact]
    public void Unplaced_vm_without_known_host_goes_to_virtual_group()
    {
        var vm = AddDevice(_devices, "08:00:27:11:22:33", "192.168.1.77");
        _builder.Rebuild(_ctx);
        var l = _topology.Links.Single(x => x.Touches(vm.Mac));
        Assert.Equal(LinkKind.VirtualHypervisor, l.Kind);
        Assert.True(_devices.TryGet(l.Other(vm.Mac), out var group));
        Assert.True(group.Has(DeviceFlags.Inferred));
        Assert.NotNull(group.UpstreamMac); // the group hangs off the gateway
    }

    [Fact]
    public void Wifi_bssid_matches_ap_mac_and_links_this_host()
    {
        var ap = AddDevice(_devices, "F0:9F:C2:10:20:30", "192.168.1.5");
        _network.WifiNetworks =
        [
            new WifiNetwork("Office", Mac.Parse("F0:9F:C2:10:20:33"), 36, 5180, "5 GHz", -55, 90, "WPA3", "802.11ax", "Ubiquiti", true, 80, DateTimeOffset.Now),
        ];
        _builder.Rebuild(_ctx);
        Assert.Equal(DeviceType.AccessPoint, ap.Type);
        var l = LinkBetween(ap.Mac, _me.Mac);
        Assert.Equal(LinkKind.WifiAssoc, l!.Kind);
        Assert.Equal("Office (5 GHz)", l.PortOf(ap.Mac));
        Assert.Equal("Office", _me.Wifi!.Ssid);
    }

    [Fact]
    public void Off_subnet_host_links_to_its_segment_gateway()
    {
        var router2 = AddDevice(_devices, "00:0D:B9:00:00:02", "192.168.1.254", DeviceType.Router);
        _network.AddOrGetSegment(IPAddress.Parse("10.20.0.0"), 16, "snmp", s => s.Gateway = IPAddress.Parse("192.168.1.254"));
        var remote = _devices.GetOrAdd(SyntheticNodes.RemoteHost(IPAddress.Parse("10.20.1.5")));
        _devices.Observe(remote.Mac, IPAddress.Parse("10.20.1.5"), "icmp");
        _builder.Rebuild(_ctx);
        var l = LinkBetween(router2.Mac, remote.Mac);
        Assert.Equal(LinkKind.L3Hop, l!.Kind);
    }

    [Fact]
    public void Stale_inferred_switch_is_removed_when_evidence_disappears()
    {
        SetupFdb();
        _builder.Rebuild(_ctx);
        var inferredMac = SyntheticNodes.InferredSwitch(_s1.Mac, "Gi1/0/2");
        Assert.True(_devices.TryGet(inferredMac, out _));

        _network.SetFdb(_s1.Mac, [Fdb(_s1, "Gi1/0/2", _a)]);
        _network.SetFdb(_s2.Mac, []);
        _builder.Rebuild(_ctx);
        Assert.False(_devices.TryGet(inferredMac, out _));
        Assert.Equal(LinkKind.BridgeFdb, LinkBetween(_s1.Mac, _a.Mac)!.Kind);
    }

    [Fact]
    public void Link_latency_is_estimated_from_host_rtts()
    {
        SetupFdb();
        _s1.Latency.Add(LatencyKind.Arp, 0.4);
        _pc.Latency.Add(LatencyKind.Arp, 0.9);
        _builder.Rebuild(_ctx);
        var l = LinkBetween(_s1.Mac, _pc.Mac)!;
        Assert.Equal(0.5, l.LatencyMs!.Value, 3);
        Assert.Equal(LatencyOrigin.Estimated, l.LatencyOrigin);
    }
}
