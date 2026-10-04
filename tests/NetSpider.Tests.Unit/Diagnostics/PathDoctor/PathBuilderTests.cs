using System.Net;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.PathDoctor;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

public sealed class PathBuilderTests
{
    private readonly Office _o = new();
    private readonly AppSettings _settings = new();

    private PathBuilder Builder(AdapterInfo? adapter, DeviceStore? devices = null, TopologyStore? topo = null, NetworkState? net = null) =>
        new(devices ?? _o.Devices, topo ?? _o.Topology, net ?? _o.Network, () => _settings, () => adapter);

    [Fact]
    public void Wired_path_walks_topology_then_traceroute()
    {
        var p = Builder(_o.Adapter()).Build();
        Assert.Equal("Wired", p.Medium);
        Assert.Equal(
            [HopRole.ThisHost, HopRole.Switch, HopRole.Switch, HopRole.Firewall, HopRole.Modem, HopRole.IspHop, HopRole.IspHop, HopRole.IspHop, HopRole.InternetTarget],
            p.Hops.Select(h => h.Role).ToArray());
        Assert.Equal(["my-pc", "access-sw", "core-sw-01", "OPNsense"], p.Hops.Take(4).Select(h => h.Name).ToArray());
        Assert.Equal(["3", "5", "igb1"], p.Hops.Skip(1).Take(3).Select(h => h.PortIn ?? "").ToArray());
        Assert.All(p.Hops.Skip(1).Take(3), h => Assert.Equal(HopProbe.ArpIcmp, h.Probe));
        Assert.Equal(Office.ModemIp, p.Hops[4].Ip);
        Assert.Equal(HopProbe.IcmpOnly, p.Hops[4].Probe);
        Assert.Equal("isp-bras", p.Hops[5].Name);
        Assert.Equal(IPAddress.Parse("62.1.3.1"), p.Hops[7].Ip);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), p.Hops[^1].Ip);
        Assert.Equal("Internet (Cloudflare 1.1.1.1)", p.Hops[^1].Name);
        Assert.Equal(HopProbe.Self, p.Hops[0].Probe);
        Assert.Equal(Enumerable.Range(0, p.Hops.Count), p.Hops.Select(h => h.Index));
    }

    [Fact]
    public void Unmanaged_switch_hop_is_probed_through_anchors()
    {
        _o.Topology.RemoveWhere(l => l.Touches(_o.Me.Mac));
        _o.Topology.Upsert(_o.TvRack.Mac, _o.Me.Mac, LinkKind.InferredUnmanagedSwitch);
        _o.Tvs[3].State = DeviceState.Offline;
        var p = Builder(_o.Adapter()).Build();
        var hop = p.Hops[1];
        Assert.Equal(HopRole.UnmanagedSwitch, hop.Role);
        Assert.Equal(HopProbe.Anchors, hop.Probe);
        Assert.Null(hop.Ip);
        Assert.Equal(3, hop.Anchors.Count);
        Assert.DoesNotContain(_o.Me.Mac, hop.Anchors);
        Assert.DoesNotContain(_o.Tvs[3].Mac, hop.Anchors);
        Assert.Equal("core-sw-01", p.Hops[2].Name);
        Assert.Equal("7", p.Hops[2].PortIn);
    }

    [Fact]
    public void Minimal_path_without_topology_uses_adapter_and_traceroute()
    {
        var net = new NetworkState { InternetPath = _o.Network.InternetPath };
        var p = Builder(_o.Adapter(), new DeviceStore(), new TopologyStore(), net).Build();
        Assert.Equal(HopRole.ThisHost, p.Hops[0].Role);
        Assert.Equal(HopRole.Router, p.Hops[1].Role);
        Assert.Equal(IPAddress.Parse("10.40.0.1"), p.Hops[1].Ip);
        Assert.Equal(HopProbe.ArpIcmp, p.Hops[1].Probe);
        Assert.Equal(HopRole.Modem, p.Hops[2].Role);
        Assert.Equal(HopRole.InternetTarget, p.Hops[^1].Role);
        Assert.Equal(7, p.Hops.Count); // self, gw, modem, 3 ISP, target
    }

    [Fact]
    public void No_adapter_no_topology_still_yields_host_and_target()
    {
        var p = Builder(null, new DeviceStore(), new TopologyStore(), new NetworkState()).Build();
        Assert.Equal([HopRole.ThisHost, HopRole.InternetTarget], p.Hops.Select(h => h.Role).ToArray());
    }

    [Fact]
    public void Wifi_host_gets_synthetic_ap_hop_when_bssid_is_unknown()
    {
        _o.Me.Wifi = new WifiAssociation("office", Mac.Parse("11:22:33:44:55:66"), 36, "5 GHz", -55, "ax");
        var p = Builder(_o.Adapter(wireless: true)).Build();
        Assert.Equal("Wi-Fi", p.Medium);
        Assert.Equal(HopRole.AccessPoint, p.Hops[1].Role);
        Assert.Equal("Wi-Fi AP office", p.Hops[1].Name);
        Assert.Null(p.Hops[1].Ip);
        Assert.Equal(HopProbe.None, p.Hops[1].Probe);
    }

    [Fact]
    public void Wifi_host_matches_bssid_to_ap_device()
    {
        _o.Me.Wifi = new WifiAssociation("office", _o.Ap.Mac.Offset(2), 36, "5 GHz", -55, "ax");
        var p = Builder(_o.Adapter(wireless: true)).Build();
        Assert.Equal(HopRole.AccessPoint, p.Hops[1].Role);
        Assert.Equal(_o.Ap.Mac, p.Hops[1].Mac);
        Assert.Equal(HopProbe.ArpIcmp, p.Hops[1].Probe);
    }

    [Fact]
    public void Upnp_private_wan_adds_double_nat_modem_when_traceroute_misses_it()
    {
        var net = new NetworkState
        {
            InternetPath = [new TracerouteHop(1, IPAddress.Parse("10.40.0.1"), 0.4, null, null), new TracerouteHop(2, IPAddress.Parse("62.1.1.1"), 8, null, null)],
            Wan = new WanInfo(IPAddress.Parse("192.168.178.20"), "Connected", "IP_Routed", null, "OPNsense", "upnp", [], DateTimeOffset.Now),
        };
        var p = Builder(_o.Adapter(), topo: _o.Topology, net: net).Build();
        int modem = p.Hops.ToList().FindIndex(h => h.Role == HopRole.Modem);
        Assert.True(modem > 0);
        Assert.Equal(HopRole.IspHop, p.Hops[modem + 1].Role);
        Assert.Contains("192.168.178.20", p.Hops[modem].Note);
    }

    [Fact]
    public void Only_first_private_hop_after_gateway_is_the_modem()
    {
        // the real trace from the dev network: OPNsense → ISP modem → ISP-internal RFC 1918 routers → TDC → Cloudflare
        var net = new NetworkState
        {
            InternetPath =
            [
                new TracerouteHop(1, IPAddress.Parse("10.40.0.1"), 0.5, null, null),
                new TracerouteHop(2, IPAddress.Parse("10.255.104.1"), 2, null, null),
                new TracerouteHop(3, IPAddress.Parse("10.254.131.228"), 20, null, null),
                new TracerouteHop(4, IPAddress.Parse("10.0.31.85"), 20, null, null),
                new TracerouteHop(5, IPAddress.Parse("87.53.191.249"), 20, "ae30-0.alb2nqp8.dk.ip.tdc.net", null),
            ],
        };
        var p = Builder(_o.Adapter(), net: net).Build();
        var wan = p.Hops.SkipWhile(h => h.Role != HopRole.Firewall).Skip(1).ToList();
        Assert.Equal([HopRole.Modem, HopRole.IspHop, HopRole.IspHop, HopRole.IspHop, HopRole.InternetTarget], wan.Select(h => h.Role).ToArray());
        Assert.Equal(Office.ModemIp, wan[0].Ip);
        Assert.Equal("ISP hop 1 (10.254.131.228)", wan[1].Name);
    }

    [Fact]
    public void Target_comes_from_first_enabled_internet_target()
    {
        _settings.InternetTargets = [new InternetTarget { Name = "off", Host = "8.8.8.8", Enabled = false }, new InternetTarget { Name = "Quad9", Host = "9.9.9.9" }];
        var p = Builder(_o.Adapter()).Build();
        Assert.Equal(IPAddress.Parse("9.9.9.9"), p.Hops[^1].Ip);
        Assert.Equal("Internet (Quad9 9.9.9.9)", p.Hops[^1].Name);
    }
}
