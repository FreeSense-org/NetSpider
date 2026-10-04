using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.PathDoctor;
using static NetSpider.Tests.Unit.Diagnostics.TestNet;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

/// <summary>
/// Synthetic office used by the Path Doctor tests:
/// <code>
/// Internet ─ OPNsense 10.40.0.1 ─ core-sw-01 ─┬─ p5 ─ access-sw ─ p3 ─ this PC 10.40.210.17
///                                              ├─ p7 ─ inferred "TV rack" ─ tv1..tv4
///                                              └─ p9 ─ ap-upstairs ─ (Wi-Fi) phone1..phone3
/// </code>
/// </summary>
internal sealed class Office
{
    public readonly DeviceStore Devices = new();
    public readonly TopologyStore Topology = new();
    public readonly NetworkState Network = new();
    public readonly Device Me, Gw, Core, Access, TvRack, Ap;
    public readonly List<Device> Tvs = [], Phones = [];

    public static readonly IPAddress ModemIp = IPAddress.Parse("10.255.104.1");

    public Office()
    {
        Me = AddDevice(Devices, LocalMac.ToString(), "10.40.210.17", DeviceType.ThisComputer, DeviceFlags.ThisHost, "my-pc");
        Gw = AddDevice(Devices, "00:0D:B9:00:00:01", "10.40.0.1", DeviceType.Firewall, DeviceFlags.Gateway, "OPNsense");
        Core = AddDevice(Devices, "00:1B:21:00:00:01", "10.40.0.2", DeviceType.CoreSwitch, name: "core-sw-01");
        Access = AddDevice(Devices, "00:1B:21:00:00:02", "10.40.0.3", DeviceType.AccessSwitch, name: "access-sw");
        Ap = AddDevice(Devices, "00:27:22:00:00:10", "10.40.0.10", DeviceType.AccessPoint, name: "ap-upstairs");

        TvRack = Devices.GetOrAdd(SyntheticNodes.InferredSwitch(Core.Mac, "7"));
        TvRack.Type = DeviceType.UnmanagedSwitch;
        TvRack.SetFlag(DeviceFlags.Inferred);
        TvRack.SetFlag(DeviceFlags.Infrastructure);
        TvRack.UserLabel = "TV rack";

        var inet = Devices.GetOrAdd(SyntheticNodes.Internet);
        inet.Type = DeviceType.Internet;

        Link(SyntheticNodes.Internet, Gw.Mac, LinkKind.Wan, (Gw.Mac, "WAN"));
        Link(Gw.Mac, Core.Mac, LinkKind.LldpCdp, (Gw.Mac, "igb1"));
        Link(Core.Mac, Access.Mac, LinkKind.LldpCdp, (Core.Mac, "5"));
        Link(Access.Mac, Me.Mac, LinkKind.BridgeFdb, (Access.Mac, "3"));
        Link(Core.Mac, TvRack.Mac, LinkKind.InferredUnmanagedSwitch, (Core.Mac, "7"));
        Link(Core.Mac, Ap.Mac, LinkKind.BridgeFdb, (Core.Mac, "9"));
        for (int i = 1; i <= 4; i++)
        {
            var tv = AddDevice(Devices, $"00:50:B6:00:07:0{i}", $"10.40.7.{i}", DeviceType.Tv, name: $"tv{i}");
            Tvs.Add(tv);
            Link(TvRack.Mac, tv.Mac, LinkKind.InferredUnmanagedSwitch);
        }
        for (int i = 1; i <= 3; i++)
        {
            var ph = AddDevice(Devices, $"00:50:B6:00:09:0{i}", $"10.40.9.{i}", DeviceType.Phone, name: $"phone{i}");
            Phones.Add(ph);
            Link(Ap.Mac, ph.Mac, LinkKind.WifiAssoc);
        }

        Network.InternetPath =
        [
            new TracerouteHop(1, IPAddress.Parse("10.40.0.1"), 0.4, "opnsense", null),
            new TracerouteHop(2, ModemIp, 1.2, null, null),
            new TracerouteHop(3, IPAddress.Parse("62.1.1.1"), 8, "isp-bras", null),
            new TracerouteHop(4, null, null, null, null),
            new TracerouteHop(5, IPAddress.Parse("62.1.2.1"), 9, null, null),
            new TracerouteHop(6, IPAddress.Parse("62.1.3.1"), 10, null, null),
            new TracerouteHop(7, IPAddress.Parse("62.1.4.1"), 11, null, null),
            new TracerouteHop(8, IPAddress.Parse("1.1.1.1"), 12, "one.one.one.one", null),
        ];
    }

    public AdapterInfo Adapter(bool wireless = false) => new()
    {
        Id = "TEST",
        PcapName = "",
        Name = wireless ? "Wi-Fi" : "Ethernet",
        Mac = LocalMac,
        IPv4 = [new IpWithPrefix(IPAddress.Parse("10.40.210.17"), 16)],
        GatewayV4 = IPAddress.Parse("10.40.0.1"),
        IsUp = true,
        IsWireless = wireless,
    };

    private void Link(Mac a, Mac b, LinkKind kind, (Mac Dev, string Port)? port = null) =>
        Topology.Upsert(a, b, kind, l => { if (port is { } p) l.SetPort(p.Dev, p.Port); l.Confidence = kind == LinkKind.GatewayStar ? 0.3 : 0.9; });

    public TopologyTree Tree() => TopologyTree.Build(Topology.Links, Devices.All);

    public void Offline(IEnumerable<Device> ds)
    {
        foreach (var d in ds) d.State = DeviceState.Offline;
    }

    public FaultSnapshot Snapshot(IEnumerable<DiagnosticSignal>? active = null, NetworkPath? path = null, IEnumerable<Device>? unreachable = null) =>
        FaultSnapshot.Create(DateTimeOffset.Now, active, path, unreachable?.Select(d => d.Mac), Tree(), Devices.All);

    public static PathHop Hop(int i, HopRole role, string name, Mac? mac, string? ip, HopHealth health, HopProbe probe = HopProbe.IcmpOnly, double? rtt = null) =>
        new(i, role, name, mac, ip is null ? null : IPAddress.Parse(ip), probe, [], null, health, rtt, null, 0, null, null, null, null, []);

    /// <summary>this PC → access-sw → core-sw-01 → OPNsense → modem → ISP → 1.1.1.1 with the given healths (index 1..6).</summary>
    public NetworkPath Path(params HopHealth[] h)
    {
        var hops = new List<PathHop>
        {
            Hop(0, HopRole.ThisHost, "my-pc", Me.Mac, "10.40.210.17", HopHealth.Up, HopProbe.Self, 0),
            Hop(1, HopRole.Switch, "access-sw", Access.Mac, "10.40.0.3", h[0], HopProbe.ArpIcmp, 0.5),
            Hop(2, HopRole.Switch, "core-sw-01", Core.Mac, "10.40.0.2", h[1], HopProbe.ArpIcmp, 0.6),
            Hop(3, HopRole.Firewall, "OPNsense", Gw.Mac, "10.40.0.1", h[2], HopProbe.ArpIcmp, 0.7),
            Hop(4, HopRole.Modem, "Modem 10.255.104.1", null, "10.255.104.1", h[3], HopProbe.IcmpOnly, 1.5),
            Hop(5, HopRole.IspHop, "isp-bras", null, "62.1.1.1", h[4], HopProbe.IcmpOnly, 8),
            Hop(6, HopRole.InternetTarget, "Internet (Cloudflare 1.1.1.1)", null, "1.1.1.1", h[5], HopProbe.IcmpOnly, 12),
        };
        return new NetworkPath(DateTimeOffset.Now, DateTimeOffset.Now, "Wired", hops);
    }

    public static DiagnosticSignal Sig(SignalKind kind, string summary, Mac? device = null, string? port = null, double weight = 0.5,
        IReadOnlyList<Mac>? affected = null, string source = "test", DateTimeOffset? time = null) =>
        new(time ?? DateTimeOffset.Now, kind, source, summary, device, port, weight, affected);
}
