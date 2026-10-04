using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>Forced demo scenarios (<c>--scenario fault,storm</c>) so screenshots can show a specific state.</summary>
[Flags]
public enum DemoScenario { None = 0, PathFault = 1, Storm = 2, Healthy = 4, Isolation = 8 }

/// <summary>
/// Simulated diagnostics for the demo network: a live hop chain, incidents, switch-port health, storm center, Wi-Fi link
/// telemetry, per-AP health and probe agents. Names and MACs come from <see cref="DemoNetwork"/> so everything lines up
/// with the spider web. Each area implements the real Core interface so the view models can't tell the difference.
/// </summary>
public sealed class DemoDiagnostics : IDisposable
{
    private readonly IDeviceStore _devices;
    private readonly INetworkState _network;
    private readonly AppSettings _settings;
    private readonly object _sync = new();
    private Random _rng = new(7);
    private Timer? _timer;
    private int _t;
    private DateTimeOffset _start;

    public DemoDiagnostics(IDeviceStore devices, INetworkState network, AppSettings settings)
    {
        _devices = devices;
        _network = network;
        _settings = settings;
    }

    public DemoScenario Scenario { get; set; }
    public bool IsRunning => _timer is not null;

    public DemoPathMonitor Path { get; } = new();
    public DemoIncidentService Incidents { get; } = new();
    public DemoPortHealthMonitor Ports { get; } = new();
    public DemoStormCenter Storm { get; } = new();
    public DemoWifiLinkMonitor Wifi { get; } = new();
    public DemoApHealthMonitor Aps { get; } = new();
    public DemoProbeAgentHub Agents { get; } = new();

    /// <summary>Recent diagnostic signals (newest first), as the monitors would publish them on the event bus.</summary>
    public IReadOnlyList<DiagnosticSignal> Signals { get { lock (_sync) return _signals.ToArray(); } }
    private readonly List<DiagnosticSignal> _signals = [];
    public event Action? SignalsChanged;

    // =========================================================================================================
    //  lifecycle
    // =========================================================================================================

    public void Start()
    {
        lock (_sync)
        {
            if (_timer is not null) return;
            Build();
            _timer = new Timer(_ => SafeTick(), null, TimeSpan.FromMilliseconds(400), TimeSpan.FromSeconds(1));
        }
        Path.Rebuilt = () => { lock (_sync) { BuildPath(); TickPath(DateTimeOffset.Now); } Path.Raise(); };
    }

    public void Stop()
    {
        Timer? t;
        lock (_sync)
        {
            t = _timer;
            _timer = null;
        }
        if (t is null) return;
        // wait for a tick that is already running so no demo event fires after the switch back to real data
        using var done = new ManualResetEvent(false);
        try { if (t.Dispose(done)) done.WaitOne(TimeSpan.FromSeconds(2)); }
        catch (ObjectDisposedException) { }
    }

    public void Dispose() => Stop();

    /// <summary>Builds the static parts and prefills history (also used by the headless snapshot mode).</summary>
    public void Build()
    {
        lock (_sync)
        {
            _rng = new Random(7);
            _t = 0;
            _start = DateTimeOffset.Now;
            _signals.Clear();
            BuildPath();
            BuildIncidents();
            BuildStormHistory();
            BuildWifiHistory();
            BuildAgents();
            // prefill ~2 minutes of history so charts aren't empty on the first frame
            var now = DateTimeOffset.Now;
            for (int i = 120; i > 0; i--) { TickPath(now.AddSeconds(-i), prefill: true); TickStorm(now.AddSeconds(-i), prefill: true); }
            _t = 0;
            Step(now);
        }
        RaiseAll();
    }

    private void SafeTick()
    {
        try
        {
            lock (_sync)
            {
                if (_timer is null) return; // stopped meanwhile
                _t++;
                Step(DateTimeOffset.Now);
            }
            RaiseAll();
        }
        catch (Exception ex) { Log.Warning(ex, "Demo diagnostics tick failed"); }
    }

    private void RaiseAll()
    {
        Path.Raise(); Incidents.RaiseAll(); Ports.Raise(); Storm.Raise(); Wifi.Raise(); Aps.Raise(); Agents.Raise();
        SignalsChanged?.Invoke();
    }

    private void Step(DateTimeOffset now)
    {
        TickPath(now);
        TickIncidents(now);
        TickPorts(now);
        TickStorm(now);
        TickWifi(now);
        TickAps(now);
        TickAgents(now);
    }

    private string Name(Mac m, string fallback) => _devices.TryGet(m, out var d) ? d.DisplayName : fallback;

    private double Noise(double sd)
    {
        double u1 = 1 - _rng.NextDouble(), u2 = _rng.NextDouble();
        return sd * Math.Sqrt(-2 * Math.Log(u1)) * Math.Cos(2 * Math.PI * u2);
    }

    private void Signal(SignalKind kind, string source, string summary, Mac? device = null, string? port = null, double weight = 0.5)
    {
        _signals.Insert(0, DiagnosticSignal.Create(kind, source, summary, device, port, weight));
        if (_signals.Count > 60) _signals.RemoveAt(_signals.Count - 1);
    }

    // =========================================================================================================
    //  scenario timeline
    // =========================================================================================================

    private bool PathFaultActive => !Scenario.HasFlag(DemoScenario.Healthy)
        && (Scenario.HasFlag(DemoScenario.PathFault) || _t % 150 is >= 45 and < 80);

    private StormLevel StormPhase =>
        Scenario.HasFlag(DemoScenario.Storm) ? StormLevel.Storm
        : Scenario.HasFlag(DemoScenario.Healthy) ? StormLevel.Normal
        : _t % 200 is >= 100 and < 112 ? StormLevel.Storm
        : _t % 70 is >= 20 and < 30 ? StormLevel.Elevated : StormLevel.Normal;

    // =========================================================================================================
    //  path
    // =========================================================================================================

    private sealed class HopSim
    {
        public required HopRole Role;
        public required string Name;
        public Mac? Mac;
        public IPAddress? Ip;
        public HopProbe Probe;
        public string? PortIn;
        public double Base;
        public double Jitter;
        public string? Note;
        public readonly List<double?> Recent = [];
        public double? Last;
        public bool? Arp;
        public bool? Icmp;
    }

    private readonly List<HopSim> _hops = [];
    private DateTimeOffset _pathBuilt;

    private void BuildPath()
    {
        _pathBuilt = DateTimeOffset.Now;
        _hops.Clear();
        void H(HopRole role, string name, Mac? mac, string? ip, HopProbe probe, string? portIn, double rtt, double jitter, string? note) =>
            _hops.Add(new HopSim
            {
                Role = role, Name = name, Mac = mac, Ip = ip is null ? null : IPAddress.Parse(ip), Probe = probe, PortIn = portIn,
                Base = rtt, Jitter = jitter, Note = note,
            });
        H(HopRole.ThisHost, Name(DemoNetwork.ThisHostMac, "SPIDER-WS"), DemoNetwork.ThisHostMac, "192.168.1.50", HopProbe.Self, null, 0, 0,
            "Ethernet · 1 Gbps full duplex");
        H(HopRole.Switch, Name(DemoNetwork.AccessMac, "usw-lite-office"), DemoNetwork.AccessMac, "192.168.1.3", HopProbe.ArpIcmp, "Port 4", 0.34, 0.05,
            "Access switch · uplink Port 8 → core g21");
        H(HopRole.Switch, Name(DemoNetwork.CoreMac, "core-sw-01"), DemoNetwork.CoreMac, "192.168.1.2", HopProbe.ArpIcmp, "g21", 0.52, 0.06,
            "Core switch · STP root");
        H(HopRole.Router, Name(DemoNetwork.GatewayMac, "UDM-Pro"), DemoNetwork.GatewayMac, "192.168.1.1", HopProbe.ArpIcmp, "SFP+ 1", 0.71, 0.08,
            "Gateway · NAT · WAN eth9");
        H(HopRole.Modem, "ISP modem", null, "192.168.100.1", HopProbe.IcmpOnly, "LAN 1", 1.9, 0.25,
            "Bridge mode · via traceroute + UPnP IGD");
        H(HopRole.IspHop, "cpe-gw.isp.example.net", null, "84.212.32.1", HopProbe.IcmpOnly, null, 4.1, 0.7, "ISP hop 1 · first hop beyond the modem");
        H(HopRole.IspHop, "ae2-osl-core1.isp.example.net", null, "195.159.5.33", HopProbe.IcmpOnly, null, 6.3, 0.9, "ISP hop 2 · Oslo core");
        H(HopRole.InternetTarget, "one.one.one.one", null, "1.1.1.1", HopProbe.IcmpOnly, null, 9.6, 1.1, "Cloudflare DNS");
    }

    private void TickPath(DateTimeOffset now, bool prefill = false)
    {
        bool fault = !prefill && PathFaultActive;
        for (int i = 0; i < _hops.Count; i++)
        {
            var h = _hops[i];
            double? v;
            if (h.Role == HopRole.ThisHost) v = 0.02;
            else if (fault && i >= 4) v = null;
            else
            {
                double spike = h.Role is HopRole.IspHop or HopRole.InternetTarget && _rng.NextDouble() < 0.04 ? _rng.Next(6, 28) : 0;
                double loss = h.Role is HopRole.IspHop ? 0.006 : h.Role == HopRole.InternetTarget ? 0.004 : 0.001;
                v = _rng.NextDouble() < loss ? null : Math.Round(Math.Max(h.Base * 0.6, h.Base + Math.Abs(Noise(h.Jitter)) + spike), 3);
            }
            h.Recent.Add(v);
            if (h.Recent.Count > 300) h.Recent.RemoveAt(0);
            h.Last = v;
            h.Icmp = h.Role == HopRole.ThisHost ? null : v is not null;
            h.Arp = h.Probe == HopProbe.ArpIcmp ? true : null;
        }
        if (prefill) return;

        int downRounds = Math.Max(1, _settings.HopDownRounds);
        var built = new List<PathHop>();
        double? prevRtt = 0;
        for (int i = 0; i < _hops.Count; i++)
        {
            var h = _hops[i];
            var window = h.Recent.TakeLast(30).ToList();
            double lossPct = window.Count == 0 ? 0 : 100.0 * window.Count(x => x is null) / window.Count;
            var vals = window.Where(x => x is not null).Select(x => x!.Value).ToList();
            double? jitter = vals.Count > 2 ? vals.Zip(vals.Skip(1), (a, b) => Math.Abs(a - b)).Average() : null;
            bool down = h.Recent.Count >= downRounds && h.Recent.TakeLast(downRounds).All(x => x is null);
            var health = h.Role == HopRole.ThisHost ? HopHealth.Up
                : down ? HopHealth.Down
                : lossPct >= 5 || h.Last > h.Base * 3 + 6 ? HopHealth.Degraded : HopHealth.Up;
            double? rtt = down ? null : h.Last ?? vals.LastOrDefault();
            double? added = rtt is { } r && prevRtt is { } p ? Math.Max(0, r - p) : null;
            if (rtt is not null && health != HopHealth.Down) prevRtt = rtt;
            string? note = h.Note;
            if (down && i == 4) note = $"No reply for {downRounds * 2 + _rng.Next(0, 6)} s — UDM-Pro still answers";
            else if (down) note = "Unreachable (beyond the fault)";
            else if (health == HopHealth.Degraded && h.Role is HopRole.IspHop or HopRole.InternetTarget) note = $"Latency spikes · {h.Note}";
            built.Add(new PathHop(i, h.Role, h.Name, h.Mac, h.Ip, h.Probe, [], h.PortIn, health, rtt, h.Role == HopRole.ThisHost ? null : added,
                Math.Round(lossPct, 1), jitter is { } j ? Math.Round(j, 2) : null, h.Arp, down ? false : h.Icmp, note,
                h.Recent.TakeLast(120).ToArray()));
        }
        Path.Current = new NetworkPath(_pathBuilt, now, "Wired", built);
    }

    // =========================================================================================================
    //  incidents
    // =========================================================================================================

    private Guid _faultIncident;

    private static readonly Mac Xbox = Mac.Parse("98:5F:D3:21:7C:44");
    private static readonly Mac Tv = Mac.Parse("8C:79:F5:0D:6E:19");
    private static readonly Mac AppleTv = Mac.Parse("F0:B3:EC:12:88:5A");
    private static readonly Mac HpPrinter = Mac.Parse("3C:52:82:7B:19:E0");
    private static readonly Mac ShellyGarage = Mac.Parse("E8:68:E7:B1:0C:94");
    private static readonly Mac MiasPhone = Mac.Parse("F2:6C:3D:A1:B7:5E");

    private static string Pcap(DateTimeOffset t, string tag) =>
        System.IO.Path.Combine(AppPaths.Root, "captures", $"{tag}-{t:yyyyMMdd-HHmmss}.pcapng");

    private void BuildIncidents()
    {
        var now = DateTimeOffset.Now;
        _faultIncident = Guid.Empty;
        string tvRack = Name(DemoNetwork.InferredMac, "Inferred switch · TV rack");
        var list = new List<Incident>
        {
            new(Guid.NewGuid(), now.AddMinutes(-4).AddSeconds(-12), null, AlertSeverity.Critical, IncidentCategory.LocalNetwork,
                "3 devices unreachable behind the TV rack",
                "Inferred switch 'TV rack' or its uplink to core-sw-01 port 7 — 3 devices unreachable",
                0.78, DemoNetwork.InferredMac, "g7", "core-sw-01 g7 ↔ TV rack",
                [Xbox, Tv, AppleTv],
                [
                    $"{Name(Xbox, "XBOX-LIVINGROOM")}, {Name(Tv, "Samsung TV")} and {Name(AppleTv, "Apple TV")} stopped answering ARP within 4 s of each other",
                    "Their lowest common ancestor is the inferred unmanaged switch on core-sw-01 g7",
                    "core-sw-01 itself still answers (0.5 ms) — the fault is below it",
                    "core-sw-01 g7 flapped 3× in the last hour (ifLastChange moved)",
                    "No STP topology change or loop seen at the time",
                ],
                Pcap(now.AddMinutes(-4), "incident-tv-rack")),
            new(Guid.NewGuid(), now.AddMinutes(-52), now.AddMinutes(-46), AlertSeverity.Warning, IncidentCategory.SwitchPort,
                "CRC errors on core-sw-01 g8",
                $"Cable or NIC on core-sw-01 port g8 ({Name(HpPrinter, "HP printer")}) — FCS errors rising 42/min",
                0.9, HpPrinter, "g8", "core-sw-01 g8 ↔ HP-LaserJet-M454", [HpPrinter],
                ["dot3StatsFCSErrors +2 480 in 60 s on g8", "ifInErrors rising, ifOutErrors flat → receive side (cable/NIC)", "Port negotiated 100 Mbps full duplex"],
                null),
            new(Guid.NewGuid(), now.AddMinutes(-111), now.AddMinutes(-109), AlertSeverity.Critical, IncidentCategory.Storm,
                "Broadcast storm — ARP flood from a Shelly relay",
                $"{Name(ShellyGarage, "shellyplus1pm-garage")} on ap-upstairs (core-sw-01 g2) sent 4 100 ARP/s for 94 s",
                0.88, ShellyGarage, "g2", "core-sw-01 g2 ↔ ap-upstairs", [ShellyGarage],
                ["Broadcast 4 360 pps vs baseline 55 pps (×79)", "92 % ARP who-has for 192.168.20.0/24 from one MAC", "Ingress: core-sw-01 g2 (ifInBroadcastPkts)"],
                Pcap(now.AddMinutes(-111), "storm")),
            new(Guid.NewGuid(), now.AddHours(-3).AddMinutes(-8), now.AddHours(-3).AddMinutes(-4), AlertSeverity.Warning, IncidentCategory.Wifi,
                "Wi-Fi clients on ap-upstairs unreachable",
                "ap-upstairs radio (5 GHz) — 7 of 7 clients unreachable while its management IP answered",
                0.72, DemoNetwork.Ap2Mac, null, "ap-upstairs radio", [MiasPhone],
                ["Management IP 192.168.1.5 answered throughout (0.6 ms)", "All 7 associated clients failed ARP + ICMP", "Clients on ap-living-room unaffected"],
                null),
            new(Guid.NewGuid(), now.AddDays(-1).Date.AddHours(22).AddMinutes(14), now.AddDays(-1).Date.AddHours(22).AddMinutes(25), AlertSeverity.Critical, IncidentCategory.Isp,
                "Internet unreachable — ISP",
                "ISP — first hop beyond the modem (84.212.32.1) stopped answering; the modem answered throughout",
                0.85, null, null, "ISP modem → cpe-gw.isp.example.net", [DemoNetwork.InternetMac],
                ["UDM-Pro and ISP modem answered (0.7 / 1.9 ms)", "cpe-gw.isp.example.net and every target beyond it: 100 % loss", "All 3 internet monitor targets down for 11 min"],
                Pcap(now.AddDays(-1).Date.AddHours(22).AddMinutes(14), "incident-isp")),
            new(Guid.NewGuid(), now.AddDays(-1).Date.AddHours(9).AddMinutes(41), now.AddDays(-1).Date.AddHours(9).AddMinutes(41).AddSeconds(38), AlertSeverity.Warning, IncidentCategory.OwnLink,
                "This PC's own link went down",
                "Your own cable/port: Ethernet link down on SPIDER-WS (media disconnected) — not a network fault",
                0.97, DemoNetwork.ThisHostMac, "Ethernet", "SPIDER-WS ↔ usw-lite-office Port 4", [],
                ["NotifyIpInterfaceChange: Ethernet operational status → down", "Every probe failed simultaneously", "Link came back at 1 Gbps after 38 s"],
                null),
        };
        Incidents.Set(list);
    }

    private void TickIncidents(DateTimeOffset now)
    {
        bool fault = PathFaultActive && _hops.Count > 4 && _hops[4].Recent.TakeLast(Math.Max(1, _settings.HopDownRounds)).All(x => x is null);
        if (fault && _faultIncident == Guid.Empty)
        {
            _faultIncident = Guid.NewGuid();
            var inc = new Incident(_faultIncident, now.AddSeconds(-Math.Max(1, _settings.HopDownRounds) * 2), null, AlertSeverity.Critical, IncidentCategory.Modem,
                "ISP modem not answering",
                "ISP modem or its link from UDM-Pro WAN (eth9) — UDM-Pro answers but the modem and everything beyond it stopped replying",
                0.84, DemoNetwork.InternetMac, "WAN (eth9)", "UDM-Pro WAN (eth9) → ISP modem", [DemoNetwork.InternetMac],
                ["UDM-Pro (192.168.1.1) answers ARP + ICMP (0.7 ms)", "ISP modem 192.168.100.1: no ICMP reply for 3 rounds",
                 "ISP hops and 1.1.1.1 unreachable from the same moment", "UDM-Pro WAN link speed unchanged (1 Gbps) per SNMP"],
                Pcap(now, "incident-modem"));
            Incidents.Upsert(inc);
            Signal(SignalKind.HopDown, "PathMonitor", "ISP modem 192.168.100.1 stopped answering ICMP (3 rounds)", null, "WAN (eth9)", 0.85);
            Signal(SignalKind.InternetDown, "InternetMonitor", "All internet targets down");
        }
        else if (!fault && _faultIncident != Guid.Empty)
        {
            if (Incidents.Find(_faultIncident) is { } open) Incidents.Upsert(open with { End = now });
            _faultIncident = Guid.Empty;
            Signal(SignalKind.HopUp, "PathMonitor", "ISP modem 192.168.100.1 answers again", null, null, 0.2);
            Signal(SignalKind.InternetUp, "InternetMonitor", "Internet reachable again");
        }

        // background chatter
        if (_t % 17 == 3) Signal(SignalKind.PortErrors, "PortHealthMonitor", "core-sw-01 g8: FCS errors +38 in 60 s", HpPrinter, "g8", 0.6);
        if (_t % 23 == 9) Signal(SignalKind.HopDegraded, "PathMonitor", "cpe-gw.isp.example.net latency spike 27 ms (+23 ms)", null, null, 0.3);
        if (_t % 29 == 14) Signal(SignalKind.WifiRoamed, "WifiLinkMonitor", "Roamed ap-upstairs → ap-living-room (RSSI −74 → −56 dBm)", DemoNetwork.Ap1Mac, null, 0.1);
        if (_t % 41 == 20) Signal(SignalKind.DevicesUnreachable, "FaultLocator", "3 devices behind core-sw-01 g7 still unreachable", DemoNetwork.InferredMac, "g7", 0.78);
        if (_t % 37 == 5) Signal(SignalKind.ApDegraded, "ApHealthMonitor", "ap-upstairs: client loss 6.5 % (RF?)", DemoNetwork.Ap2Mac, null, 0.4);
        if (_t == 1)
        {
            Signal(SignalKind.PortFlapping, "PortHealthMonitor", "core-sw-01 g7 link flapped (3× in the last hour)", DemoNetwork.CoreMac, "g7", 0.6);
            Signal(SignalKind.DevicesUnreachable, "FaultLocator", "XBOX-LIVINGROOM, Samsung S95C, Living-Room-Apple-TV unreachable", DemoNetwork.InferredMac, "g7", 0.78);
        }
    }

    // =========================================================================================================
    //  switch ports
    // =========================================================================================================

    private void TickPorts(DateTimeOffset now)
    {
        var list = new List<PortHealth>();
        var ports = _network.SwitchPorts;
        string? downgraded = ports.Where(p => p.Switch == DemoNetwork.AccessMac && p.Up == true && p.Name is not ("Port 8" or "Port 4"))
            .Select(p => p.Name).FirstOrDefault();
        foreach (var p in ports)
        {
            bool up = p.Up == true;
            bool uplink = p.Alias == "Uplink" || p.Name is "g21" or "g24" or "Port 8";
            double scale = uplink ? 60e6 : 2e6;
            double inBps = up ? Math.Abs(scale * (0.4 + _rng.NextDouble())) : 0;
            double outBps = up ? Math.Abs(scale * (0.3 + _rng.NextDouble() * 0.8)) : 0;
            double bc = up ? 0.6 + _rng.NextDouble() * 2.5 : 0, mc = up ? 2 + _rng.NextDouble() * 8 : 0;
            double err = 0, fcs = 0;
            int flaps = 0;
            bool dupSuspect = false, downgradedSpeed = false;
            string? problem = null;
            var health = up ? HopHealth.Up : HopHealth.Unknown;
            long? speed = p.SpeedMbps;
            string? duplex = p.Duplex;
            if (p.Switch == DemoNetwork.CoreMac && p.Name == "g8")
            {
                fcs = 0.62 + _rng.NextDouble() * 0.2; err = fcs + 0.04;
                problem = $"CRC/FCS errors rising — {fcs * 60:0}/min (bad cable or NIC)";
                health = HopHealth.Degraded;
            }
            else if (p.Switch == DemoNetwork.CoreMac && p.Name == "g7")
            {
                flaps = 3;
                err = 0.05;
                problem = "Link flapped 3× in the last hour";
                health = HopHealth.Degraded;
                inBps *= 0.05; outBps *= 0.05;
            }
            else if (p.Switch == DemoNetwork.AccessMac && p.Name == downgraded)
            {
                downgradedSpeed = true; dupSuspect = true;
                speed = 100; duplex = "half";
                err = 0.02;
                problem = "Speed downgraded 1G → 100M, late collisions (duplex mismatch?)";
                health = HopHealth.Degraded;
            }
            var st = StormPhase;
            if (st != StormLevel.Normal && p.Switch == DemoNetwork.CoreMac && p.Name == "g2")
                bc = st == StormLevel.Storm ? 4100 + _rng.Next(0, 300) : 380 + _rng.Next(0, 80);
            list.Add(new PortHealth(p.Switch, p.Index, p.Name, up, speed, duplex, inBps, outBps, err, err * 0.2, fcs, bc, mc,
                flaps, dupSuspect, downgradedSpeed, problem, health, now));
        }
        Ports.Current = list;
    }

    // =========================================================================================================
    //  storm center
    // =========================================================================================================

    private static readonly string[] Protocols = ["ARP", "mDNS", "SSDP", "DHCP", "NetBIOS", "IPv6 ND", "LLDP", "STP", "IGMP"];
    private static readonly double[] ProtoBase = [24, 70, 95, 4, 6, 18, 1.2, 1.0, 3];
    private DateTimeOffset? _stormStart;
    private double _stormPeak;

    private void BuildStormHistory()
    {
        var now = DateTimeOffset.Now;
        _stormStart = null;
        Storm.SetHistory(
        [
            new StormEvent(now.AddMinutes(-111), now.AddMinutes(-109).AddSeconds(-26), StormLevel.Storm, 4360, "ARP",
                $"ARP flood from {Name(ShellyGarage, "shellyplus1pm-garage")} (core-sw-01 g2 via ap-upstairs) — ×79 baseline", Pcap(now.AddMinutes(-111), "storm")),
            new StormEvent(now.AddHours(-5).AddMinutes(-3), now.AddHours(-5), StormLevel.Elevated, 820, "SSDP",
                "SSDP M-SEARCH burst from Samsung S95C — Living Room (behind TV rack, core-sw-01 g7)", null),
            new StormEvent(now.AddDays(-2).AddHours(-1), now.AddDays(-2).AddHours(-1).AddMinutes(6), StormLevel.Storm, 18900, "ARP",
                "Layer-2 loop: duplicate frames on core-sw-01 g5 and g9 (STP disabled on a desk switch)", Pcap(now.AddDays(-2).AddHours(-1), "loop")),
        ]);
    }

    private void TickStorm(DateTimeOffset now, bool prefill = false)
    {
        var level = prefill ? StormLevel.Normal : StormPhase;
        double mult = level switch { StormLevel.Storm => 1, StormLevel.Elevated => 1, _ => 1 };
        var byProto = new Dictionary<string, double>();
        for (int i = 0; i < Protocols.Length; i++)
            byProto[Protocols[i]] = Math.Round(Math.Max(0, ProtoBase[i] * mult * (0.75 + _rng.NextDouble() * 0.5)), 1);
        if (level == StormLevel.Elevated) { byProto["SSDP"] += 420 + _rng.Next(0, 160); byProto["ARP"] += 60; }
        if (level == StormLevel.Storm) { byProto["ARP"] += 3900 + _rng.Next(0, 700); byProto["IPv6 ND"] += 120; }

        double bc = byProto["ARP"] + byProto["DHCP"] + byProto["NetBIOS"] * 0.8 + 6 + _rng.NextDouble() * 6;
        double mc = byProto["mDNS"] + byProto["SSDP"] + byProto["IPv6 ND"] + byProto["LLDP"] + byProto["STP"] + byProto["IGMP"];
        double uu = 2 + _rng.NextDouble() * 4 + (level == StormLevel.Storm ? 160 + _rng.Next(0, 60) : 0);
        double total = bc + mc + uu + 2400 + _rng.Next(0, 900);
        Storm.Push(now, bc, mc, uu);
        if (prefill) return;

        var sources = new List<StormSource>();
        void Src(Mac m, string fallback, double pps, double bcp, double mcp, string proto, Mac? sw, string? port, string location) =>
            sources.Add(new StormSource(m, Name(m, fallback), Math.Round(pps, 1), Math.Round(bcp, 1), Math.Round(mcp, 1), proto,
                sw, sw is { } s ? Name(s, "switch") : null, port, location));
        if (level == StormLevel.Storm)
            Src(ShellyGarage, "shellyplus1pm-garage", byProto["ARP"] * 0.93, byProto["ARP"] * 0.93, 0, "ARP", DemoNetwork.CoreMac, "g2",
                "core-sw-01 g2 → ap-upstairs (Wi-Fi client)");
        Src(Tv, "Samsung TV", level == StormLevel.Elevated ? byProto["SSDP"] * 0.9 : 38 + _rng.NextDouble() * 9, 0.4,
            level == StormLevel.Elevated ? byProto["SSDP"] * 0.9 : 38, "SSDP", DemoNetwork.CoreMac, "g7", "core-sw-01 g7 → behind inferred switch 'TV rack'");
        Src(Mac.Parse("5C:AA:FD:7B:12:40"), "Sonos Arc", 22 + _rng.NextDouble() * 5, 0.2, 22, "SSDP", DemoNetwork.CoreMac, "g1", "core-sw-01 g1 → ap-living-room (Wi-Fi)");
        Src(Mac.Parse("00:17:88:6B:22:E1"), "Hue Bridge", 14 + _rng.NextDouble() * 4, 0.5, 14, "mDNS", DemoNetwork.CoreMac, "g12", "core-sw-01 g12");
        Src(DemoNetwork.GatewayMac, "UDM-Pro", 9 + _rng.NextDouble() * 3, 7.5, 1.5, "ARP", DemoNetwork.CoreMac, "g24", "core-sw-01 g24 (uplink to gateway)");
        Src(HpPrinter, "HP printer", 5 + _rng.NextDouble() * 2, 1.2, 4, "mDNS", DemoNetwork.CoreMac, "g8", "core-sw-01 g8");

        var ingress = new List<StormIngress>();
        if (level == StormLevel.Storm)
            ingress.Add(new StormIngress(DemoNetwork.CoreMac, "core-sw-01", "g2", Math.Round(byProto["ARP"] * 0.95), 30, "ap-upstairs uplink — storm enters here"));
        ingress.Add(new StormIngress(DemoNetwork.CoreMac, "core-sw-01", "g7", level == StormLevel.Elevated ? 18 : 6, level == StormLevel.Elevated ? Math.Round(byProto["SSDP"] * 0.9) : 46, "Inferred switch 'TV rack'"));
        ingress.Add(new StormIngress(DemoNetwork.CoreMac, "core-sw-01", "g1", 4, 31, "ap-living-room"));
        ingress.Add(new StormIngress(DemoNetwork.CoreMac, "core-sw-01", "g24", 9, 6, "Uplink to UDM-Pro"));

        var loops = new List<LoopSuspect>();
        if (level == StormLevel.Storm)
            loops.Add(new LoopSuspect("Same MAC seen on core-sw-01 g2 and g7 within 2 s — possible loop through the TV rack switch",
                DemoNetwork.CoreMac, ["g2", "g7"], [ShellyGarage], 0.41, now));

        if (level != StormLevel.Normal)
        {
            _stormStart ??= now;
            _stormPeak = Math.Max(_stormPeak, bc + mc);
        }
        else if (_stormStart is { } s)
        {
            var dom = _stormPeak > 3000 ? "ARP" : "SSDP";
            Storm.AddHistory(new StormEvent(s, now, _stormPeak > 3000 ? StormLevel.Storm : StormLevel.Elevated, Math.Round(_stormPeak), dom,
                _stormPeak > 3000 ? $"ARP flood from {Name(ShellyGarage, "shellyplus1pm-garage")} (core-sw-01 g2)" : "SSDP burst from Samsung S95C (TV rack, core-sw-01 g7)",
                _stormPeak > 3000 ? Pcap(s, "storm") : null));
            Signal(SignalKind.StormEnded, "StormCenter", $"{dom} storm ended after {(now - s).TotalSeconds:0} s (peak {_stormPeak:0} pps)");
            _stormStart = null;
            _stormPeak = 0;
        }
        if (level == StormLevel.Storm && _stormStart == now)
            Signal(SignalKind.StormDetected, "StormCenter", "ARP broadcast storm from shellyplus1pm-garage (core-sw-01 g2)", ShellyGarage, "g2", 0.85);

        Storm.Status = new StormStatus(now, level, Math.Round(bc, 1), Math.Round(mc, 1), Math.Round(uu, 1), Math.Round(total), 55, 230,
            byProto, sources.OrderByDescending(x => x.Pps).ToList(), ingress.OrderByDescending(x => x.BroadcastPps + x.MulticastPps).ToList(), loops);
    }

    // =========================================================================================================
    //  Wi-Fi link + APs
    // =========================================================================================================

    private Mac _bssid;
    private int _rssi = -57;

    private void BuildWifiHistory()
    {
        var now = DateTimeOffset.Now;
        _bssid = DemoNetwork.Ap1Mac.Offset(2);
        var hist = new List<WifiLinkSample>();
        for (int i = 300; i > 0; i--) hist.Add(WifiSample(now.AddSeconds(-i), i));
        Wifi.SetHistory(hist);
        Wifi.SetEvents(
        [
            new WifiEvent(now.AddHours(-2).AddMinutes(-14), "Disconnected", "SpiderNet", DemoNetwork.Ap2Mac.Offset(2),
                "Reason 4: disassociated due to inactivity (AP)"),
            new WifiEvent(now.AddHours(-2).AddMinutes(-14).AddSeconds(3), "AuthFailed", "SpiderNet", DemoNetwork.Ap2Mac.Offset(2),
                "4-way handshake timeout (wrong PSK or interference)"),
            new WifiEvent(now.AddHours(-2).AddMinutes(-13).AddSeconds(51), "Connected", "SpiderNet", DemoNetwork.Ap2Mac.Offset(2), "802.11ax · 5 GHz ch 149"),
            new WifiEvent(now.AddMinutes(-38), "Roamed", "SpiderNet", DemoNetwork.Ap1Mac.Offset(2), "ap-upstairs → ap-living-room · RSSI −74 → −56 dBm"),
            new WifiEvent(now.AddMinutes(-12), "SignalWeak", "SpiderNet", DemoNetwork.Ap1Mac.Offset(2), "RSSI −78 dBm for 20 s (microwave on ch 1?)"),
            new WifiEvent(now.AddMinutes(-11).AddSeconds(-40), "SignalRecovered", "SpiderNet", DemoNetwork.Ap1Mac.Offset(2), "RSSI back to −58 dBm"),
        ]);
    }

    private WifiLinkSample WifiSample(DateTimeOffset t, int seed)
    {
        // slow drift + occasional dips
        double drift = 4 * Math.Sin(seed / 37.0) + 2 * Math.Sin(seed / 11.0);
        _rssi = (int)Math.Round(-58 + drift + Noise(1.2) - (seed % 97 is >= 40 and < 46 ? 13 : 0));
        int q = Math.Clamp(2 * (_rssi + 100), 0, 100);
        double rate = _rssi > -60 ? 1201 : _rssi > -67 ? 864.6 : _rssi > -72 ? 576 : 288;
        double apRtt = Math.Round(1.6 + Math.Abs(Noise(0.7)) + (_rssi < -70 ? _rng.Next(4, 18) : 0), 2);
        double gwRtt = Math.Round(apRtt + 0.6 + Math.Abs(Noise(0.25)), 2);
        bool lost = _rng.NextDouble() < (_rssi < -70 ? 0.08 : 0.004);
        return new WifiLinkSample(t, true, "SpiderNet", _bssid, 36, "5 GHz", _rssi, q, rate, Math.Round(rate * 0.92, 1), "802.11ax",
            lost ? null : apRtt, lost ? null : gwRtt);
    }

    private void TickWifi(DateTimeOffset now)
    {
        var s = WifiSample(now, (int)(now - _start).TotalSeconds + 300);
        Wifi.Add(s);
    }

    private void TickAps(DateTimeOffset now)
    {
        var all = _devices.All;
        int Clients(Mac ap) => all.Count(d => d.UpstreamMac == ap);
        int c1 = Math.Max(1, Clients(DemoNetwork.Ap1Mac)), c2 = Math.Max(1, Clients(DemoNetwork.Ap2Mac));
        double loss2 = 5.5 + _rng.NextDouble() * 2;
        Aps.Current =
        [
            new ApHealth(DemoNetwork.Ap1Mac, Name(DemoNetwork.Ap1Mac, "ap-living-room"), IPAddress.Parse("192.168.1.4"), true, Math.Round(0.55 + _rng.NextDouble() * 0.2, 2),
                c1, c1, Math.Round(3.1 + Noise(0.4), 1), Math.Round(_rng.NextDouble() * 0.6, 1), HopHealth.Up, null, now),
            new ApHealth(DemoNetwork.Ap2Mac, Name(DemoNetwork.Ap2Mac, "ap-upstairs"), IPAddress.Parse("192.168.1.5"), true, Math.Round(0.6 + _rng.NextDouble() * 0.2, 2),
                c2, Math.Max(0, c2 - 1), Math.Round(17.5 + Noise(3), 1), Math.Round(loss2, 1), HopHealth.Degraded,
                FormattableString.Invariant($"Clients reachable but high loss ({loss2:0.#} %) — RF interference? 2.4 GHz ch 11 overlaps a neighbour; Shelly Plus 1PM at −79 dBm"), now),
        ];
    }

    // =========================================================================================================
    //  probe agents
    // =========================================================================================================

    private void BuildAgents() => TickAgents(DateTimeOffset.Now);

    private void TickAgents(DateTimeOffset now)
    {
        bool fault = PathFaultActive;
        ProbeTargetResult R(string target, string ip, double ms, double loss) =>
            fault && target is "1.1.1.1" or "ISP modem"
                ? new ProbeTargetResult(target, ip, null, null, 100, 30, "timeout")
                : new ProbeTargetResult(target, ip, Math.Round(ms + Math.Abs(Noise(ms * 0.15)), 2), Math.Round(ms * 1.05, 2), loss, 30, null);
        ProbeAgentReport Rep(string id, string host, string ip, string mac, string medium, IReadOnlyList<ProbeTargetResult> res, WifiLinkSample? wifi) =>
            new(id, host, ip, mac, medium, now, res, wifi, "192.168.1.1", "1.0.0");
        var mbp = Rep("agent-mbp", "Alex-MBP", "192.168.1.110", "F8:4D:89:5A:23:C7", "Wi-Fi",
            [R("UDM-Pro", "192.168.1.1", 2.4, 0), R("SPIDER-WS", "192.168.1.50", 2.9, 0), R("ISP modem", "192.168.100.1", 3.8, 0), R("1.1.1.1", "1.1.1.1", 11.6, 0.0)],
            new WifiLinkSample(now, true, "SpiderNet", DemoNetwork.Ap1Mac.Offset(2), 36, "5 GHz", -46 + _rng.Next(-2, 3), 100, 1201, 1080, "802.11ax", 1.4, 2.3));
        var pi = Rep("agent-pi", "pi-probe", "192.168.1.40", "DC:A6:32:5E:0B:7F", "Wired",
            [R("UDM-Pro", "192.168.1.1", 0.42, 0), R("Alex-iPhone", "192.168.1.101", 6.8, 1.2), R("ISP modem", "192.168.100.1", 1.7, 0), R("1.1.1.1", "1.1.1.1", 9.4, 0)], null);
        // built-in "local:" agents: this PC's wired and Wi-Fi adapters probing each other (dual-interface self-test)
        bool isolation = Scenario.HasFlag(DemoScenario.Isolation) || (!Scenario.HasFlag(DemoScenario.Healthy) && _t % 120 is >= 85 and < 115);
        ProbeTargetResult Cross(string target, string ip, double ms) => isolation
            ? new ProbeTargetResult(target, ip, null, null, 100, 30, "timeout (no ARP reply)")
            : R(target, ip, ms, 0);
        var wifiNow = Wifi.Current;
        var localWired = Rep("local:eth", "This PC (Ethernet)", "192.168.1.50", "D8:BB:C1:7A:3F:10", "Wired",
            [R("Gateway", "192.168.1.1", 0.7, 0), R("Wi-Fi gateway", "192.168.1.1", 0.7, 0), Cross("Other adapter", "192.168.1.150", 3.4), R("1.1.1.1", "1.1.1.1", 9.6, 0)], null);
        var localWifi = Rep("local:wlan", "This PC (Wi-Fi)", "192.168.1.150", "D8:BB:C1:7A:3F:11", "Wi-Fi",
            [R("Gateway", "192.168.1.1", 2.6, 0.3), R("Wired gateway", "192.168.1.1", 2.6, 0.3), Cross("Other adapter", "192.168.1.50", 3.1), R("1.1.1.1", "1.1.1.1", 12.1, 0.3)], wifiNow);
        Agents.Current =
        [
            new ProbeAgentInfo("local:eth", "This PC (Ethernet)", "192.168.1.50", "D8:BB:C1:7A:3F:10", "Wired", now, true, localWired),
            new ProbeAgentInfo("local:wlan", "This PC (Wi-Fi)", "192.168.1.150", "D8:BB:C1:7A:3F:11", "Wi-Fi", now, true, localWifi),
            new ProbeAgentInfo("agent-mbp", "Alex-MBP", "192.168.1.110", "F8:4D:89:5A:23:C7", "Wi-Fi", now.AddSeconds(-_rng.Next(0, 3)), true, mbp),
            new ProbeAgentInfo("agent-pi", "pi-probe", "192.168.1.40", "DC:A6:32:5E:0B:7F", "Wired", now.AddSeconds(-_rng.Next(0, 3)), true, pi),
            new ProbeAgentInfo("agent-garage", "garage-pi", "192.168.20.60", null, "Wi-Fi", now.AddHours(-2).AddMinutes(-7), false, null),
        ];
    }

    // =========================================================================================================
    //  interface implementations (state holders)
    // =========================================================================================================

    public sealed class DemoPathMonitor : IPathMonitor
    {
        public bool IsRunning => true;
        public NetworkPath? Path => Current;
        public NetworkPath? Current { get; set; }
        internal Action? Rebuilt;
        public void Rebuild() => Rebuilt?.Invoke();
        public event Action<NetworkPath>? Updated;
        internal void Raise() { if (Current is { } p) Updated?.Invoke(p); }
    }

    public sealed class DemoIncidentService : IIncidentService
    {
        private readonly object _l = new();
        private List<Incident> _list = [];
        private readonly List<Incident> _changed = [];
        public IReadOnlyList<Incident> Incidents { get { lock (_l) return _list.ToArray(); } }
        public IReadOnlyList<Incident> Active { get { lock (_l) return _list.Where(i => i.Ongoing).ToArray(); } }
        public void Clear() { lock (_l) { _list = _list.Where(i => i.Ongoing).ToList(); _changed.Add(_list.FirstOrDefault() ?? Dummy); } }
        public event Action<Incident>? IncidentChanged;
        private static readonly Incident Dummy = new(Guid.Empty, DateTimeOffset.MinValue, DateTimeOffset.MinValue, AlertSeverity.Info, IncidentCategory.Unknown, "", "", 0, null, null, null, [], [], null);
        internal void Set(List<Incident> list) { lock (_l) { _list = list; _changed.AddRange(list); } }
        internal Incident? Find(Guid id) { lock (_l) return _list.FirstOrDefault(i => i.Id == id); }
        internal void Upsert(Incident inc)
        {
            lock (_l)
            {
                int i = _list.FindIndex(x => x.Id == inc.Id);
                if (i >= 0) _list[i] = inc; else _list.Insert(0, inc);
                _changed.Add(inc);
            }
        }
        internal void RaiseAll()
        {
            Incident[] changed;
            lock (_l) { changed = _changed.ToArray(); _changed.Clear(); }
            foreach (var c in changed) IncidentChanged?.Invoke(c);
        }
    }

    public sealed class DemoPortHealthMonitor : IPortHealthMonitor
    {
        public IReadOnlyList<PortHealth> Current { get; set; } = [];
        public IReadOnlyList<PortHealth> Ports => Current;
        public PortHealth? Get(Mac switchMac, string port) => Current.FirstOrDefault(p => p.Switch == switchMac && p.Name == port);
        public event Action? Updated;
        internal void Raise() => Updated?.Invoke();
    }

    public sealed class DemoStormCenter : IStormCenter
    {
        private readonly object _l = new();
        private List<StormEvent> _history = [];
        public StormStatus Status { get; set; } = StormStatus.Empty;
        public IReadOnlyList<StormEvent> History { get { lock (_l) return _history.ToArray(); } }
        /// <summary>Prefilled pps history (time, bcast, mcast, unknown unicast) so the demo charts start full.</summary>
        public IReadOnlyList<(DateTimeOffset T, double B, double M, double U)> Rates { get { lock (_l) return _rates.ToArray(); } }
        private readonly List<(DateTimeOffset, double, double, double)> _rates = [];
        public event Action<StormStatus>? Updated;
        internal void Raise() => Updated?.Invoke(Status);
        internal void SetHistory(List<StormEvent> h) { lock (_l) { _history = h; _rates.Clear(); } }
        internal void AddHistory(StormEvent e) { lock (_l) _history.Insert(0, e); }
        internal void Push(DateTimeOffset t, double b, double m, double u) { lock (_l) { _rates.Add((t, b, m, u)); if (_rates.Count > 600) _rates.RemoveAt(0); } }

        public string? RecordNow() =>
            System.IO.Path.Combine(AppPaths.Root, "captures", $"storm-manual-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.pcapng");

        public async Task<StormControlResult> RunStormControlCheckAsync(StormControlOptions options, CancellationToken ct)
        {
            int ms = Math.Min(options.DurationMs, 5000), pps = Math.Min(options.Pps, 5000);
            await Task.Delay(ms, ct);
            int sent = pps * ms / 1000;
            return new StormControlResult(true, sent, TimeSpan.FromMilliseconds(ms), true,
                "Storm control is active on core-sw-01 — the burst was capped after ~0.4 s",
                [
                    $"Sent {sent:N0} broadcast frames at {pps:N0} pps for {ms / 1000.0:0.#} s (demo — nothing was transmitted)",
                    "core-sw-01 g6 ifInBroadcastPkts rose by 1 012, then flat: ingress limited to ~1 000 pps",
                    "usw-lite-office forwarded only 38 % of the burst upstream (storm-control drop counter +3 140)",
                    "No broadcast increase on other access ports — the burst did not flood the network",
                ]);
        }
    }

    public sealed class DemoWifiLinkMonitor : IWifiLinkMonitor
    {
        private readonly object _l = new();
        private List<WifiLinkSample> _history = [];
        private List<WifiEvent> _events = [];
        public bool Available => true;
        public WifiLinkSample? Current { get { lock (_l) return _history.LastOrDefault(); } }
        public IReadOnlyList<WifiLinkSample> History { get { lock (_l) return _history.ToArray(); } }
        public IReadOnlyList<WifiEvent> Events { get { lock (_l) return _events.ToArray(); } }
        public event Action? Updated;
        internal void Raise() => Updated?.Invoke();
        internal void SetHistory(List<WifiLinkSample> h) { lock (_l) _history = h; }
        internal void SetEvents(List<WifiEvent> e) { lock (_l) _events = e; }
        internal void Add(WifiLinkSample s) { lock (_l) { _history.Add(s); if (_history.Count > 900) _history.RemoveAt(0); } }
    }

    public sealed class DemoApHealthMonitor : IApHealthMonitor
    {
        public IReadOnlyList<ApHealth> Current { get; set; } = [];
        public IReadOnlyList<ApHealth> AccessPoints => Current;
        public event Action? Updated;
        internal void Raise() => Updated?.Invoke();
    }

    public sealed class DemoProbeAgentHub : IProbeAgentHub
    {
        public bool IsListening => true;
        public int Port => 47810;
        public IReadOnlyList<ProbeAgentInfo> Current { get; set; } = [];
        public IReadOnlyList<ProbeAgentInfo> Agents => Current;
        public event Action? Updated;
        internal void Raise() => Updated?.Invoke();
    }
}
