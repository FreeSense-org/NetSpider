using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.App.Services;

/// <summary>
/// A realistic, living home + small-office network (~42 devices) that populates the real Core stores so every view of
/// the app can be demonstrated without Npcap. Deterministic for a given seed; <see cref="Tick"/> advances the simulation.
/// </summary>
public sealed class DemoNetwork : IDisposable
{
    // ---- well-known demo MACs ----
    public static Mac GatewayMac { get; } = Mac.Parse("74:AC:B9:4E:21:01");   // Ubiquiti UDM
    public static Mac ThisHostMac { get; } = Mac.Parse("D8:BB:C1:7A:3F:10");  // Micro-Star (MSI) desktop board

    internal static readonly Mac CoreMac = Mac.Parse("A0:40:A0:5C:11:20");      // Netgear GS724T
    internal static readonly Mac AccessMac = Mac.Parse("F4:92:BF:A8:30:41");    // UniFi Switch Lite 8 PoE
    internal static readonly Mac Ap1Mac = Mac.Parse("74:83:C2:61:9A:10");       // U6-Pro
    internal static readonly Mac Ap2Mac = Mac.Parse("78:45:58:D2:47:20");       // U6-Lite
    internal static readonly Mac InferredMac = SyntheticNodes.InferredSwitch(CoreMac, "g7");
    internal static readonly Mac InternetMac = SyntheticNodes.Internet;

    private static readonly IPAddress SsdpGroup = IPAddress.Parse("239.255.255.250");
    private static readonly IPAddress MdnsGroup = IPAddress.Parse("224.0.0.251");

    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly IAlertService _alerts;
    private readonly INetworkState _network;
    private readonly IEventBus _bus;
    private readonly AppSettings _settings;
    private readonly ILogger<DemoNetwork>? _log;
    private readonly object _sync = new();

    private readonly Dictionary<Mac, Node> _nodes = new();
    private readonly List<(Mac A, Mac B, LatencyOrigin Origin, string Method)> _pairs = new();
    private readonly Dictionary<string, List<Mac>> _protocolSources = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string>? _logoIndex;

    private Random _rng = new(42);
    private Timer? _tickTimer;
    private Timer? _packetTimer;
    private int _tick;
    private int _nextNewDeviceTick, _nextStormTick, _nextFlipTick;
    private int _extraDevices;
    private int _stormTicks;
    private Mac _stormSource;
    private long _dropped;
    private bool _built;

    public DemoNetwork(IDeviceStore devices, ITopologyStore topology, IAlertService alerts, INetworkState network, IEventBus bus,
        AppSettings settings, ILogger<DemoNetwork>? log = null)
    {
        _devices = devices;
        _topology = topology;
        _alerts = alerts;
        _network = network;
        _bus = bus;
        _settings = settings;
        _log = log;
    }

    private volatile bool _running;
    public bool IsRunning { get => _running; private set => _running = value; }

    // ============================================================================================
    //  Simulation node (latency model)
    // ============================================================================================

    private sealed class Node(Mac mac)
    {
        public Mac Mac { get; } = mac;
        public Mac? Parent { get; set; }
        public LinkKind Kind { get; set; }
        /// <summary>Port name on the parent (switch) side.</summary>
        public string? ParentPort { get; set; }
        /// <summary>Port name on this device's side of the uplink.</summary>
        public string? ChildPort { get; set; }
        public long? Speed { get; set; }
        public double? Poe { get; set; }
        public double BaseLink { get; set; }
        public double LinkLat { get; set; }
        public double Proc { get; set; }
        public double Loss { get; set; }
        public bool Wifi { get; set; }
        public bool NoArp { get; set; }
        public bool Measured { get; set; }
        public int OfflineTicks { get; set; }
    }

    // ============================================================================================
    //  Lifecycle
    // ============================================================================================

    public void Start()
    {
        lock (_sync)
        {
            if (IsRunning) return;
            _network.IsDemo = true;
            if (!_built) BuildCore(42);
            _tickTimer = new Timer(_ => SafeTick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
            _packetTimer = new Timer(_ => SafePackets(), null, TimeSpan.FromMilliseconds(120), TimeSpan.FromMilliseconds(120));
            IsRunning = true;
        }
        _log?.LogInformation("Demo network started");
    }

    /// <summary>
    /// Stops the simulation timers and waits (briefly) for a tick or packet burst that is already running, so nothing from the
    /// demo reaches the stores or the event bus after this returns.
    /// </summary>
    public void Stop()
    {
        Timer? tick, packets;
        lock (_sync)
        {
            tick = _tickTimer;
            packets = _packetTimer;
            _tickTimer = _packetTimer = null;
            IsRunning = false;
        }
        WaitDispose(tick);
        WaitDispose(packets);
    }

    private static void WaitDispose(Timer? t)
    {
        if (t is null) return;
        using var done = new ManualResetEvent(false);
        try { if (t.Dispose(done)) done.WaitOne(TimeSpan.FromSeconds(2)); }
        catch (ObjectDisposedException) { }
    }

    /// <summary>
    /// Stops the simulation and removes everything it put into the stores, plus its own internal state. Does not touch
    /// <see cref="INetworkState.IsDemo"/>: <see cref="DataModeController"/> owns the demo/real switch.
    /// </summary>
    public void Clear()
    {
        Stop();
        lock (_sync) ClearStores();
    }

    /// <summary>MACs of every device the demo has ever added (demo identity; used to verify that no demo data leaks into real mode).</summary>
    public IReadOnlyCollection<Mac> BuiltMacs { get { lock (_sync) return _builtMacs.ToArray(); } }
    private readonly HashSet<Mac> _builtMacs = new();

    public void Dispose() => Stop();

    public void Build(int seed = 42)
    {
        lock (_sync) BuildCore(seed);
        _topology.NotifyChanged();
    }

    private void SafeTick()
    {
        // a timer callback that fires while Stop()/Clear() runs must not rebuild the demo (Tick() builds when nothing is built)
        if (!IsRunning) return;
        try { Tick(); }
        catch (Exception ex) { _log?.LogError(ex, "Demo tick failed"); }
    }

    private void SafePackets()
    {
        if (!IsRunning) return;
        try { PublishPacketBurst(); }
        catch (Exception ex) { _log?.LogError(ex, "Demo packet burst failed"); }
    }

    private void ClearStores()
    {
        // everything: the demo also adds segments, VLANs, DHCP servers, STP bridges, LLDP neighbors, IGMP querier, ...
        _devices.Clear();
        _topology.Clear();
        _alerts.Clear();
        _network.Reset();
        _nodes.Clear();
        _pairs.Clear();
        _protocolSources.Clear();
        _built = false;
    }

    // ============================================================================================
    //  Build
    // ============================================================================================

    private void BuildCore(int seed)
    {
        ClearStores();
        _rng = new Random(seed);
        _tick = 0;
        _extraDevices = 0;
        _stormTicks = 0;
        _dropped = 0;
        _nextNewDeviceTick = _rng.Next(15, 25);
        _nextStormTick = _rng.Next(30, 40);
        _nextFlipTick = _rng.Next(40, 60);

        BuildDevices();
        BuildSwitchTables();
        BuildPairs();
        BuildNetworkState();
        BuildAlerts();
        PrefillLatency();
        _built = true;
        _log?.LogInformation("Demo network built: {Devices} devices, {Links} links", _devices.Count, _topology.Links.Count);
    }

    private void BuildDevices()
    {
        // ---------------- WAN + infrastructure ----------------
        var inet = Add(InternetMac, null, DeviceType.Internet, null, null, null, ("user", "Internet"), null, LinkKind.Wan, null,
            proc: 0, ageDays: 400, noArp: true);
        inet.SetFlag(DeviceFlags.Infrastructure);

        var udm = Add(GatewayMac, "192.168.1.1", DeviceType.Router, "Ubiquiti Inc", "Ubiquiti", "UniFi Dream Machine Pro",
            ("snmp", "UDM-Pro"), null, LinkKind.LldpCdp, null, proc: 0.12, ageDays: 400, protocols: ["ARP", "SSDP", "LLDP", "DHCP", "IGMP", "ICMPv6"]);
        udm.SetFlag(DeviceFlags.Gateway | DeviceFlags.Infrastructure | DeviceFlags.DhcpServer | DeviceFlags.IgmpQuerier);
        udm.Firmware = "UniFi OS 4.1.13";
        udm.OsGuess = "Linux 5.4 (UniFi OS)";
        udm.AddIp(IPAddress.Parse("192.168.20.1"));
        udm.AddIp(IPAddress.Parse("192.168.30.1"));
        udm.AddIp(IPAddress.Parse("fe80::76ac:b9ff:fe4e:2101"));
        udm.AddIp(IPAddress.Parse("2a02:aa1:1023:6400::1"));
        Ports(udm, 22, 53, 80, 443, 8443);
        udm.SetPort(new PortInfo(161, "udp", PortState.Open, "snmp"));
        udm.AddService(new ServiceInfo("udp", 10001, "Ubiquiti Discovery", "ubnt-discovery"));
        udm.AddService(new ServiceInfo("tcp", 443, "UniFi OS", "https"));
        Ev(udm, "snmp", Fields.Model, "UDM-Pro", Confidence.Snmp);
        Ev(udm, "ubnt", Fields.Firmware, "4.1.13", Confidence.VendorProtocol);
        Ev(udm, "tls", Fields.Hostname, "unifi.local", Confidence.Tls);
        Ev(udm, "lldp", Fields.Capabilities, "Router, Bridge", Confidence.Lldp);
        Cert(udm, 443, "unifi.local", ["unifi.local", "192.168.1.1"], "Ubiquiti Inc.", self: true, days: 3650);
        Mcast(udm, "224.0.0.1", "224.0.0.22");
        // The gateway is the root of the latency tree; the Internet hangs off it via the WAN link.
        Wire(GatewayMac, InternetMac, LinkKind.Wan, "WAN (eth9)", null, 1000, 9.5, measured: true);
        var inetNode = _nodes[InternetMac];
        inetNode.Parent = GatewayMac;
        inetNode.ParentPort = "WAN (eth9)";
        inetNode.Speed = 1000;
        inetNode.BaseLink = inetNode.LinkLat = 9.5;
        inetNode.Measured = true;
        inet.UpstreamMac = GatewayMac;
        Vlans(udm, 1, 20, 30, 40);

        var core = Add(CoreMac, "192.168.1.2", DeviceType.CoreSwitch, "NETGEAR", "Netgear", "GS724T",
            ("snmp", "core-sw-01"), GatewayMac, LinkKind.LldpCdp, "SFP+ 1", "g24", 10000, 0.08, 0.35, measured: true, ageDays: 380,
            protocols: ["LLDP", "STP", "ARP"]);
        core.SetFlag(DeviceFlags.Infrastructure | DeviceFlags.StpRoot);
        core.Firmware = "6.0.1.29";
        Ports(core, 80, 443);
        core.SetPort(new PortInfo(161, "udp", PortState.Open, "snmp"));
        core.SetProperty("sysDescr", "GS724Tv4 ProSAFE 24-Port Gigabit Smart Switch, 6.0.1.29");
        core.SetProperty("uptime", "41d 03:12:55");
        Ev(core, "snmp", Fields.Description, "GS724Tv4 ProSAFE 24-Port Gigabit Smart Switch", Confidence.Snmp);
        Ev(core, "lldp", Fields.Capabilities, "Bridge", Confidence.Lldp);
        Ev(core, "nsdp", Fields.Model, "GS724Tv4", Confidence.VendorProtocol);
        Vlans(core, 1, 20, 30, 40);

        var access = Add(AccessMac, "192.168.1.3", DeviceType.AccessSwitch, "Ubiquiti Inc", "Ubiquiti", "UniFi Switch Lite 8 PoE",
            ("lldp", "usw-lite-office"), CoreMac, LinkKind.LldpCdp, "g21", "Port 8", 1000, 0.1, 0.3, measured: true, ageDays: 200,
            protocols: ["LLDP", "STP", "ARP"]);
        access.SetFlag(DeviceFlags.Infrastructure);
        access.Firmware = "7.1.26";
        Ports(access, 22);
        Ev(access, "lldp", Fields.Model, "USW-Lite-8-PoE", Confidence.Lldp);
        Ev(access, "ubnt", Fields.Firmware, "7.1.26", Confidence.VendorProtocol);
        Vlans(access, 1, 30, 40);

        var inferred = Add(InferredMac, null, DeviceType.UnmanagedSwitch, null, null, "Unmanaged switch (inferred)",
            ("user", "Inferred switch · TV rack"), CoreMac, LinkKind.InferredUnmanagedSwitch, "g7", null, 1000, 0.12, 0, ageDays: 90, noArp: true);
        inferred.SetFlag(DeviceFlags.Inferred | DeviceFlags.Infrastructure);
        inferred.TypeConfidence = 0.7;
        Ev(inferred, "fdb", "inference", "3 MACs on g7 without LLDP/CDP", 0.7);

        var ap1 = Add(Ap1Mac, "192.168.1.4", DeviceType.AccessPoint, "Ubiquiti Inc", "Ubiquiti", "U6-Pro",
            ("lldp", "ap-living-room"), CoreMac, LinkKind.LldpCdp, "g1", "eth0", 1000, 0.1, 0.25, poe: 12.4, measured: true, ageDays: 300,
            protocols: ["LLDP", "ARP", "IGMP"]);
        ap1.SetFlag(DeviceFlags.Infrastructure | DeviceFlags.PoePowered);
        Ports(ap1, 22);
        Ev(ap1, "lldp", Fields.Model, "U6-Pro", Confidence.Lldp);
        Ev(ap1, "ubnt", Fields.Firmware, "6.6.77", Confidence.VendorProtocol);
        Vlans(ap1, 1, 20);

        var ap2 = Add(Ap2Mac, "192.168.1.5", DeviceType.AccessPoint, "Ubiquiti Inc", "Ubiquiti", "U6-Lite",
            ("lldp", "ap-upstairs"), CoreMac, LinkKind.LldpCdp, "g2", "eth0", 1000, 0.1, 0.25, poe: 8.1, measured: true, ageDays: 300,
            protocols: ["LLDP", "ARP", "IGMP"]);
        ap2.SetFlag(DeviceFlags.Infrastructure | DeviceFlags.PoePowered);
        Ports(ap2, 22);
        Ev(ap2, "lldp", Fields.Model, "U6-Lite", Confidence.Lldp);
        Vlans(ap2, 1, 20);

        // ---------------- wired on the core switch ----------------
        var cam1 = Add(Mac.Parse("C0:56:E3:4A:10:01"), "192.168.30.11", DeviceType.Camera, "Hangzhou Hikvision Digital Technology", "Hikvision",
            "DS-2CD2387G2-LU", ("dhcp", "cam-driveway"), CoreMac, LinkKind.BridgeFdb, "g3", "eth0", 100, 0.15, 0.6, vlan: 30, poe: 6.2,
            protocols: ["ARP", "IGMP", "DHCP"]);
        cam1.SetFlag(DeviceFlags.PoePowered | DeviceFlags.MulticastSource);
        Ports(cam1, 80, 443, 554, 8000);
        cam1.AddService(new ServiceInfo("tcp", 554, "RTSP", "rtsp"));
        cam1.AddService(new ServiceInfo("udp", 3702, "ONVIF NVT", "onvif"));
        Ev(cam1, "onvif", Fields.Model, "DS-2CD2387G2-LU", Confidence.VendorProtocol);
        Ev(cam1, "http", Fields.Brand, "Hikvision", Confidence.Http);
        Mcast(cam1, "239.192.30.11");

        var nas = Add(Mac.Parse("00:11:32:9C:44:21"), "192.168.1.20", DeviceType.Nas, "Synology Incorporated", "Synology", "DS920+",
            ("mdns", "nas"), CoreMac, LinkKind.BridgeFdb, "g4", "LAN 1", 1000, 0.12, 0.06, measured: true, ageDays: 700,
            protocols: ["ARP", "mDNS", "SSDP", "NetBIOS", "ICMPv6"]);
        nas.Firmware = "DSM 7.2.2-72806";
        nas.OsGuess = "Linux 4.4 (DSM)";
        nas.SetHostname("netbios", "NAS");
        nas.AddIp(IPAddress.Parse("fe80::211:32ff:fe9c:4421"));
        Ports(nas, 22, 80, 139, 443, 445, 5000, 5001, 32400);
        nas.AddService(new ServiceInfo("udp", 5353, "nas", "_smb._tcp"));
        nas.AddService(new ServiceInfo("udp", 5353, "nas", "_http._tcp"));
        nas.AddService(new ServiceInfo("tcp", 32400, "Plex Media Server", "http"));
        Ev(nas, "mdns", Fields.Model, "DS920+", Confidence.Mdns);
        Ev(nas, "tls", "certificateCN", "nas.spider.home", Confidence.Tls);
        Ev(nas, "ssdp", Fields.Brand, "Synology", Confidence.Ssdp);
        Ev(nas, "smb", Fields.Os, "Samba 4.15 (SMB 3.1.1)", Confidence.NetBios);
        Cert(nas, 5001, "nas.spider.home", ["nas.spider.home", "nas.local"], "Let's Encrypt", self: false, days: 90, issuerOrg: "Let's Encrypt");
        nas.SetProperty("cpu", "Intel Celeron J4125 · 7%");
        nas.SetProperty("memory", "8 GB · 41% used");
        nas.SetProperty("volume1", "21.8 TB · 63% used");
        nas.SetProperty("uptime", "22d 11:04:31");
        Mcast(nas, MdnsGroup.ToString(), SsdpGroup.ToString());

        var pve = Add(Mac.Parse("BC:24:11:00:AA:01"), "192.168.1.30", DeviceType.Hypervisor, "Proxmox Server Solutions GmbH", "Proxmox",
            "Proxmox VE 8.2", ("dns", "pve01.spider.home"), CoreMac, LinkKind.BridgeFdb, "g5", "enp3s0", 1000, 0.12, 0.05, measured: true, ageDays: 500,
            protocols: ["ARP", "LLDP", "ICMPv6"]);
        pve.OsGuess = "Debian 12 (Proxmox VE)";
        Ports(pve, 22, 111, 3128, 8006);
        Ev(pve, "tls", Fields.Description, "Proxmox Virtual Environment", Confidence.Tls);
        Ev(pve, "http", Fields.Model, "Proxmox VE 8.2", Confidence.Http);
        Ev(pve, "lldp", Fields.Hostname, "pve01", Confidence.Lldp);
        Cert(pve, 8006, "pve01.spider.home", ["pve01", "pve01.spider.home", "192.168.1.30"], "Proxmox Virtual Environment", self: true, days: 730,
            issuerOrg: "PVE Cluster Manager CA");
        pve.SetFlag(DeviceFlags.SelfSignedCertificate);
        pve.SetProperty("cpu", "AMD Ryzen 7 5700G · 18%");
        pve.SetProperty("memory", "64 GB · 52% used");
        pve.SetProperty("uptime", "63d 02:51:09");

        (string Mac, string Ip, string Name, string Os, int[] Ports)[] vms =
        [
            ("BC:24:11:3E:51:A2", "192.168.1.31", "home-assistant-vm", "Home Assistant OS 13", [22, 8123]),
            ("BC:24:11:7F:02:C3", "192.168.1.32", "pihole", "Debian 12", [22, 53, 80]),
            ("BC:24:11:C4:9D:14", "192.168.1.33", "docker-host", "Ubuntu 24.04", [22, 80, 443, 9000]),
        ];
        foreach (var vm in vms)
        {
            var d = Add(Mac.Parse(vm.Mac), vm.Ip, DeviceType.VirtualMachine, "Proxmox Server Solutions GmbH", "Proxmox", "Virtual machine",
                ("dns", vm.Name), pve.Mac, LinkKind.VirtualHypervisor, "vmbr0", "ens18", 10000, 0.03, 0.05, measured: false, ageDays: 120,
                protocols: ["ARP", "ICMPv6"]);
            d.SetFlag(DeviceFlags.Virtual);
            d.OsGuess = vm.Os;
            Ports(d, vm.Ports);
            Ev(d, "dns", Fields.Hostname, vm.Name, 0.6);
            Ev(d, "ttl", Fields.Os, "Linux", Confidence.Ttl);
        }
        var haVm = _devices.TryGet(Mac.Parse(vms[0].Mac), out var ha) ? ha : null;
        if (haVm is not null)
        {
            haVm.AddService(new ServiceInfo("udp", 5353, "Home", "_home-assistant._tcp"));
            haVm.AddService(new ServiceInfo("udp", 5353, "Home", "_hap._tcp"));
            AddProtocols(haVm.Mac, "mDNS");
        }

        var me = Add(ThisHostMac, "192.168.1.50", DeviceType.ThisComputer, "Micro-Star INTL CO., LTD.", "MSI", "MAG B650 Tomahawk",
            ("netbios", "SPIDER-WS"), AccessMac, LinkKind.BridgeFdb, "Port 4", "Ethernet", 1000, 0.1, 0.02, measured: true, ageDays: 900,
            protocols: ["ARP", "mDNS", "SSDP", "NetBIOS", "DHCP", "ICMPv6"]);
        me.SetFlag(DeviceFlags.ThisHost | DeviceFlags.WakeOnLanCapable);
        me.OsGuess = "Windows 11 Pro 24H2";
        me.AddIp(IPAddress.Parse("fe80::5c1e:9a2b:44f0:3d10"));
        Ports(me, 135, 139, 445, 3389);
        Ev(me, "local", Fields.Os, "Windows 11 Pro", Confidence.User);
        Ev(me, "smb", Fields.Domain, "WORKGROUP", Confidence.NetBios);

        // ---------------- behind the inferred unmanaged switch (TV rack) ----------------
        var xbox = Add(Mac.Parse("98:5F:D3:21:7C:44"), "192.168.1.60", DeviceType.GameConsole, "Microsoft Corporation", "Microsoft",
            "Xbox Series X", ("netbios", "XBOX-LIVINGROOM"), InferredMac, LinkKind.InferredUnmanagedSwitch, null, "eth0", 1000, 0.15, 0.3,
            protocols: ["ARP", "SSDP", "NetBIOS", "ICMPv6", "DHCP"]);
        Ports(xbox, 3074);
        xbox.SetPort(new PortInfo(3074, "udp", PortState.Open, "xbox-live"));
        Ev(xbox, "ssdp", Fields.Model, "Xbox Series X", Confidence.Ssdp);
        Ev(xbox, "dhcp", Fields.DhcpVendorClass, "MSFT 5.0 XBOX", Confidence.Dhcp);
        Mcast(xbox, SsdpGroup.ToString());

        var tv = Add(Mac.Parse("8C:79:F5:0D:6E:19"), "192.168.1.61", DeviceType.Tv, "Samsung Electronics Co.,Ltd", "Samsung",
            "QE65S95C OLED", ("ssdp", "Samsung S95C — Living Room"), InferredMac, LinkKind.InferredUnmanagedSwitch, null, "eth0", 100, 0.15, 0.9,
            protocols: ["ARP", "SSDP", "mDNS", "DHCP"]);
        Ports(tv, 8001, 8002, 9197);
        tv.AddService(new ServiceInfo("udp", 1900, "Samsung TV", "urn:dial-multiscreen-org:service:dial:1"));
        Ev(tv, "ssdp", Fields.Model, "QE65S95CATXXC", Confidence.Ssdp);
        Ev(tv, "http", Fields.Firmware, "T-PTMDEUC-1502.4", Confidence.Http);
        Mcast(tv, SsdpGroup.ToString(), MdnsGroup.ToString());

        var appleTv = Add(Mac.Parse("F0:B3:EC:12:88:5A"), "192.168.1.62", DeviceType.MediaStreamer, "Apple, Inc.", "Apple", "Apple TV 4K (3rd gen)",
            ("mdns", "Living-Room-Apple-TV"), InferredMac, LinkKind.InferredUnmanagedSwitch, null, "en0", 1000, 0.15, 0.4,
            protocols: ["ARP", "mDNS", "ICMPv6"]);
        Ports(appleTv, 7000, 7100, 49152);
        appleTv.AddService(new ServiceInfo("udp", 5353, "Living Room", "_airplay._tcp"));
        appleTv.AddService(new ServiceInfo("udp", 5353, "Living Room", "_companion-link._tcp"));
        appleTv.AddService(new ServiceInfo("udp", 5353, "Living Room", "_homekit._tcp"));
        Ev(appleTv, "mdns", Fields.ModelNumber, "AppleTV14,1", Confidence.Mdns);
        Mcast(appleTv, MdnsGroup.ToString());
        appleTv.AddIp(IPAddress.Parse("fe80::1c8b:a0ff:fe12:885a"));

        // ---------------- more wired core devices ----------------
        var hp = Add(Mac.Parse("3C:52:82:7B:19:E0"), "192.168.1.70", DeviceType.Printer, "Hewlett Packard", "HP", "Color LaserJet Pro M454dw",
            ("mdns", "HP-LaserJet-M454"), CoreMac, LinkKind.BridgeFdb, "g8", "eth0", 100, 0.15, 1.1, ageDays: 600,
            protocols: ["ARP", "mDNS", "SSDP", "NetBIOS", "DHCP"]);
        Ports(hp, 80, 443, 631, 9100);
        hp.SetPort(new PortInfo(161, "udp", PortState.Open, "snmp"));
        hp.AddService(new ServiceInfo("udp", 5353, "HP Color LaserJet", "_ipp._tcp"));
        hp.AddService(new ServiceInfo("udp", 5353, "HP Color LaserJet", "_pdl-datastream._tcp"));
        Ev(hp, "snmp", Fields.Model, "HP Color LaserJet Pro M454dw", Confidence.Snmp);
        Ev(hp, "mdns", Fields.Model, "Color LaserJet Pro M454dw", Confidence.Mdns);
        Ev(hp, "snmp", Fields.Serial, "VNB3R12345", Confidence.Snmp);
        hp.SetProperty("toner.black", "62%");
        hp.SetProperty("toner.cyan", "38%");
        hp.SetProperty("toner.magenta", "45%");
        hp.SetProperty("toner.yellow", "12%");
        hp.SetProperty("pages", "18 442");
        hp.SetFlag(DeviceFlags.DefaultSnmpCommunity);
        Mcast(hp, MdnsGroup.ToString());

        var pi = Add(Mac.Parse("DC:A6:32:5E:0B:7F"), "192.168.1.40", DeviceType.Server, "Raspberry Pi Trading Ltd", "Raspberry Pi", "Raspberry Pi 4 Model B",
            ("mdns", "raspberrypi"), CoreMac, LinkKind.BridgeFdb, "g9", "eth0", 1000, 0.12, 0.15, ageDays: 450,
            protocols: ["ARP", "mDNS", "ICMPv6", "DHCP"]);
        pi.OsGuess = "Raspberry Pi OS (Debian 12)";
        Ports(pi, 22, 80, 1883);
        pi.SetPort(new PortInfo(51820, "udp", PortState.Open, "wireguard"));
        pi.AddService(new ServiceInfo("tcp", 1883, "Mosquitto MQTT", "mqtt"));
        Ev(pi, "ssh", Fields.Os, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 0.6);
        Ev(pi, "dhcp", Fields.DhcpFingerprint, "1,28,2,3,15,6,119,12,44,47,26,121,42", Confidence.Dhcp);
        pi.AddIp(IPAddress.Parse("fe80::dea6:32ff:fe5e:b7f"));

        var hue = Add(Mac.Parse("00:17:88:6B:22:E1"), "192.168.20.10", DeviceType.SmartHomeHub, "Philips Lighting BV", "Philips Hue", "Hue Bridge v2",
            ("mdns", "Philips-hue"), CoreMac, LinkKind.BridgeFdb, "g10", "eth0", 100, 0.15, 1.6, vlan: 20, ageDays: 800,
            protocols: ["ARP", "mDNS", "SSDP", "IGMP"]);
        Ports(hue, 80, 443);
        hue.AddService(new ServiceInfo("udp", 5353, "Hue Bridge - 6B22E1", "_hue._tcp"));
        hue.AddService(new ServiceInfo("udp", 5353, "Hue Bridge - 6B22E1", "_hap._tcp"));
        Ev(hue, "http", Fields.Model, "BSB002", Confidence.VendorProtocol);
        Ev(hue, "ssdp", Fields.Brand, "Signify", Confidence.Ssdp);
        hue.SetProperty("lights", "23");
        Mcast(hue, MdnsGroup.ToString(), SsdpGroup.ToString());

        var haBox = Add(Mac.Parse("2C:CF:67:10:93:AB"), "192.168.20.11", DeviceType.SmartHomeHub, "Raspberry Pi Trading Ltd", "Home Assistant",
            "Home Assistant Green", ("mdns", "homeassistant"), CoreMac, LinkKind.BridgeFdb, "g11", "eth0", 1000, 0.12, 0.4, vlan: 20, ageDays: 150,
            protocols: ["ARP", "mDNS", "SSDP"]);
        Ports(haBox, 8123, 4357);
        haBox.AddService(new ServiceInfo("udp", 5353, "Home", "_home-assistant._tcp"));
        Ev(haBox, "mdns", Fields.Model, "Home Assistant Green", Confidence.Mdns);
        Mcast(haBox, MdnsGroup.ToString());

        var rogue = Add(Mac.Parse("50:C7:BF:1A:2B:3C"), "192.168.0.1", DeviceType.Router, "TP-LINK TECHNOLOGIES CO.,LTD.", "TP-Link",
            "TL-WR902AC travel router", ("dhcp", "TL-WR902AC"), CoreMac, LinkKind.BridgeFdb, "g12", "LAN", 100, 0.15, 0.9, ageDays: 0,
            protocols: ["ARP", "DHCP"]);
        rogue.SetFlag(DeviceFlags.RogueDhcp | DeviceFlags.DhcpServer | DeviceFlags.New);
        Ports(rogue, 80);
        Ev(rogue, "dhcp", "dhcpServer", "Offered 192.168.0.100 (router 192.168.0.1)", Confidence.Dhcp);
        Ev(rogue, "http", Fields.Model, "TL-WR902AC", Confidence.Http);

        var brother = Add(Mac.Parse("00:80:77:4D:5E:6F"), "192.168.1.71", DeviceType.Printer, "Brother Industries, Ltd.", "Brother",
            "HL-2270DW", ("netbios", "BRN0080774D5E6F"), CoreMac, LinkKind.BridgeFdb, "g13", "eth0", 100, 0.15, 2.2, ageDays: 2500,
            protocols: ["ARP", "NetBIOS", "SSDP"]);
        brother.SetFlag(DeviceFlags.CleartextManagement | DeviceFlags.DefaultSnmpCommunity);
        Ports(brother, 21, 23, 80, 515, 9100);
        brother.SetPort(new PortInfo(23, "tcp", PortState.Open, "telnet", "Brother NC-6800h telnet"));
        Ev(brother, "snmp", Fields.Model, "Brother HL-2270DW series", Confidence.Snmp);
        Ev(brother, "telnet", Fields.Description, "Brother NC-6800h, Firmware Ver.1.13", 0.6);
        brother.SetProperty("toner.black", "8%");

        // ---------------- on the access switch (office) ----------------
        var cam2 = Add(Mac.Parse("C0:56:E3:4A:10:02"), "192.168.30.12", DeviceType.Camera, "Hangzhou Hikvision Digital Technology", "Hikvision",
            "DS-2CD2143G2-IU", ("dhcp", "cam-backyard"), AccessMac, LinkKind.BridgeFdb, "Port 1", "eth0", 100, 0.15, 0.7, vlan: 30, poe: 4.8,
            protocols: ["ARP", "IGMP"]);
        cam2.SetFlag(DeviceFlags.PoePowered | DeviceFlags.MulticastSource | DeviceFlags.ExpiredCertificate);
        Ports(cam2, 80, 443, 554);
        Ev(cam2, "onvif", Fields.Model, "DS-2CD2143G2-IU", Confidence.VendorProtocol);
        Ev(cam2, "tls", "certificate", "Expired self-signed certificate", Confidence.Tls);
        Cert(cam2, 443, "IPC", ["192.168.30.12"], "IPC", self: true, days: -120);
        Mcast(cam2, "239.192.30.12");

        var phoneDesk = Add(Mac.Parse("80:5E:C0:44:91:0D"), "192.168.40.20", DeviceType.VoipPhone, "Yealink(Xiamen) Network Technology", "Yealink",
            "T54W", ("lldp", "Office Desk Phone"), AccessMac, LinkKind.BridgeFdb, "Port 2", "eth0", 100, 0.12, 0.5, vlan: 40, poe: 3.9,
            protocols: ["LLDP", "CDP", "ARP", "DHCP"]);
        phoneDesk.SetFlag(DeviceFlags.PoePowered);
        Ports(phoneDesk, 80, 443);
        phoneDesk.SetPort(new PortInfo(5060, "udp", PortState.Open, "sip"));
        Ev(phoneDesk, "lldp", Fields.Model, "SIP-T54W", Confidence.Lldp);
        Ev(phoneDesk, "lldp", "lldpMed", "Voice VLAN 40, DSCP 46", Confidence.Lldp);

        var sonosPort = Add(Mac.Parse("48:A6:B8:0E:7A:31"), "192.168.1.84", DeviceType.AudioStreamer, "Sonos, Inc.", "Sonos", "Sonos Port",
            ("ssdp", "Sonos Port — Office"), AccessMac, LinkKind.BridgeFdb, "Port 5", "eth0", 100, 0.12, 0.35, ageDays: 330,
            protocols: ["ARP", "SSDP", "mDNS", "IGMP"]);
        SonosCommon(sonosPort, "S23");

        var dell = Add(Mac.Parse("A4:BB:6D:2F:C0:18"), "192.168.1.55", DeviceType.Laptop, "Dell Inc.", "Dell", "Latitude 7440",
            ("netbios", "WORK-LAPTOP"), AccessMac, LinkKind.BridgeFdb, "Port 6", "Ethernet 2", 1000, 0.12, 0.05, ageDays: 70,
            protocols: ["ARP", "NetBIOS", "DHCP", "SSDP"]);
        dell.OsGuess = "Windows 11 Enterprise";
        dell.State = DeviceState.Offline;
        _nodes[dell.Mac].OfflineTicks = int.MaxValue / 2;
        Ports(dell, 135, 445);
        Ev(dell, "dhcp", Fields.DhcpVendorClass, "MSFT 5.0", Confidence.Dhcp);

        // ---------------- Wi-Fi clients ----------------
        Wifi("DA:A1:19:3C:7E:01", "192.168.1.101", DeviceType.Phone, "Apple, Inc.", "Apple", "iPhone 15 Pro", ("mdns", "Alex-iPhone"), Ap1Mac, 2.6, 1.6, rssi: -51, ["mDNS", "ARP", "ICMPv6", "DHCP"],
            d => { d.AddService(new ServiceInfo("udp", 5353, "Alex’s iPhone", "_apple-mobdev2._tcp")); Ports(d, 62078); d.AddIp(IPAddress.Parse("2a02:aa1:1023:6400:8d3e:41f2:9a07:c1b5")); });
        Wifi("6E:2F:8B:90:14:A2", "192.168.1.102", DeviceType.Phone, "Apple, Inc.", "Apple", "iPhone 14", ("mdns", "Sams-iPhone"), Ap2Mac, 3.4, 2.1, rssi: -63, ["mDNS", "ARP", "ICMPv6"],
            d => { Ports(d, 62078); d.AddIp(IPAddress.Parse("2a02:aa1:1023:6400:31c9:77de:5b20:8e4a")); });
        Wifi("F2:6C:3D:A1:B7:5E", "192.168.1.103", DeviceType.Phone, "Apple, Inc.", "Apple", "iPhone SE", ("dhcp", "Mias-iPhone"), Ap2Mac, 4.2, 2.8, rssi: -71, ["mDNS", "ARP", "DHCP"],
            d => { d.SetFlag(DeviceFlags.New); d.FirstSeen = DateTimeOffset.Now.AddMinutes(-18); });
        Wifi("F8:4D:89:5A:23:C7", "192.168.1.110", DeviceType.Laptop, "Apple, Inc.", "Apple", "MacBook Pro 14\" M3", ("mdns", "Alex-MBP"), Ap1Mac, 2.2, 0.3, rssi: -45, ["mDNS", "ARP", "ICMPv6", "NetBIOS"],
            d => { Ports(d, 22, 445, 5000, 7000); d.AddService(new ServiceInfo("udp", 5353, "Alex’s MacBook Pro", "_airplay._tcp")); d.AddService(new ServiceInfo("udp", 5353, "Alex’s MacBook Pro", "_smb._tcp")); d.OsGuess = "macOS 15 Sequoia"; });
        Wifi("5C:AA:FD:7B:12:40", "192.168.1.80", DeviceType.AudioStreamer, "Sonos, Inc.", "Sonos", "Sonos Arc", ("ssdp", "Sonos Arc — Living Room"), Ap1Mac, 2.4, 0.4, rssi: -48, ["SSDP", "mDNS", "ARP", "IGMP"],
            d => SonosCommon(d, "S19"));
        Wifi("94:9F:3E:21:A6:5B", "192.168.1.81", DeviceType.AudioStreamer, "Sonos, Inc.", "Sonos", "Sonos One SL", ("ssdp", "Sonos One — Kitchen"), Ap1Mac, 2.9, 0.4, rssi: -58, ["SSDP", "mDNS", "ARP", "IGMP"],
            d => SonosCommon(d, "S38"));
        Wifi("48:A6:B8:C3:4E:09", "192.168.1.82", DeviceType.AudioStreamer, "Sonos, Inc.", "Sonos", "Sonos Era 100", ("ssdp", "Sonos Era 100 — Bedroom"), Ap2Mac, 3.1, 0.4, rssi: -61, ["SSDP", "mDNS", "ARP", "IGMP"],
            d => SonosCommon(d, "S39"));
        Wifi("BA:7C:52:D9:0E:66", "192.168.1.104", DeviceType.Tablet, "Apple, Inc.", "Apple", "iPad Air (M2)", ("mdns", "Mias-iPad"), Ap2Mac, 3.6, 2.4, rssi: -66, ["mDNS", "ARP"],
            d => Ports(d, 62078));
        Wifi("08:A6:BC:3F:51:7D", "192.168.20.30", DeviceType.SmartHomeHub, "Amazon Technologies Inc.", "Amazon", "Echo Dot (5th Gen)", ("dhcp", "Echo-Kitchen"), Ap1Mac, 3.0, 1.9, rssi: -60, ["ARP", "SSDP", "mDNS", "DHCP"],
            d => { d.NativeVlan = 20; d.AddVlan(20); Ports(d, 4070, 55443); Mcast(d, SsdpGroup.ToString(), MdnsGroup.ToString()); });
        Wifi("D4:F5:47:1C:8B:2A", "192.168.20.31", DeviceType.MediaStreamer, "Google, Inc.", "Google", "Chromecast with Google TV", ("mdns", "Bedroom TV"), Ap2Mac, 3.3, 1.2, rssi: -64, ["mDNS", "SSDP", "ARP", "IGMP"],
            d => { d.NativeVlan = 20; d.AddVlan(20); Ports(d, 8008, 8009, 8443); d.AddService(new ServiceInfo("udp", 5353, "Bedroom TV", "_googlecast._tcp")); Mcast(d, MdnsGroup.ToString(), SsdpGroup.ToString()); });
        Wifi("C8:2B:96:4A:10:D3", "192.168.20.40", DeviceType.SmartPlug, "Shelly (Allterco Robotics)", "Shelly", "Shelly Plus Plug S", ("mdns", "shellyplusplugs-c82b964a10d3"), Ap1Mac, 4.5, 2.6, rssi: -67, ["mDNS", "ARP", "DHCP"],
            d => ShellyCommon(d));
        Wifi("C8:2B:96:4A:22:E7", "192.168.20.41", DeviceType.SmartPlug, "Shelly (Allterco Robotics)", "Shelly", "Shelly Plus Plug S", ("mdns", "shellyplusplugs-c82b964a22e7"), Ap2Mac, 5.1, 2.6, rssi: -74, ["mDNS", "ARP"],
            d => ShellyCommon(d));
        Wifi("E8:68:E7:B1:0C:94", "192.168.20.42", DeviceType.IoT, "Espressif Inc.", "Shelly", "Shelly Plus 1PM", ("mdns", "shellyplus1pm-garage"), Ap2Mac, 6.0, 3.0, rssi: -79, ["mDNS", "ARP"],
            d => { ShellyCommon(d); d.Model = "Shelly Plus 1PM"; });
        Wifi("18:B4:30:6D:2E:5F", "192.168.20.50", DeviceType.IoT, "Nest Labs Inc.", "Google Nest", "Nest Learning Thermostat", ("dhcp", "Nest-Hallway"), Ap1Mac, 4.8, 3.5, rssi: -69, ["ARP", "mDNS"],
            d => { d.NativeVlan = 20; d.AddVlan(20); Ports(d, 9543); });
        Wifi("34:3E:A4:71:9C:08", "192.168.20.51", DeviceType.Camera, "Ring LLC", "Ring", "Video Doorbell Pro 2", ("dhcp", "Ring-FrontDoor"), Ap1Mac, 7.5, 4.0, rssi: -80, ["ARP", "DHCP"],
            d => { d.NativeVlan = 20; d.AddVlan(20); _nodes[d.Mac].Loss = 0.04; });
        Wifi("A2:9F:6B:3D:E4:1C", "192.168.1.105", DeviceType.Phone, "Samsung Electronics Co.,Ltd", "Samsung", "Galaxy S24", ("dhcp", "Galaxy-S24"), Ap1Mac, 3.8, 2.0, rssi: -57, ["ARP", "DHCP", "mDNS"],
            d => d.AddIp(IPAddress.Parse("2a02:aa1:1023:6400:f1a2:b3c4:d5e6:7788")));

        // the rogue router has no business on VLAN 1 subnet 192.168.1.x — it hands out 192.168.0.x
        rogue.FirstSeen = DateTimeOffset.Now.AddMinutes(-7);
    }

    // ============================================================================================
    //  Device helpers
    // ============================================================================================

    private Device Add(Mac mac, string? ip, DeviceType type, string? oui, string? brand, string? model, (string Src, string Name)? host,
        Mac? parent, LinkKind kind, string? parentPort, string? childPort = null, long? speed = 1000, double link = 0.15, double proc = 0.1,
        int vlan = 1, double? poe = null, bool measured = false, double loss = 0.002, int ageDays = 30, bool noArp = false,
        string[]? protocols = null)
    {
        _builtMacs.Add(mac);
        var d = _devices.GetOrAdd(mac);
        if (ip is not null) _devices.Observe(mac, IPAddress.Parse(ip), "demo");
        else d.Touch();
        d.OuiVendor = oui;
        d.Brand = brand;
        d.Model = model;
        d.Type = type;
        d.TypeConfidence = Math.Round(0.82 + _rng.NextDouble() * 0.17, 2);
        d.IdentityConfidence = Math.Round(0.7 + _rng.NextDouble() * 0.29, 2);
        if (host is { } h) d.SetHostname(h.Src, h.Name);
        if (!SyntheticNodes.IsSynthetic(mac))
        {
            d.NativeVlan = vlan;
            d.AddVlan(vlan);
        }
        d.FirstSeen = DateTimeOffset.Now.AddDays(-ageDays).AddMinutes(-_rng.Next(0, 1440));
        d.LastSeen = DateTimeOffset.Now;
        d.LogoPath = FindLogo(brand);
        if (oui is not null) Ev(d, "oui", Fields.Vendor, oui, Confidence.Oui);
        if (brand is not null) Ev(d, "classifier", Fields.Brand, brand, Math.Max(0.6, d.IdentityConfidence));
        Ev(d, "classifier", Fields.DeviceType, type.ToString(), d.TypeConfidence);
        if (host is { } hh) Ev(d, hh.Src, Fields.Hostname, hh.Name, SourceConfidence(hh.Src));

        var node = new Node(mac)
        {
            Parent = parent, Kind = kind, ParentPort = parentPort, ChildPort = childPort, Speed = speed, Poe = poe,
            BaseLink = link, LinkLat = link, Proc = proc, Loss = loss, Measured = measured, NoArp = noArp,
        };
        _nodes[mac] = node;

        if (parent is { } p)
        {
            d.UpstreamMac = p;
            d.UpstreamPort = parentPort;
            Wire(p, mac, kind, parentPort, childPort, speed, link, measured, poe);
        }
        if (protocols is not null) AddProtocols(mac, protocols);
        return d;
    }

    private void Wifi(string mac, string ip, DeviceType type, string oui, string brand, string model, (string, string) host, Mac ap,
        double link, double proc, int rssi, string[] protocols, Action<Device>? extra = null)
    {
        var m = Mac.Parse(mac);
        bool isAp1 = ap == Ap1Mac;
        long phyRate = rssi > -55 ? 1201 : rssi > -68 ? 866 : 286;
        var d = Add(m, ip, type, oui, brand, model, host, ap, LinkKind.WifiAssoc, isAp1 ? "wlan1" : "wlan0", "wlan0", phyRate, link, proc,
            loss: rssi < -75 ? 0.025 : 0.005, ageDays: _rng.Next(3, 400), protocols: protocols);
        _nodes[m].Wifi = true;
        d.SetFlag(DeviceFlags.WifiClient);
        bool fiveG = rssi > -72;
        d.Wifi = new WifiAssociation("SpiderNet", ap.Offset(fiveG ? 2 : 1), fiveG ? (isAp1 ? 36 : 149) : (isAp1 ? 1 : 11),
            fiveG ? "5 GHz" : "2.4 GHz", rssi, fiveG ? "802.11ax" : "802.11n");
        if (d.Has(DeviceFlags.RandomizedMac)) Ev(d, "oui", "privateMac", "Locally administered (randomized) MAC", 1.0);
        extra?.Invoke(d);
    }

    private void SonosCommon(Device d, string model)
    {
        Ports(d, 1400, 1443);
        d.AddService(new ServiceInfo("udp", 5353, d.Hostname ?? "Sonos", "_sonos._tcp"));
        d.AddService(new ServiceInfo("udp", 5353, d.Hostname ?? "Sonos", "_spotify-connect._tcp"));
        d.AddService(new ServiceInfo("udp", 5353, d.Hostname ?? "Sonos", "_airplay._tcp"));
        Ev(d, "ssdp", Fields.ModelNumber, model, Confidence.Ssdp);
        Ev(d, "http", Fields.Firmware, "80.1-55240", Confidence.VendorProtocol);
        d.Firmware = "Sonos S2 16.4";
        Mcast(d, SsdpGroup.ToString(), MdnsGroup.ToString(), "239.255.255.251");
    }

    private void ShellyCommon(Device d)
    {
        d.NativeVlan = 20;
        d.AddVlan(20);
        Ports(d, 80);
        d.AddService(new ServiceInfo("udp", 5353, d.Hostname ?? "shelly", "_shelly._tcp"));
        d.AddService(new ServiceInfo("udp", 5353, d.Hostname ?? "shelly", "_http._tcp"));
        Ev(d, "http", Fields.Model, d.Model ?? "Shelly", Confidence.VendorProtocol);
        Ev(d, "http", Fields.Firmware, "1.4.4", Confidence.VendorProtocol);
        d.SetFlag(DeviceFlags.CleartextManagement);
        Mcast(d, MdnsGroup.ToString());
    }

    private void Wire(Mac parent, Mac child, LinkKind kind, string? parentPort, string? childPort, long? speed, double latency, bool measured,
        double? poe = null)
    {
        _topology.Upsert(parent, child, kind, l =>
        {
            l.SetPort(parent, parentPort);
            l.SetPort(child, childPort);
            l.SpeedMbps = speed;
            l.Duplex = speed is null ? null : speed <= 100 && kind == LinkKind.BridgeFdb && _rng.NextDouble() < 0.1 ? "half" : "full";
            l.PoeWatts = poe;
            l.LatencyMs = Math.Round(latency, 3);
            l.LatencyOrigin = measured ? LatencyOrigin.Measured : LatencyOrigin.Estimated;
            l.Confidence = kind switch
            {
                LinkKind.InferredUnmanagedSwitch => 0.7,
                LinkKind.BridgeFdb => 0.95,
                LinkKind.WifiAssoc => 0.9,
                _ => 1.0,
            };
        });
    }

    private static void Ports(Device d, params int[] ports)
    {
        foreach (var p in ports) d.SetPort(new PortInfo(p, "tcp", PortState.Open, ServiceName(p), null, null));
    }

    private static void Mcast(Device d, params string[] groups)
    {
        foreach (var g in groups) d.AddMulticastGroup(IPAddress.Parse(g));
    }

    private static void Vlans(Device d, params int[] vlans)
    {
        foreach (var v in vlans) d.AddVlan(v);
    }

    private static void Ev(Device d, string source, string field, string value, double confidence) => d.AddEvidence(source, field, value, confidence);

    private static void Cert(Device d, int port, string cn, string[] sans, string issuer, bool self, int days, string? issuerOrg = null)
    {
        var notAfter = DateTime.UtcNow.AddDays(days);
        var notBefore = days > 0 ? DateTime.UtcNow.AddDays(-Math.Min(400, days / 2 + 30)) : DateTime.UtcNow.AddDays(days - 730);
        var serial = Convert.ToHexString(BitConverter.GetBytes(d.Mac.Value ^ (ulong)port));
        d.SetCertificate(new TlsCertInfo(port, "CN=" + cn, cn, sans, "CN=" + issuer, issuerOrg ?? issuer, notBefore, notAfter, serial,
            Convert.ToHexString(BitConverter.GetBytes(d.Mac.Value * 2654435761UL)) + "A1B2C3D4E5F60718293A", self));
    }

    private void AddProtocols(Mac mac, params string[] protocols)
    {
        foreach (var p in protocols)
        {
            if (!_protocolSources.TryGetValue(p, out var list)) _protocolSources[p] = list = new List<Mac>();
            if (!list.Contains(mac)) list.Add(mac);
        }
    }

    private static double SourceConfidence(string src) => src switch
    {
        "mdns" => Confidence.Mdns,
        "ssdp" => Confidence.Ssdp,
        "dhcp" => Confidence.Dhcp,
        "netbios" => Confidence.NetBios,
        "snmp" => Confidence.Snmp,
        "lldp" => Confidence.Lldp,
        "user" => Confidence.User,
        _ => 0.6,
    };

    private static string? ServiceName(int port) => port switch
    {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 53 => "domain", 80 => "http", 111 => "rpcbind", 135 => "msrpc", 139 => "netbios-ssn",
        443 => "https", 445 => "microsoft-ds", 515 => "printer", 554 => "rtsp", 631 => "ipp", 1400 => "sonos-http", 1443 => "sonos-https",
        1883 => "mqtt", 3074 => "xbox-live", 3128 => "spiceproxy", 3389 => "ms-wbt-server", 4070 => "spotify", 4357 => "ha-observer",
        5000 => "http-mgmt", 5001 => "https-mgmt", 7000 => "airplay", 7100 => "airplay-ctl", 8000 => "hik-sdk", 8001 => "samsung-ws",
        8002 => "samsung-wss", 8006 => "proxmox", 8008 => "cast-http", 8009 => "cast", 8123 => "home-assistant", 8443 => "https-alt",
        9000 => "portainer", 9100 => "jetdirect", 9197 => "dial", 9543 => "nest", 32400 => "plex", 49152 => "upnp", 55443 => "alexa",
        62078 => "iphone-sync", _ => null,
    };

    private string? FindLogo(string? brand)
    {
        if (string.IsNullOrWhiteSpace(brand)) return null;
        if (_logoIndex is null)
        {
            _logoIndex = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string[] ext = [".png", ".svg", ".ico", ".jpg", ".jpeg", ".webp"];
                foreach (var f in Directory.EnumerateFiles(AppPaths.Logos))
                    if (ext.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
                        _logoIndex.TryAdd(Path.GetFileNameWithoutExtension(f), f);
            }
            catch (Exception ex) { _log?.LogDebug(ex, "Logo cache not readable"); }
        }
        if (_logoIndex.TryGetValue(brand, out var path)) return path;
        var compact = new string(brand.Where(char.IsLetterOrDigit).ToArray());
        if (_logoIndex.TryGetValue(compact, out path)) return path;
        var first = brand.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        return _logoIndex.TryGetValue(first, out path) ? path : null;
    }

    // ============================================================================================
    //  Switch tables, pairs, network state, alerts
    // ============================================================================================

    private void BuildSwitchTables()
    {
        var now = DateTimeOffset.Now;
        BuildSwitch(CoreMac, 24, i => $"g{i}", now);
        BuildSwitch(AccessMac, 8, i => $"Port {i}", now);

        _network.AddNeighbor(new NeighborEntry(CoreMac, "g24", GatewayMac, GatewayMac.ToString(), "SFP+ 1", "UDM-Pro", IPAddress.Parse("192.168.1.1"),
            "UniFi Dream Machine Pro", "Router, Bridge", "LLDP", now));
        _network.AddNeighbor(new NeighborEntry(CoreMac, "g21", AccessMac, AccessMac.ToString(), "Port 8", "usw-lite-office", IPAddress.Parse("192.168.1.3"),
            "USW-Lite-8-PoE, 7.1.26", "Bridge", "LLDP", now));
        _network.AddNeighbor(new NeighborEntry(CoreMac, "g1", Ap1Mac, Ap1Mac.ToString(), "eth0", "ap-living-room", IPAddress.Parse("192.168.1.4"),
            "U6-Pro, 6.6.77", "Bridge, WLAN Access Point", "LLDP", now));
        _network.AddNeighbor(new NeighborEntry(CoreMac, "g2", Ap2Mac, Ap2Mac.ToString(), "eth0", "ap-upstairs", IPAddress.Parse("192.168.1.5"),
            "U6-Lite, 6.6.77", "Bridge, WLAN Access Point", "LLDP", now));
        _network.AddNeighbor(new NeighborEntry(AccessMac, "Port 2", Mac.Parse("80:5E:C0:44:91:0D"), null, "WAN PORT", "SIP-T54W", IPAddress.Parse("192.168.40.20"),
            "Yealink SIP-T54W 96.86.0.70", "Telephone", "LLDP-MED", now));
        _network.AddNeighbor(new NeighborEntry(GatewayMac, "SFP+ 1", CoreMac, CoreMac.ToString(), "g24", "core-sw-01", IPAddress.Parse("192.168.1.2"),
            "GS724Tv4", "Bridge", "LLDP", now));
    }

    private void BuildSwitch(Mac sw, int portCount, Func<int, string> portName, DateTimeOffset now)
    {
        var swNode = _nodes[sw];
        var children = _nodes.Values.Where(n => n.Parent == sw && n.ParentPort is not null).ToDictionary(n => n.ParentPort!, n => n);
        var ports = new List<SwitchPortInfo>();
        for (int i = 1; i <= portCount; i++)
        {
            var name = portName(i);
            bool isUplink = swNode.ChildPort == name;
            children.TryGetValue(name, out var child);
            long? speed = isUplink ? swNode.Speed : child?.Speed;
            bool up = isUplink || child is not null;
            string? alias = isUplink ? "Uplink" : child is not null && _devices.TryGet(child.Mac, out var cd) ? cd.DisplayName : null;
            int pvid = child is not null && _devices.TryGet(child.Mac, out var pd) ? pd.NativeVlan ?? 1 : 1;
            ports.Add(new SwitchPortInfo(sw, i, name, alias, up ? speed : null, up, up ? "full" : null, up ? child?.Poe : null, pvid));
        }
        _network.SetSwitchPorts(sw, ports);

        var fdb = new List<FdbEntry>();
        foreach (var n in _nodes.Values)
        {
            if (n.Mac == sw || SyntheticNodes.IsSynthetic(n.Mac)) continue;
            var port = PortTowards(sw, n.Mac);
            if (port is null) continue;
            int? vlan = _devices.TryGet(n.Mac, out var d) ? d.NativeVlan : null;
            fdb.Add(new FdbEntry(sw, port, PortIndex(port), n.Mac, vlan ?? 1, now));
        }
        _network.SetFdb(sw, fdb);
    }

    /// <summary>The switch port through which <paramref name="target"/> is reached from <paramref name="sw"/>.</summary>
    private string? PortTowards(Mac sw, Mac target)
    {
        var cur = target;
        for (int guard = 0; guard < 16; guard++)
        {
            if (!_nodes.TryGetValue(cur, out var n) || n.Parent is not { } p) break;
            if (p == sw) return n.ParentPort;
            cur = p;
        }
        return _nodes[sw].ChildPort; // not below this switch: reached via the uplink
    }

    private static int? PortIndex(string port)
    {
        var digits = new string(port.Reverse().TakeWhile(char.IsDigit).Reverse().ToArray());
        return int.TryParse(digits, out var i) ? i : null;
    }

    private void BuildPairs()
    {
        _pairs.Clear();
        var seen = new HashSet<(Mac, Mac)>();
        void P(Mac a, Mac b, LatencyOrigin o, string method)
        {
            if (a == b) return;
            var key = a.Value <= b.Value ? (a, b) : (b, a);
            if (seen.Add(key)) _pairs.Add((a, b, o, method));
        }

        var nasMac = Mac.Parse("00:11:32:9C:44:21");
        var pveMac = Mac.Parse("BC:24:11:00:AA:01");
        P(ThisHostMac, nasMac, LatencyOrigin.Measured, "tcp-syn-passive");
        P(ThisHostMac, pveMac, LatencyOrigin.Measured, "tcp-syn-passive");
        P(ThisHostMac, Mac.Parse("BC:24:11:3E:51:A2"), LatencyOrigin.Measured, "tcp-syn-passive");
        P(Mac.Parse("F8:4D:89:5A:23:C7"), nasMac, LatencyOrigin.Measured, "tcp-syn-passive");
        P(Mac.Parse("5C:AA:FD:7B:12:40"), nasMac, LatencyOrigin.Measured, "tcp-syn-passive");

        // switches / gateway ping their direct neighbours (SNMP DISMAN-PING-MIB)
        foreach (var n in _nodes.Values)
            if (n.Parent is { } p && (p == CoreMac || p == AccessMac || p == GatewayMac) && !SyntheticNodes.IsSynthetic(n.Mac))
                P(p, n.Mac, LatencyOrigin.Measured, "snmp-ping");

        var all = _nodes.Keys.ToList();
        int i = 0;
        foreach (var m in all)
        {
            P(ThisHostMac, m, LatencyOrigin.Estimated, "path-sum");
            P(GatewayMac, m, i++ % 3 == 0 ? LatencyOrigin.Measured : LatencyOrigin.Estimated, i % 3 == 1 ? "snmp-ping" : "path-sum");
        }
        for (int k = 0; k < 30; k++)
            P(all[_rng.Next(all.Count)], all[_rng.Next(all.Count)], LatencyOrigin.Estimated, "path-sum");
        RefreshPairs();
    }

    private void FixGatewayMethods()
    {
        // keep Method consistent with Origin for the gateway pairs
        for (int i = 0; i < _pairs.Count; i++)
        {
            var p = _pairs[i];
            if (p.Origin == LatencyOrigin.Measured && p.Method == "path-sum") _pairs[i] = p with { Method = "snmp-ping" };
            if (p.Origin == LatencyOrigin.Estimated && p.Method != "path-sum") _pairs[i] = p with { Method = "path-sum" };
        }
    }

    private void RefreshPairs()
    {
        FixGatewayMethods();
        var now = DateTimeOffset.Now;
        foreach (var (a, b, origin, method) in _pairs)
        {
            double path = PathSum(a, b);
            double proc = _nodes.TryGetValue(b, out var nb) ? nb.Proc : 0;
            double ms = origin == LatencyOrigin.Measured
                ? path + proc * (0.8 + _rng.NextDouble() * 0.4) + Noise(0.02 + path * 0.05)
                : path + proc;
            _topology.SetPairLatency(new PairLatency(a, b, Math.Round(Math.Max(0.01, ms), 3), origin, method, now));
        }
    }

    /// <summary>Sum of current link latencies along the tree path between two nodes.</summary>
    private double PathSum(Mac a, Mac b)
    {
        var up = new Dictionary<Mac, double>();
        double acc = 0;
        var cur = a;
        for (int g = 0; g < 16; g++)
        {
            up[cur] = acc;
            if (!_nodes.TryGetValue(cur, out var n) || n.Parent is not { } p) break;
            acc += n.LinkLat;
            cur = p;
        }
        acc = 0;
        cur = b;
        for (int g = 0; g < 16; g++)
        {
            if (up.TryGetValue(cur, out var fromA)) return fromA + acc;
            if (!_nodes.TryGetValue(cur, out var n) || n.Parent is not { } p) break;
            acc += n.LinkLat;
            cur = p;
        }
        return acc;
    }

    private void BuildNetworkState()
    {
        var now = DateTimeOffset.Now;
        int Count(string prefix) => _devices.All.Count(d => d.PrimaryIPv4?.ToString().StartsWith(prefix, StringComparison.Ordinal) == true);

        _network.AddOrGetSegment(IPAddress.Parse("192.168.1.0"), 24, "adapter", s =>
        {
            s.IsLocal = true; s.VlanId = 1; s.VlanName = "Default"; s.Gateway = IPAddress.Parse("192.168.1.1");
            s.HostsFound = Count("192.168.1."); s.LastScanned = now.AddMinutes(-2);
        });
        _network.AddOrGetSegment(IPAddress.Parse("192.168.20.0"), 24, "snmp-routes", s =>
        {
            s.VlanId = 20; s.VlanName = "IoT"; s.Gateway = IPAddress.Parse("192.168.20.1"); s.HostsFound = Count("192.168.20."); s.LastScanned = now.AddMinutes(-2);
        });
        _network.AddOrGetSegment(IPAddress.Parse("192.168.30.0"), 24, "dhcp-121", s =>
        {
            s.VlanId = 30; s.VlanName = "Cameras"; s.Gateway = IPAddress.Parse("192.168.30.1"); s.HostsFound = Count("192.168.30."); s.LastScanned = now.AddMinutes(-2);
        });
        _network.AddOrGetSegment(IPAddress.Parse("192.168.40.0"), 24, "lldp-med", s =>
        {
            s.VlanId = 40; s.VlanName = "Voice"; s.Gateway = IPAddress.Parse("192.168.40.1"); s.HostsFound = Count("192.168.40.");
        });
        _network.AddOrGetSegment(IPAddress.Parse("10.0.10.0"), 24, "traceroute", s =>
        {
            s.VlanName = "Lab"; s.Gateway = IPAddress.Parse("10.0.10.1"); s.ScanEnabled = false;
        });

        _network.AddVlan(new VlanInfo(1, "Default", "lldp", Native: true, Voice: false));
        _network.AddVlan(new VlanInfo(20, "IoT", "snmp", false, false));
        _network.AddVlan(new VlanInfo(30, "Cameras", "snmp", false, false));
        _network.AddVlan(new VlanInfo(40, "Voice", "lldp", false, Voice: true));

        _network.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("192.168.1.1"), GatewayMac, IPAddress.Parse("192.168.1.142"), IPAddress.Parse("192.168.1.1"),
            [IPAddress.Parse("192.168.1.32"), IPAddress.Parse("1.1.1.1")], IPAddress.Parse("255.255.255.0"), TimeSpan.FromHours(24), now.AddMinutes(-3), false));
        _network.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("192.168.0.1"), Mac.Parse("50:C7:BF:1A:2B:3C"), IPAddress.Parse("192.168.0.100"),
            IPAddress.Parse("192.168.0.1"), [IPAddress.Parse("192.168.0.1")], IPAddress.Parse("255.255.255.0"), TimeSpan.FromHours(2), now.AddMinutes(-6), true));

        _network.AddStp(new StpInfo("8000.A040A05C1120", CoreMac, 32768, 0, "8000.A040A05C1120", CoreMac, "RSTP", now));
        _network.AddStp(new StpInfo("8000.A040A05C1120", CoreMac, 32768, 20000, "8000.F492BFA83041", AccessMac, "RSTP", now));
        _network.IgmpQuerier = GatewayMac;
        _network.NicPassesVlanTags = false;

        _network.WifiNetworks = BuildWifi(now);

        _network.Wan = new WanInfo(IPAddress.Parse("84.212.47.139"), "Connected", "IP_Routed", TimeSpan.FromDays(13).Add(TimeSpan.FromHours(7.3)),
            "UniFi Dream Machine Pro", "UPnP IGD",
            [
                new PortMapping("TCP", 32400, IPAddress.Parse("192.168.1.20"), 32400, "Plex Media Server", true, null, null),
                new PortMapping("UDP", 3074, IPAddress.Parse("192.168.1.60"), 3074, "Xbox Live", true, TimeSpan.FromHours(1), null),
                new PortMapping("TCP", 5001, IPAddress.Parse("192.168.1.20"), 5001, "Synology DSM", true, null, null),
                new PortMapping("UDP", 51820, IPAddress.Parse("192.168.1.40"), 51820, "WireGuard", true, null, null),
                new PortMapping("TCP", 8080, IPAddress.Parse("192.168.1.71"), 80, "Old printer web (stale)", false, TimeSpan.Zero, null),
            ], now);

        _network.InternetPath =
        [
            new TracerouteHop(1, IPAddress.Parse("192.168.1.1"), 0.41, "unifi.local", GatewayMac),
            new TracerouteHop(2, IPAddress.Parse("84.212.32.1"), 3.9, "cpe-gw.isp.example.net", null),
            new TracerouteHop(3, IPAddress.Parse("10.250.4.17"), 5.2, null, null),
            new TracerouteHop(4, IPAddress.Parse("195.159.5.33"), 6.1, "ae2-osl-core1.isp.example.net", null),
            new TracerouteHop(5, null, null, null, null),
            new TracerouteHop(6, IPAddress.Parse("80.239.193.86"), 8.7, "osl-b2-link.ip.twelve99.net", null),
            new TracerouteHop(7, IPAddress.Parse("162.158.92.2"), 9.4, null, null),
            new TracerouteHop(8, IPAddress.Parse("1.1.1.1"), 9.6, "one.one.one.one", null),
        ];

        var rogueMac = Mac.Parse("50:C7:BF:1A:2B:3C");
        _network.Health = new HealthReport(now, 86,
        [
            new HealthCheckResult("gw", "Gateway reachability", HealthStatus.Pass, 100, "Gateway answers ARP in 0.4 ms and ICMP in 0.5 ms", "0% loss over 60 probes", GatewayMac),
            new HealthCheckResult("dns-latency", "DNS resolver latency", HealthStatus.Pass, 95, "Local resolver 4.2 ms, 1.1.1.1 9.8 ms", "Resolver 192.168.1.32 (Pi-hole) is faster than public DNS."),
            new HealthCheckResult("dns-hijack", "DNS hijack check", HealthStatus.Pass, 100, "Answers match 1.1.1.1 and 8.8.8.8 for 12 test names"),
            new HealthCheckResult("mtu", "MTU black hole", HealthStatus.Pass, 100, "1500 bytes DF passes to 1.1.1.1; jumbo 9000 passes on LAN"),
            new HealthCheckResult("cleartext", "Cleartext management", HealthStatus.Warn, 60, "4 devices expose Telnet/HTTP/FTP management",
                "Brother HL-2270DW: telnet 23, ftp 21; Shelly plugs: HTTP without auth.", Mac.Parse("00:80:77:4D:5E:6F")),
            new HealthCheckResult("certs", "Expired certificates", HealthStatus.Warn, 70, "1 expired TLS certificate", "cam-backyard (192.168.30.12:443) expired 120 days ago.",
                Mac.Parse("C0:56:E3:4A:10:02")),
            new HealthCheckResult("smbv1", "SMBv1", HealthStatus.Pass, 100, "No SMBv1 servers found"),
            new HealthCheckResult("snmp", "Default SNMP community", HealthStatus.Warn, 65, "2 devices answer to community 'public'", "HP LaserJet M454dw, Brother HL-2270DW",
                Mac.Parse("3C:52:82:7B:19:E0")),
            new HealthCheckResult("igmp", "IGMP querier", HealthStatus.Pass, 100, "Querier present: UDM-Pro (192.168.1.1)", null, GatewayMac),
            new HealthCheckResult("rogue-dhcp", "Rogue DHCP", HealthStatus.Fail, 0, "Second DHCP server 192.168.0.1 (TP-Link TL-WR902AC) on g12",
                "Offers 192.168.0.100 with router 192.168.0.1. Unplug the travel router or disable its DHCP server.", rogueMac),
            new HealthCheckResult("bcast", "Broadcast ratio", HealthStatus.Pass, 90, "Broadcast 11% of traffic (threshold 15%)"),
            new HealthCheckResult("bufferbloat", "Bufferbloat", HealthStatus.Skipped, 0, "Not run — start it from the Health view (takes ~20 s)"),
        ]);
    }

    private IReadOnlyList<WifiNetwork> BuildWifi(DateTimeOffset now)
    {
        static int Freq(string band, int ch) => band switch { "2.4 GHz" => 2407 + 5 * ch, "6 GHz" => 5950 + 5 * ch, _ => 5000 + 5 * ch };
        WifiNetwork W(string ssid, Mac bssid, int ch, string band, int rssi, string sec, string phy, string? vendor, bool conn, int width) =>
            new(ssid, bssid, ch, Freq(band, ch), band, rssi, Math.Clamp(2 * (rssi + 100), 0, 100), sec, phy, vendor, conn, width, now);

        var avm = Mac.Parse("3C:A6:2F:81:05:D2");
        var hua = Mac.Parse("E4:A8:B6:0F:33:91");
        return
        [
            W("SpiderNet", Ap1Mac.Offset(1), 1, "2.4 GHz", -47, "WPA2/WPA3-Personal", "802.11ax", "Ubiquiti", false, 20),
            W("SpiderNet", Ap1Mac.Offset(2), 36, "5 GHz", -42, "WPA2/WPA3-Personal", "802.11ax", "Ubiquiti", true, 80),
            W("SpiderNet", Ap1Mac.Offset(3), 37, "6 GHz", -55, "WPA3-Personal", "802.11ax", "Ubiquiti", false, 160),
            W("SpiderNet", Ap2Mac.Offset(1), 11, "2.4 GHz", -61, "WPA2/WPA3-Personal", "802.11ax", "Ubiquiti", false, 20),
            W("SpiderNet", Ap2Mac.Offset(2), 149, "5 GHz", -58, "WPA2/WPA3-Personal", "802.11ax", "Ubiquiti", false, 80),
            W("SpiderNet-IoT", Ap1Mac.Offset(4), 1, "2.4 GHz", -48, "WPA2-Personal", "802.11n", "Ubiquiti", false, 20),
            W("FRITZ!Box 7590 XY", avm, 6, "2.4 GHz", -72, "WPA2-Personal", "802.11ax", "AVM", false, 40),
            W("FRITZ!Box 7590 XY", avm.Offset(1), 44, "5 GHz", -78, "WPA2-Personal", "802.11ax", "AVM", false, 80),
            W("Telia-5G-4F2A", hua, 6, "2.4 GHz", -69, "WPA2-Personal", "802.11ax", "Huawei", false, 20),
            W("Telia-5G-4F2A", hua.Offset(1), 100, "5 GHz", -81, "WPA2/WPA3-Personal", "802.11ax", "Huawei", false, 160),
            W("DIRECT-7A-HP M454 LaserJet", Mac.Parse("3E:52:82:7B:19:E1"), 6, "2.4 GHz", -52, "WPA2-Personal", "802.11n", "HP", false, 20),
            W("", Mac.Parse("9A:3B:51:0C:72:10"), 11, "2.4 GHz", -84, "WPA2-Personal", "802.11n", null, false, 20),
            W("Neighbour-Guest", Mac.Parse("60:22:32:AB:19:4C"), 1, "2.4 GHz", -88, "Open", "802.11n", "Ubiquiti", false, 20),
            W("NETGEAR-Orbi-77", Mac.Parse("94:A6:7E:5C:2D:08"), 44, "5 GHz", -74, "WPA2-Personal", "802.11ac", "Netgear", false, 80),
            W("Starlink", Mac.Parse("74:24:9F:1A:C5:63"), 149, "5 GHz", -86, "WPA2-Personal", "802.11be", "Starlink", false, 80),
        ];
    }

    private void BuildAlerts()
    {
        var now = DateTimeOffset.Now;
        void A(AlertSeverity s, AlertKind k, string title, string details, Mac? src, TimeSpan ago, double? rate = null) =>
            _alerts.Raise(Alert.Create(s, k, title, details, src, rate) with { Time = now - ago }, TimeSpan.Zero);

        A(AlertSeverity.Info, AlertKind.NewDevice, "New device: Mias-iPhone", "Randomized MAC F2:6C:3D:A1:B7:5E joined SpiderNet (2.4 GHz) on ap-upstairs",
            Mac.Parse("F2:6C:3D:A1:B7:5E"), TimeSpan.FromMinutes(18));
        A(AlertSeverity.Warning, AlertKind.ExpiredCertificate, "Expired TLS certificate on cam-backyard", "192.168.30.12:443 certificate CN=IPC expired 120 days ago",
            Mac.Parse("C0:56:E3:4A:10:02"), TimeSpan.FromMinutes(14));
        A(AlertSeverity.Warning, AlertKind.CleartextManagement, "Telnet management on Brother HL-2270DW", "Telnet (23) and FTP (21) open on 192.168.1.71",
            Mac.Parse("00:80:77:4D:5E:6F"), TimeSpan.FromMinutes(12));
        A(AlertSeverity.Info, AlertKind.DeviceOffline, "Device offline: WORK-LAPTOP", "No ARP reply for 5 minutes (last seen on usw-lite-office Port 6)",
            Mac.Parse("A4:BB:6D:2F:C0:18"), TimeSpan.FromMinutes(9));
        A(AlertSeverity.Critical, AlertKind.RogueDhcp, "Rogue DHCP server 192.168.0.1", "TP-Link TL-WR902AC on core-sw-01 g12 offered 192.168.0.100 (router 192.168.0.1)",
            Mac.Parse("50:C7:BF:1A:2B:3C"), TimeSpan.FromMinutes(6));
        A(AlertSeverity.Warning, AlertKind.LatencySpike, "Latency spike: Ring-FrontDoor", "ICMP RTT jumped from 9 ms to 148 ms (loss 4%)",
            Mac.Parse("34:3E:A4:71:9C:08"), TimeSpan.FromMinutes(3));
        A(AlertSeverity.Warning, AlertKind.DefaultSnmpCommunity, "SNMP community 'public' accepted", "HP Color LaserJet Pro M454dw answers SNMPv2c with community 'public'",
            Mac.Parse("3C:52:82:7B:19:E0"), TimeSpan.FromMinutes(2));
    }

    private void PrefillLatency()
    {
        var now = DateTimeOffset.Now;
        foreach (var n in _nodes.Values)
        {
            if (n.Mac == ThisHostMac || !_devices.TryGet(n.Mac, out var d)) continue;
            for (int i = 0; i < 60; i++)
            {
                var t = now - TimeSpan.FromSeconds(60 - i);
                var (arp, icmp) = Sample(n, d.State == DeviceState.Offline);
                if (!n.NoArp) d.Latency.Add(new LatencySample(t, LatencyKind.Arp, arp));
                if (!SyntheticNodes.IsSynthetic(n.Mac) || n.Mac == InternetMac) d.Latency.Add(new LatencySample(t, LatencyKind.Icmp, icmp));
            }
        }
    }

    // ============================================================================================
    //  Simulation
    // ============================================================================================

    private double Noise(double sigma)
    {
        // Box–Muller
        double u1 = 1.0 - _rng.NextDouble(), u2 = _rng.NextDouble();
        return sigma * Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2 * Math.PI * u2);
    }

    private (double? Arp, double? Icmp) Sample(Node n, bool offline)
    {
        if (offline || _rng.NextDouble() < n.Loss) return (null, null);
        if (n.Mac == InternetMac)
        {
            double wan = PathSum(ThisHostMac, InternetMac) + Math.Abs(Noise(0.8)) + (_rng.NextDouble() < 0.03 ? _rng.Next(8, 30) : 0);
            return (null, Math.Round(wan, 3));
        }
        double path = PathSum(ThisHostMac, n.Mac);
        double arp = path + n.Proc * (0.85 + _rng.NextDouble() * 0.3) + Math.Abs(Noise(n.Wifi ? 0.6 : 0.03));
        if (n.Wifi && _rng.NextDouble() < 0.04) arp += _rng.Next(15, 90); // power-save wake-up
        double icmp = arp * 1.08 + 0.04 + Math.Abs(Noise(n.Wifi ? 0.4 : 0.02));
        if (_rng.NextDouble() < n.Loss) return (Math.Round(arp, 3), null);
        return (Math.Round(Math.Max(0.03, arp), 3), Math.Round(Math.Max(0.05, icmp), 3));
    }

    public void Tick()
    {
        var activities = new List<PacketActivity>();
        var alertsToRaise = new List<Alert>();
        TrafficSnapshot snap;
        List<Device> changed = new();
        lock (_sync)
        {
            if (!_built) BuildCore(42);
            _tick++;
            var now = DateTimeOffset.Now;

            // 1) link jitter
            foreach (var n in _nodes.Values)
            {
                if (n.Parent is null) continue;
                double j = n.Wifi ? Noise(n.BaseLink * 0.25) : n.Kind == LinkKind.Wan ? Noise(0.9) : Noise(n.BaseLink * 0.08);
                n.LinkLat = Math.Max(n.BaseLink * 0.5, n.BaseLink + j);
            }
            foreach (var l in _topology.Links)
            {
                var child = _nodes.TryGetValue(l.A, out var na) && na.Parent == l.B ? na : _nodes.TryGetValue(l.B, out var nb) && nb.Parent == l.A ? nb : null;
                if (child is null) continue;
                _topology.Upsert(l.A, l.B, l.Kind, x => x.LatencyMs = Math.Round(child.LinkLat, 3));
            }

            // 2) online/offline flips
            if (_tick >= _nextFlipTick)
            {
                _nextFlipTick = _tick + _rng.Next(60, 90);
                var candidates = _nodes.Values.Where(n => n.Wifi && n.OfflineTicks == 0).ToList();
                if (candidates.Count > 0)
                {
                    var n = candidates[_rng.Next(candidates.Count)];
                    n.OfflineTicks = _rng.Next(8, 16);
                    if (_devices.TryGet(n.Mac, out var d))
                    {
                        d.State = DeviceState.Offline;
                        alertsToRaise.Add(Alert.Create(AlertSeverity.Info, AlertKind.DeviceOffline, $"Device offline: {d.DisplayName}",
                            $"No ARP/ICMP reply from {d.PrimaryIPv4} for 3 probes", d.Mac));
                    }
                }
            }

            // 3) latency samples
            foreach (var n in _nodes.Values)
            {
                if (n.Mac == ThisHostMac || !_devices.TryGet(n.Mac, out var d)) continue;
                if (n.OfflineTicks > 0 && n.OfflineTicks < int.MaxValue / 4)
                {
                    n.OfflineTicks--;
                    if (n.OfflineTicks == 0) { d.State = DeviceState.Online; d.Touch(); }
                }
                bool offline = d.State == DeviceState.Offline;
                var (arp, icmp) = Sample(n, offline);
                if (!n.NoArp) d.Latency.Add(LatencyKind.Arp, arp);
                if (!SyntheticNodes.IsSynthetic(n.Mac) || n.Mac == InternetMac) d.Latency.Add(LatencyKind.Icmp, icmp);
                if (!offline && (arp ?? icmp) is not null) d.LastSeen = now;
                changed.Add(d);
            }

            // 4) device↔device pairs
            RefreshPairs();

            // 5) events: new device, storm
            if (_tick >= _nextNewDeviceTick && _extraDevices < 6)
            {
                _nextNewDeviceTick = _tick + _rng.Next(25, 40);
                var d = AddExtraDevice();
                if (d is not null)
                {
                    alertsToRaise.Add(Alert.Create(AlertSeverity.Info, AlertKind.NewDevice, $"New device: {d.DisplayName}",
                        $"{d.Mac} ({d.OuiVendor ?? "unknown vendor"}) appeared at {d.PrimaryIPv4} via {(d.UpstreamMac == Ap1Mac ? "ap-living-room" : "ap-upstairs")}", d.Mac));
                    activities.Add(new PacketActivity(d.Mac, "DHCP", now));
                    activities.Add(new PacketActivity(d.Mac, "ARP", now));
                }
            }
            if (_tick >= _nextStormTick)
            {
                _nextStormTick = _tick + _rng.Next(45, 70);
                var iot = _nodes.Values.Where(n => _devices.TryGet(n.Mac, out var d) && d.Type is DeviceType.SmartPlug or DeviceType.IoT or DeviceType.Camera)
                    .Select(n => n.Mac).ToList();
                if (iot.Count > 0)
                {
                    _stormSource = iot[_rng.Next(iot.Count)];
                    _stormTicks = 6;
                    double rate = 1400 + _rng.Next(0, 1600);
                    var name = _devices.TryGet(_stormSource, out var sd) ? sd.DisplayName : _stormSource.ToString();
                    alertsToRaise.Add(Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, $"Broadcast storm from {name}",
                        $"{rate:0} pps broadcast from {_stormSource} (threshold {_settings.StormPerMacPps:0} pps). Broadcast ratio rose to {38 + _rng.Next(0, 20)}%.",
                        _stormSource, rate));
                }
            }

            // 6) traffic
            snap = BuildTraffic(now);
            if (_stormTicks > 0)
            {
                _stormTicks--;
                for (int i = 0; i < 6; i++) activities.Add(new PacketActivity(_stormSource, "ARP", now));
            }
            _network.LastTraffic = snap;
        }

        foreach (var d in changed) _devices.NotifyChanged(d, "latency");
        _topology.NotifyChanged();
        foreach (var a in alertsToRaise) _alerts.Raise(a, TimeSpan.Zero);
        _bus.Publish(snap);
        foreach (var a in activities) _bus.Publish(a);
    }

    private TrafficSnapshot BuildTraffic(DateTimeOffset now)
    {
        double t = _tick / 20.0;
        double total = 210 + 70 * Math.Sin(t) + 30 * Math.Sin(t * 2.7 + 1) + Noise(15);
        double stormBoost = _stormTicks > 0 ? 900 + _rng.Next(0, 600) : 0;
        total = Math.Max(60, total);
        double bcast = total * (0.08 + 0.05 * (0.5 + 0.5 * Math.Sin(t * 1.3))) + stormBoost;
        double mcast = total * (0.18 + 0.04 * Math.Sin(t * 0.7));
        total += stormBoost;
        double unicast = Math.Max(0, total - bcast - mcast);

        double arp = bcast * 0.62, dhcp = bcast * 0.04, netbios = bcast * 0.18;
        double mdns = mcast * 0.42, ssdp = mcast * 0.31, igmp = mcast * 0.05, lldp = 0.25, stp = 0.5;
        double ipv6 = unicast * 0.14 + mcast * 0.1;
        double ipv4 = Math.Max(0, total - arp - dhcp - netbios - mdns - ssdp - igmp - lldp - stp - ipv6);
        var byProto = new Dictionary<string, double>
        {
            ["IPv4"] = Math.Round(ipv4, 1), ["IPv6"] = Math.Round(ipv6, 1), ["ARP"] = Math.Round(arp, 1), ["mDNS"] = Math.Round(mdns, 1),
            ["SSDP"] = Math.Round(ssdp, 1), ["NetBIOS"] = Math.Round(netbios, 1), ["IGMP"] = Math.Round(igmp, 1), ["DHCP"] = Math.Round(dhcp, 1),
            ["STP"] = stp, ["LLDP"] = lldp,
        };

        (string Mac, double Share, double Bshare)[] talkers =
        [
            ("00:11:32:9C:44:21", 0.22, 0.01), ("D8:BB:C1:7A:3F:10", 0.17, 0.02), ("F0:B3:EC:12:88:5A", 0.11, 0.0), ("BC:24:11:00:AA:01", 0.08, 0.01),
            ("5C:AA:FD:7B:12:40", 0.06, 0.02), ("D4:F5:47:1C:8B:2A", 0.05, 0.03), ("98:5F:D3:21:7C:44", 0.04, 0.01), ("74:AC:B9:4E:21:01", 0.04, 0.05),
        ];
        var top = talkers.Select(x =>
        {
            double pps = Math.Max(0.5, (total - stormBoost) * x.Share * (0.8 + _rng.NextDouble() * 0.4));
            return new TalkerStat(Mac.Parse(x.Mac), Math.Round(pps, 1), Math.Round(pps * x.Bshare, 1), Math.Round(pps * 0.05, 1), Math.Round(pps * (400 + _rng.Next(0, 900))));
        }).ToList();
        if (stormBoost > 0) top.Insert(0, new TalkerStat(_stormSource, Math.Round(stormBoost, 1), Math.Round(stormBoost, 1), 0, stormBoost * 64));
        top = top.OrderByDescending(x => x.Pps).ToList();

        if (_rng.NextDouble() < 0.08) _dropped += _rng.Next(1, 4);
        return new TrafficSnapshot(now, Math.Round(total, 1), Math.Round(bcast, 1), Math.Round(mcast, 1), Math.Round(unicast, 1),
            Math.Round(total * 520 + Noise(4000)), byProto, top, _dropped);
    }

    private static readonly (string Mac, string Ip, DeviceType Type, string Oui, string Brand, string Model, string Host)[] ExtraPool =
    [
        ("7A:12:C4:9E:33:01", "192.168.1.120", DeviceType.Phone, "Apple, Inc.", "Apple", "iPhone 16", "Guest-iPhone"),
        ("3E:91:5B:20:7D:A4", "192.168.1.121", DeviceType.Phone, "Google, Inc.", "Google", "Pixel 8", "Pixel-8"),
        ("F0:27:2D:61:4B:90", "192.168.20.60", DeviceType.Tablet, "Amazon Technologies Inc.", "Amazon", "Kindle Paperwhite", "kindle-paperwhite"),
        ("0A:6D:E2:58:C1:37", "192.168.1.122", DeviceType.Tablet, "Samsung Electronics Co.,Ltd", "Samsung", "Galaxy Tab S9", "Galaxy-Tab-S9"),
        ("A8:59:5F:3C:00:D2", "192.168.1.123", DeviceType.GameConsole, "Valve Corporation", "Valve", "Steam Deck OLED", "steamdeck"),
        ("48:E1:E9:8B:15:6C", "192.168.20.61", DeviceType.SmartPlug, "Chengdu Meross Technology Co., Ltd.", "Meross", "MSS310 Smart Plug", "Meross_Smart_Plug"),
    ];

    private Device? AddExtraDevice()
    {
        if (_extraDevices >= ExtraPool.Length) return null;
        var x = ExtraPool[_extraDevices++];
        var ap = _rng.NextDouble() < 0.5 ? Ap1Mac : Ap2Mac;
        int rssi = -50 - _rng.Next(0, 28);
        Wifi(x.Mac, x.Ip, x.Type, x.Oui, x.Brand, x.Model, ("dhcp", x.Host), ap, 2.5 + _rng.NextDouble() * 3, 1.0 + _rng.NextDouble() * 1.5, rssi,
            ["ARP", "DHCP", "mDNS"]);
        if (!_devices.TryGet(Mac.Parse(x.Mac), out var d)) return null;
        d.SetFlag(DeviceFlags.New);
        d.FirstSeen = DateTimeOffset.Now;
        if (x.Ip.StartsWith("192.168.20.", StringComparison.Ordinal)) { d.NativeVlan = 20; d.AddVlan(20); }
        var n = _nodes[d.Mac];
        for (int i = 0; i < 5; i++)
        {
            var (arp, icmp) = Sample(n, false);
            d.Latency.Add(new LatencySample(DateTimeOffset.Now - TimeSpan.FromSeconds(5 - i), LatencyKind.Arp, arp));
            d.Latency.Add(new LatencySample(DateTimeOffset.Now - TimeSpan.FromSeconds(5 - i), LatencyKind.Icmp, icmp));
        }
        _pairs.Add((ThisHostMac, d.Mac, LatencyOrigin.Estimated, "path-sum"));
        _pairs.Add((GatewayMac, d.Mac, LatencyOrigin.Estimated, "path-sum"));
        _pairs.Add((ap, d.Mac, LatencyOrigin.Measured, "snmp-ping"));
        _devices.NotifyChanged(d, "new");
        return d;
    }

    // ---- packet rain ----

    private static readonly (string Protocol, double Weight)[] ProtocolMix =
    [
        ("ARP", 30), ("mDNS", 22), ("SSDP", 15), ("ICMPv6", 7), ("IGMP", 6), ("NetBIOS", 6), ("LLDP", 5), ("DHCP", 4), ("STP", 4), ("CDP", 0.5),
    ];

    private void PublishPacketBurst()
    {
        var batch = new List<PacketActivity>(4);
        lock (_sync)
        {
            if (!_built || _protocolSources.Count == 0) return;
            int count = _rng.Next(0, 4);
            double totalW = ProtocolMix.Sum(p => p.Weight);
            var now = DateTimeOffset.Now;
            for (int i = 0; i < count; i++)
            {
                double r = _rng.NextDouble() * totalW;
                string proto = ProtocolMix[^1].Protocol;
                foreach (var (p, w) in ProtocolMix)
                {
                    if ((r -= w) <= 0) { proto = p; break; }
                }
                if (!_protocolSources.TryGetValue(proto, out var sources) || sources.Count == 0) continue;
                var mac = sources[_rng.Next(sources.Count)];
                if (_devices.TryGet(mac, out var d) && d.State == DeviceState.Offline) continue;
                batch.Add(new PacketActivity(mac, proto, now));
            }
        }
        foreach (var a in batch) _bus.Publish(a);
    }
}
