using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Tests.Integration.Export;

internal static class TestData
{
    public const string Evil = "<script>alert(\"x\")</script> & \"quoted\", comma";

    public static readonly Mac RouterMac = Mac.Parse("00:11:32:AA:BB:01");
    public static readonly Mac NasMac = Mac.Parse("00:11:32:AA:BB:02");
    public static readonly Mac EvilMac = Mac.Parse("3C:22:FB:00:00:03");
    public static readonly Mac PhoneMac = Mac.Parse("DA:A1:19:00:00:04"); // randomized (LAA)

    public static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "netspider-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }

    public static ExportData Build(byte[]? png = null)
    {
        var store = new DeviceStore();

        var router = store.Observe(RouterMac, IPAddress.Parse("192.168.1.1"), "arp");
        router.AddIp(IPAddress.Parse("fe80::211:32ff:feaa:bb01"));
        router.SetHostname("dns", "router.lan");
        router.SetHostname("mdns", "gateway");
        router.OuiVendor = "Synology Incorporated";
        router.Brand = "Ubiquiti";
        router.Model = "UDM Pro";
        router.Type = DeviceType.Router;
        router.OsGuess = "Linux 4.x (UniFi OS)";
        router.IdentityConfidence = 0.95;
        router.Ttl = 64;
        router.SetFlag(DeviceFlags.Gateway);
        router.SetPort(new PortInfo(22, "tcp", PortState.Open, "ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"));
        router.SetPort(new PortInfo(443, "tcp", PortState.Open, "https", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"));
        router.SetPort(new PortInfo(23, "tcp", PortState.Closed));
        router.SetPort(new PortInfo(161, "udp", PortState.Filtered, "snmp"));
        router.Latency.Add(LatencyKind.Arp, 0.42);
        router.Latency.Add(LatencyKind.Icmp, 0.61);
        router.Latency.Add(LatencyKind.Icmp, 0.75);

        var nas = store.Observe(NasMac, IPAddress.Parse("192.168.1.20"), "arp");
        nas.OuiVendor = "Synology Incorporated";
        nas.Brand = "Synology";
        nas.Model = "DS920+";
        nas.Type = DeviceType.Nas;
        nas.UserLabel = "Backup NAS";
        nas.AddVlan(10);
        nas.SetPort(new PortInfo(5001, "tcp", PortState.Open, "https"));

        var evil = store.Observe(EvilMac, IPAddress.Parse("192.168.1.100"), "arp");
        evil.SetHostname("netbios", Evil);
        evil.Model = Evil;
        evil.OuiVendor = "Evil & <Co>";
        evil.SetPort(new PortInfo(8080, "tcp", PortState.Open, "http", "Server: Evil\u0001Server/1.0 <b>"));

        var phone = store.Observe(PhoneMac, IPAddress.Parse("192.168.1.50"), "arp");
        phone.Type = DeviceType.Phone;
        phone.State = DeviceState.Offline;

        // synthetic node: must be excluded from inventory-style exports
        var internet = store.GetOrAdd(SyntheticNodes.Internet);
        internet.Type = DeviceType.Internet;

        var topo = new TopologyStore();
        topo.Upsert(RouterMac, NasMac, LinkKind.LldpCdp, l => { l.PortA = "eth1"; l.SpeedMbps = 1000; l.LatencyMs = 0.3; });
        topo.Upsert(RouterMac, SyntheticNodes.Internet, LinkKind.Wan);

        var alerts = new List<Alert>
        {
            Alert.Create(AlertSeverity.Critical, AlertKind.RogueDhcp, "Rogue DHCP server", "Server 192.168.1.66 answered " + Evil, EvilMac),
            Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "Broadcast storm", "812 pps broadcast", RouterMac, 812.5),
            Alert.Create(AlertSeverity.Info, AlertKind.NewDevice, "New device", "Phone joined", PhoneMac),
        };

        var net = new NetworkState();
        net.AddOrGetSegment(IPAddress.Parse("192.168.1.0"), 24, "adapter", s => { s.IsLocal = true; s.Gateway = IPAddress.Parse("192.168.1.1"); s.HostsFound = 4; });
        net.AddOrGetSegment(IPAddress.Parse("10.10.0.0"), 16, "snmp-route", s => { s.VlanId = 10; s.VlanName = "Servers"; });
        net.AddVlan(new VlanInfo(1, "default", "lldp", true, false));
        net.AddVlan(new VlanInfo(20, "Voice", "cdp", false, true));
        net.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("192.168.1.1"), RouterMac, IPAddress.Parse("192.168.1.77"), IPAddress.Parse("192.168.1.1"),
            [IPAddress.Parse("1.1.1.1")], IPAddress.Parse("255.255.255.0"), TimeSpan.FromHours(24), DateTimeOffset.Now, false));
        net.AddDhcpServer(new DhcpServerInfo(IPAddress.Parse("192.168.1.66"), EvilMac, IPAddress.Parse("192.168.1.200"), null, [], null, null, DateTimeOffset.Now, true));
        net.AddStp(new StpInfo("8000.001132aabb01", RouterMac, 32768, 0, "8000.001132aabb01", RouterMac, "RSTP", DateTimeOffset.Now));
        net.Wan = new WanInfo(IPAddress.Parse("203.0.113.7"), "Connected", "IP_Routed", TimeSpan.FromHours(50), "UDM Pro", "UPnP IGD",
            [new PortMapping("TCP", 32400, IPAddress.Parse("192.168.1.20"), 32400, "Plex " + Evil, true, null, null)], DateTimeOffset.Now);
        net.InternetPath = [new TracerouteHop(1, IPAddress.Parse("192.168.1.1"), 0.6, "router.lan", RouterMac), new TracerouteHop(2, null, null, null, null)];
        net.WifiNetworks = [new WifiNetwork("HomeNet", Mac.Parse("00:11:32:AA:BB:10"), 36, 5180, "5 GHz", -48, 90, "WPA3-Personal (CCMP)", "Wi-Fi 6 (802.11ax)", "Ubiquiti", true, 80, DateTimeOffset.Now)];
        net.Health = new HealthReport(DateTimeOffset.Now, 72,
        [
            new HealthCheckResult("dns", "DNS health", HealthStatus.Pass, 100, "Resolver answers match"),
            new HealthCheckResult("cleartext", "Cleartext management", HealthStatus.Warn, 60, "Telnet open on " + Evil, "port 23"),
            new HealthCheckResult("rogue-dhcp", "Rogue DHCP", HealthStatus.Fail, 0, "1 rogue server"),
        ]);
        net.NicPassesVlanTags = false;
        net.LastTraffic = new TrafficSnapshot(DateTimeOffset.Now, 120, 10, 20, 90, 50_000, new Dictionary<string, double> { ["ARP"] = 3 }, [], 0);

        var adapter = new AdapterInfo
        {
            Id = "{TEST}",
            PcapName = @"\Device\NPF_{TEST}",
            Name = "Ethernet",
            Mac = Mac.Parse("10:20:30:40:50:60"),
            IPv4 = [new IpWithPrefix(IPAddress.Parse("192.168.1.10"), 24)],
            GatewayV4 = IPAddress.Parse("192.168.1.1"),
            IsUp = true,
        };

        return new ExportData(store.All, topo.Links, alerts, net, png, adapter);
    }

    public static int RealDeviceCount(ExportData d) => d.Devices.Count(x => !SyntheticNodes.IsSynthetic(x.Mac));
}
