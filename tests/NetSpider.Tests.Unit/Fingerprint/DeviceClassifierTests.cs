using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Fingerprint;
using NetSpider.Fingerprint.Classification;

namespace NetSpider.Tests.Unit.Fingerprint;

public sealed class DeviceClassifierTests
{
    private static readonly OuiDatabase Oui = new(NullLogger<OuiDatabase>.Instance, Path.Combine(Path.GetTempPath(), "netspider-oui-none"), null, false);
    private static readonly DeviceClassifier Classifier = new(NullLogger<DeviceClassifier>.Instance, Oui);

    private static Device Make(string mac)
    {
        var d = new Device(Mac.Parse(mac));
        d.OuiVendor = Oui.Lookup(d.Mac);
        return d;
    }

    private static ServiceInfo Mdns(string type, string name, params (string K, string V)[] txt) =>
        new("mdns", 0, name, type, null, txt.ToDictionary(t => t.K, t => t.V));

    [Fact]
    public void Sonos_speaker_from_ssdp_and_port_1400()
    {
        var d = Make("48:A6:B8:12:34:56");
        d.AddEvidence("ssdp", Fields.Vendor, "Sonos, Inc.", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.Model, "Sonos One", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.DeviceType, "urn:schemas-upnp-org:device:ZonePlayer:1", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.Firmware, "79.1-56030", Confidence.Ssdp);
        d.SetPort(new PortInfo(1400, "tcp", PortState.Open));
        d.AddService(Mdns("_sonos._tcp", "Living Room"));

        Assert.True(Classifier.Classify(d));
        Assert.Equal("Sonos", d.Brand);
        Assert.Equal("Sonos One", d.Model);
        Assert.Equal("79.1-56030", d.Firmware);
        Assert.Equal(DeviceType.AudioStreamer, d.Type);
        Assert.True(d.TypeConfidence > 0.9);
        Assert.True(d.IdentityConfidence > 0.9);
        Assert.False(Classifier.Classify(d)); // idempotent
    }

    [Fact]
    public void Apple_tv_from_mdns_model_code()
    {
        var d = Make("DA:11:22:33:44:55"); // private MAC, no OUI
        d.AddService(Mdns("_airplay._tcp", "Living Room", ("model", "AppleTV11,1"), ("srcvers", "770.8.1")));
        d.AddService(Mdns("_companion-link._tcp", "Living Room"));
        d.SetHostname("mdns", "Living-Room.local");

        Classifier.Classify(d);
        Assert.Equal("Apple", d.Brand);
        Assert.Equal(DeviceType.MediaStreamer, d.Type);
        Assert.Equal("tvOS", d.OsGuess);
        Assert.StartsWith("Apple TV 4K", d.Model);
    }

    [Theory]
    [InlineData("AudioAccessory5,1", DeviceType.AudioStreamer, "HomePod mini")]
    [InlineData("iPhone15,2", DeviceType.Phone, "iPhone (iPhone15,2)")]
    [InlineData("MacBookPro18,3", DeviceType.Laptop, "MacBook Pro (MacBookPro18,3)")]
    [InlineData("Mac14,2", DeviceType.Laptop, "MacBook Air (Mac14,2)")]
    [InlineData("Mac14,3", DeviceType.Desktop, "Mac mini (Mac14,3)")]
    [InlineData("iPad13,1", DeviceType.Tablet, "iPad (iPad13,1)")]
    public void Apple_model_codes(string code, DeviceType type, string model)
    {
        var d = Make("00:03:93:00:00:01");
        d.AddService(Mdns("_device-info._tcp", "Thing", ("model", code)));
        Classifier.Classify(d);
        Assert.Equal("Apple", d.Brand);
        Assert.Equal(type, d.Type);
        Assert.Equal(model, d.Model);
    }

    [Fact]
    public void Iphone_with_private_mac_and_lockdown_port()
    {
        var d = Make("F2:AA:BB:CC:DD:EE");
        d.SetHostname("dhcp", "Alex-iPhone");
        d.SetPort(new PortInfo(62078, "tcp", PortState.Open));
        d.Ttl = 64;
        Classifier.Classify(d);
        Assert.Equal("Apple", d.Brand);
        Assert.Equal(DeviceType.Phone, d.Type);
        Assert.Equal("iOS", d.OsGuess);
    }

    [Fact]
    public void Netgear_managed_switch_from_snmp()
    {
        var d = Make("A0:63:91:00:00:10");
        d.SetProperty("sysDescr", "GS724Tv4 ProSafe 24-port Gigabit Smart Switch, 6.3.1.4, B1.0.0.4");
        d.SetProperty("sysObjectID", "1.3.6.1.4.1.4526.100.4.19");
        d.SetHostname("snmp", "office-switch");
        Classifier.Classify(d);
        Assert.Equal("Netgear", d.Brand);
        Assert.Equal(DeviceType.AccessSwitch, d.Type);
        Assert.Equal("GS724Tv4", d.Model);
    }

    [Fact]
    public void Netgear_orbi_gateway_is_router()
    {
        var d = Make("A0:63:91:00:00:01");
        d.SetFlag(DeviceFlags.Gateway);
        d.AddEvidence("ssdp", Fields.Vendor, "NETGEAR", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.Model, "RBR750", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.DeviceType, "urn:schemas-upnp-org:device:InternetGatewayDevice:1", Confidence.Ssdp);
        Classifier.Classify(d);
        Assert.Equal("Netgear", d.Brand);
        Assert.Equal("RBR750", d.Model);
        Assert.Equal(DeviceType.Router, d.Type);
    }

    [Fact]
    public void Gateway_with_firewall_evidence_is_firewall()
    {
        var d = Make("00:09:0F:00:00:01"); // Fortinet OUI
        d.SetFlag(DeviceFlags.Gateway);
        d.SetCertificate(new TlsCertInfo(443, "CN=FGT60FTK21000000", "FGT60FTK21000000", [], "CN=FGT60FTK21000000", "Fortinet", DateTime.UtcNow.AddYears(-1), DateTime.UtcNow.AddYears(5), "01", "AA", true));
        Classifier.Classify(d);
        Assert.Equal("Fortinet", d.Brand);
        Assert.Equal(DeviceType.Firewall, d.Type);
    }

    [Fact]
    public void Plain_gateway_without_other_evidence_is_router()
    {
        var d = Make("C8:D7:19:00:00:01");
        d.SetFlag(DeviceFlags.Gateway);
        d.SetPort(new PortInfo(80, "tcp", PortState.Open));
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Router, d.Type);
        Assert.Equal("Linksys", d.Brand);
    }

    [Fact]
    public void Ubiquiti_access_point_from_vendor_probe()
    {
        var d = Make("E0:63:DA:00:11:22");
        d.AddEvidence("ubnt-discovery", Fields.Model, "U6-LR", Confidence.VendorProtocol);
        d.AddEvidence("ubnt-discovery", Fields.Firmware, "6.6.55", Confidence.VendorProtocol);
        d.AddEvidence("ubnt-discovery", Fields.Hostname, "U6-LR-Office", Confidence.VendorProtocol);
        Classifier.Classify(d);
        Assert.Equal("Ubiquiti", d.Brand);
        Assert.Equal(DeviceType.AccessPoint, d.Type);
        Assert.Equal("U6-LR", d.Model);
        Assert.Equal("6.6.55", d.Firmware);
    }

    [Fact]
    public void Udm_pro_is_router()
    {
        var d = Make("E0:63:DA:00:11:23");
        d.AddEvidence("ubnt-discovery", Fields.Model, "UDM-Pro", Confidence.VendorProtocol);
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Router, d.Type);
    }

    [Fact]
    public void Synology_nas()
    {
        var d = Make("00:11:32:AA:BB:CC");
        d.SetPort(new PortInfo(5000, "tcp", PortState.Open));
        d.SetPort(new PortInfo(5001, "tcp", PortState.Open));
        d.SetPort(new PortInfo(445, "tcp", PortState.Open));
        d.AddService(Mdns("_http._tcp", "DiskStation", ("vendor", "Synology"), ("model", "DS920+")));
        Classifier.Classify(d);
        Assert.Equal("Synology", d.Brand);
        Assert.Equal(DeviceType.Nas, d.Type);
        Assert.Equal("DS920+", d.Model);
    }

    [Fact]
    public void Hp_printer_from_ipp()
    {
        var d = Make("9C:8E:99:01:02:03");
        d.AddService(Mdns("_ipp._tcp", "HP Color LaserJet MFP M283fdw", ("ty", "HP Color LaserJet MFP M283fdw"), ("usb_MFG", "HP")));
        d.SetPort(new PortInfo(9100, "tcp", PortState.Open));
        d.SetPort(new PortInfo(631, "tcp", PortState.Open));
        Classifier.Classify(d);
        Assert.Equal("HP", d.Brand);
        Assert.Equal(DeviceType.Printer, d.Type);
        Assert.Contains("LaserJet", d.Model);
    }

    [Fact]
    public void Brother_printer_from_hostname_and_ports_only()
    {
        var d = Make("00:80:77:01:02:03");
        d.SetHostname("dhcp", "BRW3C2AF4123456");
        d.SetPort(new PortInfo(9100, "tcp", PortState.Open));
        Classifier.Classify(d);
        Assert.Equal("Brother", d.Brand);
        Assert.Equal(DeviceType.Printer, d.Type);
    }

    [Fact]
    public void Windows_desktop_from_ports_dhcp_and_hostname()
    {
        var d = Make("00:D8:61:01:02:03");
        d.SetHostname("netbios", "DESKTOP-4F7K2QX");
        d.AddEvidence("dhcp", Fields.DhcpVendorClass, "MSFT 5.0", Confidence.Dhcp);
        d.SetPort(new PortInfo(3389, "tcp", PortState.Open));
        d.SetPort(new PortInfo(445, "tcp", PortState.Open));
        d.SetPort(new PortInfo(135, "tcp", PortState.Open));
        d.Ttl = 128;
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Desktop, d.Type);
        Assert.Equal("Windows", d.OsGuess);
    }

    [Fact]
    public void Android_phone_from_dhcp()
    {
        var d = Make("EE:01:02:03:04:05");
        d.AddEvidence("dhcp", Fields.DhcpVendorClass, "android-dhcp-14", Confidence.Dhcp);
        d.SetHostname("dhcp", "Galaxy-S23");
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Phone, d.Type);
        Assert.Equal("Android 14", d.OsGuess);
        Assert.Equal("Samsung", d.Brand);
    }

    [Fact]
    public void Hikvision_camera_with_onvif()
    {
        var d = Make("C0:56:E3:01:02:03");
        d.SetPort(new PortInfo(554, "tcp", PortState.Open));
        d.AddService(new ServiceInfo("wsd", 80, "ONVIF", "onvif:NetworkVideoTransmitter"));
        d.AddEvidence("onvif", Fields.Model, "DS-2CD2143G2-I", Confidence.Ssdp);
        Classifier.Classify(d);
        Assert.Equal("Hikvision", d.Brand);
        Assert.Equal(DeviceType.Camera, d.Type);
        Assert.Equal("DS-2CD2143G2-I", d.Model);
    }

    [Fact]
    public void Generic_onvif_camera_by_ports()
    {
        var d = Make("EE:00:00:00:00:09");
        d.SetPort(new PortInfo(554, "tcp", PortState.Open));
        d.AddService(new ServiceInfo("wsd", 0, "onvif device", "onvif"));
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Camera, d.Type);
    }

    [Fact]
    public void Chromecast_and_google_cast()
    {
        var d = Make("F4:F5:D8:01:02:03");
        d.AddService(Mdns("_googlecast._tcp", "Chromecast-Ultra-1234", ("md", "Chromecast Ultra"), ("fn", "Living Room TV")));
        Classifier.Classify(d);
        Assert.Equal("Google", d.Brand);
        Assert.Equal(DeviceType.MediaStreamer, d.Type);
    }

    [Fact]
    public void Nest_hub()
    {
        var d = Make("F4:F5:D8:01:02:04");
        d.AddService(Mdns("_googlecast._tcp", "Google-Nest-Hub-abc", ("md", "Google Nest Hub")));
        Classifier.Classify(d);
        Assert.Equal(DeviceType.SmartHomeHub, d.Type);
    }

    [Fact]
    public void Proxmox_hypervisor_by_port_8006_and_cert()
    {
        var d = Make("BC:24:11:00:00:01");
        d.SetPort(new PortInfo(8006, "tcp", PortState.Open));
        d.SetCertificate(new TlsCertInfo(8006, "CN=pve.lan", "pve.lan", ["pve.lan"], "CN=Proxmox Virtual Environment", "PVE Cluster Manager CA", DateTime.UtcNow, DateTime.UtcNow.AddYears(2), "1", "x", false));
        Classifier.Classify(d);
        Assert.Equal(DeviceType.Hypervisor, d.Type);
        Assert.Equal("Proxmox", d.Brand);
    }

    [Fact]
    public void HyperV_vm_from_oui()
    {
        var d = Make("00:15:5D:01:02:03");
        d.SetHostname("dns", "build-agent-01");
        Classifier.Classify(d);
        Assert.Equal(DeviceType.VirtualMachine, d.Type);
    }

    [Fact]
    public void Espressif_iot_and_shelly_override()
    {
        var esp = Make("24:0A:C4:01:02:03");
        esp.SetHostname("dhcp", "ESP_1A2B3C");
        Classifier.Classify(esp);
        Assert.Equal("Espressif", esp.Brand);
        Assert.Equal(DeviceType.IoT, esp.Type);

        var shelly = Make("24:0A:C4:01:02:04");
        shelly.SetHostname("mdns", "shellyplus1pm-a8032ab12345");
        shelly.AddService(Mdns("_shelly._tcp", "shellyplus1pm-a8032ab12345", ("gen", "2")));
        Classifier.Classify(shelly);
        Assert.Equal("Shelly", shelly.Brand);
        Assert.Equal(DeviceType.SmartPlug, shelly.Type);
    }

    [Fact]
    public void Philips_hue_bridge()
    {
        var d = Make("00:17:88:01:02:03");
        d.AddService(Mdns("_hue._tcp", "Philips Hue - 1A2B3C", ("bridgeid", "001788fffe1a2b3c"), ("modelid", "BSB002")));
        Classifier.Classify(d);
        Assert.Equal("Philips Hue", d.Brand);
        Assert.Equal(DeviceType.SmartHomeHub, d.Type);
    }

    [Fact]
    public void Apc_ups_via_snmp()
    {
        var d = Make("00:C0:B7:01:02:03");
        d.SetProperty("sysDescr", "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin AF1:v6.8.2 MN:AP9630 HR:05 SN: ZA1234567890 MD:01/01/2020)");
        d.SetProperty("sysObjectID", "1.3.6.1.4.1.318.1.3.27");
        Classifier.Classify(d);
        Assert.Equal("APC", d.Brand);
        Assert.Equal(DeviceType.Ups, d.Type);
    }

    [Fact]
    public void Dell_idrac()
    {
        var d = Make("D0:94:66:01:02:03");
        d.SetCertificate(new TlsCertInfo(443, "CN=idrac-ABC1234, O=Dell Inc.", "idrac-ABC1234", [], "CN=idrac-ABC1234", "Dell Inc.", DateTime.UtcNow, DateTime.UtcNow.AddYears(5), "1", "x", true));
        Classifier.Classify(d);
        Assert.Equal("Dell", d.Brand);
        Assert.Equal(DeviceType.Server, d.Type);
    }

    [Fact]
    public void Lldp_capabilities_identify_switch()
    {
        var d = Make("00:1B:21:00:00:01");
        d.AddEvidence("lldp", Fields.Capabilities, "Bridge", Confidence.Lldp);
        d.AddEvidence("lldp", Fields.Description, "Some managed switch firmware 1.2", Confidence.Lldp);
        Classifier.Classify(d);
        Assert.Equal(DeviceType.AccessSwitch, d.Type);
    }

    [Fact]
    public void Ttl_only_gives_os_family()
    {
        var d = Make("EE:00:00:00:00:01");
        d.Ttl = 255;
        Classifier.Classify(d);
        Assert.Equal("Network OS", d.OsGuess);
        d.Ttl = 64;
        Classifier.Classify(d);
        Assert.Equal("Linux/macOS/iOS/Android", d.OsGuess);
    }

    [Fact]
    public void Higher_confidence_evidence_wins()
    {
        var d = Make("00:0E:58:00:00:01"); // Sonos OUI (0.4)
        d.AddEvidence("user", Fields.Brand, "Acme", Confidence.User);
        d.AddEvidence("user", Fields.DeviceType, "Server", Confidence.User);
        Classifier.Classify(d);
        Assert.Equal("Acme", d.Brand);
        Assert.Equal(DeviceType.Server, d.Type);
    }

    [Fact]
    public void Oui_only_brand_is_low_confidence()
    {
        var d = Make("A0:63:91:00:00:33");
        Classifier.Classify(d);
        Assert.Equal("Netgear", d.Brand);
        Assert.InRange(d.IdentityConfidence, 0.3, 0.5);
    }

    [Fact]
    public void This_host_and_synthetic_nodes()
    {
        var me = Make("00:D8:61:01:02:99");
        me.SetFlag(DeviceFlags.ThisHost);
        Classifier.Classify(me);
        Assert.Equal(DeviceType.ThisComputer, me.Type);

        var cloud = new Device(SyntheticNodes.Internet) { Type = DeviceType.Internet };
        Assert.False(Classifier.Classify(cloud));
        Assert.Equal(DeviceType.Internet, cloud.Type);
    }

    [Fact]
    public void Lg_webos_tv_and_roku()
    {
        var tv = Make("EE:00:00:00:00:02");
        tv.SetHostname("mdns", "LGwebOSTV");
        tv.AddService(Mdns("_airplay._tcp", "[LG] webOS TV OLED65C3", ("model", "OLED65C3PUA")));
        Classifier.Classify(tv);
        Assert.Equal("LG", tv.Brand);
        Assert.Equal(DeviceType.Tv, tv.Type);
        Assert.Equal("webOS", tv.OsGuess);

        var roku = Make("EE:00:00:00:00:03");
        roku.AddEvidence("ssdp", Fields.Vendor, "Roku", Confidence.Ssdp);
        roku.AddEvidence("ssdp", Fields.Model, "Roku Ultra 4802X", Confidence.Ssdp);
        Classifier.Classify(roku);
        Assert.Equal("Roku", roku.Brand);
        Assert.Equal(DeviceType.MediaStreamer, roku.Type);
    }

    [Fact]
    public void Fritzbox_router()
    {
        var d = Make("3C:A6:2F:01:02:03");
        d.AddEvidence("ssdp", Fields.Vendor, "AVM Berlin", Confidence.Ssdp);
        d.AddEvidence("ssdp", Fields.Model, "FRITZ!Box 7590", Confidence.Ssdp);
        Classifier.Classify(d);
        Assert.Equal("AVM", d.Brand);
        Assert.Equal(DeviceType.Router, d.Type);
        Assert.Equal("FRITZ!Box 7590", d.Model);
    }

    [Fact]
    public void Mikrotik_from_routeros_sysdescr()
    {
        var d = Make("48:8F:5A:01:02:03");
        d.SetProperty("sysDescr", "RouterOS CRS326-24G-2S+");
        Classifier.Classify(d);
        Assert.Equal("MikroTik", d.Brand);
        Assert.Equal(DeviceType.AccessSwitch, d.Type);
        Assert.Equal("CRS326-24G-2S+", d.Model);
    }

    [Fact]
    public void Tplink_kasa_plug()
    {
        var d = Make("50:C7:BF:00:11:23");
        d.AddEvidence("tplink", Fields.Model, "HS110(EU)", Confidence.VendorProtocol);
        Classifier.Classify(d);
        Assert.Equal("TP-Link", d.Brand);
        Assert.Equal(DeviceType.SmartPlug, d.Type);
    }

    [Fact]
    public void Home_assistant()
    {
        var d = Make("DC:A6:32:12:34:57");
        d.AddService(Mdns("_home-assistant._tcp", "Home", ("version", "2026.9.1")));
        d.SetPort(new PortInfo(8123, "tcp", PortState.Open));
        Classifier.Classify(d);
        Assert.Equal("Home Assistant", d.Brand);
        Assert.Equal(DeviceType.SmartHomeHub, d.Type);
    }
}
