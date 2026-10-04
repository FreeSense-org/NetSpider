using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Ssdp;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class SsdpTests
{
    private const string SonosXml = """
    <?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType>
        <friendlyName>Living Room</friendlyName>
        <manufacturer>Sonos, Inc.</manufacturer>
        <manufacturerURL>http://www.sonos.com</manufacturerURL>
        <modelName>Sonos One</modelName>
        <modelNumber>S18</modelNumber>
        <serialNumber>00-0E-58-AA-BB-CC:1</serialNumber>
        <UDN>uuid:RINCON_000E58AABBCC01400</UDN>
        <presentationURL>/</presentationURL>
        <iconList>
          <icon><mimetype>image/png</mimetype><width>48</width><height>48</height><depth>24</depth><url>/img/icon-S18-48.png</url></icon>
          <icon><mimetype>image/png</mimetype><width>256</width><height>256</height><depth>24</depth><url>/img/icon-S18-256.png</url></icon>
        </iconList>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
            <controlURL>/MediaRenderer/AVTransport/Control</controlURL>
          </service>
        </serviceList>
      </device>
    </root>
    """;

    [Fact]
    public void Parses_Sonos_Description_And_Picks_Largest_Icon()
    {
        var uri = new Uri("http://192.168.1.40:1400/xml/device_description.xml");
        var dev = UpnpXml.Parse(SonosXml, uri);
        Assert.NotNull(dev);
        Assert.Equal("Living Room", dev!.FriendlyName);
        Assert.Equal("Sonos, Inc.", dev.Manufacturer);
        Assert.Equal("Sonos One", dev.ModelName);
        Assert.Equal("S18", dev.ModelNumber);
        Assert.Equal("http://192.168.1.40:1400/img/icon-S18-256.png", dev.IconUrl);
        Assert.Single(dev.Services);
        Assert.Equal("http://192.168.1.40:1400/MediaRenderer/AVTransport/Control", dev.Services[0].ControlUrl);
    }

    [Fact]
    public void Applies_Description_To_Device()
    {
        var uri = new Uri("http://192.168.1.40:1400/d.xml");
        var dev = UpnpXml.Parse(SonosXml, uri)!;
        var desc = new SsdpDescription(System.Net.IPAddress.Parse("192.168.1.40"), uri, "Linux UPnP/1.0 Sonos/1", dev);

        var device = new Device(Mac.Parse("00:0E:58:AA:BB:CC"));
        Assert.True(SsdpInterpreter.Apply(device, desc));
        Assert.Equal("Living Room", device.Hostname);
        Assert.Contains(device.Evidence, e => e.Field == Fields.Vendor && e.Value == "Sonos, Inc.");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value == "Sonos One");
        Assert.Contains(device.Evidence, e => e.Field == Fields.DeviceType && e.Value == nameof(DeviceType.AudioStreamer));
        Assert.Equal("http://192.168.1.40:1400/img/icon-S18-256.png", device.IconUrl);
    }

    [Fact]
    public void Parses_Headers_From_Notify()
    {
        var text = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://10.0.0.1:5000/desc.xml\r\nSERVER: Linux/3.14 UPnP/1.1 MiniUPnPd/2.1\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";
        var h = SsdpInterpreter.ParseHeaders(text);
        Assert.Equal("http://10.0.0.1:5000/desc.xml", h["location"]);
        Assert.Equal("Linux/3.14", SsdpInterpreter.OsFromServer(h["SERVER"]));
    }

    [Theory]
    [InlineData("urn:schemas-upnp-org:device:InternetGatewayDevice:1", nameof(DeviceType.Router))]
    [InlineData("urn:schemas-upnp-org:device:MediaRenderer:1", nameof(DeviceType.AudioStreamer))]
    [InlineData("urn:schemas-upnp-org:device:Printer:1", nameof(DeviceType.Printer))]
    public void Maps_DeviceType(string deviceType, string expected) =>
        Assert.Equal(expected, SsdpInterpreter.TypeFromDeviceType(deviceType));

    [Fact]
    public void Registry_Finds_Igd()
    {
        var reg = new SsdpRegistry();
        var igdChild = new UpnpDevice("urn:schemas-upnp-org:device:WANConnectionDevice:1", null, null, null, null, null, null, null, null, null, null,
            new[] { new UpnpService("urn:schemas-upnp-org:service:WANIPConnection:1", "/ctl/IPConn", null, null) }, Array.Empty<UpnpDevice>());
        var root = new UpnpDevice("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "Router", null, null, null, null, null, null, null, null, null,
            Array.Empty<UpnpService>(), new[] { igdChild });
        reg.Add(new SsdpDescription(System.Net.IPAddress.Parse("10.0.0.1"), new Uri("http://10.0.0.1:5000/d.xml"), null, root));
        Assert.Single(reg.InternetGatewayDevices());
    }
}
