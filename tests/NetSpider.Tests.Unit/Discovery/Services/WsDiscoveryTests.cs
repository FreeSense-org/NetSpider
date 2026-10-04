using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Wsd;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class WsDiscoveryTests
{
    private const string OnvifProbeMatch = """
    <?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
      xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <SOAP-ENV:Body>
        <d:ProbeMatches>
          <d:ProbeMatch>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
            <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/HIKVISION%20DS-2CD2143 onvif://www.onvif.org/hardware/DS-2CD2143G0</d:Scopes>
            <d:XAddrs>http://192.168.1.64/onvif/device_service</d:XAddrs>
          </d:ProbeMatch>
        </d:ProbeMatches>
      </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    """;

    [Fact]
    public void Parses_Onvif_Camera()
    {
        var (types, scopes, xaddrs) = WsDiscoveryProbe.ParseProbeMatch(OnvifProbeMatch);
        Assert.Contains("NetworkVideoTransmitter", types);
        Assert.Contains("onvif", scopes);
        Assert.Equal("http://192.168.1.64/onvif/device_service", xaddrs);

        var device = new Device(Mac.Parse("AA:BB:CC:00:11:22"));
        Assert.True(WsDiscoveryProbe.ApplyMatch(device, types, scopes, xaddrs));
        Assert.Contains(device.Evidence, e => e.Field == Fields.DeviceType && e.Value == nameof(DeviceType.Camera));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value.Contains("HIKVISION"));
        Assert.Contains(device.Evidence, e => e.Field == Fields.ModelNumber && e.Value == "DS-2CD2143G0");
    }

    [Fact]
    public void Identifies_Windows_Computer()
    {
        var device = new Device(Mac.Parse("AA:BB:CC:00:11:33"));
        Assert.True(WsDiscoveryProbe.ApplyMatch(device, "pub:Computer", null, null));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Os && e.Value == "Windows");
    }
}
