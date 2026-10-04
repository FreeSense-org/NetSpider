using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetSpider.Core.Model;
using NetSpider.Discovery.Vendor;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class VendorTests
{
    [Fact]
    public void Parses_Ubiquiti_Tlv()
    {
        var body = new List<byte>();
        AddTlv(body, 0x02, Concat(Mac.Parse("DC:9F:DB:00:11:22").ToBytes(), new byte[] { 192, 168, 1, 20 }));
        AddTlv(body, 0x0B, Encoding.ASCII.GetBytes("MyAP"));
        AddTlv(body, 0x03, Encoding.ASCII.GetBytes("WA.ar934x.v8.7.0"));
        AddTlv(body, 0x15, Encoding.ASCII.GetBytes("UAP-AC-Lite"));
        var packet = Concat(new byte[] { 0x01, 0x00, 0x00, (byte)body.Count }, body.ToArray());

        var info = UbiquitiDiscovery.Parse(packet);
        Assert.NotNull(info);
        Assert.Equal(Mac.Parse("DC:9F:DB:00:11:22"), info!.Hwaddr);
        Assert.Equal(IPAddress.Parse("192.168.1.20"), info.IpAddress);
        Assert.Equal("MyAP", info.Hostname);
        Assert.Equal("UAP-AC-Lite", info.ModelDisplay);

        var device = new Device(info.Hwaddr!.Value);
        Assert.True(UbiquitiDiscovery.Apply(device, info));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Brand && e.Value == "Ubiquiti");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value == "UAP-AC-Lite");
        Assert.Equal("MyAP", device.Hostname);
    }

    [Fact]
    public void Parses_MikroTik_Mndp()
    {
        var body = new List<byte>();
        AddMndp(body, 1, Mac.Parse("CC:2D:E0:AA:BB:CC").ToBytes());
        AddMndp(body, 5, Encoding.ASCII.GetBytes("gateway"));
        AddMndp(body, 7, Encoding.ASCII.GetBytes("7.11.2"));
        AddMndp(body, 8, Encoding.ASCII.GetBytes("MikroTik"));
        AddMndp(body, 12, Encoding.ASCII.GetBytes("RB5009"));
        var packet = Concat(new byte[] { 0, 0, 0, 0 }, body.ToArray());

        var info = MikroTikMndp.Parse(packet);
        Assert.NotNull(info);
        Assert.Equal("gateway", info!.Identity);
        Assert.Equal("RB5009", info.Board);
        Assert.Equal("7.11.2", info.Version);

        var device = new Device(info.Mac!.Value);
        Assert.True(MikroTikMndp.Apply(device, info));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Brand && e.Value == "MikroTik");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value == "RB5009");
    }

    [Fact]
    public void Builds_And_Parses_Nsdp()
    {
        var req = NetgearNsdp.BuildReadRequest(Mac.Parse("00:11:22:33:44:55"), 1);
        Assert.Equal("NSDP", Encoding.ASCII.GetString(req, 24, 4));

        // Build a response: 32-byte header with signature, then TLVs.
        var resp = new byte[32];
        resp[0] = 1; resp[1] = 2;
        Encoding.ASCII.GetBytes("NSDP").CopyTo(resp, 24);
        var tlvs = new List<byte>();
        AddNsdp(tlvs, 0x0001, Encoding.ASCII.GetBytes("GS308E"));
        AddNsdp(tlvs, 0x0003, Encoding.ASCII.GetBytes("office-switch"));
        AddNsdp(tlvs, 0x0006, new byte[] { 192, 168, 1, 5 });
        AddNsdp(tlvs, 0x000D, Encoding.ASCII.GetBytes("1.00.10"));
        AddNsdp(tlvs, 0xFFFF, Array.Empty<byte>());
        var full = Concat(resp, tlvs.ToArray());

        var info = NetgearNsdp.Parse(full);
        Assert.NotNull(info);
        Assert.Equal("GS308E", info!.Model);
        Assert.Equal("office-switch", info.Name);
        Assert.Equal(IPAddress.Parse("192.168.1.5"), info.Ip);
        Assert.Equal("1.00.10", info.Firmware);

        var device = new Device(Mac.Parse("00:aa:bb:cc:dd:ee"));
        Assert.True(NetgearNsdp.Apply(device, info));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Brand && e.Value == "Netgear");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value == "GS308E");
    }

    [Fact]
    public void Builds_Valid_Mqtt_Connect()
    {
        var c = MqttProbe.BuildConnect();
        Assert.Equal(0x10, c[0]); // CONNECT packet type
        // protocol name "MQTT" after fixed header + remaining length byte(s)
        var text = Encoding.ASCII.GetString(c);
        Assert.Contains("MQTT", text);
    }

    [Fact]
    public void Builds_Coap_WellKnownCore_Get()
    {
        var g = CoapProbe.BuildWellKnownCoreGet();
        Assert.Equal(0x40, g[0]); // ver 1, type CON, token len 0
        Assert.Equal(0x01, g[1]); // GET
        var text = Encoding.ASCII.GetString(g);
        Assert.Contains(".well-known", text);
        Assert.Contains("core", text);
    }

    private static void AddTlv(List<byte> buf, byte type, byte[] val)
    {
        buf.Add(type);
        buf.Add((byte)(val.Length >> 8)); buf.Add((byte)(val.Length & 0xFF));
        buf.AddRange(val);
    }

    private static void AddMndp(List<byte> buf, ushort type, byte[] val)
    {
        buf.Add((byte)(type >> 8)); buf.Add((byte)(type & 0xFF));
        buf.Add((byte)(val.Length >> 8)); buf.Add((byte)(val.Length & 0xFF));
        buf.AddRange(val);
    }

    private static void AddNsdp(List<byte> buf, ushort type, byte[] val)
    {
        buf.Add((byte)(type >> 8)); buf.Add((byte)(type & 0xFF));
        buf.Add((byte)(val.Length >> 8)); buf.Add((byte)(val.Length & 0xFF));
        buf.AddRange(val);
    }

    private static byte[] Concat(byte[] a, byte[] b) { var r = new byte[a.Length + b.Length]; a.CopyTo(r, 0); b.CopyTo(r, a.Length); return r; }
}
