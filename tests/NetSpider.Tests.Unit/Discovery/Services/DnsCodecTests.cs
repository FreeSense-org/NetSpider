using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetSpider.Discovery.Services.Dns;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class DnsCodecTests
{
    // A tiny packet builder with support for a compression pointer.
    private static byte[] Header(ushort qd, ushort an)
    {
        var h = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), 0x8400); // response, authoritative
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), qd);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(6), an);
        return h;
    }

    private static void WriteName(List<byte> buf, string name)
    {
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            buf.Add((byte)label.Length);
            buf.AddRange(Encoding.UTF8.GetBytes(label));
        }
        buf.Add(0);
    }

    [Fact]
    public void Parses_A_Record_With_Hostname()
    {
        var buf = new List<byte>();
        buf.AddRange(Header(0, 1));
        WriteName(buf, "mymac.local");
        buf.AddRange(new byte[] { 0, 1, 0, 1 });              // type A, class IN
        buf.AddRange(new byte[] { 0, 0, 0, 120 });            // ttl
        buf.AddRange(new byte[] { 0, 4, 192, 168, 1, 50 });   // rdlen + ip

        Assert.True(DnsCodec.TryParse(buf.ToArray(), out var msg));
        var a = Assert.Single(msg.Answers);
        Assert.Equal(DnsType.A, a.Type);
        Assert.Equal("mymac.local", a.Name);
        Assert.Equal(IPAddress.Parse("192.168.1.50"), a.AsAddress());
    }

    [Fact]
    public void Resolves_Compression_Pointer_In_Ptr()
    {
        // Build "_http._tcp.local" once, then a PTR whose rdata points back to it.
        var buf = new List<byte>();
        buf.AddRange(Header(0, 1));
        int nameOffset = buf.Count;        // the PTR owner name lives here and the rdata points back to it
        WriteName(buf, "_http._tcp.local");
        buf.AddRange(new byte[] { 0, 12, 0, 1 });     // type PTR, class IN
        buf.AddRange(new byte[] { 0, 0, 0, 60 });     // ttl
        // rdata: "Printer" + pointer to the service name
        var rdata = new List<byte>();
        rdata.Add((byte)"Printer".Length);
        rdata.AddRange(Encoding.UTF8.GetBytes("Printer"));
        rdata.Add(0xC0); rdata.Add((byte)nameOffset);
        buf.Add(0); buf.Add((byte)rdata.Count); // rdlen
        buf.AddRange(rdata);

        var packet = buf.ToArray();
        Assert.True(DnsCodec.TryParse(packet, out var msg));
        var ptr = Assert.Single(msg.Answers);
        var target = DnsCodec.ParseName(packet, ptr);
        Assert.Equal("Printer._http._tcp.local", target);
    }

    [Fact]
    public void Parses_Srv_And_Txt()
    {
        // SRV record
        var buf = new List<byte>();
        buf.AddRange(Header(0, 2));

        // SRV owner "svc._x._tcp.local"
        WriteName(buf, "svc._x._tcp.local");
        buf.AddRange(new byte[] { 0, 33, 0, 1, 0, 0, 0, 60 }); // SRV IN ttl
        var srv = new List<byte> { 0, 10, 0, 5 };              // priority 10, weight 5
        srv.AddRange(new byte[] { 0x1F, 0x90 });               // port 8080
        WriteName(srv, "host.local");                          // target (inline)
        buf.Add(0); buf.Add((byte)srv.Count);
        buf.AddRange(srv);

        // TXT owner "svc._x._tcp.local" with md=Chromecast and bare key
        WriteName(buf, "svc._x._tcp.local");
        buf.AddRange(new byte[] { 0, 16, 0, 1, 0, 0, 0, 60 }); // TXT IN ttl
        var txt = new List<byte>();
        AddTxt(txt, "md=Chromecast");
        AddTxt(txt, "flag");
        buf.Add(0); buf.Add((byte)txt.Count);
        buf.AddRange(txt);

        var packet = buf.ToArray();
        Assert.True(DnsCodec.TryParse(packet, out var msg));
        var srvRr = msg.Answers.First(r => r.Type == DnsType.Srv);
        var parsed = DnsCodec.ParseSrv(packet, srvRr);
        Assert.NotNull(parsed);
        Assert.Equal(8080, parsed!.Port);
        Assert.Equal("host.local", parsed.Target);

        var txtRr = msg.Answers.First(r => r.Type == DnsType.Txt);
        var map = DnsCodec.ParseTxt(txtRr.RData.Span);
        Assert.Equal("Chromecast", map["md"]);
        Assert.True(map.ContainsKey("flag"));
    }

    private static void AddTxt(List<byte> buf, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        buf.Add((byte)bytes.Length);
        buf.AddRange(bytes);
    }

    [Fact]
    public void Builds_Query_That_Round_Trips()
    {
        var q = DnsCodec.BuildQuery([new DnsQuestion("_services._dns-sd._udp.local", DnsType.Ptr, 0x8001)]);
        Assert.True(DnsCodec.TryParse(q, out var msg));
        var question = Assert.Single(msg.Questions);
        Assert.Equal("_services._dns-sd._udp.local", question.Name);
        Assert.Equal(DnsType.Ptr, question.Type);
        Assert.True(question.UnicastResponse);
    }

    [Fact]
    public void Malformed_Packet_Does_Not_Throw()
    {
        Assert.False(DnsCodec.TryParse(new byte[] { 1, 2, 3 }, out _));
        var truncated = new byte[] { 0, 0, 0x84, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0xC0 };
        DnsCodec.TryParse(truncated, out _); // just must not throw
    }
}
