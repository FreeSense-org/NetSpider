using System.Buffers.Binary;
using System.Text;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Dns;
using NetSpider.Discovery.Services.Mdns;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class MdnsInterpreterTests
{
    [Fact]
    public void Records_Hostname_From_A_Record()
    {
        var packet = BuildResponse(answers: b =>
        {
            WriteName(b, "appletv.local");
            b.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 7 });
        }, answerCount: 1);

        Assert.True(DnsCodec.TryParse(packet, out var msg));
        var device = new Device(Mac.Parse("00:11:22:33:44:77"));
        Assert.True(MdnsInterpreter.Apply(device, packet, msg));
        Assert.Equal("appletv", device.Hostname);
    }

    [Fact]
    public void Chromecast_Txt_Sets_Brand_And_Model()
    {
        var packet = BuildResponse(answers: b =>
        {
            WriteName(b, "Chromecast._googlecast._tcp.local");
            b.AddRange(new byte[] { 0, 16, 0, 1, 0, 0, 0, 120 }); // TXT IN ttl
            var txt = new List<byte>();
            AddTxt(txt, "md=Chromecast Ultra");
            AddTxt(txt, "fn=Living Room TV");
            b.Add((byte)(txt.Count >> 8)); b.Add((byte)(txt.Count & 0xFF));
            b.AddRange(txt);
        }, answerCount: 1);

        Assert.True(DnsCodec.TryParse(packet, out var msg));
        var device = new Device(Mac.Parse("00:11:22:33:44:78"));
        Assert.True(MdnsInterpreter.Apply(device, packet, msg));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Model && e.Value == "Chromecast Ultra");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Brand && e.Value == "Google");
        Assert.Equal("Living Room TV", device.Hostname);
    }

    private static byte[] BuildResponse(Action<List<byte>> answers, int answerCount)
    {
        var buf = new List<byte>(new byte[12]);
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(buf).Slice(2), 0x8400);
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(buf).Slice(6), (ushort)answerCount);
        answers(buf);
        return buf.ToArray();
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

    private static void AddTxt(List<byte> buf, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        buf.Add((byte)bytes.Length);
        buf.AddRange(bytes);
    }
}
