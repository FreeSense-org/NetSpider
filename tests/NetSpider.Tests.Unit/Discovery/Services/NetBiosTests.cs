using System.Buffers.Binary;
using System.Text;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.NetBios;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class NetBiosTests
{
    [Fact]
    public void Builds_Nbstat_Query()
    {
        var q = NetBiosProbe.BuildNbstatQuery();
        // 12-byte header, QDCOUNT=1, encoded name starts with length 0x20
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(4)));
        Assert.Equal(0x20, q[12]);
        // trailing qtype NBSTAT 0x0021
        Assert.Equal(0x0021, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(q.Length - 4)));
    }

    [Fact]
    public void Parses_Name_Table()
    {
        var resp = new List<byte>();
        // header
        var hdr = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(hdr.AsSpan(6), 1); // ANCOUNT = 1
        resp.AddRange(hdr);
        // RFC 1002 NODE STATUS RESPONSE: QDCOUNT=0; the answer RR restates the full encoded name ("*" -> "CK" + "AA"*15)
        resp.Add(0x20);
        resp.AddRange("CK"u8.ToArray());
        for (int i = 0; i < 30; i++) resp.Add((byte)'A');
        resp.Add(0);
        // type NBSTAT, class IN, ttl
        resp.AddRange(new byte[] { 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0 });
        // rdata: numNames=2, then name entries
        var rdata = new List<byte> { 2 };
        AddName(rdata, "MYPC", 0x00, group: false);
        AddName(rdata, "WORKGROUP", 0x00, group: true);
        // statistics: unit MAC
        rdata.AddRange(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 });
        BinaryPrimitives.WriteUInt16BigEndian(hdr.AsSpan(), 0); // noop
        resp.Add((byte)(rdata.Count >> 8)); resp.Add((byte)(rdata.Count & 0xFF)); // rdlen
        resp.AddRange(rdata);

        var device = new Device(Mac.Parse("00:11:22:33:44:55"));
        Assert.True(NetBiosProbe.Parse(resp.ToArray(), device));
        Assert.Equal("MYPC", device.Hostname);
        Assert.Contains(device.Evidence, e => e.Field == Fields.Domain && e.Value == "WORKGROUP");
        Assert.Equal("DE:AD:BE:EF:00:01", device.GetProperty("netbios.mac"));
    }

    private static void AddName(List<byte> buf, string name, byte suffix, bool group)
    {
        var padded = name.PadRight(15).Substring(0, 15);
        buf.AddRange(Encoding.ASCII.GetBytes(padded));
        buf.Add(suffix);
        ushort flags = (ushort)(group ? 0x8000 : 0x0000);
        buf.Add((byte)(flags >> 8)); buf.Add((byte)(flags & 0xFF));
    }
}
