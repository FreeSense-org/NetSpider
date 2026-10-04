using System.Buffers.Binary;
using System.Text;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Smb;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class SmbTests
{
    [Theory]
    [InlineData((ushort)0x0311, "3.1.1")]
    [InlineData((ushort)0x0210, "2.1")]
    public void Maps_Dialect(ushort d, string expected) => Assert.Equal(expected, SmbProbe.DialectName(d));

    [Theory]
    [InlineData((byte)10, (byte)0, 22621, "Windows 11")]
    [InlineData((byte)10, (byte)0, 19041, "Windows 10")]
    [InlineData((byte)6, (byte)1, 7601, "Windows 7")]
    public void Maps_Windows_Version(byte major, byte minor, int build, string expectedContains) =>
        Assert.Contains(expectedContains, SmbProbe.WindowsVersion(major, minor, build));

    [Fact]
    public void Parses_Ntlm_Challenge_Av_Pairs_And_Version()
    {
        var ntlm = BuildChallenge();
        var device = new Device(Mac.Parse("00:11:22:33:44:66"));
        Assert.True(SmbProbe.ParseNtlmChallenge(device, ntlm));
        Assert.Equal("FILESERVER", device.GetProperty("smb.computer"));
        Assert.Equal("CONTOSO", device.GetProperty("smb.domain"));
        Assert.Equal("fileserver.contoso.local", device.GetProperty("smb.dnsComputer"));
        Assert.Contains(device.Evidence, e => e.Field == Fields.Os && e.Value.Contains("Windows"));
    }

    [Fact]
    public void Finds_Ntlm_In_Larger_Buffer()
    {
        var inner = BuildChallenge();
        var wrapped = new byte[20 + inner.Length];
        inner.CopyTo(wrapped, 20);
        var found = SmbProbe.FindNtlmChallenge(wrapped);
        Assert.NotNull(found);
        Assert.Equal((byte)'N', found![0]);
    }

    // Build a minimal NTLMSSP CHALLENGE (type 2) with a TargetInfo block and a Version field.
    private static byte[] BuildChallenge()
    {
        var target = new List<byte>();
        AddAv(target, 1, "FILESERVER");                 // NetBIOS computer
        AddAv(target, 2, "CONTOSO");                     // NetBIOS domain
        AddAv(target, 3, "fileserver.contoso.local");    // DNS computer
        target.AddRange(new byte[] { 0, 0, 0, 0 });      // EOL av pair

        var buf = new byte[56 + target.Count];
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(buf, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8), 2); // type 2
        // TargetName fields (offset 12) - leave zero
        // TargetInfo fields at offset 40: len, maxlen, offset
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(40), (ushort)target.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(42), (ushort)target.Count);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(44), 56);
        // Version at offset 48: major 10, minor 0, build 22621
        buf[48] = 10; buf[49] = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(50), 22621);
        buf[55] = 0x0F;
        target.ToArray().CopyTo(buf, 56);
        return buf;
    }

    private static void AddAv(List<byte> buf, ushort id, string value)
    {
        var v = Encoding.Unicode.GetBytes(value);
        buf.Add((byte)(id & 0xFF)); buf.Add((byte)(id >> 8));
        buf.Add((byte)(v.Length & 0xFF)); buf.Add((byte)(v.Length >> 8));
        buf.AddRange(v);
    }
}
