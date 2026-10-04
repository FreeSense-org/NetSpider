using System.Buffers.Binary;
using NetSpider.Capture;

namespace NetSpider.Tests.Integration.Export;

public sealed class PcapNgWriterTests
{
    private sealed record Block(uint Type, int Length, byte[] Body);

    private static List<Block> ReadBlocks(byte[] file)
    {
        var blocks = new List<Block>();
        int off = 0;
        while (off < file.Length)
        {
            Assert.True(file.Length - off >= 12, "truncated block header");
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(off));
            int len = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(off + 4));
            Assert.True(len >= 12 && len % 4 == 0, $"block length {len} must be >= 12 and 32-bit aligned");
            Assert.True(off + len <= file.Length, "block overruns file");
            int trailer = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(off + len - 4));
            Assert.Equal(len, trailer);
            blocks.Add(new Block(type, len, file.AsSpan(off + 8, len - 12).ToArray()));
            off += len;
        }
        return blocks;
    }

    [Fact]
    public void Writes_shb_idb_and_epbs_with_consistent_lengths()
    {
        var ts = new DateTime(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc).AddTicks(1234560); // .123456 s
        var packets = new[] { new byte[] { 0xAA }, Enumerable.Range(0, 60).Select(i => (byte)i).ToArray(), new byte[61] };

        using var ms = new MemoryStream();
        using (var w = new PcapNgWriter(new NonClosingStream(ms), "unit test", "eth0"))
        {
            foreach (var p in packets) w.WritePacket(ts, p);
        }
        var blocks = ReadBlocks(ms.ToArray());

        Assert.Equal(new uint[] { 0x0A0D0D0A, 1, 6, 6, 6 }, blocks.Select(b => b.Type));

        var shb = blocks[0].Body;
        Assert.Equal(0x1A2B3C4Du, BinaryPrimitives.ReadUInt32LittleEndian(shb));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(shb.AsSpan(4)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(shb.AsSpan(6)));
        Assert.Equal(-1L, BinaryPrimitives.ReadInt64LittleEndian(shb.AsSpan(8)));

        var idb = blocks[1].Body;
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(idb)); // LINKTYPE_ETHERNET
        Assert.Equal(262144, BinaryPrimitives.ReadInt32LittleEndian(idb.AsSpan(4)));
        Assert.Contains((ushort)9, ReadOptionCodes(idb.AsSpan(8))); // if_tsresol

        ulong expectedUs = (ulong)((ts - DateTime.UnixEpoch).Ticks / 10);
        for (int i = 0; i < packets.Length; i++)
        {
            var epb = blocks[2 + i];
            int padded = (packets[i].Length + 3) & ~3;
            Assert.Equal(32 + padded, epb.Length);
            var b = epb.Body;
            Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(b)); // interface id
            ulong us = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4)) << 32 | BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(8));
            Assert.Equal(expectedUs, us);
            Assert.Equal(packets[i].Length, BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(12)));
            Assert.Equal(packets[i].Length, BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(16)));
            Assert.Equal(packets[i], b.AsSpan(20, packets[i].Length).ToArray());
            Assert.All(b.AsSpan(20 + packets[i].Length, padded - packets[i].Length).ToArray(), x => Assert.Equal(0, x));
        }
    }

    private static List<ushort> ReadOptionCodes(ReadOnlySpan<byte> opts)
    {
        var codes = new List<ushort>();
        int o = 0;
        while (o + 4 <= opts.Length)
        {
            ushort code = BinaryPrimitives.ReadUInt16LittleEndian(opts[o..]);
            ushort len = BinaryPrimitives.ReadUInt16LittleEndian(opts[(o + 2)..]);
            if (code == 0) break;
            codes.Add(code);
            o += 4 + ((len + 3) & ~3);
        }
        return codes;
    }

    private sealed class NonClosingStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        protected override void Dispose(bool disposing) { /* keep the MemoryStream readable */ }
    }
}
