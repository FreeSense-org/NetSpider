using System.Buffers.Binary;
using System.Net;
using NetSpider.Capture;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.Core;

public class CaptureTests
{
    [Fact]
    public void PcapNg_blocks_are_well_formed()
    {
        var ms = new MemoryStream();
        var frame = FrameBuilder.ArpRequest(Mac.Parse("00:11:22:33:44:55"), IPAddress.Parse("192.168.1.2"), IPAddress.Parse("192.168.1.1"));
        using (var w = new PcapNgWriter(new NonClosing(ms), "test", "eth0"))
        {
            w.WritePacket(DateTime.UtcNow, frame);
            w.WritePacket(DateTime.UtcNow, frame.AsSpan(0, 42));
        }
        var b = ms.ToArray();
        var types = new List<uint>();
        int off = 0;
        while (off < b.Length)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off));
            int len = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(off + 4));
            Assert.Equal(0, len % 4);
            Assert.Equal(len, BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(off + len - 4)));
            types.Add(type);
            off += len;
        }
        Assert.Equal(b.Length, off);
        Assert.Equal([0x0A0D0D0Au, 1u, 6u, 6u], types);
    }

    [Fact]
    public void Traffic_counter_classifies_frames()
    {
        var c = new TrafficCounter();
        var src = Mac.Parse("00:11:22:33:44:55");
        var arp = FrameBuilder.ArpRequest(src, IPAddress.Parse("192.168.1.2"), IPAddress.Parse("192.168.1.1"));
        var mdns = FrameBuilder.Udp4(src, IpUtil.MulticastMac(IPAddress.Parse("224.0.0.251")), IPAddress.Parse("192.168.1.2"), IPAddress.Parse("224.0.0.251"), 5353, 5353, new byte[12]);
        for (int i = 0; i < 3; i++) c.Count(new CapturedFrame(arp, DateTime.UtcNow, 0, false));
        c.Count(new CapturedFrame(mdns, DateTime.UtcNow, 0, false));
        Assert.Equal("mDNS", TrafficCounter.ProtocolName(new CapturedFrame(mdns, DateTime.UtcNow, 0, false)));
        var snap = c.Snapshot(0);
        Assert.True(snap.PpsByProtocol.ContainsKey("ARP"));
        Assert.True(snap.PpsByProtocol.ContainsKey("mDNS"));
        Assert.Equal(src, Assert.Single(snap.TopTalkers).Mac);
        Assert.True(snap.BroadcastPps > snap.MulticastPps);
    }

    [Theory]
    [InlineData("Hyper-V Virtual Ethernet Adapter", "Hyper-V")]
    [InlineData("vEthernet (WSL (Hyper-V firewall))", "WSL")]
    [InlineData("VMware Virtual Ethernet Adapter for VMnet8", "VMware")]
    [InlineData("Tailscale Tunnel", "VPN")]
    [InlineData("Intel(R) Ethernet Controller I225-V", null)]
    public void Virtual_adapters_are_classified(string desc, string? kind) =>
        Assert.Equal(kind, AdapterCatalog.ClassifyVirtual(desc));

    private sealed class NonClosing(Stream inner) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    }
}
