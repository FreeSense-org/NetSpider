using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class RawCrossoverProbeTests
{
    private static readonly byte[] Nonce = [1, 2, 3, 4, 5, 6, 7, 8];

    private static byte[] Frame(ushort seq, byte[]? nonce = null) => RawCrossoverProbe.BuildFrame(
        Mac.Parse("00:1B:21:5E:0F:01"), Mac.Parse("60:FF:9E:10:20:30"),
        IPAddress.Parse("10.40.210.17"), IPAddress.Parse("10.40.211.5"), seq, nonce ?? Nonce);

    [Fact]
    public void Frame_is_a_valid_icmp_echo_with_checksums()
    {
        var f = Frame(7);
        var eth = EthernetView.Parse(f);
        Assert.Equal(EthernetView.Ipv4, eth.EtherType);
        Assert.Equal(Mac.Parse("60:FF:9E:10:20:30"), eth.Destination);
        var ip = f.AsSpan(eth.PayloadOffset);
        Assert.Equal(0, FrameBuilder.Checksum(ip[..20]));
        int total = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
        Assert.Equal(0, FrameBuilder.Checksum(ip[20..total]));
        Assert.Equal(8, ip[20]);
    }

    [Fact]
    public void Matches_only_our_nonce_and_returns_sequence()
    {
        Assert.True(RawCrossoverProbe.TryMatch(Frame(42), Nonce, out var seq));
        Assert.Equal(42, seq);
        Assert.False(RawCrossoverProbe.TryMatch(Frame(42, [9, 9, 9, 9, 9, 9, 9, 9]), Nonce, out _));
        var arp = FrameBuilder.ArpRequest(Mac.Parse("00:1B:21:5E:0F:01"), IPAddress.Parse("10.40.210.17"), IPAddress.Parse("10.40.0.1"));
        Assert.False(RawCrossoverProbe.TryMatch(arp, Nonce, out _));
    }

    [Fact]
    public void Result_loss_math()
    {
        var r = new CrossoverResult("Ethernet", "Wi-Fi", 5, 4, 1.2, 0.9, 1.6, "same subnet", null, DateTimeOffset.Now);
        Assert.Equal(20, r.LossPercent);
        Assert.True(r.Ok);
        Assert.False((r with { Received = 0, Error = "no frames" }).Ok);
    }
}
