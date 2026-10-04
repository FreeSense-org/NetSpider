using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.Core;

public class PacketRecorderTests
{
    private sealed class FakeSource : IFrameSource
    {
        public bool IsRunning { get; set; } = true;
        public AdapterInfo? Adapter => null;
        public bool PcapAvailable => true;
        public string? PcapVersion => null;
        public IReadOnlyList<AdapterInfo> ListAdapters() => [];
        public void Start(AdapterInfo adapter) { }
        public void Stop() { IsRunning = false; Stopped?.Invoke(); }
        public IDisposable Subscribe(IFrameHandler handler) => new Dummy();
        public long Send(ReadOnlySpan<byte> frame) => 0;
        public ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default) => ValueTask.FromResult(0L);
        public string? DumpRecent(string reason) => null;
        public event Action<AdapterInfo>? Started { add { } remove { } }
        public event Action? Stopped;
        private sealed class Dummy : IDisposable { public void Dispose() { } }
    }

    private static CapturedFrame Frame() => new(
        FrameBuilder.ArpRequest(Mac.Parse("00:11:22:33:44:55"), IPAddress.Parse("10.0.0.2"), IPAddress.Parse("10.0.0.1")),
        DateTime.UtcNow, 0, false);

    [Fact]
    public void Records_until_stopped_and_writes_valid_pcapng()
    {
        var rec = new PacketRecorder(new FakeSource(), NullLogger<PacketRecorder>.Instance);
        var path = rec.Start("test");
        Assert.NotNull(path);
        Assert.True(rec.IsRecording);
        Assert.Null(rec.Start("again")); // only one recording at a time
        for (int i = 0; i < 25; i++) rec.OnFrame(Frame());
        Assert.Equal(path, rec.Stop());
        Assert.False(rec.IsRecording);
        Assert.Equal(25, rec.Frames);
        Assert.Equal("stopped", rec.StopReason);

        var b = File.ReadAllBytes(path!);
        int off = 0, packets = 0;
        while (off < b.Length)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off));
            int len = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(off + 4));
            if (type == 6) packets++;
            off += len;
        }
        Assert.Equal(25, packets);
        File.Delete(path!);
    }

    [Fact]
    public void Stops_when_capture_stops_and_refuses_without_capture()
    {
        var src = new FakeSource();
        var rec = new PacketRecorder(src, NullLogger<PacketRecorder>.Instance);
        var path = rec.Start("test");
        rec.OnFrame(Frame());
        src.Stop();
        Assert.False(rec.IsRecording);
        Assert.Equal("capture stopped", rec.StopReason);
        Assert.Null(rec.Start("no capture"));
        File.Delete(path!);
    }
}
