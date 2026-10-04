using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Capture;

/// <summary>
/// Start/stop recording of all captured frames to a pcapng file in <see cref="AppPaths.Captures"/>. Frames are queued
/// from the capture dispatch thread and written on a background task, so recording never slows the capture pipeline.
/// Recording stops automatically at the size or time cap, or when capture stops.
/// </summary>
public sealed class PacketRecorder : IPacketRecorder, IFrameHandler, IDisposable
{
    private readonly IFrameSource _source;
    private readonly ILogger<PacketRecorder> _log;
    private readonly object _sync = new();
    private Channel<CapturedFrame>? _queue;
    private Task? _writer;
    private long _frames, _bytes, _maxBytes;
    private DateTimeOffset _deadline;

    public PacketRecorder(IFrameSource frames, ILogger<PacketRecorder> log)
    {
        _source = frames;
        _log = log;
        _source.Stopped += () => StopInternal("capture stopped");
    }

    public bool IsRecording { get { lock (_sync) return _queue is not null; } }
    public string? Path { get; private set; }
    public DateTimeOffset? Started { get; private set; }
    public long Frames => Interlocked.Read(ref _frames);
    public long Bytes => Interlocked.Read(ref _bytes);
    public string? StopReason { get; private set; }
    public event Action? Changed;

    public string? Start(string label, long maxBytes = 1L << 30, TimeSpan? maxDuration = null)
    {
        lock (_sync)
        {
            if (_queue is not null || !_source.IsRunning) return null;
            var safe = string.Concat(label.Select(c => char.IsLetterOrDigit(c) ? c : '_'));
            Path = System.IO.Path.Combine(AppPaths.Captures, $"{DateTime.Now:yyyyMMdd-HHmmss}-{safe}.pcapng");
            Started = DateTimeOffset.Now;
            StopReason = null;
            _frames = _bytes = 0;
            _maxBytes = Math.Max(1 << 20, maxBytes);
            _deadline = DateTimeOffset.Now + (maxDuration ?? TimeSpan.FromMinutes(60));
            var queue = Channel.CreateBounded<CapturedFrame>(new BoundedChannelOptions(100_000)
            {
                FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true, SingleWriter = true,
            });
            _queue = queue;
            var path = Path;
            var adapter = _source.Adapter?.Name;
            _writer = Task.Run(() => WriteLoopAsync(queue, path, adapter, label));
            _log.LogInformation("Recording started: {Path}", path);
        }
        Raise();
        return Path;
    }

    public string? Stop() => StopInternal("stopped");

    private string? StopInternal(string reason)
    {
        Channel<CapturedFrame>? queue;
        Task? writer;
        lock (_sync)
        {
            queue = _queue;
            writer = _writer;
            if (queue is null) return null;
            _queue = null;
            _writer = null;
            StopReason = reason;
        }
        queue.Writer.TryComplete();
        try { writer?.Wait(TimeSpan.FromSeconds(5)); } catch { }
        _log.LogInformation("Recording {Reason}: {Path} ({Frames} frames, {Bytes} bytes)", reason, Path, Frames, Bytes);
        Raise();
        return Path;
    }

    public void OnFrame(CapturedFrame frame)
    {
        var q = _queue;
        if (q is null) return;
        if (Interlocked.Read(ref _bytes) >= _maxBytes) { _ = Task.Run(() => StopInternal("size limit")); return; }
        if (DateTimeOffset.Now >= _deadline) { _ = Task.Run(() => StopInternal("time limit")); return; }
        q.Writer.TryWrite(frame); // frame.Data is owned by the frame and never reused, so it can be written later
    }

    private async Task WriteLoopAsync(Channel<CapturedFrame> queue, string path, string? adapter, string label)
    {
        try
        {
            using var w = PcapNgWriter.Create(path, $"NetSpider recording: {label}", adapter);
            long sinceRaise = 0;
            await foreach (var f in queue.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                w.WritePacket(f.TimestampUtc, f.Data);
                Interlocked.Increment(ref _frames);
                Interlocked.Add(ref _bytes, f.Data.Length + 32);
                if (++sinceRaise >= 500) { sinceRaise = 0; Raise(); }
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Recording to {Path} failed", path);
            lock (_sync) { _queue = null; _writer = null; StopReason = "error: " + ex.Message; }
            Raise();
        }
    }

    private void Raise() { try { Changed?.Invoke(); } catch { } }

    public void Dispose() => StopInternal("app closing");
}
