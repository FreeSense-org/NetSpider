using System.Diagnostics;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetSpider.Capture;

/// <summary>
/// Npcap capture + injection on one adapter. Frames are copied off the pcap thread into a bounded channel and dispatched
/// to <see cref="IFrameHandler"/>s on a dedicated thread. Injected frames are looped back by Npcap so probes can use the
/// pcap timestamp of their own request for precise RTTs.
/// </summary>
public sealed class CaptureService : IFrameSource, IDisposable
{
    private readonly ILogger<CaptureService> _log;
    private readonly IEventBus _bus;
    private readonly INetworkState _network;
    private readonly AppSettings _settings;
    private readonly object _handlersSync = new();
    private IFrameHandler[] _handlers = [];
    private readonly TrafficCounter _counter = new();
    private readonly RecentFrameRing _ring = new(30_000);
    private readonly object _sendSync = new();

    private LibPcapLiveDevice? _device;
    private Channel<CapturedFrame>? _channel;
    private Thread? _dispatchThread;
    private Timer? _statsTimer;
    private CancellationTokenSource? _cts;
    private long _channelDrops;
    private Mac _localMac;

    // token bucket for paced injection
    private readonly SemaphoreSlim _paceGate = new(1, 1);
    private long _nextSendTicks;

    public CaptureService(ILogger<CaptureService> log, IEventBus bus, INetworkState network, AppSettings settings)
    {
        _log = log;
        _bus = bus;
        _network = network;
        _settings = settings;
        var status = NpcapEnvironment.Check();
        PcapAvailable = status.NpcapInstalled;
        PcapVersion = status.Version;
    }

    public bool IsRunning => _device is not null;
    public AdapterInfo? Adapter { get; private set; }
    public bool PcapAvailable { get; private set; }
    public string? PcapVersion { get; private set; }

    /// <summary>Re-detects Npcap (after the guided install) so capture works without restarting the app.</summary>
    public bool RecheckPcap()
    {
        var status = NpcapEnvironment.Check();
        PcapAvailable = status.NpcapInstalled;
        PcapVersion = status.Version;
        return PcapAvailable;
    }

    public event Action<AdapterInfo>? Started;
    public event Action? Stopped;

    public IReadOnlyList<AdapterInfo> ListAdapters()
    {
        if (!PcapAvailable) return [];
        try { return AdapterCatalog.List(); }
        catch (Exception ex) { _log.LogError(ex, "Listing adapters failed"); return []; }
    }

    public void Start(AdapterInfo adapter)
    {
        Stop();
        var dev = LibPcapLiveDeviceList.New().FirstOrDefault(d => string.Equals(d.Name, adapter.PcapName, StringComparison.OrdinalIgnoreCase))
                  ?? throw new InvalidOperationException($"Capture device {adapter.PcapName} not found");

        var config = new DeviceConfiguration
        {
            Mode = DeviceModes.Promiscuous | DeviceModes.MaxResponsiveness,
            ReadTimeout = 50,
            Snaplen = 65536,
            KernelBufferSize = 16 * 1024 * 1024,
            Immediate = true,
            TimestampResolution = TimestampResolution.Microsecond,
            TimestampType = TimestampType.HostHighPrecision,
        };
        config.ConfigurationFailed += (_, e) => _log.LogDebug("pcap config {Property} not applied: {Error}", e.Property, e.Error);
        dev.Open(config);

        _localMac = adapter.Mac;
        _cts = new CancellationTokenSource();
        _channel = Channel.CreateBounded<CapturedFrame>(new BoundedChannelOptions(50_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true,
        }, _ => Interlocked.Increment(ref _channelDrops));

        dev.OnPacketArrival += OnPacketArrival;
        _device = dev;
        Adapter = adapter;

        _dispatchThread = new Thread(DispatchLoop) { IsBackground = true, Name = "NetSpider frame dispatch", Priority = ThreadPriority.AboveNormal };
        _dispatchThread.Start(_cts.Token);
        dev.StartCapture();
        _statsTimer = new Timer(_ => PublishStats(), null, 1000, 1000);

        _log.LogInformation("Capture started on {Adapter} ({Pcap})", adapter.Name, adapter.PcapName);
        Started?.Invoke(adapter);
    }

    public void Stop()
    {
        var dev = _device;
        if (dev is null) return;
        _device = null;
        _statsTimer?.Dispose();
        _statsTimer = null;
        try { dev.OnPacketArrival -= OnPacketArrival; dev.StopCapture(); } catch (Exception ex) { _log.LogDebug(ex, "StopCapture"); }
        try { dev.Close(); } catch { }
        _cts?.Cancel();
        _channel?.Writer.TryComplete();
        _dispatchThread?.Join(1000);
        _dispatchThread = null;
        _log.LogInformation("Capture stopped");
        Stopped?.Invoke();
    }

    public IDisposable Subscribe(IFrameHandler handler)
    {
        lock (_handlersSync) _handlers = [.. _handlers, handler];
        return new Unsubscriber(() => { lock (_handlersSync) _handlers = _handlers.Where(h => h != handler).ToArray(); });
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        var data = e.Data.ToArray();
        var ts = e.Header.Timeval.Date;
        bool outbound = data.Length >= 12 && Mac.FromBytes(data.AsSpan(6, 6)) == _localMac;
        var frame = new CapturedFrame(data, ts, Stopwatch.GetTimestamp(), outbound);
        _channel?.Writer.TryWrite(frame);
    }

    private void DispatchLoop(object? state)
    {
        var ct = (CancellationToken)state!;
        var reader = _channel!.Reader;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (!reader.WaitToReadAsync(ct).AsTask().GetAwaiter().GetResult()) break;
                while (reader.TryRead(out var f))
                {
                    _counter.Count(f);
                    _ring.Add(f);
                    var handlers = _handlers;
                    foreach (var h in handlers)
                    {
                        try { h.OnFrame(f); }
                        catch (Exception ex) { _log.LogDebug(ex, "Frame handler {Handler} failed", h.GetType().Name); }
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "Dispatch loop crashed"); }
    }

    private void PublishStats()
    {
        try
        {
            long dropped = Interlocked.Read(ref _channelDrops);
            try { if (_device?.Statistics is { } s) dropped += s.DroppedPackets + s.InterfaceDroppedPackets; } catch { }
            var snap = _counter.Snapshot(dropped);
            _network.LastTraffic = snap;
            _bus.Publish(snap);
        }
        catch (Exception ex) { _log.LogDebug(ex, "stats"); }
    }

    public long Send(ReadOnlySpan<byte> frame)
    {
        var dev = _device ?? throw new InvalidOperationException("Capture is not running");
        lock (_sendSync)
        {
            long t = Stopwatch.GetTimestamp();
            dev.SendPacket(frame);
            return t;
        }
    }

    public async ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default)
    {
        int pps = Math.Max(10, _settings.MaxInjectPps);
        long interval = Stopwatch.Frequency / pps;
        await _paceGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            long now = Stopwatch.GetTimestamp();
            if (_nextSendTicks > now)
            {
                var wait = TimeSpan.FromSeconds((double)(_nextSendTicks - now) / Stopwatch.Frequency);
                if (wait > TimeSpan.FromMilliseconds(1)) await Task.Delay(wait, ct).ConfigureAwait(false);
                else while (Stopwatch.GetTimestamp() < _nextSendTicks) Thread.SpinWait(50);
            }
            _nextSendTicks = Math.Max(Stopwatch.GetTimestamp(), _nextSendTicks) + interval;
        }
        finally { _paceGate.Release(); }
        return Send(frame);
    }

    public string? DumpRecent(string reason)
    {
        try
        {
            var frames = _ring.Snapshot();
            if (frames.Length == 0) return null;
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSpider", "Captures");
            Directory.CreateDirectory(dir);
            var safe = string.Concat(reason.Select(c => char.IsLetterOrDigit(c) ? c : '_'));
            var path = Path.Combine(dir, $"{DateTime.Now:yyyyMMdd-HHmmss}-{safe}.pcapng");
            using var w = PcapNgWriter.Create(path, $"NetSpider dump: {reason}", Adapter?.Name);
            foreach (var f in frames) w.WritePacket(f.TimestampUtc, f.Data);
            _log.LogInformation("Wrote {Count} frames to {Path}", frames.Length, path);
            return path;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "pcapng dump failed");
            return null;
        }
    }

    public void Dispose() => Stop();

    private sealed class Unsubscriber(Action a) : IDisposable { public void Dispose() => a(); }
}

/// <summary>Fixed-size ring of the most recent frames for alert-triggered pcapng dumps.</summary>
internal sealed class RecentFrameRing(int capacity)
{
    private readonly CapturedFrame?[] _items = new CapturedFrame?[capacity];
    private int _next;
    private readonly object _sync = new();

    public void Add(CapturedFrame f)
    {
        lock (_sync) { _items[_next] = f; _next = (_next + 1) % _items.Length; }
    }

    public CapturedFrame[] Snapshot()
    {
        lock (_sync)
        {
            var list = new List<CapturedFrame>(_items.Length);
            for (int i = 0; i < _items.Length; i++)
                if (_items[(_next + i) % _items.Length] is { } f) list.Add(f);
            return list.ToArray();
        }
    }
}
