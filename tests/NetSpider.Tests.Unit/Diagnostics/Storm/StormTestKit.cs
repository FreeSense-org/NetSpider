using System.Diagnostics;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.Diagnostics.Storm;

/// <summary>Frame source that never touches a NIC: records every injected frame and serves dumps from a temp folder.</summary>
internal sealed class StormFakeFrameSource : IFrameSource
{
    private readonly object _sync = new();
    private readonly List<byte[]> _sent = new();
    public string DumpDir { get; } = Path.Combine(Path.GetTempPath(), "netspider-storm-tests", Guid.NewGuid().ToString("N"));
    public int Dumps;

    public bool IsRunning { get; set; }
    public AdapterInfo? Adapter { get; set; }
    public bool PcapAvailable => true;
    public string? PcapVersion => "fake";
    public int SentCount { get { lock (_sync) return _sent.Count; } }
    public IReadOnlyList<byte[]> Sent { get { lock (_sync) return _sent.ToArray(); } }

    public IReadOnlyList<AdapterInfo> ListAdapters() => Adapter is null ? [] : [Adapter];
    public void Start(AdapterInfo adapter) { Adapter = adapter; IsRunning = true; }
    public void Stop() => IsRunning = false;
    public IDisposable Subscribe(IFrameHandler handler) => new Noop();

    public long Send(ReadOnlySpan<byte> frame)
    {
        lock (_sync) _sent.Add(frame.ToArray());
        return Stopwatch.GetTimestamp();
    }

    public ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default) => ValueTask.FromResult(Send(frame));

    public string? DumpRecent(string reason)
    {
        Interlocked.Increment(ref Dumps);
        Directory.CreateDirectory(DumpDir);
        var path = Path.Combine(DumpDir, $"{reason}-{Dumps}.pcapng");
        File.WriteAllBytes(path, []);
        return path;
    }

    public event Action<AdapterInfo>? Started { add { } remove { } }
    public event Action? Stopped { add { } remove { } }
    private sealed class Noop : IDisposable { public void Dispose() { } }
}

internal sealed class FakePortHealthMonitor : IPortHealthMonitor
{
    public List<PortHealth> List { get; } = new();
    public IReadOnlyList<PortHealth> Ports => List;
    public PortHealth? Get(Mac switchMac, string port) => List.FirstOrDefault(p => p.Switch == switchMac && string.Equals(p.Name, port, StringComparison.OrdinalIgnoreCase));
    public event Action? Updated { add { } remove { } }

    public static PortHealth Port(Mac sw, string name, double bcastPps, double mcastPps = 0, bool up = true, int ifIndex = 1) =>
        new(sw, ifIndex, name, up, 1000, "full", 0, 0, 0, 0, 0, bcastPps, mcastPps, 0, false, false, null, up ? HopHealth.Up : HopHealth.Down, DateTimeOffset.Now);
}
