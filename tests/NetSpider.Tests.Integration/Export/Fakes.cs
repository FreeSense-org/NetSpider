using System.Net;
using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Integration.Export;

internal sealed class SingleServiceProvider(object? service) : IServiceProvider
{
    public object? GetService(Type serviceType) => service is not null && serviceType.IsInstanceOfType(service) ? service : null;
}

internal sealed class FakeFrameSource(string dir) : IFrameSource
{
    public bool IsRunning { get; set; }
    public AdapterInfo? Adapter => null;
    public bool PcapAvailable => true;
    public string? PcapVersion => "test";
    public string? LastReason { get; private set; }
    public string? DumpPath { get; private set; }

    public IReadOnlyList<AdapterInfo> ListAdapters() => [];
    public void Start(AdapterInfo adapter) => IsRunning = true;
    public void Stop() => IsRunning = false;
    public IDisposable Subscribe(IFrameHandler handler) => new Nop();
    public long Send(ReadOnlySpan<byte> frame) => 0;
    public ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default) => ValueTask.FromResult(0L);

    public string? DumpRecent(string reason)
    {
        LastReason = reason;
        DumpPath = Path.Combine(dir, $"dump-{Guid.NewGuid():N}.pcapng");
        using var w = PcapNgWriter.Create(DumpPath, "test dump", "eth0");
        w.WritePacket(DateTime.UtcNow, new byte[60]);
        return DumpPath;
    }

    public event Action<AdapterInfo>? Started { add { } remove { } }
    public event Action? Stopped { add { } remove { } }

    private sealed class Nop : IDisposable { public void Dispose() { } }
}

internal sealed class FakeSettingsStore(AppSettings settings) : ISettingsStore
{
    public AppSettings Settings { get; } = settings;
    public void Save() { }
    public event Action? Saved { add { } remove { } }
}

/// <summary>Records every request body; responds 204.</summary>
internal sealed class RecordingHandler : HttpMessageHandler
{
    private readonly object _sync = new();
    public List<(Uri Uri, string MediaType, string Body, DateTime At)> Requests { get; } = new();

    public int Count { get { lock (_sync) return Requests.Count; } }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        lock (_sync) Requests.Add((request.RequestUri!, request.Content?.Headers.ContentType?.MediaType ?? "", body, DateTime.UtcNow));
        return new HttpResponseMessage(HttpStatusCode.NoContent);
    }
}

internal sealed class FakeNotifier : INotifier
{
    public List<Alert> Received { get; } = new();
    public bool Throw { get; set; }

    public Task NotifyAsync(Alert alert, CancellationToken ct = default)
    {
        lock (Received) Received.Add(alert);
        if (Throw) throw new InvalidOperationException("boom");
        return Task.CompletedTask;
    }
}

internal sealed class FakeRepository : IDeviceRepository
{
    public List<Alert> Alerts { get; } = new();
    public Task InitializeAsync(CancellationToken ct = default) => Task.CompletedTask;
    public Task<IReadOnlyList<KnownDevice>> LoadKnownAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<KnownDevice>>([]);
    public Task SaveAsync(IEnumerable<Device> devices, CancellationToken ct = default) => Task.CompletedTask;
    public Task SaveAlertAsync(Alert alert, CancellationToken ct = default) { lock (Alerts) Alerts.Add(alert); return Task.CompletedTask; }
    public Task SetUserLabelAsync(Mac mac, string? label, CancellationToken ct = default) => Task.CompletedTask;
}
