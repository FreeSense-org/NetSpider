using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.LocalLink;

/// <summary>
/// Watches this host's own NIC: Windows <see cref="NetworkChange"/> events plus a 2 s poll of the capture adapter (or the
/// best physical adapter) for operational status, speed, IPv4 and gateway. Publishes LocalLinkDown/Up, LocalSpeedChanged,
/// LocalIpChanged, LocalGatewayChanged and DhcpLeaseLost <see cref="DiagnosticSignal"/>s on the event bus.
/// </summary>
public sealed class LocalLinkWatcher : IStartable, IDisposable
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    private readonly IEventBus _bus;
    private readonly ILogger<LocalLinkWatcher> _log;
    private readonly IFrameSource? _frames;
    private readonly SemaphoreSlim _kick = new(0, int.MaxValue);
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private LocalLinkState? _last;
    private string? _adapterId;

    public LocalLinkWatcher(IEventBus bus, ILogger<LocalLinkWatcher> log, IFrameSource? frames = null)
    {
        _bus = bus;
        _log = log;
        _frames = frames;
    }

    /// <summary>Latest snapshot of the watched adapter.</summary>
    public LocalLinkState? Current { get { lock (_sync) return _last; } }

    public bool IsRunning => _loop is { IsCompleted: false };

    public void Start()
    {
        if (IsRunning) return;
        NetworkChange.NetworkAvailabilityChanged += OnAvailability;
        NetworkChange.NetworkAddressChanged += OnAddress;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    private void OnAvailability(object? sender, NetworkAvailabilityEventArgs e) => Kick();
    private void OnAddress(object? sender, EventArgs e) => Kick();

    private void Kick()
    {
        try { if (_kick.CurrentCount < 4) _kick.Release(); } catch { }
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { Poll(); }
            catch (Exception ex) { _log.LogDebug(ex, "Local link poll failed"); }
            try
            {
                await _kick.WaitAsync(PollInterval, ct).ConfigureAwait(false);
                // NetworkChange fires in bursts: let the stack settle a moment
                await Task.Delay(200, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>One poll: choose the adapter, snapshot it, diff and publish.</summary>
    public void Poll()
    {
        var nic = ChooseAdapter();
        var cur = nic is null ? null : LocalAdapters.Snapshot(nic);
        if (cur is null) return;
        LocalLinkState? prev;
        lock (_sync)
        {
            prev = _last;
            _last = cur;
            _adapterId = cur.Id;
        }
        foreach (var s in LocalLinkRules.Diff(prev, cur, DateTimeOffset.Now))
        {
            _log.LogInformation("Local link: {Kind} {Summary}", s.Kind, s.Summary);
            _bus.Publish(s);
        }
    }

    private NetworkInterface? ChooseAdapter()
    {
        // 1. the capture adapter, when capture runs
        if (_frames is { IsRunning: true, Adapter: { } a } && LocalAdapters.FindById(a.Id) is { } cap) return cap;

        // 2. stick to the adapter we were watching so a pulled cable is reported, unless another adapter took over
        string? id;
        bool wasUp;
        lock (_sync) { id = _adapterId; wasUp = _last?.Up == true; }
        var current = id is null ? null : LocalAdapters.FindById(id);
        if (current is not null && current.OperationalStatus == OperationalStatus.Up) return current;
        // just went down: report it on this poll, consider switching adapters on the next one
        if (current is not null && wasUp) return current;

        // 3. best physical adapter (up, has a gateway); fall back to the stale one so its "down" state is visible
        return LocalAdapters.FindBest() ?? current;
    }

    public void Dispose()
    {
        NetworkChange.NetworkAvailabilityChanged -= OnAvailability;
        NetworkChange.NetworkAddressChanged -= OnAddress;
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts?.Dispose();
        _cts = null;
    }
}
