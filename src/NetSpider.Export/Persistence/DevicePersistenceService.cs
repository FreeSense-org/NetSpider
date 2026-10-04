using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Export.Persistence;

/// <summary>
/// Bridges the in-memory <see cref="IDeviceStore"/> and the <see cref="IDeviceRepository"/>: restores user labels and first-seen
/// times for returning devices, flags and alerts on genuinely new devices, and saves changed devices every 30 s and on dispose.
/// </summary>
public sealed class DevicePersistenceService : IStartable, IDisposable
{
    private readonly IDeviceRepository _repo;
    private readonly IDeviceStore _store;
    private readonly IAlertService _alerts;
    private readonly ILogger<DevicePersistenceService> _log;
    private readonly TimeSpan _saveInterval;
    private readonly ConcurrentDictionary<Mac, KnownDevice> _known = new();
    private readonly ConcurrentDictionary<Mac, Device> _dirty = new();
    private readonly ConcurrentDictionary<Mac, byte> _processed = new();
    private readonly List<Device> _pendingAdds = new();
    private readonly object _sync = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _loaded;
    private bool _started;
    private bool _disposed;
    private Task? _loop;

    public DevicePersistenceService(IDeviceRepository repo, IDeviceStore store, IAlertService alerts, ILogger<DevicePersistenceService> log)
        : this(repo, store, alerts, log, TimeSpan.FromSeconds(30)) { }

    public DevicePersistenceService(IDeviceRepository repo, IDeviceStore store, IAlertService alerts, ILogger<DevicePersistenceService> log, TimeSpan saveInterval)
    {
        _repo = repo;
        _store = store;
        _alerts = alerts;
        _log = log;
        _saveInterval = saveInterval;
    }

    /// <summary>Delay before the NewDevice alert is raised, so the alert can include the IP/vendor learned right after discovery.</summary>
    public TimeSpan NewDeviceAlertDelay { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>When set and <see cref="INetworkState.IsDemo"/> is true, devices are neither persisted nor alerted on.</summary>
    public INetworkState? Network { get; init; }

    private bool Suspended => Network?.IsDemo == true;

    /// <summary>true when the database contained at least one device before this session (enables "new device" alerts).</summary>
    public bool HadHistory { get; private set; }

    /// <summary>Completes when the known devices have been loaded (or loading failed).</summary>
    public Task Ready => _ready.Task;

    public IReadOnlyDictionary<Mac, KnownDevice> Known => _known;

    public void Start()
    {
        lock (_sync)
        {
            if (_started) return;
            _started = true;
        }
        _store.DeviceAdded += OnDeviceAdded;
        _store.DeviceChanged += OnDeviceChanged;
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            await _repo.InitializeAsync(ct).ConfigureAwait(false);
            var known = await _repo.LoadKnownAsync(ct).ConfigureAwait(false);
            foreach (var k in known) _known[k.Mac] = k;
            HadHistory = known.Count > 0;
            _log.LogInformation("Loaded {Count} known devices from history", known.Count);
        }
        catch (OperationCanceledException) { _ready.TrySetResult(); return; }
        catch (Exception ex)
        {
            // Without history we cannot tell new from returning devices; treat this session like a first run.
            _log.LogError(ex, "Could not load device history");
        }

        List<Device> backlog;
        lock (_sync)
        {
            _loaded = true;
            backlog = [.. _pendingAdds, .. _store.All];
            _pendingAdds.Clear();
        }
        foreach (var d in backlog) Process(d);
        _ready.TrySetResult();

        try
        {
            using var timer = new PeriodicTimer(_saveInterval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                await FlushAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "Device persistence loop failed"); }
    }

    private void OnDeviceAdded(Device d)
    {
        if (Suspended) return;
        lock (_sync)
        {
            if (!_loaded) { _pendingAdds.Add(d); return; }
        }
        Process(d);
    }

    private void OnDeviceChanged(Device d, string? reason)
    {
        if (Suspended) return;
        if (!SyntheticNodes.IsGraphOnly(d.Mac)) _dirty[d.Mac] = d;
    }

    private const string Reason = "persistence";

    private void Process(Device d)
    {
        try
        {
            if (Suspended || SyntheticNodes.IsGraphOnly(d.Mac)) return;
            if (!_processed.TryAdd(d.Mac, 0))
            {
                // Same MAC re-added after a store Clear(): re-apply the label but never alert twice in one session.
                if (_known.TryGetValue(d.Mac, out var again)) ApplyKnown(d, again);
                return;
            }

            if (_known.TryGetValue(d.Mac, out var k))
            {
                ApplyKnown(d, k);
            }
            else
            {
                _known[d.Mac] = new KnownDevice(d.Mac, null, null, null, DeviceType.Unknown, null, null, d.FirstSeen, d.LastSeen);
                if (HadHistory)
                {
                    d.SetFlag(DeviceFlags.New);
                    _store.NotifyChanged(d, Reason);
                    _ = RaiseNewDeviceAsync(d);
                }
            }
            _dirty[d.Mac] = d;
        }
        catch (Exception ex) { _log.LogWarning(ex, "Persistence handling failed for {Mac}", d.Mac); }
    }

    private void ApplyKnown(Device d, KnownDevice k)
    {
        bool changed = false;
        if (d.UserLabel is null && k.UserLabel is not null) { d.UserLabel = k.UserLabel; changed = true; }
        if (k.FirstSeen != DateTimeOffset.MinValue && k.FirstSeen < d.FirstSeen) { d.FirstSeen = k.FirstSeen; changed = true; }
        if (changed) _store.NotifyChanged(d, Reason);
    }

    private async Task RaiseNewDeviceAsync(Device d)
    {
        try
        {
            if (NewDeviceAlertDelay > TimeSpan.Zero) await Task.Delay(NewDeviceAlertDelay, _cts.Token).ConfigureAwait(false);
            var ip = d.PrimaryIPv4?.ToString() ?? d.IPv6.FirstOrDefault()?.Address.ToString();
            var who = d.OuiVendor ?? d.Brand;
            var details = $"A device that has never been seen on this network appeared: MAC {d.Mac}"
                + (ip is null ? "" : $", IP {ip}")
                + (who is null ? "" : $", vendor {who}")
                + (d.Hostname is { } h ? $", hostname {h}" : "")
                + (d.Has(DeviceFlags.RandomizedMac) ? " (randomized MAC)" : "") + ".";
            _alerts.Raise(Alert.Create(AlertSeverity.Info, AlertKind.NewDevice, $"New device: {d.DisplayName}", details, d.Mac), TimeSpan.Zero);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogWarning(ex, "Could not raise NewDevice alert for {Mac}", d.Mac); }
    }

    /// <summary>Saves all devices changed since the last flush.</summary>
    public async Task FlushAsync(CancellationToken ct = default)
    {
        await _saveGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_dirty.IsEmpty) return;
            var batch = new List<Device>();
            foreach (var mac in _dirty.Keys.ToList())
                if (_dirty.TryRemove(mac, out var d)) batch.Add(d);
            try
            {
                await _repo.SaveAsync(batch, ct).ConfigureAwait(false);
                _log.LogDebug("Saved {Count} devices", batch.Count);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                foreach (var d in batch) _dirty.TryAdd(d.Mac, d); // retry on the next tick
                _log.LogWarning(ex, "Saving {Count} devices failed", batch.Count);
            }
        }
        finally { _saveGate.Release(); }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
        }
        _store.DeviceAdded -= OnDeviceAdded;
        _store.DeviceChanged -= OnDeviceChanged;
        try { _cts.Cancel(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try
        {
            if (!FlushAsync().Wait(TimeSpan.FromSeconds(10))) _log.LogWarning("Final device save timed out");
        }
        catch (Exception ex) { _log.LogWarning(ex, "Final device save failed"); }
        _cts.Dispose();
    }
}
