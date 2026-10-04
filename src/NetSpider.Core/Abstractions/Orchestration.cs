using NetSpider.Core.Model;

namespace NetSpider.Core.Abstractions;

/// <summary>Coordinates capture, passive monitors, active scan stages, classification, topology and health.</summary>
public interface IScanOrchestrator
{
    bool IsMonitoring { get; }
    bool IsScanning { get; }
    ScanContext? Context { get; }

    /// <summary>Starts capture on the adapter, subscribes all <see cref="IFrameHandler"/>s, starts all <see cref="IPassiveMonitor"/>s and the latency engine.</summary>
    Task StartMonitoringAsync(AdapterInfo adapter, CancellationToken ct = default);

    /// <summary>Runs all <see cref="IActiveProbe"/>s by order, then <see cref="IDeviceProbe"/>s for every device, then classification, logos, topology and health.</summary>
    Task RunFullScanAsync(CancellationToken ct = default);

    /// <summary>Re-runs all device probes for one device ("deep re-probe").</summary>
    Task ReprobeDeviceAsync(Device device, CancellationToken ct = default);

    void StopAll();

    event Action<ScanProgress>? Progress;
    event Action? ScanCompleted;
}

/// <summary>Services that need to hook events at application start (persistence, notifications, ...).</summary>
public interface IStartable
{
    void Start();
}

public interface ISettingsStore
{
    AppSettings Settings { get; }
    void Save();
    event Action? Saved;
}
