using NetSpider.Core.Model;

namespace NetSpider.Core.Abstractions;

// All monitors below publish DiagnosticSignal records on IEventBus; IIncidentService correlates them into incidents.

/// <summary>Builds and continuously probes the hop chain from this PC to the internet (Path Doctor).</summary>
public interface IPathMonitor
{
    bool IsRunning { get; }
    NetworkPath? Path { get; }
    /// <summary>Recomputes the hop chain from topology + traceroute (called after scans/topology changes).</summary>
    void Rebuild();
    event Action<NetworkPath>? Updated;
}

/// <summary>Correlates diagnostic signals into incidents with a root-cause hypothesis (fault locator).</summary>
public interface IIncidentService
{
    IReadOnlyList<Incident> Incidents { get; }
    IReadOnlyList<Incident> Active { get; }
    void Clear();
    event Action<Incident>? IncidentChanged;
}

public interface IIncidentRepository
{
    Task SaveIncidentAsync(Incident incident, CancellationToken ct = default);
    Task<IReadOnlyList<Incident>> LoadIncidentsAsync(int max, CancellationToken ct = default);
    /// <summary>Deletes all stored incidents (Settings → "Clear device history and incidents").</summary>
    Task ClearAsync(CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>Polls SNMP IF-MIB/EtherLike counters on managed switches and derives per-port health.</summary>
public interface IPortHealthMonitor
{
    IReadOnlyList<PortHealth> Ports { get; }
    PortHealth? Get(Mac switchMac, string port);
    event Action? Updated;
}

/// <summary>Dedicated broadcast-storm tool: live state, sources, ingress ports, loop suspects, history, opt-in active check.</summary>
public interface IStormCenter
{
    StormStatus Status { get; }
    IReadOnlyList<StormEvent> History { get; }
    /// <summary>Writes the rolling capture to pcapng and returns the path (null when capture is not running).</summary>
    string? RecordNow();
    /// <summary>Opt-in active test (requires <see cref="AppSettings.StormControlCheckEnabled"/>): sends a short, rate-limited broadcast burst and reports whether storm-control reacted.</summary>
    Task<StormControlResult> RunStormControlCheckAsync(StormControlOptions options, CancellationToken ct);
    event Action<StormStatus>? Updated;
}

/// <summary>Continuous capture-to-file recorder: streams every captured frame into a pcapng until stopped (or a cap is hit).</summary>
public interface IPacketRecorder
{
    bool IsRecording { get; }
    string? Path { get; }
    DateTimeOffset? Started { get; }
    long Frames { get; }
    long Bytes { get; }
    /// <summary>Why the last recording ended ("stopped", "size limit", "time limit", "capture stopped", error text).</summary>
    string? StopReason { get; }
    /// <summary>Starts recording; returns the file path, or null when capture isn't running or a recording is already active.</summary>
    string? Start(string label, long maxBytes = 1L << 30, TimeSpan? maxDuration = null);
    /// <summary>Stops recording and returns the finished file path (null when nothing was recording).</summary>
    string? Stop();
    event Action? Changed;
}

/// <summary>This host's Wi-Fi link telemetry (RSSI, rates, roams, disconnect reasons) and per-AP health.</summary>
public interface IWifiLinkMonitor
{
    bool Available { get; }
    WifiLinkSample? Current { get; }
    IReadOnlyList<WifiLinkSample> History { get; }
    IReadOnlyList<WifiEvent> Events { get; }
    event Action? Updated;
}

public interface IApHealthMonitor
{
    IReadOnlyList<ApHealth> AccessPoints { get; }
    event Action? Updated;
}

/// <summary>Receives reports from NetSpider.Probe agents on the LAN.</summary>
public interface IProbeAgentHub
{
    bool IsListening { get; }
    int Port { get; }
    IReadOnlyList<ProbeAgentInfo> Agents { get; }
    event Action? Updated;
}
