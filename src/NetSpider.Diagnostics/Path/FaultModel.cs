using System.Net;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.PathDoctor;

/// <summary>What the fault rules need to know about one device.</summary>
public sealed record NodeInfo(Mac Mac, string Name, DeviceType Type, IPAddress? Ip, bool Online, bool Inferred, bool ThisHost, bool Gateway)
{
    public bool IsAp => Type == DeviceType.AccessPoint;
    public bool IsSwitch => Type is DeviceType.CoreSwitch or DeviceType.AccessSwitch or DeviceType.UnmanagedSwitch || Inferred;
    public string Label => Ip is null ? Name : $"{Name} ({Ip})";

    public static NodeInfo From(Device d) => new(d.Mac, d.DisplayName, d.Type, d.PrimaryIPv4, d.State != DeviceState.Offline,
        d.Has(DeviceFlags.Inferred) || (SyntheticNodes.IsGraphOnly(d.Mac) && d.PrimaryIPv4 is null) || d.Type == DeviceType.Internet,
        d.Has(DeviceFlags.ThisHost), d.Has(DeviceFlags.Gateway));
}

/// <summary>Everything the fault rules look at for one evaluation. Pure data, so the rules are deterministic.</summary>
/// <param name="Active">Conditions that are currently on (down-type signals without a later recovery, recent one-shot signals).</param>
/// <param name="Window">All signals in the correlation window (used as evidence).</param>
/// <param name="Unreachable">Devices that went offline within the window and are still offline.</param>
public sealed record FaultSnapshot(
    DateTimeOffset Now,
    IReadOnlyList<DiagnosticSignal> Active,
    IReadOnlyList<DiagnosticSignal> Window,
    NetworkPath? Path,
    IReadOnlyCollection<Mac> Unreachable,
    TopologyTree? Tree,
    IReadOnlyDictionary<Mac, NodeInfo> Nodes)
{
    public static FaultSnapshot Create(DateTimeOffset now, IEnumerable<DiagnosticSignal>? active = null, NetworkPath? path = null,
        IEnumerable<Mac>? unreachable = null, TopologyTree? tree = null, IEnumerable<Device>? devices = null, IEnumerable<DiagnosticSignal>? window = null)
    {
        var a = active?.ToList() ?? [];
        return new FaultSnapshot(now, a, window?.ToList() ?? a, path, unreachable?.ToHashSet() ?? [], tree,
            (devices ?? []).Select(NodeInfo.From).ToDictionary(n => n.Mac));
    }
}

/// <summary>Root-cause hypothesis produced by <see cref="FaultRules"/>.</summary>
public sealed record FaultVerdict(
    IncidentCategory Category, AlertSeverity Severity, string Title, string RootCause, double Confidence,
    Mac? SuspectDevice, string? SuspectPort, string? SuspectLink, IReadOnlyList<Mac> Affected, IReadOnlyList<string> Evidence);

/// <summary>Decides which signals still describe an ongoing condition.</summary>
public static class SignalActivity
{
    /// <summary>How long one-shot signals (errors, flaps, speed changes…) keep a condition open.</summary>
    public static readonly TimeSpan OneShotHold = TimeSpan.FromSeconds(60);
    /// <summary>Down-type signals without a matching recovery expire after this long.</summary>
    public static readonly TimeSpan MaxConditionAge = TimeSpan.FromMinutes(15);

    /// <summary>Recovery kind for each down-type kind.</summary>
    private static readonly Dictionary<SignalKind, SignalKind> Pairs = new()
    {
        [SignalKind.LocalLinkDown] = SignalKind.LocalLinkUp,
        [SignalKind.HopDown] = SignalKind.HopUp,
        [SignalKind.HopDegraded] = SignalKind.HopUp,
        [SignalKind.PortDown] = SignalKind.PortUp,
        [SignalKind.StormDetected] = SignalKind.StormEnded,
        [SignalKind.WifiDisconnected] = SignalKind.WifiConnected,
        [SignalKind.AgentReportFailure] = SignalKind.AgentReportRecovered,
        [SignalKind.AgentOffline] = SignalKind.AgentReportRecovered,
        [SignalKind.InternetDown] = SignalKind.InternetUp,
    };

    private static readonly HashSet<SignalKind> Recoveries =
        [SignalKind.LocalLinkUp, SignalKind.HopUp, SignalKind.PortUp, SignalKind.StormEnded, SignalKind.WifiConnected, SignalKind.AgentReportRecovered, SignalKind.InternetUp];

    /// <summary>Signals that represent an ongoing condition at <paramref name="now"/>.</summary>
    public static IReadOnlyList<DiagnosticSignal> Active(IEnumerable<DiagnosticSignal> history, DateTimeOffset now)
    {
        var ordered = history.OrderBy(s => s.Time).ToList();
        var result = new List<DiagnosticSignal>();
        for (int i = 0; i < ordered.Count; i++)
        {
            var s = ordered[i];
            if (s.Time > now) continue;
            if (Recoveries.Contains(s.Kind)) continue;
            if (Pairs.TryGetValue(s.Kind, out var up))
            {
                if (now - s.Time > MaxConditionAge) continue;
                bool cleared = false;
                for (int j = i + 1; j < ordered.Count && !cleared; j++)
                {
                    var o = ordered[j];
                    if (o.Time > now) break;
                    if ((o.Kind == up || o.Kind == s.Kind) && SameSubject(s, o)) cleared = true; // recovered, or superseded by a newer copy
                }
                if (!cleared) result.Add(s);
            }
            else if (now - s.Time <= OneShotHold) result.Add(s);
        }
        return result;
    }

    private static bool SameSubject(DiagnosticSignal a, DiagnosticSignal b) => a.Kind switch
    {
        // one global condition each
        SignalKind.LocalLinkDown or SignalKind.StormDetected or SignalKind.WifiDisconnected or SignalKind.InternetDown => true,
        SignalKind.HopDown or SignalKind.HopDegraded => a.Source == b.Source,
        SignalKind.PortDown => a.Device == b.Device && PortEquals(a.Port, b.Port),
        _ => a.Source == b.Source && a.Device == b.Device,
    };

    public static bool PortEquals(string? a, string? b) =>
        a is not null && b is not null && string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);
}
