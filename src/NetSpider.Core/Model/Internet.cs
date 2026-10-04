using System.Net;

namespace NetSpider.Core.Model;

public enum InternetState { Disabled, Starting, Online, Degraded, Offline }

/// <summary>Live state of one internet ping target.</summary>
public sealed record InternetTargetStatus(
    string Name, string Host, IPAddress? Address, bool Up, double? LastMs, LatencySummary Summary,
    IReadOnlyList<double?> Recent, DateTimeOffset? DownSince, string? Error);

/// <summary>A period during which every enabled target failed.</summary>
public sealed record InternetOutage(DateTimeOffset Start, DateTimeOffset? End)
{
    public TimeSpan Duration => (End ?? DateTimeOffset.Now) - Start;
    public bool Ongoing => End is null;
}

public sealed record InternetStatus(
    InternetState State, DateTimeOffset Since, IReadOnlyList<InternetTargetStatus> Targets,
    IReadOnlyList<InternetOutage> Outages, double UptimePercent, double? BestMs, DateTimeOffset Updated)
{
    public static readonly InternetStatus Disabled = new(InternetState.Disabled, DateTimeOffset.Now, [], [], 100, null, DateTimeOffset.Now);
}
