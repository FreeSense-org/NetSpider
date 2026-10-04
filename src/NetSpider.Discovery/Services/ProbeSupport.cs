using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Discovery.Services;

/// <summary>Shared helpers for service/application discovery probes.</summary>
internal static class ProbeSupport
{
    /// <summary>
    /// Resolves the device a socket reply belongs to. Prefers the IP index; for an off-segment IP with no known MAC,
    /// falls back to a synthetic remote-host node so evidence is still recorded somewhere.
    /// </summary>
    public static Device ResolveByIp(IDeviceStore store, ScanContext ctx, IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var existing = store.FindByIp(ip);
        if (existing is not null) return existing;
        bool local = ctx.Segments.Any(s => s.IsLocal && s.Contains(ip));
        if (local)
            // On the local segment but MAC not yet learned: index the IP under a placeholder keyed on the IP.
            return store.Observe(SyntheticNodes.RemoteHost(ip), ip, "service");
        return store.Observe(SyntheticNodes.RemoteHost(ip), ip, "service");
    }

    /// <summary>Per-source packet-activity throttle (~4/s) for the graph's packet-rain ripples.</summary>
    public sealed class ActivityThrottle
    {
        private readonly IEventBus _bus;
        private readonly Dictionary<(ulong, string), long> _last = new();
        private readonly object _sync = new();
        private readonly long _minTicks = System.Diagnostics.Stopwatch.Frequency / 4;

        public ActivityThrottle(IEventBus bus) => _bus = bus;

        public void Publish(Mac source, string protocol)
        {
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            lock (_sync)
            {
                var key = (source.Value, protocol);
                if (_last.TryGetValue(key, out var t) && now - t < _minTicks) return;
                _last[key] = now;
            }
            _bus.Publish(new PacketActivity(source, protocol, DateTimeOffset.Now));
        }
    }

    public static IEnumerable<IPAddress> LocalUnicastSourceIps(ScanContext ctx)
    {
        if (ctx.LocalIPv4 is { } v4) yield return v4;
    }
}
