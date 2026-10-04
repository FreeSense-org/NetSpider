using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;

namespace NetSpider.Discovery.L3;

/// <summary>
/// Scan stage 150: traces the path to 1.1.1.1 into <see cref="INetworkState.InternetPath"/>. Private hops outside the
/// local segments (double NAT, routed LANs) are added as /24 candidate segments ("traceroute").
/// </summary>
public sealed class TracerouteProbe : IActiveProbe
{
    public static readonly IPAddress Target = IPAddress.Parse("1.1.1.1");
    private const int MaxHops = 20;

    private readonly ILogger<TracerouteProbe> _log;
    private readonly ITracerouter _tracer;
    private readonly INetworkState _network;
    private readonly SubnetDiscoverer _subnets;
    private readonly DiscoveryContext _dctx;

    public TracerouteProbe(ILogger<TracerouteProbe> log, ITracerouter tracer, INetworkState network, SubnetDiscoverer subnets, DiscoveryContext dctx)
    {
        _log = log;
        _tracer = tracer;
        _network = network;
        _subnets = subnets;
        _dctx = dctx;
    }

    public string Name => "Traceroute";
    public ProbeLayer Layer => ProbeLayer.L3;
    public int Order => 150;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        if (!ctx.Settings.Traceroute) return;
        try
        {
            progress?.Report(new ScanProgress(Name, 0.1, $"tracing {Target}"));
            var hops = await _tracer.TraceAsync(Target, MaxHops, ct).ConfigureAwait(false);
            if (hops.Count == 0) return;
            _network.InternetPath = hops;
            foreach (var h in hops)
            {
                if (h.Address is not { } ip || !SubnetDiscoverer.IsCandidateAddress(ip) || _dctx.InLocalSegment(ip)) continue;
                _subnets.AddCandidate(IpUtil.NetworkAddress(ip, 24), 24, "traceroute", ip);
            }
            progress?.Report(new ScanProgress(Name, 1, $"{hops.Count} hops"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "Traceroute stage failed"); }
    }
}
