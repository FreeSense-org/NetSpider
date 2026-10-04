using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L3;

/// <summary>
/// Collects the IPv4 subnets that exist on the network.
/// <list type="bullet">
/// <item>Scan stage 5: the adapter's own segments (<c>IsLocal</c>) and private prefixes from the Windows route table ("route-table").</item>
/// <item>Frame handler: private source addresses seen in captured IPv4 traffic outside every known segment become /24 candidates ("observed"), once per /24.</item>
/// <item>Other probes feed it too: DHCP option 121, traceroute hops, LLDP/CDP management addresses.</item>
/// </list>
/// New non-local segments get <c>ScanEnabled = settings.ScanOtherSubnets</c>.
/// </summary>
public sealed class SubnetDiscoverer : IActiveProbe, IFrameHandler
{
    private readonly ILogger<SubnetDiscoverer> _log;
    private readonly INetworkState _network;
    private readonly AppSettings _settings;
    private readonly DiscoveryContext _ctx;
    private readonly HashSet<uint> _checked24 = new();
    private readonly object _sync = new();

    public SubnetDiscoverer(ILogger<SubnetDiscoverer> log, INetworkState network, AppSettings settings, DiscoveryContext ctx)
    {
        _log = log;
        _network = network;
        _settings = settings;
        _ctx = ctx;
    }

    public string Name => "Subnet discovery";
    public ProbeLayer Layer => ProbeLayer.L3;
    public int Order => 5;

    public Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _ctx.Update(ctx);
        try
        {
            var a = ctx.Adapter;
            foreach (var ip in a.IPv4)
            {
                if (ip.PrefixLength is <= 0 or >= 32) continue;
                _network.AddOrGetSegment(ip.Address, ip.PrefixLength, "adapter", s =>
                {
                    s.IsLocal = true;
                    s.ScanEnabled = true;
                    if (a.GatewayV4 is { } gw && s.Contains(gw)) s.Gateway = gw;
                });
            }
            progress?.Report(new ScanProgress(Name, 0.3, "adapter segments"));

            int added = 0;
            foreach (var r in SafeRoutes())
            {
                ct.ThrowIfCancellationRequested();
                if (!IsRoutableCandidate(r)) continue;
                if (AddCandidate(r.Destination, r.PrefixLength, "route-table", r.NextHop) is not null) added++;
            }
            _log.LogDebug("Route table contributed {Count} candidate segments", added);
            progress?.Report(new ScanProgress(Name, 1, $"{_network.Segments.Count} segments"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "Subnet discovery failed"); }
        return Task.CompletedTask;
    }

    private IReadOnlyList<RouteEntry> SafeRoutes()
    {
        try { return RouteTable.ReadIPv4(); }
        catch (Exception ex) { _log.LogDebug(ex, "GetIpForwardTable2 failed"); return []; }
    }

    /// <summary>Private, routed (has a next hop), /16../30 prefixes. On-link routes of other adapters (Hyper-V, WSL) are skipped.</summary>
    public static bool IsRoutableCandidate(RouteEntry r) =>
        r.HasGateway && !r.Loopback && r.PrefixLength is >= 16 and <= 30 && IsCandidateAddress(r.Destination);

    /// <summary>RFC 1918 only: link-local 169.254/16 and CGNAT 100.64/10 are never candidate LANs.</summary>
    public static bool IsCandidateAddress(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168);
    }

    /// <summary>Adds a segment unless one already covers it. Returns the new segment, or null when it was already known.</summary>
    public NetworkSegment? AddCandidate(IPAddress network, int prefix, string source, IPAddress? gateway = null, int? vlanId = null)
    {
        if (network.AddressFamily != AddressFamily.InterNetwork || prefix is < 8 or > 30) return null;
        var net = IpUtil.NetworkAddress(network, prefix);
        lock (_sync)
        {
            var existing = _network.Segments;
            if (existing.Any(s => s.Network.Equals(net) && s.PrefixLength == prefix))
            {
                if (vlanId is not null || gateway is not null)
                    _network.AddOrGetSegment(net, prefix, source, s => { s.VlanId ??= vlanId; s.Gateway ??= NonZero(gateway); });
                return null;
            }
            // Already covered by a local segment (e.g. a /24 inside our /16): nothing new.
            if (existing.Any(s => s.IsLocal && s.PrefixLength <= prefix && s.Contains(net))) return null;
            var seg = _network.AddOrGetSegment(net, prefix, source, s =>
            {
                s.IsLocal = false;
                s.ScanEnabled = _settings.ScanOtherSubnets;
                s.Gateway ??= NonZero(gateway);
                s.VlanId ??= vlanId;
            });
            _log.LogInformation("New candidate segment {Cidr} from {Source}", seg.Cidr, source);
            return seg;
        }
    }

    private static IPAddress? NonZero(IPAddress? ip) => ip is null || ip.Equals(IPAddress.Any) ? null : ip;

    /// <summary>A private address seen somewhere (traffic, LLDP mgmt, traceroute): adds its /24 if no known segment covers it.</summary>
    public NetworkSegment? ConsiderAddress(IPAddress ip, string source)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (!IsCandidateAddress(ip) || _ctx.Adapter is null || _ctx.InLocalSegment(ip)) return null;
        uint key = IpUtil.ToUInt32(ip) & 0xFFFFFF00;
        lock (_sync)
        {
            if (_checked24.Count > 65_536) _checked24.Clear();
            if (!_checked24.Add(key)) return null;
        }
        if (_network.Segments.Any(s => s.Contains(ip))) return null;
        return AddCandidate(IpUtil.FromUInt32(key), 24, source);
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.IsOutbound || frame.Eth.EtherType != EthernetView.Ipv4) return;
        try
        {
            var p = frame.Payload;
            if (p.Length < 20) return;
            uint src = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(p[12..]);
            if (!IsCandidateRaw(src)) return;
            uint key = src & 0xFFFFFF00;
            lock (_sync) if (_checked24.Contains(key)) return;
            ConsiderAddress(IpUtil.FromUInt32(src), "observed");
        }
        catch (Exception ex) { _log.LogDebug(ex, "SubnetDiscoverer frame"); }
    }

    private static bool IsCandidateRaw(uint ip)
    {
        uint a = ip >> 24, b = (ip >> 16) & 0xFF;
        return a == 10 || (a == 172 && b is >= 16 and < 32) || (a == 192 && b == 168);
    }
}
