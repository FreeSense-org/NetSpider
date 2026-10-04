using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Scan stage 50: when no IGMP querier has been heard after at least 10 s of capture, sends ONE IGMPv2 general query
/// (max response time 1 s) and lets <see cref="IgmpMonitor"/> collect the membership reports for 3 s. This reveals
/// multicast group membership per device on networks without a querier.
/// <para>
/// Querier-election risk: IGMP queriers elect the lowest source IP. Our query makes this host the querier for the
/// "other querier present" interval (~255 s) on networks that had none, and on a network whose querier we simply did
/// not hear yet (e.g. a 125 s query interval) a lower-addressed host would win the election only after our query
/// times out, while a snooping switch may briefly treat our port as an mrouter port and flood multicast to it. This is
/// why only a single query is sent, only when no querier was seen, and only if <see cref="AppSettings.IgmpQuery"/> is on.
/// </para>
/// </summary>
public sealed class IgmpQueryProbe : IActiveProbe
{
    private static readonly TimeSpan MinObservation = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CollectFor = TimeSpan.FromSeconds(3);
    private static readonly IPAddress AllHosts = IPAddress.Parse("224.0.0.1");
    private const byte MaxResponseTenths = 10;

    private readonly ILogger<IgmpQueryProbe> _log;
    private readonly IFrameSource _frames;
    private readonly INetworkState _network;
    private readonly IgmpMonitor _monitor;
    private readonly DiscoveryContext _dctx;

    public IgmpQueryProbe(ILogger<IgmpQueryProbe> log, IFrameSource frames, INetworkState network, IgmpMonitor monitor, DiscoveryContext dctx)
    {
        _log = log;
        _frames = frames;
        _network = network;
        _monitor = monitor;
        _dctx = dctx;
    }

    public string Name => "IGMP query";
    public ProbeLayer Layer => ProbeLayer.L2;
    public int Order => 50;

    /// <summary>true when the last run actually sent a query.</summary>
    public bool QuerySent { get; private set; }

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        QuerySent = false;
        if (!ctx.Settings.IgmpQuery || !_frames.IsRunning || ctx.LocalIPv4 is not { } local) return;
        try
        {
            var observed = _monitor.ObservedFor;
            if (_dctx.MonitoringSince is { } since && DateTimeOffset.Now - since > observed) observed = DateTimeOffset.Now - since;
            if (observed < MinObservation)
            {
                progress?.Report(new ScanProgress(Name, 0.1, "listening for an existing querier"));
                await Task.Delay(MinObservation - observed, ct).ConfigureAwait(false);
            }
            if (_network.IgmpQuerier is not null || _monitor.SinceLastQuery is not null)
            {
                _log.LogDebug("IGMP querier present ({Querier}); not querying", _network.IgmpQuerier);
                return;
            }

            _frames.Send(BuildQueryFrame(ctx.LocalMac, local, MaxResponseTenths));
            QuerySent = true;
            _log.LogInformation("No IGMP querier seen; sent one IGMPv2 general query");
            progress?.Report(new ScanProgress(Name, 0.5, "collecting membership reports"));
            await Task.Delay(CollectFor, ct).ConfigureAwait(false);
            progress?.Report(new ScanProgress(Name, 1, null));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "IGMP query failed"); }
    }

    /// <summary>Ethernet + IPv4 (TTL 1, Router Alert option, DSCP CS6) + IGMPv2 general query to 224.0.0.1.</summary>
    public static byte[] BuildQueryFrame(Mac src, IPAddress srcIp, byte maxRespTenths)
    {
        var igmp = IgmpParser.BuildV2GeneralQuery(maxRespTenths);
        var frame = new byte[60];
        int o = FrameBuilder.WriteEthernet(frame, IpUtil.MulticastMac(AllHosts), src, EthernetView.Ipv4);
        var ip = frame.AsSpan(o, 24 + igmp.Length);
        ip[0] = 0x46; ip[1] = 0xC0;
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(24 + igmp.Length));
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)Random.Shared.Next(1, 65535));
        ip[8] = 1; ip[9] = IpView.Igmp;
        srcIp.TryWriteBytes(ip[12..], out _);
        AllHosts.TryWriteBytes(ip[16..], out _);
        ip[20] = 0x94; ip[21] = 0x04; // Router Alert
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], FrameBuilder.Checksum(ip[..24]));
        igmp.CopyTo(ip[24..]);
        return frame;
    }
}
