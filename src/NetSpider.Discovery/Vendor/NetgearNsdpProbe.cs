using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services;

namespace NetSpider.Discovery.Vendor;

/// <summary>Netgear NSDP probe: sends a read request from the local NSDP port to the broadcast address and parses replies.</summary>
public sealed class NetgearNsdpProbe : IActiveProbe
{
    // classic firmware listens 63321(local)->63322; newer uses 63323->63324.
    private static readonly (int Local, int Remote)[] PortPairs = { (63321, 63322), (63323, 63324) };

    private readonly IDeviceStore _store;
    private readonly ILogger<NetgearNsdpProbe> _log;

    public NetgearNsdpProbe(IDeviceStore store, ILogger<NetgearNsdpProbe> log) { _store = store; _log = log; }

    public string Name => "Netgear NSDP";
    public ProbeLayer Layer => ProbeLayer.Vendor;
    public int Order => 217;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0));
        var request = NetgearNsdp.BuildReadRequest(ctx.LocalMac, (uint)Environment.TickCount);
        foreach (var (local, remote) in PortPairs)
        {
            if (ct.IsCancellationRequested) break;
            var targets = new List<IPEndPoint> { new(IPAddress.Broadcast, remote) };
            try
            {
                await VendorUdp.BroadcastCollectAsync(ctx.LocalIPv4, local, targets, request,
                    TimeSpan.FromMilliseconds(1500), (data, from) => Handle(ctx, data, from), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "NSDP probe {Local}", local); }
        }
        progress?.Report(new ScanProgress(Name, 1));
    }

    private void Handle(ScanContext ctx, byte[] data, IPEndPoint from)
    {
        var info = NetgearNsdp.Parse(data);
        if (info is null) return;
        var mac = info.Mac ?? _store.FindByIp(from.Address)?.Mac;
        var device = mac is { } m ? _store.Observe(m, info.Ip ?? from.Address, "vendor:netgear")
                                  : ProbeSupport.ResolveByIp(_store, ctx, from.Address);
        if (NetgearNsdp.Apply(device, info)) _store.NotifyChanged(device, "vendor:netgear");
    }
}
