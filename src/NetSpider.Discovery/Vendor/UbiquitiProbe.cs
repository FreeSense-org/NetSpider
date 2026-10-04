using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services;

namespace NetSpider.Discovery.Vendor;

/// <summary>Ubiquiti device discovery: broadcasts the v1 request on UDP/10001 and parses the TLV responses.</summary>
public sealed class UbiquitiProbe : IActiveProbe
{
    private const int Port = 10001;
    private readonly IDeviceStore _store;
    private readonly ILogger<UbiquitiProbe> _log;

    public UbiquitiProbe(IDeviceStore store, ILogger<UbiquitiProbe> log) { _store = store; _log = log; }

    public string Name => "Ubiquiti discovery";
    public ProbeLayer Layer => ProbeLayer.Vendor;
    public int Order => 215;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0));
        var targets = new List<IPEndPoint> { new(IPAddress.Broadcast, Port) };
        if (ctx.LocalSegment is { } seg) targets.Add(new IPEndPoint(BroadcastOf(seg), Port));
        try
        {
            await VendorUdp.BroadcastCollectAsync(ctx.LocalIPv4, 0, targets, UbiquitiDiscovery.Request,
                TimeSpan.FromSeconds(3), (data, from) => Handle(ctx, data, from), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "Ubiquiti probe"); }
        progress?.Report(new ScanProgress(Name, 1));
    }

    private void Handle(ScanContext ctx, byte[] data, IPEndPoint from)
    {
        try
        {
            var info = UbiquitiDiscovery.Parse(data);
            if (info is null) return;
            var mac = info.Hwaddr ?? _store.FindByIp(from.Address)?.Mac;
            var device = mac is { } m ? _store.Observe(m, info.IpAddress ?? from.Address, "vendor:ubiquiti")
                                      : ProbeSupport.ResolveByIp(_store, ctx, from.Address);
            if (UbiquitiDiscovery.Apply(device, info)) _store.NotifyChanged(device, "vendor:ubiquiti");
        }
        catch (Exception ex) { _log.LogDebug(ex, "Ubiquiti parse"); }
    }

    private static IPAddress BroadcastOf(NetworkSegment seg)
    {
        uint net = IpUtil.ToUInt32(seg.Network);
        uint bcast = net | ~IpUtil.MaskOf(seg.PrefixLength);
        return IpUtil.FromUInt32(bcast);
    }
}
