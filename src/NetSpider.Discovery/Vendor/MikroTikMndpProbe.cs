using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services;

namespace NetSpider.Discovery.Vendor;

/// <summary>MikroTik MNDP: broadcasts a request on UDP/5678 and also parses MNDP datagrams seen passively on the wire.</summary>
public sealed class MikroTikMndpProbe : IActiveProbe, IFrameHandler
{
    private const int Port = 5678;
    private readonly IDeviceStore _store;
    private readonly ILogger<MikroTikMndpProbe> _log;

    public MikroTikMndpProbe(IDeviceStore store, ILogger<MikroTikMndpProbe> log) { _store = store; _log = log; }

    public string Name => "MikroTik MNDP";
    public ProbeLayer Layer => ProbeLayer.Vendor;
    public int Order => 216;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0));
        var targets = new List<IPEndPoint> { new(IPAddress.Broadcast, Port) };
        try
        {
            await VendorUdp.BroadcastCollectAsync(ctx.LocalIPv4, Port, targets, MikroTikMndp.Request,
                TimeSpan.FromSeconds(3), (data, from) => HandleDatagram(ctx, data, from), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "MNDP probe"); }
        progress?.Report(new ScanProgress(Name, 1));
    }

    private void HandleDatagram(ScanContext ctx, byte[] data, IPEndPoint from)
    {
        var info = MikroTikMndp.Parse(data);
        if (info is null) return;
        var mac = info.Mac ?? _store.FindByIp(from.Address)?.Mac;
        var device = mac is { } m ? _store.Observe(m, info.IPv4 ?? from.Address, "vendor:mikrotik")
                                  : ProbeSupport.ResolveByIp(_store, ctx, from.Address);
        if (MikroTikMndp.Apply(device, info)) _store.NotifyChanged(device, "vendor:mikrotik");
    }

    // Passive: MNDP is also sent to UDP/5678; capture the frames directly.
    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            if (frame.IsOutbound) return;
            var udp = UdpView.TryParse(frame);
            if (!udp.Valid || (udp.SrcPort != Port && udp.DstPort != Port)) return;
            var info = MikroTikMndp.Parse(udp.Payload);
            if (info is null) return;
            var mac = info.Mac ?? frame.Eth.Source;
            var device = _store.Observe(mac, info.IPv4 ?? udp.SrcIp, "vendor:mikrotik");
            if (MikroTikMndp.Apply(device, info)) _store.NotifyChanged(device, "vendor:mikrotik");
        }
        catch (Exception ex) { _log.LogDebug(ex, "MNDP frame"); }
    }
}
