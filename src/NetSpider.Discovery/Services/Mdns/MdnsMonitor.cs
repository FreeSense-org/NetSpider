using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Dns;

namespace NetSpider.Discovery.Services.Mdns;

/// <summary>Passive mDNS parser: every UDP/5353 frame (v4 and v6, query or response) is mapped to its source MAC.</summary>
public sealed class MdnsMonitor : IFrameHandler, IPassiveMonitor
{
    private const int MdnsPort = 5353;
    private readonly IDeviceStore _store;
    private readonly ILogger<MdnsMonitor> _log;
    private readonly ProbeSupport.ActivityThrottle _activity;

    public MdnsMonitor(IDeviceStore store, IEventBus bus, ILogger<MdnsMonitor> log)
    {
        _store = store;
        _log = log;
        _activity = new ProbeSupport.ActivityThrottle(bus);
    }

    public string Name => "mDNS monitor";
    public void Start(ScanContext ctx) { }
    public void Stop() { }

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            if (frame.IsOutbound) return;
            var udp = UdpView.TryParse(frame);
            if (!udp.Valid || (udp.DstPort != MdnsPort && udp.SrcPort != MdnsPort)) return;
            if (!DnsCodec.TryParse(udp.Payload, out var msg)) return;

            var mac = frame.Eth.Source;
            if (mac.IsMulticast || mac.IsBroadcast) return;
            var device = _store.Observe(mac, udp.SrcIp, "mdns");
            var packet = udp.Payload.ToArray();
            if (MdnsInterpreter.Apply(device, packet, msg))
                _store.NotifyChanged(device, "mdns");
            _activity.Publish(mac, "mDNS");
        }
        catch (Exception ex) { _log.LogDebug(ex, "mDNS parse failed"); }
    }
}
