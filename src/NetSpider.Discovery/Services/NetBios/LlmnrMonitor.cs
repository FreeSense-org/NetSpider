using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Dns;

namespace NetSpider.Discovery.Services.NetBios;

/// <summary>Passive LLMNR (UDP/5355) listener: records the hostnames devices query and answer for.</summary>
public sealed class LlmnrMonitor : IFrameHandler, IPassiveMonitor
{
    private const int LlmnrPort = 5355;
    private const string Source = "llmnr";
    private readonly IDeviceStore _store;
    private readonly ILogger<LlmnrMonitor> _log;
    private readonly ProbeSupport.ActivityThrottle _activity;

    public LlmnrMonitor(IDeviceStore store, IEventBus bus, ILogger<LlmnrMonitor> log)
    {
        _store = store; _log = log;
        _activity = new ProbeSupport.ActivityThrottle(bus);
    }

    public string Name => "LLMNR monitor";
    public void Start(ScanContext ctx) { }
    public void Stop() { }

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            if (frame.IsOutbound) return;
            var udp = UdpView.TryParse(frame);
            if (!udp.Valid || (udp.DstPort != LlmnrPort && udp.SrcPort != LlmnrPort)) return;
            if (!DnsCodec.TryParse(udp.Payload, out var msg)) return;

            var mac = frame.Eth.Source;
            if (mac.IsMulticast || mac.IsBroadcast) return;
            var device = _store.Observe(mac, udp.SrcIp, Source);
            bool changed = false;

            // A responder answering for its own name (authoritative A/AAAA) reveals its hostname.
            if (msg.IsResponse)
                foreach (var rr in msg.Answers)
                    if (rr.Type is DnsType.A or DnsType.Aaaa && !string.IsNullOrWhiteSpace(rr.Name))
                        changed |= device.SetHostname(Source, rr.Name);

            // A querier's own single-label name is a weak hint; store it as a property, not the primary hostname.
            if (!msg.IsResponse && msg.Questions.Count > 0)
                changed |= device.SetProperty("llmnr.query", msg.Questions[0].Name);

            if (changed) _store.NotifyChanged(device, Source);
            _activity.Publish(mac, "LLMNR");
        }
        catch (Exception ex) { _log.LogDebug(ex, "LLMNR parse"); }
    }
}
