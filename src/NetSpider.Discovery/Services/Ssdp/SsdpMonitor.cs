using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Ssdp;

/// <summary>Passive SSDP listener: NOTIFY and M-SEARCH responses on UDP/1900, keeping LOCATION/SERVER/USN.</summary>
public sealed class SsdpMonitor : IFrameHandler, IPassiveMonitor
{
    private const int SsdpPort = 1900;
    private readonly IDeviceStore _store;
    private readonly ILogger<SsdpMonitor> _log;
    private readonly ProbeSupport.ActivityThrottle _activity;

    public SsdpMonitor(IDeviceStore store, IEventBus bus, ILogger<SsdpMonitor> log)
    {
        _store = store; _log = log;
        _activity = new ProbeSupport.ActivityThrottle(bus);
    }

    public string Name => "SSDP monitor";
    public void Start(ScanContext ctx) { }
    public void Stop() { }

    public void OnFrame(CapturedFrame frame)
    {
        try
        {
            if (frame.IsOutbound) return;
            var udp = UdpView.TryParse(frame);
            if (!udp.Valid || (udp.SrcPort != SsdpPort && udp.DstPort != SsdpPort)) return;
            if (udp.Payload.Length < 8) return;
            var text = Encoding.ASCII.GetString(udp.Payload);
            if (!text.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("HTTP/1.1", StringComparison.OrdinalIgnoreCase))
                return; // ignore M-SEARCH requests themselves
            var headers = SsdpInterpreter.ParseHeaders(text);

            var mac = frame.Eth.Source;
            if (mac.IsMulticast || mac.IsBroadcast) return;
            var device = _store.Observe(mac, udp.SrcIp, "ssdp");
            bool changed = SsdpInterpreter.ApplyHeaders(device, headers);
            if (headers.TryGetValue("LOCATION", out var loc)) changed |= device.SetProperty("ssdp.location", loc);
            if (changed) _store.NotifyChanged(device, "ssdp");
            _activity.Publish(mac, "SSDP");
        }
        catch (Exception ex) { _log.LogDebug(ex, "SSDP parse failed"); }
    }
}
