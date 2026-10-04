using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Dns;

/// <summary>Reverse-DNS (PTR) lookup for each device's primary IP, with a short timeout. Hostname source "dns".</summary>
public sealed class ReverseDnsProbe : IDeviceProbe
{
    private readonly IDeviceStore _store;
    private readonly ILogger<ReverseDnsProbe> _log;

    public ReverseDnsProbe(IDeviceStore store, ILogger<ReverseDnsProbe> log) { _store = store; _log = log; }

    public string Name => "Reverse DNS";
    public int Order => 240;

    public bool AppliesTo(Device device, ScanContext ctx) => device.IPv4.Length > 0 || device.IPv6.Length > 0;

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4 ?? device.IPv6.FirstOrDefault()?.Address;
        if (ip is null) return;
        try
        {
            var lookup = System.Net.Dns.GetHostEntryAsync(ip);
            // if we stop waiting, the lookup may still fault later: observe it so it is not logged as unobserved
            _ = lookup.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            var done = await Task.WhenAny(lookup, Task.Delay(1500, ct)).ConfigureAwait(false);
            if (done != lookup) return;
            var entry = await lookup.ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(entry.HostName) && !IPAddress.TryParse(entry.HostName, out _))
            {
                if (device.SetHostname("dns", entry.HostName))
                    _store.NotifyChanged(device, "dns");
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "PTR {Ip}", ip); }
    }
}
