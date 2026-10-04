using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Wifi;
using Xunit.Abstractions;

namespace NetSpider.Tests.Unit.Wifi;

/// <summary>Real wlanapi.dll smoke run. Never fails on machines without Wi-Fi; prints what the APIs return.</summary>
[Trait("Category", "Hardware")]
public sealed class WlanLinkHardwareTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Real_wlan_link_api_smoke()
    {
        using var api = new WlanLinkApi();
        if (!api.Open()) { output.WriteLine($"WLAN unavailable: {api.Status}"); return; }
        output.WriteLine($"Handle open; notifications registered: {api.NotificationsActive} {api.Status}");
        var ifs = api.Interfaces();
        output.WriteLine($"{ifs.Count} interface(s)");
        foreach (var i in ifs)
        {
            output.WriteLine($"  {i.Id} '{i.Description}' state={i.State}");
            output.WriteLine($"  query: {api.Query(i.Id)}");
        }
        output.WriteLine($"Reason 0x3800B (WlanReasonCodeToString): {api.ReasonToString(WlanCodes.ReasonDriverDisconnected)}");
        output.WriteLine($"Reason 0x2800D: {api.ReasonToString(WlanCodes.ReasonKeyMismatch)}");

        // full monitor for a few seconds
        var store = new SettingsStore(Path.Combine(Path.GetTempPath(), $"ns-wifilink-hw-{Guid.NewGuid():N}.json"));
        var bus = new EventBus();
        bus.Subscribe<DiagnosticSignal>(s => output.WriteLine($"  signal {s.Kind}: {s.Summary}"));
        using var mon = new WifiLinkMonitor(store, bus, NullLogger<WifiLinkMonitor>.Instance);
        mon.Start();
        await Task.Delay(TimeSpan.FromSeconds(3.5));
        output.WriteLine($"Monitor: Available={mon.Available} Status={mon.Status} samples={mon.History.Count} events={mon.Events.Count}");
        output.WriteLine($"Current: {mon.Current}");
        foreach (var e in mon.Events) output.WriteLine($"  event {e}");
    }
}
