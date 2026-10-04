using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Internet;

namespace NetSpider.Tests.Unit.Diagnostics;

public class InternetMonitorTests
{
    private static SettingsStore TempSettings() => new(Path.Combine(Path.GetTempPath(), $"ns-inet-{Guid.NewGuid():N}.json"));

    [Fact]
    public void Disabled_by_default()
    {
        var store = TempSettings();
        Assert.False(store.Settings.InternetMonitorEnabled);
        using var mon = new InternetMonitor(store, new AlertService(), NullLogger<InternetMonitor>.Instance);
        mon.Start();
        Assert.False(mon.IsRunning);
        Assert.Equal(InternetState.Disabled, mon.Status.State);
    }

    [Fact]
    public async Task Goes_offline_then_restores_with_alerts()
    {
        var store = TempSettings();
        store.Settings.InternetMonitorEnabled = true;
        store.Settings.InternetIntervalSeconds = 1;
        store.Settings.InternetOutageRounds = 2;
        store.Settings.InternetTargets = [new InternetTarget { Name = "TEST-NET", Host = "192.0.2.1" }];
        var alerts = new AlertService();
        using var mon = new InternetMonitor(store, alerts, NullLogger<InternetMonitor>.Instance);
        mon.Start();

        await WaitFor(() => mon.Status.State == InternetState.Offline, TimeSpan.FromSeconds(15));
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.InternetDown && a.Severity == AlertSeverity.Critical);

        store.Settings.InternetTargets = [new InternetTarget { Name = "Loopback", Host = "127.0.0.1" }];
        store.Save(); // Saved -> ApplySettings
        await WaitFor(() => mon.Status.State == InternetState.Online, TimeSpan.FromSeconds(10));
        Assert.Contains(alerts.Alerts, a => a.Kind == AlertKind.InternetRestored);
        var outage = Assert.Single(mon.Status.Outages);
        Assert.False(outage.Ongoing);

        store.Settings.InternetMonitorEnabled = false;
        store.Save();
        Assert.False(mon.IsRunning);
        Assert.Equal(InternetState.Disabled, mon.Status.State);
    }

    private static async Task WaitFor(Func<bool> cond, TimeSpan timeout)
    {
        var end = DateTime.UtcNow + timeout;
        while (!cond())
        {
            if (DateTime.UtcNow > end) Assert.Fail("condition not reached in time");
            await Task.Delay(100);
        }
    }
}
