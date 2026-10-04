using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Persistence;

namespace NetSpider.Tests.Integration.Export;

public sealed class DevicePersistenceServiceTests : IDisposable
{
    private readonly string _dir = TestData.TempDir();
    private readonly DeviceStore _store = new();
    private readonly AlertService _alerts = new();
    private string DbPath => Path.Combine(_dir, "netspider.db");

    private SqliteDeviceRepository NewRepo() => new(NullLogger<SqliteDeviceRepository>.Instance, DbPath);

    private DevicePersistenceService NewService(SqliteDeviceRepository repo) =>
        new(repo, _store, _alerts, NullLogger<DevicePersistenceService>.Instance, TimeSpan.FromHours(1)) { NewDeviceAlertDelay = TimeSpan.FromMilliseconds(50) };

    private static async Task<bool> WaitFor(Func<bool> cond, int ms = 3000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until) { if (cond()) return true; await Task.Delay(20); }
        return cond();
    }

    [Fact]
    public async Task First_run_does_not_flag_or_alert()
    {
        using var repo = NewRepo();
        using (var svc = NewService(repo))
        {
            svc.Start();
            await svc.Ready;
            Assert.False(svc.HadHistory);
            var d = _store.Observe(TestData.NasMac, IPAddress.Parse("192.168.1.20"), "arp");
            await Task.Delay(100);
            Assert.False(d.Has(DeviceFlags.New));
            await svc.FlushAsync();
        }
        Assert.Empty(_alerts.Alerts);
        Assert.Single(await repo.LoadKnownAsync());
    }

    [Fact]
    public async Task Known_device_gets_label_and_first_seen_unknown_device_is_new()
    {
        var firstSeen = DateTimeOffset.Now.AddDays(-100);
        using (var seed = NewRepo())
        {
            await seed.SaveAsync([new Device(TestData.NasMac) { FirstSeen = firstSeen, UserLabel = "Backup NAS" }]);
        }

        using var repo = NewRepo();
        using var svc = NewService(repo);
        svc.Start();
        await svc.Ready;
        Assert.True(svc.HadHistory);

        var known = _store.Observe(TestData.NasMac, IPAddress.Parse("192.168.1.20"), "arp");
        Assert.Equal("Backup NAS", known.UserLabel);
        Assert.Equal(firstSeen.ToUnixTimeMilliseconds(), known.FirstSeen.ToUnixTimeMilliseconds());
        Assert.False(known.Has(DeviceFlags.New));

        var fresh = _store.Observe(TestData.PhoneMac, IPAddress.Parse("192.168.1.50"), "arp");
        Assert.True(fresh.Has(DeviceFlags.New));
        Assert.True(await WaitFor(() => _alerts.Alerts.Any(a => a.Kind == AlertKind.NewDevice)));
        var alert = Assert.Single(_alerts.Alerts);
        Assert.Equal(AlertSeverity.Info, alert.Severity);
        Assert.Equal(TestData.PhoneMac, alert.Source);
        Assert.Contains("192.168.1.50", alert.Details);

        // synthetic nodes are never "new"
        var internet = _store.GetOrAdd(SyntheticNodes.Internet);
        Assert.False(internet.Has(DeviceFlags.New));

        // re-adding the same MAC in this session must not alert again
        _store.Remove(TestData.PhoneMac);
        _store.GetOrAdd(TestData.PhoneMac);
        await Task.Delay(100);
        Assert.Single(_alerts.Alerts);
    }

    [Fact]
    public async Task Devices_added_before_load_are_processed()
    {
        using (var seed = NewRepo()) await seed.SaveAsync([new Device(TestData.RouterMac) { UserLabel = "Router" }]);

        var early = _store.GetOrAdd(TestData.RouterMac);
        var earlyNew = _store.GetOrAdd(TestData.EvilMac);
        using var repo = NewRepo();
        using var svc = NewService(repo);
        svc.Start();
        await svc.Ready;

        Assert.Equal("Router", early.UserLabel);
        Assert.True(earlyNew.Has(DeviceFlags.New));
    }

    [Fact]
    public async Task Dispose_saves_dirty_devices()
    {
        using var repo = NewRepo();
        var svc = NewService(repo);
        svc.Start();
        await svc.Ready;
        var d = _store.Observe(TestData.RouterMac, IPAddress.Parse("192.168.1.1"), "arp");
        d.Brand = "Ubiquiti";
        _store.NotifyChanged(d, "classify");
        svc.Dispose();

        var k = Assert.Single(await repo.LoadKnownAsync());
        Assert.Equal("Ubiquiti", k.Brand);
        Assert.Equal("192.168.1.1", k.LastIp);
    }

    public void Dispose() => TestData.TryDelete(_dir);
}
