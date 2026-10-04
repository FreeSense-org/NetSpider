using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Persistence;

namespace NetSpider.Tests.Integration.Export;

public sealed class SqliteRepositoryTests : IDisposable
{
    private readonly string _dir = TestData.TempDir();
    private string DbPath => Path.Combine(_dir, "netspider.db");

    private SqliteDeviceRepository NewRepo() => new(NullLogger<SqliteDeviceRepository>.Instance, DbPath);

    [Fact]
    public async Task Initialize_creates_schema_in_wal_mode()
    {
        using var repo = NewRepo();
        await repo.InitializeAsync();
        await repo.InitializeAsync(); // idempotent

        using var c = new SqliteConnection($"Data Source={DbPath};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode";
        Assert.Equal("wal", (string)cmd.ExecuteScalar()!);
        cmd.CommandText = "SELECT group_concat(name) FROM (SELECT name FROM sqlite_master WHERE type='table' ORDER BY name)";
        Assert.Equal("alerts,devices", (string)cmd.ExecuteScalar()!);
    }

    [Fact]
    public async Task Devices_round_trip()
    {
        var d = new Device(TestData.NasMac)
        {
            Brand = "Synology", Model = "DS920+", Type = DeviceType.Nas, OuiVendor = "Synology Incorporated", UserLabel = "Backup NAS",
            OsGuess = "DSM 7", FirstSeen = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.FromHours(2)),
        };
        d.LastSeen = d.FirstSeen.AddDays(3);
        d.AddIp(IPAddress.Parse("192.168.1.20"));
        d.SetHostname("mdns", "nas.local");
        d.SetPort(new PortInfo(5001, "tcp", PortState.Open, "https"));
        d.AddVlan(10);
        var synthetic = new Device(SyntheticNodes.Internet);

        using (var repo = NewRepo()) await repo.SaveAsync([d, synthetic]);

        using var repo2 = NewRepo();
        var known = await repo2.LoadKnownAsync();
        var k = Assert.Single(known);
        Assert.Equal(TestData.NasMac, k.Mac);
        Assert.Equal("nas.local", k.Name);
        Assert.Equal("Synology", k.Brand);
        Assert.Equal("DS920+", k.Model);
        Assert.Equal(DeviceType.Nas, k.Type);
        Assert.Equal("Backup NAS", k.UserLabel);
        Assert.Equal("192.168.1.20", k.LastIp);
        Assert.Equal(d.FirstSeen, k.FirstSeen);
        Assert.Equal(d.LastSeen, k.LastSeen);

        var json = await repo2.LoadDetailsJsonAsync(TestData.NasMac);
        using var doc = JsonDocument.Parse(json!);
        Assert.Equal("DSM 7", doc.RootElement.GetProperty("osGuess").GetString());
        Assert.Equal(5001, doc.RootElement.GetProperty("ports")[0].GetProperty("port").GetInt32());
        Assert.Equal(10, doc.RootElement.GetProperty("vlans")[0].GetInt32());
    }

    [Fact]
    public async Task Upsert_keeps_earliest_first_seen_and_existing_label()
    {
        using var repo = NewRepo();
        var early = DateTimeOffset.Now.AddDays(-30);
        await repo.SaveAsync([new Device(TestData.RouterMac) { FirstSeen = early, Type = DeviceType.Router }]);
        await repo.SetUserLabelAsync(TestData.RouterMac, "Main router");

        // later session: new device object without label, later first-seen, unknown type
        await repo.SaveAsync([new Device(TestData.RouterMac) { Brand = "Ubiquiti" }]);

        var k = Assert.Single(await repo.LoadKnownAsync());
        Assert.Equal(early.ToUnixTimeMilliseconds(), k.FirstSeen.ToUnixTimeMilliseconds());
        Assert.Equal("Main router", k.UserLabel);
        Assert.Equal(DeviceType.Router, k.Type);
        Assert.Equal("Ubiquiti", k.Brand);

        await repo.SetUserLabelAsync(TestData.RouterMac, null);
        Assert.Null(Assert.Single(await repo.LoadKnownAsync()).UserLabel);
    }

    [Fact]
    public async Task Set_label_for_unknown_device_creates_row()
    {
        using var repo = NewRepo();
        await repo.SetUserLabelAsync(TestData.PhoneMac, "Anna's phone");
        Assert.Equal("Anna's phone", Assert.Single(await repo.LoadKnownAsync()).UserLabel);
    }

    [Fact]
    public async Task Alerts_round_trip_newest_first()
    {
        using var repo = NewRepo();
        var a1 = Alert.Create(AlertSeverity.Warning, AlertKind.BroadcastStorm, "Storm", "800 pps 'quoted'; DROP TABLE alerts;--", TestData.RouterMac, 800.5)
            with { Time = DateTimeOffset.Now.AddMinutes(-5) };
        var a2 = Alert.Create(AlertSeverity.Critical, AlertKind.GatewayMacChanged, "Gateway MAC changed", "x");
        await repo.SaveAlertAsync(a1);
        await repo.SaveAlertAsync(a2);
        await repo.SaveAlertAsync(a2); // idempotent by id

        var list = await repo.LoadAlertsAsync();
        Assert.Equal(2, list.Count);
        Assert.Equal(a2.Id, list[0].Id);
        var r1 = list[1];
        Assert.Equal(a1.Id, r1.Id);
        Assert.Equal(AlertSeverity.Warning, r1.Severity);
        Assert.Equal(AlertKind.BroadcastStorm, r1.Kind);
        Assert.Equal(a1.Details, r1.Details);
        Assert.Equal(TestData.RouterMac, r1.Source);
        Assert.Equal(800.5, r1.Rate);
        Assert.Null(list[0].Source);
    }

    [Fact]
    public async Task Concurrent_saves_do_not_fail()
    {
        using var repo = NewRepo();
        var tasks = Enumerable.Range(0, 20).Select(i => repo.SaveAsync([new Device(new Mac(0x001132000000UL + (ulong)i))]));
        await Task.WhenAll(tasks);
        Assert.Equal(20, (await repo.LoadKnownAsync()).Count);
    }

    public void Dispose() => TestData.TryDelete(_dir);
}
