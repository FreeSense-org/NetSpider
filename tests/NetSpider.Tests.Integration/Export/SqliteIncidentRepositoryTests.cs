using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Export.Persistence;

namespace NetSpider.Tests.Integration.Export;

public sealed class SqliteIncidentRepositoryTests : IDisposable
{
    private readonly string _dir = TestData.TempDir();
    private string DbPath => Path.Combine(_dir, "netspider.db");

    private SqliteIncidentRepository NewRepo() => new(NullLogger<SqliteIncidentRepository>.Instance, DbPath);

    private static Incident Sample(DateTimeOffset start, DateTimeOffset? end = null, string title = "Modem unreachable") => new(
        Guid.NewGuid(), start, end, AlertSeverity.Critical, IncidentCategory.Modem, title,
        "Everything up to OPNsense (10.40.0.1) answers; the ISP modem 10.255.104.1 does not → modem or the router↔modem cable/WAN link",
        0.8, TestData.RouterMac, "igb1", "OPNsense ↔ Modem 10.255.104.1",
        [TestData.RouterMac, TestData.NasMac], ["Modem 10.255.104.1: no answer for 3 rounds", TestData.Evil], @"C:\caps\incident.pcapng");

    [Fact]
    public async Task Incidents_round_trip_and_update_in_place()
    {
        var start = new DateTimeOffset(2026, 10, 4, 14, 2, 3, TimeSpan.FromHours(2));
        var inc = Sample(start);
        using (var repo = NewRepo())
        {
            await repo.SaveIncidentAsync(inc);
            await repo.SaveIncidentAsync(inc with { End = start.AddMinutes(3), Confidence = 0.9 });
        }

        using var repo2 = NewRepo();
        var loaded = Assert.Single(await repo2.LoadIncidentsAsync(10));
        Assert.Equal(inc.Id, loaded.Id);
        Assert.Equal(start, loaded.Start);
        Assert.Equal(start.AddMinutes(3), loaded.End);
        Assert.Equal(AlertSeverity.Critical, loaded.Severity);
        Assert.Equal(IncidentCategory.Modem, loaded.Category);
        Assert.Equal(inc.Title, loaded.Title);
        Assert.Equal(inc.RootCause, loaded.RootCause);
        Assert.Equal(0.9, loaded.Confidence);
        Assert.Equal(TestData.RouterMac, loaded.SuspectDevice);
        Assert.Equal("igb1", loaded.SuspectPort);
        Assert.Equal(inc.SuspectLink, loaded.SuspectLink);
        Assert.Equal(inc.Affected, loaded.Affected);
        Assert.Equal(inc.Evidence, loaded.Evidence);
        Assert.Equal(inc.PcapPath, loaded.PcapPath);
    }

    [Fact]
    public async Task Nulls_round_trip_and_load_returns_most_recent_oldest_first()
    {
        var t0 = DateTimeOffset.Now.AddHours(-1);
        using var repo = NewRepo();
        for (int i = 0; i < 5; i++)
            await repo.SaveIncidentAsync(new Incident(Guid.NewGuid(), t0.AddMinutes(i), null, AlertSeverity.Warning, IncidentCategory.Unknown,
                $"#{i}", "r", 0.3, null, null, null, [], [], null));
        var list = await repo.LoadIncidentsAsync(3);
        Assert.Equal(["#2", "#3", "#4"], list.Select(i => i.Title).ToArray());
        Assert.All(list, i => { Assert.Null(i.End); Assert.Null(i.SuspectDevice); Assert.Empty(i.Affected); Assert.Null(i.PcapPath); });
    }

    [Fact]
    public async Task Shares_the_database_with_the_device_repository()
    {
        using (var devices = new SqliteDeviceRepository(NullLogger<SqliteDeviceRepository>.Instance, DbPath))
            await devices.InitializeAsync();
        using (var repo = NewRepo())
            await repo.SaveIncidentAsync(Sample(DateTimeOffset.Now));

        using var c = new SqliteConnection($"Data Source={DbPath};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT group_concat(name) FROM (SELECT name FROM sqlite_master WHERE type='table' ORDER BY name)";
        Assert.Equal("alerts,devices,incidents", (string)cmd.ExecuteScalar()!);
        cmd.CommandText = "SELECT affected FROM incidents";
        Assert.StartsWith("[\"", (string)cmd.ExecuteScalar()!);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        TestData.TryDelete(_dir);
    }
}
