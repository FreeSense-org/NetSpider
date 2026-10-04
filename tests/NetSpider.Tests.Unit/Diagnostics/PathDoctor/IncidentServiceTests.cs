using System.Collections.Concurrent;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.PathDoctor;
using static NetSpider.Tests.Unit.Diagnostics.PathDoctor.Office;

namespace NetSpider.Tests.Unit.Diagnostics.PathDoctor;

internal sealed class ManualTime : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 4, 14, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(double seconds) => Now = Now.AddSeconds(seconds);
}

internal sealed class FakeIncidentRepository : IIncidentRepository
{
    public readonly ConcurrentDictionary<Guid, Incident> Saved = new();
    public List<Incident> Preload { get; init; } = [];

    public Task SaveIncidentAsync(Incident incident, CancellationToken ct = default) { Saved[incident.Id] = incident; return Task.CompletedTask; }
    public Task<IReadOnlyList<Incident>> LoadIncidentsAsync(int max, CancellationToken ct = default) => Task.FromResult<IReadOnlyList<Incident>>(Preload);
}

public sealed class IncidentServiceTests : IDisposable
{
    private readonly Office _o = new();
    private readonly EventBus _bus = new();
    private readonly AlertService _alerts = new();
    private readonly ManualTime _time = new();
    private readonly SettingsStore _settings = new(Path.Combine(Path.GetTempPath(), $"ns-inc-{Guid.NewGuid():N}.json"));
    private readonly FakeFrameSource _frames = new();
    private readonly FakeIncidentRepository _repo = new();
    private IncidentService? _svc;

    private IncidentService Service(IIncidentRepository? repo = null)
    {
        _svc = new IncidentService(_bus, _alerts, _o.Devices, _o.Topology, _settings, NullLogger<IncidentService>.Instance,
            frames: _frames, repository: repo ?? _repo, time: _time);
        _svc.Start(autoTick: false);
        return _svc;
    }

    private DiagnosticSignal At(SignalKind kind, string summary, Mac? device = null, string? port = null) =>
        Sig(kind, summary, device, port, time: _time.Now);

    [Fact]
    public async Task Own_link_incident_opens_alerts_dumps_pcap_and_closes_after_clear_period()
    {
        _frames.Start(new AdapterInfo { Id = "x", PcapName = "x", Name = "Ethernet" });
        var svc = Service();
        var changes = new List<Incident>();
        svc.IncidentChanged += changes.Add;

        _bus.Publish(At(SignalKind.LocalLinkDown, "Cable unplugged or switch port down on Ethernet", _o.Me.Mac, "Ethernet"));
        _time.Advance(1);
        svc.Tick();

        var inc = Assert.Single(svc.Active);
        Assert.Equal(IncidentCategory.OwnLink, inc.Category);
        Assert.Contains("on Ethernet", inc.RootCause);
        Assert.Equal(@"C:\dumps\incident.pcapng", inc.PcapPath);
        var alert = Assert.Single(_alerts.Alerts);
        Assert.Equal(AlertSeverity.Critical, alert.Severity);
        Assert.Equal(inc.Title, alert.Title);
        Assert.Equal(_o.Me.Mac, alert.Source);
        Assert.Contains(inc.RootCause, alert.Details);

        // still down: same incident, no new alert
        _time.Advance(5);
        svc.Tick();
        Assert.Single(svc.Incidents);
        Assert.Single(_alerts.Alerts);

        _bus.Publish(At(SignalKind.LocalLinkUp, "Link restored on Ethernet", _o.Me.Mac, "Ethernet"));
        var clearedAt = _time.Now;
        svc.Tick();
        _time.Advance(20);
        svc.Tick();
        Assert.Single(svc.Active);
        _time.Advance(11);
        svc.Tick();
        Assert.Empty(svc.Active);
        var closed = Assert.Single(svc.Incidents);
        Assert.Equal(clearedAt, closed.End);
        Assert.Contains(changes, c => c.End is not null);

        await WaitFor(() => _repo.Saved.TryGetValue(inc.Id, out var s) && s.End is not null);
    }

    [Fact]
    public void Devices_going_offline_together_become_one_lca_incident()
    {
        var svc = Service();
        foreach (var tv in _o.Tvs.Take(2))
        {
            tv.State = DeviceState.Offline;
            _o.Devices.NotifyChanged(tv, "state");
        }
        _time.Advance(3);
        foreach (var tv in _o.Tvs.Skip(2))
        {
            tv.State = DeviceState.Offline;
            _o.Devices.NotifyChanged(tv, "state");
        }
        svc.Tick();
        var inc = Assert.Single(svc.Active);
        Assert.Equal(IncidentCategory.LocalNetwork, inc.Category);
        Assert.Equal(_o.TvRack.Mac, inc.SuspectDevice);
        Assert.Equal(4, inc.Affected.Count);

        // a port error signal arriving later updates the same incident with boosted confidence
        _bus.Publish(At(SignalKind.PortErrors, "340 CRC errors/min", _o.Core.Mac, "7"));
        svc.Tick();
        var updated = Assert.Single(svc.Incidents);
        Assert.Equal(inc.Id, updated.Id);
        Assert.True(updated.Confidence > inc.Confidence);
        Assert.Contains(updated.Evidence, e => e.Contains("CRC"));

        // devices come back → closes 30 s later
        foreach (var tv in _o.Tvs) { tv.State = DeviceState.Online; _o.Devices.NotifyChanged(tv, "state"); }
        _time.Advance(61); // the port signal's hold time also expires
        svc.Tick();
        _time.Advance(31);
        svc.Tick();
        Assert.Empty(svc.Active);
    }

    [Fact]
    public void Path_updates_feed_the_path_cut_rule()
    {
        var svc = Service();
        svc.SetPath(_o.Path(HopHealth.Up, HopHealth.Up, HopHealth.Up, HopHealth.Down, HopHealth.Down, HopHealth.Down));
        svc.Tick();
        var inc = Assert.Single(svc.Active);
        Assert.Equal(IncidentCategory.Modem, inc.Category);
        Assert.Equal(AlertKind.Incident, _alerts.Alerts.Single().Kind);
    }

    [Fact]
    public void Storm_signal_maps_to_storm_alert_kind()
    {
        var svc = Service();
        _bus.Publish(At(SignalKind.StormDetected, "ARP storm 4200 pps", _o.Core.Mac, "7"));
        svc.Tick();
        Assert.Equal(IncidentCategory.Storm, Assert.Single(svc.Active).Category);
        Assert.Equal(AlertKind.BroadcastStorm, _alerts.Alerts.Single().Kind);
    }

    [Fact]
    public void Quiet_network_creates_nothing()
    {
        var svc = Service();
        svc.Tick();
        _bus.Publish(At(SignalKind.LocalIpChanged, "IP changed"));
        svc.Tick();
        Assert.Empty(svc.Incidents);
        Assert.Empty(_alerts.Alerts);
    }

    [Fact]
    public async Task Loads_recent_incidents_from_repository_and_closes_stale_ones()
    {
        var old = new Incident(Guid.NewGuid(), _time.Now.AddHours(-2), null, AlertSeverity.Warning, IncidentCategory.Isp, "Internet / ISP outage",
            "x", 0.5, null, null, null, [], [], null);
        var repo = new FakeIncidentRepository { Preload = [old] };
        var svc = Service(repo);
        await WaitFor(() => svc.Incidents.Count == 1);
        var loaded = svc.Incidents[0];
        Assert.Equal(old.Id, loaded.Id);
        Assert.False(loaded.Ongoing);
        Assert.Empty(svc.Active);
        svc.Clear();
        Assert.Empty(svc.Incidents);
    }

    private static async Task WaitFor(Func<bool> cond)
    {
        var end = DateTime.UtcNow.AddSeconds(5);
        while (!cond())
        {
            if (DateTime.UtcNow > end) Assert.Fail("condition not reached in time");
            await Task.Delay(20);
        }
    }

    public void Dispose() => _svc?.Dispose();
}
