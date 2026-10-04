using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Discovery.Services.Snmp;

namespace NetSpider.Tests.Unit.Discovery.Services.PortHealth;

internal sealed class PortHealthSettingsStore(AppSettings settings) : ISettingsStore
{
    public AppSettings Settings { get; } = settings;
    public void Save() => Saved?.Invoke();
    public event Action? Saved;
}

public sealed class PortHealthMonitorTests
{
    private static readonly Mac Sw = Mac.Parse("00:1B:21:00:00:01");
    private readonly EventBus _bus = new();
    private readonly AlertService _alerts = new();
    private readonly DeviceStore _devices = new();
    private readonly NetworkState _network = new();
    private readonly AppSettings _settings = new();
    private readonly PortHealthMonitor _monitor;
    private readonly List<DiagnosticSignal> _signals = new();

    public PortHealthMonitorTests()
    {
        _monitor = new PortHealthMonitor(NullLogger<PortHealthMonitor>.Instance, _devices, _network, _bus, _alerts, new PortHealthSettingsStore(_settings));
        _bus.Subscribe<DiagnosticSignal>(_signals.Add);
        var sw = _devices.GetOrAdd(Sw);
        sw.SetHostname("snmp", "core-sw-01");
    }

    private static PortCounterSample S(int ifIndex, string name, DateTimeOffset t, ulong fcs = 0, bool up = true) =>
        new(Sw, ifIndex, name, t, up, 1000, "full", TimeSpan.FromSeconds(10), 0, 0, fcs, 0, 0, 0, 0, 0, 0, fcs, 0, 0, 0);

    [Fact]
    public void Transitions_publish_signals_with_switch_and_port_and_raise_alerts_once()
    {
        var t0 = DateTimeOffset.Now;
        _monitor.Apply(Sw, new PortCounterPoll(TimeSpan.FromHours(1), [S(7, "Gi1/0/7", t0), S(8, "Gi1/0/8", t0)]));
        _monitor.Apply(Sw, new PortCounterPoll(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(60),
            [S(7, "Gi1/0/7", t0.AddSeconds(60), fcs: 6000), S(8, "Gi1/0/8", t0.AddSeconds(60), fcs: 6000)]));

        Assert.Equal(2, _signals.Count(s => s.Kind == SignalKind.PortErrors));
        var sig = _signals.First(s => s.Port == "Gi1/0/7");
        Assert.Equal(Sw, sig.Device);
        Assert.Contains("core-sw-01", sig.Summary);
        // per-port cooldown: both ports alert, even though they share the switch MAC
        Assert.Equal(2, _alerts.Alerts.Count(a => a.Kind == PortHealthMonitor.AlertKindFor(SignalKind.PortErrors)));
    }

    [Fact]
    public void Ports_and_lookup_by_name_or_ifindex_after_publish()
    {
        var t0 = DateTimeOffset.Now;
        _monitor.Apply(Sw, new PortCounterPoll(null, [S(7, "Gi1/0/7", t0)]));
        Assert.Empty(_monitor.Ports);
        int updated = 0;
        _monitor.Updated += () => updated++;
        _monitor.Publish();
        Assert.Equal(1, updated);
        Assert.Single(_monitor.Ports);
        Assert.NotNull(_monitor.Get(Sw, "gi1/0/7"));
        Assert.NotNull(_monitor.Get(Sw, "7"));
        Assert.Null(_monitor.Get(Sw, "Gi1/0/9"));
        Assert.Null(_monitor.Get(Mac.Parse("00:00:00:00:00:99"), "Gi1/0/7"));
        Assert.Single(_monitor.History(Sw, "Gi1/0/7"));
    }

    [Fact]
    public void Targets_are_snmp_devices_and_switches_with_ports()
    {
        var snmp = _devices.Observe(Mac.Parse("00:1B:21:00:00:02"), IPAddress.Parse("192.168.1.2"), "test");
        snmp.SetProperty("snmp.sysObjectID", "1.3.6.1.4.1.9.1.1");
        var sw2 = _devices.Observe(Mac.Parse("00:1B:21:00:00:03"), IPAddress.Parse("192.168.1.3"), "test");
        _network.SetSwitchPorts(sw2.Mac, [new SwitchPortInfo(sw2.Mac, 1, "1", null, 1000, true, "full", null, null)]);
        _devices.Observe(Mac.Parse("00:1B:21:00:00:04"), IPAddress.Parse("192.168.1.4"), "test"); // plain host
        var noIp = _devices.GetOrAdd(Mac.Parse("00:1B:21:00:00:05"));
        noIp.SetProperty("snmp.community", "public");

        var targets = _monitor.Targets().Select(d => d.Mac).ToHashSet();
        Assert.Equal(2, targets.Count);
        Assert.Contains(snmp.Mac, targets);
        Assert.Contains(sw2.Mac, targets);
    }

    [Fact]
    public void Alert_kind_mapping_uses_dedicated_port_kinds()
    {
        Assert.Equal(AlertKind.PortErrors, PortHealthMonitor.AlertKindFor(SignalKind.PortErrors));
        Assert.Equal(AlertKind.PortFlapping, PortHealthMonitor.AlertKindFor(SignalKind.PortFlapping));
        Assert.Equal(AlertKind.DuplexMismatch, PortHealthMonitor.AlertKindFor(SignalKind.PortDuplexMismatch));
    }
}
