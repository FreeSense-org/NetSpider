using NetSpider.Diagnostics.PathDoctor;
using NetSpider.Diagnostics.Wifi;
using NetSpider.Diagnostics.Agents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Capture;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics;
using NetSpider.Discovery;
using NetSpider.Export;
using NetSpider.Fingerprint;
using NetSpider.Wifi;

namespace NetSpider.Tests.Integration.Composition;

/// <summary>Wires every workstream's registration together exactly as the app does and resolves all roles.</summary>
public class EngineCompositionTests
{
    private static ServiceProvider Build()
    {
        var services = new ServiceCollection()
            .AddLogging(b => b.SetMinimumLevel(LogLevel.Warning))
            .AddNetSpiderCore()
            .AddNetSpiderCapture()
            .AddNetSpiderL2Discovery()
            .AddNetSpiderServiceDiscovery()
            .AddNetSpiderFingerprint()
            .AddNetSpiderDiagnostics()
            .AddNetSpiderWifi()
            .AddNetSpiderExport()
            .AddNetSpiderIncidentStore()
            .AddNetSpiderPathDoctor()
            .AddNetSpiderPortHealth()
            .AddNetSpiderStormCenter()
          .AddNetSpiderWifiLink()
          .AddNetSpiderApHealth()
          .AddNetSpiderProbeAgents();
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    [Fact]
    public void All_core_services_resolve()
    {
        using var sp = Build();
        Assert.NotNull(sp.GetRequiredService<IScanOrchestrator>());
        Assert.NotNull(sp.GetRequiredService<IPathMonitor>());
        Assert.NotNull(sp.GetRequiredService<IIncidentService>());
        Assert.NotNull(sp.GetRequiredService<IIncidentRepository>());
        Assert.NotNull(sp.GetRequiredService<IPortHealthMonitor>());
        Assert.NotNull(sp.GetRequiredService<IStormCenter>());
        Assert.NotNull(sp.GetRequiredService<IWifiLinkMonitor>());
        Assert.NotNull(sp.GetRequiredService<IApHealthMonitor>());
        Assert.NotNull(sp.GetRequiredService<IProbeAgentHub>());
        Assert.NotNull(sp.GetRequiredService<IInternetMonitor>());
        Assert.NotNull(sp.GetRequiredService<IFrameSource>());
        Assert.NotNull(sp.GetRequiredService<ILatencyProber>());
        Assert.NotNull(sp.GetRequiredService<ILatencyEngine>());
        Assert.NotNull(sp.GetRequiredService<ITopologyBuilder>());
        Assert.NotNull(sp.GetRequiredService<IHealthService>());
        Assert.NotNull(sp.GetRequiredService<ITracerouter>());
        Assert.NotNull(sp.GetRequiredService<IWakeOnLan>());
        Assert.NotNull(sp.GetRequiredService<IOuiLookup>());
        Assert.NotNull(sp.GetRequiredService<IDeviceClassifier>());
        Assert.NotNull(sp.GetRequiredService<ILogoProvider>());
        Assert.NotNull(sp.GetRequiredService<IWifiScanner>());
        Assert.NotNull(sp.GetRequiredService<IDeviceRepository>());
        Assert.NotEmpty(sp.GetServices<IExporter>());
        Assert.NotEmpty(sp.GetServices<INotifier>());
        Assert.NotEmpty(sp.GetServices<IStartable>());
        Assert.NotEmpty(sp.GetServices<IRemotePinger>());
    }

    [Fact]
    public void Probes_have_unique_names_and_expected_order()
    {
        using var sp = Build();
        var active = sp.GetServices<IActiveProbe>().OrderBy(p => p.Order).ToList();
        var names = active.Select(p => p.Name).ToList();
        Assert.Equal(names.Count, names.Distinct().Count());
        // L2 sweeps precede service discovery which precedes the gateway audit.
        int Idx(string fragment) => names.FindIndex(n => n.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        Assert.True(Idx("ARP") >= 0 && Idx("mDNS") > Idx("ARP"));
        Assert.True(Idx("Gateway") > Idx("SSDP"));

        var device = sp.GetServices<IDeviceProbe>().ToList();
        Assert.Equal(device.Count, device.Select(p => p.GetType()).Distinct().Count());
        Assert.Contains(device, p => p.Name.Contains("Port", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(device, p => p.Name.Contains("TLS", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(device, p => p.Name.Contains("SNMP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Frame_handlers_are_singletons_shared_with_their_other_roles()
    {
        using var sp = Build();
        var handlers = sp.GetServices<IFrameHandler>().ToList();
        Assert.Equal(handlers.Count, handlers.Distinct().Count());
        Assert.Contains(handlers, h => ReferenceEquals(h, sp.GetRequiredService<ILatencyProber>()));
        Assert.True(handlers.Count >= 12, $"expected many frame handlers, got {handlers.Count}");
    }

    [Fact]
    public void Startables_start_without_capture()
    {
        using var sp = Build();
        foreach (var s in sp.GetServices<IStartable>()) s.Start();
    }
}
