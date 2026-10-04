using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Capture;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics;
using NetSpider.Diagnostics.LocalLink;
using NetSpider.Diagnostics.PathDoctor;
using NetSpider.Discovery;
using NetSpider.Export;
using NetSpider.Export.Persistence;
using NetSpider.Fingerprint;
using NetSpider.Wifi;

namespace NetSpider.Tests.Integration.Composition;

/// <summary>The Path Doctor and incident store registrations compose with the rest of the engine.</summary>
public class PathDoctorCompositionTests
{
    [Fact]
    public void Path_doctor_and_incident_store_resolve_as_singletons()
    {
        using var sp = new ServiceCollection()
            .AddLogging(b => b.SetMinimumLevel(LogLevel.Warning))
            .AddNetSpiderCore()
            .AddNetSpiderCapture()
            .AddNetSpiderL2Discovery()
            .AddNetSpiderServiceDiscovery()
            .AddNetSpiderFingerprint()
            .AddNetSpiderDiagnostics()
            .AddNetSpiderWifi()
            .AddNetSpiderExport()
            .AddNetSpiderPathDoctor()
            .AddNetSpiderIncidentStore()
            .BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        Assert.Same(sp.GetRequiredService<PathMonitor>(), sp.GetRequiredService<IPathMonitor>());
        Assert.Same(sp.GetRequiredService<IncidentService>(), sp.GetRequiredService<IIncidentService>());
        Assert.IsType<SqliteIncidentRepository>(sp.GetRequiredService<IIncidentRepository>());
        var startables = sp.GetServices<IStartable>().ToList();
        Assert.Contains(startables, s => s is PathMonitor);
        Assert.Contains(startables, s => s is LocalLinkWatcher);
        Assert.Contains(startables, s => s is IncidentService);
    }
}
