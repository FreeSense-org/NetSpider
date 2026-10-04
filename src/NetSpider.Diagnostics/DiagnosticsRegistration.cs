using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics.Anomaly;
using NetSpider.Diagnostics.Health;
using NetSpider.Diagnostics.Internet;
using NetSpider.Diagnostics.Latency;
using NetSpider.Diagnostics.Topology;

namespace NetSpider.Diagnostics;

public static class DiagnosticsRegistration
{
    /// <summary>Registers orchestrator, latency engine, topology builder, anomaly detectors and health suite.</summary>
    public static IServiceCollection AddNetSpiderDiagnostics(this IServiceCollection services)
    {
        services.AddSingleton<TopologyBuilder>();
        services.AddSingleton<ITopologyBuilder>(sp => sp.GetRequiredService<TopologyBuilder>());

        services.AddSingleton<PassiveTcpRttTracker>();
        services.AddSingleton<IFrameHandler>(sp => sp.GetRequiredService<PassiveTcpRttTracker>());

        services.AddSingleton<AnomalyEngine>();
        services.AddSingleton<IFrameHandler>(sp => sp.GetRequiredService<AnomalyEngine>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<AnomalyEngine>());

        services.AddSingleton<LatencyEngine>();
        services.AddSingleton<ILatencyEngine>(sp => sp.GetRequiredService<LatencyEngine>());

        services.AddSingleton<HealthService>();
        services.AddSingleton<IHealthService>(sp => sp.GetRequiredService<HealthService>());

        services.AddSingleton<InternetMonitor>();
        services.AddSingleton<IInternetMonitor>(sp => sp.GetRequiredService<InternetMonitor>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<InternetMonitor>());

        services.AddSingleton<ScanOrchestrator>();
        services.AddSingleton<IScanOrchestrator>(sp => sp.GetRequiredService<ScanOrchestrator>());
        return services;
    }
}
