using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Diagnostics.Agents;

public static class ProbeAgentRegistration
{
    /// <summary>Registers the probe agent hub (UDP receiver for NetSpider.Probe agents; listens only when enabled in settings) and the local dual-interface vantage monitor.</summary>
    public static IServiceCollection AddNetSpiderProbeAgents(this IServiceCollection services)
    {
        services.AddSingleton<ProbeAgentHub>();
        services.AddSingleton<IProbeAgentHub>(sp => sp.GetRequiredService<ProbeAgentHub>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<ProbeAgentHub>());

        // dual-interface self-test: this PC's own adapters as built-in vantages (idle unless >= 2 adapters are up)
        services.AddSingleton<LocalVantageMonitor>();
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<LocalVantageMonitor>());
        return services;
    }
}
