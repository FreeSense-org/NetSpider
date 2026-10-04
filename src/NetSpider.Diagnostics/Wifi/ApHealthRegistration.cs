using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Diagnostics.Wifi;

public static class ApHealthRegistration
{
    /// <summary>Registers the per-AP health monitor (management + wireless-client reachability, self-starting).</summary>
    public static IServiceCollection AddNetSpiderApHealth(this IServiceCollection services)
    {
        services.AddSingleton<ApHealthMonitor>();
        services.AddSingleton<IApHealthMonitor>(sp => sp.GetRequiredService<ApHealthMonitor>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<ApHealthMonitor>());
        return services;
    }
}
