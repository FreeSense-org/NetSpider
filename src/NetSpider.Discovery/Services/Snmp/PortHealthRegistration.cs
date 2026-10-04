using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Snmp;

namespace NetSpider.Discovery;

public static class PortHealthRegistration
{
    /// <summary>
    /// Registers the SNMP switch-port health monitor (IF-MIB/EtherLike counters → <see cref="IPortHealthMonitor"/>), self-started
    /// through <see cref="IStartable"/>. Also exposes an on-demand single-port counter read as
    /// <c>Func&lt;Mac, string, CancellationToken, Task&lt;PortCounterSample?&gt;&gt;</c>, which the Storm Center's storm-control check
    /// resolves optionally (there is no Core interface for it yet).
    /// </summary>
    public static IServiceCollection AddNetSpiderPortHealth(this IServiceCollection services)
    {
        services.AddSingleton<PortHealthMonitor>();
        services.AddSingleton<IPortHealthMonitor>(sp => sp.GetRequiredService<PortHealthMonitor>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<PortHealthMonitor>());
        services.AddSingleton<Func<Mac, string, CancellationToken, Task<PortCounterSample?>>>(sp => sp.GetRequiredService<PortHealthMonitor>().ReadPortNowAsync);
        return services;
    }
}
