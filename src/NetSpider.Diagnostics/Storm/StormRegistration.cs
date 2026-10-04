using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics.Storm;

namespace NetSpider.Diagnostics;

public static class StormRegistration
{
    /// <summary>
    /// Registers the Storm Center (<see cref="IStormCenter"/>, self-started via <see cref="IStartable"/>) and its capture-thread
    /// per-source tally (<see cref="IFrameHandler"/>). Optional collaborators are resolved lazily: the AnomalyEngine,
    /// <see cref="IPortHealthMonitor"/> and the on-demand port counter reader from AddNetSpiderPortHealth().
    /// </summary>
    public static IServiceCollection AddNetSpiderStormCenter(this IServiceCollection services)
    {
        services.AddSingleton<StormFrameTally>();
        services.AddSingleton<IFrameHandler>(sp => sp.GetRequiredService<StormFrameTally>());

        services.AddSingleton<StormCenter>();
        services.AddSingleton<IStormCenter>(sp => sp.GetRequiredService<StormCenter>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<StormCenter>());
        return services;
    }
}
