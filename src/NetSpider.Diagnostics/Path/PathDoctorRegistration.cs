using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Diagnostics.LocalLink;

namespace NetSpider.Diagnostics.PathDoctor;

public static class PathDoctorRegistration
{
    /// <summary>
    /// Registers the Path Doctor: <see cref="PathMonitor"/> (<see cref="IPathMonitor"/>), <see cref="LocalLinkWatcher"/> and the
    /// fault locator <see cref="IncidentService"/> (<see cref="IIncidentService"/>). All three are <see cref="IStartable"/>.
    /// Optional services (ILatencyProber, IFrameSource, IIncidentRepository) are resolved with GetService.
    /// </summary>
    public static IServiceCollection AddNetSpiderPathDoctor(this IServiceCollection services)
    {
        services.AddSingleton<IHopProber>(sp => new HopProber(
            sp.GetRequiredService<ILogger<HopProber>>(), sp.GetService<ILatencyProber>(), sp.GetService<IFrameSource>()));

        services.AddSingleton(sp => new PathMonitor(
            sp.GetRequiredService<ISettingsStore>(), sp.GetRequiredService<IDeviceStore>(), sp.GetRequiredService<ITopologyStore>(),
            sp.GetRequiredService<INetworkState>(), sp.GetRequiredService<IEventBus>(), sp.GetRequiredService<IHopProber>(),
            sp.GetRequiredService<ILogger<PathMonitor>>(), sp.GetService<IFrameSource>()));
        services.AddSingleton<IPathMonitor>(sp => sp.GetRequiredService<PathMonitor>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<PathMonitor>());

        services.AddSingleton(sp => new LocalLinkWatcher(
            sp.GetRequiredService<IEventBus>(), sp.GetRequiredService<ILogger<LocalLinkWatcher>>(), sp.GetService<IFrameSource>()));
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<LocalLinkWatcher>());

        services.AddSingleton(sp => new IncidentService(
            sp.GetRequiredService<IEventBus>(), sp.GetRequiredService<IAlertService>(), sp.GetRequiredService<IDeviceStore>(),
            sp.GetRequiredService<ITopologyStore>(), sp.GetRequiredService<ISettingsStore>(), sp.GetRequiredService<ILogger<IncidentService>>(),
            sp.GetService<IPathMonitor>(), sp.GetService<IFrameSource>(), sp.GetService<IIncidentRepository>(),
            network: sp.GetService<INetworkState>()));
        services.AddSingleton<IIncidentService>(sp => sp.GetRequiredService<IncidentService>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<IncidentService>());
        return services;
    }
}
