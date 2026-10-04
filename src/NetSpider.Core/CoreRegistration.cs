using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Services;

namespace NetSpider.Core;

public static class CoreRegistration
{
    public static IServiceCollection AddNetSpiderCore(this IServiceCollection services)
    {
        services.AddSingleton<ISettingsStore, SettingsStore>();
        services.AddSingleton(sp => sp.GetRequiredService<ISettingsStore>().Settings);
        services.AddSingleton<IDeviceStore, DeviceStore>();
        services.AddSingleton<ITopologyStore, TopologyStore>();
        services.AddSingleton<IAlertService, AlertService>();
        services.AddSingleton<INetworkState, NetworkState>();
        services.AddSingleton<IEventBus, EventBus>();
        return services;
    }
}
