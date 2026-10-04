using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Wifi;

public static class WifiRegistration
{
    /// <summary>Registers the native WLAN scanner and the background Wi-Fi monitor.</summary>
    public static IServiceCollection AddNetSpiderWifi(this IServiceCollection services)
    {
        services.AddSingleton<WlanNativeScanner>();
        services.AddSingleton<IWifiScanner>(sp => sp.GetRequiredService<WlanNativeScanner>());
        services.AddSingleton<WifiMonitor>();
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<WifiMonitor>());
        return services;
    }
}
