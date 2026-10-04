using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Wifi;

public static class WifiLinkRegistration
{
    /// <summary>Registers the Wi-Fi link telemetry monitor (this host's RSSI/rates/roams/disconnect reasons; self-starting).</summary>
    public static IServiceCollection AddNetSpiderWifiLink(this IServiceCollection services)
    {
        services.AddSingleton<WifiLinkMonitor>();
        services.AddSingleton<IWifiLinkMonitor>(sp => sp.GetRequiredService<WifiLinkMonitor>());
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<WifiLinkMonitor>());
        return services;
    }
}
