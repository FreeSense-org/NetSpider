using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Fingerprint.Classification;

namespace NetSpider.Fingerprint;

public static class FingerprintRegistration
{
    /// <summary>Registers the OUI database, device classifier and vendor logo service (all singletons).</summary>
    public static IServiceCollection AddNetSpiderFingerprint(this IServiceCollection services)
    {
        services.AddSingleton<OuiDatabase>();
        services.AddSingleton<IOuiLookup>(sp => sp.GetRequiredService<OuiDatabase>());
        services.AddSingleton<DeviceClassifier>();
        services.AddSingleton<IDeviceClassifier>(sp => sp.GetRequiredService<DeviceClassifier>());
        services.AddSingleton<VendorLogoService>();
        services.AddSingleton<ILogoProvider>(sp => sp.GetRequiredService<VendorLogoService>());
        return services;
    }
}
