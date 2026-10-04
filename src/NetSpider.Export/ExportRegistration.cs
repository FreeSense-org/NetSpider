using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Export.Exporters;
using NetSpider.Export.Notifications;
using NetSpider.Export.Persistence;

namespace NetSpider.Export;

public static class ExportRegistration
{
    /// <summary>Registers SQLite persistence, exporters and notifiers.</summary>
    public static IServiceCollection AddNetSpiderExport(this IServiceCollection services)
    {
        // persistence
        services.AddSingleton(sp => new SqliteDeviceRepository(sp.GetRequiredService<ILogger<SqliteDeviceRepository>>()));
        services.AddSingleton<IDeviceRepository>(sp => sp.GetRequiredService<SqliteDeviceRepository>());
        services.AddSingleton(sp => new DevicePersistenceService(
            sp.GetRequiredService<IDeviceRepository>(), sp.GetRequiredService<IDeviceStore>(), sp.GetRequiredService<IAlertService>(),
            sp.GetRequiredService<ILogger<DevicePersistenceService>>())
        {
            Network = sp.GetService<INetworkState>(),
        });
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<DevicePersistenceService>());

        // exporters
        services.AddSingleton<IExporter, JsonExporter>();
        services.AddSingleton<IExporter, CsvExporter>();
        services.AddSingleton<IExporter, NmapXmlExporter>();
        services.AddSingleton<IExporter, HtmlReportExporter>();
        services.AddSingleton<IExporter>(sp => new PcapNgExporter(sp));

        // notifications
        services.AddSingleton(sp => new WebhookNotifier(sp.GetRequiredService<ISettingsStore>(), sp.GetRequiredService<ILogger<WebhookNotifier>>()));
        services.AddSingleton<INotifier>(sp => sp.GetRequiredService<WebhookNotifier>());
        services.AddSingleton<SyslogNotifier>();
        services.AddSingleton<INotifier>(sp => sp.GetRequiredService<SyslogNotifier>());
        services.AddSingleton(sp =>
        {
            var svc = ActivatorUtilities.CreateInstance<NotificationService>(sp);
            svc.Network = sp.GetService<INetworkState>();
            return svc;
        });
        services.AddSingleton<IStartable>(sp => sp.GetRequiredService<NotificationService>());
        return services;
    }
}
