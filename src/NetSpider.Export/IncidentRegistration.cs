using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Export.Persistence;

namespace NetSpider.Export;

public static class IncidentRegistration
{
    /// <summary>Registers <see cref="SqliteIncidentRepository"/> as <see cref="IIncidentRepository"/> (table <c>incidents</c> in netspider.db).</summary>
    public static IServiceCollection AddNetSpiderIncidentStore(this IServiceCollection services)
    {
        services.AddSingleton(sp => new SqliteIncidentRepository(sp.GetRequiredService<ILogger<SqliteIncidentRepository>>()));
        services.AddSingleton<IIncidentRepository>(sp => sp.GetRequiredService<SqliteIncidentRepository>());
        return services;
    }
}
