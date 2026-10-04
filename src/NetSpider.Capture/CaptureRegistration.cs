using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;

namespace NetSpider.Capture;

public static class CaptureRegistration
{
    public static IServiceCollection AddNetSpiderCapture(this IServiceCollection services)
    {
        services.AddSingleton<CaptureService>();
        services.AddSingleton<IFrameSource>(sp => sp.GetRequiredService<CaptureService>());
        services.AddSingleton<PacketRecorder>();
        services.AddSingleton<IPacketRecorder>(sp => sp.GetRequiredService<PacketRecorder>());
        services.AddSingleton<IFrameHandler>(sp => sp.GetRequiredService<PacketRecorder>());
        return services;
    }
}
