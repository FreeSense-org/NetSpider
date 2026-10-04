using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L3;

namespace NetSpider.Discovery;

public static class L2Registration
{
    /// <summary>Registers L2/L3 sweeps, latency prober, passive L2 parsers, DHCP, IGMP, traceroute, subnet/VLAN discovery.</summary>
    public static IServiceCollection AddNetSpiderL2Discovery(this IServiceCollection services)
    {
        // ---- shared helpers ----
        services.AddSingleton<DiscoveryContext>();
        services.AddSingleton<IPassiveMonitor>(sp => sp.GetRequiredService<DiscoveryContext>());
        services.AddSingleton<ActivityPublisher>();
        services.AddSingleton<DhcpProbeRegistry>();

        // ---- latency primitives (also matches ARP/NDP replies on the capture thread) ----
        services.AddSingleton<LatencyProber>();
        services.AddSingleton<ILatencyProber>(sp => sp.GetRequiredService<LatencyProber>());
        Handler<LatencyProber>(services);

        // ---- passive frame handlers ----
        AddHandler<ArpWatcher>(services);
        AddHandler<DiscoveryProtocolMonitor>(services);
        AddHandler<StpMonitor>(services);
        AddHandler<L2SignalMonitor>(services);
        AddHandler<DhcpMonitor>(services);
        AddHandler<IgmpMonitor>(services);
        AddHandler<NdpMonitor>(services);

        // ---- subnet discovery: scan stage + frame handler ----
        services.AddSingleton<SubnetDiscoverer>();
        services.AddSingleton<IActiveProbe>(sp => sp.GetRequiredService<SubnetDiscoverer>());
        Handler<SubnetDiscoverer>(services);

        // ---- scan stages ----
        AddProbe<ArpSweepProbe>(services);
        AddProbe<NdpSweepProbe>(services);
        AddProbe<DhcpDiscoverProbe>(services);
        AddProbe<IgmpQueryProbe>(services);
        AddProbe<VlanProber>(services);
        AddProbe<RemoteSubnetSweepProbe>(services);
        AddProbe<TracerouteProbe>(services);

        // ---- tools ----
        services.AddSingleton<Tracerouter>();
        services.AddSingleton<ITracerouter>(sp => sp.GetRequiredService<Tracerouter>());
        services.AddSingleton<WakeOnLanSender>();
        services.AddSingleton<IWakeOnLan>(sp => sp.GetRequiredService<WakeOnLanSender>());
        return services;
    }

    private static void AddHandler<T>(IServiceCollection services) where T : class, IFrameHandler
    {
        services.AddSingleton<T>();
        Handler<T>(services);
    }

    private static void Handler<T>(IServiceCollection services) where T : class, IFrameHandler =>
        services.AddSingleton<IFrameHandler>(sp => sp.GetRequiredService<T>());

    private static void AddProbe<T>(IServiceCollection services) where T : class, IActiveProbe
    {
        services.AddSingleton<T>();
        services.AddSingleton<IActiveProbe>(sp => sp.GetRequiredService<T>());
    }
}
