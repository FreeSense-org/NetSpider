using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Discovery.Gateway;
using NetSpider.Discovery.Services.Dns;
using NetSpider.Discovery.Services.Mdns;
using NetSpider.Discovery.Services.NetBios;
using NetSpider.Discovery.Services.PortScan;
using NetSpider.Discovery.Services.Smb;
using NetSpider.Discovery.Services.Snmp;
using NetSpider.Discovery.Services.Ssdp;
using NetSpider.Discovery.Services.Tls;
using NetSpider.Discovery.Services.Wsd;
using NetSpider.Discovery.Vendor;

namespace NetSpider.Discovery;

public static class ServiceDiscoveryRegistration
{
    /// <summary>
    /// Registers mDNS, SSDP/UPnP, WS-Discovery, NetBIOS/LLMNR, reverse DNS, port scan, TLS, SMB, SNMP, vendor/IoT
    /// probes and the gateway audit. Each class is a single shared singleton with its interfaces forwarded to it.
    /// </summary>
    public static IServiceCollection AddNetSpiderServiceDiscovery(this IServiceCollection services)
    {
        // shared registries
        services.AddSingleton<SsdpRegistry>();

        // ---- frame handlers + passive monitors (same instance implements both) ----
        services.AddSingleton<MdnsMonitor>();
        services.Forward<MdnsMonitor, IFrameHandler>();
        services.Forward<MdnsMonitor, IPassiveMonitor>();

        services.AddSingleton<SsdpMonitor>();
        services.Forward<SsdpMonitor, IFrameHandler>();
        services.Forward<SsdpMonitor, IPassiveMonitor>();

        services.AddSingleton<LlmnrMonitor>();
        services.Forward<LlmnrMonitor, IFrameHandler>();
        services.Forward<LlmnrMonitor, IPassiveMonitor>();

        // ---- active probes (network-wide stages) ----
        services.AddSingleton<MdnsBrowseProbe>();
        services.Forward<MdnsBrowseProbe, IActiveProbe>();

        services.AddSingleton<SsdpProbe>();
        services.Forward<SsdpProbe, IActiveProbe>();

        services.AddSingleton<UbiquitiProbe>();
        services.Forward<UbiquitiProbe, IActiveProbe>();

        services.AddSingleton<MikroTikMndpProbe>();
        services.Forward<MikroTikMndpProbe, IActiveProbe>();
        services.Forward<MikroTikMndpProbe, IFrameHandler>();

        services.AddSingleton<NetgearNsdpProbe>();
        services.Forward<NetgearNsdpProbe, IActiveProbe>();

        services.AddSingleton<WsDiscoveryProbe>();
        services.Forward<WsDiscoveryProbe, IActiveProbe>();

        services.AddSingleton<GatewayAuditProbe>();
        services.Forward<GatewayAuditProbe, IActiveProbe>();

        // ---- per-device probes ----
        services.AddSingleton<NetBiosProbe>();
        services.Forward<NetBiosProbe, IDeviceProbe>();

        services.AddSingleton<ReverseDnsProbe>();
        services.Forward<ReverseDnsProbe, IDeviceProbe>();

        services.AddSingleton<PortScanProbe>();
        services.Forward<PortScanProbe, IDeviceProbe>();

        services.AddSingleton<TlsInspectorProbe>();
        services.Forward<TlsInspectorProbe, IDeviceProbe>();

        services.AddSingleton<SmbProbe>();
        services.Forward<SmbProbe, IDeviceProbe>();

        services.AddSingleton<SnmpProbe>();
        services.Forward<SnmpProbe, IDeviceProbe>();

        services.AddSingleton<HttpDeviceProbe>();
        services.Forward<HttpDeviceProbe, IDeviceProbe>();

        services.AddSingleton<MqttProbe>();
        services.Forward<MqttProbe, IDeviceProbe>();

        services.AddSingleton<CoapProbe>();
        services.Forward<CoapProbe, IDeviceProbe>();

        // ---- device↔device latency via SNMP ----
        services.AddSingleton<SnmpRemotePinger>();
        services.Forward<SnmpRemotePinger, IRemotePinger>();

        return services;
    }

    private static void Forward<TImpl, TService>(this IServiceCollection services)
        where TImpl : class, TService where TService : class =>
        services.AddSingleton<TService>(sp => sp.GetRequiredService<TImpl>());
}
