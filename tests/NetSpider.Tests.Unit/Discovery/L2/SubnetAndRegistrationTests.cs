using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L3;
using static NetSpider.Tests.Unit.Discovery.L2.L2TestKit;

namespace NetSpider.Tests.Unit.Discovery.L2;

public sealed class SubnetAndRegistrationTests
{
    private static CapturedFrame Udp(string src, string dst) =>
        Frame(FrameBuilder.Udp4(Mac.Parse("74:AC:B9:00:00:01"), LocalMac, IPAddress.Parse(src), IPAddress.Parse(dst), 1234, 5678, "x"u8));

    [Fact]
    public void Observed_private_sources_become_24_candidates_once()
    {
        var kit = new L2TestKit();
        kit.Settings.ScanOtherSubnets = false;
        kit.Subnets.OnFrame(Udp("10.50.60.7", "192.168.1.50"));
        kit.Subnets.OnFrame(Udp("10.50.60.8", "192.168.1.50"));
        kit.Subnets.OnFrame(Udp("192.168.1.20", "192.168.1.50")); // local
        kit.Subnets.OnFrame(Udp("8.8.8.8", "192.168.1.50"));      // public
        kit.Subnets.OnFrame(Udp("169.254.3.3", "192.168.1.50"));  // link-local
        kit.Subnets.OnFrame(Udp("100.64.1.1", "192.168.1.50"));   // CGNAT

        var seg = Assert.Single(kit.Network.Segments, s => !s.IsLocal);
        Assert.Equal("10.50.60.0/24", seg.Cidr);
        Assert.Equal("observed", seg.Source);
        Assert.False(seg.ScanEnabled);
    }

    [Fact]
    public async Task Stage_adds_adapter_segment_as_local()
    {
        var kit = new L2TestKit();
        await kit.Subnets.RunAsync(kit.ScanContext(), null, CancellationToken.None);
        var local = Assert.Single(kit.Network.Segments, s => s.Cidr == "192.168.1.0/24");
        Assert.True(local.IsLocal);
        Assert.Equal(GatewayIp, local.Gateway);
    }

    [Fact]
    public void Route_row_layout_parses()
    {
        var row = new byte[104];
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(8), 12);         // InterfaceIndex
        BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(12), 2);         // AF_INET
        IPAddress.Parse("10.8.0.0").TryWriteBytes(row.AsSpan(16), out _);
        row[40] = 16;                                                        // prefix length
        BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(44), 2);
        IPAddress.Parse("192.168.1.254").TryWriteBytes(row.AsSpan(48), out _);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(84), 25);         // metric
        var r = RouteTable.ParseRow(row)!;
        Assert.Equal(IPAddress.Parse("10.8.0.0"), r.Destination);
        Assert.Equal(16, r.PrefixLength);
        Assert.Equal(IPAddress.Parse("192.168.1.254"), r.NextHop);
        Assert.Equal(12u, r.InterfaceIndex);
        Assert.Equal(25u, r.Metric);
        Assert.True(SubnetDiscoverer.IsRoutableCandidate(r));
        Assert.False(SubnetDiscoverer.IsRoutableCandidate(r with { NextHop = IPAddress.Any }));
        Assert.False(SubnetDiscoverer.IsRoutableCandidate(r with { Destination = IPAddress.Parse("8.8.0.0") }));
    }

    [Fact]
    public void Live_route_table_read_does_not_throw()
    {
        var routes = RouteTable.ReadIPv4();
        Assert.All(routes, r => Assert.InRange(r.PrefixLength, 0, 32));
    }

    // ------------------------------------------------------------------------------------------ DI wiring

    [Fact]
    public void Registration_resolves_every_role_with_shared_singletons()
    {
        var kit = new L2TestKit();
        var services = new ServiceCollection();
        services.AddSingleton<IFrameSource>(kit.Frames);
        services.AddSingleton<IDeviceStore>(kit.Store);
        services.AddSingleton<INetworkState>(kit.Network);
        services.AddSingleton<IAlertService>(kit.Alerts);
        services.AddSingleton<IEventBus>(kit.Bus);
        services.AddSingleton(kit.Settings);
        services.AddNetSpiderL2Discovery();
        var sp = new MiniProvider(services);

        var handlers = sp.GetAll<IFrameHandler>();
        var probes = sp.GetAll<IActiveProbe>().OrderBy(p => p.Order).ToList();
        var monitors = sp.GetAll<IPassiveMonitor>();

        Assert.Equal([5, 10, 20, 40, 50, 60, 120, 150], probes.Select(p => p.Order));
        Assert.Contains(handlers, h => h is LatencyProber);
        Assert.Contains(handlers, h => h is ArpWatcher);
        Assert.Contains(handlers, h => h is DiscoveryProtocolMonitor);
        Assert.Contains(handlers, h => h is StpMonitor);
        Assert.Contains(handlers, h => h is L2SignalMonitor);
        Assert.Contains(handlers, h => h is DhcpMonitor);
        Assert.Contains(handlers, h => h is IgmpMonitor);
        Assert.Contains(handlers, h => h is NdpMonitor);
        Assert.Contains(handlers, h => h is SubnetDiscoverer);
        Assert.Equal(handlers.Count, handlers.Distinct().Count());
        Assert.Same(sp.Get<ILatencyProber>(), handlers.OfType<LatencyProber>().Single());
        Assert.Same(probes.OfType<SubnetDiscoverer>().Single(), handlers.OfType<SubnetDiscoverer>().Single());
        Assert.Same(sp.Get<StpMonitor>(), handlers.OfType<StpMonitor>().Single());
        Assert.IsType<DiscoveryContext>(Assert.Single(monitors));
        Assert.IsType<Tracerouter>(sp.Get<ITracerouter>());
        Assert.IsType<WakeOnLanSender>(sp.Get<IWakeOnLan>());
    }

    /// <summary>Just enough of a DI container (singletons, factories, IEnumerable, ILogger&lt;T&gt;) to validate the registrations.</summary>
    private sealed class MiniProvider(IServiceCollection services) : IServiceProvider
    {
        private readonly Dictionary<ServiceDescriptor, object> _singletons = new();

        public T Get<T>() => (T)GetService(typeof(T))!;
        public List<T> GetAll<T>() => ((IEnumerable<T>)GetService(typeof(IEnumerable<T>))!).ToList();

        public object? GetService(Type t)
        {
            if (t == typeof(IServiceProvider)) return this;
            if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IEnumerable<>))
            {
                var item = t.GetGenericArguments()[0];
                var all = services.Where(d => d.ServiceType == item).Select(Resolve).ToArray();
                var arr = Array.CreateInstance(item, all.Length);
                for (int i = 0; i < all.Length; i++) arr.SetValue(all[i], i);
                return arr;
            }
            if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(ILogger<>))
                return Activator.CreateInstance(typeof(NullLogger<>).MakeGenericType(t.GetGenericArguments()));
            var d = services.LastOrDefault(x => x.ServiceType == t);
            return d is null ? null : Resolve(d);
        }

        private object Resolve(ServiceDescriptor d)
        {
            if (_singletons.TryGetValue(d, out var o)) return o;
            o = d.ImplementationInstance ?? d.ImplementationFactory?.Invoke(this) ?? ActivatorUtilities.CreateInstance(this, d.ImplementationType!);
            _singletons[d] = o;
            return o;
        }
    }
}
