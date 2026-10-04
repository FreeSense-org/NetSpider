using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.Diagnostics;

internal sealed class FakeFrameSource : IFrameSource
{
    public bool IsRunning { get; private set; }
    public AdapterInfo? Adapter { get; set; }
    public bool PcapAvailable { get; set; } = true;
    public string? PcapVersion => "fake";
    public List<IFrameHandler> Handlers { get; } = [];
    public int Dumps;

    public IReadOnlyList<AdapterInfo> ListAdapters() => Adapter is null ? [] : [Adapter];
    public void Start(AdapterInfo adapter) { Adapter = adapter; IsRunning = true; Started?.Invoke(adapter); }
    public void Stop() { IsRunning = false; Stopped?.Invoke(); }
    public IDisposable Subscribe(IFrameHandler handler) { Handlers.Add(handler); return new Unsub(() => Handlers.Remove(handler)); }
    public long Send(ReadOnlySpan<byte> frame) => 0;
    public ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default) => ValueTask.FromResult(0L);
    public string? DumpRecent(string reason) { Interlocked.Increment(ref Dumps); return $"C:\\dumps\\{reason}.pcapng"; }
    public event Action<AdapterInfo>? Started;
    public event Action? Stopped;
    private sealed class Unsub(Action a) : IDisposable { public void Dispose() => a(); }
}

/// <summary>Minimal IServiceProvider supporting single instances and IEnumerable&lt;T&gt;.</summary>
internal sealed class FakeServiceProvider : IServiceProvider
{
    private readonly Dictionary<Type, List<object>> _items = new();

    public FakeServiceProvider Add<T>(T instance) where T : notnull
    {
        if (!_items.TryGetValue(typeof(T), out var l)) _items[typeof(T)] = l = [];
        l.Add(instance);
        return this;
    }

    public object? GetService(Type serviceType)
    {
        if (serviceType.IsGenericType && serviceType.GetGenericTypeDefinition() == typeof(IEnumerable<>))
        {
            var t = serviceType.GetGenericArguments()[0];
            var arr = Array.CreateInstance(t, _items.TryGetValue(t, out var l) ? l.Count : 0);
            if (l is not null) for (int i = 0; i < l.Count; i++) arr.SetValue(l[i], i);
            return arr;
        }
        return _items.TryGetValue(serviceType, out var list) ? list[^1] : null;
    }
}

internal static class TestNet
{
    public static readonly Mac LocalMac = Mac.Parse("AA:00:00:00:00:01");

    public static AdapterInfo Adapter(string ip = "192.168.1.10", int prefix = 24, string gw = "192.168.1.1", bool isVirtual = false) => new()
    {
        Id = "test",
        PcapName = @"\Device\NPF_{TEST}",
        Name = "Ethernet",
        Mac = LocalMac,
        IPv4 = [new IpWithPrefix(IPAddress.Parse(ip), prefix)],
        GatewayV4 = IPAddress.Parse(gw),
        DnsServers = [IPAddress.Parse(gw)],
        IsUp = true,
        IsVirtual = isVirtual,
    };

    public static ScanContext Context(AdapterInfo? adapter = null, AppSettings? settings = null)
    {
        var a = adapter ?? Adapter();
        var seg = new NetworkSegment(a.IPv4[0].Address, a.IPv4[0].PrefixLength, "adapter") { IsLocal = true, Gateway = a.GatewayV4 };
        return new ScanContext { Adapter = a, Settings = settings ?? new AppSettings(), Segments = [seg] };
    }

    public static CapturedFrame Frame(byte[] data, DateTime t, bool outbound = false) => new(data, t, 0, outbound);

    /// <summary>Ethernet + IPv4 + TCP (20-byte header, no options).</summary>
    public static byte[] Tcp4(Mac srcMac, Mac dstMac, string src, string dst, int sport, int dport, uint seq, uint ack, byte flags)
    {
        var tcp = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(8), ack);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(14), 64240);
        return FrameBuilder.Ip4Frame(srcMac, dstMac, IPAddress.Parse(src), IPAddress.Parse(dst), 6, tcp);
    }

    /// <summary>Ethernet + IPv6 + TCP.</summary>
    public static byte[] Tcp6(Mac srcMac, Mac dstMac, string src, string dst, int sport, int dport, uint seq, uint ack, byte flags)
    {
        var tcp = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(tcp, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(8), ack);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        return FrameBuilder.Ip6Frame(srcMac, dstMac, IPAddress.Parse(src), IPAddress.Parse(dst), 6, tcp, 64);
    }

    public static byte[] Udp4(Mac srcMac, Mac dstMac, string src, string dst, int sport, int dport, int payload = 40) =>
        FrameBuilder.Udp4(srcMac, dstMac, IPAddress.Parse(src), IPAddress.Parse(dst), sport, dport, new byte[payload]);

    /// <summary>802.3/LLC STP BPDU (config or RST) with the given flags, or a TCN BPDU.</summary>
    public static byte[] Bpdu(Mac src, bool tc, bool tcn = false)
    {
        var buf = new byte[60];
        Mac.Parse("01:80:C2:00:00:00").WriteTo(buf);
        src.WriteTo(buf.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(12), 39);
        buf[14] = 0x42; buf[15] = 0x42; buf[16] = 0x03;
        // BPDU: protocol id 0, version 2 (RSTP), type 2 (RST) or 0x80 (TCN), flags
        buf[17] = 0; buf[18] = 0; buf[19] = tcn ? (byte)0 : (byte)2; buf[20] = tcn ? (byte)0x80 : (byte)0x02;
        buf[21] = tc ? (byte)0x01 : (byte)0x00;
        return buf;
    }

    public static Device AddDevice(IDeviceStore store, string mac, string? ip = null, DeviceType type = DeviceType.Unknown, DeviceFlags flags = DeviceFlags.None, string? name = null)
    {
        var d = store.GetOrAdd(Mac.Parse(mac));
        if (ip is not null) store.Observe(d.Mac, IPAddress.Parse(ip), "test");
        if (type != DeviceType.Unknown) { d.Type = type; d.TypeConfidence = 0.9; }
        if (flags != DeviceFlags.None) d.SetFlag(flags);
        if (name is not null) d.SetHostname("snmp", name);
        return d;
    }
}
