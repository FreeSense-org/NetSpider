using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Discovery.L2;
using NetSpider.Discovery.L3;

namespace NetSpider.Tests.Unit.Discovery.L2;

/// <summary>Fake capture adapter: records sent frames and lets a test-provided responder loop frames back to handlers.</summary>
internal sealed class FakeFrameSource : IFrameSource
{
    private readonly List<IFrameHandler> _handlers = new();
    public List<byte[]> Sent { get; } = new();

    /// <summary>Called for every sent frame (after recording); typically schedules loopback + reply deliveries.</summary>
    public Action<byte[], long>? OnSend { get; set; }

    public bool IsRunning { get; set; } = true;
    public AdapterInfo? Adapter { get; set; } = L2TestKit.Adapter();
    public bool PcapAvailable => true;
    public string? PcapVersion => "fake";

    public IReadOnlyList<AdapterInfo> ListAdapters() => Adapter is null ? [] : [Adapter];
    public void Start(AdapterInfo adapter) { Adapter = adapter; IsRunning = true; }
    public void Stop() => IsRunning = false;

    public IDisposable Subscribe(IFrameHandler handler)
    {
        lock (_handlers) _handlers.Add(handler);
        return new Unsub(() => { lock (_handlers) _handlers.Remove(handler); });
    }

    public void Deliver(CapturedFrame f)
    {
        IFrameHandler[] hs;
        lock (_handlers) hs = _handlers.ToArray();
        foreach (var h in hs) h.OnFrame(f);
    }

    public long Send(ReadOnlySpan<byte> frame)
    {
        long t = Stopwatch.GetTimestamp();
        var copy = frame.ToArray();
        lock (Sent) Sent.Add(copy);
        OnSend?.Invoke(copy, t);
        return t;
    }

    public ValueTask<long> SendPacedAsync(byte[] frame, CancellationToken ct = default) => ValueTask.FromResult(Send(frame));
    public string? DumpRecent(string reason) => null;

#pragma warning disable CS0067
    public event Action<AdapterInfo>? Started;
    public event Action? Stopped;
#pragma warning restore CS0067

    private sealed class Unsub(Action a) : IDisposable { public void Dispose() => a(); }
}

internal sealed class L2TestKit
{
    public static readonly Mac LocalMac = Mac.Parse("3C:52:82:11:22:33");
    public static readonly IPAddress LocalIp = IPAddress.Parse("192.168.1.50");
    public static readonly IPAddress GatewayIp = IPAddress.Parse("192.168.1.1");
    public static readonly IPAddress LocalLinkLocal = IPAddress.Parse("fe80::3e52:82ff:fe11:2233");

    public static AdapterInfo Adapter(IPAddress? dhcpServer = null) => new()
    {
        Id = "test", PcapName = @"\Device\NPF_{TEST}", Name = "Ethernet", Description = "Test NIC", Mac = LocalMac,
        IPv4 = [new IpWithPrefix(LocalIp, 24)], IPv6 = [LocalLinkLocal], GatewayV4 = GatewayIp,
        DhcpServer = dhcpServer ?? GatewayIp, IsUp = true, SpeedMbps = 1000,
    };

    public FakeFrameSource Frames { get; } = new();
    public DeviceStore Store { get; } = new();
    public NetworkState Network { get; } = new();
    public AlertService Alerts { get; } = new();
    public EventBus Bus { get; } = new();
    public AppSettings Settings { get; } = new();
    public DiscoveryContext Ctx { get; }
    public ActivityPublisher Activity { get; }
    public SubnetDiscoverer Subnets { get; }

    public L2TestKit()
    {
        Ctx = new DiscoveryContext(Frames, Network);
        Activity = new ActivityPublisher(Bus);
        Subnets = new SubnetDiscoverer(NullLogger<SubnetDiscoverer>.Instance, Network, Settings, Ctx);
        Ctx.Update(ScanContext());
        Network.AddOrGetSegment(LocalIp, 24, "adapter", s => { s.IsLocal = true; s.Gateway = GatewayIp; });
    }

    public ScanContext ScanContext() => new() { Adapter = Frames.Adapter!, Settings = Settings, Segments = Network.Segments };

    public static CapturedFrame Frame(byte[] data, bool outbound = false, DateTime? ts = null, long? ticks = null) =>
        new(data, ts ?? DateTime.UtcNow, ticks ?? Stopwatch.GetTimestamp(), outbound);

    public static byte[] Hex(string hex) => Convert.FromHexString(string.Concat(hex.Where(Uri.IsHexDigit)));

    /// <summary>Ethernet II frame.</summary>
    public static byte[] Eth(Mac dst, Mac src, ushort type, byte[] payload)
    {
        var f = new byte[Math.Max(60, 14 + payload.Length)];
        FrameBuilder.WriteEthernet(f, dst, src, type);
        payload.CopyTo(f, 14);
        return f;
    }

    /// <summary>802.3 frame with LLC (and optional SNAP) header.</summary>
    public static byte[] Llc(Mac dst, Mac src, byte[] llcAndPayload)
    {
        var f = new byte[Math.Max(60, 14 + llcAndPayload.Length)];
        dst.WriteTo(f);
        src.WriteTo(f.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(12), (ushort)llcAndPayload.Length);
        llcAndPayload.CopyTo(f, 14);
        return f;
    }

    public static byte[] Snap(uint oui, ushort pid, byte[] payload) =>
        [0xAA, 0xAA, 0x03, (byte)(oui >> 16), (byte)(oui >> 8), (byte)oui, (byte)(pid >> 8), (byte)pid, .. payload];

    /// <summary>IPv4 packet with optional raw options (e.g. Router Alert) and a correct header checksum.</summary>
    public static byte[] Ip4(IPAddress src, IPAddress dst, byte proto, byte[] l4, byte ttl = 64, byte[]? options = null)
    {
        options ??= [];
        int hl = 20 + options.Length;
        var p = new byte[hl + l4.Length];
        p[0] = (byte)(0x40 | (hl / 4));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        p[8] = ttl; p[9] = proto;
        src.TryWriteBytes(p.AsSpan(12), out _);
        dst.TryWriteBytes(p.AsSpan(16), out _);
        options.CopyTo(p, 20);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), FrameBuilder.Checksum(p.AsSpan(0, hl)));
        l4.CopyTo(p, hl);
        return p;
    }
}
