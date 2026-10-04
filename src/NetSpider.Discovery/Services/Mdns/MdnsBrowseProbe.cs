using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Dns;

namespace NetSpider.Discovery.Services.Mdns;

/// <summary>
/// Active mDNS/DNS-SD browse: enumerates services via <c>_services._dns-sd._udp.local</c>, then queries each discovered
/// service type and instance. Responses (multicast or unicast on the socket) are interpreted against the sender's IP.
/// </summary>
public sealed class MdnsBrowseProbe : IActiveProbe
{
    private static readonly IPAddress MdnsV4 = IPAddress.Parse("224.0.0.251");
    private static readonly IPAddress MdnsV6 = IPAddress.Parse("ff02::fb");
    private const int MdnsPort = 5353;
    private const string Enumerator = "_services._dns-sd._udp.local";

    private readonly IDeviceStore _store;
    private readonly ILogger<MdnsBrowseProbe> _log;

    public MdnsBrowseProbe(IDeviceStore store, ILogger<MdnsBrowseProbe> log) { _store = store; _log = log; }

    public string Name => "mDNS browse";
    public ProbeLayer Layer => ProbeLayer.L7;
    public int Order => 200;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0, "querying services"));
        using var socket = CreateSocket(ctx);
        if (socket is null) return;

        var discoveredTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queriedInstances = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Receive(byte[] data, IPAddress from)
        {
            if (!DnsCodec.TryParse(data, out var msg)) return;
            foreach (var rr in msg.Answers)
            {
                if (rr.Type == DnsType.Ptr && rr.Name.Equals(Enumerator, StringComparison.OrdinalIgnoreCase))
                    discoveredTypes.Add(DnsCodec.ParseName(data, rr));
                else if (rr.Type == DnsType.Ptr)
                    queriedInstances.Add(DnsCodec.ParseName(data, rr));
            }
            var device = ProbeSupport.ResolveByIp(_store, ctx, from);
            if (MdnsInterpreter.Apply(device, data, msg)) _store.NotifyChanged(device, "mdns");
        }

        using var receiver = StartReceiver(socket, Receive, ct);

        // 1) enumerate service types
        await SendQueryAsync(socket, ctx, Enumerator, DnsType.Ptr, ct).ConfigureAwait(false);
        await DelayDrain(TimeSpan.FromMilliseconds(1200), ct).ConfigureAwait(false);

        // 2) query each discovered service type (PTR -> instances)
        foreach (var type in discoveredTypes.ToArray())
            await SendQueryAsync(socket, ctx, Normalize(type), DnsType.Ptr, ct).ConfigureAwait(false);
        await DelayDrain(TimeSpan.FromMilliseconds(1500), ct).ConfigureAwait(false);

        // 3) resolve each instance (SRV/TXT/A via ANY)
        foreach (var inst in queriedInstances.ToArray())
            await SendQueryAsync(socket, ctx, Normalize(inst), DnsType.Any, ct).ConfigureAwait(false);
        await DelayDrain(TimeSpan.FromMilliseconds(2000), ct).ConfigureAwait(false);

        progress?.Report(new ScanProgress(Name, 1, $"{discoveredTypes.Count} service types"));
    }

    private static string Normalize(string name) => name.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? name : name.TrimEnd('.') + ".local";

    private Socket? CreateSocket(ScanContext ctx)
    {
        try
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try { socket.Bind(new IPEndPoint(IPAddress.Any, MdnsPort)); }
            catch (SocketException)
            {
                // Windows mDNS responder owns 5353; fall back to an ephemeral port and use the QU bit on queries.
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            }
            var local = ctx.LocalIPv4 ?? IPAddress.Any;
            try { socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MdnsV4, local)); }
            catch (Exception ex) { _log.LogDebug(ex, "mDNS v4 join failed"); }
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
            return socket;
        }
        catch (Exception ex) { _log.LogDebug(ex, "mDNS socket setup failed"); return null; }
    }

    private async Task SendQueryAsync(Socket socket, ScanContext ctx, string name, DnsType type, CancellationToken ct)
    {
        try
        {
            bool unicast = (socket.LocalEndPoint as IPEndPoint)?.Port != MdnsPort;
            ushort cls = (ushort)(unicast ? 0x8001 : 0x0001); // QU bit + IN
            var query = DnsCodec.BuildQuery([new DnsQuestion(name, type, cls)]);
            await socket.SendToAsync(query, SocketFlags.None, new IPEndPoint(MdnsV4, MdnsPort), ct).ConfigureAwait(false);
        }
        catch (Exception ex) { _log.LogDebug(ex, "mDNS send {Name}", name); }
    }

    private IDisposable StartReceiver(Socket socket, Action<byte[], IPAddress> onMessage, CancellationToken ct)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _ = Task.Run(async () =>
        {
            var buf = new byte[9000];
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    var r = await socket.ReceiveFromAsync(buf, SocketFlags.None, from, cts.Token).ConfigureAwait(false);
                    if (r.ReceivedBytes > 0 && r.RemoteEndPoint is IPEndPoint ep)
                        onMessage(buf[..r.ReceivedBytes], ep.Address);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _log.LogDebug(ex, "mDNS recv"); }
            }
        }, cts.Token);
        return new Disposer(() => { try { cts.Cancel(); } catch { } cts.Dispose(); });
    }

    private static async Task DelayDrain(TimeSpan span, CancellationToken ct)
    {
        try { await Task.Delay(span, ct).ConfigureAwait(false); } catch (OperationCanceledException) { }
    }

    private sealed class Disposer(Action a) : IDisposable { public void Dispose() => a(); }
}
