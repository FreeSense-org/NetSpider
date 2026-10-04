using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Ssdp;

/// <summary>
/// Active SSDP search: M-SEARCH for ssdp:all and upnp:rootdevice, then fetches and parses each LOCATION description,
/// applying friendlyName/manufacturer/model/icon to devices and storing the full tree in <see cref="SsdpRegistry"/>.
/// </summary>
public sealed class SsdpProbe : IActiveProbe
{
    private static readonly IPAddress SsdpV4 = IPAddress.Parse("239.255.255.250");
    private const int SsdpPort = 1900;

    private readonly IDeviceStore _store;
    private readonly SsdpRegistry _registry;
    private readonly ILogger<SsdpProbe> _log;

    public SsdpProbe(IDeviceStore store, SsdpRegistry registry, ILogger<SsdpProbe> log)
    {
        _store = store; _registry = registry; _log = log;
    }

    public string Name => "SSDP/UPnP search";
    public ProbeLayer Layer => ProbeLayer.L7;
    public int Order => 210;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0, "M-SEARCH"));
        var locations = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);

        using (var socket = CreateSocket(ctx))
        {
            if (socket is null) return;
            using var receiver = StartReceiver(socket, (data, from) =>
            {
                var text = Encoding.ASCII.GetString(data);
                if (!text.StartsWith("HTTP/1.1", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase)) return;
                var headers = SsdpInterpreter.ParseHeaders(text);
                var device = ProbeSupport.ResolveByIp(_store, ctx, from);
                if (SsdpInterpreter.ApplyHeaders(device, headers)) _store.NotifyChanged(device, "ssdp");
                if (headers.TryGetValue("LOCATION", out var loc) && !string.IsNullOrWhiteSpace(loc))
                    locations[loc] = from;
            }, ct);

            foreach (var target in new[] { "ssdp:all", "upnp:rootdevice" })
            {
                await SendSearchAsync(socket, target, ct).ConfigureAwait(false);
                await Delay(250, ct).ConfigureAwait(false);
                await SendSearchAsync(socket, target, ct).ConfigureAwait(false);
            }
            await Delay(3000, ct).ConfigureAwait(false);
        }

        progress?.Report(new ScanProgress(Name, 0.5, $"fetching {locations.Count} descriptions"));
        await FetchDescriptionsAsync(ctx, locations, ct).ConfigureAwait(false);
        progress?.Report(new ScanProgress(Name, 1, $"{_registry.All.Count} UPnP devices"));
    }

    private async Task FetchDescriptionsAsync(ScanContext ctx, Dictionary<string, IPAddress> locations, CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(8);
        using var http = CreateHttpClient();
        var tasks = locations
            .Where(kv => !_registry.Contains(kv.Key) && Uri.TryCreate(kv.Key, UriKind.Absolute, out _))
            .Select(async kv =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try { await FetchOneAsync(ctx, http, kv.Key, kv.Value, ct).ConfigureAwait(false); }
                catch (Exception ex) { _log.LogDebug(ex, "SSDP fetch {Loc}", kv.Key); }
                finally { gate.Release(); }
            });
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task FetchOneAsync(ScanContext ctx, HttpClient http, string location, IPAddress from, CancellationToken ct)
    {
        var uri = new Uri(location);
        using var resp = await http.GetAsync(uri, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return;
        var xml = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var root = UpnpXml.Parse(xml, uri);
        if (root is null) return;
        var server = resp.Headers.TryGetValues("SERVER", out var sv) ? string.Join(" ", sv) : null;
        var ip = uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6 && IPAddress.TryParse(uri.Host, out var hostIp) ? hostIp : from;
        var desc = new SsdpDescription(ip, uri, server, root);
        _registry.Add(desc);
        var device = ProbeSupport.ResolveByIp(_store, ctx, ip);
        if (SsdpInterpreter.Apply(device, desc)) _store.NotifyChanged(device, "ssdp");
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 3 };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
    }

    private Socket? CreateSocket(ScanContext ctx)
    {
        try
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
            return socket;
        }
        catch (Exception ex) { _log.LogDebug(ex, "SSDP socket setup failed"); return null; }
    }

    private async Task SendSearchAsync(Socket socket, string target, CancellationToken ct)
    {
        var msg = "M-SEARCH * HTTP/1.1\r\n" +
                  "HOST: 239.255.255.250:1900\r\n" +
                  "MAN: \"ssdp:discover\"\r\n" +
                  "MX: 2\r\n" +
                  $"ST: {target}\r\n\r\n";
        try { await socket.SendToAsync(Encoding.ASCII.GetBytes(msg), SocketFlags.None, new IPEndPoint(SsdpV4, SsdpPort), ct).ConfigureAwait(false); }
        catch (Exception ex) { _log.LogDebug(ex, "SSDP send"); }
    }

    private IDisposable StartReceiver(Socket socket, Action<byte[], IPAddress> onMessage, CancellationToken ct)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _ = Task.Run(async () =>
        {
            var buf = new byte[8192];
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    var r = await socket.ReceiveFromAsync(buf, SocketFlags.None, from, cts.Token).ConfigureAwait(false);
                    if (r.ReceivedBytes > 0 && r.RemoteEndPoint is IPEndPoint ep) onMessage(buf[..r.ReceivedBytes], ep.Address);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _log.LogDebug(ex, "SSDP recv"); }
            }
        }, cts.Token);
        return new Disposer(() => { try { cts.Cancel(); } catch { } cts.Dispose(); });
    }

    private static async Task Delay(int ms, CancellationToken ct) { try { await Task.Delay(ms, ct).ConfigureAwait(false); } catch (OperationCanceledException) { } }

    private sealed class Disposer(Action a) : IDisposable { public void Dispose() => a(); }
}
