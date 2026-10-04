using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Wsd;

/// <summary>
/// WS-Discovery Probe to 239.255.255.250:3702. Parses ProbeMatches (Types, Scopes, XAddrs). ONVIF scopes identify
/// camera name/hardware/type; Windows hosts (pub:Computer) and printers are also recognized.
/// </summary>
public sealed class WsDiscoveryProbe : IActiveProbe
{
    private static readonly IPAddress WsdV4 = IPAddress.Parse("239.255.255.250");
    private const int WsdPort = 3702;
    private const string Source = "wsd";

    private readonly IDeviceStore _store;
    private readonly ILogger<WsDiscoveryProbe> _log;

    public WsDiscoveryProbe(IDeviceStore store, ILogger<WsDiscoveryProbe> log) { _store = store; _log = log; }

    public string Name => "WS-Discovery/ONVIF";
    public ProbeLayer Layer => ProbeLayer.L7;
    public int Order => 220;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0, "probe"));
        using var socket = CreateSocket(ctx);
        if (socket is null) return;
        using var receiver = StartReceiver(socket, (data, from) => Handle(ctx, data, from), ct);

        foreach (var types in new[] { "dn:NetworkVideoTransmitter", "", "pub:Computer" })
        {
            await SendProbeAsync(socket, types, ct).ConfigureAwait(false);
            await Delay(300, ct).ConfigureAwait(false);
        }
        await Delay(3000, ct).ConfigureAwait(false);
        progress?.Report(new ScanProgress(Name, 1));
    }

    private void Handle(ScanContext ctx, byte[] data, IPAddress from)
    {
        try
        {
            var text = Encoding.UTF8.GetString(data);
            var (types, scopes, xaddrs) = ParseProbeMatch(text);
            if (types is null && scopes is null && xaddrs is null) return;
            var device = ProbeSupport.ResolveByIp(_store, ctx, from);
            bool changed = ApplyMatch(device, types, scopes, xaddrs);
            if (changed) _store.NotifyChanged(device, Source);
        }
        catch (Exception ex) { _log.LogDebug(ex, "WSD parse"); }
    }

    /// <summary>Parses the Types/Scopes/XAddrs out of a WS-Discovery SOAP ProbeMatch (or Hello) envelope.</summary>
    public static (string? Types, string? Scopes, string? XAddrs) ParseProbeMatch(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            string? Find(string local) => doc.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase))?.Value?.Trim();
            return (Find("Types"), Find("Scopes"), Find("XAddrs"));
        }
        catch { return (null, null, null); }
    }

    public static bool ApplyMatch(Device device, string? types, string? scopes, string? xaddrs)
    {
        bool changed = false;
        if (!string.IsNullOrWhiteSpace(xaddrs))
        {
            var first = xaddrs.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (first is not null) changed |= device.SetProperty("wsd.xaddr", first);
        }

        bool isCamera = types?.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase) == true
            || scopes?.Contains("onvif", StringComparison.OrdinalIgnoreCase) == true;
        bool isComputer = types?.Contains("Computer", StringComparison.OrdinalIgnoreCase) == true;
        bool isPrinter = types?.Contains("Print", StringComparison.OrdinalIgnoreCase) == true
            || scopes?.Contains("/Printer", StringComparison.OrdinalIgnoreCase) == true;

        if (isCamera)
        {
            changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Camera), Confidence.Ssdp);
            changed |= device.AddEvidence(Source, Fields.Service, "ONVIF", Confidence.Ssdp);
        }
        if (isComputer) { changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Desktop), Confidence.Http); changed |= device.AddEvidence(Source, Fields.Os, "Windows", Confidence.Http); }
        if (isPrinter) changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Printer), Confidence.Ssdp);

        // ONVIF scopes: onvif://www.onvif.org/name/..., /hardware/..., /type/...
        if (!string.IsNullOrWhiteSpace(scopes))
            foreach (var scope in scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var (key, val) = OnvifScope(scope);
                if (val is null) continue;
                switch (key)
                {
                    case "name": changed |= device.AddEvidence(Source, Fields.Model, val, Confidence.Ssdp); break;
                    case "hardware": changed |= device.AddEvidence(Source, Fields.ModelNumber, val, Confidence.Ssdp); break;
                    case "location": changed |= device.SetProperty("onvif.location", val); break;
                    case "type": changed |= device.AddEvidence(Source, Fields.Service, "ONVIF " + val, Confidence.Ssdp); break;
                }
            }
        return changed;
    }

    private static (string Key, string? Value) OnvifScope(string scope)
    {
        const string pfx = "onvif://www.onvif.org/";
        if (!scope.StartsWith(pfx, StringComparison.OrdinalIgnoreCase)) return ("", null);
        var rest = scope[pfx.Length..];
        int slash = rest.IndexOf('/');
        if (slash < 0) return (rest.ToLowerInvariant(), null);
        var key = rest[..slash].ToLowerInvariant();
        var val = Uri.UnescapeDataString(rest[(slash + 1)..]);
        return (key, val);
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
        catch (Exception ex) { _log.LogDebug(ex, "WSD socket setup failed"); return null; }
    }

    private async Task SendProbeAsync(Socket socket, string types, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString();
        var typesEl = string.IsNullOrEmpty(types) ? "" : $"<d:Types xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns:pub=\"http://schemas.microsoft.com/windows/pub/2005/07\">{types}</d:Types>";
        var env =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
            "<e:Header>" +
            $"<w:MessageID>urn:uuid:{id}</w:MessageID>" +
            "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
            "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>" +
            "</e:Header><e:Body><d:Probe>" + typesEl + "</d:Probe></e:Body></e:Envelope>";
        try { await socket.SendToAsync(Encoding.UTF8.GetBytes(env), SocketFlags.None, new IPEndPoint(WsdV4, WsdPort), ct).ConfigureAwait(false); }
        catch (Exception ex) { _log.LogDebug(ex, "WSD send"); }
    }

    private IDisposable StartReceiver(Socket socket, Action<byte[], IPAddress> onMessage, CancellationToken ct)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _ = Task.Run(async () =>
        {
            var buf = new byte[16384];
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    var r = await socket.ReceiveFromAsync(buf, SocketFlags.None, from, cts.Token).ConfigureAwait(false);
                    if (r.ReceivedBytes > 0 && r.RemoteEndPoint is IPEndPoint ep) onMessage(buf[..r.ReceivedBytes], ep.Address);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _log.LogDebug(ex, "WSD recv"); }
            }
        }, cts.Token);
        return new Disposer(() => { try { cts.Cancel(); } catch { } cts.Dispose(); });
    }

    private static async Task Delay(int ms, CancellationToken ct) { try { await Task.Delay(ms, ct).ConfigureAwait(false); } catch (OperationCanceledException) { } }

    private sealed class Disposer(Action a) : IDisposable { public void Dispose() => a(); }
}
