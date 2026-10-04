using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.Ssdp;

namespace NetSpider.Discovery.Gateway;

/// <summary>
/// Audits the WAN gateway: UPnP IGD (external IP, status, port-forward table) via the <see cref="SsdpRegistry"/> and a
/// targeted M-SEARCH, plus NAT-PMP and PCP external-address requests. Writes <see cref="INetworkState.Wan"/>.
/// </summary>
public sealed class GatewayAuditProbe : IActiveProbe
{
    private static readonly IPAddress SsdpV4 = IPAddress.Parse("239.255.255.250");

    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly SsdpRegistry _registry;
    private readonly ILogger<GatewayAuditProbe> _log;

    public GatewayAuditProbe(IDeviceStore store, INetworkState network, SsdpRegistry registry, ILogger<GatewayAuditProbe> log)
    {
        _store = store; _network = network; _registry = registry; _log = log;
    }

    public string Name => "Gateway audit";
    public ProbeLayer Layer => ProbeLayer.L7;
    public int Order => 250;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress(Name, 0, "IGD"));
        try
        {
            var igd = await FindIgdAsync(ctx, ct).ConfigureAwait(false);
            if (igd is not null)
            {
                var wan = await QueryIgdAsync(ctx, igd.Value.ControlUrl, igd.Value.ServiceType, ct).ConfigureAwait(false);
                if (wan is not null) { _network.Wan = wan; progress?.Report(new ScanProgress(Name, 1, "UPnP-IGD")); return; }
            }

            if (ctx.Gateway is { } gw)
            {
                var natpmp = await NatPmpAsync(ctx, gw, ct).ConfigureAwait(false);
                if (natpmp is not null) { _network.Wan = natpmp; progress?.Report(new ScanProgress(Name, 1, "NAT-PMP")); return; }
                await PcpAnnounceAsync(ctx, gw, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "Gateway audit"); }
        progress?.Report(new ScanProgress(Name, 1));
    }

    // ---- UPnP IGD ----

    private async Task<(string ControlUrl, string ServiceType)?> FindIgdAsync(ScanContext ctx, CancellationToken ct)
    {
        // first, anything SSDP already discovered
        var hit = FindConnectionService(_registry.InternetGatewayDevices());
        if (hit is not null) return hit;

        // targeted M-SEARCH for IGD v1 and v2
        await TargetedSearchAsync(ctx, ct).ConfigureAwait(false);
        return FindConnectionService(_registry.InternetGatewayDevices());
    }

    private static (string ControlUrl, string ServiceType)? FindConnectionService(IEnumerable<SsdpDescription> igds)
    {
        foreach (var desc in igds)
            foreach (var dev in desc.AllDevices())
                foreach (var svc in dev.Services)
                    if ((svc.ServiceType.Contains("WANIPConnection", StringComparison.OrdinalIgnoreCase)
                         || svc.ServiceType.Contains("WANPPPConnection", StringComparison.OrdinalIgnoreCase))
                        && !string.IsNullOrWhiteSpace(svc.ControlUrl))
                        return (svc.ControlUrl!, svc.ServiceType);
        return null;
    }

    private async Task TargetedSearchAsync(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
            var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var receiver = Task.Run(async () =>
            {
                var buf = new byte[8192];
                while (!cts.IsCancellationRequested)
                {
                    try
                    {
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        var r = await socket.ReceiveFromAsync(buf, SocketFlags.None, from, cts.Token).ConfigureAwait(false);
                        var text = Encoding.ASCII.GetString(buf, 0, r.ReceivedBytes);
                        var h = SsdpInterpreter.ParseHeaders(text);
                        if (h.TryGetValue("LOCATION", out var loc)) locations.Add(loc);
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }
            }, cts.Token);

            foreach (var st in new[] { "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2" })
            {
                var msg = $"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n";
                await socket.SendToAsync(Encoding.ASCII.GetBytes(msg), SocketFlags.None, new IPEndPoint(SsdpV4, 1900), ct).ConfigureAwait(false);
            }
            await Task.Delay(2500, ct).ConfigureAwait(false);
            cts.Cancel();
            try { await receiver.ConfigureAwait(false); } catch { }

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            foreach (var loc in locations)
            {
                if (_registry.Contains(loc) || !Uri.TryCreate(loc, UriKind.Absolute, out var uri)) continue;
                try
                {
                    var xml = await http.GetStringAsync(uri, ct).ConfigureAwait(false);
                    var root = UpnpXml.Parse(xml, uri);
                    if (root is not null) _registry.Add(new SsdpDescription(IPAddress.TryParse(uri.Host, out var ipp) ? ipp : (ctx.Gateway ?? IPAddress.None), uri, null, root));
                }
                catch (Exception ex) { _log.LogDebug(ex, "IGD desc {Loc}", loc); }
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "IGD search"); }
    }

    private async Task<WanInfo?> QueryIgdAsync(ScanContext ctx, string controlUrl, string serviceType, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        var extIp = await SoapAsync(http, controlUrl, serviceType, "GetExternalIPAddress", "", ct).ConfigureAwait(false);
        var external = ReadXmlValue(extIp, "NewExternalIPAddress");
        var status = await SoapAsync(http, controlUrl, serviceType, "GetStatusInfo", "", ct).ConfigureAwait(false);
        var connStatus = ReadXmlValue(status, "NewConnectionStatus");
        var uptimeStr = ReadXmlValue(status, "NewUptime");
        var typeInfo = await SoapAsync(http, controlUrl, serviceType, "GetConnectionTypeInfo", "", ct).ConfigureAwait(false);
        var connType = ReadXmlValue(typeInfo, "NewConnectionType");

        var mappings = await ReadPortMappingsAsync(ctx, http, controlUrl, serviceType, ct).ConfigureAwait(false);

        TimeSpan? uptime = long.TryParse(uptimeStr, out var up) ? TimeSpan.FromSeconds(up) : null;
        IPAddress? extAddr = IPAddress.TryParse(external, out var e) ? e : null;
        return new WanInfo(extAddr, connStatus, connType, uptime, null, "UPnP-IGD", mappings, DateTimeOffset.Now);
    }

    private async Task<IReadOnlyList<PortMapping>> ReadPortMappingsAsync(ScanContext ctx, HttpClient http, string controlUrl, string serviceType, CancellationToken ct)
    {
        var mappings = new List<PortMapping>();
        for (int i = 0; i < 128 && !ct.IsCancellationRequested; i++)
        {
            var body = $"<NewPortMappingIndex>{i}</NewPortMappingIndex>";
            var resp = await SoapAsync(http, controlUrl, serviceType, "GetGenericPortMappingEntry", body, ct).ConfigureAwait(false);
            if (resp is null) break; // SOAP fault => past the end of the table
            var proto = ReadXmlValue(resp, "NewProtocol") ?? "TCP";
            var extPort = int.TryParse(ReadXmlValue(resp, "NewExternalPort"), out var ep) ? ep : 0;
            var intPort = int.TryParse(ReadXmlValue(resp, "NewInternalPort"), out var ip2) ? ip2 : 0;
            var client = ReadXmlValue(resp, "NewInternalClient");
            var desc = ReadXmlValue(resp, "NewPortMappingDescription");
            var enabled = ReadXmlValue(resp, "NewEnabled") == "1";
            var remote = ReadXmlValue(resp, "NewRemoteHost");
            var lease = int.TryParse(ReadXmlValue(resp, "NewLeaseDuration"), out var l) && l > 0 ? TimeSpan.FromSeconds(l) : (TimeSpan?)null;
            IPAddress? clientIp = IPAddress.TryParse(client, out var ci) ? ci : null;
            mappings.Add(new PortMapping(proto, extPort, clientIp, intPort, desc, enabled, lease, remote));

            // Flag the targeted device as WAN-exposed.
            if (clientIp is not null && _store.FindByIp(clientIp) is { } dev)
            {
                dev.SetProperty($"wan.exposed.{proto}.{extPort}", $"{clientIp}:{intPort} {desc}");
                _store.NotifyChanged(dev, "wan");
            }
        }
        return mappings;
    }

    private async Task<string?> SoapAsync(HttpClient http, string controlUrl, string serviceType, string action, string innerArgs, CancellationToken ct)
    {
        var envelope =
            "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            "<s:Body>" +
            $"<u:{action} xmlns:u=\"{serviceType}\">{innerArgs}</u:{action}>" +
            "</s:Body></s:Envelope>";
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, controlUrl);
            req.Content = new StringContent(envelope, Encoding.UTF8, "text/xml");
            req.Headers.TryAddWithoutValidation("SOAPAction", $"\"{serviceType}#{action}\"");
            using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null; // 500 => SOAP fault (end of table)
            return await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "SOAP {Action}", action); return null; }
    }

    private static string? ReadXmlValue(string? xml, string local)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try
        {
            return XDocument.Parse(xml).Descendants().FirstOrDefault(e => e.Name.LocalName.Equals(local, StringComparison.OrdinalIgnoreCase))?.Value?.Trim();
        }
        catch { return null; }
    }

    // ---- NAT-PMP (RFC 6886) ----

    private async Task<WanInfo?> NatPmpAsync(ScanContext ctx, IPAddress gateway, CancellationToken ct)
    {
        try
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            // version 0, opcode 0 = external address request
            await udp.SendToAsync(new byte[] { 0, 0 }, SocketFlags.None, new IPEndPoint(gateway, 5351), ct).ConfigureAwait(false);
            var buf = new byte[32];
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(1000);
            var from = new IPEndPoint(IPAddress.Any, 0);
            var r = await udp.ReceiveFromAsync(buf, SocketFlags.None, from, timeoutCts.Token).ConfigureAwait(false);
            // response: version(0) op(128) result(2) epoch(4) ext-ip(4)
            if (r.ReceivedBytes >= 12 && buf[1] == 128)
            {
                var extIp = new IPAddress(buf.AsSpan(8, 4).ToArray());
                return new WanInfo(extIp, "Connected", null, null, null, "NAT-PMP", [], DateTimeOffset.Now);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "NAT-PMP"); }
        return null;
    }

    // ---- PCP (RFC 6887) ANNOUNCE ----

    private async Task PcpAnnounceAsync(ScanContext ctx, IPAddress gateway, CancellationToken ct)
    {
        try
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            // PCP request: version 2, opcode 0 (ANNOUNCE), reserved, lifetime 0, client IP (IPv4-mapped IPv6)
            var req = new byte[24];
            req[0] = 2; req[1] = 0;
            var client = (ctx.LocalIPv4 ?? IPAddress.Any).MapToIPv6().GetAddressBytes();
            client.CopyTo(req, 8);
            await udp.SendToAsync(req, SocketFlags.None, new IPEndPoint(gateway, 5351), ct).ConfigureAwait(false);
            var buf = new byte[64];
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(800);
            var from = new IPEndPoint(IPAddress.Any, 0);
            var r = await udp.ReceiveFromAsync(buf, SocketFlags.None, from, timeoutCts.Token).ConfigureAwait(false);
            if (r.ReceivedBytes >= 4 && buf[0] == 2 && _store.FindByIp(gateway) is { } dev)
            {
                dev.SetProperty("pcp.supported", "true");
                _store.NotifyChanged(dev, "pcp");
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "PCP"); }
    }
}
