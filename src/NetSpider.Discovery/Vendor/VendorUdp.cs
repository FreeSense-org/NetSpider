using System.Net;
using System.Net.Sockets;

namespace NetSpider.Discovery.Vendor;

/// <summary>Shared UDP broadcast request/collect helper for vendor L2/L3 discovery protocols.</summary>
internal static class VendorUdp
{
    /// <summary>
    /// Binds a UDP socket (optionally to a fixed local port), broadcasts <paramref name="payload"/> to each target,
    /// and invokes <paramref name="onResponse"/> for every datagram received during <paramref name="collect"/>.
    /// </summary>
    public static async Task BroadcastCollectAsync(
        IPAddress? localIp, int localPort, IEnumerable<IPEndPoint> targets, byte[] payload,
        TimeSpan collect, Action<byte[], IPEndPoint> onResponse, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.EnableBroadcast = true;
        try { socket.Bind(new IPEndPoint(localIp ?? IPAddress.Any, localPort)); }
        catch (SocketException) { socket.Bind(new IPEndPoint(localIp ?? IPAddress.Any, 0)); }

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
                    if (r.ReceivedBytes > 0 && r.RemoteEndPoint is IPEndPoint ep) onResponse(buf[..r.ReceivedBytes], ep);
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }, cts.Token);

        foreach (var target in targets)
        {
            try { await socket.SendToAsync(payload, SocketFlags.None, target, ct).ConfigureAwait(false); }
            catch { }
        }

        try { await Task.Delay(collect, ct).ConfigureAwait(false); } catch (OperationCanceledException) { }
        cts.Cancel();
        try { await receiver.ConfigureAwait(false); } catch { }
    }
}
