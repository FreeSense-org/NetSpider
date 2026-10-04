using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Probe;

/// <summary>Finds the hub by broadcasting a key-tagged <c>NETSPIDER_HUB?</c> request to UDP 47811.</summary>
public static class HubLocator
{
    public static async Task<IPEndPoint?> DiscoverAsync(byte[] key, TimeSpan timeout, CancellationToken ct, int discoveryPort = AgentProtocol.DiscoveryPort)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        var request = AgentProtocol.BuildDiscoveryRequest(key, out var challenge);

        foreach (var dest in BroadcastTargets())
        {
            try { await udp.SendAsync(request, new IPEndPoint(dest, discoveryPort), ct).ConfigureAwait(false); }
            catch (SocketException) { }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        while (true)
        {
            UdpReceiveResult res;
            try { res = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return null; }
            catch (SocketException) { continue; } // e.g. ICMP port unreachable from the loopback send
            if (AgentProtocol.TryParseDiscoveryReply(res.Buffer, key, challenge, out var port))
                return new IPEndPoint(res.RemoteEndPoint.Address, port);
        }
    }

    /// <summary>Limited broadcast, each interface's directed broadcast, and loopback (hub on the same machine).</summary>
    private static IEnumerable<IPAddress> BroadcastTargets()
    {
        var list = new List<IPAddress> { IPAddress.Broadcast };
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var u in nic.GetIPProperties().UnicastAddresses)
                {
                    if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.PrefixLength is <= 0 or >= 31) continue;
                    uint ip = ToUInt(u.Address), mask = u.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - u.PrefixLength);
                    list.Add(FromUInt(ip | ~mask));
                }
            }
        }
        catch { }
        list.Add(IPAddress.Loopback);
        return list.Distinct();
    }

    private static uint ToUInt(IPAddress a) { var b = a.GetAddressBytes(); return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]); }
    private static IPAddress FromUInt(uint v) => new([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);
}
