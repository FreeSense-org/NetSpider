using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetSpider.Probe;

/// <summary>This agent's own network identity: the interface that carries traffic to the hub (or the internet).</summary>
public sealed record LocalInfo(string? InterfaceName, IPAddress? Ip, string? Mac, string Medium, IPAddress? Gateway);

/// <summary>Cross-platform local interface lookup (System.Net.NetworkInformation plus /sys and /proc on Linux).</summary>
public static class LocalNetwork
{
    public static LocalInfo Describe(IPAddress? hub)
    {
        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .ToList();

            NetworkInterface? nic = null;
            foreach (var dest in new[] { hub, IPAddress.Parse("1.1.1.1") })
            {
                if (dest is null || IPAddress.IsLoopback(dest)) continue;
                if (SourceAddressFor(dest) is not { } src || IPAddress.IsLoopback(src)) continue;
                nic = nics.FirstOrDefault(n => n.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(src)));
                if (nic is not null) break;
            }
            nic ??= nics.FirstOrDefault(n => GatewayOf(n) is not null) ?? nics.FirstOrDefault();
            if (nic is null) return new LocalInfo(null, null, null, "unknown", null);

            var ip = nic.GetIPProperties().UnicastAddresses.Select(u => u.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            string? mac = macBytes.Length == 6 && macBytes.Any(b => b != 0) ? string.Join(":", macBytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture))) : null;
            return new LocalInfo(nic.Name, ip, mac, IsWireless(nic) ? "Wi-Fi" : "Wired", GatewayOf(nic));
        }
        catch
        {
            return new LocalInfo(null, null, null, "unknown", null);
        }
    }

    /// <summary>The local address the OS would use to reach <paramref name="dest"/> (connect() on UDP sends nothing).</summary>
    public static IPAddress? SourceAddressFor(IPAddress dest)
    {
        try
        {
            using var s = new Socket(dest.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(dest, 9));
            return (s.LocalEndPoint as IPEndPoint)?.Address;
        }
        catch { return null; }
    }

    private static bool IsWireless(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) return true;
        if (OperatingSystem.IsLinux())
        {
            try { return Directory.Exists($"/sys/class/net/{nic.Name}/wireless") || Directory.Exists($"/sys/class/net/{nic.Name}/phy80211"); }
            catch { }
        }
        return false;
    }

    private static IPAddress? GatewayOf(NetworkInterface nic)
    {
        try
        {
            var gw = nic.GetIPProperties().GatewayAddresses.Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            if (gw is not null) return gw;
        }
        catch { }
        return OperatingSystem.IsLinux() ? LinuxGatewayFromProcRoute(nic.Name) : null;
    }

    /// <summary>Default route from /proc/net/route (little-endian hex), in case the runtime did not report one.</summary>
    private static IPAddress? LinuxGatewayFromProcRoute(string ifName)
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/net/route").Skip(1))
            {
                var f = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (f.Length < 3 || f[0] != ifName || f[1] != "00000000") continue;
                if (uint.TryParse(f[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var g) && g != 0)
                    return new IPAddress(g); // /proc stores network order bytes as host-endian hex, which IPAddress(long) expects on little-endian
            }
        }
        catch { }
        return null;
    }
}
