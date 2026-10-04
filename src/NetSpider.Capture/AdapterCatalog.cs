using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetSpider.Core.Model;
using SharpPcap.LibPcap;

namespace NetSpider.Capture;

/// <summary>Joins Npcap devices with .NET NetworkInterface data (gateway, DNS, DHCP, speed, type).</summary>
public static class AdapterCatalog
{
    private static readonly (string Needle, string Kind)[] VirtualMarkers =
    [
        // most specific first: WSL adapters are also Hyper-V vEthernet adapters
        ("WSL", "WSL"), ("Docker", "Docker"), ("Hyper-V", "Hyper-V"), ("vEthernet", "Hyper-V"),
        ("VMware", "VMware"), ("VirtualBox", "VirtualBox"), ("TAP-Windows", "VPN"), ("WireGuard", "VPN"), ("Tailscale", "VPN"),
        ("ZeroTier", "VPN"), ("OpenVPN", "VPN"), ("Wintun", "VPN"), ("Cisco AnyConnect", "VPN"), ("Fortinet", "VPN"),
        ("Loopback", "Loopback"), ("Bluetooth", "Bluetooth"), ("Wi-Fi Direct", "WiFiDirect"), ("Microsoft Kernel Debug", "Debug"),
    ];

    public static string? ClassifyVirtual(string text)
    {
        foreach (var (needle, kind) in VirtualMarkers)
            if (text.Contains(needle, StringComparison.OrdinalIgnoreCase)) return kind;
        return null;
    }

    public static IReadOnlyList<AdapterInfo> List()
    {
        var nics = NetworkInterface.GetAllNetworkInterfaces().ToDictionary(n => n.Id.Trim('{', '}').ToUpperInvariant(), n => n);
        var result = new List<AdapterInfo>();
        foreach (var dev in LibPcapLiveDeviceList.Instance)
        {
            var guid = ExtractGuid(dev.Name);
            nics.TryGetValue(guid ?? "", out var nic);
            var iface = dev.Interface;
            var name = nic?.Name ?? iface?.FriendlyName ?? dev.Description ?? dev.Name;
            var desc = nic?.Description ?? dev.Description ?? "";

            var props = SafeProps(nic);
            var v4 = new List<IpWithPrefix>();
            var v6 = new List<IPAddress>();
            if (props is not null)
            {
                foreach (var u in props.UnicastAddresses)
                {
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork) v4.Add(new IpWithPrefix(u.Address, u.PrefixLength));
                    else if (u.Address.AddressFamily == AddressFamily.InterNetworkV6) v6.Add(u.Address);
                }
            }
            else
            {
                foreach (var a in iface?.Addresses ?? [])
                {
                    var ip = a.Addr?.ipAddress;
                    if (ip is null) continue;
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        v4.Add(new IpWithPrefix(ip, a.Netmask?.ipAddress is { } m ? IpUtil.PrefixFromMask(m) : 24));
                    else if (ip.AddressFamily == AddressFamily.InterNetworkV6) v6.Add(ip);
                }
            }

            var gateways = props?.GatewayAddresses.Select(g => g.Address).ToList() ?? iface?.GatewayAddresses ?? [];
            Mac mac = Mac.Zero;
            try
            {
                var pa = nic?.GetPhysicalAddress() ?? iface?.MacAddress;
                if (pa is not null && pa.GetAddressBytes().Length == 6) mac = Mac.FromPhysicalAddress(pa);
            }
            catch { }

            var virt = ClassifyVirtual(desc + " " + name) ?? (dev.Loopback ? "Loopback" : null);
            if (nic?.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp) virt ??= "VPN";
            if (nic?.NetworkInterfaceType == NetworkInterfaceType.Loopback) virt = "Loopback";

            IPAddress? dhcp = null;
            try { dhcp = props?.DhcpServerAddresses.FirstOrDefault(); } catch { }

            result.Add(new AdapterInfo
            {
                Id = guid ?? dev.Name,
                PcapName = dev.Name,
                Name = name,
                Description = desc,
                Mac = mac,
                IPv4 = v4,
                IPv6 = v6,
                GatewayV4 = gateways.FirstOrDefault(g => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any)),
                GatewayV6 = gateways.FirstOrDefault(g => g.AddressFamily == AddressFamily.InterNetworkV6),
                DnsServers = props?.DnsAddresses.ToList() ?? [],
                DhcpServer = dhcp,
                SpeedMbps = nic is null ? 0 : Math.Max(0, nic.Speed / 1_000_000),
                IsUp = nic?.OperationalStatus == OperationalStatus.Up,
                IsWireless = nic?.NetworkInterfaceType == NetworkInterfaceType.Wireless80211,
                IsVirtual = virt is not null,
                VirtualKind = virt,
            });
        }
        // Best candidates first: up, physical, has gateway, has IPv4.
        return result
            .OrderByDescending(a => a.IsUp)
            .ThenBy(a => a.IsVirtual)
            .ThenByDescending(a => a.GatewayV4 is not null)
            .ThenByDescending(a => a.IPv4.Count > 0)
            .ThenBy(a => a.IsWireless)
            .ToList();
    }

    private static IPInterfaceProperties? SafeProps(NetworkInterface? nic)
    {
        try { return nic?.GetIPProperties(); } catch { return null; }
    }

    private static string? ExtractGuid(string pcapName)
    {
        int s = pcapName.IndexOf('{'), e = pcapName.IndexOf('}');
        return s >= 0 && e > s ? pcapName[(s + 1)..e].ToUpperInvariant() : null;
    }
}
