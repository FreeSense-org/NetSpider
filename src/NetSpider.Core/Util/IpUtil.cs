using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace NetSpider.Core.Model;

public static class IpUtil
{
    public static uint ToUInt32(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        Span<byte> b = stackalloc byte[4];
        ip.TryWriteBytes(b, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(b);
    }

    public static IPAddress FromUInt32(uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return new IPAddress(b);
    }

    public static uint MaskOf(int prefix) => prefix <= 0 ? 0 : prefix >= 32 ? uint.MaxValue : uint.MaxValue << (32 - prefix);

    public static int PrefixFromMask(IPAddress mask)
    {
        uint m = ToUInt32(mask);
        int n = 0;
        while ((m & 0x8000_0000) != 0) { n++; m <<= 1; }
        return n;
    }

    public static IPAddress NetworkAddress(IPAddress ip, int prefix) =>
        ip.AddressFamily == AddressFamily.InterNetwork ? FromUInt32(ToUInt32(ip) & MaskOf(prefix)) : ip;

    public static bool InSubnet(IPAddress ip, IPAddress network, int prefix)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetwork || network.AddressFamily != AddressFamily.InterNetwork) return false;
        uint m = MaskOf(prefix);
        return (ToUInt32(ip) & m) == (ToUInt32(network) & m);
    }

    /// <summary>All usable host addresses in the subnet (network and broadcast excluded for prefixes &lt; 31).</summary>
    public static IEnumerable<IPAddress> Hosts(IPAddress network, int prefix)
    {
        uint net = ToUInt32(network) & MaskOf(prefix);
        uint count = prefix >= 32 ? 1u : 1u << (32 - prefix);
        if (prefix >= 31) { for (uint i = 0; i < count; i++) yield return FromUInt32(net + i); yield break; }
        for (uint i = 1; i < count - 1; i++) yield return FromUInt32(net + i);
    }

    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.IsIPv6LinkLocal || ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] < 128);
    }

    public static bool IsMulticast(IPAddress ip) =>
        ip.AddressFamily == AddressFamily.InterNetwork ? (ip.GetAddressBytes()[0] & 0xF0) == 0xE0 : ip.IsIPv6Multicast;

    /// <summary>Ethernet multicast MAC for an IPv4 (01:00:5E) or IPv6 (33:33) multicast group.</summary>
    public static Mac MulticastMac(IPAddress group)
    {
        var b = group.GetAddressBytes();
        if (b.Length == 4) return new Mac(0x01005E000000UL | ((ulong)(b[1] & 0x7F) << 16) | ((ulong)b[2] << 8) | b[3]);
        return new Mac(0x333300000000UL | ((ulong)b[12] << 24) | ((ulong)b[13] << 16) | ((ulong)b[14] << 8) | b[15]);
    }

    /// <summary>IPv6 solicited-node multicast address ff02::1:ffXX:XXXX for a unicast address.</summary>
    public static IPAddress SolicitedNode(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        var s = new byte[16];
        s[0] = 0xFF; s[1] = 0x02; s[11] = 0x01; s[12] = 0xFF;
        s[13] = b[13]; s[14] = b[14]; s[15] = b[15];
        return new IPAddress(s);
    }

    /// <summary>Parses "a.b.c.d/nn".</summary>
    public static bool TryParseCidr(string s, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0;
        var parts = s.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out prefix) || prefix is < 0 or > 32) return false;
        network = NetworkAddress(ip, prefix);
        return true;
    }

    /// <summary>Parses a port list like "22,80,8000-8100".</summary>
    public static IEnumerable<int> ParsePorts(string? spec)
    {
        if (string.IsNullOrWhiteSpace(spec)) yield break;
        foreach (var part in spec.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var r = part.Split('-');
            if (r.Length == 1 && int.TryParse(r[0], out var p) && p is > 0 and < 65536) yield return p;
            else if (r.Length == 2 && int.TryParse(r[0], out var a) && int.TryParse(r[1], out var z))
                for (int i = Math.Max(1, a); i <= Math.Min(65535, z); i++) yield return i;
        }
    }
}
