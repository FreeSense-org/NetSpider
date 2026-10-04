using NetSpider.Core.Model;

namespace NetSpider.Core.Services;

/// <summary>
/// Deterministic locally-administered MACs for nodes that are not real NICs (Internet cloud, inferred switches, remote hosts).
/// Layout: byte 0 = 0xFE (LAA unicast), byte 1 = 0x50 | category, bytes 2-5 = 32-bit value.
/// </summary>
public static class SyntheticNodes
{
    private const ulong Marker = 0xFE50_0000_0000UL;

    private static Mac Make(int category, uint value) => new(Marker | ((ulong)(category & 0x0F) << 32) | value);

    public static readonly Mac Internet = Make(0, 1);

    public static Mac InferredSwitch(Mac upstream, string? port) =>
        Make(1, (uint)HashCode.Combine(upstream.Value, port ?? ""));

    public static Mac InferredSwitch(int clusterId) => Make(2, (uint)clusterId);

    public static Mac Hop(System.Net.IPAddress ip) => Make(3, IpUtil.ToUInt32(ip));

    /// <summary>Identity for a host on another (routed) subnet whose real MAC is unknown. Replace with the real MAC if SNMP ARP tables reveal it.</summary>
    public static Mac RemoteHost(System.Net.IPAddress ip) => Make(4, IpUtil.ToUInt32(ip));

    public static bool IsSynthetic(Mac mac) => (mac.Value & 0xFFF0_0000_0000UL) == Marker;

    /// <summary>Pure graph nodes (Internet, inferred switches, hops) that are not real hosts. Remote hosts are real and excluded.</summary>
    public static bool IsGraphOnly(Mac mac) => IsSynthetic(mac) && !IsRemoteHost(mac);

    /// <summary>true for remote-host identities (they have a real IP and can be probed).</summary>
    public static bool IsRemoteHost(Mac mac) => (mac.Value & 0xFFFF_0000_0000UL) == (Marker | (4UL << 32));
}
