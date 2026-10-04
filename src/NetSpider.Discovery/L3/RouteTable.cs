using System.Net;
using System.Runtime.InteropServices;

namespace NetSpider.Discovery.L3;

/// <summary>One IPv4 route from the Windows forwarding table.</summary>
public sealed record RouteEntry(IPAddress Destination, int PrefixLength, IPAddress NextHop, uint InterfaceIndex, uint Metric, int Protocol, bool Loopback)
{
    public bool HasGateway => !NextHop.Equals(IPAddress.Any);
    public override string ToString() => $"{Destination}/{PrefixLength} via {NextHop} if {InterfaceIndex}";
}

/// <summary>Reads the IPv4 route table via <c>GetIpForwardTable2</c> (iphlpapi).</summary>
public static class RouteTable
{
    private const ushort AfInet = 2;
    /// <summary>sizeof(MIB_IPFORWARD_ROW2) on x64/x86 (8-byte aligned because of NET_LUID).</summary>
    private const int RowSize = 104;
    private const int RowsOffset = 8;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetIpForwardTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr memory);

    public static IReadOnlyList<RouteEntry> ReadIPv4()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var list = new List<RouteEntry>();
        IntPtr table = IntPtr.Zero;
        try
        {
            if (GetIpForwardTable2(AfInet, out table) != 0 || table == IntPtr.Zero) return list;
            int count = Marshal.ReadInt32(table);
            var row = new byte[RowSize];
            for (int i = 0; i < count && i < 100_000; i++)
            {
                Marshal.Copy(table + RowsOffset + i * RowSize, row, 0, RowSize);
                if (ParseRow(row) is { } r) list.Add(r);
            }
        }
        finally
        {
            if (table != IntPtr.Zero) FreeMibTable(table);
        }
        return list;
    }

    /// <summary>
    /// MIB_IPFORWARD_ROW2 layout: InterfaceLuid @0 (8), InterfaceIndex @8 (4), DestinationPrefix @12 {SOCKADDR_INET (28) + PrefixLength @40},
    /// NextHop @44 (SOCKADDR_INET, 28), SitePrefixLength @72, ValidLifetime @76, PreferredLifetime @80, Metric @84, Protocol @88,
    /// Loopback @92, AutoconfigureAddress @93, Publish @94, Immortal @95, Age @96, Origin @100.
    /// </summary>
    internal static RouteEntry? ParseRow(ReadOnlySpan<byte> r)
    {
        if (r.Length < RowSize) return null;
        ushort family = BitConverter.ToUInt16(r[12..]);
        if (family != AfInet) return null;
        var dest = new IPAddress(r.Slice(16, 4));
        int prefix = r[40];
        ushort nhFamily = BitConverter.ToUInt16(r[44..]);
        var nextHop = nhFamily == AfInet ? new IPAddress(r.Slice(48, 4)) : IPAddress.Any;
        return new RouteEntry(dest, prefix, nextHop, BitConverter.ToUInt32(r[8..]), BitConverter.ToUInt32(r[84..]), BitConverter.ToInt32(r[88..]), r[92] != 0);
    }
}
