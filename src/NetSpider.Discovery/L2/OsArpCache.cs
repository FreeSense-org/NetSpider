using System.Net;
using System.Runtime.InteropServices;

namespace NetSpider.Discovery.L2;

/// <summary>Reads the operating system's IPv4 neighbor (ARP) cache via iphlpapi GetIpNetTable.</summary>
internal static class OsArpCache
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public int Index;
        public int PhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] PhysAddr;
        public uint Addr;
        public int Type; // 1 other, 2 invalid, 3 dynamic, 4 static
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetIpNetTable(IntPtr table, ref int size, bool order);

    /// <summary>Unicast IPs with a resolved (dynamic or static) MAC; empty on non-Windows or failure.</summary>
    public static IReadOnlyList<IPAddress> Read()
    {
        if (!OperatingSystem.IsWindows()) return [];
        int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return [];
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, false) != 0) return [];
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MibIpNetRow>();
            var result = new List<IPAddress>(count);
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow>(buf + 4 + i * rowSize);
                if (row.Type is not (3 or 4) || row.PhysAddrLen != 6) continue;
                if (row.PhysAddr[0] == 0xFF || (row.PhysAddr[0] & 1) != 0) continue; // broadcast/multicast entries
                var ip = new IPAddress(row.Addr); // dwAddr is in network byte order, as IPAddress(long) expects
                result.Add(ip);
            }
            return result;
        }
        catch { return []; }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
