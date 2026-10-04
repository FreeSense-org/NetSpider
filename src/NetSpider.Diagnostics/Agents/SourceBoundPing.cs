using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NetSpider.Diagnostics.Agents;

/// <summary>
/// Pings from a specific local source address. <see cref="System.Net.NetworkInformation.Ping"/> cannot choose the
/// source, so on Windows this uses iphlpapi <c>IcmpSendEcho2Ex</c>; with Windows' strong-host send model the echo then
/// leaves through the adapter that owns the source address (a source on an adapter without a route to the destination
/// fails instead of silently using another adapter). TCP connect with <see cref="Socket.Bind"/> is the fallback for
/// targets that drop ICMP.
/// </summary>
public static partial class SourceBoundPing
{
    private const int IpSuccess = 0;
    private const int IpReqTimedOut = 11010;

    /// <summary>ICMP echo from <paramref name="source"/> to <paramref name="destination"/> (IPv4, Windows only).</summary>
    public static Task<(double? Ms, string? Error)> IcmpAsync(IPAddress source, IPAddress destination, int timeoutMs, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult<(double?, string?)>((null, "source-bound ICMP needs Windows"));
        if (source.AddressFamily != AddressFamily.InterNetwork || destination.AddressFamily != AddressFamily.InterNetwork)
            return Task.FromResult<(double?, string?)>((null, "IPv4 only"));
        return Task.Run(() => IcmpSync(source, destination, timeoutMs), ct);
    }

    private static (double? Ms, string? Error) IcmpSync(IPAddress source, IPAddress destination, int timeoutMs)
    {
        var handle = IcmpCreateFile();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return (null, $"IcmpCreateFile failed ({Marshal.GetLastPInvokeError()})");
        try
        {
            var payload = new byte[32];
            // ICMP_ECHO_REPLY (32/64-bit) + payload + 8 bytes for an ICMP error + IO_STATUS_BLOCK slack
            int replySize = 64 + payload.Length + 8 + 16;
            var reply = Marshal.AllocHGlobal(replySize);
            try
            {
                var opt = new IpOptionInformation { Ttl = 64 };
                long t0 = Stopwatch.GetTimestamp();
                uint n = IcmpSendEcho2Ex(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ToIpAddr(source), ToIpAddr(destination),
                    payload, (ushort)payload.Length, ref opt, reply, (uint)replySize, (uint)Math.Max(100, timeoutMs));
                double elapsed = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                if (n == 0)
                {
                    int err = Marshal.GetLastPInvokeError();
                    return (null, err switch
                    {
                        IpReqTimedOut => "TimedOut",
                        1231 => "NetworkUnreachable (no route from this adapter)", // ERROR_NETWORK_UNREACHABLE
                        1232 => "HostUnreachable",
                        11003 => "DestinationHostUnreachable",
                        _ => $"IP error {err}",
                    });
                }
                // ICMP_ECHO_REPLY: Address(4) Status(4) RoundTripTime(4) ...
                int status = Marshal.ReadInt32(reply, 4);
                uint rtt = (uint)Marshal.ReadInt32(reply, 8);
                if (status != IpSuccess) return (null, status == IpReqTimedOut ? "TimedOut" : $"ICMP status {status}");
                // RoundTripTime has 1 ms resolution; use the wall clock for sub-ms answers
                double ms = rtt > 0 && elapsed > rtt + 1 ? rtt : elapsed;
                return (Math.Round(ms, 2), null);
            }
            finally { Marshal.FreeHGlobal(reply); }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (null, ex.Message);
        }
        finally { IcmpCloseHandle(handle); }
    }

    /// <summary>
    /// TCP connect from <paramref name="source"/> to 443 then 80. A refused connection (RST) means the host answered.
    /// </summary>
    public static async Task<(double? Ms, string? Error)> TcpAsync(IPAddress source, IPAddress destination, TimeSpan timeout, CancellationToken ct = default)
    {
        string? last = null;
        foreach (var port in new[] { 443, 80 })
        {
            using var s = new Socket(destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            long t0 = Stopwatch.GetTimestamp();
            try
            {
                s.Bind(new IPEndPoint(source, 0));
                await s.ConnectAsync(new IPEndPoint(destination, port), cts.Token).ConfigureAwait(false);
                return (Math.Round(Stopwatch.GetElapsedTime(t0).TotalMilliseconds, 2), null);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return (Math.Round(Stopwatch.GetElapsedTime(t0).TotalMilliseconds, 2), null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { last = "TimedOut (tcp)"; }
            catch (SocketException ex) { last = $"{ex.SocketErrorCode} (tcp)"; }
        }
        return (null, last);
    }

    /// <summary>IPAddr is the address in network byte order as it lies in memory.</summary>
    private static uint ToIpAddr(IPAddress ip) => BitConverter.ToUInt32(ip.GetAddressBytes(), 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct IpOptionInformation
    {
        public byte Ttl;
        public byte Tos;
        public byte Flags;
        public byte OptionsSize;
        public IntPtr OptionsData;
    }

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial IntPtr IcmpCreateFile();

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IcmpCloseHandle(IntPtr handle);

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial uint IcmpSendEcho2Ex(IntPtr icmpHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        uint sourceAddress, uint destinationAddress, byte[] requestData, ushort requestSize, ref IpOptionInformation requestOptions,
        IntPtr replyBuffer, uint replySize, uint timeout);
}
