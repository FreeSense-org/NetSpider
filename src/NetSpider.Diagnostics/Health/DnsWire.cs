using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetSpider.Diagnostics.Health;

/// <summary>Minimal DNS A-query encoder/decoder and UDP client (enough for resolver timing and NXDOMAIN-hijack tests).</summary>
public static class DnsWire
{
    public const int RcodeNoError = 0, RcodeServFail = 2, RcodeNxDomain = 3;

    public sealed record Response(ushort Id, int Rcode, IReadOnlyList<IPAddress> Addresses, bool Truncated);

    public static byte[] EncodeQuery(ushort id, string name, ushort qtype = 1)
    {
        var labels = name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        int len = 12 + labels.Sum(l => 1 + Encoding.ASCII.GetByteCount(l)) + 1 + 4;
        var buf = new byte[len];
        BinaryPrimitives.WriteUInt16BigEndian(buf, id);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), 0x0100); // RD
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), 1);      // QDCOUNT
        int o = 12;
        foreach (var l in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(l);
            if (bytes.Length > 63) throw new ArgumentException("DNS label too long", nameof(name));
            buf[o++] = (byte)bytes.Length;
            bytes.CopyTo(buf, o);
            o += bytes.Length;
        }
        buf[o++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), qtype);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o + 2), 1); // IN
        return buf;
    }

    public static Response? Decode(ReadOnlySpan<byte> msg)
    {
        if (msg.Length < 12) return null;
        ushort id = BinaryPrimitives.ReadUInt16BigEndian(msg);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(msg[2..]);
        if ((flags & 0x8000) == 0) return null; // not a response
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg[4..]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(msg[6..]);
        int o = 12;
        for (int i = 0; i < qd; i++)
        {
            if (!SkipName(msg, ref o) || o + 4 > msg.Length) return null;
            o += 4;
        }
        var addrs = new List<IPAddress>();
        for (int i = 0; i < an; i++)
        {
            if (!SkipName(msg, ref o) || o + 10 > msg.Length) break;
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(msg[o..]);
            ushort cls = BinaryPrimitives.ReadUInt16BigEndian(msg[(o + 2)..]);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg[(o + 8)..]);
            o += 10;
            if (o + rdlen > msg.Length) break;
            if (cls == 1 && type == 1 && rdlen == 4) addrs.Add(new IPAddress(msg.Slice(o, 4)));
            else if (cls == 1 && type == 28 && rdlen == 16) addrs.Add(new IPAddress(msg.Slice(o, 16)));
            o += rdlen;
        }
        return new Response(id, flags & 0x000F, addrs, (flags & 0x0200) != 0);
    }

    private static bool SkipName(ReadOnlySpan<byte> msg, ref int o)
    {
        for (int guard = 0; guard < 128 && o < msg.Length; guard++)
        {
            byte len = msg[o];
            if (len == 0) { o++; return true; }
            if ((len & 0xC0) == 0xC0) { o += 2; return o <= msg.Length; }
            o += 1 + len;
        }
        return false;
    }

    /// <summary>Sends one A query over UDP and returns the decoded response and elapsed milliseconds, or null on timeout.</summary>
    public static async Task<(Response Response, double Ms)?> QueryAsync(IPAddress server, string name, TimeSpan timeout, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        var id = (ushort)Random.Shared.Next(1, 65535);
        var q = EncodeQuery(id, name);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            await udp.SendAsync(q, new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
            while (true)
            {
                var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                var resp = Decode(r.Buffer);
                if (resp is not null && resp.Id == id) return (resp, sw.Elapsed.TotalMilliseconds);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (SocketException) { return null; }
    }
}
