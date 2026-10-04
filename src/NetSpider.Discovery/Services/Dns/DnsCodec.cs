using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetSpider.Discovery.Services.Dns;

public enum DnsType : ushort
{
    A = 1, Ns = 2, Cname = 5, Ptr = 12, Txt = 16, Aaaa = 28, Srv = 33, Nsec = 47, Any = 255,
}

public enum DnsClass : ushort { In = 1, Any = 255 }

public sealed record DnsQuestion(string Name, DnsType Type, ushort Class)
{
    /// <summary>mDNS unicast-response (QU) bit lives in the top bit of the class field.</summary>
    public bool UnicastResponse => (Class & 0x8000) != 0;
}

public sealed record DnsResourceRecord(string Name, DnsType Type, ushort Class, uint Ttl, ReadOnlyMemory<byte> RData)
{
    public bool CacheFlush => (Class & 0x8000) != 0;

    public IPAddress? AsAddress()
    {
        var d = RData.Span;
        return Type switch
        {
            DnsType.A when d.Length == 4 => new IPAddress(d.ToArray()),
            DnsType.Aaaa when d.Length == 16 => new IPAddress(d.ToArray()),
            _ => null,
        };
    }
}

public sealed record DnsSrv(ushort Priority, ushort Weight, ushort Port, string Target);

public sealed class DnsMessage
{
    public ushort Id { get; set; }
    public ushort Flags { get; set; }
    public bool IsResponse => (Flags & 0x8000) != 0;
    public List<DnsQuestion> Questions { get; } = new();
    public List<DnsResourceRecord> Answers { get; } = new();
    public List<DnsResourceRecord> Authorities { get; } = new();
    public List<DnsResourceRecord> Additionals { get; } = new();

    public IEnumerable<DnsResourceRecord> AllRecords => Answers.Concat(Authorities).Concat(Additionals);
}

/// <summary>
/// Minimal DNS wire reader/writer with RFC 1035 name compression, used by mDNS and LLMNR. Tolerant: a malformed
/// section stops parsing rather than throwing, so partial captures still yield what was read.
/// </summary>
public static class DnsCodec
{
    public static bool TryParse(ReadOnlySpan<byte> data, out DnsMessage message)
    {
        message = new DnsMessage();
        if (data.Length < 12) return false;
        try
        {
            message.Id = BinaryPrimitives.ReadUInt16BigEndian(data);
            message.Flags = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
            int qd = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
            int an = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
            int ns = BinaryPrimitives.ReadUInt16BigEndian(data[8..]);
            int ar = BinaryPrimitives.ReadUInt16BigEndian(data[10..]);
            int pos = 12;

            for (int i = 0; i < qd; i++)
            {
                var name = ReadName(data, ref pos);
                if (pos + 4 > data.Length) return message.Questions.Count > 0;
                var type = (DnsType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
                var cls = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
                pos += 4;
                message.Questions.Add(new DnsQuestion(name, type, cls));
            }

            if (!ReadRecords(data, ref pos, an, message.Answers)) return true;
            if (!ReadRecords(data, ref pos, ns, message.Authorities)) return true;
            ReadRecords(data, ref pos, ar, message.Additionals);
            return true;
        }
        catch
        {
            // Return whatever was decoded before the fault.
            return message.Questions.Count > 0 || message.Answers.Count > 0;
        }
    }

    private static bool ReadRecords(ReadOnlySpan<byte> data, ref int pos, int count, List<DnsResourceRecord> into)
    {
        for (int i = 0; i < count; i++)
        {
            var name = ReadName(data, ref pos);
            if (pos + 10 > data.Length) return false;
            var type = (DnsType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            var cls = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(data[(pos + 4)..]);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 8)..]);
            pos += 10;
            if (pos + rdlen > data.Length) return false;
            var rdata = data.Slice(pos, rdlen).ToArray();
            into.Add(new DnsResourceRecord(name, type, cls, ttl, rdata));
            pos += rdlen;
        }
        return true;
    }

    /// <summary>Reads a possibly-compressed domain name, advancing <paramref name="pos"/> past the encoded name.</summary>
    public static string ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var sb = new StringBuilder();
        int jumps = 0;
        int cursor = pos;
        int afterPointer = -1;
        while (cursor < data.Length)
        {
            byte len = data[cursor];
            if (len == 0) { cursor++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= data.Length) { cursor += 1; break; }
                int ptr = ((len & 0x3F) << 8) | data[cursor + 1];
                if (afterPointer < 0) afterPointer = cursor + 2;
                if (++jumps > 128 || ptr >= data.Length) break;
                cursor = ptr;
                continue;
            }
            cursor++;
            if (cursor + len > data.Length) break;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.UTF8.GetString(data.Slice(cursor, len)));
            cursor += len;
        }
        pos = afterPointer >= 0 ? afterPointer : cursor;
        return sb.ToString();
    }

    // ---- TXT / SRV / NSEC helpers ----

    /// <summary>Parses a TXT rdata into key/value pairs. A bare key (no '=') maps to an empty value.</summary>
    public static Dictionary<string, string> ParseTxt(ReadOnlySpan<byte> rdata)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int i = 0;
        while (i < rdata.Length)
        {
            int len = rdata[i++];
            if (len == 0 || i + len > rdata.Length) { if (len == 0) continue; break; }
            var entry = Encoding.UTF8.GetString(rdata.Slice(i, len));
            i += len;
            int eq = entry.IndexOf('=');
            if (eq < 0) map[entry] = "";
            else map[entry[..eq]] = entry[(eq + 1)..];
        }
        return map;
    }

    public static DnsSrv? ParseSrv(ReadOnlySpan<byte> data, DnsResourceRecord rr)
    {
        var d = rr.RData.Span;
        if (d.Length < 7) return null;
        ushort prio = BinaryPrimitives.ReadUInt16BigEndian(d);
        ushort weight = BinaryPrimitives.ReadUInt16BigEndian(d[2..]);
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(d[4..]);
        // The SRV target may use compression pointers into the full message, so resolve against the whole packet.
        int offset = FindRData(data, rr);
        string target;
        if (offset >= 0)
        {
            int p = offset + 6;
            target = ReadName(data, ref p);
        }
        else
        {
            int p = 6;
            target = ReadName(d, ref p);
        }
        return new DnsSrv(prio, weight, port, target);
    }

    /// <summary>Reads a PTR/CNAME/NS target name (a single compressed name) from an rdata, resolving pointers against the packet.</summary>
    public static string ParseName(ReadOnlySpan<byte> packet, DnsResourceRecord rr)
    {
        int offset = FindRData(packet, rr);
        if (offset >= 0) { int p = offset; return ReadName(packet, ref p); }
        int q = 0; return ReadName(rr.RData.Span, ref q);
    }

    private static int FindRData(ReadOnlySpan<byte> packet, DnsResourceRecord rr)
    {
        var needle = rr.RData.Span;
        if (needle.Length == 0) return -1;
        int idx = packet.IndexOf(needle);
        return idx;
    }

    // ---- writer ----

    /// <summary>Builds a DNS query message. For mDNS set <paramref name="id"/>=0; set QU in each question's class when needed.</summary>
    public static byte[] BuildQuery(IEnumerable<DnsQuestion> questions, ushort id = 0, bool recursionDesired = false)
    {
        var qs = questions.ToList();
        using var ms = new MemoryStream();
        Span<byte> hdr = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(hdr, id);
        BinaryPrimitives.WriteUInt16BigEndian(hdr[2..], (ushort)(recursionDesired ? 0x0100 : 0));
        BinaryPrimitives.WriteUInt16BigEndian(hdr[4..], (ushort)qs.Count);
        ms.Write(hdr);
        // No compression on write: simple and correct for queries.
        Span<byte> tc = stackalloc byte[4];
        foreach (var q in qs)
        {
            WriteName(ms, q.Name);
            BinaryPrimitives.WriteUInt16BigEndian(tc, (ushort)q.Type);
            BinaryPrimitives.WriteUInt16BigEndian(tc[2..], q.Class);
            ms.Write(tc);
        }
        return ms.ToArray();
    }

    public static void WriteName(Stream s, string name)
    {
        if (!string.IsNullOrEmpty(name))
            foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                var bytes = Encoding.UTF8.GetBytes(label);
                int len = Math.Min(bytes.Length, 63);
                s.WriteByte((byte)len);
                s.Write(bytes, 0, len);
            }
        s.WriteByte(0);
    }
}
