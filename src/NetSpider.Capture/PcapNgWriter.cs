using System.Buffers.Binary;
using System.Text;

namespace NetSpider.Capture;

/// <summary>Minimal pcapng writer: Section Header, one Ethernet Interface Description (µs), Enhanced Packet Blocks.</summary>
public sealed class PcapNgWriter : IDisposable
{
    private readonly Stream _stream;
    private readonly BinaryWriter _w;

    public PcapNgWriter(Stream stream, string? comment = null, string? interfaceName = null)
    {
        _stream = stream;
        _w = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        WriteSectionHeader(comment);
        WriteInterfaceDescription(interfaceName);
    }

    public static PcapNgWriter Create(string path, string? comment = null, string? interfaceName = null) =>
        new(File.Create(path), comment, interfaceName);

    private void WriteSectionHeader(string? comment)
    {
        var opts = Options((1, comment), (4, "NetSpider"));
        int len = 28 + opts.Length;
        _w.Write(0x0A0D0D0Au);
        _w.Write(len);
        _w.Write(0x1A2B3C4Du);
        _w.Write((ushort)1); _w.Write((ushort)0);
        _w.Write(-1L); // section length unknown
        _w.Write(opts);
        _w.Write(len);
    }

    private void WriteInterfaceDescription(string? name)
    {
        // options: if_name (2), if_tsresol (9) = 6 -> microseconds
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        if (!string.IsNullOrEmpty(name)) WriteOption(bw, 2, Encoding.UTF8.GetBytes(name));
        WriteOption(bw, 9, [6]);
        bw.Write((ushort)0); bw.Write((ushort)0);
        var opts = ms.ToArray();

        int len = 20 + opts.Length;
        _w.Write(1u);
        _w.Write(len);
        _w.Write((ushort)1); // LINKTYPE_ETHERNET
        _w.Write((ushort)0);
        _w.Write(262144); // snaplen
        _w.Write(opts);
        _w.Write(len);
    }

    public void WritePacket(DateTime timestampUtc, ReadOnlySpan<byte> data)
    {
        ulong us = (ulong)((timestampUtc - DateTime.UnixEpoch).Ticks / 10);
        int padded = (data.Length + 3) & ~3;
        int len = 32 + padded;
        _w.Write(6u);
        _w.Write(len);
        _w.Write(0u); // interface id
        _w.Write((uint)(us >> 32));
        _w.Write((uint)us);
        _w.Write(data.Length);
        _w.Write(data.Length);
        _w.Write(data);
        for (int i = data.Length; i < padded; i++) _w.Write((byte)0);
        _w.Write(len);
    }

    private static byte[] Options(params (ushort Code, string? Value)[] opts)
    {
        using var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        bool any = false;
        foreach (var (code, value) in opts)
        {
            if (string.IsNullOrEmpty(value)) continue;
            WriteOption(bw, code, Encoding.UTF8.GetBytes(value));
            any = true;
        }
        if (any) { bw.Write((ushort)0); bw.Write((ushort)0); }
        return ms.ToArray();
    }

    private static void WriteOption(BinaryWriter bw, ushort code, byte[] value)
    {
        bw.Write(code);
        bw.Write((ushort)value.Length);
        bw.Write(value);
        for (int i = value.Length; i % 4 != 0; i++) bw.Write((byte)0);
    }

    public void Dispose()
    {
        _w.Flush();
        _w.Dispose();
        _stream.Dispose();
    }
}
