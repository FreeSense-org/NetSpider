using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.NetBios;

/// <summary>Sends an NBSTAT (node status, name *<00>) query to UDP/137 and parses the returned NetBIOS name table.</summary>
public sealed class NetBiosProbe : IDeviceProbe
{
    private const string Source = "netbios";
    private readonly IDeviceStore _store;
    private readonly ILogger<NetBiosProbe> _log;

    public NetBiosProbe(IDeviceStore store, ILogger<NetBiosProbe> log) { _store = store; _log = log; }

    public string Name => "NetBIOS NBSTAT";
    public int Order => 230;

    public bool AppliesTo(Device device, ScanContext ctx) => device.IPv4.Length > 0;

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        try
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            var query = BuildNbstatQuery();
            await udp.SendToAsync(query, SocketFlags.None, new IPEndPoint(ip, 137), ct).ConfigureAwait(false);

            var buf = new byte[2048];
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(600);
            var from = new IPEndPoint(IPAddress.Any, 0);
            var r = await udp.ReceiveFromAsync(buf, SocketFlags.None, from, timeoutCts.Token).ConfigureAwait(false);
            if (r.ReceivedBytes <= 0) return;

            if (Parse(buf.AsSpan(0, r.ReceivedBytes), device)) _store.NotifyChanged(device, Source);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "NBSTAT {Ip}", ip); }
    }

    /// <summary>NBSTAT request: header + encoded name "*" (type 0x00) + NBSTAT(0x21)/IN(0x0001).</summary>
    public static byte[] BuildNbstatQuery()
    {
        var buf = new byte[50];
        BinaryPrimitives.WriteUInt16BigEndian(buf, 0x4E53);   // txn id
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), 0x0010); // broadcast flag (standard query)
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), 1);      // QDCOUNT
        int o = 12;
        buf[o++] = 0x20; // encoded name length (32)
        // "*" + 15 nulls, first-level encoded (each nibble + 'A')
        Span<byte> name = stackalloc byte[16];
        name[0] = (byte)'*';
        for (int i = 0; i < 16; i++) { buf[o++] = (byte)('A' + (name[i] >> 4)); buf[o++] = (byte)('A' + (name[i] & 0x0F)); }
        buf[o++] = 0x00; // root label
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), 0x0021); o += 2; // NBSTAT
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), 0x0001); o += 2; // IN
        return buf[..o];
    }

    /// <summary>Parses an NBSTAT response: name table (computer/workgroup) plus the unit's MAC in the statistics block.</summary>
    public static bool Parse(ReadOnlySpan<byte> data, Device device)
    {
        if (data.Length < 57) return false;
        // Header (12). NBSTAT responses normally carry no question (QDCOUNT=0); skip any that are present.
        int qdCount = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
        int anCount = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
        if (anCount == 0) return false;
        int pos = 12;
        for (int q = 0; q < qdCount && pos < data.Length; q++) pos = SkipName(data, pos) + 4;
        if (pos >= data.Length) return false;
        // answer: name, type(2), class(2), ttl(4), rdlen(2), rdata
        pos = SkipName(data, pos);
        if (pos + 10 > data.Length) return false;
        pos += 8; // type+class+ttl
        int rdlen = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]); pos += 2;
        if (pos >= data.Length) return false;
        int numNames = data[pos++];
        bool changed = false;
        string? workgroup = null; string? computer = null;
        for (int i = 0; i < numNames && pos + 18 <= data.Length; i++)
        {
            var nameBytes = data.Slice(pos, 15);
            byte suffix = data[pos + 15];
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 16)..]);
            pos += 18;
            bool group = (flags & 0x8000) != 0;
            var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd(' ', '\0');
            if (string.IsNullOrWhiteSpace(name) || name.Any(c => c < 0x20 || c > 0x7E)) continue;
            if (suffix == 0x00 && !group) computer ??= name;
            else if ((suffix == 0x00 && group) || suffix == 0x1E) workgroup ??= name;
            else if (suffix == 0x20 && !group) computer ??= name; // file server service
        }
        if (computer is not null) changed |= device.SetHostname(Source, computer);
        if (workgroup is not null)
        {
            changed |= device.AddEvidence(Source, Fields.Domain, workgroup, Confidence.NetBios);
            changed |= device.SetProperty("netbios.workgroup", workgroup);
        }
        // the adapter MAC follows the name list (6 bytes at the start of the statistics block)
        if (pos + 6 <= data.Length)
        {
            var mac = Mac.FromBytes(data.Slice(pos, 6));
            if (!mac.IsZero) changed |= device.SetProperty("netbios.mac", mac.ToString());
        }
        return changed;
    }

    private static int SkipName(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length)
        {
            byte len = data[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;
            pos += len + 1;
        }
        return pos;
    }
}
