using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

public sealed record ClasslessRoute(IPAddress Network, int PrefixLength, IPAddress Router)
{
    public override string ToString() => $"{Network}/{PrefixLength} via {Router}";
}

/// <summary>Decoded BOOTP/DHCPv4 message (RFC 2131/2132).</summary>
public sealed class DhcpPacket
{
    public const byte Discover = 1, Offer = 2, Request = 3, Decline = 4, Ack = 5, Nak = 6, Release = 7, Inform = 8;
    public const uint MagicCookie = 0x63825363;

    public byte Op { get; init; }
    public uint Xid { get; init; }
    public ushort Flags { get; init; }
    public bool Broadcast => (Flags & 0x8000) != 0;
    public required IPAddress ClientIp { get; init; }
    public required IPAddress YourIp { get; init; }
    public required IPAddress ServerIpField { get; init; }
    public required IPAddress RelayIp { get; init; }
    public Mac ClientMac { get; init; }

    /// <summary>Options by code (repeated options concatenated per RFC 3396).</summary>
    public Dictionary<byte, byte[]> Options { get; } = new();
    /// <summary>Option codes in the order the client sent them (a fingerprint signal in itself).</summary>
    public List<byte> OptionOrder { get; } = [];

    public bool IsBootRequest => Op == 1;
    public byte? MessageType => Opt(53) is { Length: >= 1 } b ? b[0] : null;
    public string MessageTypeName => MessageType switch
    {
        Discover => "DISCOVER", Offer => "OFFER", Request => "REQUEST", Decline => "DECLINE", Ack => "ACK",
        Nak => "NAK", Release => "RELEASE", Inform => "INFORM", null => "BOOTP", { } t => $"type {t}",
    };

    public byte[]? Opt(byte code) => Options.TryGetValue(code, out var v) ? v : null;

    public byte[]? ParameterRequestList => Opt(55);
    /// <summary>Option 55 as a comma-joined list, the classic DHCP fingerprint ("1,3,6,15,31,33,43,44,46,47,119,121,249,252").</summary>
    public string? Fingerprint => ParameterRequestList is { Length: > 0 } l ? string.Join(",", l) : null;
    public string? VendorClass => Str(60);
    public string? Hostname => Str(12);
    public string? DomainName => Str(15);
    public IPAddress? RequestedIp => Ip(50);
    public IPAddress? ServerIdentifier => Ip(54);
    public IPAddress? SubnetMask => Ip(1);
    public IReadOnlyList<IPAddress> Routers => Ips(3);
    public IReadOnlyList<IPAddress> DnsServers => Ips(6);
    public TimeSpan? LeaseTime => Opt(51) is { Length: >= 4 } b ? TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(b)) : null;
    public int? MaxMessageSize => Opt(57) is { Length: >= 2 } b ? BinaryPrimitives.ReadUInt16BigEndian(b) : null;
    public string? ClientIdentifier => Opt(61) is { Length: > 0 } b ? TextUtil.Hex(b) : null;
    public string? UserClass => Opt(77) is { Length: > 0 } b ? TextUtil.Str(b) : null;

    /// <summary>Option 81 client FQDN: flags, rcode1, rcode2, then ASCII or DNS wire-format name (E flag).</summary>
    public string? ClientFqdn
    {
        get
        {
            var b = Opt(81);
            if (b is null || b.Length <= 3) return null;
            var name = b.AsSpan(3);
            if ((b[0] & 0x04) == 0) return TextUtil.Str(name);
            var sb = new StringBuilder();
            int i = 0;
            while (i < name.Length && name[i] != 0)
            {
                int l = name[i++];
                if (i + l > name.Length) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(name.Slice(i, l)));
                i += l;
            }
            return sb.Length == 0 ? null : sb.ToString();
        }
    }

    /// <summary>Option 121 (RFC 3442), falling back to Microsoft's option 249.</summary>
    public IReadOnlyList<ClasslessRoute> ClasslessRoutes => ParseClasslessRoutes(Opt(121) ?? Opt(249));

    public static IReadOnlyList<ClasslessRoute> ParseClasslessRoutes(byte[]? b)
    {
        var list = new List<ClasslessRoute>();
        if (b is null) return list;
        int i = 0;
        while (i < b.Length)
        {
            int width = b[i++];
            if (width > 32) break;
            int sig = (width + 7) / 8;
            if (i + sig + 4 > b.Length) break;
            var net = new byte[4];
            Array.Copy(b, i, net, 0, sig);
            i += sig;
            var router = new IPAddress(b.AsSpan(i, 4));
            i += 4;
            list.Add(new ClasslessRoute(new IPAddress(net), width, router));
        }
        return list;
    }

    private string? Str(byte code) => Opt(code) is { } b ? TextUtil.Str(b) : null;
    private IPAddress? Ip(byte code) => Opt(code) is { Length: >= 4 } b ? new IPAddress(b.AsSpan(0, 4)) : null;
    private IReadOnlyList<IPAddress> Ips(byte code)
    {
        var b = Opt(code);
        if (b is null) return [];
        var r = new List<IPAddress>(b.Length / 4);
        for (int i = 0; i + 4 <= b.Length; i += 4) r.Add(new IPAddress(b.AsSpan(i, 4)));
        return r;
    }

    /// <param name="p">UDP payload.</param>
    public static DhcpPacket? Parse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 240 || p[0] is not (1 or 2) || p[1] != 1 || p[2] != 6) return null;
        if (BinaryPrimitives.ReadUInt32BigEndian(p[236..]) != MagicCookie) return null;
        var pkt = new DhcpPacket
        {
            Op = p[0],
            Xid = BinaryPrimitives.ReadUInt32BigEndian(p[4..]),
            Flags = BinaryPrimitives.ReadUInt16BigEndian(p[10..]),
            ClientIp = new IPAddress(p.Slice(12, 4)),
            YourIp = new IPAddress(p.Slice(16, 4)),
            ServerIpField = new IPAddress(p.Slice(20, 4)),
            RelayIp = new IPAddress(p.Slice(24, 4)),
            ClientMac = Mac.FromBytes(p.Slice(28, 6)),
        };
        int off = 240;
        while (off < p.Length)
        {
            byte code = p[off++];
            if (code == 0) continue;
            if (code == 255) break;
            if (off >= p.Length) break;
            int len = p[off++];
            if (off + len > p.Length) break;
            var v = p.Slice(off, len).ToArray();
            off += len;
            if (pkt.Options.TryGetValue(code, out var prev)) pkt.Options[code] = [.. prev, .. v];
            else { pkt.Options[code] = v; pkt.OptionOrder.Add(code); }
        }
        return pkt;
    }
}

/// <summary>Builds DHCP client messages for active probing. Only DISCOVER is ever built: we never take a lease.</summary>
public static class DhcpBuilder
{
    /// <summary>Parameters requested in our DISCOVER (incl. 121/249 classless routes).</summary>
    public static readonly byte[] DefaultParameters = [1, 3, 6, 15, 28, 42, 44, 51, 54, 58, 59, 119, 121, 249, 252];

    /// <summary>BOOTP payload for a DHCPDISCOVER with the broadcast flag set.</summary>
    public static byte[] Discover(Mac clientMac, uint xid, IReadOnlyList<byte>? parameters = null, string? hostname = null)
    {
        var buf = new byte[300];
        buf[0] = 1; buf[1] = 1; buf[2] = 6; buf[3] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4), xid);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(10), 0x8000); // broadcast flag: replies go to ff:ff:ff:ff:ff:ff
        clientMac.WriteTo(buf.AsSpan(28));
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(236), DhcpPacket.MagicCookie);
        int o = 240;
        buf[o++] = 53; buf[o++] = 1; buf[o++] = DhcpPacket.Discover;
        buf[o++] = 61; buf[o++] = 7; buf[o++] = 1; clientMac.WriteTo(buf.AsSpan(o)); o += 6;
        var prl = parameters ?? DefaultParameters;
        buf[o++] = 55; buf[o++] = (byte)prl.Count;
        foreach (var b in prl) buf[o++] = b;
        if (!string.IsNullOrEmpty(hostname))
        {
            var h = Encoding.ASCII.GetBytes(hostname.Length > 32 ? hostname[..32] : hostname);
            buf[o++] = 12; buf[o++] = (byte)h.Length;
            h.CopyTo(buf.AsSpan(o)); o += h.Length;
        }
        buf[o++] = 255;
        return buf;
    }

    /// <summary>Complete Ethernet frame: 0.0.0.0:68 → 255.255.255.255:67, optionally 802.1Q tagged.</summary>
    public static byte[] DiscoverFrame(Mac clientMac, uint xid, int? vlanId = null) =>
        FrameBuilder.Udp4(clientMac, Mac.Broadcast, IPAddress.Any, IPAddress.Broadcast, 68, 67, Discover(clientMac, xid), ttl: 64, vlanId: vlanId);

    /// <summary>Extracts a DHCP message from an Ethernet frame's IPv4/UDP 67/68 payload.</summary>
    public static bool TryExtract(CapturedFrame frame, out DhcpPacket packet, out IpView ip, out IPAddress srcIp)
    {
        packet = null!; ip = default; srcIp = IPAddress.None;
        if (frame.Eth.EtherType != EthernetView.Ipv4) return false;
        var payload = frame.Payload;
        if (!IpView.TryParse(payload, EthernetView.Ipv4, out ip) || ip.Protocol != IpView.Udp || !ip.FirstFragment) return false;
        var l4 = ip.L4(payload);
        if (!UdpView.TryParse(l4, out var udp)) return false;
        bool dhcpPorts = (udp.SourcePort == 68 && udp.DestinationPort == 67) || (udp.SourcePort == 67 && udp.DestinationPort == 68) ||
                         (udp.SourcePort == 67 && udp.DestinationPort == 67);
        if (!dhcpPorts) return false;
        var p = Parse(l4.Slice(udp.PayloadOffset, udp.PayloadLength));
        if (p is null) return false;
        packet = p;
        srcIp = ip.Source(payload);
        return true;
    }

    private static DhcpPacket? Parse(ReadOnlySpan<byte> b) => DhcpPacket.Parse(b);
}
