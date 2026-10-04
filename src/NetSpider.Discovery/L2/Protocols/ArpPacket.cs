using System.Buffers.Binary;
using System.Net;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2.Protocols;

/// <summary>Ethernet/IPv4 ARP packet (RFC 826).</summary>
public sealed record ArpPacket(ushort Op, Mac SenderMac, IPAddress SenderIp, Mac TargetMac, IPAddress TargetIp)
{
    public const ushort Request = 1, Reply = 2;

    /// <summary>Gratuitous ARP: sender IP equals target IP (announcement).</summary>
    public bool IsGratuitous => SenderIp.Equals(TargetIp);
    /// <summary>ARP probe (RFC 5227): sender IP 0.0.0.0, used for duplicate-address detection.</summary>
    public bool IsProbe => SenderIp.Equals(IPAddress.Any);

    /// <param name="p">Ethernet payload (after the EtherType / VLAN tags).</param>
    public static ArpPacket? Parse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 28) return null;
        if (BinaryPrimitives.ReadUInt16BigEndian(p) != 1 || BinaryPrimitives.ReadUInt16BigEndian(p[2..]) != 0x0800 || p[4] != 6 || p[5] != 4) return null;
        return new ArpPacket(
            BinaryPrimitives.ReadUInt16BigEndian(p[6..]),
            Mac.FromBytes(p.Slice(8, 6)), new IPAddress(p.Slice(14, 4)),
            Mac.FromBytes(p.Slice(18, 6)), new IPAddress(p.Slice(24, 4)));
    }

    /// <summary>Cheap pre-check without allocation: op code and target IP of an ARP payload.</summary>
    public static bool TryPeek(ReadOnlySpan<byte> p, out ushort op, out uint senderIp, out uint targetIp)
    {
        op = 0; senderIp = targetIp = 0;
        if (p.Length < 28 || p[4] != 6 || p[5] != 4) return false;
        op = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
        senderIp = BinaryPrimitives.ReadUInt32BigEndian(p[14..]);
        targetIp = BinaryPrimitives.ReadUInt32BigEndian(p[24..]);
        return true;
    }
}
