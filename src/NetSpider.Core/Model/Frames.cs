using System.Buffers.Binary;

namespace NetSpider.Core.Model;

/// <summary>A captured Ethernet frame. <see cref="Data"/> is owned by the frame; do not keep references after the handler returns unless copied.</summary>
public sealed class CapturedFrame
{
    public CapturedFrame(byte[] data, DateTime timestampUtc, long arrivalTicks, bool isOutbound)
    {
        Data = data;
        TimestampUtc = timestampUtc;
        ArrivalTicks = arrivalTicks;
        IsOutbound = isOutbound;
        Eth = EthernetView.Parse(data);
    }

    public byte[] Data { get; }
    /// <summary>Npcap timestamp (HOST_HIPREC when available), microsecond resolution.</summary>
    public DateTime TimestampUtc { get; }
    /// <summary><see cref="System.Diagnostics.Stopwatch.GetTimestamp"/> when the frame was dequeued by the capture thread.</summary>
    public long ArrivalTicks { get; }
    /// <summary>true when the frame was sent by this host (Npcap loops back injected frames).</summary>
    public bool IsOutbound { get; }
    public EthernetView Eth { get; }

    public ReadOnlySpan<byte> Payload => Data.AsSpan(Eth.PayloadOffset);
}

/// <summary>Parsed Ethernet II / 802.3 header, including up to two 802.1Q/802.1ad tags.</summary>
public readonly record struct EthernetView(Mac Destination, Mac Source, ushort EtherType, int? VlanId, int? OuterVlanId, int Priority, int PayloadOffset, bool IsLlc, bool Valid)
{
    public const ushort Ipv4 = 0x0800, Arp = 0x0806, Ipv6 = 0x86DD, Vlan = 0x8100, QinQ = 0x88A8, Lldp = 0x88CC, WakeOnLan = 0x0842,
        Eapol = 0x888E, Slow = 0x8809 /* LACP */, Mndp = 0x88B5;

    /// <summary>For 802.3 LLC frames the EtherType is replaced by the DSAP/SSAP/SNAP information:</summary>
    public byte LlcDsap { get; init; }
    public byte LlcSsap { get; init; }
    /// <summary>SNAP OUI and protocol id (e.g. Cisco 00000C / 2000 for CDP).</summary>
    public uint SnapOui { get; init; }
    public ushort SnapPid { get; init; }

    public static EthernetView Parse(ReadOnlySpan<byte> d)
    {
        if (d.Length < 14) return default;
        var dst = Mac.FromBytes(d[..6]);
        var src = Mac.FromBytes(d.Slice(6, 6));
        int off = 12;
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(d[off..]);
        int? vlan = null, outer = null; int prio = 0;
        int tags = 0;
        while ((type == Vlan || type == QinQ) && d.Length >= off + 6 && tags < 2)
        {
            ushort tci = BinaryPrimitives.ReadUInt16BigEndian(d[(off + 2)..]);
            if (vlan is not null) outer = vlan;
            vlan = tci & 0x0FFF;
            prio = tci >> 13;
            off += 4;
            type = BinaryPrimitives.ReadUInt16BigEndian(d[off..]);
            tags++;
        }
        off += 2;
        if (type <= 1500)
        {
            // IEEE 802.3 length field -> LLC
            if (d.Length < off + 3) return new EthernetView(dst, src, type, vlan, outer, prio, off, true, true);
            byte dsap = d[off], ssap = d[off + 1];
            uint oui = 0; ushort pid = 0;
            int llcLen = 3;
            if (dsap == 0xAA && ssap == 0xAA && d.Length >= off + 8)
            {
                oui = (uint)(d[off + 3] << 16 | d[off + 4] << 8 | d[off + 5]);
                pid = BinaryPrimitives.ReadUInt16BigEndian(d[(off + 6)..]);
                llcLen = 8;
            }
            return new EthernetView(dst, src, type, vlan, outer, prio, off + llcLen, true, true) { LlcDsap = dsap, LlcSsap = ssap, SnapOui = oui, SnapPid = pid };
        }
        return new EthernetView(dst, src, type, vlan, outer, prio, off, false, true);
    }

    public bool IsStp => IsLlc && LlcDsap == 0x42 && LlcSsap == 0x42;
    public bool IsCdp => IsLlc && SnapOui == 0x00000C && SnapPid == 0x2000;
    public bool IsVtp => IsLlc && SnapOui == 0x00000C && SnapPid == 0x2003;
    public bool IsDtp => IsLlc && SnapOui == 0x00000C && SnapPid == 0x2004;
    public bool IsPvst => IsLlc && SnapOui == 0x00000C && SnapPid == 0x010B;
}
