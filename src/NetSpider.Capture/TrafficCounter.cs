using NetSpider.Core.Model;

namespace NetSpider.Capture;

/// <summary>Accumulates per-second traffic counters on the capture thread; <see cref="Snapshot"/> resets them.</summary>
public sealed class TrafficCounter
{
    private readonly object _sync = new();
    private long _total, _bcast, _mcast, _bytes;
    private Dictionary<string, long> _byProto = new();
    private Dictionary<Mac, TalkerAcc> _talkers = new();
    private DateTime _since = DateTime.UtcNow;

    private sealed class TalkerAcc { public long Pkts, Bcast, Mcast, Bytes; }

    public void Count(CapturedFrame f)
    {
        var e = f.Eth;
        if (!e.Valid) return;
        var proto = ProtocolName(f);
        lock (_sync)
        {
            _total++;
            _bytes += f.Data.Length;
            bool b = e.Destination.IsBroadcast, m = !b && e.Destination.IsMulticast;
            if (b) _bcast++; else if (m) _mcast++;
            _byProto[proto] = _byProto.GetValueOrDefault(proto) + 1;
            if (!_talkers.TryGetValue(e.Source, out var t)) _talkers[e.Source] = t = new TalkerAcc();
            t.Pkts++; t.Bytes += f.Data.Length;
            if (b) t.Bcast++; else if (m) t.Mcast++;
        }
    }

    public TrafficSnapshot Snapshot(long dropped, int topN = 15)
    {
        lock (_sync)
        {
            var now = DateTime.UtcNow;
            double secs = Math.Max(0.001, (now - _since).TotalSeconds);
            var talkers = _talkers
                .OrderByDescending(kv => kv.Value.Pkts)
                .Take(topN)
                .Select(kv => new TalkerStat(kv.Key, kv.Value.Pkts / secs, kv.Value.Bcast / secs, kv.Value.Mcast / secs, kv.Value.Bytes / secs))
                .ToList();
            var snap = new TrafficSnapshot(DateTimeOffset.Now, _total / secs, _bcast / secs, _mcast / secs, (_total - _bcast - _mcast) / secs,
                _bytes / secs, _byProto.ToDictionary(kv => kv.Key, kv => kv.Value / secs), talkers, dropped);
            _total = _bcast = _mcast = _bytes = 0;
            _byProto = new();
            _talkers = new();
            _since = now;
            return snap;
        }
    }

    /// <summary>Coarse protocol label used for traffic charts and packet-rain.</summary>
    public static string ProtocolName(CapturedFrame f)
    {
        var e = f.Eth;
        if (e.IsLlc)
        {
            if (e.IsStp || e.IsPvst) return "STP";
            if (e.IsCdp) return "CDP";
            if (e.IsVtp || e.IsDtp) return "VTP/DTP";
            return "LLC";
        }
        switch (e.EtherType)
        {
            case EthernetView.Arp: return "ARP";
            case EthernetView.Lldp: return "LLDP";
            case EthernetView.Eapol: return "EAPOL";
            case EthernetView.Slow: return "LACP";
            case EthernetView.WakeOnLan: return "WoL";
            case EthernetView.Ipv4: return Ipv4Proto(f.Payload);
            case EthernetView.Ipv6: return Ipv6Proto(f.Payload);
            default: return $"0x{e.EtherType:X4}";
        }
    }

    private static string Ipv4Proto(ReadOnlySpan<byte> p)
    {
        if (p.Length < 20) return "IPv4";
        int ihl = (p[0] & 0x0F) * 4;
        byte proto = p[9];
        if (proto == 1) return "ICMP";
        if (proto == 2) return "IGMP";
        if (proto == 6) return "TCP";
        if (proto == 17 && p.Length >= ihl + 4)
        {
            int sport = p[ihl] << 8 | p[ihl + 1], dport = p[ihl + 2] << 8 | p[ihl + 3];
            return UdpName(sport, dport);
        }
        return "IPv4";
    }

    private static string Ipv6Proto(ReadOnlySpan<byte> p)
    {
        if (p.Length < 40) return "IPv6";
        byte next = p[6];
        if (next == 58) return "ICMPv6";
        if (next == 6) return "TCP";
        if (next == 17 && p.Length >= 44) return UdpName(p[40] << 8 | p[41], p[42] << 8 | p[43]);
        return "IPv6";
    }

    private static string UdpName(int s, int d)
    {
        static string? N(int port) => port switch
        {
            53 => "DNS", 67 or 68 => "DHCP", 546 or 547 => "DHCPv6", 123 => "NTP", 137 or 138 => "NetBIOS", 161 or 162 => "SNMP",
            1900 => "SSDP", 5353 => "mDNS", 5355 => "LLMNR", 3702 => "WSD", 10001 => "Ubiquiti", 5678 => "MNDP",
            63321 or 63322 => "NSDP", 29808 or 29809 => "TP-Link", 514 => "Syslog", 5683 => "CoAP", 6666 or 6667 => "Tuya",
            _ => null,
        };
        return N(d) ?? N(s) ?? "UDP";
    }
}
