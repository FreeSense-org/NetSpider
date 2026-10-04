using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive IGMP (v1/v2/v3) and MLD (v1/v2) listener. Membership reports add multicast groups to the reporting device
/// (flag <see cref="DeviceFlags.MulticastSource"/>), leave/done messages remove them, and queries identify the
/// IGMP/MLD querier (<see cref="INetworkState.IgmpQuerier"/>, flag <see cref="DeviceFlags.IgmpQuerier"/>).
/// </summary>
public sealed class IgmpMonitor : IFrameHandler
{
    private readonly ILogger<IgmpMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly ActivityPublisher _activity;
    private long _firstFrameTicks;
    private long _lastQueryTicks;

    public IgmpMonitor(ILogger<IgmpMonitor> log, IDeviceStore store, INetworkState network, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _network = network;
        _activity = activity;
    }

    /// <summary>How long frames have been flowing through this handler.</summary>
    public TimeSpan ObservedFor
    {
        get
        {
            long first = Interlocked.Read(ref _firstFrameTicks);
            return first == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(Environment.TickCount64 - first);
        }
    }

    /// <summary>Time since the last IGMP/MLD query from another device, or null if none was seen.</summary>
    public TimeSpan? SinceLastQuery
    {
        get
        {
            long q = Interlocked.Read(ref _lastQueryTicks);
            return q == 0 ? null : TimeSpan.FromMilliseconds(Environment.TickCount64 - q);
        }
    }

    public void OnFrame(CapturedFrame frame)
    {
        if (Interlocked.Read(ref _firstFrameTicks) == 0) Interlocked.CompareExchange(ref _firstFrameTicks, Environment.TickCount64, 0);
        if (frame.IsOutbound) return; // our own query must not count as a querier
        var eth = frame.Eth;
        if (eth.EtherType != EthernetView.Ipv4 && eth.EtherType != EthernetView.Ipv6) return;
        try
        {
            var p = frame.Payload;
            if (!IpView.TryParse(p, eth.EtherType, out var ip) || !ip.FirstFragment) return;
            GroupMessage? msg = null;
            if (ip.IsV4 && ip.Protocol == IpView.Igmp) msg = IgmpParser.ParseIgmp(ip.L4(p));
            else if (!ip.IsV4 && ip.Protocol == IpView.Icmp6)
            {
                var icmp = ip.L4(p);
                if (icmp.Length > 0 && icmp[0] is 130 or 131 or 132 or 143) msg = IgmpParser.ParseMld(icmp);
            }
            if (msg is null) return;
            Apply(msg, eth.Source, ip.Source(p));
        }
        catch (Exception ex) { _log.LogDebug(ex, "IGMP/MLD frame from {Mac}", eth.Source); }
    }

    internal Device? Apply(GroupMessage msg, Mac src, IPAddress srcIp)
    {
        if (src.IsMulticast || src.IsZero) return null;
        _activity.Publish(src, msg.Protocol);
        var addr = srcIp.Equals(IPAddress.Any) || srcIp.Equals(IPAddress.IPv6Any) ? null : srcIp;
        var d = _store.Observe(src, addr, msg.Protocol.ToLowerInvariant());
        bool ch = false;

        if (msg.Kind == GroupMessageKind.Query)
        {
            Interlocked.Exchange(ref _lastQueryTicks, Environment.TickCount64);
            if (_network.IgmpQuerier != src) _network.IgmpQuerier = src;
            if (!d.Has(DeviceFlags.IgmpQuerier)) { d.SetFlag(DeviceFlags.IgmpQuerier); ch = true; }
            ch |= d.SetProperty($"{msg.Protocol.ToLowerInvariant()}.querier", $"{msg.Protocol}v{msg.Version}{(addr is null ? " (0.0.0.0 snooping querier)" : "")}");
        }
        else
        {
            foreach (var g in msg.Joined)
            {
                if (IsNoiseGroup(g)) continue;
                ch |= d.AddMulticastGroup(g);
            }
            foreach (var g in msg.Left) ch |= d.RemoveMulticastGroup(g);
            if (msg.Joined.Any(g => !IsNoiseGroup(g)) && !d.Has(DeviceFlags.MulticastSource)) { d.SetFlag(DeviceFlags.MulticastSource); ch = true; }
            if (d.MulticastGroups.Length == 0 && d.Has(DeviceFlags.MulticastSource)) { d.SetFlag(DeviceFlags.MulticastSource, false); ch = true; }
            ch |= d.SetProperty($"{msg.Protocol.ToLowerInvariant()}.version", msg.Version.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        if (ch) _store.NotifyChanged(d, "multicast");
        return d;
    }

    /// <summary>All-hosts groups and IPv6 solicited-node groups (every IPv6 host joins one per address) are not interesting.</summary>
    public static bool IsNoiseGroup(IPAddress g)
    {
        var b = g.GetAddressBytes();
        if (b.Length == 4) return b[0] == 224 && b[1] == 0 && b[2] == 0 && b[3] is 1 or 2;
        if (b[0] == 0xFF && b[1] == 0x02 && BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(2)) == 0 && b[10] == 0 && b[11] == 0x01 && b[12] == 0xFF) return true;
        return b[0] == 0xFF && b[1] == 0x02 && b.AsSpan(2, 13).IndexOfAnyExcept((byte)0) < 0 && b[15] is 1 or 2;
    }
}
