using System.Net;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive ARP observer. Learns every ARP sender (requests, replies, gratuitous announcements) and detects:
/// <list type="bullet">
/// <item>an IP claimed by a second, live MAC → <see cref="AlertKind.DuplicateIp"/> (Warning) and <see cref="DeviceFlags.IpConflict"/>;</item>
/// <item>an IP flipping back and forth between MACs → <see cref="AlertKind.ArpSpoofing"/>;</item>
/// <item>the gateway IP changing MAC → <see cref="AlertKind.GatewayMacChanged"/> (Critical).</item>
/// </list>
/// A change is treated as a benign DHCP re-lease when the previous owner has not been seen for more than 5 minutes.
/// First-hop-redundancy virtual MACs (VRRP/HSRP/GLBP) are exempt.
/// </summary>
public sealed class ArpWatcher : IFrameHandler
{
    public static readonly TimeSpan StaleOwner = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FlipWindow = TimeSpan.FromMinutes(2);

    private readonly ILogger<ArpWatcher> _log;
    private readonly IDeviceStore _store;
    private readonly IAlertService _alerts;
    private readonly DiscoveryContext _ctx;
    private readonly ActivityPublisher _activity;
    private readonly Dictionary<IPAddress, (Mac From, Mac To, DateTimeOffset When, int Flips)> _changes = new();

    public ArpWatcher(ILogger<ArpWatcher> log, IDeviceStore store, IAlertService alerts, DiscoveryContext ctx, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _alerts = alerts;
        _ctx = ctx;
        _activity = activity;
    }

    /// <summary>Raised for every IP→MAC change that was judged suspicious (ip, old MAC, new MAC).</summary>
    public event Action<IPAddress, Mac, Mac>? IpMacChanged;

    public void OnFrame(CapturedFrame frame)
    {
        if (frame.Eth.EtherType != EthernetView.Arp || frame.IsOutbound) return;
        try
        {
            var arp = ArpPacket.Parse(frame.Payload);
            if (arp is null || arp.SenderMac.IsZero || arp.SenderMac.IsMulticast) return;
            _activity.Publish(arp.SenderMac, "ARP");
            if (arp.IsProbe) { _store.Observe(arp.SenderMac, null, "arp"); return; }
            Process(arp, frame.Eth.Source);
        }
        catch (Exception ex) { _log.LogDebug(ex, "ArpWatcher"); }
    }

    internal void Process(ArpPacket arp, Mac ethSource)
    {
        var ip = arp.SenderIp;
        var mac = arp.SenderMac;
        var now = DateTimeOffset.Now;
        var gateway = _ctx.Gateway;
        bool isGateway = gateway is not null && gateway.Equals(ip);

        var prev = _store.FindByIp(ip);
        if (prev is not null && prev.Mac != mac && !SyntheticNodes.IsSynthetic(prev.Mac) && prev.HasIp(ip)
            && (prev.Has(DeviceFlags.ThisHost) || now - prev.LastSeen <= StaleOwner) && !IsFhrpVirtual(prev.Mac) && !IsFhrpVirtual(mac))
        {
            OnConflict(ip, prev, mac, isGateway, arp.IsGratuitous, now);
        }

        var dev = _store.Observe(mac, ip, "arp");
        bool changed = false;
        if (ethSource != mac) changed |= dev.SetProperty("arp.proxyVia", ethSource.ToString());
        if (arp.IsGratuitous) changed |= dev.SetProperty("arp.gratuitous", "seen");
        if (isGateway && !dev.Has(DeviceFlags.Gateway))
        {
            dev.SetFlag(DeviceFlags.Gateway);
            DeviceHints.HintType(dev, "arp", DeviceType.Router, 0.6);
            changed = true;
        }
        if (changed) _store.NotifyChanged(dev, "arp");
    }

    private void OnConflict(IPAddress ip, Device prev, Mac newMac, bool isGateway, bool gratuitous, DateTimeOffset now)
    {
        int flips = 1;
        lock (_changes)
        {
            if (_changes.TryGetValue(ip, out var c) && now - c.When < FlipWindow && c.From == newMac && c.To == prev.Mac) flips = c.Flips + 1;
            _changes[ip] = (prev.Mac, newMac, now, flips);
            if (_changes.Count > 10_000) _changes.Clear();
        }

        var newDev = _store.GetOrAdd(newMac);
        prev.SetFlag(DeviceFlags.IpConflict);
        newDev.SetFlag(DeviceFlags.IpConflict);
        _store.NotifyChanged(prev, "ip-conflict");
        _store.NotifyChanged(newDev, "ip-conflict");
        IpMacChanged?.Invoke(ip, prev.Mac, newMac);

        if (isGateway)
        {
            prev.SetFlag(DeviceFlags.Gateway, false);
            _alerts.Raise(Alert.Create(AlertSeverity.Critical, AlertKind.GatewayMacChanged,
                $"Gateway {ip} changed MAC address",
                $"The default gateway {ip} was answered by {newMac} but was {prev.Mac} ({prev.DisplayName}) moments ago. " +
                "This is the classic signature of ARP spoofing / man-in-the-middle, unless the router was just replaced or failed over.",
                newMac));
        }

        if (flips >= 2 || isGateway)
        {
            _alerts.Raise(Alert.Create(isGateway ? AlertSeverity.Critical : AlertSeverity.Warning, AlertKind.ArpSpoofing,
                $"Possible ARP spoofing of {ip}",
                $"{ip} is being claimed alternately by {prev.Mac} and {newMac}{(gratuitous ? " (gratuitous ARP)" : "")}; " +
                $"{flips} flips within {FlipWindow.TotalMinutes:0} min.",
                newMac));
        }
        else
        {
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.DuplicateIp,
                $"IP address conflict on {ip}",
                $"{ip} is used by {prev.Mac} ({prev.DisplayName}) and {newMac}.",
                newMac));
        }
    }

    /// <summary>VRRP 00:00:5E:00:01/02:xx, HSRP 00:00:0C:07:AC:xx / 00:00:0C:9F:Fx:xx, GLBP 00:07:B4:00:xx:xx.</summary>
    public static bool IsFhrpVirtual(Mac m)
    {
        ulong v = m.Value;
        return (v >> 8) == 0x00005E0001 || (v >> 8) == 0x00005E0002 || (v >> 8) == 0x00000C07AC
               || (v >> 12) == 0x00000C9FF || (v >> 16) == 0x0007B400;
    }
}
