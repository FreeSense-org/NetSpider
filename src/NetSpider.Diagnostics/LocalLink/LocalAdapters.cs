using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetSpider.Capture;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.LocalLink;

/// <summary>Point-in-time view of one local NIC (what the link watcher diffs between polls).</summary>
public sealed record LocalLinkState(
    string Id, string Name, string Description, Mac Mac, bool Up, long SpeedMbps, bool IsWireless,
    IReadOnlyList<IpWithPrefix> IPv4, IPAddress? Gateway)
{
    public bool HasApipa => IPv4.Any(a => LocalAdapters.IsApipa(a.Address));
    public bool HasRoutableV4 => IPv4.Any(a => !LocalAdapters.IsApipa(a.Address));
}

/// <summary>Adapter selection and snapshots from <see cref="NetworkInterface"/> (works without packet capture).</summary>
public static class LocalAdapters
{
    public static bool IsApipa(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 169 && b[1] == 254;
    }

    public static string NormalizeId(string id) => id.Trim('{', '}').ToUpperInvariant();

    public static bool IsVirtual(NetworkInterface nic) =>
        nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp ||
        AdapterCatalog.ClassifyVirtual(nic.Description + " " + nic.Name) is not null;

    public static NetworkInterface[] All()
    {
        try { return NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return []; }
    }

    public static NetworkInterface? FindById(string id)
    {
        var want = NormalizeId(id);
        return All().FirstOrDefault(n => NormalizeId(n.Id) == want);
    }

    /// <summary>Best physical adapter: up, has an IPv4 gateway, not virtual; wired preferred over wireless.</summary>
    public static NetworkInterface? FindBest()
    {
        var candidates = All().Where(n => !IsVirtual(n)).Select(n => (Nic: n, State: Snapshot(n))).Where(x => x.State is not null).ToList();
        return candidates
            .OrderByDescending(x => x.State!.Up)
            .ThenByDescending(x => x.State!.Gateway is not null)
            .ThenByDescending(x => x.State!.HasRoutableV4)
            .ThenBy(x => x.State!.IsWireless)
            .Select(x => x.Nic)
            .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up);
    }

    public static LocalLinkState? Snapshot(NetworkInterface nic)
    {
        try
        {
            var v4 = new List<IpWithPrefix>();
            IPAddress? gw = null;
            try
            {
                var props = nic.GetIPProperties();
                foreach (var u in props.UnicastAddresses)
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork) v4.Add(new IpWithPrefix(u.Address, u.PrefixLength));
                gw = props.GatewayAddresses.Select(g => g.Address)
                    .FirstOrDefault(g => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any));
            }
            catch { /* adapter vanished mid-query */ }
            Mac mac = Mac.Zero;
            try
            {
                var pa = nic.GetPhysicalAddress().GetAddressBytes();
                if (pa.Length == 6) mac = Mac.FromBytes(pa);
            }
            catch { }
            long speed = 0;
            try { speed = Math.Max(0, nic.Speed / 1_000_000); } catch { }
            return new LocalLinkState(NormalizeId(nic.Id), nic.Name, nic.Description, mac, nic.OperationalStatus == OperationalStatus.Up, speed,
                nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211, v4, gw);
        }
        catch { return null; }
    }

    /// <summary>An <see cref="AdapterInfo"/> built from a NIC when capture is not running (no Npcap device name).</summary>
    public static AdapterInfo? ToAdapterInfo(NetworkInterface? nic)
    {
        if (nic is null || Snapshot(nic) is not { } s) return null;
        return new AdapterInfo
        {
            Id = s.Id,
            PcapName = "",
            Name = s.Name,
            Description = s.Description,
            Mac = s.Mac,
            IPv4 = s.IPv4,
            GatewayV4 = s.Gateway,
            SpeedMbps = s.SpeedMbps,
            IsUp = s.Up,
            IsWireless = s.IsWireless,
            IsVirtual = false,
        };
    }
}
