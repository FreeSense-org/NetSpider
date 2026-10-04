using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Storm;

/// <summary>Where a MAC enters the managed network: the edge switch port from the FDB.</summary>
public sealed record SourceLocation(Mac Switch, string SwitchName, string Port, int MacsOnPort, string Location);

/// <summary>
/// Maps MACs to switch ports through the SNMP FDB. When a MAC is learned on several switches, the port with the fewest
/// MACs is the edge (uplinks carry many). Port names come from the switch's ifName table when available. Topology links
/// name what sits behind the port (an inferred unmanaged switch, an AP, ...).
/// Build one per FDB/topology change; lookups are O(1).
/// </summary>
public sealed class StormLocator
{
    private readonly Dictionary<Mac, List<FdbEntry>> _byMac = new();
    private readonly Dictionary<(Mac Sw, string Port), HashSet<Mac>> _macsOnPort = new();
    private readonly Dictionary<(Mac Sw, int IfIndex), string> _portNames = new();
    private readonly IReadOnlyList<Link> _links;
    private readonly Func<Mac, string?> _name;

    public StormLocator(IReadOnlyList<FdbEntry> fdb, IReadOnlyList<SwitchPortInfo> ports, IReadOnlyList<Link> links, Func<Mac, string?> name)
    {
        _links = links;
        _name = name;
        foreach (var p in ports)
            if (!string.IsNullOrWhiteSpace(p.Name)) _portNames[(p.Switch, p.Index)] = p.Name;
        foreach (var e in fdb)
        {
            if (e.Mac.IsMulticast) continue;
            if (!_byMac.TryGetValue(e.Mac, out var list)) _byMac[e.Mac] = list = new();
            list.Add(e);
            var key = (e.Switch, PortName(e));
            if (!_macsOnPort.TryGetValue(key, out var set)) _macsOnPort[key] = set = new();
            set.Add(e.Mac);
        }
    }

    public static readonly StormLocator Empty = new([], [], [], _ => null);

    /// <summary>The switch's interface name for the entry (ifName via ifIndex), else the bridge port number.</summary>
    public string PortName(FdbEntry e) =>
        e.PortIndex is { } i && i > 0 && _portNames.TryGetValue((e.Switch, i), out var n) ? n : e.Port;

    public int MacsOnPort(Mac sw, string port) => _macsOnPort.TryGetValue((sw, port), out var s) ? s.Count : 0;

    public IReadOnlyCollection<Mac> MacsOn(Mac sw, string port) => _macsOnPort.TryGetValue((sw, port), out var s) ? s : [];

    public string SwitchName(Mac sw) => _name(sw) ?? sw.ToString();

    public SourceLocation? Locate(Mac mac)
    {
        if (!_byMac.TryGetValue(mac, out var entries) || entries.Count == 0) return null;
        // the edge: the switch port with the fewest learned MACs (ties: the switch with the fewest MAC-bearing ports of this MAC)
        var best = entries
            .Select(e => (Entry: e, Port: PortName(e), Count: MacsOnPort(e.Switch, PortName(e))))
            .OrderBy(x => x.Count)
            .ThenBy(x => x.Entry.Switch.Value)
            .First();
        var sw = best.Entry.Switch;
        string swName = SwitchName(sw);
        string text = $"{swName} port {best.Port}";
        string? behind = Behind(sw, best.Port, best.Entry.Port, mac);
        if (behind is not null) text += $" → behind {behind}";
        else if (best.Count > 1) text += $" (shared by {best.Count} MACs: unmanaged switch, AP or uplink)";
        return new SourceLocation(sw, swName, best.Port, best.Count, text);
    }

    /// <summary>Names the device on the far side of the port (inferred unmanaged switch first), unless it is the MAC itself.</summary>
    private string? Behind(Mac sw, string portName, string bridgePort, Mac source)
    {
        Link? found = null;
        foreach (var l in _links)
        {
            if (!l.Touches(sw)) continue;
            var p = l.PortOf(sw);
            if (p is null || !(string.Equals(p, portName, StringComparison.OrdinalIgnoreCase) || string.Equals(p, bridgePort, StringComparison.OrdinalIgnoreCase))) continue;
            var other = l.Other(sw);
            if (other == source) return null; // directly attached
            if (l.Kind == LinkKind.InferredUnmanagedSwitch) { found = l; break; }
            if (l.Kind is LinkKind.BridgeFdb or LinkKind.LldpCdp or LinkKind.WifiAssoc) found ??= l;
        }
        if (found is null) return null;
        var o = found.Other(sw);
        string name = _name(o) ?? o.ToString();
        return found.Kind == LinkKind.InferredUnmanagedSwitch ? $"inferred switch '{name}'" : $"'{name}'";
    }
}
