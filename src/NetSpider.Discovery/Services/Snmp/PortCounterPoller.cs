using Lextm.SharpSnmpLib;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>One poll of a device's physical ports. <see cref="SysUpTime"/> is used to detect agent reboots.</summary>
public sealed record PortCounterPoll(TimeSpan? SysUpTime, IReadOnlyList<PortCounterSample> Samples);

/// <summary>
/// Reads IF-MIB (ifTable/ifXTable) and EtherLike-MIB (dot3StatsTable) counters for the physical Ethernet ports of one
/// SNMP agent. Uses bulk walks per column (plain walks on v1), 64-bit HC counters with a fallback to 32-bit columns,
/// and skips VLAN/loopback/CPU/tunnel interfaces by ifType and name.
/// </summary>
internal static class PortCounterPoller
{
    /// <summary>ethernetCsmacd(6), iso88023Csmacd(7), fastEther(62), fastEtherFX(69), gigabitEthernet(117).</summary>
    public static readonly HashSet<int> PhysicalIfTypes = [6, 7, 62, 69, 117];

    private static readonly string[] VirtualNamePrefixes =
        ["lo", "vlan", "cpu", "br", "bridge", "switch", "tun", "docker", "veth", "null", "bond", "port-channel", "po", "ae", "irb", "mgmt-bridge"];

    /// <summary>true when the interface is a physical Ethernet port worth polling.</summary>
    public static bool IsPhysical(int? ifType, string? name)
    {
        if (ifType is { } t && !PhysicalIfTypes.Contains(t)) return false;
        if (string.IsNullOrWhiteSpace(name)) return ifType is not null;
        var n = name.Trim().ToLowerInvariant();
        foreach (var p in VirtualNamePrefixes)
        {
            if (!n.StartsWith(p, StringComparison.Ordinal)) continue;
            // "po1"/"ae0" are aggregates, but "port 1"/"poe" are real ports: require a digit right after short prefixes
            if (p.Length <= 2 && n.Length > p.Length && !char.IsDigit(n[p.Length])) continue;
            return false;
        }
        return true;
    }

    public static async Task<PortCounterPoll?> PollAsync(SnmpClient client, Mac switchMac, CancellationToken ct)
    {
        var upVars = await client.GetAsync([Oids.SysUpTime], ct).ConfigureAwait(false);
        TimeSpan? sysUp = upVars.Count > 0 ? AsTicks(upVars[0].Data) : null;

        var types = await WalkAsync(client, Oids.IfType, ct).ConfigureAwait(false);
        var names = await WalkAsync(client, Oids.IfName, ct).ConfigureAwait(false);
        if (types.Count == 0 && names.Count == 0)
        {
            names = await WalkAsync(client, Oids.IfDescr, ct).ConfigureAwait(false);
            if (names.Count == 0) return null; // agent did not answer IF-MIB
        }
        var descr = names.Count == 0 ? await WalkAsync(client, Oids.IfDescr, ct).ConfigureAwait(false) : names;

        var indexes = types.Keys.Union(names.Keys).Union(descr.Keys)
            .Where(i => IsPhysical(types.TryGetValue(i, out var t) ? (int?)AsLong(t) : null, NameOf(i, names, descr)))
            .ToHashSet();
        if (indexes.Count == 0) return new PortCounterPoll(sysUp, []);

        async Task<Dictionary<int, ISnmpData>> Col(string oid) => Filter(await WalkAsync(client, oid, ct).ConfigureAwait(false), indexes);
        async Task<Dictionary<int, ISnmpData>> ColOr(string hc, string fallback)
        {
            var r = await Col(hc).ConfigureAwait(false);
            return r.Count > 0 ? r : await Col(fallback).ConfigureAwait(false);
        }

        var oper = await Col(Oids.IfOperStatus).ConfigureAwait(false);
        var high = await Col(Oids.IfHighSpeed).ConfigureAwait(false);
        var speed = high.Count > 0 ? null : await Col(Oids.IfSpeed).ConfigureAwait(false);
        var lastChange = await Col(Oids.IfLastChange).ConfigureAwait(false);
        var inOct = await ColOr(Oids.IfHCInOctets, Oids.IfInOctets).ConfigureAwait(false);
        var outOct = await ColOr(Oids.IfHCOutOctets, Oids.IfOutOctets).ConfigureAwait(false);
        var inErr = await Col(Oids.IfInErrors).ConfigureAwait(false);
        var outErr = await Col(Oids.IfOutErrors).ConfigureAwait(false);
        var inDisc = await Col(Oids.IfInDiscards).ConfigureAwait(false);
        var outDisc = await Col(Oids.IfOutDiscards).ConfigureAwait(false);
        var bcast = await ColOr(Oids.IfHCInBroadcastPkts, Oids.IfInBroadcastPkts).ConfigureAwait(false);
        var mcast = await ColOr(Oids.IfHCInMulticastPkts, Oids.IfInMulticastPkts).ConfigureAwait(false);
        var ucast = await ColOr(Oids.IfHCInUcastPkts, Oids.IfInUcastPkts).ConfigureAwait(false);
        var fcs = await Col(Oids.Dot3StatsFcsErrors).ConfigureAwait(false);
        var align = fcs.Count == 0 ? [] : await Col(Oids.Dot3StatsAlignmentErrors).ConfigureAwait(false);
        var late = fcs.Count == 0 ? [] : await Col(Oids.Dot3StatsLateCollisions).ConfigureAwait(false);
        var excess = fcs.Count == 0 ? [] : await Col(Oids.Dot3StatsExcessiveCollisions).ConfigureAwait(false);
        var duplex = await Col(Oids.Dot3DuplexStatus).ConfigureAwait(false);

        var now = DateTimeOffset.Now;
        var samples = new List<PortCounterSample>(indexes.Count);
        foreach (var i in indexes.Order())
        {
            if (!oper.ContainsKey(i) && !inOct.ContainsKey(i)) continue; // no data for this row
            samples.Add(new PortCounterSample(switchMac, i, NameOf(i, names, descr) ?? $"if{i}", now,
                OperUp: oper.TryGetValue(i, out var o) && AsLong(o) == 1,
                SpeedMbps: SpeedOf(i, high, speed),
                Duplex: duplex.TryGetValue(i, out var d) ? DuplexName(AsLong(d)) : null,
                LastChange: lastChange.TryGetValue(i, out var lc) ? AsTicks(lc) : null,
                InOctets: U(inOct, i), OutOctets: U(outOct, i), InErrors: U(inErr, i), OutErrors: U(outErr, i),
                InDiscards: U(inDisc, i), OutDiscards: U(outDisc, i), InBroadcast: U(bcast, i), InMulticast: U(mcast, i),
                InUnicast: U(ucast, i), FcsErrors: U(fcs, i), AlignmentErrors: U(align, i), LateCollisions: U(late, i),
                ExcessiveCollisions: U(excess, i)));
        }
        return new PortCounterPoll(sysUp, samples);
    }

    /// <summary>Reads one port with a single GET (used by the on-demand storm-control check). Falls back to 32-bit columns.</summary>
    public static async Task<(PortCounterSample? Sample, TimeSpan? SysUpTime)> ReadPortAsync(SnmpClient client, Mac switchMac, int ifIndex, string name, CancellationToken ct)
    {
        string[] hc = [Oids.IfHCInOctets, Oids.IfHCOutOctets, Oids.IfHCInBroadcastPkts, Oids.IfHCInMulticastPkts, Oids.IfHCInUcastPkts];
        string[] basic = [Oids.IfOperStatus, Oids.IfHighSpeed, Oids.IfLastChange, Oids.IfInErrors, Oids.IfOutErrors, Oids.IfInDiscards, Oids.IfOutDiscards,
            Oids.IfInOctets, Oids.IfOutOctets, Oids.IfInBroadcastPkts, Oids.IfInMulticastPkts, Oids.IfInUcastPkts];
        string[] dot3 = [Oids.Dot3StatsFcsErrors, Oids.Dot3StatsAlignmentErrors, Oids.Dot3StatsLateCollisions, Oids.Dot3StatsExcessiveCollisions, Oids.Dot3DuplexStatus];

        var values = new Dictionary<string, ISnmpData>();
        async Task Get(IEnumerable<string> cols, bool scalarUpTime)
        {
            var oids = cols.Select(c => $"{c}.{ifIndex}").ToList();
            if (scalarUpTime) oids.Insert(0, Oids.SysUpTime);
            foreach (var v in await client.GetAsync(oids, ct).ConfigureAwait(false))
                if (!IsMissing(v.Data)) values[v.Id.ToString()] = v.Data;
        }
        await Get(basic, true).ConfigureAwait(false);
        if (values.Count == 0) return (null, null);
        await Get(hc, false).ConfigureAwait(false);   // v1 agents reject the whole request; the 32-bit values stay
        await Get(dot3, false).ConfigureAwait(false);

        ISnmpData? V(string col) => values.GetValueOrDefault($"{col}.{ifIndex}");
        ulong C(string hcCol, string col) => AsULong(V(hcCol) ?? V(col));
        ulong C1(string col) => AsULong(V(col));

        long? speed = V(Oids.IfHighSpeed) is { } hs && AsLong(hs) > 0 ? AsLong(hs) : null;
        var sample = new PortCounterSample(switchMac, ifIndex, name, DateTimeOffset.Now,
            OperUp: V(Oids.IfOperStatus) is { } o && AsLong(o) == 1, SpeedMbps: speed,
            Duplex: V(Oids.Dot3DuplexStatus) is { } d ? DuplexName(AsLong(d)) : null,
            LastChange: V(Oids.IfLastChange) is { } lc ? AsTicks(lc) : null,
            InOctets: C(Oids.IfHCInOctets, Oids.IfInOctets), OutOctets: C(Oids.IfHCOutOctets, Oids.IfOutOctets),
            InErrors: C1(Oids.IfInErrors), OutErrors: C1(Oids.IfOutErrors), InDiscards: C1(Oids.IfInDiscards), OutDiscards: C1(Oids.IfOutDiscards),
            InBroadcast: C(Oids.IfHCInBroadcastPkts, Oids.IfInBroadcastPkts), InMulticast: C(Oids.IfHCInMulticastPkts, Oids.IfInMulticastPkts),
            InUnicast: C(Oids.IfHCInUcastPkts, Oids.IfInUcastPkts), FcsErrors: C1(Oids.Dot3StatsFcsErrors), AlignmentErrors: C1(Oids.Dot3StatsAlignmentErrors),
            LateCollisions: C1(Oids.Dot3StatsLateCollisions), ExcessiveCollisions: C1(Oids.Dot3StatsExcessiveCollisions));
        return (sample, values.GetValueOrDefault(Oids.SysUpTime) is { } up ? AsTicks(up) : null);
    }

    // ---- value helpers ----

    private static async Task<Dictionary<int, ISnmpData>> WalkAsync(SnmpClient client, string column, CancellationToken ct)
    {
        var map = new Dictionary<int, ISnmpData>();
        foreach (var v in await client.WalkAsync(column, ct).ConfigureAwait(false))
        {
            var suffix = SnmpClient.RowSuffix(v, column);
            if (suffix.Length == 1 && !IsMissing(v.Data)) map[(int)suffix[0]] = v.Data;
        }
        return map;
    }

    private static Dictionary<int, ISnmpData> Filter(Dictionary<int, ISnmpData> map, HashSet<int> keep)
    {
        foreach (var k in map.Keys.Where(k => !keep.Contains(k)).ToList()) map.Remove(k);
        return map;
    }

    private static string? NameOf(int i, Dictionary<int, ISnmpData> names, Dictionary<int, ISnmpData> descr)
    {
        var n = names.TryGetValue(i, out var a) ? a.ToString() : null;
        if (string.IsNullOrWhiteSpace(n)) n = descr.TryGetValue(i, out var b) ? b.ToString() : null;
        return string.IsNullOrWhiteSpace(n) ? null : n.Trim();
    }

    private static long? SpeedOf(int i, Dictionary<int, ISnmpData> high, Dictionary<int, ISnmpData>? speed)
    {
        if (high.TryGetValue(i, out var h) && AsLong(h) is var hv and > 0) return hv;
        if (speed is not null && speed.TryGetValue(i, out var s) && AsULong(s) is var sv and > 0) return (long)(sv / 1_000_000);
        return null;
    }

    private static ulong U(Dictionary<int, ISnmpData> map, int i) => map.TryGetValue(i, out var v) ? AsULong(v) : 0;

    internal static bool IsMissing(ISnmpData data) =>
        data.TypeCode is SnmpType.NoSuchObject or SnmpType.NoSuchInstance or SnmpType.EndOfMibView or SnmpType.Null;

    internal static ulong AsULong(ISnmpData? data) => data switch
    {
        null => 0,
        Counter64 c => c.ToUInt64(),
        Counter32 c => c.ToUInt32(),
        Gauge32 g => g.ToUInt32(),
        TimeTicks t => t.ToUInt32(),
        Integer32 n => (ulong)Math.Max(0, n.ToInt32()),
        _ => ulong.TryParse(data.ToString(), out var v) ? v : 0,
    };

    internal static long AsLong(ISnmpData? data) => data is Integer32 n ? n.ToInt32() : (long)AsULong(data);

    /// <summary>TimeTicks are hundredths of a second.</summary>
    internal static TimeSpan? AsTicks(ISnmpData? data) => data switch
    {
        TimeTicks t => TimeSpan.FromMilliseconds(t.ToUInt32() * 10.0),
        null => null,
        _ when !IsMissing(data) && ulong.TryParse(data.ToString(), out var v) => TimeSpan.FromMilliseconds(v * 10.0),
        _ => null,
    };

    internal static string DuplexName(long code) => code switch { 2 => "half", 3 => "full", _ => "unknown" };
}
