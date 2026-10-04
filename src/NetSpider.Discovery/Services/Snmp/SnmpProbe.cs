using System.Net;
using Lextm.SharpSnmpLib;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>
/// SNMP v1/v2c/v3 device probe: system group + vendor from enterprise OID, bridge FDB/port tables, LLDP neighbors,
/// router ARP/route tables, HOST-RESOURCES and PRINTER-MIB. Writes switch data to <see cref="INetworkState"/>.
/// </summary>
public sealed class SnmpProbe : IDeviceProbe
{
    private const string Source = "snmp";
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly ILogger<SnmpProbe> _log;

    public SnmpProbe(IDeviceStore store, INetworkState network, ILogger<SnmpProbe> log)
    {
        _store = store; _network = network; _log = log;
    }

    public string Name => "SNMP";
    public int Order => 330;

    public bool AppliesTo(Device device, ScanContext ctx) => device.PrimaryIPv4 is not null && !device.Mac.IsMulticast;

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        var s = ctx.Settings;
        SnmpClient? client;
        try
        {
            client = await SnmpClient.EstablishAsync(ip, s.SnmpCommunities, s.SnmpTimeoutMs,
                s.SnmpV3User, s.SnmpV3AuthPassword, s.SnmpV3PrivPassword, s.SnmpV3AuthProtocol, s.SnmpV3PrivProtocol, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex) { _log.LogDebug(ex, "SNMP establish {Ip}", ip); return; }
        if (client is null) return;

        bool changed = false;
        try
        {
            changed |= MarkDefaultCommunity(device, client, s);
            changed |= await ReadSystemAsync(device, client, ct).ConfigureAwait(false);
            bool isBridge = await ReadBridgeAsync(device, client, ct).ConfigureAwait(false);
            changed |= isBridge;
            changed |= await ReadRouterAsync(device, ctx, client, ct).ConfigureAwait(false);
            changed |= await ReadHostResourcesAsync(device, client, ct).ConfigureAwait(false);
            changed |= await ReadPrinterAsync(device, client, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "SNMP probe {Ip}", ip); }

        if (changed) _store.NotifyChanged(device, Source);
    }

    private static bool MarkDefaultCommunity(Device device, SnmpClient client, AppSettings s)
    {
        if (client.Version != VersionCode.V3 && client.Credential is "public" or "private")
        {
            device.SetProperty("snmp.community", client.Credential);
            if (!device.Has(DeviceFlags.DefaultSnmpCommunity)) { device.SetFlag(DeviceFlags.DefaultSnmpCommunity); return true; }
        }
        return false;
    }

    private async Task<bool> ReadSystemAsync(Device device, SnmpClient client, CancellationToken ct)
    {
        var vars = await client.GetAsync(new[] { Oids.SysDescr, Oids.SysObjectId, Oids.SysName, Oids.SysLocation, Oids.SysContact, Oids.SysUpTime }, ct).ConfigureAwait(false);
        if (vars.Count == 0) return false;
        bool changed = false;
        foreach (var v in vars)
        {
            var oid = v.Id.ToString();
            var val = v.Data.ToString();
            if (string.IsNullOrWhiteSpace(val)) continue;
            if (oid.StartsWith(Oids.SysDescr[..^2])) { changed |= device.AddEvidence(Source, Fields.Description, val, Confidence.Snmp); changed |= device.SetProperty("snmp.sysDescr", val); }
            else if (oid.StartsWith(Oids.SysObjectId[..^2]))
            {
                changed |= device.SetProperty("snmp.sysObjectID", val);
                var ent = Oids.EnterpriseOf(val);
                if (ent is { } e && Oids.EnterpriseVendors.TryGetValue(e, out var vendor))
                    changed |= device.AddEvidence(Source, Fields.Vendor, vendor, Confidence.Snmp);
            }
            else if (oid.StartsWith(Oids.SysName[..^2])) changed |= device.SetHostname(Source, val);
            else if (oid.StartsWith(Oids.SysLocation[..^2])) changed |= device.SetProperty("snmp.location", val);
            else if (oid.StartsWith(Oids.SysContact[..^2])) changed |= device.SetProperty("snmp.contact", val);
            else if (oid.StartsWith(Oids.SysUpTime[..^2])) changed |= device.SetProperty("snmp.uptime", val);
        }
        return changed;
    }

    private async Task<bool> ReadBridgeAsync(Device device, SnmpClient client, CancellationToken ct)
    {
        var numPorts = await client.GetStringAsync(Oids.Dot1dBaseNumPorts, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(numPorts) || !int.TryParse(numPorts, out var np) || np <= 0) return false;

        if (!device.Has(DeviceFlags.Infrastructure)) device.SetFlag(DeviceFlags.Infrastructure);
        device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.AccessSwitch), Confidence.Snmp);

        // bridge port -> ifIndex
        var portToIf = new Dictionary<uint, int>();
        foreach (var v in await client.WalkAsync(Oids.Dot1dBasePortIfIndex, ct).ConfigureAwait(false))
        {
            var suffix = SnmpClient.RowSuffix(v, Oids.Dot1dBasePortIfIndex);
            if (suffix.Length == 1 && int.TryParse(v.Data.ToString(), out var ifIndex)) portToIf[suffix[0]] = ifIndex;
        }

        // interface attributes keyed by ifIndex
        var ifNames = await WalkStringsAsync(client, Oids.IfName, ct).ConfigureAwait(false);
        var ifDescrs = await WalkStringsAsync(client, Oids.IfDescr, ct).ConfigureAwait(false);
        var ifAlias = await WalkStringsAsync(client, Oids.IfAlias, ct).ConfigureAwait(false);
        var ifSpeed = await WalkStringsAsync(client, Oids.IfHighSpeed, ct).ConfigureAwait(false);
        var ifOper = await WalkStringsAsync(client, Oids.IfOperStatus, ct).ConfigureAwait(false);
        var duplex = await WalkStringsAsync(client, Oids.Dot3DuplexStatus, ct).ConfigureAwait(false);
        var pvid = await WalkStringsAsync(client, Oids.Dot1qPvid, ct).ConfigureAwait(false);
        var poe = await WalkStringsAsync(client, Oids.PethPsePortActualPower, ct).ConfigureAwait(false);

        var ports = new List<SwitchPortInfo>();
        foreach (var (bridgePort, ifIndex) in portToIf)
        {
            string key = ifIndex.ToString();
            string name = ifNames.GetValueOrDefault(key) ?? ifDescrs.GetValueOrDefault(key) ?? $"port{bridgePort}";
            long? speed = long.TryParse(ifSpeed.GetValueOrDefault(key), out var sp) ? sp : null;
            bool? up = ifOper.TryGetValue(key, out var os) ? os == "1" : null;
            string? dup = duplex.GetValueOrDefault(key) is { } dx ? DuplexName(dx) : null;
            double? watts = ParsePoe(poe, bridgePort);
            int? vid = int.TryParse(pvid.GetValueOrDefault(bridgePort.ToString()), out var pv) ? pv : null;
            ports.Add(new SwitchPortInfo(device.Mac, ifIndex, name, ifAlias.GetValueOrDefault(key), speed, up, dup, watts, vid));
        }
        if (ports.Count > 0) _network.SetSwitchPorts(device.Mac, ports);

        await ReadFdbAsync(device, client, portToIf, ct).ConfigureAwait(false);
        await ReadLldpAsync(device, client, ct).ConfigureAwait(false);
        return true;
    }

    private async Task ReadFdbAsync(Device device, SnmpClient client, Dictionary<uint, int> portToIf, CancellationToken ct)
    {
        var entries = new List<FdbEntry>();
        // Q-BRIDGE first (includes VLAN); the row suffix is vlan + 6 MAC octets.
        foreach (var v in await client.WalkAsync(Oids.Dot1qTpFdbPort, ct).ConfigureAwait(false))
        {
            var suffix = SnmpClient.RowSuffix(v, Oids.Dot1qTpFdbPort);
            if (suffix.Length < 7) continue;
            int vlan = (int)suffix[0];
            var mac = MacFromSuffix(suffix.AsSpan(suffix.Length - 6));
            if (int.TryParse(v.Data.ToString(), out var bridgePort) && !mac.IsZero)
                entries.Add(new FdbEntry(device.Mac, bridgePort.ToString(), portToIf.GetValueOrDefault((uint)bridgePort), mac, vlan, DateTimeOffset.Now));
        }
        if (entries.Count == 0)
            foreach (var v in await client.WalkAsync(Oids.Dot1dTpFdbPort, ct).ConfigureAwait(false))
            {
                var suffix = SnmpClient.RowSuffix(v, Oids.Dot1dTpFdbPort);
                if (suffix.Length < 6) continue;
                var mac = MacFromSuffix(suffix.AsSpan(suffix.Length - 6));
                if (int.TryParse(v.Data.ToString(), out var bridgePort) && !mac.IsZero)
                    entries.Add(new FdbEntry(device.Mac, bridgePort.ToString(), portToIf.GetValueOrDefault((uint)bridgePort), mac, null, DateTimeOffset.Now));
            }
        if (entries.Count > 0) _network.SetFdb(device.Mac, entries);
    }

    private async Task ReadLldpAsync(Device device, SnmpClient client, CancellationToken ct)
    {
        var sysName = await WalkStringsBySuffixAsync(client, Oids.LldpRemSysName, ct).ConfigureAwait(false);
        var sysDesc = await WalkStringsBySuffixAsync(client, Oids.LldpRemSysDesc, ct).ConfigureAwait(false);
        var portId = await WalkStringsBySuffixAsync(client, Oids.LldpRemPortId, ct).ConfigureAwait(false);
        var chassis = await WalkStringsBySuffixAsync(client, Oids.LldpRemChassis, ct).ConfigureAwait(false);
        foreach (var key in sysName.Keys.Union(chassis.Keys))
        {
            _network.AddNeighbor(new NeighborEntry(
                device.Mac, key.Split('.').ElementAtOrDefault(1),
                null, chassis.GetValueOrDefault(key), portId.GetValueOrDefault(key), sysName.GetValueOrDefault(key),
                null, sysDesc.GetValueOrDefault(key), null, "lldp-mib", DateTimeOffset.Now));
        }
    }

    private async Task<bool> ReadRouterAsync(Device device, ScanContext ctx, SnmpClient client, CancellationToken ct)
    {
        bool changed = false;
        // ARP table (ipNetToPhysical then ipNetToMedia)
        var arp = await client.WalkAsync(Oids.IpNetToPhysicalPhysAddress, ct).ConfigureAwait(false);
        string column = Oids.IpNetToPhysicalPhysAddress;
        if (arp.Count == 0) { arp = await client.WalkAsync(Oids.IpNetToMediaPhysAddress, ct).ConfigureAwait(false); column = Oids.IpNetToMediaPhysAddress; }

        foreach (var v in arp)
        {
            var suffix = SnmpClient.RowSuffix(v, column);
            var ip = ExtractIpFromArpSuffix(suffix);
            var mac = MacFromOctetString(v.Data);
            if (ip is null || mac is null || mac.Value.IsZero) continue;
            bool local = ctx.Segments.Any(seg => seg.IsLocal && seg.Contains(ip));
            if (local) _store.Observe(mac.Value, ip, "snmp-arp");
            else device.SetProperty($"snmp.arp.{ip}", mac.Value.ToString());
            changed = true;
        }

        // Routes → segments (private only)
        foreach (var v in await client.WalkAsync(Oids.IpCidrRouteDest, ct).ConfigureAwait(false))
        {
            if (v.Data is IP ipData && IPAddress.TryParse(ipData.ToString(), out var net) && IpUtil.IsPrivate(net))
            {
                _network.AddOrGetSegment(net, 24, "snmp-route");
                changed = true;
            }
        }
        return changed;
    }

    private async Task<bool> ReadHostResourcesAsync(Device device, SnmpClient client, CancellationToken ct)
    {
        bool changed = false;
        var cpu = await WalkStringsAsync(client, Oids.HrProcessorLoad, ct).ConfigureAwait(false);
        if (cpu.Count > 0)
        {
            var loads = cpu.Values.Select(x => int.TryParse(x, out var n) ? n : 0).ToArray();
            if (loads.Length > 0) changed |= device.SetProperty("host.cpu", (loads.Average()).ToString("F0") + "%");
        }
        var up = await client.GetStringAsync(Oids.HrSystemUptime, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(up)) changed |= device.SetProperty("host.uptime", up);

        var descr = await WalkStringsAsync(client, Oids.HrStorageDescr, ct).ConfigureAwait(false);
        var size = await WalkStringsAsync(client, Oids.HrStorageSize, ct).ConfigureAwait(false);
        var used = await WalkStringsAsync(client, Oids.HrStorageUsed, ct).ConfigureAwait(false);
        foreach (var (idx, name) in descr)
        {
            if (!long.TryParse(size.GetValueOrDefault(idx), out var total) || total <= 0) continue;
            long u = long.TryParse(used.GetValueOrDefault(idx), out var uu) ? uu : 0;
            int pct = (int)(100.0 * u / total);
            bool isRam = name.Contains("RAM", StringComparison.OrdinalIgnoreCase) || name.Contains("memory", StringComparison.OrdinalIgnoreCase);
            changed |= device.SetProperty(isRam ? "host.mem" : $"host.disk.{name}", pct + "%");
        }
        return changed;
    }

    private async Task<bool> ReadPrinterAsync(Device device, SnmpClient client, CancellationToken ct)
    {
        bool changed = false;
        var descr = await WalkStringsAsync(client, Oids.PrtMarkerSuppliesDescription, ct).ConfigureAwait(false);
        var level = await WalkStringsAsync(client, Oids.PrtMarkerSuppliesLevel, ct).ConfigureAwait(false);
        var max = await WalkStringsAsync(client, Oids.PrtMarkerSuppliesMaxCapacity, ct).ConfigureAwait(false);
        if (descr.Count > 0)
        {
            changed |= device.AddEvidence(Source, Fields.DeviceType, nameof(DeviceType.Printer), Confidence.Snmp);
            foreach (var (idx, name) in descr)
            {
                if (!long.TryParse(level.GetValueOrDefault(idx), out var lv) || !long.TryParse(max.GetValueOrDefault(idx), out var mx) || mx <= 0) continue;
                int pct = (int)(100.0 * lv / mx);
                changed |= device.SetProperty($"printer.supply.{name}", pct + "%");
            }
        }
        var pages = await WalkStringsAsync(client, Oids.PrtMarkerLifeCount, ct).ConfigureAwait(false);
        var pageCount = pages.Values.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(pageCount)) changed |= device.SetProperty("printer.pageCount", pageCount);
        return changed;
    }

    // ---- helpers ----

    private static async Task<Dictionary<string, string>> WalkStringsAsync(SnmpClient client, string column, CancellationToken ct)
    {
        var map = new Dictionary<string, string>();
        foreach (var v in await client.WalkAsync(column, ct).ConfigureAwait(false))
        {
            var suffix = SnmpClient.RowSuffix(v, column);
            if (suffix.Length == 0) continue;
            map[string.Join('.', suffix)] = v.Data.ToString();
        }
        return map;
    }

    private static async Task<Dictionary<string, string>> WalkStringsBySuffixAsync(SnmpClient client, string column, CancellationToken ct)
        => await WalkStringsAsync(client, column, ct).ConfigureAwait(false);

    private static Mac MacFromSuffix(ReadOnlySpan<uint> octets)
    {
        if (octets.Length < 6) return Mac.Zero;
        Span<byte> b = stackalloc byte[6];
        for (int i = 0; i < 6; i++) b[i] = (byte)octets[i];
        return Mac.FromBytes(b);
    }

    private static Mac? MacFromOctetString(ISnmpData data)
    {
        if (data is OctetString os)
        {
            var raw = os.GetRaw();
            if (raw.Length == 6) return Mac.FromBytes(raw);
        }
        return null;
    }

    private static IPAddress? ExtractIpFromArpSuffix(uint[] suffix)
    {
        // ipNetToMedia suffix: ifIndex + 4 IP octets. ipNetToPhysical: ifIndex + addrType + len + 4 octets.
        if (suffix.Length >= 4)
        {
            var tail = suffix[^4..];
            if (tail.All(x => x <= 255))
                return new IPAddress(new byte[] { (byte)tail[0], (byte)tail[1], (byte)tail[2], (byte)tail[3] });
        }
        return null;
    }

    private static double? ParsePoe(Dictionary<string, string> poe, uint bridgePort)
    {
        // pethPsePortActualPower is in milliwatts, indexed by group.port; match on the trailing port number.
        foreach (var (k, val) in poe)
            if (k.EndsWith("." + bridgePort) && double.TryParse(val, out var mw) && mw > 0) return mw / 1000.0;
        return null;
    }

    private static string DuplexName(string code) => code switch { "2" => "half", "3" => "full", _ => "unknown" };
}
