using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Scan stage 10: ARP-sweeps every host of the directly attached IPv4 segments (two paced passes) and records the L2
/// RTT of each reply. Also registers this computer as a device and flags the gateway.
/// </summary>
public sealed class ArpSweepProbe : IActiveProbe
{
    private static readonly TimeSpan ReplyTimeout = TimeSpan.FromMilliseconds(1500);

    private readonly ILogger<ArpSweepProbe> _log;
    private readonly IFrameSource _frames;
    private readonly IDeviceStore _store;
    private readonly LatencyProber _prober;
    private readonly DiscoveryContext _dctx;

    public ArpSweepProbe(ILogger<ArpSweepProbe> log, IFrameSource frames, IDeviceStore store, LatencyProber prober, DiscoveryContext dctx)
    {
        _log = log;
        _frames = frames;
        _store = store;
        _prober = prober;
        _dctx = dctx;
    }

    public string Name => "ARP sweep";
    public ProbeLayer Layer => ProbeLayer.L2;
    public int Order => 10;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        try { EnsureLocalHost(_store, ctx.Adapter); }
        catch (Exception ex) { _log.LogDebug(ex, "Registering local host failed"); }

        var segments = LocalSegments(ctx);
        var targets = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();
        foreach (var seg in segments)
            foreach (var ip in SweepTargets(seg.Network, seg.PrefixLength, ctx.Settings.MinSweepPrefix, ctx.LocalIPv4))
                if (!_dctx.IsLocalIp(ip) && seen.Add(ip)) targets.Add(ip);

        // Oversized segments (e.g. a /16) are only swept around our own address; also sweep every /24 where hosts are
        // already known to live (gateway, DHCP/DNS servers, OS ARP cache, passively observed devices).
        foreach (var seg in segments.Where(s => s.PrefixLength < Math.Clamp(ctx.Settings.MinSweepPrefix, 16, 30)))
        {
            var hints = new List<IPAddress?> { ctx.Gateway, ctx.Adapter.DhcpServer };
            hints.AddRange(ctx.Adapter.DnsServers);
            hints.AddRange(OsArpCache.Read());
            hints.AddRange(_store.All.SelectMany(d => d.IPv4));
            var blocks = hints.OfType<IPAddress>().Where(seg.Contains).Select(ip => IpUtil.NetworkAddress(ip, 24)).Distinct().Take(64).ToList();
            foreach (var block in blocks)
                foreach (var ip in IpUtil.Hosts(block, 24))
                    if (!_dctx.IsLocalIp(ip) && seen.Add(ip)) targets.Add(ip);
            if (blocks.Count > 0) _log.LogInformation("ARP sweep of {Cidr} extended with {Count} known /24 blocks", seg.Cidr, blocks.Count);
        }

        if (targets.Count == 0) { _log.LogDebug("ARP sweep: no local IPv4 segment"); return; }
        _log.LogInformation("ARP sweep of {Count} addresses in {Segments}", targets.Count, string.Join(", ", segments.Select(s => s.Cidr)));

        var found = new ConcurrentDictionary<IPAddress, Mac>();
        try
        {
            if (_frames.IsRunning)
            {
                var remaining = targets;
                for (int pass = 1; pass <= 2 && remaining.Count > 0; pass++)
                {
                    ct.ThrowIfCancellationRequested();
                    await SweepPassAsync(remaining, pass, found, progress, ct).ConfigureAwait(false);
                    remaining = remaining.Where(ip => !found.ContainsKey(ip)).ToList();
                }
            }
            else
            {
                _log.LogInformation("Capture not running: ARP sweep falls back to SendARP (no L2 RTT)");
                await SendArpFallbackAsync(targets, found, progress, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "ARP sweep failed"); }

        FlagGateway(ctx);
        foreach (var seg in segments)
        {
            seg.HostsFound = found.Keys.Count(seg.Contains);
            seg.LastScanned = DateTimeOffset.Now;
        }
        progress?.Report(new ScanProgress(Name, 1, $"{found.Count} hosts"));
    }

    private IReadOnlyList<NetworkSegment> LocalSegments(ScanContext ctx)
    {
        var segs = _dctx.AllSegments(ctx).Where(s => s.IsLocal && s.Network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && s.VlanId is null).ToList();
        if (segs.Count == 0)
            foreach (var a in ctx.Adapter.IPv4)
                segs.Add(new NetworkSegment(a.Address, a.PrefixLength, "adapter") { IsLocal = true, Gateway = ctx.Gateway });
        return segs;
    }

    /// <summary>Hosts to sweep; segments larger than <paramref name="minPrefix"/> are capped to the block around our address.</summary>
    public static IEnumerable<IPAddress> SweepTargets(IPAddress network, int prefix, int minPrefix, IPAddress? local)
    {
        if (prefix >= 32) return [];
        minPrefix = Math.Clamp(minPrefix, 16, 30);
        if (prefix < minPrefix)
        {
            var anchor = local is not null && IpUtil.InSubnet(local, network, prefix) ? local : network;
            return IpUtil.Hosts(IpUtil.NetworkAddress(anchor, minPrefix), minPrefix);
        }
        return IpUtil.Hosts(network, prefix);
    }

    private async Task SweepPassAsync(List<IPAddress> targets, int pass, ConcurrentDictionary<IPAddress, Mac> found, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        int done = 0;
        long lastReport = 0;
        var tasks = new List<Task>(targets.Count);
        foreach (var ip in targets)
        {
            ct.ThrowIfCancellationRequested();
            tasks.Add(PingOneAsync(ip));
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);

        async Task PingOneAsync(IPAddress ip)
        {
            try
            {
                var (ms, mac) = await _prober.ArpPingCoreAsync(ip, ReplyTimeout, paced: true, vlanId: null, ct).ConfigureAwait(false);
                if (mac is { } m && !m.IsZero)
                {
                    found[ip] = m;
                    var d = _store.Observe(m, ip, "arp");
                    if (ms is { } v) d.Latency.Add(LatencyKind.Arp, v);
                    _store.NotifyChanged(d, "arp-rtt");
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _log.LogDebug(ex, "ARP sweep {Ip}", ip); }
            finally
            {
                int n = Interlocked.Increment(ref done);
                long now = Environment.TickCount64;
                if (progress is not null && (now - Interlocked.Read(ref lastReport) > 200 || n == targets.Count))
                {
                    Interlocked.Exchange(ref lastReport, now);
                    double frac = pass == 1 ? 0.8 * n / targets.Count : 0.8 + 0.2 * n / targets.Count;
                    progress.Report(new ScanProgress(Name, frac, $"pass {pass}: {n}/{targets.Count}, {found.Count} hosts"));
                }
            }
        }
    }

    private async Task SendArpFallbackAsync(List<IPAddress> targets, ConcurrentDictionary<IPAddress, Mac> found, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        int done = 0;
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = 32, CancellationToken = ct }, (ip, _) =>
        {
            try
            {
                var mac = new byte[6];
                uint len = 6;
                uint dst = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
                if (SendARP(dst, 0, mac, ref len) == 0 && len == 6)
                {
                    var m = Mac.FromBytes(mac);
                    if (!m.IsZero) { found[ip] = m; _store.Observe(m, ip, "arp"); }
                }
            }
            catch (Exception ex) { _log.LogDebug(ex, "SendARP {Ip}", ip); }
            int n = Interlocked.Increment(ref done);
            if (n % 16 == 0) progress?.Report(new ScanProgress(Name, (double)n / targets.Count, $"{found.Count} hosts"));
            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physAddrLen);

    private void FlagGateway(ScanContext ctx)
    {
        if (ctx.Gateway is not { } gw) return;
        var d = _store.FindByIp(gw);
        if (d is null) return;
        bool changed = !d.Has(DeviceFlags.Gateway);
        d.SetFlag(DeviceFlags.Gateway);
        changed |= DeviceHints.HintType(d, "arp", DeviceType.Router, 0.6);
        if (changed) _store.NotifyChanged(d, "gateway");
        foreach (var seg in _dctx.AllSegments(ctx).Where(s => s.IsLocal && s.Contains(gw)))
            seg.Gateway ??= gw;
    }

    /// <summary>Registers this computer (flag <see cref="DeviceFlags.ThisHost"/>, type <see cref="DeviceType.ThisComputer"/>) with all its addresses.</summary>
    public static Device EnsureLocalHost(IDeviceStore store, AdapterInfo adapter)
    {
        var d = store.GetOrAdd(adapter.Mac);
        foreach (var a in adapter.IPv4) store.Observe(adapter.Mac, a.Address, "local");
        foreach (var a in adapter.IPv6) d.AddIp(DeviceHints.Normalize(a));
        d.SetFlag(DeviceFlags.ThisHost);
        if (adapter.IsVirtual) d.SetFlag(DeviceFlags.Virtual);
        if (adapter.IsWireless) d.SetFlag(DeviceFlags.WifiClient);
        d.Type = DeviceType.ThisComputer;
        d.TypeConfidence = 1.0;
        d.SetHostname("local", Environment.MachineName);
        d.OsGuess ??= RuntimeInformation.OSDescription;
        d.SetProperty("adapter", adapter.Description.Length > 0 ? adapter.Description : adapter.Name);
        if (adapter.SpeedMbps > 0) d.SetProperty("linkSpeedMbps", adapter.SpeedMbps.ToString(System.Globalization.CultureInfo.InvariantCulture));
        d.Touch();
        store.NotifyChanged(d, "local-host");
        return d;
    }
}
