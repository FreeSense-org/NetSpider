using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Topology;

namespace NetSpider.Diagnostics.Latency;

/// <summary>
/// Periodically measures hostâ†’device latency (ARP/NDP at L2, ICMP at L3, optionally TCP), raises latency-spike and
/// packet-loss alerts, maintains per-link latency and answers deviceâ†”device latency queries.
/// </summary>
public sealed class LatencyEngine : ILatencyEngine, IDisposable
{
    public const int MaxInFlight = 32;
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(1000);

    private readonly ILogger<LatencyEngine> _log;
    private readonly IServiceProvider _sp;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly IAlertService _alerts;
    private readonly AppSettings _settings;
    private readonly PassiveTcpRttTracker? _passive;
    private readonly ConcurrentDictionary<Mac, ProbeState> _state = new();

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private ScanContext? _ctx;
    private bool _warnedNoProber;

    public LatencyEngine(ILogger<LatencyEngine> log, IServiceProvider sp, IDeviceStore devices, ITopologyStore topology, IAlertService alerts, AppSettings settings)
    {
        _log = log;
        _sp = sp;
        _devices = devices;
        _topology = topology;
        _alerts = alerts;
        _settings = settings;
        _passive = sp.GetService<PassiveTcpRttTracker>();
    }

    private sealed class ProbeState
    {
        public DateTimeOffset? LastReply;
        public int ConsecutiveFailedCycles;
        public int Cycles;
    }

    public bool IsRunning => _loop is { IsCompleted: false };
    public long CycleCount { get; private set; }

    /// <summary>Time of the last successful probe of any kind for the device.</summary>
    public DateTimeOffset? LastReply(Mac mac) => _state.TryGetValue(mac, out var s) ? s.LastReply : null;

    /// <summary>Number of consecutive cycles in which every probe to the device failed.</summary>
    public int ConsecutiveFailedCycles(Mac mac) => _state.TryGetValue(mac, out var s) ? s.ConsecutiveFailedCycles : 0;

    public void Start(ScanContext ctx)
    {
        Stop();
        _ctx = ctx;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loop = Task.Run(() => LoopAsync(ct), ct);
        _log.LogInformation("Latency engine started (interval {Interval}s)", _settings.LatencyIntervalSeconds);
    }

    public void Stop()
    {
        var cts = Interlocked.Exchange(ref _cts, null);
        if (cts is null) return;
        try { cts.Cancel(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        cts.Dispose();
        _loop = null;
    }

    public void Dispose() => Stop();

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var started = DateTimeOffset.Now;
            try { if (_ctx is { } c) await RunCycleAsync(c, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Latency cycle failed"); }
            var interval = TimeSpan.FromSeconds(Math.Clamp(_settings.LatencyIntervalSeconds, 1, 60));
            var wait = interval - (DateTimeOffset.Now - started);
            if (wait < TimeSpan.FromMilliseconds(200)) wait = TimeSpan.FromMilliseconds(200);
            try { await Task.Delay(wait, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>One measurement cycle over all eligible devices (public for tests and "measure now").</summary>
    public async Task RunCycleAsync(ScanContext ctx, CancellationToken ct)
    {
        _ctx ??= ctx;
        var prober = _sp.GetService<ILatencyProber>();
        if (prober is null)
        {
            if (!_warnedNoProber) { _log.LogWarning("No ILatencyProber registered; host latency is not measured"); _warnedNoProber = true; }
        }
        else
        {
            var targets = _devices.All.Where(d => Eligible(d, ctx)).ToList();
            using var gate = new SemaphoreSlim(MaxInFlight);
            var tasks = targets.Select(async d =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try { await ProbeDeviceAsync(prober, d, ctx, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogDebug(ex, "Latency probe of {Device} failed", d); }
                finally { gate.Release(); }
            }).ToList();
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        CycleCount++;
        UpdateLinkLatencies(ctx);
    }

    /// <summary>Online, non-synthetic devices with an address; offline ones are retried every 5th cycle so they can come back.</summary>
    private bool Eligible(Device d, ScanContext ctx) =>
        (d.State != DeviceState.Offline || CycleCount % 5 == 0) &&
        !NodeKinds.IsGraphOnly(d) && d.Mac != ctx.LocalMac && !d.Has(DeviceFlags.ThisHost) && (d.IPv4.Length > 0 || d.IPv6.Length > 0);

    private async Task ProbeDeviceAsync(ILatencyProber prober, Device d, ScanContext ctx, CancellationToken ct)
    {
        bool any = false, ok = false;
        var ip4 = d.PrimaryIPv4;
        if (ip4 is not null)
        {
            bool local = NodeKinds.IsOnLocalSubnet(ip4, ctx) && !d.Has(DeviceFlags.OffSubnet);
            var icmpTask = prober.IcmpPingAsync(ip4, ProbeTimeout, ct);
            if (local)
            {
                var (arpMs, _) = await prober.ArpPingAsync(ip4, ProbeTimeout, ct).ConfigureAwait(false);
                d.Latency.Add(LatencyKind.Arp, arpMs);
                any = true; ok |= arpMs is not null;
            }
            var icmpMs = await icmpTask.ConfigureAwait(false);
            d.Latency.Add(LatencyKind.Icmp, icmpMs);
            any = true; ok |= icmpMs is not null;
        }
        else
        {
            var v6 = d.IPv6.OrderBy(a => a.Kind == Ipv6Kind.LinkLocal ? 0 : 1).Select(a => a.Address).FirstOrDefault(a => !a.IsIPv6Multicast);
            if (v6 is not null)
            {
                var ndp = await prober.NdpPingAsync(v6, d.Mac, ProbeTimeout, ct).ConfigureAwait(false);
                d.Latency.Add(LatencyKind.Ndp, ndp);
                any = true; ok |= ndp is not null;
            }
        }

        if (_settings.TcpLatency && (ip4 ?? d.IPv6.FirstOrDefault()?.Address) is { } tip)
        {
            var port = d.Ports.FirstOrDefault(p => p.State == PortState.Open && p.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase));
            if (port is not null)
            {
                var tcp = await prober.TcpPingAsync(tip, port.Port, ProbeTimeout, ct).ConfigureAwait(false);
                d.Latency.Add(LatencyKind.Tcp, tcp);
                any = true; ok |= tcp is not null;
            }
        }
        if (!any) return;

        var st = _state.GetOrAdd(d.Mac, _ => new ProbeState());
        st.Cycles++;
        if (ok)
        {
            st.LastReply = DateTimeOffset.Now;
            st.ConsecutiveFailedCycles = 0;
            d.Touch();
        }
        else st.ConsecutiveFailedCycles++;

        EvaluateAlerts(d);
        _devices.NotifyChanged(d, "latency");
    }

    private void EvaluateAlerts(Device d)
    {
        foreach (var kind in new[] { LatencyKind.Icmp, LatencyKind.Arp, LatencyKind.Ndp })
        {
            var series = d.Latency.GetSeries(kind, 21);
            var r = LatencyAlerts.Evaluate(series, _settings.LatencyBadMs);
            if (r.Spike is { } spike)
            {
                _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.LatencySpike, $"Latency spike on {d.DisplayName}",
                    $"{kind} RTT {spike.Last:0.##} ms vs median {spike.Median:0.##} ms", d.Mac, spike.Last), TimeSpan.FromMinutes(5));
            }
            if (r.LossPercent is { } loss)
            {
                _alerts.Raise(Alert.Create(loss >= 50 ? AlertSeverity.Warning : AlertSeverity.Info, AlertKind.PacketLoss, $"Packet loss to {d.DisplayName}",
                    $"{loss:0}% of the last {LatencyAlerts.LossWindow} {kind} probes were lost", d.Mac, loss), TimeSpan.FromMinutes(5));
            }
        }
    }

    private void UpdateLinkLatencies(ScanContext ctx)
    {
        try
        {
            var links = _topology.Links;
            if (links.Count == 0) return;
            var changed = LinkLatencyCalculator.Apply(links, m => _devices.TryGet(m, out var d) ? d : null, ctx.LocalMac, GetMeasuredPair);
            if (changed) _topology.NotifyChanged();
        }
        catch (Exception ex) { _log.LogDebug(ex, "link latency update failed"); }
    }

    private PairLatency? GetMeasuredPair(Mac a, Mac b)
    {
        var p = _topology.GetPairLatency(a, b);
        return p is { Origin: LatencyOrigin.Measured } ? p : _passive?.TryGet(a, b);
    }

    public async Task<PairLatency?> MeasurePairAsync(Mac from, Mac to, CancellationToken ct)
    {
        try
        {
            if (from == to) return null;
            _devices.TryGet(from, out var a);
            _devices.TryGet(to, out var b);

            // 1. ask the device itself (SNMP DISMAN-PING etc.)
            var pinger = _sp.GetService<IRemotePinger>();
            if (pinger is not null && a is not null && b is not null && HasSnmp(a) && (b.PrimaryIPv4 ?? b.IPv6.FirstOrDefault()?.Address) is { } target)
            {
                try
                {
                    var ms = await pinger.PingFromAsync(a, target, ct).ConfigureAwait(false);
                    if (ms is { } v) return Store(new PairLatency(from, to, Math.Round(v, 3), LatencyOrigin.Measured, "snmp-ping", DateTimeOffset.Now));
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogDebug(ex, "remote ping {From}->{To} failed", from, to); }
            }

            // 2. passively timed handshakes between the two
            if (_passive?.TryGet(from, to) is { } passive) return Store(passive with { From = from, To = to });

            // 3. estimate from the topology path
            var est = EstimatePair(_topology.Links, from, to);
            return est is null ? null : Store(est);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "MeasurePair {From}->{To} failed", from, to);
            return null;
        }
    }

    /// <summary>Estimated deviceâ†”device latency as the topology path sum.</summary>
    public static PairLatency? EstimatePair(IEnumerable<Link> links, Mac from, Mac to)
    {
        var path = PathLatency.ShortestPath(links, from, to);
        if (path is null) return null;
        return new PairLatency(from, to, Math.Max(LinkLatencyCalculator.FloorMs, path.Ms), LatencyOrigin.Estimated, $"path-sum ({path.Hops} hops)", DateTimeOffset.Now);
    }

    private PairLatency Store(PairLatency p)
    {
        // never overwrite a recent measurement with an estimate
        var existing = _topology.GetPairLatency(p.From, p.To);
        if (p.Origin == LatencyOrigin.Estimated && existing is { Origin: LatencyOrigin.Measured } && DateTimeOffset.Now - existing.Time < TimeSpan.FromMinutes(10))
            return existing;
        _topology.SetPairLatency(p);
        return p;
    }

    private static bool HasSnmp(Device d) =>
        d.Evidence.Any(e => e.Source.Contains("snmp", StringComparison.OrdinalIgnoreCase)) ||
        d.Properties.Keys.Any(k => k.StartsWith("snmp", StringComparison.OrdinalIgnoreCase) || k.StartsWith("sys", StringComparison.OrdinalIgnoreCase)) ||
        d.Services.Any(s => s.Name.Contains("snmp", StringComparison.OrdinalIgnoreCase) || s.Port == 161) ||
        d.Ports.Any(p => p.Port == 161 && p.State == PortState.Open);
}

/// <summary>Pure alert rules over a latency series (testable).</summary>
public static class LatencyAlerts
{
    public const int LossWindow = 20;
    public const double LossThresholdPercent = 20;

    public readonly record struct SpikeInfo(double Last, double Median);
    public readonly record struct Result(SpikeInfo? Spike, double? LossPercent);

    /// <param name="series">Oldest first; the last element is the newest sample.</param>
    public static Result Evaluate(IReadOnlyList<LatencySample> series, double badMs)
    {
        SpikeInfo? spike = null;
        double? loss = null;
        if (series.Count >= 6 && series[^1].Ms is { } last)
        {
            var prior = series.Take(series.Count - 1).Where(s => s.Ms.HasValue).Select(s => s.Ms!.Value).OrderBy(x => x).ToArray();
            if (prior.Length >= 5)
            {
                double median = prior.Length % 2 == 1 ? prior[prior.Length / 2] : (prior[prior.Length / 2 - 1] + prior[prior.Length / 2]) / 2;
                if (last > 3 * median && last > badMs) spike = new SpikeInfo(last, median);
            }
        }
        var window = series.Skip(Math.Max(0, series.Count - LossWindow)).ToArray();
        if (window.Length >= LossWindow)
        {
            int ok = window.Count(s => s.Ms.HasValue);
            // a target that never answers this probe type is filtered, not lossy
            if (ok > 0)
            {
                double pct = 100.0 * (window.Length - ok) / window.Length;
                if (pct > LossThresholdPercent) loss = pct;
            }
        }
        return new Result(spike, loss);
    }
}
