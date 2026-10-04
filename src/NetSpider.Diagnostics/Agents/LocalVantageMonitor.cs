using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

/// <summary>One of this PC's adapters used as a built-in vantage point.</summary>
public sealed record LocalVantage(string Name, string Medium, IPAddress Ip, int PrefixLength, IPAddress? Gateway, string? Mac)
{
    public string AgentId => ProbeAgentHub.LocalAgentPrefix + Name;
    public bool IsWifi => Medium == "Wi-Fi";
}

/// <summary>
/// Dual-interface self-test. When this PC has two or more eligible adapters up (typically wired + Wi-Fi), every 2 s it
/// pings from each adapter's own source address (<see cref="SourceBoundPing"/>) to: its gateway, the other adapters'
/// gateways, 1.1.1.1 and the other adapters' own IPs (the crossover path). Results are fed to the
/// <see cref="ProbeAgentHub"/> as synthetic agents <c>local:&lt;adapter&gt;</c>, so they appear in
/// <see cref="IProbeAgentHub.Agents"/> and reuse the failure/recovery signal logic, with path-naming summaries from
/// <see cref="DualPathVerdict"/>. Runs automatically (set <see cref="Enabled"/> = false to opt out); idle with fewer
/// than two adapters. Windows only (source-bound ICMP via iphlpapi).
/// </summary>
public sealed class LocalVantageMonitor : IStartable, IDisposable
{
    private static readonly TimeSpan RoundEvery = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan AdaptersEvery = TimeSpan.FromSeconds(30);
    private static readonly IPAddress InternetTarget = IPAddress.Parse("1.1.1.1");
    private const int Window = 10;
    private const int TimeoutMs = 1000;

    private readonly ProbeAgentHub _hub;
    private readonly ILogger<LocalVantageMonitor> _log;
    private readonly object _sync = new();
    private readonly Dictionary<(string Agent, string Target), TargetWindow> _windows = new();
    private readonly Dictionary<string, IReadOnlyList<ProbeTargetResult>> _latest = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<(string Agent, string Target)> _everReached = new();
    private IReadOnlyList<LocalVantage> _vantages = [];
    private DateTimeOffset _adaptersAt = DateTimeOffset.MinValue;
    private volatile bool _adaptersDirty = true;
    private DualPathVerdictResult? _verdict;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _enabled = true;
    private static readonly TimeSpan RawEvery = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RawFresh = TimeSpan.FromSeconds(90);
    private readonly Dictionary<(string FromAgent, string ToName), CrossoverResult> _raw = new();
    private DateTimeOffset _rawAt = DateTimeOffset.MinValue;
    private int _rawBusy;

    public LocalVantageMonitor(ProbeAgentHub hub, ILogger<LocalVantageMonitor> log)
    {
        _hub = hub;
        _log = log;
    }

    /// <summary>Opt-out toggle (default on). The monitor only sends traffic while ≥ 2 eligible adapters are up.</summary>
    public bool Enabled
    {
        get => _enabled;
        set { _enabled = value; if (value) StartLoop(); else StopLoop(); }
    }

    public bool IsRunning => _loop is { IsCompleted: false };
    /// <summary>True while at least two eligible adapters are being probed.</summary>
    public bool IsActive { get { lock (_sync) return _vantages.Count >= 2; } }
    public IReadOnlyList<LocalVantage> Vantages { get { lock (_sync) return _vantages; } }
    /// <summary>Latest wired-vs-Wi-Fi verdict (null unless one wired and one Wi-Fi adapter are active).</summary>
    public DualPathVerdictResult? Verdict { get { lock (_sync) return _verdict; } }
    /// <summary>Latest raw (Npcap, on-the-wire) crossover results, both directions. Empty without Npcap or without wired+Wi-Fi.</summary>
    public IReadOnlyList<CrossoverResult> Crossover { get { lock (_sync) return _raw.Values.ToList(); } }
    public event Action? Updated;

    public void Start()
    {
        if (!OperatingSystem.IsWindows()) { _log.LogDebug("Local vantage monitor needs Windows; not started"); return; }
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
        if (_enabled) StartLoop();
    }

    private void OnAddressChanged(object? sender, EventArgs e) => _adaptersDirty = true;

    private void StartLoop()
    {
        lock (_sync)
        {
            if (IsRunning || !OperatingSystem.IsWindows()) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            _loop = Task.Run(() => LoopAsync(ct));
        }
    }

    private void StopLoop()
    {
        Task? loop;
        lock (_sync)
        {
            _cts?.Cancel();
            loop = _loop;
        }
        try { loop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        lock (_sync)
        {
            _cts?.Dispose();
            _cts = null;
            _loop = null;
        }
        SetVantages([]);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            try
            {
                if (_adaptersDirty || DateTimeOffset.Now - _adaptersAt > AdaptersEvery)
                {
                    _adaptersDirty = false;
                    _adaptersAt = DateTimeOffset.Now;
                    SetVantages(FindVantages());
                }
                if (IsActive) { MaybeStartRawCrossover(ct); await RoundAsync(ct).ConfigureAwait(false); }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Local vantage round failed"); }

            var wait = RoundEvery - Stopwatch.GetElapsedTime(started);
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private void SetVantages(IReadOnlyList<LocalVantage> next)
    {
        if (next.Count < 2) next = [];
        IReadOnlyList<LocalVantage> old;
        lock (_sync)
        {
            old = _vantages;
            if (old.SequenceEqual(next)) return;
            _vantages = next;
            _windows.Clear();
            _latest.Clear();
            _everReached.Clear();
            _verdict = null;
        }
        foreach (var gone in old) _hub.RemoveAgent(gone.AgentId);
        if (next.Count >= 2)
            _log.LogInformation("Local vantages active: {Adapters}", string.Join(", ", next.Select(v => $"{v.Name} ({v.Medium}, {v.Ip})")));
        else if (old.Count >= 2)
            _log.LogInformation("Local vantages idle (fewer than two eligible adapters)");
        RaiseUpdated();
    }

    // ---------------------------------------------------------------------------------------------

    /// <summary>Up, non-virtual, non-loopback adapters with a routable IPv4 that have a gateway or share a subnet with another one.</summary>
    public static IReadOnlyList<LocalVantage> FindVantages()
    {
        var candidates = new List<LocalVantage>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (AdapterCatalog.ClassifyVirtual(nic.Description + " " + nic.Name) is not null) continue;
                IPInterfaceProperties props;
                try { props = nic.GetIPProperties(); } catch { continue; }
                var uni = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IsLinkLocal(u.Address));
                if (uni is null) continue;
                var gw = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
                string? mac = macBytes.Length == 6 ? Mac.FromBytes(macBytes).ToString() : null;
                candidates.Add(new LocalVantage(nic.Name, nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "Wi-Fi" : "Wired",
                    uni.Address, uni.PrefixLength, gw, mac));
            }
        }
        catch { return []; }
        return Eligible(candidates);
    }

    /// <summary>Keeps adapters with a gateway or sharing a subnet with another candidate; wired first.</summary>
    public static IReadOnlyList<LocalVantage> Eligible(IReadOnlyList<LocalVantage> candidates) =>
        candidates.Where(c => c.Gateway is not null || candidates.Any(o => o != c && SameSubnet(c, o)))
            .OrderBy(c => c.IsWifi).ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();

    private static bool IsLinkLocal(IPAddress ip) { var b = ip.GetAddressBytes(); return b[0] == 169 && b[1] == 254; }

    private static bool SameSubnet(LocalVantage a, LocalVantage b)
    {
        int prefix = Math.Min(a.PrefixLength, b.PrefixLength);
        if (prefix <= 0) return false;
        uint mask = prefix >= 32 ? uint.MaxValue : uint.MaxValue << (32 - prefix);
        return (ToUInt(a.Ip) & mask) == (ToUInt(b.Ip) & mask);
    }

    private static uint ToUInt(IPAddress a) { var b = a.GetAddressBytes(); return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]); }

    /// <summary>The targets one adapter probes: own gateway, the others' gateways, the internet, the others' own IPs.</summary>
    public static IReadOnlyList<(string Target, IPAddress Ip)> TargetsFor(LocalVantage v, IReadOnlyList<LocalVantage> all)
    {
        var list = new List<(string, IPAddress)>();
        if (v.Gateway is not null) list.Add((DualPathVerdict.Gateway, v.Gateway));
        foreach (var o in all.Where(o => o != v))
        {
            if (o.Gateway is not null && !o.Gateway.Equals(v.Gateway)) list.Add((DualPathVerdict.PeerGatewayPrefix + o.Name, o.Gateway));
            list.Add((DualPathVerdict.PeerPrefix + o.Name, o.Ip));
        }
        list.Add((DualPathVerdict.Internet, InternetTarget));
        return list;
    }

    /// <summary>
    /// Every 30 s, with a wired and a Wi-Fi vantage and Npcap available, measures the crossover on the wire in both
    /// directions (<see cref="RawCrossoverProbe"/>). In-stack pings between our own IPs never leave the PC, so these
    /// raw results replace the "peer:" ping results whenever they are fresh.
    /// </summary>
    private void MaybeStartRawCrossover(CancellationToken ct)
    {
        var vantages = Vantages;
        var wired = vantages.FirstOrDefault(v => !v.IsWifi);
        var wifi = vantages.FirstOrDefault(v => v.IsWifi);
        if (wired is null || wifi is null || DateTimeOffset.Now - _rawAt < RawEvery) return;
        if (Interlocked.Exchange(ref _rawBusy, 1) == 1) return;
        _rawAt = DateTimeOffset.Now;
        _ = Task.Run(async () =>
        {
            try
            {
                if (!RawCrossoverProbe.Available) return;
                var probe = new RawCrossoverProbe(_log);
                foreach (var (from, to) in new[] { (wired, wifi), (wifi, wired) })
                {
                    var r = await probe.MeasureAsync(from, to, 5, ct).ConfigureAwait(false);
                    lock (_sync) _raw[(from.AgentId, to.Name)] = r;
                    _log.LogDebug("Raw crossover {From} → {To}: {Received}/{Sent}, one-way {Ms} ms {Error}", r.From, r.To, r.Received, r.Sent, r.OneWayAvgMs, r.Error);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "Raw crossover failed"); }
            finally { Volatile.Write(ref _rawBusy, 0); }
        }, ct);
    }

    /// <summary>Fresh raw crossover result for a "peer:" target, if any.</summary>
    private CrossoverResult? RawFor(LocalVantage from, string target)
    {
        if (!target.StartsWith(DualPathVerdict.PeerPrefix, StringComparison.Ordinal)) return null;
        lock (_sync)
            return _raw.TryGetValue((from.AgentId, target[DualPathVerdict.PeerPrefix.Length..]), out var r)
                   && DateTimeOffset.Now - r.Time < RawFresh && r.Sent > 0 ? r : null;
    }

    private async Task RoundAsync(CancellationToken ct)
    {
        var vantages = Vantages;
        if (vantages.Count < 2) return;
        var now = DateTimeOffset.Now;

        var work = vantages.SelectMany(v => TargetsFor(v, vantages).Select(t => (Vantage: v, t.Target, t.Ip))).ToList();
        var measured = await Task.WhenAll(work.Select(async w =>
        {
            if (RawFor(w.Vantage, w.Target) is { } raw)
            {
                // on-the-wire result: one-way latency, a lost run counts as a real failure (not a host firewall)
                // a raw result is trustworthy either way (no host firewall involved), so it always feeds the verdict
                lock (_sync) _everReached.Add((w.Vantage.AgentId, w.Target));
                return (w.Vantage, w.Target, w.Ip, Ms: raw.Ok ? raw.OneWayAvgMs : null,
                    Error: raw.Ok ? (string?)null : $"raw crossover: {raw.Error} ({raw.Via})");
            }
            var (ms, err) = await SourceBoundPing.IcmpAsync(w.Vantage.Ip, w.Ip, TimeoutMs, ct).ConfigureAwait(false);
            if (ms is null && !w.Target.StartsWith(DualPathVerdict.PeerPrefix, StringComparison.Ordinal))
            {
                var (tcpMs, _) = await SourceBoundPing.TcpAsync(w.Vantage.Ip, w.Ip, TimeSpan.FromMilliseconds(TimeoutMs), ct).ConfigureAwait(false);
                if (tcpMs is not null) (ms, err) = (tcpMs, null);
            }
            return (w.Vantage, w.Target, w.Ip, Ms: ms, Error: err);
        })).ConfigureAwait(false);

        var reports = new List<(LocalVantage Vantage, ProbeAgentReport Report)>();
        lock (_sync)
        {
            if (!ReferenceEquals(vantages, _vantages)) return; // adapters changed meanwhile
            foreach (var v in vantages)
            {
                var results = measured.Where(m => m.Vantage == v).Select(m =>
                {
                    var key = (v.AgentId, m.Target);
                    if (!_windows.TryGetValue(key, out var win)) _windows[key] = win = new TargetWindow();
                    if (m.Ms is not null) _everReached.Add(key);
                    return win.Record(m.Target, m.Ip, m.Ms, m.Error);
                }).ToList();
                _latest[v.AgentId] = results;
                reports.Add((v, new ProbeAgentReport(v.AgentId, $"This PC ({v.Name})", v.Ip.ToString(), v.Mac, v.Medium, now, results, null,
                    v.Gateway?.ToString(), "local")));
            }
            var wired = vantages.FirstOrDefault(v => !v.IsWifi);
            var wifi = vantages.FirstOrDefault(v => v.IsWifi);
            _verdict = wired is not null && wifi is not null
                ? DualPathVerdict.Evaluate(VerdictInput(wired), VerdictInput(wifi), wired.Ip.ToString(), wifi.Ip.ToString())
                : null;
        }

        foreach (var (v, report) in reports) _hub.IngestLocal(report, (r, failure) => Describe(v, vantages, r, failure));
        RaiseUpdated();
    }

    /// <summary>
    /// Crossover results only count once they have answered at least once: a host firewall that drops ICMP on the
    /// other adapter's profile would otherwise look like an AP/LAN bridging fault. Call under <see cref="_sync"/>.
    /// </summary>
    private IReadOnlyList<ProbeTargetResult> VerdictInput(LocalVantage v) =>
        _latest[v.AgentId].Where(r => !r.Target.StartsWith(DualPathVerdict.PeerPrefix, StringComparison.Ordinal) || _everReached.Contains((v.AgentId, r.Target))).ToList();

    /// <summary>Signal text for a local transition: the dual-path verdict when it explains it, else a plain path sentence.</summary>
    private (string Summary, double Weight) Describe(LocalVantage v, IReadOnlyList<LocalVantage> all, ProbeTargetResult r, bool failure)
    {
        var self = $"{(v.IsWifi ? "Wi-Fi" : "wired")} adapter {v.Name} ({v.Ip})";
        var what = Describe(r);
        if (!failure) return ($"{self} reaches {what} again", 0.2);

        var verdict = Verdict;
        if (verdict is { Suspect: not (DualPathSuspect.Ok or DualPathSuspect.Inconclusive) }) return (verdict.Sentence, 0.6);

        // which other adapters still reach the same address?
        List<string> others;
        lock (_sync)
            others = all.Where(o => o != v && _latest.TryGetValue(o.AgentId, out var rs) &&
                                    rs.Any(x => x.Ip == r.Ip && x.RttMs is not null && x.LossPercent < AgentSignalLogic.FailLossPercent))
                .Select(o => $"{(o.IsWifi ? "Wi-Fi" : "wired")} adapter {o.Name}").ToList();
        return others.Count > 0
            ? ($"{self} cannot reach {what}, {string.Join(", ", others)} can → problem on the {(v.IsWifi ? "Wi-Fi" : "wired")} side of this PC", 0.6)
            : ($"{self} cannot reach {what}", 0.5);
    }

    private static string Describe(ProbeTargetResult r) => r.Target switch
    {
        DualPathVerdict.Gateway => $"its gateway {r.Ip}",
        DualPathVerdict.Internet => $"the internet ({r.Ip})",
        var t when t.StartsWith(DualPathVerdict.PeerPrefix, StringComparison.Ordinal) => $"this PC's {t[DualPathVerdict.PeerPrefix.Length..]} adapter ({r.Ip})",
        var t when t.StartsWith(DualPathVerdict.PeerGatewayPrefix, StringComparison.Ordinal) => $"the {t[DualPathVerdict.PeerGatewayPrefix.Length..]} gateway {r.Ip}",
        _ => r.Target,
    };

    private void RaiseUpdated()
    {
        try { Updated?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "Local vantage subscriber failed"); }
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnAddressChanged;
        StopLoop();
    }

    private sealed class TargetWindow
    {
        private readonly Queue<double?> _q = new();
        public ProbeTargetResult Record(string target, IPAddress ip, double? ms, string? error)
        {
            _q.Enqueue(ms);
            while (_q.Count > Window) _q.Dequeue();
            var ok = _q.Where(x => x is not null).Select(x => x!.Value).ToList();
            double loss = Math.Round(100.0 * (_q.Count - ok.Count) / _q.Count, 1);
            return new ProbeTargetResult(target, ip.ToString(), ms, ok.Count > 0 ? Math.Round(ok.Average(), 2) : null, loss, _q.Count, error);
        }
    }
}
