using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Diagnostics.Wifi;

/// <summary>
/// "Wired PC checking Wi-Fi": every 5 s, for each access point (DeviceType AccessPoint or the AP end of a WifiAssoc link) it
/// probes the management IP (ICMP, ARP fallback), the AP's upstream switch and up to 8 of its wireless clients round-robin,
/// then runs <see cref="ApDiagnosis"/>. Clients sleep, so a client only counts as unreachable once its last ≥2 probes (ICMP with ARP
/// fallback) failed, and a radio outage additionally needs ≥70% of recently-seen clients unreachable for 30 s. Signals (ApDown/ApClientsUnreachable/ApDegraded) are published on transitions only.
/// </summary>
public sealed class ApHealthMonitor : IApHealthMonitor, IStartable, IDisposable
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan ClientWindow = TimeSpan.FromSeconds(90);
    /// <summary>Clients not seen (passively or by probe) for this long are no longer counted.</summary>
    public static readonly TimeSpan RecentlySeen = TimeSpan.FromMinutes(30);
    public const int ClientsPerCycle = 8;
    /// <summary>A client contributes to the loss figure only after this many probes since its last outage.</summary>
    public const int MinLossSamples = 4;
    public const string SignalSource = "ap-health";
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(1);

    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly IEventBus _bus;
    private readonly ILogger<ApHealthMonitor> _log;
    private readonly IServiceProvider? _services;
    private readonly object _sync = new();
    private readonly Dictionary<Mac, ApState> _aps = new();
    private readonly Dictionary<Mac, ClientState> _clients = new();
    private readonly CancellationTokenSource _cts = new();
    private IReadOnlyList<ApHealth> _list = [];
    private Task? _loop;

    public ApHealthMonitor(IDeviceStore devices, ITopologyStore topology, INetworkState network, IEventBus bus,
        ILogger<ApHealthMonitor> log, IServiceProvider? services = null)
    {
        _devices = devices;
        _topology = topology;
        _network = network;
        _bus = bus;
        _log = log;
        _services = services;
    }

    public ApDiagnosisOptions Options { get; set; } = ApDiagnosisOptions.Default;
    public IReadOnlyList<ApHealth> AccessPoints { get { lock (_sync) return _list; } }
    public event Action? Updated;

    public void Start()
    {
        if (_loop is not null) return;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                try { await RunCycleAsync(DateTimeOffset.Now, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _log.LogDebug(ex, "AP health cycle failed"); }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogWarning(ex, "AP health monitor loop failed"); }
    }

    /// <summary>One probing + diagnosis round (exposed for tests).</summary>
    internal async Task RunCycleAsync(DateTimeOffset now, CancellationToken ct)
    {
        if (_network.IsDemo) return;
        var devices = _devices.All;
        var groups = FindAccessPoints(devices, _topology.Links);
        if (groups.Count == 0)
        {
            bool had;
            lock (_sync) { had = _list.Count > 0; _list = []; _aps.Clear(); _clients.Clear(); }
            if (had) RaiseUpdated();
            return;
        }

        var byMac = devices.ToDictionary(d => d.Mac);
        var results = await Task.WhenAll(groups.Select(g => CheckApAsync(g.Ap, g.Clients, byMac, now, ct))).ConfigureAwait(false);

        lock (_sync)
        {
            _list = results.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            var live = groups.Select(g => g.Ap.Mac).ToHashSet();
            foreach (var gone in _aps.Keys.Where(k => !live.Contains(k)).ToList()) _aps.Remove(gone);
            var liveClients = groups.SelectMany(g => g.Clients).Select(c => c.Mac).ToHashSet();
            foreach (var gone in _clients.Keys.Where(k => !liveClients.Contains(k)).ToList()) _clients.Remove(gone);
        }
        RaiseUpdated();
    }

    private async Task<ApHealth> CheckApAsync(Device ap, IReadOnlyList<Device> clients, Dictionary<Mac, Device> byMac, DateTimeOffset now, CancellationToken ct)
    {
        ApState state;
        lock (_sync)
        {
            if (!_aps.TryGetValue(ap.Mac, out state!)) _aps[ap.Mac] = state = new ApState();
        }

        // management, upstream and a round-robin slice of clients, all in parallel
        var ip = ap.PrimaryIPv4;
        var mgmtTask = ip is null ? Task.FromResult<double?>(null) : ProbeAsync(ip, arpFallback: true, ct);

        Device? upstream = ap.UpstreamMac is { } um && byMac.TryGetValue(um, out var ud) ? ud : null;
        var upstreamIp = upstream?.PrimaryIPv4;
        var upTask = upstreamIp is null ? Task.FromResult<double?>(null) : ProbeAsync(upstreamIp, arpFallback: true, ct);

        var slice = new List<Device>();
        if (clients.Count > 0)
        {
            int n = Math.Min(ClientsPerCycle, clients.Count);
            for (int i = 0; i < n; i++) slice.Add(clients[(state.Cursor + i) % clients.Count]);
            state.Cursor = (state.Cursor + n) % clients.Count;
        }
        var clientTasks = slice.Select(c => (Client: c, Task: ProbeAsync(c.PrimaryIPv4!, arpFallback: true, ct))).ToList();

        await Task.WhenAll(clientTasks.Select(t => (Task)t.Task).Append(mgmtTask).Append(upTask)).ConfigureAwait(false);

        double? mgmtRtt = mgmtTask.Result;
        // the management IP must miss two rounds (ICMP and ARP each time) before the AP counts as down
        bool? mgmtUp;
        if (ip is null) { mgmtUp = null; state.MgmtFails = 0; }
        else if (mgmtRtt is not null) { mgmtUp = true; state.MgmtFails = 0; }
        else mgmtUp = ++state.MgmtFails >= 2 ? false : state.LastMgmtUp;
        state.LastMgmtUp = mgmtUp;
        bool? upstreamUp = upstream is null ? null
            : upstreamIp is not null ? upTask.Result is not null
            : upstream.Has(DeviceFlags.Inferred) ? null
            : upstream.State == DeviceState.Online ? true : null;

        // client bookkeeping
        int seen = 0, unreachable = 0, reachable = 0, sent = 0, lost = 0;
        var rtts = new List<double>();
        var jitters = new List<double>();
        var unreachableMacs = new List<Mac>();
        lock (_sync)
        {
            foreach (var (c, t) in clientTasks)
            {
                if (!_clients.TryGetValue(c.Mac, out var cs)) _clients[c.Mac] = cs = new ClientState();
                cs.Add(now, t.Result);
            }
            foreach (var c in clients)
            {
                if (!_clients.TryGetValue(c.Mac, out var cs)) continue; // not probed yet
                cs.Trim(now - ClientWindow);
                var lastSeen = Max(c.LastSeen, cs.LastOk);
                if (now - lastSeen > RecentlySeen) continue;
                seen++;
                switch (cs.Reachability())
                {
                    case false: unreachable++; unreachableMacs.Add(c.Mac); continue;
                    case null: continue;
                }
                reachable++;
                var segment = cs.SinceLastOutage();
                if (segment.Count >= MinLossSamples)
                {
                    sent += segment.Count;
                    lost += segment.Count(p => p.Rtt is null);
                }
                var r = segment.Where(p => p.Rtt is not null).Select(p => p.Rtt!.Value).ToList();
                rtts.AddRange(r);
                if (r.Count >= 2) jitters.Add(r.Zip(r.Skip(1), (a, b) => Math.Abs(b - a)).Average());
            }
        }

        bool outageNow = seen >= Options.MinClientsForOutage && unreachable >= Math.Ceiling(seen * Options.OutageFraction - 1e-9);
        if (outageNow) state.OutageSince ??= now; else state.OutageSince = null;

        var (channel, otherBss) = ChannelOf(ap.Mac, _network.WifiNetworks);
        var (hostOnAp, radioOk, gwOk) = HostLink(ap.Mac);

        var obs = new ApObservation(ap.DisplayName, mgmtUp, mgmtRtt, upstreamUp, upstream?.DisplayName, UpstreamPort(ap, upstream),
            seen, unreachable, reachable, state.OutageSince is { } since ? now - since : TimeSpan.Zero,
            sent == 0 ? 0 : 100.0 * lost / sent, jitters.Count == 0 ? null : jitters.Average(), rtts.Count == 0 ? null : rtts.Average(),
            channel, otherBss, hostOnAp, radioOk, gwOk);
        var verdict = ApDiagnosis.Evaluate(obs, Options);

        if (verdict.Signal != state.LastSignal)
        {
            state.LastSignal = verdict.Signal;
            if (verdict.Signal is { } kind)
            {
                IReadOnlyList<Mac> affected = kind == SignalKind.ApClientsUnreachable ? unreachableMacs : clients.Select(c => c.Mac).ToList();
                var port = kind == SignalKind.ApDown ? obs.UpstreamPort : null;
                try
                {
                    _bus.Publish(DiagnosticSignal.Create(kind, SignalSource, $"{ap.DisplayName}: {verdict.Diagnosis}", ap.Mac, port, verdict.Weight, affected));
                }
                catch (Exception ex) { _log.LogDebug(ex, "Publishing AP signal failed"); }
                _log.LogInformation("AP {Ap}: {Diagnosis}", ap.DisplayName, verdict.Diagnosis);
            }
        }

        return new ApHealth(ap.Mac, ap.DisplayName, ip, mgmtUp, mgmtRtt, seen, reachable, obs.AvgClientRttMs,
            Math.Round(obs.ClientLossPercent, 1), verdict.Health, verdict.Diagnosis, now);
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset? b) => b is { } v && v > a ? v : a;

    private string? UpstreamPort(Device ap, Device? upstream)
    {
        if (upstream is null) return ap.UpstreamPort;
        foreach (var l in _topology.LinksOf(ap.Mac))
            if (l.Kind != LinkKind.WifiAssoc && l.Other(ap.Mac) == upstream.Mac && l.PortOf(upstream.Mac) is { } p) return p;
        return ap.UpstreamPort;
    }

    /// <summary>This host's own Wi-Fi view of the AP (from the optional <see cref="IWifiLinkMonitor"/>).</summary>
    private (bool OnAp, bool? RadioOk, bool? GatewayOk) HostLink(Mac ap)
    {
        var link = _services?.GetService<IWifiLinkMonitor>();
        var cur = link?.Current;
        if (link is null || cur is not { Connected: true, Bssid: { } bssid } || !IsSameAp(ap, bssid)) return (false, null, null);
        int weak = _services?.GetService<ISettingsStore>()?.Settings.WifiWeakRssiDbm ?? -75;
        var recent = link.History.Where(s => s.Time >= cur.Time - TimeSpan.FromSeconds(10)).ToList();
        bool radioOk = cur.RssiDbm >= weak && (cur.ApRttMs is not null || recent.Any(s => s.ApRttMs is not null));
        // only judge the gateway when it normally answers (some routers drop ICMP)
        bool gwKnown = link.History.Any(s => s.GatewayRttMs is not null);
        bool? gwOk = !gwKnown || recent.Count < 5 ? null : recent.Any(s => s.GatewayRttMs is not null);
        return (true, radioOk, gwOk);
    }

    // ------------------------------------------------------------------ probing

    private async Task<double?> ProbeAsync(IPAddress ip, bool arpFallback, CancellationToken ct)
    {
        try
        {
            var prober = _services?.GetService<ILatencyProber>();
            if (prober is not null)
            {
                var icmp = await prober.IcmpPingAsync(ip, ProbeTimeout, ct).ConfigureAwait(false);
                if (icmp is not null || !arpFallback) return icmp;
                var (arp, _) = await prober.ArpPingAsync(ip, ProbeTimeout, ct).ConfigureAwait(false);
                return arp;
            }
            using var ping = new Ping();
            long t0 = Stopwatch.GetTimestamp();
            var reply = await ping.SendPingAsync(ip, ProbeTimeout, null, null, ct).ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? Stopwatch.GetElapsedTime(t0).TotalMilliseconds : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    // ------------------------------------------------------------------ pure helpers

    /// <summary>Access points and their pingable wireless clients, from device types, WifiAssoc links and upstream pointers.</summary>
    internal static IReadOnlyList<(Device Ap, IReadOnlyList<Device> Clients)> FindAccessPoints(IReadOnlyList<Device> devices, IReadOnlyList<Link> links)
    {
        var byMac = devices.ToDictionary(d => d.Mac);
        var aps = new Dictionary<Mac, Device>();
        var clients = new Dictionary<Mac, Dictionary<Mac, Device>>();

        void AddAp(Device d) { if (Eligible(d)) aps.TryAdd(d.Mac, d); }
        void AddClient(Device ap, Device c)
        {
            if (!aps.ContainsKey(ap.Mac) || c == ap || !Eligible(c) || c.Has(DeviceFlags.ThisHost) || c.PrimaryIPv4 is null) return;
            if (!clients.TryGetValue(ap.Mac, out var set)) clients[ap.Mac] = set = new();
            set.TryAdd(c.Mac, c);
        }

        foreach (var d in devices) if (d.Type == DeviceType.AccessPoint) AddAp(d);
        var assoc = new List<(Device Ap, Device Client)>();
        foreach (var l in links)
        {
            if (l.Kind != LinkKind.WifiAssoc || !byMac.TryGetValue(l.A, out var a) || !byMac.TryGetValue(l.B, out var b)) continue;
            (Device Ap, Device Client)? pair =
                a.Type == DeviceType.AccessPoint ? (a, b)
                : b.Type == DeviceType.AccessPoint ? (b, a)
                : IsWirelessClient(a) && !IsWirelessClient(b) ? (b, a)
                : IsWirelessClient(b) && !IsWirelessClient(a) ? (a, b)
                : null;
            if (pair is not { } p) continue;
            AddAp(p.Ap);
            assoc.Add(p);
        }
        foreach (var (ap, c) in assoc) AddClient(ap, c);
        foreach (var d in devices)
            if (d.UpstreamMac is { } up && aps.TryGetValue(up, out var ap) && d.Type is not (DeviceType.AccessPoint or DeviceType.AccessSwitch or DeviceType.CoreSwitch or DeviceType.UnmanagedSwitch or DeviceType.Router))
                AddClient(ap, d);

        return aps.Values
            .Select(ap => (ap, (IReadOnlyList<Device>)(clients.TryGetValue(ap.Mac, out var s) ? s.Values.OrderBy(c => c.Mac).ToList() : [])))
            .ToList();

        static bool Eligible(Device d) => !d.Has(DeviceFlags.Inferred) && !SyntheticNodes.IsSynthetic(d.Mac);
        static bool IsWirelessClient(Device d) => d.Has(DeviceFlags.WifiClient) || d.Has(DeviceFlags.ThisHost);
    }

    /// <summary>The AP's channel (strongest own BSSID in the scan) and how many other BSSIDs share it.</summary>
    internal static (int? Channel, int OtherBss) ChannelOf(Mac ap, IReadOnlyList<WifiNetwork> nets)
    {
        var own = nets.Where(n => IsSameAp(ap, n.Bssid)).OrderByDescending(n => n.RssiDbm).FirstOrDefault();
        if (own is null || own.Channel == 0) return (null, 0);
        int others = nets.Count(n => n.Channel == own.Channel && n.Band == own.Band && !IsSameAp(ap, n.Bssid));
        return (own.Channel, others);
    }

    /// <summary>BSSID belongs to the AP: same OUI within ±8, also with the locally-administered bit cleared.</summary>
    internal static bool IsSameAp(Mac ap, Mac bssid)
    {
        if (Near(ap, bssid)) return true;
        const ulong Laa = 0x0200_0000_0000UL;
        return Near(new Mac(ap.Value & ~Laa), new Mac(bssid.Value & ~Laa));

        static bool Near(Mac a, Mac b) => a.Oui24 == b.Oui24 && Math.Abs((long)a.Value - (long)b.Value) <= 8;
    }

    private void RaiseUpdated()
    {
        try { Updated?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "AP health Updated handler failed"); }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }

    private sealed class ApState
    {
        public int Cursor;
        public int MgmtFails;
        public bool? LastMgmtUp;
        public DateTimeOffset? OutageSince;
        public SignalKind? LastSignal;
    }

    private sealed class ClientState
    {
        public readonly List<(DateTimeOffset Time, double? Rtt)> Probes = new();
        public DateTimeOffset? LastOk;

        public void Add(DateTimeOffset t, double? rtt)
        {
            Probes.Add((t, rtt));
            if (rtt is not null) LastOk = t;
        }

        public void Trim(DateTimeOffset cutoff) => Probes.RemoveAll(p => p.Time < cutoff);

        /// <summary>2-of-N rule: false when the last ≥2 probes failed, true when the latest probe (or the one before a single miss) answered, null when undecided.</summary>
        public bool? Reachability()
        {
            int trailing = 0;
            for (int i = Probes.Count - 1; i >= 0 && Probes[i].Rtt is null; i--) trailing++;
            if (trailing >= 2) return false;
            if (trailing == Probes.Count) return null; // no answer yet (0 or 1 probes, all failed)
            return true;
        }

        /// <summary>Probes after the last run of ≥2 consecutive failures, so loss after an outage reflects the link now.</summary>
        public List<(DateTimeOffset Time, double? Rtt)> SinceLastOutage()
        {
            int start = 0, run = 0;
            for (int i = 0; i < Probes.Count; i++)
            {
                if (Probes[i].Rtt is null) { run++; continue; }
                if (run >= 2) start = i;
                run = 0;
            }
            return Probes.GetRange(start, Probes.Count - start);
        }
    }
}
