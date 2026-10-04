using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

/// <summary>
/// Receives signed UDP reports from NetSpider.Probe agents (second vantage points) while
/// <see cref="AppSettings.ProbeAgentHubEnabled"/> is on (off by default). Tracks each agent's latest report and
/// online state, registers agents as devices, pings every online agent back (LAN → agent) and publishes
/// <see cref="SignalKind.AgentReportFailure"/>, <see cref="SignalKind.AgentReportRecovered"/> and
/// <see cref="SignalKind.AgentOffline"/> signals. Also answers key-authenticated discovery broadcasts on UDP 47811.
/// </summary>
public sealed class ProbeAgentHub : IProbeAgentHub, IStartable, IDisposable
{
    private const string Source = "ProbeAgent";
    private static readonly TimeSpan MonitorEvery = TimeSpan.FromSeconds(2);
    private const int ReverseWindow = 15;
    private const int PingTimeoutMs = 1000;

    private readonly ISettingsStore _settingsStore;
    private readonly IDeviceStore _devices;
    private readonly IEventBus _bus;
    private readonly IAlertService _alerts;
    private readonly ILogger<ProbeAgentHub> _log;

    private readonly object _sync = new();       // agent state
    private readonly object _lifecycle = new();  // sockets / loops
    private readonly Dictionary<string, AgentState> _agents = new(StringComparer.OrdinalIgnoreCase);
    private readonly ReplayCache _replay = new();
    private volatile byte[]? _key;
    private UdpClient? _udp, _discovery;
    private CancellationTokenSource? _cts;
    private readonly List<Task> _loops = [];
    private int _configuredPort, _boundPort;
    private long _accepted, _rejected;
    private DateTimeOffset _lastRejectWarning = DateTimeOffset.MinValue;
    private (DateTimeOffset At, string Name) _hubName = (DateTimeOffset.MinValue, "this PC");
    private bool _disposed;

    private readonly INetworkState? _network;

    /// <summary>While the demo network is shown, agent reports are still tracked but never touch the device store, alerts or signals.</summary>
    private bool Quiet => _network?.IsDemo == true;

    public ProbeAgentHub(ISettingsStore settingsStore, IDeviceStore devices, IEventBus bus, IAlertService alerts, ILogger<ProbeAgentHub> log,
        INetworkState? network = null)
    {
        _network = network;
        _settingsStore = settingsStore;
        _devices = devices;
        _bus = bus;
        _alerts = alerts;
        _log = log;
    }

    private AppSettings Settings => _settingsStore.Settings;

    /// <summary>UDP port for discovery requests (default 47811). 0 binds an ephemeral port (tests), negative disables discovery.</summary>
    public int DiscoveryPort { get; init; } = AgentProtocol.DiscoveryPort;
    /// <summary>The actually bound discovery port, 0 when not listening for discovery.</summary>
    public int BoundDiscoveryPort { get; private set; }

    public bool IsListening => _udp is not null;
    /// <summary>The bound report port while listening (resolves an ephemeral 0), otherwise the configured one.</summary>
    public int Port => _boundPort != 0 ? _boundPort : Settings.ProbeAgentPort;
    public long ReportsAccepted => Interlocked.Read(ref _accepted);
    public long ReportsRejected => Interlocked.Read(ref _rejected);

    public IReadOnlyList<ProbeAgentInfo> Agents
    {
        get { lock (_sync) return _agents.Values.Select(a => a.Info()).OrderBy(a => a.AgentId, StringComparer.OrdinalIgnoreCase).ToList(); }
    }

    /// <summary>Hub → agent reachability (the hub pings every online agent every 2 s), keyed by agent id.</summary>
    public IReadOnlyDictionary<string, AgentReverseProbe> ReverseReachability
    {
        get { lock (_sync) return _agents.Values.Where(a => a.Reverse.Sent > 0).ToDictionary(a => a.Id, a => a.Reverse.Snapshot(a.Id), StringComparer.OrdinalIgnoreCase); }
    }

    public event Action? Updated;

    public void Start()
    {
        _settingsStore.Saved += ApplySettings;
        ApplySettings();
    }

    /// <summary>Starts/stops listening according to the settings; generates and saves a key on first enable.</summary>
    public void ApplySettings()
    {
        try
        {
            lock (_lifecycle)
            {
                if (_disposed) return;
                var s = Settings;
                if (!s.ProbeAgentHubEnabled)
                {
                    if (IsListening) { StopListening(); _log.LogInformation("Probe agent hub stopped"); RaiseUpdated(); }
                    return;
                }

                if (string.IsNullOrWhiteSpace(s.ProbeAgentKey))
                {
                    s.ProbeAgentKey = AgentProtocol.GenerateKey();
                    _log.LogInformation("Generated a new probe agent key");
                    try { _settingsStore.Save(); } // raises Saved -> re-enters ApplySettings (same thread, re-entrant lock)
                    catch (Exception ex) { _log.LogWarning(ex, "Could not save the generated probe agent key"); }
                }
                if (!AgentProtocol.TryParseKey(s.ProbeAgentKey, out var key))
                {
                    _log.LogError("ProbeAgentKey is not valid base64 (>= 16 bytes); the probe agent hub stays off");
                    if (IsListening) { StopListening(); RaiseUpdated(); }
                    return;
                }
                _key = key;

                int port = s.ProbeAgentPort;
                if (IsListening && port == _configuredPort) return;
                if (IsListening) StopListening();
                StartListening(port);
            }
            RaiseUpdated();
        }
        catch (Exception ex) { _log.LogWarning(ex, "Applying probe agent hub settings failed"); }
    }

    private void StartListening(int port)
    {
        UdpClient udp;
        try
        {
            udp = new UdpClient(AddressFamily.InterNetwork);
            DisableConnReset(udp.Client);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Probe agent hub cannot listen on UDP {Port}", port);
            return;
        }
        _udp = udp;
        _configuredPort = port;
        _boundPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loops.Add(Task.Run(() => ReceiveLoopAsync(udp, ct)));
        _loops.Add(Task.Run(() => MonitorLoopAsync(ct)));

        if (DiscoveryPort >= 0)
        {
            try
            {
                var disc = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
                DisableConnReset(disc.Client);
                disc.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                disc.Client.Bind(new IPEndPoint(IPAddress.Any, DiscoveryPort));
                _discovery = disc;
                BoundDiscoveryPort = ((IPEndPoint)disc.Client.LocalEndPoint!).Port;
                _loops.Add(Task.Run(() => DiscoveryLoopAsync(disc, ct)));
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Probe agent discovery is unavailable (UDP {Port}); agents need --hub", DiscoveryPort);
            }
        }
        _log.LogInformation("Probe agent hub listening on UDP {Port} (discovery {Discovery})", _boundPort,
            BoundDiscoveryPort != 0 ? BoundDiscoveryPort.ToString() : "off");
    }

    private void StopListening()
    {
        _cts?.Cancel();
        try { _udp?.Dispose(); } catch { }
        try { _discovery?.Dispose(); } catch { }
        try { Task.WaitAll(_loops.ToArray(), TimeSpan.FromSeconds(3)); } catch { }
        _loops.Clear();
        _cts?.Dispose();
        _cts = null;
        _udp = null;
        _discovery = null;
        _boundPort = 0;
        BoundDiscoveryPort = 0;
    }

    private static void DisableConnReset(Socket s)
    {
        // Windows reports ICMP port-unreachable for a previous send as a receive error on UDP sockets; turn that off.
        if (!OperatingSystem.IsWindows()) return;
        try { s.IOControl(-1744830452 /* SIO_UDP_CONNRESET */, [0, 0, 0, 0], null); } catch { }
    }

    // ---------------------------------------------------------------------------------------------
    //  receive
    // ---------------------------------------------------------------------------------------------

    private async Task ReceiveLoopAsync(UdpClient udp, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult res;
            try { res = await udp.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex)
            {
                if (ct.IsCancellationRequested) break;
                _log.LogDebug(ex, "Probe agent receive error");
                continue;
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _log.LogWarning(ex, "Probe agent receive failed");
                try { await Task.Delay(200, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
                continue;
            }
            try { Ingest(res.Buffer, res.RemoteEndPoint); }
            catch (Exception ex) { _log.LogWarning(ex, "Processing a probe agent report failed"); }
        }
    }

    private async Task DiscoveryLoopAsync(UdpClient disc, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var res = await disc.ReceiveAsync(ct).ConfigureAwait(false);
                var key = _key;
                if (key is null) continue;
                var reply = AgentProtocol.TryBuildDiscoveryReply(res.Buffer, key, Port, _replay, DateTimeOffset.UtcNow);
                if (reply is null) { _log.LogDebug("Ignored discovery request from {From}", res.RemoteEndPoint); continue; }
                await disc.SendAsync(reply, res.RemoteEndPoint, ct).ConfigureAwait(false);
                _log.LogInformation("Answered probe agent discovery from {From}", res.RemoteEndPoint);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _log.LogDebug(ex, "Probe agent discovery error");
            }
        }
    }

    /// <summary>Verifies and processes one datagram (called by the receive loop; public for tests and tools).</summary>
    public AgentOpenResult Ingest(byte[] datagram, IPEndPoint from)
    {
        var key = _key;
        if (key is null) return AgentOpenResult.BadSignature;
        var result = AgentProtocol.Open(datagram, key, DateTimeOffset.UtcNow, _replay, out var report);
        if (result != AgentOpenResult.Ok || report is null)
        {
            Interlocked.Increment(ref _rejected);
            var now = DateTimeOffset.UtcNow;
            if (now - _lastRejectWarning > TimeSpan.FromMinutes(1))
            {
                _lastRejectWarning = now;
                _log.LogWarning("Rejected probe agent datagram from {From}: {Reason}", from, result);
            }
            else _log.LogDebug("Rejected probe agent datagram from {From}: {Reason}", from, result);
            return result;
        }
        Interlocked.Increment(ref _accepted);
        Process(report, from.Address);
        return AgentOpenResult.Ok;
    }

    /// <summary>Prefix of agent ids that stand for this PC's own adapters (<see cref="LocalVantageMonitor"/>).</summary>
    public const string LocalAgentPrefix = "local:";

    /// <summary>
    /// Adds a report produced in-process (a local vantage, no signature). <paramref name="describe"/> builds the signal
    /// summary for a target transition (failure = true / recovery = false) and its weight; null uses the default wording.
    /// </summary>
    public void IngestLocal(ProbeAgentReport report, Func<ProbeTargetResult, bool, (string Summary, double Weight)>? describe = null)
    {
        try
        {
            var ip = IPAddress.TryParse(report.Ip, out var a) ? a : IPAddress.Loopback;
            Process(report, ip, describe);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Processing local vantage report failed"); }
    }

    /// <summary>Forgets an agent without raising AgentOffline (used when a local adapter disappears).</summary>
    public bool RemoveAgent(string agentId)
    {
        bool removed;
        lock (_sync) removed = _agents.Remove(agentId);
        if (removed) RaiseUpdated();
        return removed;
    }

    private static bool IsLocal(string agentId) => agentId.StartsWith(LocalAgentPrefix, StringComparison.OrdinalIgnoreCase);

    private void Process(ProbeAgentReport report, IPAddress source, Func<ProbeTargetResult, bool, (string Summary, double Weight)>? describe = null)
    {
        var now = DateTimeOffset.Now;
        bool isNew, cameBack;
        var transitions = new List<(AgentTargetTransition Kind, ProbeTargetResult Result)>();
        AgentState st;
        lock (_sync)
        {
            isNew = !_agents.TryGetValue(report.AgentId, out st!);
            if (isNew) _agents[report.AgentId] = st = new AgentState(report.AgentId, now);
            cameBack = !isNew && !st.Online;
            st.LastSeen = now;
            st.Online = true;
            st.Source = source;

            bool stale = false;
            if (st.Latest is { } prev && prev.Time == report.Time)
            {
                // another chunk of the same round: merge results by target
                var merged = prev.Results.Where(r => report.Results.All(n => !n.Target.Equals(r.Target, StringComparison.OrdinalIgnoreCase)))
                    .Concat(report.Results).ToArray();
                st.Latest = report with { Results = merged, Wifi = report.Wifi ?? prev.Wifi };
            }
            else if (st.Latest is { } older && report.Time < older.Time) stale = true; // out of order, keep the newer one
            else
            {
                if (st.Latest is { } p)
                {
                    var d = (report.Time - p.Time).TotalSeconds;
                    if (d is > 0 and < 600) st.IntervalSeconds = st.IntervalSeconds is { } iv ? iv * 0.7 + d * 0.3 : d;
                }
                st.Latest = report;
            }

            if (!stale)
            {
                foreach (var r in report.Results)
                {
                    st.Targets.TryGetValue(r.Target, out var prevState);
                    var t = AgentSignalLogic.Evaluate(prevState, r, out var next);
                    st.Targets[r.Target] = next;
                    if (t != AgentTargetTransition.None) transitions.Add((t, r));
                }
            }
        }

        // local vantages are this PC's own adapters: don't relabel this PC's device as an agent
        var agentMac = IsLocal(report.AgentId) || Quiet ? (Mac.TryParse(report.Mac, out var own) ? own : null) : RegisterDevice(report, source);
        lock (_sync) st.Mac = agentMac;

        if (isNew && IsLocal(report.AgentId))
            _log.LogInformation("Local vantage {Agent} active ({Ip}, {Medium})", report.AgentId, report.Ip, report.Medium);
        else if (isNew && !Quiet)
        {
            _log.LogInformation("Probe agent {Agent} registered ({Host}, {Ip}, {Medium}, v{Version})", report.AgentId, report.Hostname, report.Ip ?? source.ToString(), report.Medium, report.Version);
            _alerts.Raise(Alert.Create(AlertSeverity.Info, AlertKind.Info, "Probe agent registered",
                $"Agent {report.AgentId} on {report.Hostname} ({report.Ip ?? source.ToString()}, {report.Medium}) is reporting {report.Results.Count} target(s).", agentMac),
                TimeSpan.FromMinutes(30));
        }
        else if (cameBack) _log.LogInformation("Probe agent {Agent} is reporting again", report.AgentId);

        foreach (var (kind, r) in transitions)
        {
            if (describe is not null)
            {
                var (summary, weight) = describe(r, kind == AgentTargetTransition.Failure);
                _log.Log(kind == AgentTargetTransition.Failure ? LogLevel.Warning : LogLevel.Information, "Local vantage: {Summary}", summary);
                Publish(DiagnosticSignal.Create(kind == AgentTargetTransition.Failure ? SignalKind.AgentReportFailure : SignalKind.AgentReportRecovered,
                    Source, summary, TargetDevice(r), weight: weight, affected: agentMac is { } lm ? [lm] : null));
            }
            else if (kind == AgentTargetTransition.Failure)
            {
                _ = Task.Run(() => PublishFailureAsync(report.AgentId, r, agentMac));
            }
            else
            {
                _log.LogInformation("Probe agent: {Summary}", AgentSignalLogic.RecoveredSummary(report.AgentId, r));
                Publish(DiagnosticSignal.Create(SignalKind.AgentReportRecovered, Source, AgentSignalLogic.RecoveredSummary(report.AgentId, r),
                    TargetDevice(r), weight: 0.2, affected: agentMac is { } m ? [m] : null));
            }
        }
        RaiseUpdated();
    }

    private Mac? RegisterDevice(ProbeAgentReport report, IPAddress source)
    {
        try
        {
            if (!Mac.TryParse(report.Mac, out var mac) || mac.IsZero || mac.IsBroadcast) return null;
            IPAddress? ip = IPAddress.TryParse(report.Ip, out var rip) && !IPAddress.Any.Equals(rip) ? rip : source;
            var device = _devices.Observe(mac, ip, "agent");
            bool changed = device.SetProperty("agent.id", report.AgentId);
            changed |= device.SetProperty("agent.medium", report.Medium);
            changed |= device.SetProperty("agent.version", report.Version);
            changed |= device.SetHostname("agent", report.Hostname);
            if (changed) _devices.NotifyChanged(device, "agent");
            return mac;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Registering probe agent {Agent} as a device failed", report.AgentId);
            return null;
        }
    }

    private Mac? TargetDevice(ProbeTargetResult r)
    {
        try { return IPAddress.TryParse(r.Ip ?? r.Target, out var ip) ? _devices.FindByIp(ip)?.Mac : null; }
        catch { return null; }
    }

    private async Task PublishFailureAsync(string agentId, ProbeTargetResult r, Mac? agentMac)
    {
        try
        {
            bool? hubCan = IPAddress.TryParse(r.Ip ?? r.Target, out var ip) ? await PingAsync(ip).ConfigureAwait(false) is not null : null;
            List<string> others;
            lock (_sync)
            {
                others = _agents.Values
                    .Where(a => a.Online && !a.Id.Equals(agentId, StringComparison.OrdinalIgnoreCase) && a.Latest is not null)
                    .Where(a => a.Latest!.Results.Any(x => SameTarget(x, r) && x.RttMs is not null && x.LossPercent < AgentSignalLogic.FailLossPercent))
                    .Select(a => a.Id).ToList();
            }
            var summary = AgentSignalLogic.FailureSummary(agentId, r, HubName(), hubCan, others);
            _log.LogWarning("Probe agent: {Summary}", summary);
            Publish(DiagnosticSignal.Create(SignalKind.AgentReportFailure, Source, summary, TargetDevice(r),
                weight: AgentSignalLogic.FailureWeight(hubCan), affected: agentMac is { } m ? [m] : null));
        }
        catch (Exception ex) { _log.LogDebug(ex, "Publishing probe agent failure failed"); }
    }

    private static bool SameTarget(ProbeTargetResult a, ProbeTargetResult b) =>
        (a.Ip is not null && a.Ip == b.Ip) || (a.Target != "gw" && a.Target.Equals(b.Target, StringComparison.OrdinalIgnoreCase));

    // ---------------------------------------------------------------------------------------------
    //  offline detection + reverse probing
    // ---------------------------------------------------------------------------------------------

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await MonitorRoundAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Probe agent monitor round failed"); }
            try { await Task.Delay(MonitorEvery, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task MonitorRoundAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        var wentOffline = new List<(string Id, string Host, string? Ip, Mac? Mac, DateTimeOffset LastSeen, AgentReverseProbe? Reverse)>();
        var toPing = new List<(AgentState State, IPAddress Ip)>();
        lock (_sync)
        {
            foreach (var a in _agents.Values)
            {
                if (a.Online && !IsLocal(a.Id) && AgentSignalLogic.IsOffline(a.LastSeen, a.IntervalSeconds, now))
                {
                    a.Online = false;
                    wentOffline.Add((a.Id, a.Latest?.Hostname ?? a.Id, a.Latest?.Ip, a.Mac, a.LastSeen, a.Reverse.Sent > 0 ? a.Reverse.Snapshot(a.Id) : null));
                }
                if (a.Online && !IsLocal(a.Id) && a.PingAddress() is { } ip) toPing.Add((a, ip));
            }
        }

        foreach (var o in wentOffline)
        {
            var still = o.Reverse is { Reachable: true } ? "; its host still answers ping, so the agent process or its network path to this PC is the problem" : "";
            var summary = $"probe agent {o.Id} ({o.Host}{(o.Ip is null ? "" : ", " + o.Ip)}) stopped reporting (last report {o.LastSeen:HH:mm:ss}){still}";
            _log.LogWarning("Probe agent: {Summary}", summary);
            Publish(DiagnosticSignal.Create(SignalKind.AgentOffline, Source, summary, o.Mac, weight: 0.4, affected: o.Mac is { } m ? [m] : null));
        }

        if (toPing.Count > 0)
        {
            var results = await Task.WhenAll(toPing.Select(async p => (p.State, Ms: await PingAsync(p.Ip, ct).ConfigureAwait(false)))).ConfigureAwait(false);
            lock (_sync)
                foreach (var (state, ms) in results) state.Reverse.Record(state.PingAddress()?.ToString(), ms, DateTimeOffset.Now);
        }
        if (wentOffline.Count > 0 || toPing.Count > 0) RaiseUpdated();
    }

    private async Task<double?> PingAsync(IPAddress ip, CancellationToken ct = default)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, TimeSpan.FromMilliseconds(PingTimeoutMs), new byte[32], new PingOptions(64, false), ct).ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Ping {Ip} failed", ip);
            return null;
        }
    }

    /// <summary>"wired PC" / "Wi-Fi PC" for the summaries, from the interface that carries this host's default route.</summary>
    private string HubName()
    {
        var cached = _hubName;
        if (DateTimeOffset.Now - cached.At < TimeSpan.FromMinutes(1)) return cached.Name;
        string name = "this PC";
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .FirstOrDefault(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)));
            if (nic is not null) name = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "Wi-Fi PC" : "wired PC";
        }
        catch { }
        _hubName = (DateTimeOffset.Now, name);
        return name;
    }

    private void Publish(DiagnosticSignal signal)
    {
        if (Quiet) return;
        try { _bus.Publish(signal); } catch (Exception ex) { _log.LogDebug(ex, "Publishing a probe agent signal failed"); }
    }

    private void RaiseUpdated()
    {
        try { Updated?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "Probe agent hub subscriber failed"); }
    }

    public void Dispose()
    {
        _settingsStore.Saved -= ApplySettings;
        lock (_lifecycle)
        {
            _disposed = true;
            StopListening();
        }
    }

    // ---------------------------------------------------------------------------------------------

    private sealed class AgentState(string id, DateTimeOffset firstSeen)
    {
        public string Id { get; } = id;
        public DateTimeOffset FirstSeen { get; } = firstSeen;
        public DateTimeOffset LastSeen { get; set; } = firstSeen;
        public bool Online { get; set; }
        public double? IntervalSeconds { get; set; }
        public ProbeAgentReport? Latest { get; set; }
        public IPAddress? Source { get; set; }
        public Mac? Mac { get; set; }
        public Dictionary<string, AgentTargetState> Targets { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ReverseState Reverse { get; } = new();

        /// <summary>The agent's own reported address, else the datagram source.</summary>
        public IPAddress? PingAddress() =>
            IPAddress.TryParse(Latest?.Ip, out var ip) && !IPAddress.Any.Equals(ip) ? ip : Source;

        public ProbeAgentInfo Info() =>
            new(Id, Latest?.Hostname ?? Id, Latest?.Ip ?? Source?.ToString(), Latest?.Mac, Latest?.Medium ?? "unknown", LastSeen, Online, Latest);
    }

    private sealed class ReverseState
    {
        private readonly Queue<double?> _window = new();
        private string? _ip;
        private double? _last;
        private DateTimeOffset _updated;
        public int Sent => _window.Count;

        public void Record(string? ip, double? ms, DateTimeOffset at)
        {
            if (ip != _ip) { _window.Clear(); _ip = ip; }
            _window.Enqueue(ms);
            while (_window.Count > ReverseWindow) _window.Dequeue();
            _last = ms;
            _updated = at;
        }

        public AgentReverseProbe Snapshot(string id)
        {
            var ok = _window.Where(x => x is not null).Select(x => x!.Value).ToList();
            double loss = _window.Count == 0 ? 0 : 100.0 * (_window.Count - ok.Count) / _window.Count;
            return new AgentReverseProbe(id, _ip, _last is not null, _last, ok.Count > 0 ? ok.Average() : null, loss, _window.Count, _updated);
        }
    }
}
