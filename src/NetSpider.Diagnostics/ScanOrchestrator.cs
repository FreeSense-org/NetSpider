using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Diagnostics.Anomaly;
using NetSpider.Diagnostics.Latency;
using NetSpider.Diagnostics.Topology;

namespace NetSpider.Diagnostics;

/// <summary>
/// The application's scan coordinator: capture + passive monitoring, full active scans, per-device re-probes,
/// classification/logo enrichment, periodic topology rebuilds and offline detection. Every optional component is
/// resolved with <c>GetService</c> so the app degrades gracefully when a workstream is not registered.
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator, IDisposable
{
    private static readonly HashSet<string> IgnoredChangeReasons = new(StringComparer.OrdinalIgnoreCase)
        { "latency", "classify", "logo", "topology", "state", "storm", "health", "oui" };
    private static readonly TimeSpan ReclassifyDebounce = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan PeriodicInterval = TimeSpan.FromSeconds(10);

    private readonly ILogger<ScanOrchestrator> _log;
    private readonly IServiceProvider _sp;
    private readonly IDeviceStore _devices;
    private readonly ITopologyStore _topology;
    private readonly INetworkState _network;
    private readonly IAlertService _alerts;
    private readonly IEventBus _bus;
    private readonly AppSettings _settings;

    private readonly object _sync = new();
    private readonly List<IDisposable> _frameSubs = [];
    private readonly List<IPassiveMonitor> _startedMonitors = [];
    private readonly ConcurrentDictionary<Mac, byte> _pendingClassify = new();
    private readonly ConcurrentDictionary<Mac, DateTimeOffset> _offline = new();
    private readonly SemaphoreSlim _logoGate = new(4);
    private readonly ConcurrentDictionary<Mac, string?> _logoBrand = new();

    private CancellationTokenSource? _monitorCts;
    private CancellationTokenSource? _scanCts;
    private Timer? _periodic;
    private int _periodicBusy;
    private int _scanning;
    private bool _eventsHooked;

    public ScanOrchestrator(ILogger<ScanOrchestrator> log, IServiceProvider sp, IDeviceStore devices, ITopologyStore topology,
        INetworkState network, IAlertService alerts, IEventBus bus, AppSettings settings)
    {
        _log = log;
        _sp = sp;
        _devices = devices;
        _topology = topology;
        _network = network;
        _alerts = alerts;
        _bus = bus;
        _settings = settings;
    }

    public bool IsMonitoring { get; private set; }
    public bool IsScanning => Volatile.Read(ref _scanning) != 0;
    public ScanContext? Context { get; private set; }

    public event Action<ScanProgress>? Progress;
    public event Action? ScanCompleted;

    // optional services (resolved lazily so registration order / absence does not matter)
    private IFrameSource? FrameSource => _sp.GetService<IFrameSource>();
    private IOuiLookup? Oui => _sp.GetService<IOuiLookup>();
    private IDeviceClassifier? Classifier => _sp.GetService<IDeviceClassifier>();
    private ILogoProvider? Logos => _sp.GetService<ILogoProvider>();
    private ILatencyEngine? LatencyEngine => _sp.GetService<ILatencyEngine>();
    private ITopologyBuilder? TopologyBuilder => _sp.GetService<ITopologyBuilder>();
    private IHealthService? Health => _sp.GetService<IHealthService>();

    // =========================================================================================================
    //  Monitoring
    // =========================================================================================================

    public async Task StartMonitoringAsync(AdapterInfo adapter, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var source = FrameSource;
        if (source is null || !source.PcapAvailable)
        {
            _alerts.Raise(Alert.Create(AlertSeverity.Critical, AlertKind.NpcapMissing, "Npcap is not installed",
                "NetSpider needs Npcap for packet capture and injection. Download it from https://npcap.com/#download (enable \"WinPcap API-compatible mode\")."), TimeSpan.FromMinutes(1));
            throw new InvalidOperationException("Npcap is not installed or could not be loaded. Install Npcap from https://npcap.com/#download (with \"WinPcap API-compatible mode\") and restart NetSpider as administrator.");
        }

        if (IsMonitoring) StopAll();

        // 1. scan context: known segments + the adapter's own subnets
        foreach (var a in adapter.IPv4)
        {
            _network.AddOrGetSegment(a.Address, a.PrefixLength, "adapter", s =>
            {
                s.IsLocal = true;
                if (adapter.GatewayV4 is { } gw && s.Contains(gw)) s.Gateway ??= gw;
            });
        }
        var ctx = BuildContext(adapter);
        Context = ctx;
        _monitorCts = new CancellationTokenSource();

        RegisterThisHost(adapter);
        HookStoreEvents();

        // 2. capture, frame handlers, passive monitors
        try { source.Start(adapter); }
        catch (Exception ex)
        {
            _log.LogError(ex, "Starting capture on {Adapter} failed", adapter.Name);
            throw new InvalidOperationException($"Could not start capture on {adapter.Name}: {ex.Message}. Run NetSpider as administrator and check that Npcap is installed.", ex);
        }

        lock (_sync)
        {
            foreach (var h in _sp.GetServices<IFrameHandler>().Distinct())
            {
                try { _frameSubs.Add(source.Subscribe(h)); }
                catch (Exception ex) { _log.LogWarning(ex, "Subscribing frame handler {Handler} failed", h.GetType().Name); }
            }
        }
        try { _sp.GetService<AnomalyEngine>()?.Start(); } catch (Exception ex) { _log.LogWarning(ex, "Anomaly engine start failed"); }

        foreach (var m in _sp.GetServices<IPassiveMonitor>().Distinct())
        {
            try { m.Start(ctx); lock (_sync) _startedMonitors.Add(m); }
            catch (Exception ex) { _log.LogWarning(ex, "Passive monitor {Monitor} failed to start", m.Name); }
        }
        IsMonitoring = true;

        // 3. OUI database (download/refresh may take a moment; devices found meanwhile are enriched afterwards)
        try { if (Oui is { } oui) await oui.EnsureLoadedAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogWarning(ex, "OUI database load failed"); }
        foreach (var d in _devices.All) EnrichNew(d);

        // 4. latency engine and periodic housekeeping
        try { LatencyEngine?.Start(ctx); } catch (Exception ex) { _log.LogWarning(ex, "Latency engine start failed"); }
        _periodic = new Timer(_ => Periodic(), null, PeriodicInterval, PeriodicInterval);
        _log.LogInformation("Monitoring started on {Adapter}", adapter);
    }

    private ScanContext BuildContext(AdapterInfo adapter)
    {
        var segs = _network.Segments
            .Where(s => s.ScanEnabled || s.IsLocal)
            .OrderByDescending(s => s.IsLocal)
            .ThenBy(s => s.PrefixLength)
            .ToList();
        return new ScanContext { Adapter = adapter, Settings = _settings, Segments = segs };
    }

    private void RegisterThisHost(AdapterInfo adapter)
    {
        try
        {
            if (adapter.Mac.IsZero) return;
            var me = _devices.GetOrAdd(adapter.Mac);
            me.SetFlag(DeviceFlags.ThisHost);
            if (me.Type == DeviceType.Unknown) { me.Type = DeviceType.ThisComputer; me.TypeConfidence = 1; }
            foreach (var a in adapter.IPv4) _devices.Observe(adapter.Mac, a.Address, "local");
            foreach (var a in adapter.IPv6) _devices.Observe(adapter.Mac, a, "local");
            me.SetHostname("netbios", Environment.MachineName);
            me.OsGuess ??= System.Runtime.InteropServices.RuntimeInformation.OSDescription;
            if (adapter.IsVirtual) me.SetFlag(DeviceFlags.Virtual);
            _devices.NotifyChanged(me, "local");
        }
        catch (Exception ex) { _log.LogDebug(ex, "register this host"); }
    }

    private void HookStoreEvents()
    {
        lock (_sync)
        {
            if (_eventsHooked) return;
            _devices.DeviceAdded += OnDeviceAdded;
            _devices.DeviceChanged += OnDeviceChanged;
            _eventsHooked = true;
        }
    }

    private void UnhookStoreEvents()
    {
        lock (_sync)
        {
            if (!_eventsHooked) return;
            _devices.DeviceAdded -= OnDeviceAdded;
            _devices.DeviceChanged -= OnDeviceChanged;
            _eventsHooked = false;
        }
    }

    /// <summary>Called on whatever thread created the device (often the capture thread): cheap work only.</summary>
    private void OnDeviceAdded(Device d)
    {
        try
        {
            EnrichNew(d);
        }
        catch (Exception ex) { _log.LogDebug(ex, "device added handler"); }
    }

    private void EnrichNew(Device d)
    {
        if (NodeKinds.IsGraphOnly(d)) return;
        bool changed = false;
        if (d.OuiVendor is null && !d.Mac.IsRandomized && Oui?.Lookup(d.Mac) is { } vendor)
        {
            d.OuiVendor = vendor;
            d.AddEvidence("oui", Fields.Vendor, vendor, Confidence.Oui);
            changed = true;
        }
        changed |= MarkSegment(d);
        if (changed) _devices.NotifyChanged(d, "oui");
        ScheduleClassify(d);
    }

    /// <summary>Gateway / off-subnet flags from the known segments.</summary>
    private bool MarkSegment(Device d)
    {
        var ctx = Context;
        if (ctx is null) return false;
        bool changed = false;
        if (ctx.Gateway is { } gw && d.HasIp(gw) && !d.Has(DeviceFlags.Gateway))
        {
            d.SetFlag(DeviceFlags.Gateway);
            changed = true;
        }
        var ip = d.PrimaryIPv4;
        if (ip is not null && !d.Has(DeviceFlags.ThisHost))
        {
            var segs = _network.Segments;
            bool local = NodeKinds.IsOnLocalSubnet(ip, ctx, segs);
            bool known = local || segs.Any(s => s.Contains(ip));
            if (known && d.Has(DeviceFlags.OffSubnet) == local)
            {
                d.SetFlag(DeviceFlags.OffSubnet, !local);
                changed = true;
            }
        }
        return changed;
    }

    private void OnDeviceChanged(Device d, string? reason)
    {
        try
        {
            if (reason is not null && IgnoredChangeReasons.Contains(reason)) return;
            if (_offline.ContainsKey(d.Mac) && d.State == DeviceState.Online) MarkOnline(d);
            ScheduleClassify(d);
        }
        catch (Exception ex) { _log.LogDebug(ex, "device changed handler"); }
    }

    /// <summary>Per-device trailing debounce: changes within 500 ms coalesce into one re-classification.</summary>
    private void ScheduleClassify(Device d)
    {
        if (NodeKinds.IsGraphOnly(d) || !_pendingClassify.TryAdd(d.Mac, 0)) return;
        var ct = _monitorCts?.Token ?? CancellationToken.None;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(ReclassifyDebounce, ct).ConfigureAwait(false);
                _pendingClassify.TryRemove(d.Mac, out _);
                MarkSegment(d);
                ClassifyAndLogo(d, ct);
            }
            catch (OperationCanceledException) { _pendingClassify.TryRemove(d.Mac, out _); }
            catch (Exception ex) { _pendingClassify.TryRemove(d.Mac, out _); _log.LogDebug(ex, "reclassify {Device}", d); }
        }, CancellationToken.None);
    }

    private void ClassifyAndLogo(Device d, CancellationToken ct)
    {
        if (Classify(d)) _devices.NotifyChanged(d, "classify");
        var key = d.IconUrl ?? d.Brand;
        if (key is null) return;
        if (_logoBrand.TryGetValue(d.Mac, out var last) && last == key && d.LogoPath is not null) return;
        _logoBrand[d.Mac] = key;
        _ = FetchLogoAsync(d, ct);
    }

    private bool Classify(Device d)
    {
        var c = Classifier;
        if (c is null) return false;
        try { return c.Classify(d); }
        catch (Exception ex) { _log.LogDebug(ex, "classify {Device}", d); return false; }
    }

    private async Task FetchLogoAsync(Device d, CancellationToken ct)
    {
        var logos = Logos;
        if (logos is null) return;
        try
        {
            await _logoGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var path = await logos.GetLogoAsync(d, ct).ConfigureAwait(false);
                if (path is not null && path != d.LogoPath)
                {
                    d.LogoPath = path;
                    _devices.NotifyChanged(d, "logo");
                }
            }
            finally { _logoGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "logo for {Device}", d); }
    }

    // =========================================================================================================
    //  Periodic: topology + offline detection
    // =========================================================================================================

    private void Periodic()
    {
        if (Interlocked.Exchange(ref _periodicBusy, 1) == 1) return;
        try
        {
            var ctx = Context;
            if (ctx is null) return;
            if (!IsScanning)
            {
                try { TopologyBuilder?.Rebuild(ctx); } catch (Exception ex) { _log.LogWarning(ex, "Topology rebuild failed"); }
            }
            DetectOffline(ctx);
            MaybeStartSnmpPoll(ctx);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Periodic housekeeping failed"); }
        finally { Volatile.Write(ref _periodicBusy, 0); }
    }

    // ---- SNMP auto-poll -------------------------------------------------------------------------------------
    private readonly ConcurrentDictionary<Mac, byte> _snmpTried = new();
    private DateTimeOffset _lastSnmpPoll = DateTimeOffset.MinValue;
    private int _snmpPolling;

    /// <summary>
    /// When <see cref="AppSettings.SnmpAutoPoll"/> is on: tries SNMP once on every device found since monitoring started
    /// (so "public"-enabled gear is read without a full scan) and re-polls devices that answered every N minutes.
    /// </summary>
    private void MaybeStartSnmpPoll(ScanContext ctx)
    {
        if (!_settings.SnmpAutoPoll || IsScanning) return;
        var probe = _sp.GetServices<IDeviceProbe>().FirstOrDefault(p => p.Name.Equals("SNMP", StringComparison.OrdinalIgnoreCase));
        if (probe is null) return;

        bool repollDue = DateTimeOffset.Now - _lastSnmpPoll >= TimeSpan.FromMinutes(Math.Max(1, _settings.SnmpPollMinutes));
        var targets = _devices.All
            .Where(d => !NodeKinds.IsGraphOnly(d) && d.State != DeviceState.Offline && d.PrimaryIPv4 is not null && probe.AppliesTo(d, ctx))
            .Where(d => !_snmpTried.ContainsKey(d.Mac) || (repollDue && d.GetProperty("snmp.sysObjectID") is not null))
            .ToList();
        if (targets.Count == 0) { if (repollDue) _lastSnmpPoll = DateTimeOffset.Now; return; }
        if (Interlocked.Exchange(ref _snmpPolling, 1) == 1) return;
        if (repollDue) _lastSnmpPoll = DateTimeOffset.Now;
        var token = _monitorCts?.Token ?? CancellationToken.None;

        _ = Task.Run(async () =>
        {
            try
            {
                await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = token }, async (d, ct) =>
                {
                    _snmpTried[d.Mac] = 0;
                    try
                    {
                        await probe.ProbeAsync(d, ctx, ct).ConfigureAwait(false);
                        if (Classify(d)) _devices.NotifyChanged(d, "classify");
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex) { _log.LogDebug(ex, "SNMP auto-poll {Device}", d); }
                }).ConfigureAwait(false);
                _log.LogDebug("SNMP auto-poll finished ({Count} devices)", targets.Count);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "SNMP auto-poll failed"); }
            finally { Volatile.Write(ref _snmpPolling, 0); }
        });
    }

    private void DetectOffline(ScanContext ctx)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, _settings.LatencyIntervalSeconds));
        var threshold = interval * 3;
        var engine = LatencyEngine as LatencyEngine;
        var now = DateTimeOffset.Now;
        foreach (var d in _devices.All)
        {
            if (d.Has(DeviceFlags.ThisHost) || NodeKinds.IsGraphOnly(d)) continue;
            if (_offline.TryGetValue(d.Mac, out var since))
            {
                if (d.LastSeen > since) MarkOnline(d);
                continue;
            }
            if (d.State == DeviceState.Offline) continue;
            if (now - d.LastSeen <= threshold) continue;
            // unseen for 3 intervals AND the latency engine's probes are failing (or, without our engine, unseen for 2 min)
            bool pingsFailing = engine is not null ? engine.ConsecutiveFailedCycles(d.Mac) >= 3 : now - d.LastSeen > TimeSpan.FromMinutes(2);
            if (!pingsFailing) continue;
            d.State = DeviceState.Offline;
            _offline[d.Mac] = now;
            _devices.NotifyChanged(d, "state");
            _alerts.Raise(Alert.Create(AlertSeverity.Info, AlertKind.DeviceOffline, $"{d.DisplayName} went offline",
                $"{d.DisplayName} [{d.Mac}] {d.PrimaryIPv4} has not been seen since {d.LastSeen:HH:mm:ss} and does not answer probes.", d.Mac), TimeSpan.FromMinutes(10));
        }
    }

    private void MarkOnline(Device d)
    {
        if (!_offline.TryRemove(d.Mac, out _)) return;
        if (d.State != DeviceState.Online) d.State = DeviceState.Online;
        _devices.NotifyChanged(d, "state");
    }

    // =========================================================================================================
    //  Full scan
    // =========================================================================================================

    public async Task RunFullScanAsync(CancellationToken ct = default)
    {
        var baseCtx = Context ?? throw new InvalidOperationException("Start monitoring an adapter before scanning.");
        if (Interlocked.CompareExchange(ref _scanning, 1, 0) != 0)
        {
            _log.LogInformation("A scan is already running");
            return;
        }
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct, _monitorCts?.Token ?? CancellationToken.None);
        _scanCts = cts;
        var token = cts.Token;
        try
        {
            var ctx = BuildContext(baseCtx.Adapter);
            Context = ctx;
            _log.LogInformation("Full scan started ({Segments} segments)", ctx.Segments.Count);

            // weights of the stages in the overall progress bar
            const double wActive = 0.55, wDevice = 0.25, wClassify = 0.03, wLogo = 0.05, wTopo = 0.04; // health uses the remainder
            double at = 0;
            var progressLock = new object();

            // 1. active probes, sequential by order
            var active = _sp.GetServices<IActiveProbe>().Distinct().OrderBy(p => p.Order).ToList();
            for (int i = 0; i < active.Count; i++)
            {
                token.ThrowIfCancellationRequested();
                var probe = active[i];
                double lo = at + wActive * i / active.Count, span = wActive / active.Count;
                Report(probe.Name, lo);
                var inner = new SyncProgress(p => Report(p.Stage, lo + span * Math.Clamp(p.Fraction, 0, 1), p.Detail));
                try { await probe.RunAsync(ctx, inner, token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogWarning(ex, "Probe {Probe} failed", probe.Name); }
            }
            at += wActive;

            // 2. per-device probes: devices in parallel, probes in order
            ctx = BuildContext(baseCtx.Adapter); // probes may have discovered segments
            Context = ctx;
            var deviceProbes = _sp.GetServices<IDeviceProbe>().Distinct().OrderBy(p => p.Order).ToList();
            var targets = _devices.All.Where(d => !NodeKinds.IsGraphOnly(d) && !d.Has(DeviceFlags.ThisHost)).ToList();
            if (deviceProbes.Count > 0 && targets.Count > 0)
            {
                int done = 0;
                Report("Probing devices", at, $"0/{targets.Count}");
                await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = token }, async (d, dct) =>
                {
                    await ProbeDeviceAsync(d, ctx, deviceProbes, dct).ConfigureAwait(false);
                    lock (progressLock)
                    {
                        var n = ++done;
                        Report("Probing devices", at + wDevice * n / targets.Count, $"{n}/{targets.Count} {d.DisplayName}");
                    }
                }).ConfigureAwait(false);
            }
            at += wDevice;

            // 3. classify
            Report("Classifying", at);
            foreach (var d in _devices.All)
            {
                token.ThrowIfCancellationRequested();
                if (NodeKinds.IsGraphOnly(d)) continue;
                if (d.OuiVendor is null) EnrichNew(d);
                MarkSegment(d);
                if (Classify(d)) _devices.NotifyChanged(d, "classify");
            }
            at += wClassify;

            // 4. logos
            if (Logos is not null)
            {
                var withBrand = _devices.All.Where(d => !NodeKinds.IsGraphOnly(d) && (d.Brand is not null || d.IconUrl is not null)).ToList();
                int done = 0;
                Report("Fetching logos", at);
                await Parallel.ForEachAsync(withBrand, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = token }, async (d, dct) =>
                {
                    _logoBrand[d.Mac] = d.IconUrl ?? d.Brand;
                    await FetchLogoAsync(d, dct).ConfigureAwait(false);
                    lock (progressLock)
                    {
                        var n = ++done;
                        Report("Fetching logos", at + wLogo * n / Math.Max(1, withBrand.Count), d.Brand);
                    }
                }).ConfigureAwait(false);
            }
            at += wLogo;

            // 5. topology and pair-latency estimates
            Report("Building topology", at);
            try { TopologyBuilder?.Rebuild(ctx); } catch (Exception ex) { _log.LogWarning(ex, "Topology rebuild failed"); }
            EstimatePairLatencies();
            at += wTopo;

            // 6. health
            if (Health is { } health)
            {
                Report("Health checks", at);
                try { await health.RunAsync(ctx, false, token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex) { _log.LogWarning(ex, "Health suite failed"); }
            }

            // the full scan already ran SNMP on every device; the auto-poller only needs to pick up newcomers / re-polls
            foreach (var d in _devices.All) _snmpTried[d.Mac] = 0;
            _lastSnmpPoll = DateTimeOffset.Now;

            Report("Done", 1.0, $"{_devices.Count} devices, {_topology.Links.Count} links");
            _log.LogInformation("Full scan finished: {Devices} devices, {Links} links", _devices.Count, _topology.Links.Count);
            try { ScanCompleted?.Invoke(); } catch (Exception ex) { _log.LogDebug(ex, "ScanCompleted handler"); }
        }
        catch (OperationCanceledException)
        {
            Report("Cancelled", 1.0);
            _log.LogInformation("Scan cancelled");
            if (ct.IsCancellationRequested) throw;
        }
        finally
        {
            _scanCts = null;
            cts.Dispose();
            Volatile.Write(ref _scanning, 0);
        }
    }

    private async Task ProbeDeviceAsync(Device d, ScanContext ctx, IReadOnlyList<IDeviceProbe> probes, CancellationToken ct)
    {
        foreach (var p in probes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (!p.AppliesTo(d, ctx)) continue;
                await p.ProbeAsync(d, ctx, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _log.LogDebug(ex, "Device probe {Probe} on {Device} failed", p.Name, d); }
        }
    }

    /// <summary>Topology path-sum estimates for gatewayâ†”device and infrastructureâ†”infrastructure pairs (measured values are kept).</summary>
    private void EstimatePairLatencies()
    {
        try
        {
            var links = _topology.Links;
            if (links.Count == 0) return;
            var all = _devices.All.Where(d => !NodeKinds.IsGraphOnly(d)).ToList();
            var gw = all.FirstOrDefault(d => d.Has(DeviceFlags.Gateway));
            var infra = all.Where(NodeKinds.IsInfrastructure).Take(40).ToList();
            var pairs = new HashSet<(Mac, Mac)>();
            if (gw is not null) foreach (var d in all) if (d != gw) pairs.Add(Order(gw.Mac, d.Mac));
            for (int i = 0; i < infra.Count; i++)
                for (int j = i + 1; j < infra.Count; j++) pairs.Add(Order(infra[i].Mac, infra[j].Mac));
            int n = 0;
            foreach (var (a, b) in pairs)
            {
                if (++n > 2000) break;
                var existing = _topology.GetPairLatency(a, b);
                if (existing is { Origin: LatencyOrigin.Measured } && DateTimeOffset.Now - existing.Time < TimeSpan.FromMinutes(10)) continue;
                if (Latency.LatencyEngine.EstimatePair(links, a, b) is { } est) _topology.SetPairLatency(est);
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "pair latency estimates"); }

        static (Mac, Mac) Order(Mac a, Mac b) => a.Value <= b.Value ? (a, b) : (b, a);
    }

    public async Task ReprobeDeviceAsync(Device device, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        var baseCtx = Context ?? throw new InvalidOperationException("Start monitoring an adapter before probing.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct, _monitorCts?.Token ?? CancellationToken.None);
        var ctx = BuildContext(baseCtx.Adapter);
        var probes = _sp.GetServices<IDeviceProbe>().Distinct().OrderBy(p => p.Order).ToList();
        Report($"Re-probing {device.DisplayName}", 0);
        int i = 0;
        foreach (var p in probes)
        {
            cts.Token.ThrowIfCancellationRequested();
            Report($"Re-probing {device.DisplayName}", 0.9 * i++ / Math.Max(1, probes.Count), p.Name);
            try
            {
                if (p.AppliesTo(device, ctx)) await p.ProbeAsync(device, ctx, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cts.Token.IsCancellationRequested) { throw; }
            catch (Exception ex) { _log.LogDebug(ex, "Re-probe {Probe} on {Device} failed", p.Name, device); }
        }
        if (Classify(device)) _devices.NotifyChanged(device, "classify");
        _logoBrand[device.Mac] = device.IconUrl ?? device.Brand;
        await FetchLogoAsync(device, cts.Token).ConfigureAwait(false);
        try { TopologyBuilder?.Rebuild(ctx); } catch (Exception ex) { _log.LogWarning(ex, "Topology rebuild failed"); }
        _devices.NotifyChanged(device, "reprobe");
        Report($"Re-probed {device.DisplayName}", 1.0);
    }

    // =========================================================================================================

    public void StopAll()
    {
        try { _scanCts?.Cancel(); } catch { }
        try { _monitorCts?.Cancel(); } catch { }
        _periodic?.Dispose();
        _periodic = null;
        try { LatencyEngine?.Stop(); } catch (Exception ex) { _log.LogDebug(ex, "latency stop"); }
        lock (_sync)
        {
            foreach (var m in _startedMonitors)
            {
                try { m.Stop(); } catch (Exception ex) { _log.LogDebug(ex, "Stopping {Monitor}", m.Name); }
            }
            _startedMonitors.Clear();
            foreach (var s in _frameSubs) { try { s.Dispose(); } catch { } }
            _frameSubs.Clear();
        }
        try { FrameSource?.Stop(); } catch (Exception ex) { _log.LogDebug(ex, "capture stop"); }
        UnhookStoreEvents();
        _monitorCts?.Dispose();
        _monitorCts = null;
        IsMonitoring = false;
    }

    public void Dispose()
    {
        StopAll();
        _logoGate.Dispose();
    }

    private void Report(string stage, double fraction, string? detail = null)
    {
        var p = new ScanProgress(stage, Math.Clamp(fraction, 0, 1), detail);
        try { Progress?.Invoke(p); } catch (Exception ex) { _log.LogDebug(ex, "Progress handler"); }
        try { _bus.Publish(p); } catch { }
    }

    /// <summary>IProgress that invokes synchronously (Progress&lt;T&gt; would post to a captured context).</summary>
    private sealed class SyncProgress(Action<ScanProgress> report) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => report(value);
    }
}
