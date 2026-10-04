using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Health;

/// <summary>
/// Network health suite: gateway reachability/latency/loss, MTU and PMTUD black holes, DNS speed and NXDOMAIN hijacking,
/// security findings derived from device flags, IPv6, optional bufferbloat grading and recent storms/loops.
/// Uses the OS ICMP API (works without Npcap).
/// </summary>
public sealed class HealthService : IHealthService
{
    public static readonly IPAddress Cloudflare = IPAddress.Parse("1.1.1.1");
    public static readonly IPAddress Google = IPAddress.Parse("8.8.8.8");
    public static readonly IPAddress CloudflareV6 = IPAddress.Parse("2606:4700:4700::1111");
    public const string BufferbloatUrl = "https://speed.cloudflare.com/__down?bytes=50000000";
    public const double DnsSlowMs = 100;
    private static readonly string[] DnsTestNames = ["example.com", "cloudflare.com", "microsoft.com"];

    private static readonly Dictionary<string, double> Weights = new()
    {
        ["gateway"] = 3, ["dns"] = 2, ["mtu"] = 1.5, ["ipv6"] = 0.5, ["cleartext"] = 1, ["snmp"] = 1, ["certs"] = 0.5,
        ["smbv1"] = 1, ["rogue"] = 2, ["storms"] = 2, ["bufferbloat"] = 1.5,
    };

    private readonly ILogger<HealthService> _log;
    private readonly INetworkState _network;
    private readonly IDeviceStore _devices;
    private readonly IAlertService _alerts;
    private readonly AppSettings _settings;

    public HealthService(ILogger<HealthService> log, INetworkState network, IDeviceStore devices, IAlertService alerts, AppSettings settings)
    {
        _log = log;
        _network = network;
        _devices = devices;
        _alerts = alerts;
        _settings = settings;
    }

    public async Task<HealthReport> RunAsync(ScanContext ctx, bool includeBufferbloat, CancellationToken ct)
    {
        var results = new List<HealthCheckResult>();
        var parallel = new[]
        {
            Guarded("gateway", "Gateway", () => CheckGatewayAsync(ctx, ct)),
            Guarded("mtu", "MTU / path MTU", () => CheckMtuAsync(ctx, ct)),
            Guarded("dns", "DNS", () => CheckDnsAsync(ctx, ct)),
            Guarded("ipv6", "IPv6", () => CheckIpv6Async(ctx, ct)),
        };
        results.AddRange(await Task.WhenAll(parallel).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested();
        results.AddRange(RunDeviceChecks());
        results.Add(CheckRecentStorms());
        if (includeBufferbloat)
            results.Add(await Guarded("bufferbloat", "Bufferbloat", () => CheckBufferbloatAsync(ct)).ConfigureAwait(false));
        else
            results.Add(new HealthCheckResult("bufferbloat", "Bufferbloat", HealthStatus.Skipped, 0, "Not run (start it from the Health view; it downloads ~50 MB)."));

        var report = new HealthReport(DateTimeOffset.Now, OverallScore(results), results);
        _network.Health = report;
        return report;
    }

    /// <summary>Weighted mean of all non-skipped checks.</summary>
    public static int OverallScore(IEnumerable<HealthCheckResult> checks)
    {
        double sum = 0, w = 0;
        foreach (var c in checks)
        {
            if (c.Status == HealthStatus.Skipped) continue;
            var weight = Weights.GetValueOrDefault(c.Id, 1);
            sum += weight * Math.Clamp(c.Score, 0, 100);
            w += weight;
        }
        return w == 0 ? 100 : (int)Math.Round(sum / w);
    }

    private static HealthStatus StatusFor(int score) => score >= 80 ? HealthStatus.Pass : score >= 50 ? HealthStatus.Warn : HealthStatus.Fail;

    private async Task<HealthCheckResult> Guarded(string id, string name, Func<Task<HealthCheckResult>> run)
    {
        try { return await run().ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Health check {Id} failed", id);
            return new HealthCheckResult(id, name, HealthStatus.Skipped, 0, "Check could not run: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    //  Gateway
    // ---------------------------------------------------------------------------------------------------------

    private async Task<HealthCheckResult> CheckGatewayAsync(ScanContext ctx, CancellationToken ct)
    {
        var gw = ctx.Gateway;
        var gwDev = gw is null ? null : _devices.FindByIp(gw);
        if (gw is null) return new HealthCheckResult("gateway", "Gateway", HealthStatus.Warn, 50, "No default gateway configured on this adapter.");
        var rtts = new List<double?>();
        for (int i = 0; i < 10; i++)
        {
            rtts.Add(await PingAsync(gw, 32, false, TimeSpan.FromSeconds(1), ct).ConfigureAwait(false) is { Status: IPStatus.Success } r ? r.Ms : null);
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        var ok = rtts.Where(x => x.HasValue).Select(x => x!.Value).ToList();
        double loss = 100.0 * (rtts.Count - ok.Count) / rtts.Count;
        if (ok.Count == 0)
            return new HealthCheckResult("gateway", "Gateway", HealthStatus.Fail, 0, $"Gateway {gw} does not answer ICMP (10/10 lost).", null, gwDev?.Mac);
        double avg = ok.Average(), max = ok.Max();
        int score = 100 - (int)Math.Round(loss * 2);
        if (avg > _settings.LatencyBadMs) score -= 40;
        else if (avg > _settings.LatencyWarnMs) score -= 20;
        score = Math.Clamp(score, 0, 100);
        return new HealthCheckResult("gateway", "Gateway", StatusFor(score), score,
            $"Gateway {gw}: avg {avg:0.##} ms, max {max:0.##} ms, loss {loss:0}%.",
            $"RTTs: {string.Join(", ", rtts.Select(x => x is { } v ? v.ToString("0.##") : "lost"))}", gwDev?.Mac);
    }

    // ---------------------------------------------------------------------------------------------------------
    //  MTU / PMTUD
    // ---------------------------------------------------------------------------------------------------------

    private async Task<HealthCheckResult> CheckMtuAsync(ScanContext ctx, CancellationToken ct)
    {
        var lines = new List<string>();
        int score = 100;
        bool blackHole = false, anyTested = false;
        var targets = new List<(IPAddress Ip, string Name, bool Jumbo)>();
        if (ctx.Gateway is { } gw) targets.Add((gw, "gateway", true));
        targets.Add((Cloudflare, "1.1.1.1", false));

        foreach (var (ip, name, jumbo) in targets)
        {
            var small = await PingAsync(ip, 32, true, TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            if (small?.Status != IPStatus.Success) { lines.Add($"{name}: unreachable, not tested"); continue; }
            anyTested = true;
            var p1500 = await PingAsync(ip, 1472, true, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            if (p1500?.Status == IPStatus.Success) lines.Add($"{name}: 1500-byte packets pass (DF)");
            else
            {
                var p1492 = await PingAsync(ip, 1464, true, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                bool tooBig = p1500?.Status == IPStatus.PacketTooBig;
                if (tooBig && p1492?.Status == IPStatus.Success) { lines.Add($"{name}: path MTU 1492 (PPPoE), signalled correctly"); score = Math.Min(score, 95); }
                else if (tooBig) { lines.Add($"{name}: path MTU below 1492, signalled correctly"); score = Math.Min(score, 85); }
                else if (p1492?.Status == IPStatus.Success)
                {
                    lines.Add($"{name}: 1500-byte DF packets silently dropped but 1492 pass - PMTUD black hole (MTU 1492 path without ICMP 'fragmentation needed')");
                    score = Math.Min(score, 40); blackHole = true;
                }
                else
                {
                    lines.Add($"{name}: 1492- and 1500-byte DF packets silently dropped - PMTUD black hole");
                    score = Math.Min(score, 30); blackHole = true;
                }
            }
            if (jumbo)
            {
                var j = await PingAsync(ip, 8972, true, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                lines.Add($"{name}: jumbo 9000 {(j?.Status == IPStatus.Success ? "supported" : "not supported")} (informational)");
            }
        }
        if (!anyTested) return new HealthCheckResult("mtu", "MTU / path MTU", HealthStatus.Skipped, 0, "No target reachable for MTU tests.", string.Join("\n", lines));
        if (blackHole)
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.MtuBlackHole, "Path-MTU black hole",
                string.Join("; ", lines) + ". Large transfers/VPNs may stall; lower the MTU or fix ICMP filtering."), TimeSpan.FromHours(1));
        return new HealthCheckResult("mtu", "MTU / path MTU", StatusFor(score), score,
            blackHole ? "PMTUD black hole detected." : "MTU is consistent.", string.Join("\n", lines));
    }

    // ---------------------------------------------------------------------------------------------------------
    //  DNS
    // ---------------------------------------------------------------------------------------------------------

    private async Task<HealthCheckResult> CheckDnsAsync(ScanContext ctx, CancellationToken ct)
    {
        var lines = new List<string>();
        var timeout = TimeSpan.FromSeconds(2);

        // OS resolver
        var sysTimes = new List<double>();
        foreach (var n in DnsTestNames)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);
                await Dns.GetHostAddressesAsync(n, AddressFamily.InterNetwork, cts.Token).ConfigureAwait(false);
                sysTimes.Add(sw.Elapsed.TotalMilliseconds);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (SocketException) { }
        }
        double? sysMedian = Median(sysTimes);
        lines.Add($"System resolver: {(sysMedian is { } s ? $"{s:0.#} ms median" : "failed")}");

        // direct UDP queries
        var configured = ctx.Adapter.DnsServers.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Take(2).ToList();
        var servers = configured.Select(a => (Ip: a, Name: $"configured {a}")).ToList();
        servers.Add((Cloudflare, "1.1.1.1"));
        servers.Add((Google, "8.8.8.8"));
        var medians = new Dictionary<IPAddress, double?>();
        await Task.WhenAll(servers.Select(async srv =>
        {
            var times = new List<double>();
            foreach (var n in DnsTestNames)
            {
                var r = await DnsWire.QueryAsync(srv.Ip, n, timeout, ct).ConfigureAwait(false);
                if (r is { } ok && ok.Response.Rcode == DnsWire.RcodeNoError) times.Add(ok.Ms);
            }
            lock (medians) medians[srv.Ip] = Median(times);
        })).ConfigureAwait(false);
        foreach (var srv in servers)
            lines.Add($"{srv.Name}: {(medians.GetValueOrDefault(srv.Ip) is { } m ? $"{m:0.#} ms median" : "no answer")}");

        int score = 100;
        string summary;
        double? primary = configured.Select(c => medians.GetValueOrDefault(c)).FirstOrDefault(x => x is not null) ?? sysMedian;
        double? best = new[] { medians.GetValueOrDefault(Cloudflare), medians.GetValueOrDefault(Google) }.Where(x => x is not null).Min();
        if (primary is null && best is null)
        {
            return new HealthCheckResult("dns", "DNS", HealthStatus.Fail, 0, "No DNS resolver answered.", string.Join("\n", lines));
        }
        if (primary is null) { score -= 50; summary = "The configured resolver does not answer; public resolvers work."; }
        else if (primary > DnsSlowMs)
        {
            score -= 30;
            summary = $"DNS is slow: {primary:0} ms median" + (best is { } b ? $" (public resolver {b:0} ms)." : ".");
            var server = configured.FirstOrDefault();
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.DnsSlow, "Slow DNS resolver", summary,
                server is null ? null : _devices.FindByIp(server)?.Mac, primary), TimeSpan.FromHours(1));
        }
        else summary = $"DNS answers in {primary:0.#} ms.";

        // NXDOMAIN hijack test
        var bogus = $"nsx-{Guid.NewGuid():N}".Substring(0, 24) + ".com";
        var hijackers = new List<string>();
        foreach (var srv in servers)
        {
            var r = await DnsWire.QueryAsync(srv.Ip, bogus, timeout, ct).ConfigureAwait(false);
            if (r is { } ok && ok.Response.Addresses.Count > 0) hijackers.Add($"{srv.Name} -> {string.Join(", ", ok.Response.Addresses)}");
        }
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var sys = await Dns.GetHostAddressesAsync(bogus, AddressFamily.InterNetwork, cts.Token).ConfigureAwait(false);
            if (sys.Length > 0) hijackers.Add($"system resolver -> {string.Join(", ", sys.Select(a => a.ToString()))}");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (SocketException) { /* NXDOMAIN, as expected */ }
        if (hijackers.Count > 0)
        {
            score -= 40;
            bool intercepted = hijackers.Any(h => h.StartsWith("1.1.1.1") || h.StartsWith("8.8.8.8"));
            var details = $"Non-existent domain {bogus} resolved: {string.Join("; ", hijackers)}." +
                          (intercepted ? " Even public resolvers are answered falsely: DNS traffic is transparently intercepted." : "");
            lines.Add("NXDOMAIN hijack: " + details);
            summary += " NXDOMAIN responses are hijacked.";
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.DnsHijack, "DNS NXDOMAIN hijacking", details), TimeSpan.FromHours(1));
        }
        else lines.Add("NXDOMAIN hijack: not detected");

        score = Math.Clamp(score, 0, 100);
        return new HealthCheckResult("dns", "DNS", StatusFor(score), score, summary, string.Join("\n", lines));
    }

    private static double? Median(IReadOnlyCollection<double> xs)
    {
        if (xs.Count == 0) return null;
        var s = xs.OrderBy(x => x).ToArray();
        return s.Length % 2 == 1 ? s[s.Length / 2] : (s[s.Length / 2 - 1] + s[s.Length / 2]) / 2;
    }

    // ---------------------------------------------------------------------------------------------------------
    //  IPv6
    // ---------------------------------------------------------------------------------------------------------

    private async Task<HealthCheckResult> CheckIpv6Async(ScanContext ctx, CancellationToken ct)
    {
        var gua = ctx.Adapter.IPv6.Where(a => Ipv6Classifier.Kind(a) == Ipv6Kind.GlobalUnicast).ToList();
        if (gua.Count == 0)
            return new HealthCheckResult("ipv6", "IPv6", HealthStatus.Warn, 60, "No global IPv6 address on this adapter (IPv4 only).");
        var r = await PingAsync(CloudflareV6, 32, false, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        if (r?.Status == IPStatus.Success)
            return new HealthCheckResult("ipv6", "IPv6", HealthStatus.Pass, 100, $"IPv6 works ({r.Value.Ms:0.#} ms to {CloudflareV6}).", string.Join(", ", gua));
        return new HealthCheckResult("ipv6", "IPv6", HealthStatus.Warn, 50, "Global IPv6 address present but the IPv6 Internet is unreachable.", string.Join(", ", gua));
    }

    // ---------------------------------------------------------------------------------------------------------
    //  Device-derived security checks
    // ---------------------------------------------------------------------------------------------------------

    /// <summary>Security/hygiene checks derived from device flags, ports and certificates (no network I/O).</summary>
    public IReadOnlyList<HealthCheckResult> RunDeviceChecks()
    {
        var devices = _devices.All;
        var results = new List<HealthCheckResult>();

        // cleartext management: flag, or telnet/FTP open
        var cleartext = new List<Device>();
        foreach (var d in devices)
        {
            bool open = d.Ports.Any(p => p.State == PortState.Open && p.Port is 23 or 21);
            if (open && !d.Has(DeviceFlags.CleartextManagement)) { d.SetFlag(DeviceFlags.CleartextManagement); _devices.NotifyChanged(d, "health"); }
            if (d.Has(DeviceFlags.CleartextManagement)) cleartext.Add(d);
        }
        results.Add(FlagCheck("cleartext", "Cleartext management", cleartext, AlertKind.CleartextManagement, AlertSeverity.Warning,
            "No Telnet/FTP/HTTP management found.", "device(s) expose cleartext management (Telnet/FTP/HTTP)", 25));

        var snmp = devices.Where(d => d.Has(DeviceFlags.DefaultSnmpCommunity)).ToList();
        results.Add(FlagCheck("snmp", "Default SNMP communities", snmp, AlertKind.DefaultSnmpCommunity, AlertSeverity.Warning,
            "No default SNMP community accepted.", "device(s) accept default SNMP communities (public/private)", 30));

        var expired = new List<Device>();
        int selfSigned = 0;
        foreach (var d in devices)
        {
            var certs = d.Certificates;
            bool exp = d.Has(DeviceFlags.ExpiredCertificate) || certs.Any(c => c.Expired);
            bool self = d.Has(DeviceFlags.SelfSignedCertificate) || certs.Any(c => c.SelfSigned);
            if (exp && !d.Has(DeviceFlags.ExpiredCertificate)) { d.SetFlag(DeviceFlags.ExpiredCertificate); _devices.NotifyChanged(d, "health"); }
            if (exp) expired.Add(d);
            if (self) selfSigned++;
        }
        var certCheck = FlagCheck("certs", "TLS certificates", expired, AlertKind.ExpiredCertificate, AlertSeverity.Info,
            "No expired certificates.", "device(s) present expired TLS certificates", 15);
        if (selfSigned > 0) certCheck = certCheck with { Details = $"{certCheck.Details}\n{selfSigned} device(s) use self-signed certificates (typical for appliances).".Trim() };
        results.Add(certCheck);

        var smb = devices.Where(d => d.Has(DeviceFlags.SmbV1)).ToList();
        results.Add(FlagCheck("smbv1", "SMBv1", smb, AlertKind.SmbV1, AlertSeverity.Warning,
            "No SMBv1 servers.", "device(s) still accept SMBv1", 30));

        // rogue DHCP / RA
        var rogue = devices.Where(d => d.Has(DeviceFlags.RogueDhcp) || d.Has(DeviceFlags.RogueRouterAdvert)).ToList();
        foreach (var s in _network.DhcpServers.Where(s => s.IsRogue))
            if (_devices.TryGet(s.ServerMac, out var d) && !rogue.Contains(d)) rogue.Add(d);
        foreach (var d in rogue)
        {
            var kind = d.Has(DeviceFlags.RogueRouterAdvert) && !d.Has(DeviceFlags.RogueDhcp) ? AlertKind.RogueRouterAdvert : AlertKind.RogueDhcp;
            _alerts.Raise(Alert.Create(AlertSeverity.Critical, kind, kind == AlertKind.RogueDhcp ? "Rogue DHCP server" : "Rogue IPv6 router advertisement",
                $"{d.DisplayName} [{d.Mac}] {d.PrimaryIPv4} hands out addresses/routes but is not the expected server.", d.Mac), TimeSpan.FromHours(1));
        }
        results.Add(rogue.Count == 0
            ? new HealthCheckResult("rogue", "Rogue DHCP / RA", HealthStatus.Pass, 100, $"{_network.DhcpServers.Count} DHCP server(s), none rogue.")
            : new HealthCheckResult("rogue", "Rogue DHCP / RA", HealthStatus.Fail, 0, $"{rogue.Count} rogue DHCP/RA source(s).",
                string.Join("\n", rogue.Select(d => $"{d.DisplayName} [{d.Mac}] {d.PrimaryIPv4}")), rogue[0].Mac));
        return results;
    }

    private HealthCheckResult FlagCheck(string id, string name, List<Device> hits, AlertKind kind, AlertSeverity sev, string okText, string badText, int penalty)
    {
        if (hits.Count == 0) return new HealthCheckResult(id, name, HealthStatus.Pass, 100, okText);
        foreach (var d in hits)
            _alerts.Raise(Alert.Create(sev, kind, name, $"{d.DisplayName} [{d.Mac}] {d.PrimaryIPv4}: {badText.Replace("device(s) ", "")}.", d.Mac), TimeSpan.FromHours(1));
        int score = Math.Max(0, 100 - penalty * hits.Count);
        return new HealthCheckResult(id, name, score >= 80 ? HealthStatus.Warn : StatusFor(score), score, $"{hits.Count} {badText}.",
            string.Join("\n", hits.Select(d => $"{d.DisplayName} [{d.Mac}] {d.PrimaryIPv4}")), hits[0].Mac);
    }

    private HealthCheckResult CheckRecentStorms()
    {
        var since = DateTimeOffset.Now - TimeSpan.FromHours(1);
        var kinds = new[] { AlertKind.BroadcastStorm, AlertKind.MulticastStorm, AlertKind.L2Loop, AlertKind.MacFlapping, AlertKind.UnknownUnicastFlood, AlertKind.MultipleStpRoots };
        var recent = _alerts.Alerts.Where(a => a.Time >= since && kinds.Contains(a.Kind)).ToList();
        if (recent.Count == 0) return new HealthCheckResult("storms", "Storms & loops", HealthStatus.Pass, 100, "No storms, loops or MAC flapping in the last hour.");
        bool critical = recent.Any(a => a.Severity == AlertSeverity.Critical);
        int score = critical ? 10 : Math.Max(30, 80 - 10 * recent.Count);
        return new HealthCheckResult("storms", "Storms & loops", critical ? HealthStatus.Fail : HealthStatus.Warn, score,
            $"{recent.Count} storm/loop alert(s) in the last hour.",
            string.Join("\n", recent.OrderByDescending(a => a.Time).Take(10).Select(a => $"{a.Time:HH:mm:ss} {a.Severity} {a.Title}: {a.Details}")));
    }

    // ---------------------------------------------------------------------------------------------------------
    //  Bufferbloat
    // ---------------------------------------------------------------------------------------------------------

    /// <summary>Grades the latency increase under load (ms): A &lt;5, B &lt;30, C &lt;60, D &lt;200, else F.</summary>
    public static char GradeBufferbloat(double increaseMs) =>
        increaseMs < 5 ? 'A' : increaseMs < 30 ? 'B' : increaseMs < 60 ? 'C' : increaseMs < 200 ? 'D' : 'F';

    private async Task<HealthCheckResult> CheckBufferbloatAsync(CancellationToken ct)
    {
        var idle = new List<double>();
        for (int i = 0; i < 10; i++)
        {
            if (await PingAsync(Cloudflare, 32, false, TimeSpan.FromSeconds(1), ct).ConfigureAwait(false) is { Status: IPStatus.Success } r) idle.Add(r.Ms);
            await Task.Delay(100, ct).ConfigureAwait(false);
        }
        if (idle.Count == 0) return new HealthCheckResult("bufferbloat", "Bufferbloat", HealthStatus.Skipped, 0, "1.1.1.1 does not answer ICMP; cannot grade.");
        double idleMedian = Median(idle)!.Value;

        using var loadCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        loadCts.CancelAfter(TimeSpan.FromSeconds(8));
        long bytes = 0;
        var sw = Stopwatch.StartNew();
        var download = Task.Run(async () =>
        {
            try
            {
                using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("NetSpider/1.0 (bufferbloat test)");
                using var resp = await http.GetAsync(BufferbloatUrl, HttpCompletionOption.ResponseHeadersRead, loadCts.Token).ConfigureAwait(false);
                await using var s = await resp.Content.ReadAsStreamAsync(loadCts.Token).ConfigureAwait(false);
                var buf = new byte[81920];
                int n;
                while ((n = await s.ReadAsync(buf, loadCts.Token).ConfigureAwait(false)) > 0) Interlocked.Add(ref bytes, n);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "bufferbloat download"); }
        }, CancellationToken.None);

        var loaded = new List<double>();
        int lost = 0;
        await Task.Delay(500, ct).ConfigureAwait(false); // let TCP ramp up
        while (!loadCts.IsCancellationRequested && !download.IsCompleted)
        {
            var r = await PingAsync(Cloudflare, 32, false, TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            if (r is { Status: IPStatus.Success } ok) loaded.Add(ok.Ms); else lost++;
            try { await Task.Delay(250, loadCts.Token).ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
        await download.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        double secs = Math.Max(0.1, sw.Elapsed.TotalSeconds);
        double mbps = bytes * 8 / secs / 1e6;
        if (loaded.Count == 0)
            return new HealthCheckResult("bufferbloat", "Bufferbloat", HealthStatus.Fail, 10, "All pings were lost under load (grade F).", $"Idle {idleMedian:0.#} ms, download {mbps:0.#} Mbit/s");
        double loadedMedian = Median(loaded)!.Value;
        double increase = Math.Max(0, loadedMedian - idleMedian);
        var grade = GradeBufferbloat(increase);
        int score = grade switch { 'A' => 100, 'B' => 85, 'C' => 65, 'D' => 40, _ => 15 };
        var status = grade switch { 'A' or 'B' => HealthStatus.Pass, 'C' => HealthStatus.Warn, _ => HealthStatus.Fail };
        var summary = $"Grade {grade}: +{increase:0} ms under load (idle {idleMedian:0.#} ms, loaded {loadedMedian:0.#} ms).";
        if (grade is 'D' or 'F')
            _alerts.Raise(Alert.Create(AlertSeverity.Warning, AlertKind.Bufferbloat, $"Bufferbloat grade {grade}",
                summary + " Enable SQM/fq_codel/CAKE on the router.", null, increase), TimeSpan.FromHours(1));
        return new HealthCheckResult("bufferbloat", "Bufferbloat", status, score, summary,
            $"Download {mbps:0.#} Mbit/s over {secs:0.#} s; {loaded.Count} pings under load, {lost} lost.");
    }

    // ---------------------------------------------------------------------------------------------------------

    private readonly record struct PingResult(IPStatus Status, double Ms);

    private static async Task<PingResult?> PingAsync(IPAddress ip, int payload, bool dontFragment, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeout, new byte[payload], new PingOptions(64, dontFragment), ct).ConfigureAwait(false);
            return new PingResult(reply.Status, reply.Status == IPStatus.Success ? Math.Max(0.05, reply.RoundtripTime) : 0);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (PingException) { return null; }
        catch (Exception) { return null; }
    }
}
