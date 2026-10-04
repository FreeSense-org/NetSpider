using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Probe;

/// <summary>The agent loop: ping targets every interval, build a signed report and send it to the hub over UDP.</summary>
public sealed class ProbeAgent
{
    private static readonly TimeSpan RediscoverEvery = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan LocalInfoEvery = TimeSpan.FromSeconds(30);

    private readonly ProbeOptions _o;
    private readonly byte[] _key;
    private readonly TargetMonitor _monitor;
    private readonly WifiReader _wifi;
    private readonly string _version;
    private IPEndPoint? _hub;
    private LocalInfo? _local;
    private DateTimeOffset _localAt = DateTimeOffset.MinValue;
    private string? _lastSummary;

    public ProbeAgent(ProbeOptions options)
    {
        _o = options;
        if (!AgentProtocol.TryParseKey(options.Key, out _key)) throw new ArgumentException("invalid key");
        _monitor = new TargetMonitor(options.Targets, options.Window, Log);
        _wifi = new WifiReader(Log);
        _version = typeof(ProbeAgent).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "1.0.0";
    }

    public static void Log(string message) => Console.WriteLine($"{DateTime.Now:HH:mm:ss} {message}");

    /// <summary>Returns the process exit code: 0 ok, 2 when <c>--once</c> could not deliver a report.</summary>
    public async Task<int> RunAsync(CancellationToken ct)
    {
        Log($"netspider-probe {_version} as '{_o.Id}' targets [{string.Join(", ", _o.Targets)}] every {_o.IntervalSeconds:0.##}s" +
            (_o.ConfigPath is null ? "" : $" (config {_o.ConfigPath})"));
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var lastDiscovery = DateTimeOffset.MinValue;
        int sentReports = 0;

        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            try
            {
                if (_hub is null && DateTimeOffset.Now - lastDiscovery >= RediscoverEvery)
                {
                    lastDiscovery = DateTimeOffset.Now;
                    _hub = await ResolveHubAsync(ct).ConfigureAwait(false);
                }

                var local = LocalInfo();
                var timeout = TimeSpan.FromSeconds(Math.Clamp(_o.IntervalSeconds * 0.8, 0.5, 2));
                var results = await _monitor.RoundAsync(local.Gateway, _hub?.Address, timeout, ct).ConfigureAwait(false);

                WifiLinkSample? wifi = null;
                if (local.Medium == "Wi-Fi")
                {
                    wifi = await _wifi.ReadAsync(local.InterfaceName, ct).ConfigureAwait(false);
                    var gwMs = results.FirstOrDefault(r => r.Target.Equals("gw", StringComparison.OrdinalIgnoreCase))?.RttMs;
                    if (wifi is not null && gwMs is not null) wifi = wifi with { GatewayRttMs = gwMs };
                }

                var report = new ProbeAgentReport(_o.Id, Environment.MachineName, local.Ip?.ToString(), local.Mac, local.Medium,
                    DateTimeOffset.Now, results, wifi, local.Gateway?.ToString(), _version);

                if (_hub is null) Log("hub not found yet (use --hub or check the key / that the hub is enabled); retrying");
                else
                {
                    var datagrams = AgentProtocol.SealChunked(report, _key);
                    foreach (var d in datagrams) await udp.SendAsync(d, _hub, ct).ConfigureAwait(false);
                    sentReports++;
                    LogRound(report, datagrams.Count, datagrams.Sum(d => d.Length));
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { Log($"round failed: {ex.Message}"); }

            if (_o.Once) break;
            var wait = TimeSpan.FromSeconds(_o.IntervalSeconds) - Stopwatch.GetElapsedTime(started);
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        Log("stopped");
        return _o.Once && sentReports == 0 ? 2 : 0;
    }

    private async Task<IPEndPoint?> ResolveHubAsync(CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(_o.HubHost))
        {
            try
            {
                var ip = IPAddress.TryParse(_o.HubHost, out var lit) ? lit
                    : (await Dns.GetHostAddressesAsync(_o.HubHost, ct).ConfigureAwait(false)).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ip is null) { Log($"cannot resolve hub '{_o.HubHost}'"); return null; }
                var ep = new IPEndPoint(ip, _o.HubPort);
                Log($"reporting to hub {ep}");
                return ep;
            }
            catch (SocketException ex) { Log($"cannot resolve hub '{_o.HubHost}': {ex.Message}"); return null; }
        }

        Log($"discovering hub (UDP broadcast to port {AgentProtocol.DiscoveryPort})...");
        var found = await HubLocator.DiscoverAsync(_key, TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        Log(found is null ? "no hub answered" : $"found hub {found}");
        return found;
    }

    private LocalInfo LocalInfo()
    {
        if (_local is null || DateTimeOffset.Now - _localAt > LocalInfoEvery)
        {
            var next = LocalNetwork.Describe(_hub?.Address);
            if (_local is null || next != _local)
                Log($"local {next.Medium} interface {next.InterfaceName ?? "?"} ip {next.Ip?.ToString() ?? "?"} mac {next.Mac ?? "?"} gw {next.Gateway?.ToString() ?? "none"}");
            _local = next;
            _localAt = DateTimeOffset.Now;
        }
        return _local;
    }

    private void LogRound(ProbeAgentReport report, int datagrams, int bytes)
    {
        var sb = new StringBuilder();
        foreach (var r in report.Results)
        {
            if (sb.Length > 0) sb.Append(" | ");
            sb.Append(string.IsNullOrEmpty(r.Ip) || r.Ip == r.Target ? r.Target : $"{r.Target} {r.Ip}").Append(' ');
            sb.Append(r.RttMs is { } ms ? $"{ms:0.#} ms" : r.Error ?? "no reply");
            sb.Append($" loss {r.LossPercent:0}%");
        }
        var summary = sb.ToString();
        if (_o.Quiet)
        {
            // in quiet mode only log when reachability changes (ignore RTT noise)
            var key = string.Join(",", report.Results.Select(r => $"{r.Target}:{r.RttMs is not null}"));
            if (key == _lastSummary) return;
            _lastSummary = key;
        }
        var wifi = report.Wifi is { Connected: true } w ? $" [wifi {w.Ssid} {w.RssiDbm} dBm {w.RxRateMbps:0}/{w.TxRateMbps:0} Mbps]" : "";
        Log($"sent {datagrams} datagram(s) {bytes} B: {summary}{wifi}");
    }
}
