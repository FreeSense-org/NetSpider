using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetSpider.Core.Model;

namespace NetSpider.Probe;

/// <summary>
/// Pings every target once per round and keeps a sliding window per target (RTT average, loss).
/// ICMP uses <see cref="Ping"/>, which works unprivileged on Linux via ICMP datagram sockets or the system ping tool;
/// when ICMP is unavailable it falls back to a TCP connect probe (443, then 80; a refused connection counts as reachable).
/// </summary>
public sealed class TargetMonitor(IReadOnlyList<string> targets, int window, Action<string> log)
{
    private static readonly TimeSpan ResolveEvery = TimeSpan.FromMinutes(5);
    private readonly List<TargetState> _targets = targets.Select(t => new TargetState(t)).ToList();
    private bool _icmpUnavailable, _icmpHintLogged;

    public async Task<IReadOnlyList<ProbeTargetResult>> RoundAsync(IPAddress? gateway, IPAddress? hub, TimeSpan timeout, CancellationToken ct)
    {
        await Task.WhenAll(_targets.Select(t => ProbeAsync(t, gateway, hub, timeout, ct))).ConfigureAwait(false);
        return _targets.Select(t => t.Result()).ToList();
    }

    private async Task ProbeAsync(TargetState t, IPAddress? gateway, IPAddress? hub, TimeSpan timeout, CancellationToken ct)
    {
        IPAddress? ip;
        try { ip = await ResolveAsync(t, gateway, hub, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
        catch (Exception ex) { t.Record(null, null, ex is SocketException ? "cannot resolve host" : ex.Message, window); return; }
        if (ip is null)
        {
            t.Record(null, null, t.Spec.Equals("gw", StringComparison.OrdinalIgnoreCase) ? "no default gateway" : t.Spec.Equals("hub", StringComparison.OrdinalIgnoreCase) ? "hub unknown" : "cannot resolve host", window);
            return;
        }

        var (ms, error) = await PingAsync(ip, timeout, ct).ConfigureAwait(false);
        t.Record(ip, ms, error, window);
    }

    private static async Task<IPAddress?> ResolveAsync(TargetState t, IPAddress? gateway, IPAddress? hub, CancellationToken ct)
    {
        if (t.Spec.Equals("gw", StringComparison.OrdinalIgnoreCase)) return gateway;
        if (t.Spec.Equals("hub", StringComparison.OrdinalIgnoreCase)) return hub;
        if (IPAddress.TryParse(t.Spec, out var literal)) return literal;
        if (t.Address is not null && DateTimeOffset.Now - t.Resolved < ResolveEvery) return t.Address;
        var addrs = await Dns.GetHostAddressesAsync(t.Spec, ct).WaitAsync(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
        t.Address = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
        t.Resolved = DateTimeOffset.Now;
        return t.Address;
    }

    private async Task<(double? Ms, string? Error)> PingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        if (!_icmpUnavailable)
        {
            try
            {
                using var ping = new Ping();
                long t0 = Stopwatch.GetTimestamp();
                var reply = await ping.SendPingAsync(ip, timeout, new byte[32], new PingOptions(64, false), ct).ConfigureAwait(false);
                double ms = Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                if (reply.Status != IPStatus.Success) return (null, reply.Status.ToString());
                if (reply.RoundtripTime > 0 && ms > reply.RoundtripTime + 1) ms = reply.RoundtripTime;
                return (Math.Round(ms, 2), null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return (null, "cancelled"); }
            catch (Exception ex) when (ex is PingException or PlatformNotSupportedException or UnauthorizedAccessException or SocketException)
            {
                // typical on Linux without CAP_NET_RAW, ping_group_range and no ping binary
                _icmpUnavailable = true;
                if (!_icmpHintLogged)
                {
                    _icmpHintLogged = true;
                    log($"ICMP ping unavailable ({(ex.InnerException ?? ex).Message}); falling back to TCP connect probes. " +
                        "On Linux allow ICMP with: sudo setcap cap_net_raw+ep ./netspider-probe  (or sysctl net.ipv4.ping_group_range=\"0 2147483647\")");
                }
            }
        }
        return await TcpPingAsync(ip, timeout, ct).ConfigureAwait(false);
    }

    private static async Task<(double? Ms, string? Error)> TcpPingAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        string? lastError = null;
        foreach (var port in new[] { 443, 80 })
        {
            using var s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            long t0 = Stopwatch.GetTimestamp();
            try
            {
                await s.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
                return (Math.Round(Stopwatch.GetElapsedTime(t0).TotalMilliseconds, 2), null);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return (Math.Round(Stopwatch.GetElapsedTime(t0).TotalMilliseconds, 2), null); // host answered with RST
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return (null, "cancelled"); }
            catch (OperationCanceledException) { lastError = "TimedOut (tcp)"; }
            catch (SocketException ex) { lastError = $"{ex.SocketErrorCode} (tcp)"; }
        }
        return (null, lastError);
    }

    private sealed class TargetState(string spec)
    {
        private readonly Queue<double?> _window = new();
        public string Spec { get; } = spec;
        public IPAddress? Address { get; set; }
        public DateTimeOffset Resolved { get; set; } = DateTimeOffset.MinValue;
        private IPAddress? _lastIp;
        private double? _last;
        private string? _error;

        public void Record(IPAddress? ip, double? ms, string? error, int window)
        {
            lock (_window)
            {
                if (ip is not null && _lastIp is not null && !ip.Equals(_lastIp)) _window.Clear(); // gateway/DNS changed: new window
                if (ip is not null) _lastIp = ip;
                _window.Enqueue(ms);
                while (_window.Count > window) _window.Dequeue();
                _last = ms;
                _error = error;
            }
        }

        public ProbeTargetResult Result()
        {
            lock (_window)
            {
                var ok = _window.Where(x => x is not null).Select(x => x!.Value).ToList();
                double loss = _window.Count == 0 ? 0 : Math.Round(100.0 * (_window.Count - ok.Count) / _window.Count, 1);
                return new ProbeTargetResult(Spec, _lastIp?.ToString(), _last, ok.Count > 0 ? Math.Round(ok.Average(), 2) : null, loss, _window.Count, _error);
            }
        }
    }
}
