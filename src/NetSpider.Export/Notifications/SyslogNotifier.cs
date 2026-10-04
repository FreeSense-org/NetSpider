using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Export.Notifications;

/// <summary>Sends alerts as RFC 5424 syslog messages over UDP to <see cref="AppSettings.SyslogServer"/>:<see cref="AppSettings.SyslogPort"/>.</summary>
public sealed class SyslogNotifier : INotifier, IDisposable
{
    /// <summary>local0.</summary>
    public const int Facility = 16;
    public const int MaxMessageBytes = 2048;
    private const string SdId = "netspider@32473"; // 32473 = documentation PEN (RFC 5612)

    private readonly ISettingsStore _settings;
    private readonly ILogger<SyslogNotifier> _log;
    private readonly UdpClient _udp = new(AddressFamily.InterNetworkV6);
    private readonly string _host = SafeHostName();
    private readonly int _pid = Environment.ProcessId;

    public SyslogNotifier(ISettingsStore settings, ILogger<SyslogNotifier> log)
    {
        _settings = settings;
        _log = log;
        try { _udp.Client.DualMode = true; } catch { }
    }

    public async Task NotifyAsync(Alert alert, CancellationToken ct = default)
    {
        var s = _settings.Settings;
        if (string.IsNullOrWhiteSpace(s.SyslogServer)) return;
        try
        {
            var endpoint = await ResolveAsync(s.SyslogServer.Trim(), s.SyslogPort is > 0 and < 65536 ? s.SyslogPort : 514, ct).ConfigureAwait(false);
            var bytes = Encoding.UTF8.GetBytes(Format(alert, _host, _pid));
            if (bytes.Length > MaxMessageBytes) bytes = bytes[..MaxMessageBytes];
            await _udp.SendAsync(bytes, endpoint, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning("Syslog send to {Server}:{Port} failed: {Message}", s.SyslogServer, s.SyslogPort, ex.Message);
        }
    }

    private static async Task<IPEndPoint> ResolveAsync(string host, int port, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var ip)) return new IPEndPoint(ip.AddressFamily == AddressFamily.InterNetwork ? ip.MapToIPv6() : ip, port);
        var addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var a = addrs.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault()
            ?? throw new SocketException((int)SocketError.HostNotFound);
        return new IPEndPoint(a.AddressFamily == AddressFamily.InterNetwork ? a.MapToIPv6() : a, port);
    }

    /// <summary>Syslog severity: Critical → 2 (crit), Warning → 4 (warning), Info → 6 (informational).</summary>
    public static int Severity(AlertSeverity s) => s switch
    {
        AlertSeverity.Critical => 2,
        AlertSeverity.Warning => 4,
        _ => 6,
    };

    /// <summary>
    /// <c>&lt;PRI&gt;1 TIMESTAMP HOSTNAME NetSpider PROCID MSGID [netspider@32473 ...] BOM MSG</c>.
    /// </summary>
    public static string Format(Alert alert, string hostName, int processId)
    {
        int pri = Facility * 8 + Severity(alert.Severity);
        var ts = alert.Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        var sd = new StringBuilder("[").Append(SdId)
            .Append(" id=\"").Append(SdEscape(alert.Id.ToString("D"))).Append('"')
            .Append(" severity=\"").Append(alert.Severity).Append('"')
            .Append(" kind=\"").Append(alert.Kind).Append('"');
        if (alert.Source is { } src) sd.Append(" source=\"").Append(src).Append('"');
        if (alert.Rate is { } rate) sd.Append(" rate=\"").Append(rate.ToString("0.##", CultureInfo.InvariantCulture)).Append('"');
        sd.Append(']');
        var msg = string.IsNullOrWhiteSpace(alert.Details) ? alert.Title : $"{alert.Title}: {alert.Details}";
        msg = msg.Replace('\r', ' ').Replace('\n', ' ');
        return $"<{pri}>1 {ts} {Token(hostName, 255)} NetSpider {processId.ToString(CultureInfo.InvariantCulture)} {Token(alert.Kind.ToString(), 32)} {sd} ﻿{msg}";
    }

    /// <summary>PARAM-VALUE escaping: '"', '\' and ']' are backslash-escaped.</summary>
    public static string SdEscape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    /// <summary>Header fields are PRINTUSASCII without spaces; "-" when empty.</summary>
    private static string Token(string s, int max)
    {
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (var c in s)
        {
            if (sb.Length == max) break;
            if (c is > (char)32 and < (char)127) sb.Append(c);
        }
        return sb.Length == 0 ? "-" : sb.ToString();
    }

    private static string SafeHostName()
    {
        try { return Dns.GetHostName(); } catch { return Environment.MachineName; }
    }

    public void Dispose() => _udp.Dispose();
}
