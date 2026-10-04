using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.PortScan;

/// <summary>
/// TCP connect scan with per-port RTT and optional banner grab. Concurrency follows the <see cref="PortScanProfile"/>.
/// Reports Open / Closed (refused) / Filtered (timeout). Sets <see cref="DeviceFlags.CleartextManagement"/> where warranted.
/// </summary>
public sealed class PortScanProbe : IDeviceProbe
{
    private const string Source = "port";
    private readonly IDeviceStore _store;
    private readonly ILogger<PortScanProbe> _log;

    public PortScanProbe(IDeviceStore store, ILogger<PortScanProbe> log) { _store = store; _log = log; }

    public string Name => "Port scan";
    public int Order => 300;

    public bool AppliesTo(Device device, ScanContext ctx) =>
        ctx.Settings.PortScan != PortScanProfile.Off && device.PrimaryIPv4 is not null;

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        var profile = ctx.Settings.PortScan;
        if (profile == PortScanProfile.Off) return;

        var ports = BuildPortList(ctx.Settings.ExtraPorts);
        int concurrency = profile switch
        {
            PortScanProfile.Stealth => 1,
            PortScanProfile.Balanced => 32,
            PortScanProfile.FastLan => 256,
            _ => 16,
        };
        var connectTimeout = profile == PortScanProfile.Stealth ? TimeSpan.FromMilliseconds(1200) : TimeSpan.FromMilliseconds(800);
        var openPorts = new List<int>();
        bool changed = false;

        using var gate = new SemaphoreSlim(concurrency);
        var tasks = ports.Select(async port =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (profile == PortScanProfile.Stealth) await Task.Delay(Random.Shared.Next(40, 120), ct).ConfigureAwait(false);
                var (state, rtt) = await ConnectAsync(ip, port, connectTimeout, ct).ConfigureAwait(false);
                if (device.SetPort(new PortInfo(port, "tcp", state, ServiceName(port), null, rtt))) changed = true;
                if (state == PortState.Open) lock (openPorts) openPorts.Add(port);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "connect {Ip}:{Port}", ip, port); }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);

        if (ctx.Settings.BannerGrab && openPorts.Count > 0)
            changed |= await GrabBannersAsync(device, ip, openPorts, ct).ConfigureAwait(false);

        changed |= ApplyCleartextFlag(device, openPorts);
        if (changed) _store.NotifyChanged(device, Source);
    }

    private static int[] BuildPortList(string extra)
    {
        var set = new SortedSet<int>(TopPorts.Default);
        foreach (var p in IpUtil.ParsePorts(extra)) set.Add(p);
        return set.ToArray();
    }

    private static async Task<(PortState State, double? RttMs)> ConnectAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var client = new TcpClient(ip.AddressFamily);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            await client.ConnectAsync(ip, port, timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();
            return (PortState.Open, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (PortState.Filtered, null); }
        catch (SocketException se) when (se.SocketErrorCode is SocketError.ConnectionRefused) { return (PortState.Closed, sw.Elapsed.TotalMilliseconds); }
        catch (SocketException se) when (se.SocketErrorCode is SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.TimedOut) { return (PortState.Filtered, null); }
        catch { return (PortState.Filtered, null); }
    }

    private async Task<bool> GrabBannersAsync(Device device, IPAddress ip, List<int> openPorts, CancellationToken ct)
    {
        bool changed = false;
        using var gate = new SemaphoreSlim(8);
        var tasks = openPorts.Select(async port =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                bool https = IsTlsPort(port);
                var banner = await BannerGrabber.GrabAsync(ip, port, https, TimeSpan.FromMilliseconds(1500), ct).ConfigureAwait(false);
                if (banner is null) return;
                if (ApplyBanner(device, port, banner)) changed = true;
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "banner {Ip}:{Port}", ip, port); }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        return changed;
    }

    private static bool IsTlsPort(int p) => p is 443 or 8443 or 9443 or 4443 or 4433 or 5001 or 8006 or 6443 or 10443 or 8834 or 636 or 993 or 995 or 465 or 8883 or 853 or 2083 or 2087 or 2096;

    private static bool ApplyBanner(Device device, int port, BannerResult banner)
    {
        bool changed = false;
        var bannerText = banner.ServerHeader ?? banner.Title ?? banner.Raw;
        changed |= device.AddService(new ServiceInfo(banner.Protocol, port, banner.Title ?? banner.ServerHeader ?? ServiceName(port) ?? "", null, bannerText));

        if (!string.IsNullOrWhiteSpace(banner.ServerHeader))
        {
            changed |= device.SetProperty($"http.server.{port}", banner.ServerHeader);
            changed |= VendorFromText(device, banner.ServerHeader, Confidence.Http);
        }
        if (!string.IsNullOrWhiteSpace(banner.Title))
        {
            changed |= device.SetProperty($"http.title.{port}", banner.Title);
            changed |= VendorFromText(device, banner.Title, Confidence.Http);
        }
        if (!string.IsNullOrWhiteSpace(banner.Realm))
        {
            changed |= device.SetProperty($"http.realm.{port}", banner.Realm);
            changed |= VendorFromText(device, banner.Realm, Confidence.Http);
        }
        if (!string.IsNullOrWhiteSpace(banner.RedirectLocation))
            changed |= device.SetProperty($"http.redirect.{port}", banner.RedirectLocation);

        // SSH/FTP/SMTP first line → OS/product hint
        if (banner.Protocol == "line" && !string.IsNullOrWhiteSpace(banner.Raw))
        {
            changed |= device.SetProperty($"banner.{port}", banner.Raw!);
            if (banner.Raw!.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase))
            {
                changed |= device.AddEvidence("ssh", Fields.Service, banner.Raw, Confidence.Port);
                var os = OsFromSsh(banner.Raw);
                if (os is not null) changed |= device.AddEvidence("ssh", Fields.Os, os, Confidence.Port);
            }
        }
        if (banner.Protocol == "rtsp" && !string.IsNullOrWhiteSpace(banner.ServerHeader))
            changed |= device.AddEvidence("rtsp", Fields.DeviceType, nameof(DeviceType.Camera), Confidence.Port);
        return changed;
    }

    private static string? OsFromSsh(string banner)
    {
        if (banner.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase)) return "Linux (Ubuntu)";
        if (banner.Contains("Debian", StringComparison.OrdinalIgnoreCase)) return "Linux (Debian)";
        if (banner.Contains("FreeBSD", StringComparison.OrdinalIgnoreCase)) return "FreeBSD";
        if (banner.Contains("RouterOS", StringComparison.OrdinalIgnoreCase)) return "MikroTik RouterOS";
        if (banner.Contains("dropbear", StringComparison.OrdinalIgnoreCase)) return "Embedded Linux (Dropbear)";
        if (banner.Contains("Windows", StringComparison.OrdinalIgnoreCase)) return "Windows";
        return null;
    }

    private static bool VendorFromText(Device device, string text, double confidence)
    {
        foreach (var (needle, field, value) in Signatures)
            if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return device.AddEvidence("http", field, value, confidence);
        return false;
    }

    private static readonly (string Needle, string Field, string Value)[] Signatures =
    {
        ("Synology", Fields.Brand, "Synology"),
        ("UniFi", Fields.Brand, "Ubiquiti"),
        ("Ubiquiti", Fields.Brand, "Ubiquiti"),
        ("EdgeOS", Fields.Brand, "Ubiquiti"),
        ("NETGEAR", Fields.Brand, "Netgear"),
        ("MikroTik", Fields.Brand, "MikroTik"),
        ("RouterOS", Fields.Brand, "MikroTik"),
        ("pfSense", Fields.Brand, "pfSense"),
        ("OPNsense", Fields.Brand, "OPNsense"),
        ("FortiGate", Fields.Brand, "Fortinet"),
        ("iDRAC", Fields.Brand, "Dell"),
        ("iLO", Fields.Brand, "HP"),
        ("Proxmox", Fields.Brand, "Proxmox"),
        ("TP-LINK", Fields.Brand, "TP-Link"),
        ("Tasmota", Fields.Brand, "Tasmota"),
        ("QNAP", Fields.Brand, "QNAP"),
        ("Home Assistant", Fields.Brand, "Home Assistant"),
        ("AVM FRITZ", Fields.Brand, "AVM"),
        ("FRITZ!Box", Fields.Brand, "AVM"),
    };

    private static bool ApplyCleartextFlag(Device device, List<int> openPorts)
    {
        bool telnetOrFtp = openPorts.Contains(23) || openPorts.Contains(21);
        bool httpNoHttps = (openPorts.Contains(80) || openPorts.Contains(8080))
            && !openPorts.Contains(443) && !openPorts.Contains(8443)
            && (device.GetProperty("http.realm.80") is not null || device.GetProperty("http.realm.8080") is not null
                || device.Properties.Keys.Any(k => k.StartsWith("http.realm.", StringComparison.Ordinal)));
        if (telnetOrFtp || httpNoHttps)
        {
            if (!device.Has(DeviceFlags.CleartextManagement)) { device.SetFlag(DeviceFlags.CleartextManagement); return true; }
        }
        return false;
    }

    public static string? ServiceName(int port) => port switch
    {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns", 80 => "http", 110 => "pop3",
        135 => "msrpc", 139 => "netbios-ssn", 143 => "imap", 161 => "snmp", 443 => "https", 445 => "smb",
        515 => "printer", 554 => "rtsp", 587 => "submission", 631 => "ipp", 993 => "imaps", 995 => "pop3s",
        1400 => "sonos", 1883 => "mqtt", 3306 => "mysql", 3389 => "rdp", 5000 => "upnp/synology", 5001 => "synology-https",
        5432 => "postgres", 5683 => "coap", 5900 => "vnc", 6443 => "kubernetes", 7000 => "airplay", 8006 => "proxmox",
        8008 => "cast", 8009 => "cast-tls", 8080 => "http-alt", 8123 => "home-assistant", 8291 => "winbox",
        8443 => "https-alt", 8728 => "mikrotik-api", 8883 => "mqtts", 9100 => "jetdirect", 32400 => "plex", 62078 => "iphone-sync",
        _ => null,
    };
}
