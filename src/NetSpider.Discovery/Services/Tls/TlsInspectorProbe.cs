using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Tls;

/// <summary>
/// Opens a TLS handshake (validation disabled, SNI set to the IP) on known secure ports and mines the server
/// certificate: subject/CN/SAN become hostnames, issuer/subject org gives brand hints, expiry/self-signed set flags.
/// </summary>
public sealed class TlsInspectorProbe : IDeviceProbe
{
    private const string Source = "tls";
    private static readonly int[] TlsPorts = { 443, 8443, 9443, 4443, 5001, 8006, 6443, 10443, 8834, 636, 993, 995, 465, 8883, 853 };

    private readonly IDeviceStore _store;
    private readonly ILogger<TlsInspectorProbe> _log;

    public TlsInspectorProbe(IDeviceStore store, ILogger<TlsInspectorProbe> log) { _store = store; _log = log; }

    public string Name => "TLS inspector";
    public int Order => 310;

    public bool AppliesTo(Device device, ScanContext ctx) =>
        ctx.Settings.TlsInspection && device.PrimaryIPv4 is not null && TargetPorts(device).Any();

    private static IEnumerable<int> TargetPorts(Device device)
    {
        var open = device.Ports.Where(p => p.State == PortState.Open).Select(p => p.Port).ToHashSet();
        foreach (var p in open)
            if (TlsPorts.Contains(p) || LooksTls(device, p)) yield return p;
    }

    private static bool LooksTls(Device device, int port)
    {
        var server = device.GetProperty($"http.server.{port}");
        return server is not null && device.Ports.Any(p => p.Port == port && p.State == PortState.Open && (p.ServiceName?.Contains("tls", StringComparison.OrdinalIgnoreCase) == true));
    }

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        bool changed = false;
        foreach (var port in TargetPorts(device).Distinct().ToArray())
        {
            try { changed |= await InspectAsync(device, ip, port, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogDebug(ex, "TLS {Ip}:{Port}", ip, port); }
        }
        if (changed) _store.NotifyChanged(device, Source);
    }

    private async Task<bool> InspectAsync(Device device, IPAddress ip, int port, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new TcpClient();
        await client.ConnectAsync(ip, port, timeoutCts.Token).ConfigureAwait(false);
        X509Certificate2? captured = null;
        using var ssl = new SslStream(client.GetStream(), false, (_, cert, _, _) =>
        {
            if (cert is not null) captured = new X509Certificate2(cert);
            return true;
        });
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ip.ToString() }, timeoutCts.Token).ConfigureAwait(false);
        if (captured is null) return false;
        return ApplyCertificate(device, port, captured);
    }

    public static bool ApplyCertificate(Device device, int port, X509Certificate2 cert)
    {
        var sans = ExtractSans(cert);
        var cn = ExtractCn(cert.Subject);
        bool selfSigned = cert.Subject == cert.Issuer;
        var issuerOrg = ExtractOrg(cert.Issuer);
        var info = new TlsCertInfo(
            port, cert.Subject, cn, sans, cert.Issuer, issuerOrg,
            cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(),
            cert.SerialNumber, cert.Thumbprint, selfSigned);
        bool changed = device.SetCertificate(info);

        // CN/SAN that aren't IPs become hostnames.
        foreach (var name in sans.Prepend(cn ?? "").Where(n => !string.IsNullOrWhiteSpace(n)))
        {
            var clean = name.StartsWith("*.") ? name[2..] : name;
            if (!IPAddress.TryParse(clean, out _)) changed |= device.SetHostname(Source, clean);
        }

        // Brand hints from subject/issuer organization.
        var subjectOrg = ExtractOrg(cert.Subject);
        foreach (var org in new[] { subjectOrg, issuerOrg })
        {
            var brand = BrandFromOrg(org);
            if (brand is not null) changed |= device.AddEvidence(Source, Fields.Brand, brand, Confidence.Tls);
        }

        if (info.Expired) { if (!device.Has(DeviceFlags.ExpiredCertificate)) { device.SetFlag(DeviceFlags.ExpiredCertificate); changed = true; } }
        if (selfSigned) { if (!device.Has(DeviceFlags.SelfSignedCertificate)) { device.SetFlag(DeviceFlags.SelfSignedCertificate); changed = true; } }
        return changed;
    }

    public static string? BrandFromOrg(string? org)
    {
        if (string.IsNullOrWhiteSpace(org)) return null;
        var o = org.ToLowerInvariant();
        if (o.Contains("synology")) return "Synology";
        if (o.Contains("ubiquiti")) return "Ubiquiti";
        if (o.Contains("fortinet")) return "Fortinet";
        if (o.Contains("idrac") || o.Contains("dell")) return "Dell";
        if (o.Contains("hewlett") || o.Contains("ilo") || o.Contains("hp ")) return "HP";
        if (o.Contains("proxmox")) return "Proxmox";
        if (o.Contains("vmware")) return "VMware";
        if (o.Contains("sophos")) return "Sophos";
        if (o.Contains("pfsense")) return "pfSense";
        if (o.Contains("mikrotik")) return "MikroTik";
        if (o.Contains("avm")) return "AVM";
        if (o.Contains("qnap")) return "QNAP";
        return null;
    }

    private static IReadOnlyList<string> ExtractSans(X509Certificate2 cert)
    {
        var list = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                try { list.AddRange(san.EnumerateDnsNames()); } catch { }
            }
            else if (ext.Oid?.Value == "2.5.29.17")
            {
                // Fallback: parse formatted string ("DNS Name=foo, IP Address=1.2.3.4").
                var formatted = ext.Format(false);
                foreach (var part in formatted.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = part.IndexOf('=');
                    if (eq > 0) list.Add(part[(eq + 1)..].Trim());
                }
            }
        }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static string? ExtractCn(string subject) => ExtractRdn(subject, "CN");
    public static string? ExtractOrg(string dn) => ExtractRdn(dn, "O");

    private static string? ExtractRdn(string dn, string key)
    {
        foreach (var part in dn.Split(',', StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0 && part[..eq].Trim().Equals(key, StringComparison.OrdinalIgnoreCase))
                return part[(eq + 1)..].Trim();
        }
        return null;
    }
}
