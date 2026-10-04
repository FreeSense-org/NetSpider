using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NetSpider.Core.Model;
using NetSpider.Discovery.Services.PortScan;
using NetSpider.Discovery.Services.Snmp;
using NetSpider.Discovery.Services.Tls;

namespace NetSpider.Tests.Unit.Discovery.Services;

public sealed class PortScanAndTlsTests
{
    [Fact]
    public void Parses_Http_Server_Title_Realm()
    {
        var response =
            "HTTP/1.1 401 Unauthorized\r\n" +
            "Server: nginx/1.24 (UniFi OS)\r\n" +
            "WWW-Authenticate: Basic realm=\"NETGEAR GS308E\"\r\n" +
            "Location: https://10.0.0.1/login\r\n\r\n" +
            "<html><head><title>UniFi OS</title></head><body><input type=\"password\"></body></html>";
        var banner = BannerGrabber.ParseHttp(response, https: false);
        Assert.Equal("nginx/1.24 (UniFi OS)", banner.ServerHeader);
        Assert.Equal("UniFi OS", banner.Title);
        Assert.Equal("NETGEAR GS308E", banner.Realm);
        Assert.Equal("https://10.0.0.1/login", banner.RedirectLocation);
        Assert.True(banner.HasLoginForm);
    }

    [Fact]
    public void Top_Ports_Include_Key_Device_Ports()
    {
        foreach (var p in new[] { 1400, 8008, 8009, 5000, 8006, 554, 1883, 9100, 631, 8291, 8728, 32400, 8123, 62078, 10001 })
            Assert.Contains(p, TopPorts.Default);
    }

    [Fact]
    public void Maps_Snmp_Enterprise_Vendors()
    {
        Assert.Equal((uint)14988, Oids.EnterpriseOf("1.3.6.1.4.1.14988.1.1.4"));
        Assert.Equal("MikroTik", Oids.EnterpriseVendors[14988]);
        Assert.Equal("Synology", Oids.EnterpriseVendors[6574]);
        Assert.Equal("Ubiquiti", Oids.EnterpriseVendors[41112]);
        Assert.Null(Oids.EnterpriseOf("1.3.6.1.2.1.1.1.0"));
    }

    [Fact]
    public void Tls_Self_Signed_Certificate_Yields_Hostname_And_Flags()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=diskstation.local, O=Synology Inc.", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("diskstation.local");
        san.AddDnsName("nas.example.com");
        req.CertificateExtensions.Add(san.Build());
        // already-expired cert
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(-1));

        var device = new Device(Mac.Parse("00:11:32:00:00:01"));
        Assert.True(TlsInspectorProbe.ApplyCertificate(device, 443, cert));

        // one hostname is kept per source; the SANs carry the rest
        Assert.Contains(device.Hostnames.Values, v => v is "diskstation.local" or "nas.example.com");
        Assert.Contains(device.Evidence, e => e.Field == Fields.Brand && e.Value == "Synology");
        Assert.True(device.Has(DeviceFlags.SelfSignedCertificate));
        Assert.True(device.Has(DeviceFlags.ExpiredCertificate));
        var info = Assert.Single(device.Certificates);
        Assert.True(info.SelfSigned);
        Assert.Equal("diskstation.local", info.CommonName);
        Assert.Contains("diskstation.local", info.SubjectAltNames);
        Assert.Contains("nas.example.com", info.SubjectAltNames);
    }

    [Fact]
    public void Brand_From_Org_Maps_Known_Vendors()
    {
        Assert.Equal("Ubiquiti", TlsInspectorProbe.BrandFromOrg("Ubiquiti Inc."));
        Assert.Equal("Fortinet", TlsInspectorProbe.BrandFromOrg("Fortinet Ltd."));
        Assert.Null(TlsInspectorProbe.BrandFromOrg("Some Random Org"));
    }
}
