using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Exporters;
using NetSpider.Export.Json;

namespace NetSpider.Tests.Integration.Export;

public sealed class ExporterTests : IDisposable
{
    private readonly string _dir = TestData.TempDir();
    private string PathFor(IExporter e) => Path.Combine(_dir, "sub", "export" + e.FileExtension);

    // ------------------------------------------------------------------ JSON

    [Fact]
    public async Task Json_export_parses_back_with_all_sections()
    {
        var data = TestData.Build();
        var exp = new JsonExporter();
        var path = PathFor(exp);
        await exp.ExportAsync(path, data);

        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = doc.RootElement;
        Assert.Equal("NetSpider", root.GetProperty("generator").GetString());

        var devices = root.GetProperty("devices");
        Assert.Equal(data.Devices.Count, devices.GetArrayLength());
        var router = devices.EnumerateArray().Single(d => d.GetProperty("mac").GetString() == "00:11:32:AA:BB:01");
        Assert.Equal("192.168.1.1", router.GetProperty("iPv4")[0].GetString());
        Assert.Equal("Router", router.GetProperty("type").GetString());
        Assert.Contains("Gateway", router.GetProperty("flags").EnumerateArray().Select(f => f.GetString()));
        Assert.Equal(22, router.GetProperty("ports")[0].GetProperty("port").GetInt32());
        Assert.True(router.GetProperty("latency").GetProperty("Icmp").GetProperty("avg").GetDouble() > 0.6);

        var evil = devices.EnumerateArray().Single(d => d.GetProperty("mac").GetString() == TestData.EvilMac.ToString());
        Assert.Equal(TestData.Evil, evil.GetProperty("model").GetString());

        Assert.Equal(2, root.GetProperty("links").GetArrayLength());
        Assert.Equal(3, root.GetProperty("alerts").GetArrayLength());
        Assert.Equal("Critical", root.GetProperty("alerts")[0].GetProperty("severity").GetString());

        var net = root.GetProperty("network");
        Assert.Equal(2, net.GetProperty("segments").GetArrayLength());
        Assert.Equal("192.168.1.0/24", net.GetProperty("segments")[0].GetProperty("cidr").GetString());
        Assert.Equal(2, net.GetProperty("vlans").GetArrayLength());
        Assert.Equal(2, net.GetProperty("dhcpServers").GetArrayLength());
        Assert.Single(net.GetProperty("stp").EnumerateArray());
        Assert.Equal("203.0.113.7", net.GetProperty("wan").GetProperty("externalIp").GetString());
        Assert.Equal(32400, net.GetProperty("wan").GetProperty("portMappings")[0].GetProperty("externalPort").GetInt32());
        Assert.Equal("HomeNet", net.GetProperty("wifi")[0].GetProperty("ssid").GetString());
        Assert.Equal(72, net.GetProperty("health").GetProperty("overallScore").GetInt32());
        Assert.Equal(3, net.GetProperty("health").GetProperty("checks").GetArrayLength());

        // strongly typed round trip through the same options
        var typed = JsonSerializer.Deserialize<ExportDocument>(await File.ReadAllTextAsync(path), ExportJson.Options)!;
        Assert.Equal(TestData.RouterMac, typed.Devices.First(d => d.Mac == TestData.RouterMac).Mac);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.7"), typed.Network.Wan!.ExternalIp);
    }

    // ------------------------------------------------------------------ CSV

    [Fact]
    public async Task Csv_export_has_one_row_per_real_device_and_escapes_fields()
    {
        var data = TestData.Build();
        var exp = new CsvExporter();
        var path = PathFor(exp);
        await exp.ExportAsync(path, data);

        var bytes = await File.ReadAllBytesAsync(path);
        Assert.True(bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }), "UTF-8 BOM expected");
        var rows = ParseCsv(Encoding.UTF8.GetString(bytes).TrimStart('﻿'));

        Assert.Equal(TestData.RealDeviceCount(data) + 1, rows.Count);
        Assert.Equal(CsvExporter.Header, rows[0]);
        Assert.All(rows, r => Assert.Equal(CsvExporter.Header.Length, r.Count));
        var evil = rows.Single(r => r[0] == TestData.EvilMac.ToString());
        Assert.Equal(TestData.Evil, evil[Array.IndexOf(CsvExporter.Header, "Model")]);
        Assert.DoesNotContain(rows, r => r[0] == SyntheticNodes.Internet.ToString());
        Assert.Equal("22, 443", rows.Single(r => r[0] == TestData.RouterMac.ToString())[Array.IndexOf(CsvExporter.Header, "Open Ports")]);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line1\nline2", "\"line1\nline2\"")]
    [InlineData("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0")]
    [InlineData("-12", "-12")]
    [InlineData(" padded", "\" padded\"")]
    public void Csv_escape(string input, string expected) => Assert.Equal(expected, CsvExporter.Escape(input));

    /// <summary>Minimal RFC 4180 parser.</summary>
    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inQuotes)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                else if (c == '"') inQuotes = false;
                else field.Append(c);
            }
            else if (c == '"') inQuotes = true;
            else if (c == ',') { row.Add(field.ToString()); field.Clear(); }
            else if (c == '\r') { }
            else if (c == '\n') { row.Add(field.ToString()); field.Clear(); rows.Add(row); row = new List<string>(); }
            else field.Append(c);
        }
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); rows.Add(row); }
        return rows;
    }

    // ------------------------------------------------------------------ Nmap XML

    [Fact]
    public async Task Nmap_xml_has_valid_nmaprun_structure()
    {
        var data = TestData.Build();
        var exp = new NmapXmlExporter();
        var path = PathFor(exp);
        await exp.ExportAsync(path, data);

        var raw = await File.ReadAllTextAsync(path);
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", raw);
        var doc = XDocument.Load(path);
        Assert.Equal("nmaprun", doc.DocumentType?.Name);
        var run = doc.Root!;
        Assert.Equal("nmaprun", run.Name.LocalName);
        foreach (var attr in new[] { "scanner", "args", "start", "startstr", "version", "xmloutputversion" }) Assert.NotNull(run.Attribute(attr));
        Assert.True(long.Parse(run.Attribute("start")!.Value) > 0);
        var scaninfo = run.Elements("scaninfo").First();
        Assert.Equal("tcp", scaninfo.Attribute("protocol")!.Value);
        Assert.Equal("22-23,443,5001,8080", scaninfo.Attribute("services")!.Value);

        // element order expected by nmap.dtd: scaninfo, verbose, debugging, host*, runstats
        var names = run.Elements().Select(e => e.Name.LocalName).ToList();
        Assert.True(names.IndexOf("debugging") < names.IndexOf("host"));
        Assert.Equal("runstats", names[^1]);

        var hosts = run.Elements("host").ToList();
        Assert.Equal(TestData.RealDeviceCount(data), hosts.Count);
        Assert.All(hosts, h =>
        {
            var st = h.Element("status")!;
            Assert.Contains(st.Attribute("state")!.Value, new[] { "up", "down" });
            Assert.NotNull(st.Attribute("reason"));
            Assert.NotNull(st.Attribute("reason_ttl"));
            Assert.All(h.Elements("address"), a => Assert.Contains(a.Attribute("addrtype")!.Value, new[] { "ipv4", "ipv6", "mac" }));
            Assert.Equal("ipv4", h.Elements("address").First().Attribute("addrtype")!.Value);
            Assert.NotNull(h.Element("hostnames"));
        });

        var router = hosts.Single(h => h.Elements("address").Any(a => a.Attribute("addr")!.Value == "192.168.1.1"));
        Assert.Equal("arp-response", router.Element("status")!.Attribute("reason")!.Value);
        var mac = router.Elements("address").Single(a => a.Attribute("addrtype")!.Value == "mac");
        Assert.Equal("00:11:32:AA:BB:01", mac.Attribute("addr")!.Value);
        Assert.Equal("Synology Incorporated", mac.Attribute("vendor")!.Value);
        Assert.Contains(router.Elements("address"), a => a.Attribute("addrtype")!.Value == "ipv6");
        var hn = router.Element("hostnames")!.Elements("hostname").ToList();
        Assert.Equal("router.lan", hn[0].Attribute("name")!.Value);
        Assert.Equal("PTR", hn[0].Attribute("type")!.Value);

        var ports = router.Element("ports")!.Elements("port").ToList();
        Assert.Equal(4, ports.Count);
        var ssh = ports.Single(p => p.Attribute("portid")!.Value == "22");
        Assert.Equal("tcp", ssh.Attribute("protocol")!.Value);
        Assert.Equal("open", ssh.Element("state")!.Attribute("state")!.Value);
        Assert.Equal("syn-ack", ssh.Element("state")!.Attribute("reason")!.Value);
        Assert.Equal("ssh", ssh.Element("service")!.Attribute("name")!.Value);
        Assert.Equal("OpenSSH", ssh.Element("service")!.Attribute("product")!.Value);
        Assert.Equal("9.6p1", ssh.Element("service")!.Attribute("version")!.Value);
        Assert.Equal("probed", ssh.Element("service")!.Attribute("method")!.Value);
        var https = ports.Single(p => p.Attribute("portid")!.Value == "443").Element("service")!;
        Assert.Equal("nginx", https.Attribute("product")!.Value);
        Assert.Equal("1.24.0", https.Attribute("version")!.Value);
        Assert.Equal("ssl", https.Attribute("tunnel")!.Value);
        Assert.Equal("reset", ports.Single(p => p.Attribute("portid")!.Value == "23").Element("state")!.Attribute("reason")!.Value);
        var snmp = ports.Single(p => p.Attribute("portid")!.Value == "161");
        Assert.Equal("udp", snmp.Attribute("protocol")!.Value);
        Assert.Equal("filtered", snmp.Element("state")!.Attribute("state")!.Value);

        var osmatch = router.Element("os")!.Element("osmatch")!;
        Assert.Equal("Linux 4.x (UniFi OS)", osmatch.Attribute("name")!.Value);
        Assert.Equal("95", osmatch.Attribute("accuracy")!.Value);
        Assert.Equal("Linux", osmatch.Element("osclass")!.Attribute("osfamily")!.Value);
        Assert.Equal("router", osmatch.Element("osclass")!.Attribute("type")!.Value);
        var times = router.Element("times")!;
        Assert.Equal("680", times.Attribute("srtt")!.Value);
        Assert.True(long.Parse(times.Attribute("to")!.Value) >= 100000);

        var phone = hosts.Single(h => h.Elements("address").Any(a => a.Attribute("addr")!.Value == "192.168.1.50"));
        Assert.Equal("down", phone.Element("status")!.Attribute("state")!.Value);

        // control characters in banners are sanitized, markup is escaped (XDocument loaded fine)
        var evilSvc = hosts.Single(h => h.Elements("address").Any(a => a.Attribute("addr")!.Value == "192.168.1.100")).Descendants("service").Single();
        Assert.DoesNotContain('\u0001', evilSvc.Attribute("product")!.Value);
        Assert.Contains(hosts.SelectMany(h => h.Descendants("hostname")), h => h.Attribute("name")!.Value == TestData.Evil);

        var rs = run.Element("runstats")!;
        Assert.Equal("success", rs.Element("finished")!.Attribute("exit")!.Value);
        Assert.Equal(TestData.RealDeviceCount(data).ToString(), rs.Element("hosts")!.Attribute("total")!.Value);
        Assert.Equal("1", rs.Element("hosts")!.Attribute("down")!.Value);
    }

    // ------------------------------------------------------------------ HTML

    [Fact]
    public async Task Html_report_contains_devices_and_escapes_content()
    {
        var png = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3 };
        var data = TestData.Build(png);
        var exp = new HtmlReportExporter();
        var path = PathFor(exp);
        await exp.ExportAsync(path, data);
        var html = await File.ReadAllTextAsync(path);

        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.Contains("#070B14", html);
        Assert.Contains("<h1>HomeNet</h1>", html);
        Assert.Contains("<svg class=\"gauge\"", html);
        Assert.Contains(">72</text>", html);
        Assert.Contains("data:image/png;base64," + Convert.ToBase64String(png), html);

        foreach (var d in data.Devices.Where(d => !SyntheticNodes.IsSynthetic(d.Mac)))
            Assert.Contains($">{d.Mac}</td>", html);
        Assert.DoesNotContain(SyntheticNodes.Internet.ToString(), html);
        int deviceRows = html.Split("<tr class=\"dev").Length - 1;
        Assert.Equal(TestData.RealDeviceCount(data), deviceRows);

        // escaping: the only <script> tag is our own sorting script
        Assert.Equal(1, html.Split("<script>").Length - 1);
        Assert.Contains("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &quot;quoted&quot;, comma", html);
        Assert.Contains("Evil &amp; &lt;Co&gt;", html);

        Assert.Contains("203.0.113.7", html);      // WAN
        Assert.Contains("32400", html);            // port mapping
        Assert.Contains("Voice", html);            // VLAN
        Assert.Contains("ROGUE", html);            // DHCP
        Assert.Contains("Rogue DHCP server", html); // alerts
        Assert.Contains("<footer>", html);
        Assert.Contains("table.sortable", html);
    }

    [Fact]
    public void Html_report_omits_topology_without_png()
    {
        var html = HtmlReportExporter.Build(TestData.Build(png: null), DateTimeOffset.Now);
        Assert.DoesNotContain("data:image/png", html);
        Assert.DoesNotContain("id=\"topology\"", html);
    }

    // ------------------------------------------------------------------ pcapng

    [Fact]
    public async Task Pcapng_export_requires_running_capture()
    {
        var src = new FakeFrameSource(_dir) { IsRunning = false };
        var exp = new PcapNgExporter(new SingleServiceProvider(src));
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => exp.ExportAsync(Path.Combine(_dir, "x.pcapng"), TestData.Build()));
        Assert.Contains("capture is not running", ex.Message, StringComparison.OrdinalIgnoreCase);

        var none = new PcapNgExporter(new SingleServiceProvider(null));
        await Assert.ThrowsAsync<InvalidOperationException>(() => none.ExportAsync(Path.Combine(_dir, "y.pcapng"), TestData.Build()));
    }

    [Fact]
    public async Task Pcapng_export_copies_dump()
    {
        var src = new FakeFrameSource(_dir) { IsRunning = true };
        var exp = new PcapNgExporter(new SingleServiceProvider(src));
        var target = Path.Combine(_dir, "out", "capture.pcapng");
        await exp.ExportAsync(target, TestData.Build());
        Assert.Equal("export", src.LastReason);
        Assert.Equal(await File.ReadAllBytesAsync(src.DumpPath!), await File.ReadAllBytesAsync(target));
    }

    public void Dispose() => TestData.TryDelete(_dir);
}
