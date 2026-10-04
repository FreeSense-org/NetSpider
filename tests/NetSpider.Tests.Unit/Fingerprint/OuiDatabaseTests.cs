using System.IO.Compression;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Fingerprint;

namespace NetSpider.Tests.Unit.Fingerprint;

public sealed class BrandNormalizerTests
{
    [Theory]
    [InlineData("Sonos, Inc.", "Sonos")]
    [InlineData("NETGEAR", "Netgear")]
    [InlineData("Apple, Inc.", "Apple")]
    [InlineData("Espressif Inc.", "Espressif")]
    [InlineData("Raspberry Pi Trading Ltd", "Raspberry Pi")]
    [InlineData("TP-LINK TECHNOLOGIES CO.,LTD.", "TP-Link")]
    [InlineData("HUAWEI TECHNOLOGIES CO.,LTD", "Huawei")]
    [InlineData("Hon Hai Precision Ind. Co.,Ltd.", "Foxconn")]
    [InlineData("ASUSTek COMPUTER INC.", "ASUS")]
    [InlineData("Synology Incorporated", "Synology")]
    [InlineData("Ubiquiti Inc", "Ubiquiti")]
    [InlineData("Cisco Systems, Inc", "Cisco")]
    [InlineData("Cisco Meraki", "Meraki")]
    [InlineData("Philips Lighting BV", "Philips Hue")]
    [InlineData("Hangzhou Hikvision Digital Technology Co.,Ltd.", "Hikvision")]
    [InlineData("SYNERGY SYSTEMS AND SOLUTIONS", "Synergy")]
    [InlineData("Juniper Networks", "Juniper")]
    [InlineData("Shenzhen YOUHUA Technology Co., Ltd", "Youhua")]
    [InlineData("Silicon Laboratories", "Silicon Labs")]
    public void Normalizes_company_names(string raw, string expected) => Assert.Equal(expected, BrandNormalizer.Normalize(raw));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Private")]
    [InlineData("IEEE Registration Authority")]
    public void Placeholders_are_null(string? raw) => Assert.Null(BrandNormalizer.Normalize(raw));

    [Theory]
    [InlineData("TP-Link", "tp-link")]
    [InlineData("Bang & Olufsen", "bang-olufsen")]
    [InlineData("Raspberry Pi", "raspberry-pi")]
    public void Keys_are_file_safe(string brand, string key) => Assert.Equal(key, BrandNormalizer.Key(brand));
}

public sealed class OuiDatabaseTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "netspider-oui-" + Guid.NewGuid().ToString("N"));

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private OuiDatabase Offline() => new(NullLogger<OuiDatabase>.Instance, _dir, null, allowDownload: false);

    [Fact]
    public async Task Embedded_snapshot_loads_all_registries()
    {
        using var db = Offline();
        await db.EnsureLoadedAsync();
        Assert.True(db.Count > 45_000, $"only {db.Count} entries");
    }

    [Theory]
    [InlineData("00:0E:58:11:22:33", "Sonos")]
    [InlineData("A0:63:91:00:00:01", "Netgear")]
    [InlineData("00:03:93:AA:BB:CC", "Apple")]
    [InlineData("24:0A:C4:01:02:03", "Espressif")]
    [InlineData("B8:27:EB:12:34:56", "Raspberry Pi")]
    [InlineData("DC:A6:32:12:34:56", "Raspberry Pi")]
    [InlineData("50:C7:BF:00:11:22", "TP-Link")]
    [InlineData("E0:63:DA:00:11:22", "Ubiquiti")]
    [InlineData("00:11:32:00:11:22", "Synology")]
    [InlineData("00:17:88:00:11:22", "Philips Hue")]
    [InlineData("00:15:5D:01:02:03", "Microsoft")]
    [InlineData("F4:F5:D8:01:02:03", "Google")]
    public void Looks_up_ma_l(string mac, string brand)
    {
        using var db = Offline();
        Assert.Equal(brand, db.Lookup(Mac.Parse(mac)));
    }

    [Fact]
    public void Longest_prefix_wins_for_ma_m_and_ma_s()
    {
        using var db = Offline();
        Assert.Equal("Synergy", db.Lookup(Mac.Parse("C8:5C:E2:70:00:01")));        // MA-M C85CE27
        Assert.Equal("DATA", db.Lookup(Mac.Parse("8C:1F:64:AF:A0:01")));            // MA-S 8C1F64AFA ("DATA ELECTRONIC DEVICES, INC")
        Assert.NotEqual("IEEE Registration Authority", db.Lookup(Mac.Parse("8C:1F:64:00:00:00")));
    }

    [Theory]
    [InlineData("DA:A1:19:12:34:56")] // randomized (LAA) phone MAC
    [InlineData("02:42:AC:11:00:02")] // docker LAA
    [InlineData("01:00:5E:00:00:FB")] // multicast
    [InlineData("00:00:00:00:00:00")]
    public void Private_and_special_macs_return_null(string mac)
    {
        using var db = Offline();
        Assert.Null(db.Lookup(Mac.Parse(mac)));
    }

    [Fact]
    public void Parses_ieee_csv_with_quotes()
    {
        const string csv = "Registry,Assignment,Organization Name,Organization Address\r\n" +
                           "MA-L,000E58,\"Sonos, Inc.\",301 Coromar Dr Goleta CA US 93117 \r\n" +
                           "MA-L,50C7BF,\"TP-LINK TECHNOLOGIES CO.,LTD.\",\"Building 24(floors 1,3,4,5) Shenzhen \"\"Guangdong\"\" CN\"\r\n" +
                           "MA-M,C85CE27,SYNERGY SYSTEMS AND SOLUTIONS,\"A1526, GREEN FIELDS\"\r\n";
        var rows = OuiDatabase.ParseIeeeCsv(csv).ToList();
        Assert.Equal(3, rows.Count);
        Assert.Equal(("000E58", "Sonos, Inc."), rows[0]);
        Assert.Equal(("50C7BF", "TP-LINK TECHNOLOGIES CO.,LTD."), rows[1]);
        Assert.Equal("C85CE27", rows[2].Assignment);
    }

    [Fact]
    public async Task Refresh_downloads_and_writes_cache_when_missing()
    {
        var handler = new FakeCsvHandler();
        using (var db = new OuiDatabase(NullLogger<OuiDatabase>.Instance, _dir, handler, allowDownload: true))
        {
            await db.EnsureLoadedAsync();
            Assert.NotNull(db.RefreshTask);
            await db.RefreshTask!;
            Assert.Equal(3, handler.Requests);
            Assert.Equal("Acme Widgets", db.Lookup(Mac.Parse("A8:00:00:00:00:01")));
        }
        Assert.True(File.Exists(Path.Combine(_dir, "oui.txt.gz")));

        // a second instance reads the fresh cache and does not download again
        var handler2 = new FakeCsvHandler();
        using var db2 = new OuiDatabase(NullLogger<OuiDatabase>.Instance, _dir, handler2, allowDownload: true);
        await db2.EnsureLoadedAsync();
        Assert.Null(db2.RefreshTask);
        Assert.Equal(0, handler2.Requests);
        Assert.Equal("Acme Widgets", db2.Lookup(Mac.Parse("A8:00:00:00:00:01")));
    }

    [Fact]
    public async Task Failed_refresh_keeps_embedded_data()
    {
        using var db = new OuiDatabase(NullLogger<OuiDatabase>.Instance, _dir, new FailingHandler(), allowDownload: true);
        await db.EnsureLoadedAsync();
        await db.RefreshTask!;
        Assert.Equal("Sonos", db.Lookup(Mac.Parse("00:0E:58:11:22:33")));
        Assert.False(File.Exists(Path.Combine(_dir, "oui.txt.gz")));
    }

    private sealed class FakeCsvHandler : HttpMessageHandler
    {
        public int Requests;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Requests);
            var sb = new System.Text.StringBuilder("Registry,Assignment,Organization Name,Organization Address\n");
            var path = request.RequestUri!.AbsolutePath;
            int digits = path.Contains("oui36") ? 9 : path.Contains("oui28") ? 7 : 6;
            for (int i = 0; i < 400; i++)
            {
                var prefix = digits == 6 ? (0xA80000 + i).ToString("X6") : (digits == 7 ? (0xB000000 + i).ToString("X7") : (0xC00000000L + i).ToString("X9"));
                sb.Append($"MA-X,{prefix},\"Acme Widgets, Inc.\",Somewhere\n");
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(sb.ToString()) });
        }
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
    }

    [Fact]
    public void Compact_format_round_trips()
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, true))
        using (var w = new StreamWriter(gz)) w.Write("000E58\tSonos, Inc.\nC85CE27\tSYNERGY SYSTEMS AND SOLUTIONS\n8C1F64AFA\tFoo Bar GmbH\n");
        ms.Position = 0;
        var t = OuiDatabase.ReadCompact(ms);
        Assert.Equal("Sonos", t.L24[0x000E58]);
        Assert.Equal("Synergy", t.M28[0xC85CE27]);
        Assert.Equal("Foo Bar", t.S36[0x8C1F64AFA]);
    }
}
