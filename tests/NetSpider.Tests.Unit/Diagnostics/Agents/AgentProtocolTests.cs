using System.Text;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class AgentProtocolTests
{
    internal static readonly byte[] Key = Convert.FromBase64String(AgentProtocol.GenerateKey());

    internal static ProbeAgentReport Report(string id = "LAPTOP-WIFI", DateTimeOffset? time = null, params ProbeTargetResult[] results) =>
        new(id, "laptop", "10.40.3.20", "60:FF:9E:10:20:30", "Wi-Fi", time ?? DateTimeOffset.Now,
            results.Length > 0 ? results : [new ProbeTargetResult("gw", "10.40.0.1", 2.1, 2.4, 0, 10, null)],
            null, "10.40.0.1", "1.0.0");

    [Fact]
    public void Seal_then_open_roundtrips()
    {
        var report = Report();
        var dgram = AgentProtocol.Seal(report, Key);
        Assert.True(dgram.Length < AgentProtocol.MaxDatagramBytes);
        Assert.Equal(AgentOpenResult.Ok, AgentProtocol.Open(dgram, Key, DateTimeOffset.UtcNow, new ReplayCache(), out var opened));
        Assert.NotNull(opened);
        Assert.Equal(report.AgentId, opened!.AgentId);
        Assert.Equal(report.Results.Single(), opened.Results.Single());
        var json = Encoding.UTF8.GetString(dgram);
        Assert.Contains("\"v\":1", json);
        Assert.Contains("\"agentId\":\"LAPTOP-WIFI\"", json);
        Assert.Contains("\"lossPercent\":0", json); // camelCase payload
    }

    [Fact]
    public void Sealed_size_does_not_depend_on_random_nonce_or_signature()
    {
        // base64 '+' used to be JSON-escaped (+), so sizes varied with the random nonce/HMAC and chunking could overshoot
        var report = Report();
        var sizes = Enumerable.Range(0, 200).Select(_ => AgentProtocol.Seal(report, Key, DateTimeOffset.UtcNow).Length).Distinct().ToList();
        Assert.Single(sizes);
    }

    [Fact]
    public void Tampered_payload_is_rejected()
    {
        var json = Encoding.UTF8.GetString(AgentProtocol.Seal(Report(), Key));
        var tampered = Encoding.UTF8.GetBytes(json.Replace("\"lossPercent\":0", "\"lossPercent\":100"));
        Assert.Equal(AgentOpenResult.BadSignature, AgentProtocol.Open(tampered, Key, DateTimeOffset.UtcNow, null, out _));

        var renamed = Encoding.UTF8.GetBytes(json.Replace("\"agentId\":\"LAPTOP-WIFI\",\"ts\"", "\"agentId\":\"OTHER\",\"ts\""));
        Assert.Equal(AgentOpenResult.BadSignature, AgentProtocol.Open(renamed, Key, DateTimeOffset.UtcNow, null, out _));
    }

    [Fact]
    public void Wrong_key_is_rejected()
    {
        var dgram = AgentProtocol.Seal(Report(), Key);
        var other = Convert.FromBase64String(AgentProtocol.GenerateKey());
        Assert.Equal(AgentOpenResult.BadSignature, AgentProtocol.Open(dgram, other, DateTimeOffset.UtcNow, null, out var r));
        Assert.Null(r);
    }

    [Fact]
    public void Replay_is_rejected()
    {
        var cache = new ReplayCache();
        var dgram = AgentProtocol.Seal(Report(), Key);
        Assert.Equal(AgentOpenResult.Ok, AgentProtocol.Open(dgram, Key, DateTimeOffset.UtcNow, cache, out _));
        Assert.Equal(AgentOpenResult.Replay, AgentProtocol.Open(dgram, Key, DateTimeOffset.UtcNow, cache, out _));
        // a fresh datagram with the same content but a new nonce is fine
        Assert.Equal(AgentOpenResult.Ok, AgentProtocol.Open(AgentProtocol.Seal(Report(), Key), Key, DateTimeOffset.UtcNow, cache, out _));
    }

    [Fact]
    public void Clock_skew_over_two_minutes_is_rejected()
    {
        var now = DateTimeOffset.UtcNow;
        var old = AgentProtocol.Seal(Report(), Key, now - TimeSpan.FromMinutes(3));
        var future = AgentProtocol.Seal(Report(), Key, now + TimeSpan.FromMinutes(3));
        var fine = AgentProtocol.Seal(Report(), Key, now - TimeSpan.FromSeconds(90));
        Assert.Equal(AgentOpenResult.Skew, AgentProtocol.Open(old, Key, now, null, out _));
        Assert.Equal(AgentOpenResult.Skew, AgentProtocol.Open(future, Key, now, null, out _));
        Assert.Equal(AgentOpenResult.Ok, AgentProtocol.Open(fine, Key, now, null, out _));
    }

    [Fact]
    public void Garbage_and_wrong_version_are_rejected()
    {
        Assert.Equal(AgentOpenResult.Malformed, AgentProtocol.Open("hello"u8, Key, DateTimeOffset.UtcNow, null, out _));
        Assert.Equal(AgentOpenResult.Malformed, AgentProtocol.Open("{}"u8, Key, DateTimeOffset.UtcNow, null, out _));
        var v2 = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(AgentProtocol.Seal(Report(), Key)).Replace("{\"v\":1", "{\"v\":2"));
        Assert.Equal(AgentOpenResult.UnsupportedVersion, AgentProtocol.Open(v2, Key, DateTimeOffset.UtcNow, null, out _));
        Assert.Equal(AgentOpenResult.TooLarge, AgentProtocol.Open(new byte[20000], Key, DateTimeOffset.UtcNow, null, out _));
    }

    [Fact]
    public void Report_serialization_roundtrips_with_wifi()
    {
        var wifi = new WifiLinkSample(DateTimeOffset.Now, true, "Office", Mac.Parse("AA:BB:CC:00:11:22"), 36, "5 GHz", -55, 90, 866.7, 780, "802.11ax", null, 3.2);
        var report = Report() with
        {
            Wifi = wifi,
            Results = [new ProbeTargetResult("gw", "10.40.0.1", 1.5, 2, 0, 10, null), new ProbeTargetResult("nas", null, null, null, 100, 10, "TimedOut")],
        };
        var bytes = AgentProtocol.SerializeReport(report);
        Assert.Contains("\"bssid\":\"AA:BB:CC:00:11:22\"", Encoding.UTF8.GetString(bytes));
        var back = AgentProtocol.DeserializeReport(bytes)!;
        Assert.Equal(report.AgentId, back.AgentId);
        Assert.Equal(report.Time, back.Time);
        Assert.Equal(report.Wifi, back.Wifi);
        Assert.Equal(report.Results, back.Results);
        Assert.Equal(report with { Results = back.Results }, back);
    }

    [Fact]
    public void Large_reports_are_split_below_8KB_and_merge_back()
    {
        var results = Enumerable.Range(0, 300)
            .Select(i => new ProbeTargetResult($"host-{i}.example.internal", $"10.1.{i / 256}.{i % 256}", i, i, 0, 10, i % 7 == 0 ? "TimedOut" : null))
            .ToArray();
        var report = Report(results: results) with { Wifi = new WifiLinkSample(DateTimeOffset.Now, true, "x", null, 1, null, -50, 100, 1, 1, null, null, null) };
        var dgrams = AgentProtocol.SealChunked(report, Key);
        Assert.True(dgrams.Count > 1);
        var cache = new ReplayCache();
        var all = new List<ProbeTargetResult>();
        int withWifi = 0;
        foreach (var d in dgrams)
        {
            Assert.True(d.Length <= AgentProtocol.MaxDatagramBytes, $"datagram {d.Length} bytes");
            Assert.Equal(AgentOpenResult.Ok, AgentProtocol.Open(d, Key, DateTimeOffset.UtcNow, cache, out var part));
            Assert.Equal(report.Time, part!.Time);
            all.AddRange(part.Results);
            if (part.Wifi is not null) withWifi++;
        }
        Assert.Equal(1, withWifi);
        Assert.Equal(results, all);
    }

    [Fact]
    public void Discovery_reply_only_for_a_valid_challenge_tag()
    {
        var req = AgentProtocol.BuildDiscoveryRequest(Key, out var challenge);
        var reply = AgentProtocol.TryBuildDiscoveryReply(req, Key, 47810);
        Assert.NotNull(reply);
        Assert.StartsWith("NETSPIDER_HUB 47810 ", Encoding.ASCII.GetString(reply!));
        Assert.True(AgentProtocol.TryParseDiscoveryReply(reply, Key, challenge, out var port));
        Assert.Equal(47810, port);

        // wrong key, tampered tag, missing tag and plain probes get no answer
        var other = Convert.FromBase64String(AgentProtocol.GenerateKey());
        Assert.Null(AgentProtocol.TryBuildDiscoveryReply(req, other, 47810));
        var text = Encoding.ASCII.GetString(req);
        var parts = text.Split(' ');
        var badTag = Convert.FromBase64String(parts[2]); badTag[0] ^= 1;
        Assert.Null(AgentProtocol.TryBuildDiscoveryReply(Encoding.ASCII.GetBytes($"{parts[0]} {parts[1]} {Convert.ToBase64String(badTag)}"), Key, 47810));
        Assert.Null(AgentProtocol.TryBuildDiscoveryReply(Encoding.ASCII.GetBytes($"{parts[0]} {parts[1]}"), Key, 47810));
        Assert.Null(AgentProtocol.TryBuildDiscoveryReply("NETSPIDER_HUB?"u8, Key, 47810));

        // replayed request is ignored when a replay cache is used
        var cache = new ReplayCache();
        Assert.NotNull(AgentProtocol.TryBuildDiscoveryReply(req, Key, 47810, cache));
        Assert.Null(AgentProtocol.TryBuildDiscoveryReply(req, Key, 47810, cache));

        // the agent rejects a reply that was not made with the key / for its challenge, or with a swapped port
        Assert.False(AgentProtocol.TryParseDiscoveryReply(reply, other, challenge, out _));
        AgentProtocol.BuildDiscoveryRequest(Key, out var otherChallenge);
        Assert.False(AgentProtocol.TryParseDiscoveryReply(reply, Key, otherChallenge, out _));
        var swapped = Encoding.ASCII.GetString(reply).Replace("47810", "4444");
        Assert.False(AgentProtocol.TryParseDiscoveryReply(Encoding.ASCII.GetBytes(swapped), Key, challenge, out _));
    }

    [Fact]
    public void Replay_cache_is_bounded()
    {
        var cache = new ReplayCache(capacity: 100);
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < 500; i++) Assert.True(cache.TryAdd("n" + i, now));
        Assert.True(cache.Count <= 100);
        Assert.False(cache.TryAdd("n499", now));
        // old entries expire after the retention period
        Assert.True(cache.TryAdd("n499", now + TimeSpan.FromMinutes(10)));
    }

    [Fact]
    public void Key_parsing()
    {
        Assert.True(AgentProtocol.TryParseKey(AgentProtocol.GenerateKey(), out var k));
        Assert.Equal(32, k.Length);
        Assert.False(AgentProtocol.TryParseKey("", out _));
        Assert.False(AgentProtocol.TryParseKey("not base64!", out _));
        Assert.False(AgentProtocol.TryParseKey(Convert.ToBase64String(new byte[8]), out _));
    }
}
