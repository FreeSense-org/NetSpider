using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

// NOTE: this file is compiled into both NetSpider.Diagnostics (hub) and NetSpider.Probe (agent, linked file).
// Keep it free of dependencies beyond NetSpider.Core models and the BCL, and keep it trim/AOT friendly
// (source-generated JSON, no reflection).

/// <summary>Result of opening (verifying) a received report datagram.</summary>
public enum AgentOpenResult { Ok, Malformed, UnsupportedVersion, TooLarge, BadSignature, Skew, Replay }

/// <summary>
/// Wire protocol between NetSpider.Probe agents and the hub.
/// <para>Reports: one UDP datagram per report (or per chunk of targets) to the hub port (default 47810) carrying
/// <c>{"v":1,"agentId":..,"ts":unixMs,"nonce":b64,"payload":{ProbeAgentReport},"sig":b64}</c>.
/// <c>sig</c> = HMAC-SHA256(key, "NSP1\n" + agentId + "\n" + ts + "\n" + nonce + "\n" + payloadBytes) where
/// payloadBytes are the exact UTF-8 bytes of the <c>payload</c> value as transmitted.</para>
/// <para>Discovery: agent broadcasts <c>NETSPIDER_HUB? &lt;challenge&gt; &lt;tag&gt;</c> to UDP 47811 with
/// tag = HMAC(key, "NSPD-REQ\n" + challenge). The hub answers <c>NETSPIDER_HUB &lt;port&gt; &lt;tag2&gt;</c>
/// only when the tag is valid, with tag2 = HMAC(key, "NSPD-RSP\n" + challenge + "\n" + port) so the agent can
/// verify the reply as well. Nobody without the key learns that a hub exists.</para>
/// </summary>
public static class AgentProtocol
{
    public const int Version = 1;
    public const int DefaultPort = 47810;
    public const int DiscoveryPort = 47811;
    /// <summary>Hard limit for a report datagram; agents split targets across datagrams to stay below it.</summary>
    public const int MaxDatagramBytes = 8000;
    public static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(2);

    public const string DiscoveryRequestPrefix = "NETSPIDER_HUB?";
    public const string DiscoveryReplyPrefix = "NETSPIDER_HUB";

    private static readonly byte[] ReportDomain = "NSP1\n"u8.ToArray();
    private static readonly byte[] DiscoveryReqDomain = "NSPD-REQ\n"u8.ToArray();
    private static readonly byte[] DiscoveryRspDomain = "NSPD-RSP\n"u8.ToArray();

    // ---------------------------------------------------------------------------------------------
    //  keys
    // ---------------------------------------------------------------------------------------------

    /// <summary>New random 32-byte key, base64 encoded.</summary>
    public static string GenerateKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    /// <summary>Decodes a base64 key; requires at least 16 bytes.</summary>
    public static bool TryParseKey(string? base64, out byte[] key)
    {
        key = [];
        if (string.IsNullOrWhiteSpace(base64)) return false;
        try { key = Convert.FromBase64String(base64.Trim()); }
        catch (FormatException) { return false; }
        return key.Length >= 16;
    }

    // ---------------------------------------------------------------------------------------------
    //  report envelope
    // ---------------------------------------------------------------------------------------------

    public static byte[] SerializeReport(ProbeAgentReport report) =>
        JsonSerializer.SerializeToUtf8Bytes(report, AgentJsonContext.Default.ProbeAgentReport);

    public static ProbeAgentReport? DeserializeReport(ReadOnlySpan<byte> json) =>
        JsonSerializer.Deserialize(json, AgentJsonContext.Default.ProbeAgentReport);

    /// <summary>Builds one signed datagram for <paramref name="report"/>.</summary>
    public static byte[] Seal(ProbeAgentReport report, byte[] key, DateTimeOffset? now = null, string? nonce = null)
    {
        var payload = SerializeReport(report);
        long ts = (now ?? DateTimeOffset.UtcNow).ToUnixTimeMilliseconds();
        nonce ??= Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var sig = Convert.ToBase64String(Sign(key, report.AgentId, ts, nonce, payload));

        var buffer = new ArrayBufferWriter<byte>(payload.Length + 256);
        // Relaxed escaping keeps base64 "+" literal: with the default encoder "+" becomes 002B, making the datagram size
        // depend on the random nonce/signature and letting SealChunked overshoot MaxDatagramBytes.
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            w.WriteStartObject();
            w.WriteNumber("v", Version);
            w.WriteString("agentId", report.AgentId);
            w.WriteNumber("ts", ts);
            w.WriteString("nonce", nonce);
            w.WritePropertyName("payload");
            w.WriteRawValue(payload, skipInputValidation: true);
            w.WriteString("sig", sig);
            w.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Seals the report, splitting its target results over several datagrams when one would exceed
    /// <see cref="MaxDatagramBytes"/>. Every chunk carries the same <see cref="ProbeAgentReport.Time"/>, so the
    /// hub merges them; Wi-Fi details travel only in the first chunk.
    /// </summary>
    public static IReadOnlyList<byte[]> SealChunked(ProbeAgentReport report, byte[] key, DateTimeOffset? now = null)
    {
        var whole = Seal(report, key, now);
        if (whole.Length <= MaxDatagramBytes) return [whole];

        var output = new List<byte[]>();
        var pending = new List<ProbeTargetResult>();
        bool first = true;
        foreach (var r in report.Results)
        {
            pending.Add(r);
            var probe = Seal(Chunk(report, pending, first), key, now);
            if (probe.Length <= MaxDatagramBytes) continue;
            if (pending.Count == 1)
            {
                // a single oversized result (absurdly long error/name): trim it rather than drop the report
                pending[0] = r with { Target = Trim(r.Target, 200) ?? "", Error = Trim(r.Error, 200) };
                continue;
            }
            pending.RemoveAt(pending.Count - 1);
            output.Add(Seal(Chunk(report, pending, first), key, now));
            first = false;
            pending.Clear();
            pending.Add(r);
        }
        if (pending.Count > 0 || output.Count == 0) output.Add(Seal(Chunk(report, pending, first), key, now));
        return output;

        static ProbeAgentReport Chunk(ProbeAgentReport r, List<ProbeTargetResult> items, bool first) =>
            r with { Results = items.ToArray(), Wifi = first ? r.Wifi : null };
        static string? Trim(string? s, int n) => s is null || s.Length <= n ? s : s[..n];
    }

    /// <summary>Verifies and decodes a datagram. Replay protection uses <paramref name="replay"/> (may be null for tests).</summary>
    public static AgentOpenResult Open(ReadOnlySpan<byte> datagram, byte[] key, DateTimeOffset now, ReplayCache? replay,
        out ProbeAgentReport? report)
    {
        report = null;
        if (datagram.Length > MaxDatagramBytes + 192) return AgentOpenResult.TooLarge;
        try
        {
            var reader = new Utf8JsonReader(datagram);
            using var doc = JsonDocument.ParseValue(ref reader);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return AgentOpenResult.Malformed;
            if (!root.TryGetProperty("v", out var v) || v.ValueKind != JsonValueKind.Number) return AgentOpenResult.Malformed;
            if (v.GetInt32() != Version) return AgentOpenResult.UnsupportedVersion;
            if (!root.TryGetProperty("agentId", out var idEl) || idEl.GetString() is not { Length: > 0 and <= 128 } agentId) return AgentOpenResult.Malformed;
            if (!root.TryGetProperty("ts", out var tsEl) || !tsEl.TryGetInt64(out long ts)) return AgentOpenResult.Malformed;
            if (!root.TryGetProperty("nonce", out var nEl) || nEl.GetString() is not { Length: >= 8 and <= 64 } nonce) return AgentOpenResult.Malformed;
            if (!root.TryGetProperty("payload", out var payloadEl) || payloadEl.ValueKind != JsonValueKind.Object) return AgentOpenResult.Malformed;
            if (!root.TryGetProperty("sig", out var sigEl) || sigEl.GetString() is not { } sigText) return AgentOpenResult.Malformed;

            byte[] sig;
            try { sig = Convert.FromBase64String(sigText); } catch (FormatException) { return AgentOpenResult.BadSignature; }

            var payload = Encoding.UTF8.GetBytes(payloadEl.GetRawText());
            var expected = Sign(key, agentId, ts, nonce, payload);
            if (!CryptographicOperations.FixedTimeEquals(expected, sig)) return AgentOpenResult.BadSignature;

            var sent = DateTimeOffset.FromUnixTimeMilliseconds(ts);
            if ((now - sent).Duration() > MaxSkew) return AgentOpenResult.Skew;

            var parsed = DeserializeReport(payload);
            if (parsed is null || parsed.AgentId != agentId || parsed.Results is null) return AgentOpenResult.Malformed;

            // replay check last, so garbage cannot fill the cache
            if (replay is not null && !replay.TryAdd(agentId + "|" + nonce, now)) return AgentOpenResult.Replay;

            report = parsed;
            return AgentOpenResult.Ok;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or ArgumentException)
        {
            return AgentOpenResult.Malformed;
        }
    }

    public static byte[] Sign(byte[] key, string agentId, long ts, string nonce, ReadOnlySpan<byte> payload)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        h.AppendData(ReportDomain);
        h.AppendData(Encoding.UTF8.GetBytes(agentId + "\n" + ts.ToString(CultureInfo.InvariantCulture) + "\n" + nonce + "\n"));
        h.AppendData(payload);
        return h.GetHashAndReset();
    }

    // ---------------------------------------------------------------------------------------------
    //  discovery
    // ---------------------------------------------------------------------------------------------

    /// <summary>Builds a discovery request; keep <paramref name="challenge"/> to verify the reply.</summary>
    public static byte[] BuildDiscoveryRequest(byte[] key, out byte[] challenge)
    {
        challenge = RandomNumberGenerator.GetBytes(16);
        var tag = Hmac(key, DiscoveryReqDomain, challenge);
        return Encoding.ASCII.GetBytes($"{DiscoveryRequestPrefix} {Convert.ToBase64String(challenge)} {Convert.ToBase64String(tag)}");
    }

    /// <summary>Hub side: returns the reply datagram, or null when the request is not validly tagged with the key.</summary>
    public static byte[]? TryBuildDiscoveryReply(ReadOnlySpan<byte> request, byte[] key, int hubPort, ReplayCache? replay = null, DateTimeOffset? now = null)
    {
        if (request.Length is 0 or > 256) return null;
        string text;
        try { text = Encoding.ASCII.GetString(request).Trim(); } catch { return null; }
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || parts[0] != DiscoveryRequestPrefix) return null;
        byte[] challenge, tag;
        try { challenge = Convert.FromBase64String(parts[1]); tag = Convert.FromBase64String(parts[2]); }
        catch (FormatException) { return null; }
        if (challenge.Length is < 8 or > 64) return null;
        if (!CryptographicOperations.FixedTimeEquals(Hmac(key, DiscoveryReqDomain, challenge), tag)) return null;
        if (replay is not null && !replay.TryAdd("disc|" + parts[1], now ?? DateTimeOffset.UtcNow)) return null;
        var port = hubPort.ToString(CultureInfo.InvariantCulture);
        var rtag = Hmac(key, DiscoveryRspDomain, [.. challenge, .. "\n"u8, .. Encoding.ASCII.GetBytes(port)]);
        return Encoding.ASCII.GetBytes($"{DiscoveryReplyPrefix} {port} {Convert.ToBase64String(rtag)}");
    }

    /// <summary>Agent side: validates a discovery reply against the challenge it sent and returns the hub's report port.</summary>
    public static bool TryParseDiscoveryReply(ReadOnlySpan<byte> reply, byte[] key, byte[] challenge, out int port)
    {
        port = 0;
        if (reply.Length is 0 or > 256) return false;
        var parts = Encoding.ASCII.GetString(reply).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || parts[0] != DiscoveryReplyPrefix) return false;
        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p is < 1 or > 65535) return false;
        byte[] tag;
        try { tag = Convert.FromBase64String(parts[2]); } catch (FormatException) { return false; }
        var expected = Hmac(key, DiscoveryRspDomain, [.. challenge, .. "\n"u8, .. Encoding.ASCII.GetBytes(parts[1])]);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag)) return false;
        port = p;
        return true;
    }

    private static byte[] Hmac(byte[] key, byte[] domain, ReadOnlySpan<byte> data)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        h.AppendData(domain);
        h.AppendData(data);
        return h.GetHashAndReset();
    }
}

/// <summary>Bounded LRU of recently seen nonces (thread-safe). Entries older than <see cref="Retention"/> are forgotten.</summary>
public sealed class ReplayCache(int capacity = 8192)
{
    private readonly Dictionary<string, LinkedListNode<(string Key, DateTimeOffset Seen)>> _map = new(StringComparer.Ordinal);
    private readonly LinkedList<(string Key, DateTimeOffset Seen)> _order = new();
    private readonly object _sync = new();

    /// <summary>Must exceed twice the allowed clock skew so a nonce cannot be replayed while its timestamp is still valid.</summary>
    public TimeSpan Retention { get; init; } = TimeSpan.FromMinutes(5);
    public int Count { get { lock (_sync) return _map.Count; } }

    /// <summary>Returns false when the nonce was already seen.</summary>
    public bool TryAdd(string nonce, DateTimeOffset now)
    {
        lock (_sync)
        {
            while (_order.First is { } oldest && (now - oldest.Value.Seen > Retention || _map.Count >= capacity))
            {
                _map.Remove(oldest.Value.Key);
                _order.RemoveFirst();
            }
            if (_map.ContainsKey(nonce)) return false;
            _map[nonce] = _order.AddLast((nonce, now));
            return true;
        }
    }
}

/// <summary>Serializes <see cref="Mac"/> as "AA:BB:CC:DD:EE:FF".</summary>
public sealed class AgentMacJsonConverter : JsonConverter<Mac>
{
    public override Mac Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String && Mac.TryParse(reader.GetString(), out var m) ? m : throw new JsonException("invalid MAC");

    public override void Write(Utf8JsonWriter writer, Mac value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
    Converters = [typeof(AgentMacJsonConverter)])]
[JsonSerializable(typeof(ProbeAgentReport))]
public sealed partial class AgentJsonContext : JsonSerializerContext;
