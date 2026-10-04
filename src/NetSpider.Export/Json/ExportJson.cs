using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetSpider.Core.Model;

namespace NetSpider.Export.Json;

/// <summary>Shared System.Text.Json configuration for exports, the SQLite details blob and webhook payloads.</summary>
public static class ExportJson
{
    public static JsonSerializerOptions Options { get; } = Create(indented: true);
    public static JsonSerializerOptions Compact { get; } = Create(indented: false);

    public static JsonSerializerOptions Create(bool indented)
    {
        var o = new JsonSerializerOptions
        {
            WriteIndented = indented,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        o.Converters.Add(new MacJsonConverter());
        o.Converters.Add(new IPAddressJsonConverter());
        o.Converters.Add(new JsonStringEnumConverter());
        o.MakeReadOnly(populateMissingResolver: true);
        return o;
    }
}

/// <summary>Serializes <see cref="Mac"/> as "AA:BB:CC:DD:EE:FF".</summary>
public sealed class MacJsonConverter : JsonConverter<Mac>
{
    public override Mac Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String && Mac.TryParse(reader.GetString(), out var m) ? m : throw new JsonException("Invalid MAC address");

    public override void Write(Utf8JsonWriter writer, Mac value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());

    public override Mac ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        Mac.TryParse(reader.GetString(), out var m) ? m : throw new JsonException("Invalid MAC address");

    public override void WriteAsPropertyName(Utf8JsonWriter writer, Mac value, JsonSerializerOptions options) => writer.WritePropertyName(value.ToString());
}

/// <summary>Serializes <see cref="IPAddress"/> as its canonical string form.</summary>
public sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return null;
        return IPAddress.TryParse(reader.GetString(), out var ip) ? ip : throw new JsonException("Invalid IP address");
    }

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());

    public override IPAddress ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        IPAddress.TryParse(reader.GetString(), out var ip) ? ip : throw new JsonException("Invalid IP address");

    public override void WriteAsPropertyName(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) => writer.WritePropertyName(value.ToString());
}
