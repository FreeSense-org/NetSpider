using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Rendering;

/// <summary>The NetSpider neon palette and value→color mappings shared by every Skia-drawn control.</summary>
public static class Neon
{
    public static readonly SKColor Background = SKColor.Parse("#070B14");
    public static readonly SKColor BackgroundDeep = SKColor.Parse("#03060C");
    public static readonly SKColor Panel = SKColor.Parse("#0D1424");
    public static readonly SKColor PanelLight = SKColor.Parse("#16213A");
    public static readonly SKColor Border = SKColor.Parse("#1E2B47");
    public static readonly SKColor Cyan = SKColor.Parse("#00E5FF");
    public static readonly SKColor Magenta = SKColor.Parse("#FF2BD6");
    public static readonly SKColor Green = SKColor.Parse("#3DFF8B");
    public static readonly SKColor Yellow = SKColor.Parse("#E9F542");
    public static readonly SKColor Amber = SKColor.Parse("#FFC23D");
    public static readonly SKColor Orange = SKColor.Parse("#FF8A3D");
    public static readonly SKColor Red = SKColor.Parse("#FF3D5A");
    public static readonly SKColor Blue = SKColor.Parse("#3D8BFF");
    public static readonly SKColor Violet = SKColor.Parse("#9B7BFF");
    public static readonly SKColor Grey = SKColor.Parse("#5A6478");
    public static readonly SKColor Text = SKColor.Parse("#E8F1FF");
    public static readonly SKColor TextDim = SKColor.Parse("#8A9BB8");
    public static readonly SKColor TextFaint = SKColor.Parse("#56657F");

    /// <summary>Latency → ring/edge color using the user's thresholds (green &lt; good, yellow &lt; warn, orange &lt; bad, red beyond).</summary>
    public static SKColor Latency(double? ms, double good, double warn, double bad)
    {
        if (ms is not { } v) return Grey;
        if (v < good) return Green;
        if (v < warn) return Lerp(Green, Yellow, (float)((v - good) / Math.Max(0.001, warn - good)) * 0.8f + 0.2f);
        if (v < bad) return Lerp(Yellow, Orange, (float)((v - warn) / Math.Max(0.001, bad - warn)));
        return Red;
    }

    public static SKColor Latency(double? ms, AppSettings s) => Latency(ms, s.LatencyGoodMs, s.LatencyWarnMs, s.LatencyBadMs);

    public static SKColor Protocol(string proto) => proto.ToUpperInvariant() switch
    {
        "ARP" => Cyan,
        "MDNS" => Magenta,
        "SSDP" => Amber,
        "LLDP" => Green,
        "CDP" => SKColor.Parse("#7DFFB9"),
        "DHCP" or "DHCPV6" => Violet,
        "IGMP" or "MLD" => SKColor.Parse("#FF7AB8"),
        "NETBIOS" or "LLMNR" or "NBNS" => SKColor.Parse("#B7C4FF"),
        "STP" or "RSTP" => Yellow,
        "ICMPV6" or "NDP" => SKColor.Parse("#4DD8FF"),
        "ICMP" => SKColor.Parse("#5CF2FF"),
        "WSD" => SKColor.Parse("#FFAE7A"),
        _ => Text,
    };

    public static string ProtocolInitials(string proto) => proto.ToUpperInvariant() switch
    {
        "NETBIOS" => "NB",
        "ICMPV6" => "ND",
        "DHCPV6" => "D6",
        _ => proto.Length <= 5 ? proto : proto[..4],
    };

    /// <summary>Edge thickness by link speed: 10G thick, 1G normal, 100M thin, unknown hairline.</summary>
    public static float SpeedWidth(long? mbps) => mbps switch
    {
        null or <= 0 => 0.9f,
        >= 10000 => 4.2f,
        >= 2500 => 3.2f,
        >= 1000 => 2.2f,
        >= 100 => 1.3f,
        _ => 1.0f,
    };

    public static SKColor LedForSpeed(long? mbps, bool? up) => up == false || mbps is null or <= 0
        ? SKColor.Parse("#1A2235")
        : mbps >= 10000 ? Blue : mbps >= 1000 ? Green : mbps >= 100 ? Amber : Orange;

    public static SKColor Lerp(SKColor a, SKColor b, float t)
    {
        t = Math.Clamp(t, 0, 1);
        return new SKColor((byte)(a.Red + (b.Red - a.Red) * t), (byte)(a.Green + (b.Green - a.Green) * t),
            (byte)(a.Blue + (b.Blue - a.Blue) * t), (byte)(a.Alpha + (b.Alpha - a.Alpha) * t));
    }

    public static SKColor A(this SKColor c, float alpha) => c.WithAlpha((byte)Math.Clamp(alpha * 255f, 0, 255));

    public static string FormatMs(double? ms)
    {
        if (ms is not { } v) return "—";
        if (v < 0.1) return "<0.1 ms";
        if (v < 10) return v.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture) + " ms";
        if (v < 100) return v.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " ms";
        return v.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " ms";
    }

    public static string FormatSpeed(long? mbps) => mbps switch
    {
        null or <= 0 => "unknown",
        >= 1000 when mbps % 1000 == 0 => $"{mbps / 1000} Gbps",
        >= 1000 => $"{mbps / 1000.0:0.#} Gbps",
        _ => $"{mbps} Mbps",
    };
}
