using System.Text;

namespace NetSpider.Wifi;

/// <summary>Wi-Fi generation, ordered so that a higher value is newer.</summary>
public enum WifiGeneration { Unknown = 0, Legacy11a, Legacy11b, Legacy11g, Wifi4, Wifi5, Wifi6, Wifi7 }

/// <summary>Facts parsed from a beacon/probe-response Information Elements blob.</summary>
public sealed record IeSummary(int? ChannelWidthMhz, WifiGeneration Generation, string? RsnSecurity, int? PrimaryChannel);

/// <summary>Pure helpers for channel/band math, PHY naming and 802.11 Information Element parsing.</summary>
public static class WifiMath
{
    public const string Band24 = "2.4 GHz";
    public const string Band5 = "5 GHz";
    public const string Band6 = "6 GHz";
    public const string Band60 = "60 GHz";

    // ------------------------------------------------------------------ frequency / channel

    /// <summary>Band name for a centre frequency in MHz, or "" when unknown.</summary>
    public static string BandOf(int mhz) => mhz switch
    {
        >= 2400 and < 2500 => Band24,
        >= 4900 and < 5925 => Band5,
        >= 5925 and <= 7125 => Band6,
        >= 57000 and <= 71000 => Band60,
        _ => "",
    };

    /// <summary>IEEE channel number for a frequency in MHz (6 GHz: (f − 5950)/5, with 5935 MHz = channel 2).</summary>
    public static int ChannelOf(int mhz)
    {
        if (mhz == 2484) return 14;
        if (mhz is >= 2407 and < 2484) return (mhz - 2407) / 5;
        if (mhz is >= 4900 and < 5000) return (mhz - 4000) / 5; // Japan 4.9 GHz (ch 182..196)
        if (mhz is >= 5000 and < 5925) return (mhz - 5000) / 5;
        if (mhz == 5935) return 2;
        if (mhz is >= 5925 and <= 7125) return (mhz - 5950) / 5;
        if (mhz is >= 57000 and <= 71000) return (mhz - 56160) / 2160;
        return 0;
    }

    /// <summary>WLAN_BSS_ENTRY.ulChCenterFrequency is in kHz.</summary>
    public static int KhzToMhz(uint khz) => (int)((khz + 500) / 1000);

    // ------------------------------------------------------------------ PHY

    /// <summary>Maps DOT11_PHY_TYPE (windot11.h) to a generation.</summary>
    public static WifiGeneration FromDot11PhyType(int phyType) => phyType switch
    {
        4 => WifiGeneration.Legacy11a,   // dot11_phy_type_ofdm
        2 or 5 => WifiGeneration.Legacy11b, // dsss, hrdsss
        6 => WifiGeneration.Legacy11g,   // erp
        7 => WifiGeneration.Wifi4,       // ht
        8 => WifiGeneration.Wifi5,       // vht
        10 => WifiGeneration.Wifi6,      // he
        11 => WifiGeneration.Wifi7,      // eht
        _ => WifiGeneration.Unknown,
    };

    /// <summary>Human-readable PHY, e.g. "Wi-Fi 6E (802.11ax)".</summary>
    public static string PhyName(WifiGeneration gen, string band) => gen switch
    {
        WifiGeneration.Legacy11a => "802.11a",
        WifiGeneration.Legacy11b => "802.11b",
        WifiGeneration.Legacy11g => "802.11g",
        WifiGeneration.Wifi4 => "Wi-Fi 4 (802.11n)",
        WifiGeneration.Wifi5 => "Wi-Fi 5 (802.11ac)",
        WifiGeneration.Wifi6 => band == Band6 ? "Wi-Fi 6E (802.11ax)" : "Wi-Fi 6 (802.11ax)",
        WifiGeneration.Wifi7 => "Wi-Fi 7 (802.11be)",
        _ => "Unknown",
    };

    // ------------------------------------------------------------------ security

    /// <summary>DOT11_AUTH_ALGORITHM + DOT11_CIPHER_ALGORITHM → display string.</summary>
    public static string SecurityName(int auth, int cipher)
    {
        string a = auth switch
        {
            1 => cipher is 1 or 5 or 0x101 ? "WEP" : "Open",
            2 => "WEP (shared key)",
            3 => "WPA-Enterprise",
            4 => "WPA-Personal",
            5 => "WPA (none)",
            6 => "WPA2-Enterprise",
            7 => "WPA2-Personal",
            8 => "WPA3-Enterprise 192",
            9 => "WPA3-Personal",
            10 => "OWE",
            11 => "WPA3-Enterprise",
            _ => $"Auth {auth}",
        };
        string? c = cipher switch
        {
            0 => null,
            1 => "WEP40",
            2 => "TKIP",
            4 => "CCMP",
            5 => "WEP104",
            6 => "BIP",
            8 => "GCMP",
            9 => "GCMP-256",
            10 => "CCMP-256",
            0x100 => null,
            0x101 => "WEP",
            _ => null,
        };
        if (a is "Open" or "WEP") return a;
        return c is null ? a : $"{a} ({c})";
    }

    // ------------------------------------------------------------------ IEs

    public static string DecodeSsid(ReadOnlySpan<byte> raw)
    {
        if (raw.IsEmpty) return "";
        bool allZero = true;
        foreach (var b in raw) if (b != 0) { allZero = false; break; }
        if (allZero) return "";
        try { return new UTF8Encoding(false, true).GetString(raw); }
        catch (DecoderFallbackException) { return Encoding.Latin1.GetString(raw); }
    }

    /// <summary>
    /// Parses an Information Elements blob: channel width from HT Operation (61), VHT Operation (192),
    /// HE Operation (255/36, incl. 6 GHz info) and EHT Operation (255/106); generation from the presence of
    /// HT/VHT/HE/EHT elements; and security from RSN (48) / WPA vendor IEs.
    /// </summary>
    public static IeSummary ParseIes(ReadOnlySpan<byte> ies)
    {
        int width = 0;
        int? primary = null;
        var gen = WifiGeneration.Unknown;
        string? rsn = null;
        bool wpa1 = false;

        int i = 0;
        while (i + 2 <= ies.Length)
        {
            byte id = ies[i];
            int len = ies[i + 1];
            if (i + 2 + len > ies.Length) break;
            var d = ies.Slice(i + 2, len);
            i += 2 + len;

            switch (id)
            {
                case 3 when d.Length >= 1: // DS Parameter Set
                    primary ??= d[0];
                    break;
                case 45: // HT Capabilities
                    gen = Max(gen, WifiGeneration.Wifi4);
                    break;
                case 61 when d.Length >= 2: // HT Operation
                    gen = Max(gen, WifiGeneration.Wifi4);
                    primary = d[0];
                    width = Math.Max(width, HtWidth(d));
                    break;
                case 191: // VHT Capabilities
                    gen = Max(gen, WifiGeneration.Wifi5);
                    break;
                case 192 when d.Length >= 3: // VHT Operation
                    gen = Max(gen, WifiGeneration.Wifi5);
                    width = Math.Max(width, VhtWidth(d[0], d[1], d[2]));
                    break;
                case 48 when d.Length >= 2: // RSN
                    rsn = ParseRsn(d);
                    break;
                case 221 when d.Length >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01: // WPA1 vendor IE
                    wpa1 = true;
                    break;
                case 255 when d.Length >= 1: // Element ID Extension
                    var ext = d[0];
                    var e = d[1..];
                    switch (ext)
                    {
                        case 35: gen = Max(gen, WifiGeneration.Wifi6); break; // HE Capabilities
                        case 36: // HE Operation
                            gen = Max(gen, WifiGeneration.Wifi6);
                            width = Math.Max(width, HeWidth(e, ref primary));
                            break;
                        case 108: gen = Max(gen, WifiGeneration.Wifi7); break; // EHT Capabilities
                        case 106: // EHT Operation
                            gen = Max(gen, WifiGeneration.Wifi7);
                            width = Math.Max(width, EhtWidth(e));
                            break;
                    }
                    break;
            }
        }

        if (rsn is null && wpa1) rsn = "WPA-Personal";
        // No wide-channel element (or an HT element without 40 MHz) means a 20 MHz BSS.
        return new IeSummary(width == 0 ? (ies.IsEmpty ? null : 20) : width, gen, rsn, primary);
    }

    private static WifiGeneration Max(WifiGeneration a, WifiGeneration b) => a >= b ? a : b;

    /// <summary>HT Operation: byte 1 bits 0-1 secondary channel offset (1 above, 3 below), bit 2 STA channel width.</summary>
    internal static int HtWidth(ReadOnlySpan<byte> d)
    {
        int offset = d[1] & 0x03;
        bool anyWidth = (d[1] & 0x04) != 0;
        return anyWidth && offset is 1 or 3 ? 40 : 20;
    }

    /// <summary>VHT Operation Information: width 0 = 20/40 (HT decides), 1 = 80/160/80+80 (by CCFS1), 2 = 160, 3 = 80+80.</summary>
    internal static int VhtWidth(byte chWidth, byte ccfs0, byte ccfs1) => chWidth switch
    {
        0 => 0,
        1 when ccfs1 == 0 => 80,
        1 => 160, // |CCFS1 - CCFS0| == 8 is contiguous 160; larger is 80+80, reported as 160 total
        2 => 160,
        3 => 160,
        _ => 0,
    };

    /// <summary>HE Operation (after the ext id): 3 bytes params, 1 byte BSS colour, 2 bytes basic MCS, then optional VHT info (bit 14),
    /// co-hosted BSSID indicator (bit 15) and 6 GHz Operation Information (bit 17).</summary>
    internal static int HeWidth(ReadOnlySpan<byte> e, ref int? primary)
    {
        if (e.Length < 6) return 0;
        int prm = e[0] | e[1] << 8 | e[2] << 16;
        int off = 6;
        int width = 0;
        if ((prm & (1 << 14)) != 0)
        {
            if (e.Length < off + 3) return 0;
            width = Math.Max(width, VhtWidth(e[off], e[off + 1], e[off + 2]));
            off += 3;
        }
        if ((prm & (1 << 15)) != 0) off += 1;
        if ((prm & (1 << 17)) != 0 && e.Length >= off + 5)
        {
            primary = e[off];
            int ctl = e[off + 1] & 0x03;
            byte ccfs0 = e[off + 2], ccfs1 = e[off + 3];
            int w = ctl switch
            {
                0 => 20,
                1 => 40,
                2 => 80,
                3 => 160, // 160 or 80+80
                _ => 0,
            };
            width = Math.Max(width, w);
        }
        return width;
    }

    /// <summary>EHT Operation (after the ext id): 1 byte params (bit 0 = info present), 4 bytes basic MCS, then Control (bits 0-2 width: 0=20 … 4=320).</summary>
    internal static int EhtWidth(ReadOnlySpan<byte> e)
    {
        if (e.Length < 1 || (e[0] & 0x01) == 0 || e.Length < 6) return 0;
        return (e[5] & 0x07) switch
        {
            0 => 20,
            1 => 40,
            2 => 80,
            3 => 160,
            4 => 320,
            _ => 0,
        };
    }

    /// <summary>RSN element: version(2) group(4) pairwise count(2) + suites, AKM count(2) + suites. Returns e.g. "WPA3-Personal (CCMP)".</summary>
    internal static string? ParseRsn(ReadOnlySpan<byte> d)
    {
        try
        {
            int off = 2 + 4; // version + group cipher
            if (d.Length < off + 2) return "WPA2";
            int pc = d[off] | d[off + 1] << 8; off += 2;
            string? cipher = null;
            for (int k = 0; k < pc && d.Length >= off + 4; k++, off += 4)
            {
                if (d[off] == 0x00 && d[off + 1] == 0x0F && d[off + 2] == 0xAC)
                {
                    var c = d[off + 3] switch { 2 => "TKIP", 4 => "CCMP", 8 => "GCMP", 9 => "GCMP-256", 10 => "CCMP-256", _ => null };
                    if (c is not null && (cipher is null || c != "TKIP")) cipher = c;
                }
            }
            if (d.Length < off + 2) return cipher is null ? "WPA2" : $"WPA2 ({cipher})";
            int ac = d[off] | d[off + 1] << 8; off += 2;
            bool psk = false, sae = false, eap = false, eap3 = false, owe = false;
            for (int k = 0; k < ac && d.Length >= off + 4; k++, off += 4)
            {
                if (!(d[off] == 0x00 && d[off + 1] == 0x0F && d[off + 2] == 0xAC)) continue;
                switch (d[off + 3])
                {
                    case 1 or 3 or 5: eap = true; break;
                    case 2 or 4 or 6: psk = true; break;
                    case 8 or 9 or 24 or 25: sae = true; break;
                    case 12 or 13: eap3 = true; break;
                    case 18: owe = true; break;
                }
            }
            string name = sae && psk ? "WPA2/WPA3-Personal"
                : sae ? "WPA3-Personal"
                : owe ? "OWE"
                : eap3 ? "WPA3-Enterprise"
                : eap ? "WPA2-Enterprise"
                : psk ? "WPA2-Personal"
                : "WPA2";
            return cipher is null ? name : $"{name} ({cipher})";
        }
        catch (IndexOutOfRangeException) { return "WPA2"; }
    }
}
