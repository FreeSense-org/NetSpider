using System.Globalization;
using NetSpider.Core.Model;

namespace NetSpider.Diagnostics.Agents;

// Compiled into both NetSpider.Diagnostics and NetSpider.Probe (linked file). Pure text parsing, no OS calls.

/// <summary>Parses Wi-Fi link tools' text output into a basic <see cref="WifiLinkSample"/> (best effort, English output).</summary>
public static class AgentWifiParsers
{
    /// <summary>Parses <c>netsh wlan show interfaces</c> (first interface). Returns null when no interface is listed.</summary>
    public static WifiLinkSample? ParseNetsh(string text, DateTimeOffset time)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        bool seenInterface = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            int colon = line.IndexOf(" : ", StringComparison.Ordinal);
            if (colon < 0) continue;
            var key = line[..colon].Trim();
            var value = line[(colon + 3)..].Trim();
            if (key.Equals("Name", StringComparison.OrdinalIgnoreCase))
            {
                if (seenInterface) break; // only the first interface
                seenInterface = true;
            }
            kv.TryAdd(key, value);
        }
        if (!seenInterface && kv.Count == 0) return null;

        bool connected = kv.TryGetValue("State", out var state) && state.Equals("connected", StringComparison.OrdinalIgnoreCase);
        kv.TryGetValue("SSID", out var ssid);
        Mac? bssid = (kv.TryGetValue("AP BSSID", out var b) || kv.TryGetValue("BSSID", out b)) && Mac.TryParse(b, out var m) ? m : null;
        int channel = kv.TryGetValue("Channel", out var ch) && int.TryParse(ch, NumberStyles.Integer, CultureInfo.InvariantCulture, out var c) ? c : 0;
        int quality = kv.TryGetValue("Signal", out var sig) && int.TryParse(sig.TrimEnd('%', ' '), NumberStyles.Integer, CultureInfo.InvariantCulture, out var q) ? q : 0;
        int rssi = kv.TryGetValue("Rssi", out var rs) && int.TryParse(rs, NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r
            : quality > 0 ? quality / 2 - 100 : 0;
        double rx = ParseDouble(kv, "Receive rate (Mbps)");
        double tx = ParseDouble(kv, "Transmit rate (Mbps)");
        kv.TryGetValue("Radio type", out var phy);
        kv.TryGetValue("Band", out var band);
        band ??= BandFromChannel(channel);

        return new WifiLinkSample(time, connected, connected ? ssid : null, connected ? bssid : null, channel, band,
            rssi, quality, tx, rx, phy, null, null);
    }

    /// <summary>Parses <c>iw dev &lt;if&gt; link</c>. Returns a disconnected sample for "Not connected.".</summary>
    public static WifiLinkSample? ParseIwLink(string text, DateTimeOffset time)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (text.Contains("Not connected", StringComparison.OrdinalIgnoreCase))
            return new WifiLinkSample(time, false, null, null, 0, null, 0, 0, 0, 0, null, null, null);

        Mac? bssid = null; string? ssid = null; int freq = 0, rssi = 0; double rx = 0, tx = 0; string? phy = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("Connected to ", StringComparison.OrdinalIgnoreCase))
            {
                var tok = line["Connected to ".Length..].Split(' ', 2)[0];
                if (Mac.TryParse(tok, out var m)) bssid = m;
                continue;
            }
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var key = line[..colon].Trim().ToLowerInvariant();
            var value = line[(colon + 1)..].Trim();
            switch (key)
            {
                case "ssid": ssid = value; break;
                case "freq": freq = (int)FirstNumber(value); break;
                case "signal": rssi = (int)FirstNumber(value); break;
                case "rx bitrate": rx = FirstNumber(value); phy ??= PhyFromBitrate(value); break;
                case "tx bitrate": tx = FirstNumber(value); phy = PhyFromBitrate(value) ?? phy; break;
            }
        }
        if (bssid is null && ssid is null) return null;
        int channel = ChannelFromFrequency(freq);
        int quality = rssi == 0 ? 0 : Math.Clamp(2 * (rssi + 100), 0, 100);
        return new WifiLinkSample(time, true, ssid, bssid, channel, BandFromFrequency(freq), rssi, quality, tx, rx, phy, null, null);
    }

    public static int ChannelFromFrequency(int mhz) => mhz switch
    {
        2484 => 14,
        >= 2412 and < 2484 => (mhz - 2407) / 5,
        >= 5955 and <= 7115 => (mhz - 5950) / 5,
        >= 5000 and < 5955 => (mhz - 5000) / 5,
        _ => 0,
    };

    private static string? BandFromFrequency(int mhz) => mhz switch
    {
        >= 2400 and < 2500 => "2.4 GHz",
        >= 5925 => "6 GHz",
        >= 4900 => "5 GHz",
        _ => null,
    };

    private static string? BandFromChannel(int ch) => ch switch { >= 1 and <= 14 => "2.4 GHz", >= 32 and <= 177 => "5 GHz", _ => null };

    private static string? PhyFromBitrate(string v) =>
        v.Contains("EHT", StringComparison.Ordinal) ? "802.11be" :
        v.Contains("HE-", StringComparison.Ordinal) ? "802.11ax" :
        v.Contains("VHT", StringComparison.Ordinal) ? "802.11ac" :
        v.Contains("MCS", StringComparison.Ordinal) ? "802.11n" : null;

    private static double ParseDouble(Dictionary<string, string> kv, string key) =>
        kv.TryGetValue(key, out var s) && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;

    private static double FirstNumber(string s)
    {
        int i = 0;
        while (i < s.Length && !(char.IsDigit(s[i]) || s[i] == '-')) i++;
        int j = i;
        while (j < s.Length && (char.IsDigit(s[j]) || s[j] is '.' or '-')) j++;
        return j > i && double.TryParse(s.AsSpan(i, j - i), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;
    }
}
