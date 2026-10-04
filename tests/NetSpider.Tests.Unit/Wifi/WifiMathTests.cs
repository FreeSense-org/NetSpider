using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NetSpider.Wifi;
using NetSpider.Wifi.Native;

namespace NetSpider.Tests.Unit.Wifi;

public sealed class WifiMathTests
{
    [Theory]
    [InlineData(2412, 1, "2.4 GHz")]
    [InlineData(2437, 6, "2.4 GHz")]
    [InlineData(2472, 13, "2.4 GHz")]
    [InlineData(2484, 14, "2.4 GHz")]
    [InlineData(5180, 36, "5 GHz")]
    [InlineData(5500, 100, "5 GHz")]
    [InlineData(5825, 165, "5 GHz")]
    [InlineData(5885, 177, "5 GHz")]
    [InlineData(5935, 2, "6 GHz")]
    [InlineData(5955, 1, "6 GHz")]
    [InlineData(6115, 33, "6 GHz")]
    [InlineData(6295, 69, "6 GHz")]
    [InlineData(7115, 233, "6 GHz")]
    [InlineData(58320, 1, "60 GHz")]
    public void Channel_and_band_from_frequency(int mhz, int channel, string band)
    {
        Assert.Equal(channel, WifiMath.ChannelOf(mhz));
        Assert.Equal(band, WifiMath.BandOf(mhz));
    }

    [Fact]
    public void Khz_to_mhz() => Assert.Equal(5180, WifiMath.KhzToMhz(5_180_000));

    [Theory]
    [InlineData(7, "2.4 GHz", "Wi-Fi 4 (802.11n)")]
    [InlineData(8, "5 GHz", "Wi-Fi 5 (802.11ac)")]
    [InlineData(10, "5 GHz", "Wi-Fi 6 (802.11ax)")]
    [InlineData(10, "6 GHz", "Wi-Fi 6E (802.11ax)")]
    [InlineData(11, "6 GHz", "Wi-Fi 7 (802.11be)")]
    [InlineData(6, "2.4 GHz", "802.11g")]
    [InlineData(4, "5 GHz", "802.11a")]
    public void Phy_names(int dot11PhyType, string band, string expected) =>
        Assert.Equal(expected, WifiMath.PhyName(WifiMath.FromDot11PhyType(dot11PhyType), band));

    [Theory]
    [InlineData(7, 4, "WPA2-Personal (CCMP)")]
    [InlineData(9, 4, "WPA3-Personal (CCMP)")]
    [InlineData(6, 4, "WPA2-Enterprise (CCMP)")]
    [InlineData(1, 0, "Open")]
    [InlineData(1, 5, "WEP")]
    [InlineData(10, 4, "OWE (CCMP)")]
    public void Security_names(int auth, int cipher, string expected) => Assert.Equal(expected, WifiMath.SecurityName(auth, cipher));

    // ---- IE parsing ------------------------------------------------------------------------

    private static byte[] Ie(byte id, params byte[] data) => [id, (byte)data.Length, .. data];
    private static byte[] Ext(byte ext, params byte[] data) => Ie(255, [ext, .. data]);

    [Fact]
    public void Ht_only_20MHz()
    {
        var ies = Concat(Ie(0, "abc"u8.ToArray()), Ie(3, 6), Ie(45, new byte[26]), Ie(61, 6, 0x00, 0, 0, 0));
        var r = WifiMath.ParseIes(ies);
        Assert.Equal(20, r.ChannelWidthMhz);
        Assert.Equal(WifiGeneration.Wifi4, r.Generation);
        Assert.Equal(6, r.PrimaryChannel);
    }

    [Fact]
    public void Ht_40MHz_secondary_above()
    {
        var r = WifiMath.ParseIes(Ie(61, 36, 0x05 /* offset above + any width */, 0, 0, 0));
        Assert.Equal(40, r.ChannelWidthMhz);
    }

    [Fact]
    public void Ht_secondary_offset_without_sta_width_is_20()
    {
        var r = WifiMath.ParseIes(Ie(61, 36, 0x01, 0, 0, 0));
        Assert.Equal(20, r.ChannelWidthMhz);
    }

    [Fact]
    public void Vht_80MHz()
    {
        var ies = Concat(Ie(61, 36, 0x05, 0, 0, 0), Ie(191, new byte[12]), Ie(192, 1, 42, 0, 0, 0));
        var r = WifiMath.ParseIes(ies);
        Assert.Equal(80, r.ChannelWidthMhz);
        Assert.Equal(WifiGeneration.Wifi5, r.Generation);
    }

    [Fact]
    public void Vht_160MHz_via_ccfs1()
    {
        var r = WifiMath.ParseIes(Ie(192, 1, 42, 50, 0, 0));
        Assert.Equal(160, r.ChannelWidthMhz);
    }

    [Fact]
    public void Vht_width0_defers_to_ht()
    {
        var r = WifiMath.ParseIes(Concat(Ie(61, 36, 0x07, 0, 0, 0), Ie(192, 0, 0, 0, 0, 0)));
        Assert.Equal(40, r.ChannelWidthMhz);
    }

    [Fact]
    public void He_6GHz_operation_info_160()
    {
        // params: bit 17 (6 GHz info present) => byte2 = 0x02; colour; basic MCS(2); 6 GHz info: primary 37, ctl 3, ccfs0 39, ccfs1 47, minrate
        var he = Ext(36, 0x00, 0x00, 0x02, 0x01, 0xFC, 0xFF, 37, 0x03, 39, 47, 6);
        var r = WifiMath.ParseIes(Concat(Ext(35, new byte[20]), he));
        Assert.Equal(160, r.ChannelWidthMhz);
        Assert.Equal(WifiGeneration.Wifi6, r.Generation);
        Assert.Equal(37, r.PrimaryChannel);
    }

    [Fact]
    public void He_with_vht_info_80()
    {
        // bit 14 => byte1 = 0x40; VHT info: width 1, ccfs0 42, ccfs1 0
        var he = Ext(36, 0x00, 0x40, 0x00, 0x01, 0xFC, 0xFF, 1, 42, 0);
        Assert.Equal(80, WifiMath.ParseIes(he).ChannelWidthMhz);
    }

    [Fact]
    public void He_with_cohosted_and_6ghz_skips_indicator_byte()
    {
        // bits 15 and 17: byte1 = 0x80, byte2 = 0x02; co-hosted indicator; 6 GHz info width 2 (80)
        var he = Ext(36, 0x00, 0x80, 0x02, 0x01, 0xFC, 0xFF, 0x07, 5, 0x02, 7, 0, 6);
        Assert.Equal(80, WifiMath.ParseIes(he).ChannelWidthMhz);
    }

    [Fact]
    public void Eht_320MHz()
    {
        var eht = Ext(106, 0x01, 0, 0, 0, 0, 0x04, 31, 63);
        var r = WifiMath.ParseIes(Concat(Ext(108, new byte[10]), eht));
        Assert.Equal(320, r.ChannelWidthMhz);
        Assert.Equal(WifiGeneration.Wifi7, r.Generation);
    }

    [Fact]
    public void Eht_without_info_present_does_not_set_width()
    {
        var r = WifiMath.ParseIes(Concat(Ie(192, 1, 42, 0, 0, 0), Ext(106, 0x00, 0, 0, 0, 0)));
        Assert.Equal(80, r.ChannelWidthMhz);
        Assert.Equal(WifiGeneration.Wifi7, r.Generation);
    }

    [Fact]
    public void Truncated_element_is_ignored()
    {
        var r = WifiMath.ParseIes([61, 22, 36, 0x05]);
        Assert.Null(r.PrimaryChannel);
        Assert.Equal(20, r.ChannelWidthMhz);
    }

    [Fact]
    public void Empty_blob_has_unknown_width() => Assert.Null(WifiMath.ParseIes([]).ChannelWidthMhz);

    [Fact]
    public void Rsn_wpa3_sae()
    {
        byte[] rsn = [1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 8, 0xC0, 0];
        Assert.Equal("WPA3-Personal (CCMP)", WifiMath.ParseIes(Ie(48, rsn)).RsnSecurity);
    }

    [Fact]
    public void Rsn_transition_mode()
    {
        byte[] rsn = [1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 2, 0, 0x00, 0x0F, 0xAC, 2, 0x00, 0x0F, 0xAC, 8, 0x80, 0];
        Assert.Equal("WPA2/WPA3-Personal (CCMP)", WifiMath.ParseIes(Ie(48, rsn)).RsnSecurity);
    }

    [Fact]
    public void Ssid_decoding()
    {
        Assert.Equal("Café", WifiMath.DecodeSsid("Café"u8));
        Assert.Equal("", WifiMath.DecodeSsid(new byte[8]));
        Assert.Equal("ÿþ", WifiMath.DecodeSsid([0xFF, 0xFE])); // invalid UTF-8 falls back to Latin-1
    }

    // ---- native struct layout (must match wlanapi.h) ---------------------------------------

    [Fact]
    public void Native_struct_layouts_match_wlanapi()
    {
        Assert.Equal(360, Unsafe.SizeOf<WlanNative.WLAN_BSS_ENTRY>());
        Assert.Equal(92, (int)Marshal.OffsetOf<WlanNative.WLAN_BSS_ENTRY>(nameof(WlanNative.WLAN_BSS_ENTRY.ulChCenterFrequency)));
        Assert.Equal(352, (int)Marshal.OffsetOf<WlanNative.WLAN_BSS_ENTRY>(nameof(WlanNative.WLAN_BSS_ENTRY.ulIeOffset)));
        Assert.Equal(56, (int)Marshal.OffsetOf<WlanNative.WLAN_BSS_ENTRY>(nameof(WlanNative.WLAN_BSS_ENTRY.lRssi)));
        Assert.Equal(8, (int)Marshal.OffsetOf<WlanNative.WLAN_BSS_LIST>(nameof(WlanNative.WLAN_BSS_LIST.wlanBssEntries)));
        Assert.Equal(628, Unsafe.SizeOf<WlanNative.WLAN_AVAILABLE_NETWORK>());
        Assert.Equal(612, (int)Marshal.OffsetOf<WlanNative.WLAN_AVAILABLE_NETWORK>(nameof(WlanNative.WLAN_AVAILABLE_NETWORK.dot11DefaultAuthAlgorithm)));
        Assert.Equal(532, Unsafe.SizeOf<WlanNative.WLAN_INTERFACE_INFO>());
        Assert.Equal(520, (int)Marshal.OffsetOf<WlanNative.WLAN_CONNECTION_ATTRIBUTES>(nameof(WlanNative.WLAN_CONNECTION_ATTRIBUTES.wlanAssociationAttributes)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WlanNative.WLAN_ASSOCIATION_ATTRIBUTES>(nameof(WlanNative.WLAN_ASSOCIATION_ATTRIBUTES.dot11Bssid)));
        Assert.Equal(48, (int)Marshal.OffsetOf<WlanNative.WLAN_ASSOCIATION_ATTRIBUTES>(nameof(WlanNative.WLAN_ASSOCIATION_ATTRIBUTES.dot11PhyType)));
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
}
