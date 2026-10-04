using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Tests.Unit.Diagnostics.Agents;

public class AgentWifiParsersTests
{
    [Fact]
    public void Parses_netsh_connected()
    {
        const string text = """

            There is 1 interface on the system:

                Name                   : Wi-Fi
                Description            : Realtek 8922AE WiFi 7 PCI-E NIC
                GUID                   : 00000000-1111-2222-3333-444455556666
                Physical address       : 60:ff:9e:10:20:30
                Interface type         : Primary
                State                  : connected
                SSID                   : Office
                AP BSSID               : aa:bb:cc:00:11:22
                Band                   : 5 GHz
                Channel                : 36
                Network type           : Infrastructure
                Radio type             : 802.11ax
                Authentication         : WPA2-Personal
                Receive rate (Mbps)    : 1200.5
                Transmit rate (Mbps)   : 960
                Signal                 : 92%
                Rssi                   : -48
                Profile                : Office
            """;
        var s = AgentWifiParsers.ParseNetsh(text, DateTimeOffset.Now)!;
        Assert.True(s.Connected);
        Assert.Equal("Office", s.Ssid);
        Assert.Equal(Mac.Parse("AA:BB:CC:00:11:22"), s.Bssid);
        Assert.Equal(36, s.Channel);
        Assert.Equal("5 GHz", s.Band);
        Assert.Equal(-48, s.RssiDbm);
        Assert.Equal(92, s.SignalQuality);
        Assert.Equal(1200.5, s.RxRateMbps);
        Assert.Equal(960, s.TxRateMbps);
        Assert.Equal("802.11ax", s.Phy);
    }

    [Fact]
    public void Parses_netsh_disconnected_and_older_format()
    {
        var off = AgentWifiParsers.ParseNetsh("    Name : Wi-Fi\r\n    State : disconnected\r\n", DateTimeOffset.Now)!;
        Assert.False(off.Connected);

        var old = AgentWifiParsers.ParseNetsh("    Name : Wi-Fi\n    State : connected\n    SSID : Home\n    BSSID : 01:02:03:04:05:06\n    Channel : 6\n    Signal : 80%\n", DateTimeOffset.Now)!;
        Assert.Equal(Mac.Parse("01:02:03:04:05:06"), old.Bssid);
        Assert.Equal(-60, old.RssiDbm); // derived from quality
        Assert.Equal("2.4 GHz", old.Band);
    }

    [Fact]
    public void Parses_iw_link()
    {
        const string text = """
            Connected to aa:bb:cc:dd:ee:ff (on wlan0)
            	SSID: PiNet
            	freq: 5180
            	RX: 123456 bytes (789 packets)
            	TX: 4567 bytes (89 packets)
            	signal: -52 dBm
            	rx bitrate: 433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
            	tx bitrate: 390.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 1
            """;
        var s = AgentWifiParsers.ParseIwLink(text, DateTimeOffset.Now)!;
        Assert.True(s.Connected);
        Assert.Equal("PiNet", s.Ssid);
        Assert.Equal(Mac.Parse("aa:bb:cc:dd:ee:ff"), s.Bssid);
        Assert.Equal(36, s.Channel);
        Assert.Equal("5 GHz", s.Band);
        Assert.Equal(-52, s.RssiDbm);
        Assert.Equal(433.3, s.RxRateMbps);
        Assert.Equal(390.0, s.TxRateMbps);
        Assert.Equal("802.11ac", s.Phy);

        Assert.False(AgentWifiParsers.ParseIwLink("Not connected.", DateTimeOffset.Now)!.Connected);
        Assert.Equal(6, AgentWifiParsers.ChannelFromFrequency(2437));
    }
}
