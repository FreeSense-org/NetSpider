# Changelog

All notable user-facing changes to FreeSense NetSpider are recorded here, newest first.
The format is strict and checked by CI: see [CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md).
Version numbers are computed from this file, so every pull request that changes what users see adds a line under `[Unreleased]`.

## [Unreleased]

## [1.0.0] - 2026-10-05

### New

- ARP and IPv6 neighbor sweeps discover every device on your network and measure real Layer 2 round-trip times from high-precision capture timestamps.
- A live, animated spider web shows your whole network, with a hierarchy tree and a switch-port matrix as alternative views.
- Devices are identified automatically from LLDP, CDP, STP, DHCP fingerprints, mDNS, SSDP/UPnP, WS-Discovery, NetBIOS, SMB, SNMP and TLS certificates.
- Vendor and smart-home devices are recognized, including Ubiquiti, MikroTik, Netgear, Sonos, Hue, Chromecast, Shelly, Fritz!Box and Home Assistant.
- Every device shows its brand and type, from an offline MAC-vendor database, about 170 classification rules and vendor logos.
- Other subnets and VLANs are found through the route table, DHCP options, traceroute, SNMP and tagged probes.
- Latency is measured at the MAC level (ARP/NDP) and the IP level (ICMP/TCP), including device-to-device timing where the network allows it.
- Path Doctor monitors every hop from this PC through access points, switches, the router and your ISP, with latency, loss and jitter per hop.
- The fault locator turns outages into incidents with a plain-language root cause and a confidence, such as an inferred switch or its uplink.
- Own-link monitoring warns about an unplugged cable, a speed drop to 100 Mbps, a lost DHCP lease or a changed gateway.
- Storm Center shows broadcast, multicast and unknown-unicast levels against a learned baseline, with the top sources mapped to their switch port.
- Storm Center finds network loops, keeps a storm history and records storms to a pcapng file.
- Switch-port diagnostics flag CRC errors, link flaps, duplex mismatches, speed downgrades and PoE problems from SNMP counters.
- Wi-Fi diagnostics separate the radio hop from the backhaul, with signal strength, link rate, roams, disconnect reasons and per-AP health.
- The dual-interface self-test measures true one-way latency across your switch and access point on a PC with both a wired and a Wi-Fi adapter.
- The headless probe agent for Windows and Linux, including Raspberry Pi, adds a second vantage point.
- The opt-in internet monitor pings targets you choose and keeps a history of every outage.
- A health score checks DNS, MTU black holes, bufferbloat, cleartext management, expired certificates, SMBv1 and rogue DHCP or router advertisements.
- Live MTR, Wake-on-LAN and one-click SSH, RDP and web UI launchers are available for every device.
- Results export to JSON, CSV, Nmap XML, a self-contained HTML report or pcapng.
- Alerts go to desktop notifications, Discord, Slack, JSON webhooks or syslog.
- Demo mode simulates a 43-device network, so you can try everything without Npcap and without touching your network.
- NetSpider installs per user with automatic updates, from an MSI for managed deployment, or runs as a standalone exe or portable zip, on x64, ARM64 and x86.
- The Release and Pre-release update channels can be switched in Settings, and a "What's new" dialog shows the changes after every update.
