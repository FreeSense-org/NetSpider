# netspider-probe

A small headless agent that gives NetSpider a **second vantage point**. Run it on another PC, a laptop on Wi-Fi or a
Raspberry Pi. Every interval it pings its targets (default: its gateway, the NetSpider PC and 1.1.1.1) and sends a
signed report to NetSpider over UDP. NetSpider pings the agent back. Together they test both directions
(LAN → Wi-Fi and Wi-Fi → LAN) and can say things like *"agent LAPTOP-WIFI cannot reach 10.40.0.1 (wired PC can)"*.

It has no UI, no Npcap and no admin requirement, and it runs on Windows x64 and Linux ARM64/x64.

## 1. Enable the hub in NetSpider

In NetSpider settings, turn on **Probe agent hub** (`ProbeAgentHubEnabled`). The hub listens on UDP **47810**
(`ProbeAgentPort`), and on UDP **47811** for discovery. On first enable it generates a random 32-byte key
(`ProbeAgentKey`, base64). Copy that key to the agent.

Allow inbound UDP 47810 and 47811 in the Windows firewall on the NetSpider PC, for example:

```powershell
New-NetFirewallRule -DisplayName "NetSpider probe hub" -Direction Inbound -Protocol UDP -LocalPort 47810,47811 -Action Allow -Profile Private,Domain
```

## 2. Run the agent

```text
netspider-probe --key <base64> [--hub <ip|host>[:port]] [--targets gw,hub,1.1.1.1,10.40.0.15]
                [--interval 2] [--window 10] [--id NAME] [--once] [--quiet] [--config probe.json]
```

| Option | Meaning |
|---|---|
| `--hub` | Address of the NetSpider PC. If you omit it, the agent finds the hub with an authenticated broadcast on UDP 47811. |
| `--key` | The shared key. You can also set it in the `NETSPIDER_PROBE_KEY` environment variable, or as `"key"` in `probe.json`. |
| `--targets` | `gw` = default gateway, `hub` = the NetSpider PC; anything else is an IP or a host name. |
| `--interval` | Seconds between rounds (default 2). |
| `--window` | Number of pings per target that loss and average are computed over (default 10). |
| `--id` | The agent's name in NetSpider (default: the machine name). |
| `--once` | Run one round, send one report and exit. Exit code 0 means sent; 2 means the hub was not found. |
| `--quiet` | Log only reachability changes and errors. |

Examples:

```powershell
# Windows laptop on Wi-Fi, explicit hub
.\netspider-probe.exe --hub 10.40.210.17 --key Zm9v...= --id LAPTOP-WIFI

# Smoke test: one report, then exit
.\netspider-probe.exe --hub 10.40.210.17 --key Zm9v...= --once
```

```bash
# Raspberry Pi: discover the hub, also watch the NAS and the printer
NETSPIDER_PROBE_KEY='Zm9v...=' ./netspider-probe --targets gw,hub,1.1.1.1,10.40.0.15,printer.lan --id pi-office
```

### probe.json

The agent reads `probe.json` from the directory of the executable, or the file given with `--config`. Command-line
arguments override it. See `probe.example.json`:

```jsonc
{ "hub": "10.40.210.17", "key": "<base64>", "id": "LAPTOP-WIFI", "targets": ["gw", "hub", "1.1.1.1"], "interval": 2 }
```

## 3. Build / publish

From the repository root:

```bash
# Windows x64 (single self-contained, trimmed exe)
dotnet publish src/NetSpider.Probe -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
# Raspberry Pi (64-bit Raspberry Pi OS)
dotnet publish src/NetSpider.Probe -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true
# or with the publish profiles (output in src/NetSpider.Probe/bin/publish/<rid>/)
dotnet publish src/NetSpider.Probe -p:PublishProfile=linux-arm64
```

Copy `netspider-probe` to the Pi, then run `chmod +x netspider-probe`. A 32-bit Raspberry Pi OS needs `-r linux-arm`.
No .NET installation is needed on the target.

### ICMP on Linux

.NET's `Ping` works without root. It uses unprivileged ICMP sockets when `net.ipv4.ping_group_range` allows them
(the default on Raspberry Pi OS and Ubuntu), and otherwise falls back to the system `ping` tool. If neither works, the
agent switches to TCP connect probes on ports 443 and 80, where a refused connection still counts as reachable, and it
logs this hint:

```bash
sudo setcap cap_net_raw+ep ./netspider-probe        # or:
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

### Wi-Fi details (optional)

On a Wi-Fi interface the report includes SSID, BSSID, RSSI, channel and rates. On Windows they come from
`netsh wlan show interfaces` (English output). On Linux they come from `iw dev <if> link` (`sudo apt install iw`).
If the tool is missing, the agent silently leaves this out.

## 4. Run as a service (`--install-service` hint)

The agent installs nothing by itself. Here are examples.

**Raspberry Pi / Linux (systemd)**: `/etc/systemd/system/netspider-probe.service`

```ini
[Unit]
Description=NetSpider probe agent
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/opt/netspider-probe/netspider-probe --quiet
WorkingDirectory=/opt/netspider-probe
# key + hub in /opt/netspider-probe/probe.json (chmod 600), or:
# Environment=NETSPIDER_PROBE_KEY=...
Restart=always
RestartSec=5
DynamicUser=yes
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now netspider-probe
journalctl -u netspider-probe -f
```

**Windows**: the agent is a console app and does not implement the Service Control Manager protocol. Use one of these:

```powershell
# Simplest: a scheduled task that starts at boot as SYSTEM (put key/hub in probe.json next to the exe)
schtasks /Create /TN "NetSpider Probe" /SC ONSTART /RU SYSTEM /TR "\"C:\Tools\netspider-probe\netspider-probe.exe\" --quiet"

# Or a real service through a service wrapper such as NSSM / WinSW, e.g. with NSSM:
nssm install NetSpiderProbe C:\Tools\netspider-probe\netspider-probe.exe --quiet
# sc.exe only works through such a wrapper (a bare console exe fails to start with error 1053):
sc.exe create NetSpiderProbe binPath= "C:\Tools\winsw\NetSpiderProbe.exe" start= auto
```

## Security

- Every report is signed with **HMAC-SHA256** using the shared key. The hub rejects a report when:
  - its signature is wrong,
  - its timestamp is more than **2 minutes** off the hub's clock (keep NTP on), or
  - it reuses a nonce (the hub keeps an LRU of recent nonces).
- Reports are **signed, not encrypted**. Anyone on the LAN can read them: host name, IP, MAC and ping results.
- Discovery is authenticated too. The hub answers `NETSPIDER_HUB?` only when the request carries a valid HMAC tag over
  a random challenge, and its reply is tagged as well, so the agent cannot be pointed at a fake hub. Without the key,
  nobody learns that a hub exists.
- Treat the key like a password. Prefer `probe.json` with restrictive permissions, or the `NETSPIDER_PROBE_KEY`
  variable, over `--key`, because command lines are visible to other local users. To rotate the key, clear
  `ProbeAgentKey` in NetSpider (a new one is generated) and update the agents.

## Wire protocol (v1)

UDP datagram (< 8 KB; large target lists are split into several datagrams with the same report `time`):

```json
{"v":1,"agentId":"LAPTOP-WIFI","ts":1791043200000,"nonce":"<16 random bytes b64>",
 "payload":{"agentId":"LAPTOP-WIFI","hostname":"LAPTOP","ip":"10.40.3.20","mac":"60:FF:9E:10:20:30","medium":"Wi-Fi",
            "time":"2026-10-04T18:00:00+02:00","results":[{"target":"gw","ip":"10.40.0.1","rttMs":2.1,"avgMs":2.4,
            "lossPercent":0,"sent":10}],"wifi":{...},"gateway":"10.40.0.1","version":"1.0.0"},
 "sig":"<b64 HMAC-SHA256(key, 'NSP1\n' + agentId + '\n' + ts + '\n' + nonce + '\n' + payload bytes as sent)>"}
```
