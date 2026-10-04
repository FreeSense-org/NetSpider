namespace NetSpider.Core.Model;

public enum PortScanProfile { Off, Stealth, Balanced, FastLan }

/// <summary>User settings, persisted as JSON in %LOCALAPPDATA%\NetSpider\settings.json.</summary>
public sealed class AppSettings
{
    public string? LastAdapterId { get; set; }

    // ---- scanning ----
    public bool ScanOtherSubnets { get; set; } = true;
    public bool ProbeVlans { get; set; } = true;
    /// <summary>Largest subnet (by prefix) to sweep fully; bigger ones are capped.</summary>
    public int MinSweepPrefix { get; set; } = 20;
    public int MaxInjectPps { get; set; } = 400;
    public PortScanProfile PortScan { get; set; } = PortScanProfile.Balanced;
    /// <summary>Extra ports to scan in addition to the built-in top list, e.g. "8000-8100,9999".</summary>
    public string ExtraPorts { get; set; } = "";
    public bool TlsInspection { get; set; } = true;
    public bool BannerGrab { get; set; } = true;
    public bool Traceroute { get; set; } = true;
    public bool ActiveDhcpDiscover { get; set; } = true;
    public bool IgmpQuery { get; set; } = true;

    // ---- SNMP ----
    public List<string> SnmpCommunities { get; set; } = ["public", "private"];
    public string? SnmpV3User { get; set; }
    public string? SnmpV3AuthPassword { get; set; }
    public string? SnmpV3PrivPassword { get; set; }
    public string SnmpV3AuthProtocol { get; set; } = "SHA";
    public string SnmpV3PrivProtocol { get; set; } = "AES";
    public int SnmpTimeoutMs { get; set; } = 1500;
    /// <summary>While monitoring: try SNMP on newly discovered devices and re-poll devices that answered (FDB, ports, toner…).</summary>
    public bool SnmpAutoPoll { get; set; } = true;
    public int SnmpPollMinutes { get; set; } = 5;

    // ---- latency ----
    public int LatencyIntervalSeconds { get; set; } = 3;
    public bool TcpLatency { get; set; } = false;
    public double LatencyGoodMs { get; set; } = 2;
    public double LatencyWarnMs { get; set; } = 20;
    public double LatencyBadMs { get; set; } = 50;

    // ---- internet monitor (opt-in) ----
    public bool InternetMonitorEnabled { get; set; } = false;
    public int InternetIntervalSeconds { get; set; } = 2;
    /// <summary>Consecutive failed rounds (all targets down) before the internet is declared offline.</summary>
    public int InternetOutageRounds { get; set; } = 3;
    public double InternetLatencyWarnMs { get; set; } = 100;
    public List<InternetTarget> InternetTargets { get; set; } =
    [
        new() { Name = "Cloudflare", Host = "1.1.1.1" },
        new() { Name = "Google DNS", Host = "8.8.8.8" },
        new() { Name = "Quad9", Host = "9.9.9.9" },
    ];

    // ---- updates (built-in updater) ----
    public bool UpdateCheckOnStartup { get; set; } = true;
    /// <summary>Periodic check interval in hours; 0 disables periodic checks.</summary>
    public int UpdateCheckHours { get; set; } = 6;
    /// <summary>"release" or "prerelease"; null = follow the channel the installer was built for.</summary>
    public string? UpdateChannel { get; set; }
    public UpdateAction UpdateAction { get; set; } = UpdateAction.DownloadAndAsk;
    public string? SkippedVersion { get; set; }
    public DateTimeOffset? LastUpdateCheck { get; set; }
    public string? LastUpdateResult { get; set; }
    /// <summary>The version whose "What's new" was last shown (or that was first installed); null on a fresh profile.</summary>
    public string? LastSeenVersion { get; set; }

    // ---- application behaviour ----
    public bool StartWithWindows { get; set; } = false;
    public bool StartMinimizedToTray { get; set; } = false;
    public bool CloseToTray { get; set; } = false;
    public bool AutoStartMonitoring { get; set; } = false;
    public bool ToastNotifications { get; set; } = true;
    public AlertSeverity ToastMinSeverity { get; set; } = AlertSeverity.Warning;
    /// <summary>"Information" or "Debug".</summary>
    public string LogLevel { get; set; } = "Information";
    public bool WelcomeShown { get; set; } = false;
    /// <summary>Captures folder size cap in MB; oldest pcapng files are deleted beyond it.</summary>
    public int CaptureFolderMaxMb { get; set; } = 2048;
    public WindowPlacement? Window { get; set; }

    // ---- path doctor / fault locator ----
    public bool PathMonitorEnabled { get; set; } = true;
    public int PathIntervalSeconds { get; set; } = 2;
    /// <summary>Consecutive failed probes before a hop is declared down.</summary>
    public int HopDownRounds { get; set; } = 3;

    // ---- switch-port diagnostics ----
    public bool PortCountersEnabled { get; set; } = true;
    public int PortCounterPollSeconds { get; set; } = 60;
    public double PortErrorsPerMinWarn { get; set; } = 10;

    // ---- storm center ----
    /// <summary>Unlocks the active storm-control check (sends a short broadcast burst). Off by default.</summary>
    public bool StormControlCheckEnabled { get; set; } = false;

    // ---- Wi-Fi diagnostics ----
    public bool WifiLinkMonitorEnabled { get; set; } = true;
    public int WifiWeakRssiDbm { get; set; } = -75;

    // ---- probe agents ----
    public bool ProbeAgentHubEnabled { get; set; } = false;
    public int ProbeAgentPort { get; set; } = 47810;
    /// <summary>Shared secret used to HMAC-sign agent reports; generated on first use.</summary>
    public string? ProbeAgentKey { get; set; }

    // ---- anomaly thresholds ----
    public double StormBroadcastRatio { get; set; } = 0.15;
    public double StormBroadcastPps { get; set; } = 500;
    public double StormMulticastPps { get; set; } = 2000;
    public double StormPerMacPps { get; set; } = 300;
    public int MacFlapThreshold { get; set; } = 3;
    public double TopTalkerPps { get; set; } = 1000;
    public bool DumpPcapOnAlert { get; set; } = true;

    // ---- logos ----
    public bool ScrapeVendorLogos { get; set; } = true;

    // ---- notifications ----
    public List<WebhookConfig> Webhooks { get; set; } = [];
    public string? SyslogServer { get; set; }
    public int SyslogPort { get; set; } = 514;
    public AlertSeverity NotifyMinSeverity { get; set; } = AlertSeverity.Warning;

    // ---- UI ----
    public bool ShowMacOnNodes { get; set; } = true;
    public bool ShowEstimatedLinks { get; set; } = true;
    public bool Animations { get; set; } = true;
}

public enum UpdateAction { NotifyOnly, DownloadAndAsk, InstallOnExit }

/// <summary>Remembered main-window placement and UI state.</summary>
public sealed class WindowPlacement
{
    public double X { get; set; }
    public double Y { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }
    public bool Maximized { get; set; }
    public string? LastPage { get; set; }
    public bool InspectorOpen { get; set; }
}

/// <summary>A user-defined internet ping target (IP address or host name).</summary>
public sealed class InternetTarget
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public bool Enabled { get; set; } = true;
}

public sealed class WebhookConfig
{
    public string Name { get; set; } = "";
    /// <summary>Discord, Slack or Json.</summary>
    public string Kind { get; set; } = "Json";
    public string Url { get; set; } = "";
    public bool Enabled { get; set; } = true;
}
