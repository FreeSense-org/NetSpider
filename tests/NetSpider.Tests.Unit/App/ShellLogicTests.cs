using System.Xml.Linq;
using NetSpider.App.Services;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.App;

public class WindowPlacementTests
{
    private static readonly ScreenArea Primary = new(0, 0, 1920, 1040, 1.0);
    private static readonly ScreenArea RightHiDpi = new(1920, 0, 2560, 1400, 1.5);

    [Fact]
    public void Placement_fully_on_a_screen_is_kept()
    {
        var r = WindowStateStore.Clamp(new WindowRect(100, 80, 1400, 900), [Primary]);
        Assert.Equal(new WindowRect(100, 80, 1400, 900), r);
    }

    [Fact]
    public void Disconnected_monitor_moves_the_window_to_the_primary_screen_centered()
    {
        // saved on a monitor at x=-2560 that is no longer connected
        var r = WindowStateStore.Clamp(new WindowRect(-2400, 100, 1200, 800), [Primary]);
        Assert.Equal(new WindowRect((1920 - 1200) / 2, (1040 - 800) / 2, 1200, 800), r);
    }

    [Fact]
    public void Window_hanging_off_the_edge_is_moved_inside()
    {
        var r = WindowStateStore.Clamp(new WindowRect(1500, 600, 1000, 700), [Primary]);
        Assert.Equal(1920 - 1000, r.X);
        Assert.Equal(1040 - 700, r.Y);
        Assert.Equal(1000, r.Width);
    }

    [Fact]
    public void Too_large_window_is_shrunk_to_the_working_area()
    {
        var r = WindowStateStore.Clamp(new WindowRect(0, 0, 3000, 2000), [Primary]);
        Assert.Equal(new WindowRect(0, 0, 1920, 1040), r);
    }

    [Fact]
    public void Size_is_scaled_by_the_target_monitor_dpi()
    {
        // 1700 DIP wide on a 150 % monitor = 2550 physical px: fits 2560, so it must stay inside [1920, 4480]
        var r = WindowStateStore.Clamp(new WindowRect(2500, 50, 1700, 900), [Primary, RightHiDpi]);
        Assert.Equal(1700, r.Width);
        Assert.True(r.X >= 1920 && r.X + r.Width * 1.5 <= 1920 + 2560, $"x={r.X}");
        // DIP height limited by 1400 px / 1.5
        var tall = WindowStateStore.Clamp(new WindowRect(2000, 0, 1200, 2000), [Primary, RightHiDpi]);
        Assert.Equal(Math.Round(1400 / 1.5), tall.Height);
    }

    [Fact]
    public void Title_bar_above_the_screen_is_not_accepted()
    {
        var r = WindowStateStore.Clamp(new WindowRect(200, -600, 1000, 800), [Primary]);
        Assert.True(r.Y >= 0);
    }

    [Fact]
    public void No_screens_returns_the_saved_rect()
    {
        var saved = new WindowRect(5, 6, 7, 8);
        Assert.Equal(saved, WindowStateStore.Clamp(saved, []));
    }
}

public class CaptureJanitorTests
{
    private const long MB = 1024 * 1024;
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static CaptureJanitor.CaptureFile F(string name, long mb, int hour) => new(Path.Combine(Path.GetTempPath(), name), mb * MB, T0.AddHours(hour));

    [Fact]
    public void Nothing_is_deleted_under_the_cap()
    {
        var files = new[] { F("a.pcapng", 100, 1), F("b.pcapng", 100, 2) };
        Assert.Empty(CaptureJanitor.SelectForDeletion(files, 500 * MB, []));
    }

    [Fact]
    public void Oldest_files_are_deleted_until_under_the_cap()
    {
        var files = new[] { F("new.pcapng", 300, 5), F("old.pcapng", 300, 1), F("mid.pcapng", 300, 3) };
        var del = CaptureJanitor.SelectForDeletion(files, 650 * MB, []);
        Assert.Equal(["old.pcapng"], del.Select(d => Path.GetFileName(d.Path)));
        var del2 = CaptureJanitor.SelectForDeletion(files, 299 * MB, []);
        Assert.Equal(["old.pcapng", "mid.pcapng", "new.pcapng"], del2.Select(d => Path.GetFileName(d.Path)));
    }

    [Fact]
    public void Active_recording_is_never_deleted()
    {
        var active = F("active.pcapng", 800, 0); // oldest and biggest, but being recorded
        var files = new[] { active, F("x.pcapng", 100, 2), F("y.pcapng", 100, 3) };
        var del = CaptureJanitor.SelectForDeletion(files, 500 * MB, [active.Path.ToUpperInvariant(), null]);
        Assert.DoesNotContain(del, d => d.Path == active.Path);
        Assert.Equal(2, del.Count); // still over the cap, but everything else goes
    }
}

public class NpcapInstallerTests
{
    [Fact]
    public void Latest_installer_url_is_parsed_from_the_home_page()
    {
        const string html = """
            <html><body>
            <a href="dist/npcap-1.79.exe">Npcap 1.79 installer</a> for Windows 7/2008R2, 8/2012, 8.1/2012R2, 10/2016, 2019, 11 (x86, x64, and ARM64).
            <a href="https://npcap.com/dist/npcap-1.80.exe">Npcap 1.80</a>
            <a href="dist/npcap-sdk-1.15.zip">SDK</a>
            <a href="dist/npcap-1.8.exe">old</a>
            <a href="dist/npcap-1.80.exe.sig">sig</a>
            </body></html>
            """;
        Assert.Equal("https://npcap.com/dist/npcap-1.80.exe", NpcapInstaller.ParseLatestInstallerUrl(html));
    }

    [Fact]
    public void Version_comparison_is_numeric_not_lexical()
    {
        Assert.Equal("https://npcap.com/dist/npcap-1.100.exe", NpcapInstaller.ParseLatestInstallerUrl("dist/npcap-1.99.exe dist/npcap-1.100.exe dist/npcap-1.9.exe"));
    }

    [Fact]
    public void Page_without_installer_returns_null()
    {
        Assert.Null(NpcapInstaller.ParseLatestInstallerUrl("<html>maintenance</html>"));
        Assert.Null(NpcapInstaller.ParseLatestInstallerUrl("dist/npcap-sdk-1.15.zip"));
    }
}

public class StartupTaskTests
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    [Fact]
    public void Task_xml_is_a_highest_privilege_logon_task_for_the_user()
    {
        var xml = StartupTask.BuildXml(@"C:\Users\a&b\AppData\Local\NetSpider\current\NetSpider.exe", @"PC\a&b");
        var doc = XDocument.Parse(xml);
        var trigger = doc.Descendants(Ns + "LogonTrigger").Single();
        Assert.Equal(@"PC\a&b", trigger.Element(Ns + "UserId")!.Value);
        var principal = doc.Descendants(Ns + "Principal").Single();
        Assert.Equal("HighestAvailable", principal.Element(Ns + "RunLevel")!.Value);
        Assert.Equal("InteractiveToken", principal.Element(Ns + "LogonType")!.Value);
        var exec = doc.Descendants(Ns + "Exec").Single();
        Assert.Equal("\"C:\\Users\\a&b\\AppData\\Local\\NetSpider\\current\\NetSpider.exe\"", exec.Element(Ns + "Command")!.Value);
        Assert.Equal("--minimized", exec.Element(Ns + "Arguments")!.Value);
        Assert.Equal(@"C:\Users\a&b\AppData\Local\NetSpider\current", exec.Element(Ns + "WorkingDirectory")!.Value);
        Assert.Equal("PT0S", doc.Descendants(Ns + "ExecutionTimeLimit").Single().Value);
        Assert.Equal("false", doc.Descendants(Ns + "DisallowStartIfOnBatteries").Single().Value);
        Assert.Equal(@"\" + StartupTask.TaskName, doc.Descendants(Ns + "URI").Single().Value);
    }
}

public class SettingsPorterTests
{
    [Fact]
    public void Export_then_import_round_trips_and_keeps_local_values()
    {
        var src = new AppSettings
        {
            PortScan = PortScanProfile.FastLan, SnmpCommunities = ["c1", "c2"], CloseToTray = true, ToastMinSeverity = AlertSeverity.Critical,
            LogLevel = "Debug", CaptureFolderMaxMb = 512, UpdateAction = UpdateAction.InstallOnExit,
            Webhooks = [new WebhookConfig { Name = "d", Kind = "Discord", Url = "https://example.invalid/x" }],
            LastAdapterId = "exported-adapter", Window = new WindowPlacement { Width = 1 },
        };
        var json = SettingsPorter.Export(src);
        Assert.DoesNotContain("exported-adapter", json); // machine-specific values are not exported
        Assert.Contains("\"$product\"", json);

        var parsed = SettingsPorter.Parse(json);
        Assert.True(parsed.Success, parsed.Message);
        Assert.Empty(parsed.Warnings);

        var target = new AppSettings { LastAdapterId = "mine", WelcomeShown = true };
        var changed = SettingsPorter.CopyInto(parsed.Settings!, target);
        Assert.Equal(PortScanProfile.FastLan, target.PortScan);
        Assert.Equal(["c1", "c2"], target.SnmpCommunities);
        Assert.True(target.CloseToTray);
        Assert.Equal(AlertSeverity.Critical, target.ToastMinSeverity);
        Assert.Equal(UpdateAction.InstallOnExit, target.UpdateAction);
        Assert.Equal(512, target.CaptureFolderMaxMb);
        Assert.Single(target.Webhooks);
        Assert.Equal("mine", target.LastAdapterId);
        Assert.True(target.WelcomeShown);
        Assert.Contains(nameof(AppSettings.PortScan), changed);
        Assert.DoesNotContain(nameof(AppSettings.MinSweepPrefix), changed);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"foo\": 1}")]
    [InlineData("{\"PortScan\": \"banana\"}")]
    public void Invalid_files_are_rejected(string json)
    {
        var r = SettingsPorter.Parse(json);
        Assert.False(r.Success);
        Assert.Null(r.Settings);
        Assert.False(string.IsNullOrWhiteSpace(r.Message));
    }

    [Fact]
    public void Out_of_range_values_are_clamped_with_warnings()
    {
        var r = SettingsPorter.Parse("""{ "MinSweepPrefix": 2, "SyslogPort": 70000, "LogLevel": "Trace", "ToastMinSeverity": 42, "SnmpCommunities": null }""");
        Assert.True(r.Success, r.Message);
        Assert.Equal(8, r.Settings!.MinSweepPrefix);
        Assert.Equal(65535, r.Settings.SyslogPort);
        Assert.Equal("Information", r.Settings.LogLevel);
        Assert.Equal(AlertSeverity.Warning, r.Settings.ToastMinSeverity);
        Assert.NotNull(r.Settings.SnmpCommunities);
        Assert.Equal(4, r.Warnings.Count);
    }

    [Fact]
    public void Reset_copies_defaults_and_reports_restart_settings()
    {
        var live = new AppSettings { StartMinimizedToTray = true, MaxInjectPps = 999, LastAdapterId = "keep" };
        var changed = SettingsPorter.CopyInto(new AppSettings(), live);
        Assert.False(live.StartMinimizedToTray);
        Assert.Equal(400, live.MaxInjectPps);
        Assert.Equal("keep", live.LastAdapterId);
        Assert.Equal(["Start minimized to tray"], SettingsPorter.NeedsRestart(changed));
    }
}

public class TrayTooltipTests
{
    [Fact]
    public void Tooltip_describes_monitoring_and_incidents()
    {
        Assert.Equal("FreeSense – NetSpider — monitoring Ethernet · 43 devices", TrayService.Tooltip(true, "Ethernet", 43, 0));
        Assert.Equal("FreeSense – NetSpider — 2 active incidents", TrayService.Tooltip(true, "Ethernet", 43, 2));
        Assert.Equal("FreeSense – NetSpider — idle", TrayService.Tooltip(false, null, 0, 0));
        Assert.True(TrayService.Tooltip(true, new string('x', 300), 1, 0).Length <= 127);
    }
}
