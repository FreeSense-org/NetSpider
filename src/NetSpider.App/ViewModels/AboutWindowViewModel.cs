using System.Text;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Capture;
using NetSpider.Core;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.ViewModels;

/// <summary>A label/value row in the About dialog's system information.</summary>
public sealed record InfoRow(string Label, string Value);

/// <summary>About dialog: identity, FreeSense links, system info, diagnostics, license and third-party notices.</summary>
public sealed partial class AboutWindowViewModel : ObservableObject
{
    private static AboutWindow? _open;
    private readonly UpdateService? _updates;

    public AboutWindowViewModel(UpdateService? updates)
    {
        _updates = updates;
        var pcap = SafeNpcap();
        var mode = updates?.InstallMode ?? UpdateService.DetectInstallMode();
        SystemInfo =
        [
            new("Architecture", AppInfo.Architecture switch { "X64" => "x64", "X86" => "x86", "Arm64" => "ARM64", var a => a }),
            new(".NET runtime", AppInfo.RuntimeVersion),
            new("Operating system", AppInfo.OsVersion),
            new("Npcap", pcap.NpcapInstalled ? $"{ShortNpcap(pcap.Version)} · installed" : "not installed"),
            new("Administrator", pcap.IsAdmin ? "yes" : "no"),
            new("Install mode", UpdateLogic.InstallModeName(mode)),
            new("Data folder", AppPaths.Root),
        ];
    }

    /// <summary>Shows the About dialog (or brings the open one to the front), optionally on a tab (about, license, notices, changelog).</summary>
    public static void Show(UpdateService? updates, string? tab = null)
    {
        if (_open is { } existing)
        {
            if (tab is not null && existing.DataContext is AboutWindowViewModel open) open.Tab = NormalizeTab(tab);
            existing.Activate();
            return;
        }
        var vm = new AboutWindowViewModel(updates);
        if (tab is not null) vm.Tab = NormalizeTab(tab);
        var w = new AboutWindow { DataContext = vm, Title = AppInfo.WindowTitle("About") };
        _open = w;
        w.Closed += (_, _) => _open = null;
        if (Dialogs.Owner is { IsVisible: true } owner) _ = w.ShowDialog(owner);
        else w.Show();
    }

    public Bitmap? Logo => BrandAssets.Logo;
    public bool HasLogo => Logo is not null;
    public string BrandTitle => AppInfo.BrandTitle;
    public string Version => AppInfo.Version;
    public string Channel => (_updates?.Channel ?? "Stable") + " channel";
    public string BuildDate { get; } = ReadBuildDate();
    public string Commit => AppInfo.Commit is { Length: > 0 } c ? (c.Length > 12 ? c[..12] : c) : "local build";
    public string VersionLine => $"Version {Version}  ·  {Channel}";
    public string BuildLine => $"Built {BuildDate}  ·  commit {Commit}";

    public string Website => AppInfo.Website;
    public string Repository => AppInfo.Repository;
    public string ReleasesPage => AppInfo.ReleasesPage;
    public IReadOnlyList<InfoRow> SystemInfo { get; }

    // ---- tabs ----
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsAboutTab), nameof(IsLicenseTab), nameof(IsNoticesTab), nameof(IsChangelogTab))] private string _tab = "about";
    public bool IsAboutTab { get => Tab == "about"; set { if (value) Tab = "about"; } }
    public bool IsLicenseTab { get => Tab == "license"; set { if (value) Tab = "license"; } }
    public bool IsNoticesTab { get => Tab == "notices"; set { if (value) Tab = "notices"; } }
    public bool IsChangelogTab { get => Tab == "changelog"; set { if (value) Tab = "changelog"; } }

    private static string NormalizeTab(string tab) => tab.Trim().ToLowerInvariant() switch
    {
        "license" => "license",
        "notices" or "third-party" or "thirdparty" => "notices",
        "changelog" or "changes" => "changelog",
        _ => "about",
    };

    // ---- changelog tab ----
    /// <summary>Every version in the embedded CHANGELOG.md (Unreleased first, when a pre-release has entries there).</summary>
    public IReadOnlyList<NetSpider.Core.Changelog.ChangelogRelease> ChangelogReleases { get; } =
        EmbeddedChangelog.Load().Releases.Where(r => !r.IsEmpty && (!r.IsUnreleased || AppInfo.Version.Contains('-'))).ToList();
    public bool HasChangelog => ChangelogReleases.Count > 0;
    public string CurrentVersion => AppInfo.Version;

    [RelayCommand] private static void ShowWhatsNew() => WhatsNewWindowViewModel.ShowCurrent();
    [RelayCommand] private static void OpenChangelogOnGitHub() => Launcher.Open(AppInfo.Repository + "/blob/main/CHANGELOG.md");

    public string LicenseText { get; } = ReadLicense();
    public string NoticesText { get; } = ReadNotices();

    [ObservableProperty] private string? _status;

    /// <summary>Everything above as plain text, for support requests.</summary>
    public string DiagnosticText
    {
        get
        {
            var sb = new StringBuilder();
            sb.AppendLine($"{AppInfo.BrandTitle} {AppInfo.InformationalVersion}");
            sb.AppendLine($"Channel: {Channel}");
            sb.AppendLine($"Build date: {BuildDate}");
            sb.AppendLine($"Commit: {Commit}");
            foreach (var r in SystemInfo) sb.AppendLine($"{r.Label}: {r.Value}");
            if (_updates is not null) sb.AppendLine($"Updates: {_updates.StatusText}");
            sb.AppendLine($"Website: {AppInfo.Website}");
            sb.AppendLine($"Repository: {AppInfo.Repository}");
            return sb.ToString();
        }
    }

    [RelayCommand] private static void OpenUrl(string url) => Launcher.Open(url);

    [RelayCommand]
    private void CheckForUpdates()
    {
        if (_updates is null) { Launcher.Open(AppInfo.ReleasesPage); return; }
        UpdateWindowViewModel.Show(_updates, checkNow: true);
    }

    [RelayCommand]
    private async Task CopyDiagnostics()
    {
        await CopyAsync(DiagnosticText);
        Status = "Diagnostic info copied to the clipboard";
    }

    [RelayCommand]
    private async Task ReportProblem()
    {
        await CopyAsync(DiagnosticText);
        Status = "Diagnostic info copied — paste it into the issue";
        Launcher.Open(AppInfo.IssuesUrl);
    }

    [RelayCommand] private static void OpenLogs() => Launcher.Open(AppPaths.Logs);
    [RelayCommand] private static void OpenData() => Launcher.Open(AppPaths.Root);

    /// <summary>The About window's own clipboard (it is modal, so the main window's may be unavailable).</summary>
    public Func<string, Task>? Clipboard { get; set; }

    private async Task CopyAsync(string text)
    {
        try
        {
            if (Clipboard is not null) await Clipboard(text);
            else await Dialogs.CopyAsync(text);
        }
        catch (Exception ex) { Log.Warning(ex, "Copying diagnostics failed"); }
    }

    private static Core.Abstractions.PcapStatus SafeNpcap()
    {
        try { return NpcapEnvironment.Check(); }
        catch (Exception ex)
        {
            Log.Debug(ex, "Npcap check failed");
            return new Core.Abstractions.PcapStatus(false, NpcapEnvironment.IsAdministrator(), null, ex.Message);
        }
    }

    /// <summary>"Npcap version 1.79, based on libpcap version 1.10.4" → "Npcap 1.79 (libpcap 1.10.4)".</summary>
    private static string ShortNpcap(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "unknown version";
        var m = System.Text.RegularExpressions.Regex.Match(v, @"Npcap version ([\d.]+).*?libpcap version ([\d.]+)");
        return m.Success ? $"Npcap {m.Groups[1].Value} (libpcap {m.Groups[2].Value})" : v.Trim();
    }

    private static string ReadBuildDate()
    {
        try
        {
            var exe = Environment.ProcessPath ?? typeof(AboutWindowViewModel).Assembly.Location;
            return File.GetLastWriteTime(exe).ToString("yyyy-MM-dd");
        }
        catch { return "unknown"; }
    }

    private static string ReadLicense()
    {
        var text = BrandAssets.ReadText("avares://NetSpider/Assets/LICENSE.txt");
        if (text is null)
        {
            var path = Path.Combine(AppContext.BaseDirectory, "LICENSE");
            if (File.Exists(path)) text = File.ReadAllText(path);
        }
        return text ?? "MIT License — see " + AppInfo.Repository + "/blob/main/LICENSE";
    }

    private static string ReadNotices()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "THIRD-PARTY-NOTICES.txt");
            if (File.Exists(path)) return File.ReadAllText(path);
            // embedded copy (the standalone single-file exe has no loose files)
            if (BrandAssets.ReadText("avares://NetSpider/Assets/THIRD-PARTY-NOTICES.txt") is { } embedded) return embedded;
        }
        catch (Exception ex) { Log.Debug(ex, "Reading third-party notices failed"); }
        return "Third-party notices are not available in this build.\n\nThe notices file (THIRD-PARTY-NOTICES.txt) ships with the installed and portable "
               + "versions of NetSpider. You can also read it in the source repository:\n" + AppInfo.Repository;
    }
}
