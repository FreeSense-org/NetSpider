using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Changelog;
using Serilog;

namespace NetSpider.App.ViewModels;

/// <summary>
/// The "What's new" dialog: shown once at startup after an update (every release since the last seen version, or the
/// Unreleased section for a pre-release build), and on demand from About and Settings → Updates.
/// </summary>
public sealed partial class WhatsNewWindowViewModel : ObservableObject
{
    private static WhatsNewWindow? _open;

    public WhatsNewWindowViewModel(WhatsNewPlan plan, string? fromVersion)
    {
        Plan = plan;
        FromVersion = fromVersion;
    }

    public WhatsNewPlan Plan { get; }
    public string? FromVersion { get; }
    public Action? Close { get; set; }

    public Bitmap? Logo => BrandAssets.Logo;
    public bool HasLogo => Logo is not null;
    public string Title => Plan.Title;
    public IReadOnlyList<ChangelogRelease> Releases => Plan.Releases;
    /// <summary>Several versions get a card each; a single version is listed without a header (the title names it).</summary>
    public bool ShowReleaseHeaders => Releases.Count > 1;
    public string CurrentVersion => AppInfo.Version;

    public string Subtitle
    {
        get
        {
            int versions = Releases.Count(r => !r.IsUnreleased);
            if (Plan.IsPrerelease)
                return versions > 0 && FromVersion is { Length: > 0 } since
                    ? $"Pre-release {AppInfo.Version} · updated from {since}"
                    : $"Pre-release {AppInfo.Version} · everything since the last release";
            if (versions > 1 && FromVersion is { Length: > 0 } from) return $"Updated from {from} · {versions} releases";
            var r0 = Releases.FirstOrDefault();
            return r0?.Date is { } d ? "Released " + d.ToString("MMMM d, yyyy", System.Globalization.CultureInfo.InvariantCulture) : $"Version {AppInfo.Version}";
        }
    }

    [RelayCommand] private void Dismiss() => Close?.Invoke();

    [RelayCommand]
    private void OpenFullChangelog()
    {
        Close?.Invoke();
        AboutWindowViewModel.Show(AppHost.Services?.GetService<UpdateService>(), "changelog");
    }

    // ================================================================================================ showing

    /// <summary>
    /// Startup: shows the dialog after an update (and remembers the version), remembers the version silently on a first
    /// install. Not in demo, screenshot (--hide-banners) or snapshot runs.
    /// </summary>
    public static void ShowAtStartup(ISettingsStore store, AppOptions options, bool firstRun)
    {
        if (options.Demo || options.HideBanners || options.SnapshotPath is not null || options.WhatsNew is not null) return;
        try
        {
            var settings = store.Settings;
            var lastSeen = settings.LastSeenVersion;
            var plan = WhatsNew.Plan(EmbeddedChangelog.Load(), lastSeen, AppInfo.Version, firstRun);
            if (plan.RememberVersion)
            {
                settings.LastSeenVersion = AppInfo.Version;
                try { store.Save(); } catch (Exception ex) { Log.Warning(ex, "Saving the last seen version failed"); }
            }
            if (!plan.Show) return;
            Log.Information("Showing what's new: {From} → {To} ({Count} section(s))", lastSeen ?? "(none)", AppInfo.Version, plan.Releases.Count);
            DispatcherTimer.RunOnce(() => Show(plan, lastSeen), TimeSpan.FromMilliseconds(600));
        }
        catch (Exception ex) { Log.Warning(ex, "What's new check failed"); }
    }

    /// <summary>"Show what's new" (About, Settings → Updates): this version's changes.</summary>
    public static void ShowCurrent()
    {
        var plan = WhatsNew.ForCurrent(EmbeddedChangelog.Load(), AppInfo.Version);
        if (plan.Show) Show(plan, null);
        else AboutWindowViewModel.Show(AppHost.Services?.GetService<UpdateService>(), "changelog");
    }

    /// <summary>Debug/screenshots (<c>--whats-new [last-seen]</c>): "current", or the changes since the given version.</summary>
    public static void ShowPreview(string arg)
    {
        var log = EmbeddedChangelog.Load();
        var plan = string.Equals(arg, "current", StringComparison.OrdinalIgnoreCase)
            ? WhatsNew.ForCurrent(log, AppInfo.Version)
            : WhatsNew.Plan(log, arg, AppInfo.Version, firstRun: false);
        if (!plan.Show) plan = WhatsNew.ForCurrent(log, AppInfo.Version);
        if (plan.Show) Show(plan, arg == "current" ? null : arg);
    }

    private static void Show(WhatsNewPlan plan, string? from)
    {
        if (_open is { } existing) { existing.Activate(); return; }
        var vm = new WhatsNewWindowViewModel(plan, from);
        var w = new WhatsNewWindow { DataContext = vm, Title = AppInfo.WindowTitle("What's new") };
        vm.Close = w.Close;
        _open = w;
        w.Closed += (_, _) => _open = null;
        if (Dialogs.Owner is { IsVisible: true } owner) _ = w.ShowDialog(owner);
        else
        {
            w.WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterScreen;
            w.Show();
        }
    }
}
