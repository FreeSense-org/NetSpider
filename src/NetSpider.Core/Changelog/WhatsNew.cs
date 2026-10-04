namespace NetSpider.Core.Changelog;

/// <summary>Whether to show the "What's new" dialog at startup, with which changelog sections, and whether to remember the version.</summary>
public sealed record WhatsNewPlan(bool Show, bool RememberVersion, string Title, IReadOnlyList<ChangelogRelease> Releases, bool IsPrerelease)
{
    public static WhatsNewPlan None(bool remember) => new(false, remember, "", [], false);
}

/// <summary>
/// Decides the startup "What's new" dialog: shown once after an update, with every release in (last seen, current].
/// A pre-release build shows the embedded <c>[Unreleased]</c> section ("What's new in this pre-release"). A first install
/// shows nothing and just remembers the version.
/// </summary>
public static class WhatsNew
{
    public const string PrereleaseTitle = "What's new in this pre-release";

    /// <param name="changelog">The changelog embedded in this build.</param>
    /// <param name="lastSeenVersion">AppSettings.LastSeenVersion (null on a first install or before this feature existed).</param>
    /// <param name="currentVersion">AppInfo.Version.</param>
    /// <param name="firstRun">True on a fresh install (the welcome wizard is due).</param>
    public static WhatsNewPlan Plan(Changelog changelog, string? lastSeenVersion, string currentVersion, bool firstRun)
    {
        if (!SemVer.TryParse(currentVersion, out var current)) return WhatsNewPlan.None(remember: false);
        bool remember = !string.Equals(lastSeenVersion?.Trim(), current.ToString(), StringComparison.OrdinalIgnoreCase);

        SemVer? lastSeen;
        if (string.IsNullOrWhiteSpace(lastSeenVersion))
        {
            // first install: nothing to announce. An existing install that predates "what's new": show this version only.
            if (firstRun) return WhatsNewPlan.None(remember: true);
            lastSeen = null;
        }
        else if (!SemVer.TryParse(lastSeenVersion, out var ls)) return WhatsNewPlan.None(remember: true);
        else lastSeen = ls;

        if (lastSeen is { } seen && current <= seen) return WhatsNewPlan.None(remember);

        var releases = Between(changelog, lastSeen, current);
        if (releases.Count == 0) return WhatsNewPlan.None(remember: true);
        return new WhatsNewPlan(true, true, TitleFor(current, releases), releases, current.IsPrerelease);
    }

    /// <summary>
    /// The sections between two versions, newest first: released versions in (from, to] (only <paramref name="to"/> when
    /// <paramref name="from"/> is null), plus Unreleased first when <paramref name="to"/> is a pre-release. Empty sections are left out.
    /// </summary>
    public static IReadOnlyList<ChangelogRelease> Between(Changelog changelog, SemVer? from, SemVer to)
    {
        var list = new List<ChangelogRelease>();
        if (to.IsPrerelease && changelog.Unreleased is { IsEmpty: false } u) list.Add(u);
        foreach (var r in changelog.Released)
        {
            var v = r.Version!.Value;
            if (v > to || r.IsEmpty) continue;
            if (from is { } f ? v > f : v == to) list.Add(r);
        }
        return list;
    }

    /// <summary>For the "Show what's new" links: the current version's own section (or Unreleased for a pre-release), else the newest release.</summary>
    public static WhatsNewPlan ForCurrent(Changelog changelog, string currentVersion)
    {
        SemVer.TryParse(currentVersion, out var current);
        var releases = new List<ChangelogRelease>();
        if (current.IsPrerelease && changelog.Unreleased is { IsEmpty: false } u) releases.Add(u);
        if (releases.Count == 0 && changelog.Find(current.Core) is { IsEmpty: false } own && !current.IsPrerelease) releases.Add(own);
        if (releases.Count == 0 && changelog.LatestRelease is { } latest) releases.Add(latest);
        if (releases.Count == 0) return WhatsNewPlan.None(remember: false);
        return new WhatsNewPlan(true, false, TitleFor(current, releases), releases, releases[0].IsUnreleased);
    }

    private static string TitleFor(SemVer current, IReadOnlyList<ChangelogRelease> releases) =>
        releases[0].IsUnreleased ? PrereleaseTitle : $"What's new in NetSpider {releases[0].Version}";
}
