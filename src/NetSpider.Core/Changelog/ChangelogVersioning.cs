namespace NetSpider.Core.Changelog;

/// <summary>How much the next version moves, decided by the Unreleased categories.</summary>
public enum VersionBump { None, Patch, Minor, Major }

/// <summary>What a release run should do.</summary>
public enum ReleasePlanKind
{
    /// <summary>Unreleased is empty and every written release is tagged: nothing to release.</summary>
    Nothing,
    /// <summary>Move Unreleased into a new <c>## [version]</c> section (the normal release PR).</summary>
    NewRelease,
    /// <summary>A <c>## [version]</c> section is already written but was never tagged (e.g. the seeded 1.0.0): tag and publish it as-is.</summary>
    PendingSection,
}

public sealed record ReleasePlan(ReleasePlanKind Kind, SemVer? Version, SemVer? Base, string Reason, string? Warning = null);

/// <summary>
/// Automatic versions from the changelog. The last release (tag or written section) plus the Unreleased categories decide
/// the next version: Breaking → major, New → minor, Improved/Fixed/Security/Removed/Deprecated → patch, empty → none.
/// There are no 0.x public releases: with no 1.x release yet, the first release is 1.0.0.
/// </summary>
public static class ChangelogVersioning
{
    public static readonly SemVer FirstRelease = new(1, 0, 0);

    public static VersionBump BumpFor(ChangelogRelease? unreleased)
    {
        if (unreleased is null || unreleased.IsEmpty) return VersionBump.None;
        if (unreleased.Has(ChangelogCategory.Breaking)) return VersionBump.Major;
        if (unreleased.Has(ChangelogCategory.New)) return VersionBump.Minor;
        return VersionBump.Patch;
    }

    /// <summary>
    /// The next release version after <paramref name="lastReleased"/> for the given Unreleased content, or null when
    /// Unreleased is empty. No previous release (or only 0.x) → 1.0.0. Breaking → major, New → minor, the rest → patch.
    /// </summary>
    public static SemVer? NextVersion(SemVer? lastReleased, ChangelogRelease? unreleased)
    {
        var bump = BumpFor(unreleased);
        if (bump == VersionBump.None) return null;
        return Apply(lastReleased, bump);
    }

    public static SemVer Apply(SemVer? lastReleased, VersionBump bump)
    {
        if (lastReleased is not { } last || last.Major < 1) return FirstRelease;
        if (last.IsPrerelease) throw new ArgumentException($"The last release must be a release version, not the pre-release {last}.", nameof(lastReleased));
        return bump switch
        {
            VersionBump.Major => last.NextMajor(),
            VersionBump.Minor => last.NextMinor(),
            VersionBump.Patch => last.NextPatch(),
            _ => last,
        };
    }

    /// <summary>
    /// The version the next release gets. The base is the newest of the last release tag and the newest written section.
    /// A written section newer than the last tag (never published) is released as-is when Unreleased is empty.
    /// </summary>
    public static ReleasePlan PlanRelease(Changelog changelog, SemVer? lastTag)
    {
        var unreleased = changelog.Unreleased;
        var logged = changelog.LatestRelease?.Version;
        if (logged is { } l && (lastTag is not { } t || l > t))
        {
            if (unreleased is null || unreleased.IsEmpty)
                return new ReleasePlan(ReleasePlanKind.PendingSection, l, lastTag,
                    $"## [{l}] is written but not tagged yet (last tag: {(lastTag is { } lt ? "v" + lt : "none")}): publish it as-is.");
            var next = NextVersion(l, unreleased)!.Value;
            return new ReleasePlan(ReleasePlanKind.NewRelease, next, l,
                $"{BumpFor(unreleased)} bump from {l} (newest written release).",
                $"## [{l}] was never tagged; it is used as the base version.");
        }
        var v = NextVersion(lastTag, unreleased);
        if (v is null) return new ReleasePlan(ReleasePlanKind.Nothing, null, lastTag, "[Unreleased] is empty: nothing to release.");
        string from = lastTag is { } b && b.Major >= 1 ? $"{BumpFor(unreleased)} bump from v{b}" : "first 1.x release";
        return new ReleasePlan(ReleasePlanKind.NewRelease, v, lastTag, from + ".");
    }

    /// <summary>
    /// Pre-release version <c>&lt;next&gt;-pre.&lt;n&gt;</c> where n = commits since the last release tag. With an empty
    /// Unreleased, next is the next patch of the base.
    /// </summary>
    public static SemVer PrereleaseVersion(Changelog changelog, SemVer? lastTag, int commitsSinceRelease)
    {
        if (commitsSinceRelease < 0) throw new ArgumentOutOfRangeException(nameof(commitsSinceRelease));
        var plan = PlanRelease(changelog, lastTag);
        SemVer next = plan.Kind switch
        {
            ReleasePlanKind.NewRelease => plan.Version!.Value,
            // nothing new (or only an untagged written section): the next patch after the newest known release
            _ => Apply(Max(lastTag, changelog.LatestRelease?.Version), VersionBump.Patch),
        };
        return next.WithPrerelease($"pre.{commitsSinceRelease}");
    }

    /// <summary>The newest stable version among tag names like "v1.2.3" (pre-release and malformed tags are ignored).</summary>
    public static SemVer? LatestReleaseTag(IEnumerable<string> tags)
    {
        SemVer? best = null;
        foreach (var tag in tags)
        {
            var t = tag.Trim();
            if (!t.StartsWith('v') || !SemVer.TryParse(t[1..], out var v) || v.IsPrerelease || v.Build is not null) continue;
            if (best is null || v > best.Value) best = v;
        }
        return best;
    }

    private static SemVer? Max(SemVer? a, SemVer? b) => a is null ? b : b is null ? a : a.Value >= b.Value ? a : b;
}
