using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class ChangelogVersioningTests
{
    private static SemVer V(string s) => SemVer.Parse(s);

    [Theory]
    [InlineData(ChangelogCategory.Breaking, "2.0.0")]
    [InlineData(ChangelogCategory.New, "1.5.0")]
    [InlineData(ChangelogCategory.Improved, "1.4.3")]
    [InlineData(ChangelogCategory.Fixed, "1.4.3")]
    [InlineData(ChangelogCategory.Security, "1.4.3")]
    [InlineData(ChangelogCategory.Removed, "1.4.3")]
    [InlineData(ChangelogCategory.Deprecated, "1.4.3")]
    public void Each_category_bumps_as_documented(ChangelogCategory category, string expected) =>
        Assert.Equal(V(expected), ChangelogVersioning.NextVersion(V("1.4.2"), Unreleased((category, "Some change happened."))));

    [Fact]
    public void Highest_bump_wins()
    {
        var u = Unreleased((ChangelogCategory.Fixed, "A fix."), (ChangelogCategory.New, "A feature."), (ChangelogCategory.Security, "A hardening."));
        Assert.Equal(VersionBump.Minor, ChangelogVersioning.BumpFor(u));
        Assert.Equal(V("1.3.0"), ChangelogVersioning.NextVersion(V("1.2.9"), u));
        var b = Unreleased((ChangelogCategory.Breaking, "A break."), (ChangelogCategory.New, "A feature."));
        Assert.Equal(V("2.0.0"), ChangelogVersioning.NextVersion(V("1.9.4"), b));
    }

    [Fact]
    public void Empty_unreleased_means_no_release()
    {
        Assert.Equal(VersionBump.None, ChangelogVersioning.BumpFor(Unreleased()));
        Assert.Null(ChangelogVersioning.NextVersion(V("1.0.0"), Unreleased()));
        Assert.Null(ChangelogVersioning.NextVersion(null, null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0.1.0")]
    [InlineData("0.9.3")]
    public void No_1x_release_yet_means_1_0_0(string? last)
    {
        SemVer? lastV = last is null ? null : V(last);
        Assert.Equal(V("1.0.0"), ChangelogVersioning.NextVersion(lastV, Unreleased((ChangelogCategory.Fixed, "A fix."))));
        Assert.Equal(V("1.0.0"), ChangelogVersioning.NextVersion(lastV, Unreleased((ChangelogCategory.Breaking, "A break."))));
    }

    [Fact]
    public void Prerelease_as_last_release_is_rejected() =>
        Assert.Throws<ArgumentException>(() => ChangelogVersioning.NextVersion(V("1.1.0-pre.2"), Unreleased((ChangelogCategory.Fixed, "A fix."))));

    [Fact]
    public void Latest_release_tag_ignores_prereleases_and_junk() =>
        Assert.Equal(V("1.10.0"), ChangelogVersioning.LatestReleaseTag(["v1.2.0", "v1.10.0", "v1.11.0-pre.4", "v2.0", "release-3.0.0", "1.12.0", "v0.1.0"]));

    [Fact]
    public void Latest_release_tag_is_null_without_tags() => Assert.Null(ChangelogVersioning.LatestReleaseTag([]));

    // ---------------------------------------------------------------------------------------------- release plans

    [Fact]
    public void Plan_bumps_from_the_last_tag()
    {
        var log = Parse(Valid); // Unreleased: New + Fixed; latest section 1.1.0
        var plan = ChangelogVersioning.PlanRelease(log, V("1.1.0"));
        Assert.Equal(ReleasePlanKind.NewRelease, plan.Kind);
        Assert.Equal(V("1.2.0"), plan.Version);
        Assert.Null(plan.Warning);
    }

    [Fact]
    public void Plan_publishes_an_untagged_written_section_when_unreleased_is_empty()
    {
        // the seeded changelog: 1.0.0 is written, the only tag is the old v0.1.0
        var log = Parse(With(""));
        var plan = ChangelogVersioning.PlanRelease(log, V("0.1.0"));
        Assert.Equal(ReleasePlanKind.PendingSection, plan.Kind);
        Assert.Equal(V("1.0.0"), plan.Version);
        Assert.Equal(ReleasePlanKind.PendingSection, ChangelogVersioning.PlanRelease(log, null).Kind);
    }

    [Fact]
    public void Plan_uses_an_untagged_section_as_the_base_and_warns()
    {
        var log = Parse(With("### Fixed\n- A bug was fixed today."));
        var plan = ChangelogVersioning.PlanRelease(log, null);
        Assert.Equal(ReleasePlanKind.NewRelease, plan.Kind);
        Assert.Equal(V("1.0.1"), plan.Version);
        Assert.NotNull(plan.Warning);
    }

    [Fact]
    public void Plan_does_nothing_when_everything_is_released()
    {
        var plan = ChangelogVersioning.PlanRelease(Parse(With("")), V("1.0.0"));
        Assert.Equal(ReleasePlanKind.Nothing, plan.Kind);
        Assert.Null(plan.Version);
    }

    [Fact]
    public void Plan_without_any_release_or_tag_is_1_0_0()
    {
        var log = Parse("# Changelog\n\n## [Unreleased]\n### Improved\n- Something got better today.\n");
        Assert.Equal(V("1.0.0"), ChangelogVersioning.PlanRelease(log, null).Version);
    }

    // ---------------------------------------------------------------------------------------------- pre-releases

    [Fact]
    public void Prerelease_is_next_version_plus_commit_count()
    {
        var log = Parse(Valid);
        Assert.Equal("1.2.0-pre.7", ChangelogVersioning.PrereleaseVersion(log, V("1.1.0"), 7).ToString());
    }

    [Fact]
    public void Prerelease_with_empty_unreleased_is_next_patch()
    {
        var log = Parse(With(""));
        Assert.Equal("1.0.1-pre.3", ChangelogVersioning.PrereleaseVersion(log, V("1.0.0"), 3).ToString());
        Assert.Equal("1.0.1-pre.0", ChangelogVersioning.PrereleaseVersion(log, V("0.1.0"), 0).ToString()); // untagged 1.0.0 counts
    }

    [Fact]
    public void Prerelease_sorts_before_its_release_and_after_the_previous_one()
    {
        var log = Parse(Valid);
        var pre = ChangelogVersioning.PrereleaseVersion(log, V("1.1.0"), 12);
        Assert.True(pre > V("1.1.0"));
        Assert.True(pre < ChangelogVersioning.PlanRelease(log, V("1.1.0")).Version!.Value);
        Assert.True(ChangelogVersioning.PrereleaseVersion(log, V("1.1.0"), 9) < pre);
    }

    [Fact]
    public void Prerelease_rejects_negative_counts() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => ChangelogVersioning.PrereleaseVersion(Parse(Valid), null, -1));
}
