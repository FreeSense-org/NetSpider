using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class WhatsNewTests
{
    private static readonly NetSpider.Core.Changelog.Changelog Log = Parse(Valid); // Unreleased (2), 1.1.0, 1.0.1, 1.0.0

    [Fact]
    public void First_install_only_remembers_the_version()
    {
        var plan = WhatsNew.Plan(Log, null, "1.1.0", firstRun: true);
        Assert.False(plan.Show);
        Assert.True(plan.RememberVersion);
    }

    [Fact]
    public void Update_shows_every_release_since_the_last_seen_version()
    {
        var plan = WhatsNew.Plan(Log, "1.0.0", "1.1.0", firstRun: false);
        Assert.True(plan.Show);
        Assert.True(plan.RememberVersion);
        Assert.Equal(["1.1.0", "1.0.1"], plan.Releases.Select(r => r.Title));
        Assert.Equal("What's new in NetSpider 1.1.0", plan.Title);
        Assert.False(plan.IsPrerelease);
    }

    [Fact]
    public void Same_version_shows_nothing_and_stores_nothing()
    {
        var plan = WhatsNew.Plan(Log, "1.1.0", "1.1.0", firstRun: false);
        Assert.False(plan.Show);
        Assert.False(plan.RememberVersion);
    }

    [Fact]
    public void Downgrade_shows_nothing_but_remembers()
    {
        var plan = WhatsNew.Plan(Log, "1.1.0", "1.0.1", firstRun: false);
        Assert.False(plan.Show);
        Assert.True(plan.RememberVersion);
    }

    [Fact]
    public void Prerelease_build_shows_unreleased()
    {
        var plan = WhatsNew.Plan(Log, "1.1.0", "1.2.0-pre.4", firstRun: false);
        Assert.True(plan.Show);
        Assert.True(plan.IsPrerelease);
        Assert.Equal(WhatsNew.PrereleaseTitle, plan.Title);
        Assert.True(plan.Releases.Single().IsUnreleased);
    }

    [Fact]
    public void Prerelease_after_an_older_version_also_lists_the_releases_in_between()
    {
        var plan = WhatsNew.Plan(Log, "1.0.0", "1.2.0-pre.4", firstRun: false);
        Assert.Equal(["Unreleased", "1.1.0", "1.0.1"], plan.Releases.Select(r => r.Title));
    }

    [Fact]
    public void Prerelease_to_release_shows_the_release()
    {
        var plan = WhatsNew.Plan(Log, "1.1.0-pre.9", "1.1.0", firstRun: false);
        Assert.Equal(["1.1.0"], plan.Releases.Select(r => r.Title));
    }

    [Fact]
    public void Existing_install_without_a_last_seen_version_sees_the_current_release()
    {
        var plan = WhatsNew.Plan(Log, null, "1.1.0", firstRun: false);
        Assert.True(plan.Show);
        Assert.Equal(["1.1.0"], plan.Releases.Select(r => r.Title));
    }

    [Fact]
    public void Nothing_in_the_changelog_for_the_range_shows_nothing()
    {
        var plan = WhatsNew.Plan(Log, "1.1.0", "1.1.1", firstRun: false);
        Assert.False(plan.Show);
        Assert.True(plan.RememberVersion);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("1.2")]
    public void Unreadable_last_seen_version_is_replaced(string lastSeen)
    {
        var plan = WhatsNew.Plan(Log, lastSeen, "1.1.0", firstRun: false);
        Assert.False(plan.Show);
        Assert.True(plan.RememberVersion);
    }

    [Fact]
    public void Unreadable_current_version_does_nothing()
    {
        var plan = WhatsNew.Plan(Log, "1.0.0", "dev", firstRun: false);
        Assert.False(plan.Show);
        Assert.False(plan.RememberVersion);
    }

    [Fact]
    public void For_current_prefers_own_section_then_unreleased_then_latest()
    {
        Assert.Equal("1.0.1", WhatsNew.ForCurrent(Log, "1.0.1").Releases.Single().Title);
        Assert.True(WhatsNew.ForCurrent(Log, "1.2.0-pre.1").Releases.Single().IsUnreleased);
        Assert.True(WhatsNew.ForCurrent(Log, "1.0.0-alpha.0.3").Releases.Single().IsUnreleased);
        Assert.Equal("1.1.0", WhatsNew.ForCurrent(Log, "1.5.0").Releases.Single().Title); // no own section: the newest release
        var noUnreleased = Parse(With(""));
        Assert.Equal("1.0.0", WhatsNew.ForCurrent(noUnreleased, "1.0.1-pre.2").Releases.Single().Title);
        Assert.False(WhatsNew.ForCurrent(noUnreleased, "1.0.0").RememberVersion);
    }
}
