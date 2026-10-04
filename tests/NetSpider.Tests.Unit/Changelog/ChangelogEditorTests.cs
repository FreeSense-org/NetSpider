using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class ChangelogEditorTests
{
    private static readonly DateOnly Day = new(2026, 12, 1);

    [Fact]
    public void Release_moves_unreleased_into_a_dated_section()
    {
        var text = ChangelogEditor.Release(Valid, SemVer.Parse("1.2.0"), Day);
        var log = Parse(text);
        Assert.True(log.Unreleased!.IsEmpty);
        var r = log.LatestRelease!;
        Assert.Equal("1.2.0", r.Title);
        Assert.Equal(Day, r.Date);
        Assert.Equal(2, r.EntryCount);
        Assert.Equal(42, r[ChangelogCategory.New]!.Entries.Single().PullRequest);
        // everything else is untouched
        Assert.StartsWith("# Changelog\n\nIntro paragraph with **markdown**", text);
        Assert.Contains("## [Unreleased]\n\n## [1.2.0] - 2026-12-01\n\n### New\n", text);
        Assert.EndsWith("- First public release with discovery, Path Doctor and Storm Center.\n", text);
        Assert.Equal(4, log.Released.Count());
    }

    [Fact]
    public void Release_keeps_crlf_and_link_references()
    {
        var src = With("### Fixed\n- A bug was fixed today.").Replace("\r\n", "\n").Replace("\n", "\r\n") + "\r\n\r\n[1.0.0]: https://example.org/v1.0.0\r\n";
        var text = ChangelogEditor.Release(src, SemVer.Parse("1.0.1"), Day);
        Assert.DoesNotContain("\n", text.Replace("\r\n", ""));
        Assert.EndsWith("[1.0.0]: https://example.org/v1.0.0\r\n", text);
        Assert.Equal("1.0.1", Parse(text).LatestRelease!.Title);
    }

    [Theory]
    [InlineData("1.1.0", "already exists")]
    [InlineData("1.0.5", "not newer")]
    [InlineData("1.3.0-pre.1", "not a release version")]
    public void Release_rejects_bad_versions(string version, string fragment)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ChangelogEditor.Release(Valid, SemVer.Parse(version), Day));
        Assert.Contains(fragment, ex.Message);
    }

    [Fact]
    public void Release_rejects_an_empty_unreleased() =>
        Assert.Contains("nothing to release", Assert.Throws<InvalidOperationException>(() => ChangelogEditor.Release(With(""), SemVer.Parse("1.0.1"), Day)).Message);

    [Fact]
    public void Release_rejects_an_invalid_changelog() =>
        Assert.Contains("invalid", Assert.Throws<InvalidOperationException>(() => ChangelogEditor.Release(With("### Added\n- Nope here."), SemVer.Parse("1.0.1"), Day)).Message);

    [Fact]
    public void Release_rejects_a_date_before_the_latest_release() =>
        Assert.Contains("before the latest release date", Assert.Throws<InvalidOperationException>(() =>
            ChangelogEditor.Release(Valid, SemVer.Parse("1.2.0"), new DateOnly(2026, 1, 1))).Message);

    // ---------------------------------------------------------------------------------------------- PR checks

    [Fact]
    public void New_entries_are_detected()
    {
        var baseLog = Parse(With("### Fixed\n- An old fix is waiting here."));
        var head = Parse(With("### New\n- A new feature was added.\n### Fixed\n- An old fix is waiting here."));
        var added = ChangelogEditor.NewUnreleasedEntries(baseLog, head);
        Assert.Equal(ChangelogCategory.New, added.Single().Category);
    }

    [Fact]
    public void Changed_entries_count_as_new_but_removals_do_not()
    {
        var baseLog = Parse(With("### Fixed\n- An old fix is waiting here.\n- Another fix is waiting here."));
        Assert.Single(ChangelogEditor.NewUnreleasedEntries(baseLog, Parse(With("### Fixed\n- An old fix is waiting here, reworded.\n- Another fix is waiting here."))));
        Assert.Empty(ChangelogEditor.NewUnreleasedEntries(baseLog, Parse(With("### Fixed\n- Another fix is waiting here."))));
        Assert.Empty(ChangelogEditor.NewUnreleasedEntries(baseLog, baseLog));
        // moving an entry to another category is a change
        Assert.Single(ChangelogEditor.NewUnreleasedEntries(baseLog, Parse(With("### Improved\n- An old fix is waiting here.\n### Fixed\n- Another fix is waiting here."))));
    }

    [Fact]
    public void Every_entry_is_new_when_the_base_has_no_changelog() =>
        Assert.Equal(2, ChangelogEditor.NewUnreleasedEntries(null, Parse(Valid)).Count);

    [Fact]
    public void Edited_released_sections_are_detected()
    {
        var baseLog = Parse(Valid);
        Assert.Empty(ChangelogEditor.ChangedReleases(baseLog, baseLog));
        Assert.Empty(ChangelogEditor.ChangedReleases(baseLog, Parse(ChangelogEditor.Release(Valid, SemVer.Parse("1.2.0"), Day))));
        var edited = Parse(Valid.Replace("rejects unsigned reports", "rejects unsigned and stale reports"));
        Assert.Equal([SemVer.Parse("1.1.0")], ChangelogEditor.ChangedReleases(baseLog, edited));
        var redated = Parse(Valid.Replace("## [1.0.1] - 2026-10-20", "## [1.0.1] - 2026-10-21"));
        Assert.Equal([SemVer.Parse("1.0.1")], ChangelogEditor.ChangedReleases(baseLog, redated));
    }
}
