using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class ChangelogMarkdownTests
{
    [Fact]
    public void Release_notes_are_category_headings_and_bullets()
    {
        var log = Parse(Valid);
        Assert.Equal("""
            ### New
            - The spider web can be exported as SVG. (#42)

            ### Fixed
            - The Devices list no longer flickers while sorting.

            """.Replace("\r\n", "\n"), ChangelogMarkdown.ReleaseNotes(log.Unreleased!));
        Assert.Equal("", ChangelogMarkdown.ReleaseNotes(Unreleased()));
    }

    [Fact]
    public void Notes_round_trip()
    {
        var log = Parse(Valid);
        foreach (var r in log.Releases)
        {
            var parsed = ChangelogMarkdown.ParseNotes(ChangelogMarkdown.ReleaseNotes(r), r.Version);
            Assert.NotNull(parsed);
            Assert.Equal(ChangelogMarkdown.ReleaseNotes(r), ChangelogMarkdown.ReleaseNotes(parsed!));
            Assert.Equal(r.Version, parsed!.Version);
        }
    }

    [Fact]
    public void Parse_notes_ignores_a_title_and_intro_and_keeps_pr_numbers()
    {
        var notes = "## FreeSense NetSpider 1.2.0\n\nIntro text.\n\n### Security\n- Hardened the agent protocol. (#9)\n### Fixed\n- A crash on exit is fixed.\n";
        var r = ChangelogMarkdown.ParseNotes(notes)!;
        Assert.Equal([ChangelogCategory.Fixed, ChangelogCategory.Security], r.Sections.Select(s => s.Category)); // sorted
        Assert.Equal(9, r[ChangelogCategory.Security]!.Entries.Single().PullRequest);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("## FreeSense NetSpider 1.2.0\n\nChanges since v1.1.0:\n\n- feat: something (abc1234)\n")] // old git-log notes
    [InlineData("### Added\n- Something.\n")]                                                       // unknown category
    [InlineData("### New\nFree text after a category.\n")]
    [InlineData("### New\n")]                                                                       // no entries
    public void Parse_notes_returns_null_for_other_formats(string? notes) => Assert.Null(ChangelogMarkdown.ParseNotes(notes));

    [Fact]
    public void Parse_notes_is_lenient_about_entry_style()
    {
        var r = ChangelogMarkdown.ParseNotes("### Fixed\n- lowercase without period\n")!;
        Assert.Equal("lowercase without period", r.Entries.Single().Text);
    }

    [Fact]
    public void Summary_counts_per_category_in_order()
    {
        var u = Unreleased((ChangelogCategory.Fixed, "A."), (ChangelogCategory.New, "B."), (ChangelogCategory.Fixed, "C."),
            (ChangelogCategory.Security, "D."), (ChangelogCategory.New, "E."), (ChangelogCategory.Fixed, "F."));
        Assert.Equal("2 new · 3 fixed · 1 security", ChangelogMarkdown.Summary(u));
        Assert.Equal("", ChangelogMarkdown.Summary(Unreleased()));
        var log = Parse(Valid);
        Assert.Equal("2 new · 1 fixed · 1 security", ChangelogMarkdown.Summary(log.Released));
    }

    [Fact]
    public void Category_metadata_is_complete_and_ordered()
    {
        Assert.Equal(["Breaking", "New", "Improved", "Fixed", "Security", "Removed", "Deprecated"], ChangelogCategories.All.Select(c => c.DisplayName()));
        Assert.Equal(Enumerable.Range(0, 7), ChangelogCategories.All.Select(c => c.SortOrder()));
        Assert.Equal(7, ChangelogCategories.All.Select(c => c.IconKey()).Distinct().Count());
        Assert.All(ChangelogCategories.All, c => Assert.False(string.IsNullOrEmpty(c.Symbol())));
        Assert.True(ChangelogCategories.TryParseHeading("Security", out var s) && s == ChangelogCategory.Security);
        Assert.False(ChangelogCategories.TryParseHeading("security", out _));
    }
}
