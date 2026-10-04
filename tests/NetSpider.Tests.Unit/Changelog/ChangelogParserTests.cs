using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class ChangelogParserTests
{
    [Fact]
    public void Parses_releases_sections_and_entries()
    {
        var log = Parse(Valid);
        Assert.Equal(4, log.Releases.Count);
        Assert.True(log.Releases[0].IsUnreleased);
        Assert.Equal(["1.1.0", "1.0.1", "1.0.0"], log.Released.Select(r => r.Title));
        Assert.Equal(new DateOnly(2026, 11, 2), log.LatestRelease!.Date);

        var u = log.Unreleased!;
        Assert.Equal([ChangelogCategory.New, ChangelogCategory.Fixed], u.Sections.Select(s => s.Category));
        var svg = u[ChangelogCategory.New]!.Entries.Single();
        Assert.Equal("The spider web can be exported as SVG.", svg.Text);
        Assert.Equal(42, svg.PullRequest);
        Assert.Equal("The spider web can be exported as SVG. (#42)", svg.Markdown);
        Assert.Equal(8, svg.Line);
        Assert.Null(u[ChangelogCategory.Fixed]!.Entries.Single().PullRequest);
        Assert.Equal(2, u.EntryCount);
    }

    [Fact]
    public void Records_line_numbers()
    {
        var log = Parse(Valid);
        Assert.Equal(5, log.Unreleased!.Line);
        Assert.Equal(13, log.Find(SemVer.Parse("1.1.0"))!.Line);
        Assert.Equal(15, log.Find(SemVer.Parse("1.1.0"))![ChangelogCategory.New]!.Line);
    }

    [Fact]
    public void Empty_unreleased_is_valid()
    {
        var log = Parse(With(""));
        Assert.True(log.Unreleased!.IsEmpty);
        Assert.Single(log.Released);
    }

    [Fact]
    public void Handles_crlf_bom_and_trailing_whitespace()
    {
        var text = "﻿" + Valid.Replace("\n", "   \r\n");
        var log = Parse(text);
        Assert.Equal(2, log.Unreleased!.EntryCount);
    }

    [Fact]
    public void Link_references_at_the_end_are_allowed()
    {
        var log = Parse(With("") + "\n\n[Unreleased]: https://github.com/FreeSense-org/NetSpider/compare/v1.0.0...HEAD\n[1.0.0]: https://github.com/FreeSense-org/NetSpider/releases/tag/v1.0.0\n");
        Assert.Single(log.Released);
    }

    [Fact]
    public void Lenient_parse_returns_what_it_could_read()
    {
        var log = ChangelogParser.Parse("# Changelog\n## [Unreleased]\n### New\n- lowercase entry\n- A good entry here.\n");
        Assert.Equal("A good entry here.", log.Unreleased!.Entries.Single().Text);
        Assert.False(ChangelogParser.TryParse("# Changelog\n## [Unreleased]\n### New\n- lowercase entry\n", out _));
    }

    [Fact]
    public void Repository_changelog_is_valid()
    {
        var path = FindRepoFile("CHANGELOG.md");
        var errors = ChangelogValidator.Validate(File.ReadAllText(path));
        Assert.True(errors.Count == 0, "CHANGELOG.md is invalid:\n" + string.Join("\n", errors));
        var log = ChangelogParser.Parse(File.ReadAllText(path));
        Assert.NotNull(log.Find(new SemVer(1, 0, 0)));
    }

    internal static string FindRepoFile(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var p = Path.Combine(dir.FullName, name);
            if (File.Exists(p) && File.Exists(Path.Combine(dir.FullName, "NetworkScan.slnx"))) return p;
        }
        throw new FileNotFoundException(name + " not found above " + AppContext.BaseDirectory);
    }
}
