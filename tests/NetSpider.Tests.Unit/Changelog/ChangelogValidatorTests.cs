using NetSpider.Core.Changelog;
using static NetSpider.Tests.Unit.ChangelogSpec.ChangelogTestKit;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class ChangelogValidatorTests
{
    [Fact]
    public void Valid_changelog_has_no_errors() => Assert.Empty(Errors(Valid));

    // ---------------------------------------------------------------------------------------------- structure

    [Fact]
    public void Requires_the_title_first() =>
        SingleError("# Change log\n\n## [Unreleased]\n", 1, "must start with '# Changelog'");

    [Fact]
    public void Empty_file_is_an_error() => SingleError("", 1, "empty");

    [Fact]
    public void Requires_an_unreleased_section() =>
        SingleError("# Changelog\n\n## [1.0.0] - 2026-10-05\n### New\n- First public release of the app.\n", 3, "must be the first section");

    [Fact]
    public void Unreleased_must_come_first()
    {
        var errors = Errors("# Changelog\n\n## [1.0.0] - 2026-10-05\n### New\n- First public release of the app.\n\n## [Unreleased]\n");
        Assert.Equal([3, 7], errors.Select(e => e.Line));
        Assert.All(errors, e => Assert.Contains("must be the first section", e.Message));
    }

    [Fact]
    public void Duplicate_unreleased_is_an_error() =>
        SingleError("# Changelog\n## [Unreleased]\n## [Unreleased]\n", 3, "Duplicate");

    [Theory]
    [InlineData("## [Unreleased] - 2026-10-05")]
    [InlineData("## Unreleased")]
    [InlineData("## [unreleased]")]
    public void Unreleased_heading_must_be_exact(string heading) =>
        SingleError($"# Changelog\n\n{heading}\n", 3, "exactly as '## [Unreleased]'");

    [Theory]
    [InlineData("## [1.0.0]", "Malformed release heading")]
    [InlineData("## 1.0.0 - 2026-10-05", "Malformed release heading")]
    [InlineData("## [1.0.0] – 2026-10-05", "Malformed release heading")]          // en dash
    [InlineData("## [1.0] - 2026-10-05", "is not a version")]
    [InlineData("## [v1.0.0] - 2026-10-05", "is not a version")]
    [InlineData("## [1.0.0-pre.1] - 2026-10-05", "pre-release")]
    [InlineData("## [1.0.0] - 2026-02-30", "Invalid date")]
    [InlineData("## [1.0.0] - 05.10.2026", "Invalid date")]
    [InlineData("## [1.0.0] - 2026-1-5", "Invalid date")]
    public void Release_headings_are_checked(string heading, string fragment) =>
        Assert.Contains(Errors($"# Changelog\n\n## [Unreleased]\n\n{heading}\n### New\n- First public release of the app.\n"),
            e => e.Line == 5 && e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void Duplicate_versions_are_errors() =>
        SingleError("# Changelog\n## [Unreleased]\n## [1.0.0] - 2026-10-05\n### New\n- First public release of the app.\n## [1.0.0] - 2026-10-05\n### Fixed\n- Second section with the same version.\n",
            6, "Duplicate version 1.0.0");

    [Fact]
    public void Versions_must_descend() =>
        SingleError("# Changelog\n## [Unreleased]\n## [1.0.0] - 2026-10-05\n### New\n- First public release of the app.\n## [1.1.0] - 2026-10-06\n### Fixed\n- A later version below an older one.\n",
            6, "descending order");

    [Fact]
    public void Dates_must_not_go_backwards() =>
        SingleError("# Changelog\n## [Unreleased]\n## [1.1.0] - 2026-10-01\n### New\n- A newer release dated earlier.\n## [1.0.0] - 2026-10-05\n### New\n- First public release of the app.\n",
            6, "after the newer release");

    [Fact]
    public void Released_section_needs_entries() =>
        SingleError("# Changelog\n## [Unreleased]\n## [1.0.0] - 2026-10-05\n", 3, "has no entries");

    [Fact]
    public void Link_references_must_be_last() =>
        SingleError(With("") + "\n[1.0.0]: https://example.org/v1.0.0\n## [0.9.0] - 2026-01-01\n", 11, "Only link references");

    // ---------------------------------------------------------------------------------------------- categories

    [Theory]
    [InlineData("Added", "Did you mean '### New'")]
    [InlineData("Changed", "Did you mean '### Improved'")]
    [InlineData("Bug fixes", "Did you mean '### Fixed'")]
    [InlineData("new", "Did you mean '### New'")]
    [InlineData("Misc", "Allowed, in this order")]
    public void Unknown_categories_are_rejected_with_a_hint(string name, string fragment) =>
        SingleError(With($"### {name}\n- Something changed here."), 4, fragment);

    [Fact]
    public void Categories_must_follow_the_fixed_order() =>
        SingleError(With("### Fixed\n- A bug was fixed today.\n### New\n- A new thing was added."), 6, "'### New' must come before '### Fixed'");

    [Fact]
    public void All_categories_in_order_are_valid()
    {
        var body = string.Join("\n", ChangelogCategories.All.Select(c => $"### {c.DisplayName()}\n- An entry for {c.DisplayName()}."));
        Assert.Empty(Errors(With(body)));
    }

    [Fact]
    public void Duplicate_categories_are_rejected() =>
        SingleError(With("### New\n- First new thing here.\n### New\n- Second new thing here."), 6, "Duplicate category");

    [Fact]
    public void Empty_categories_are_rejected() =>
        SingleError(With("### New\n\n### Fixed\n- A bug was fixed today."), 4, "Empty category '### New'");

    [Fact]
    public void Category_outside_a_release_is_rejected() =>
        SingleError("# Changelog\n### New\n- Something.\n## [Unreleased]\n", 2, "must be inside a release");

    [Fact]
    public void Deeper_headings_are_rejected() =>
        SingleError(With("### New\n- A new thing was added.\n#### Details"), 6, "Unexpected heading");

    // ---------------------------------------------------------------------------------------------- entries

    [Theory]
    [InlineData("- lowercase start of the entry.", "capital letter")]
    [InlineData("- Missing the final period", "period")]
    [InlineData("- Reference before the period (#12).", "after the period")]
    [InlineData("- Reference in (#12) the middle.", "last thing on the line")]
    [InlineData("- Two periods at the end..", "two periods")]
    [InlineData("- Short.", "too short")]
    [InlineData("-  Two spaces after the dash.", "one space")]
    [InlineData("-", "Empty entry")]
    [InlineData("* Star bullet entry here.", "Use '- '")]
    [InlineData("+ Plus bullet entry here.", "Use '- '")]
    [InlineData("  - Nested bullet entry here.", "Nested bullets")]
    [InlineData("    continuation of the line above.", "continuation")]
    [InlineData("Free text paragraph.", "Unexpected text")]
    [InlineData("1. Numbered entry here.", "Unexpected text")]
    public void Malformed_entries_are_rejected(string line, string fragment) =>
        Assert.Contains(Errors(With($"### New\n- A valid first entry here.\n{line}")),
            e => e.Line == 6 && e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    [Theory]
    [InlineData("- The `--demo` switch starts a simulated network.")]
    [InlineData("- Wi-Fi scans work on ARM64 laptops. (#123)")]
    [InlineData("- 802.1X ports are shown with their state.")]
    [InlineData("- \"Copy diagnostics\" includes the Npcap version.")]
    [InlineData("- Ellipses are fine at the end...")]
    public void Well_formed_entries_are_accepted(string line) => Assert.Empty(Errors(With($"### Improved\n{line}")));

    [Fact]
    public void Entry_outside_a_category_is_rejected() =>
        SingleError(With("- An entry without a category."), 4, "outside a category");

    [Fact]
    public void Entry_with_only_malformed_lines_is_not_also_reported_as_empty() =>
        SingleError(With("### Fixed\n- missing capital and period"), 5, "capital letter");

    [Fact]
    public void Github_annotations_escape_messages()
    {
        var lines = ChangelogValidator.ToGitHubAnnotations([new ChangelogError(7, "100% wrong\nreally")], "CHANGELOG.md").ToList();
        Assert.Equal("::error file=CHANGELOG.md,line=7::100%25 wrong%0Areally", lines.Single());
    }
}
