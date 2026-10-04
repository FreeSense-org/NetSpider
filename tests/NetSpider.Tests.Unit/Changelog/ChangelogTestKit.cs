using NetSpider.Core.Changelog;

namespace NetSpider.Tests.Unit.ChangelogSpec;

internal static class ChangelogTestKit
{
    /// <summary>A valid changelog with Unreleased content and three releases.</summary>
    public static readonly string Valid = """
        # Changelog

        Intro paragraph with **markdown** and a [link](https://example.org).

        ## [Unreleased]

        ### New
        - The spider web can be exported as SVG. (#42)

        ### Fixed
        - The Devices list no longer flickers while sorting.

        ## [1.1.0] - 2026-11-02

        ### New
        - Storm Center shows a per-port breakdown.

        ### Security
        - The probe agent rejects unsigned reports.

        ## [1.0.1] - 2026-10-20

        ### Fixed
        - The update dialog no longer freezes on slow networks. (#7)

        ## [1.0.0] - 2026-10-05

        ### New
        - First public release with discovery, Path Doctor and Storm Center.
        """.Replace("\r\n", "\n"); // raw literals take the source file's line endings (CRLF on Windows checkouts)

    public static Changelog Parse(string text)
    {
        var r = ChangelogParser.ParseWithDiagnostics(text);
        Assert.True(r.IsValid, "expected a valid changelog, got:\n" + string.Join("\n", r.Errors));
        return r.Changelog;
    }

    public static IReadOnlyList<ChangelogError> Errors(string text) => ChangelogValidator.Validate(text);

    /// <summary>Asserts exactly one error, at <paramref name="line"/>, whose message contains <paramref name="fragment"/>.</summary>
    public static void SingleError(string text, int line, string fragment)
    {
        var errors = Errors(text);
        Assert.True(errors.Count == 1, $"expected 1 error, got {errors.Count}:\n" + string.Join("\n", errors));
        Assert.Equal(line, errors[0].Line);
        Assert.Contains(fragment, errors[0].Message, StringComparison.OrdinalIgnoreCase);
    }

    public static ChangelogRelease Unreleased(params (ChangelogCategory Category, string Text)[] entries) =>
        new(null, null, entries.GroupBy(e => e.Category).OrderBy(g => g.Key)
            .Select(g => new ChangelogSection(g.Key, g.Select(e => new ChangelogEntry(e.Text)).ToArray())).ToArray());

    /// <summary>Wraps sections in a minimal valid changelog: title, Unreleased (with <paramref name="unreleased"/>), then 1.0.0.</summary>
    public static string With(string unreleased) => $"""
        # Changelog

        ## [Unreleased]
        {unreleased}

        ## [1.0.0] - 2026-10-05

        ### New
        - First public release of the app.
        """.Replace("\r\n", "\n");
}
