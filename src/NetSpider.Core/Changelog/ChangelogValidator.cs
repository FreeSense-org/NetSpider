namespace NetSpider.Core.Changelog;

/// <summary>
/// Checks CHANGELOG.md against the strict format in CHANGELOG-GUIDELINES.md and returns line-numbered errors:
/// title, <c>## [Unreleased]</c> first, release heading syntax, X.Y.Z versions (no pre-releases), YYYY-MM-DD dates,
/// duplicate or non-descending versions, dates going backwards, unknown/duplicate/out-of-order categories, empty
/// categories and releases, malformed or nested entries and stray text. An empty <c>## [Unreleased]</c> is valid.
/// </summary>
public static class ChangelogValidator
{
    public static IReadOnlyList<ChangelogError> Validate(string text) => ChangelogParser.ParseWithDiagnostics(text).Errors;

    public static bool IsValid(string text) => Validate(text).Count == 0;

    /// <summary>One GitHub Actions annotation per error: <c>::error file=CHANGELOG.md,line=12::message</c>.</summary>
    public static IEnumerable<string> ToGitHubAnnotations(IEnumerable<ChangelogError> errors, string file) =>
        errors.Select(e => $"::error file={file},line={e.Line}::{Escape(e.Message)}");

    // GitHub workflow commands: '%', CR and LF must be escaped in the message.
    private static string Escape(string s) => s.Replace("%", "%25").Replace("\r", "%0D").Replace("\n", "%0A");
}
