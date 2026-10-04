using System.Globalization;
using System.Text.RegularExpressions;

namespace NetSpider.Core.Changelog;

/// <summary>Result of <see cref="ChangelogParser.ParseWithDiagnostics"/>: a best-effort model plus every rule violation.</summary>
public sealed record ChangelogParseResult(Changelog Changelog, IReadOnlyList<ChangelogError> Errors)
{
    public bool IsValid => Errors.Count == 0;
}

/// <summary>
/// Parses CHANGELOG.md in the strict NetSpider format (CHANGELOG-GUIDELINES.md):
/// <code>
/// # Changelog
/// (free text)
/// ## [Unreleased]
/// ### New
/// - A user-facing sentence. (#123)
/// ## [1.0.0] - 2026-10-05
/// ### Fixed
/// - ...
/// [1.0.0]: https://...   (optional link references at the end)
/// </code>
/// Parsing never throws: it returns what it could read plus line-numbered errors (used by <see cref="ChangelogValidator"/>).
/// </summary>
public static partial class ChangelogParser
{
    public const string Title = "# Changelog";
    public const string UnreleasedHeading = "## [Unreleased]";
    private static readonly string CategoryList = string.Join(", ", ChangelogCategories.All.Select(c => c.DisplayName()));

    /// <summary>Parses leniently (errors are ignored). Use <see cref="ParseWithDiagnostics"/> or <see cref="ChangelogValidator"/> to check the format.</summary>
    public static Changelog Parse(string text) => ParseWithDiagnostics(text).Changelog;

    /// <summary>True when the text is a valid changelog.</summary>
    public static bool TryParse(string? text, out Changelog changelog)
    {
        var r = ParseWithDiagnostics(text ?? "");
        changelog = r.Changelog;
        return r.IsValid;
    }

    public static ChangelogParseResult ParseWithDiagnostics(string text)
    {
        var p = new State();
        var lines = SplitLines(text);
        bool sawTitle = false, inLinkRefs = false;

        for (int i = 0; i < lines.Length; i++)
        {
            int ln = i + 1;
            string raw = lines[i];
            string line = raw.TrimEnd();
            if (line.Length == 0) continue;

            // ---- the title must come first ----
            if (!sawTitle)
            {
                sawTitle = true;
                if (line != Title)
                {
                    p.Error(ln, $"The changelog must start with '{Title}'.");
                    if (!line.StartsWith("## ", StringComparison.Ordinal)) continue; // treat it as the title line
                }
                else continue;
            }

            // ---- link references at the bottom ----
            if (LinkRefRx().IsMatch(line))
            {
                p.CloseRelease();
                inLinkRefs = true;
                continue;
            }
            if (inLinkRefs)
            {
                p.Error(ln, "Only link references ('[1.0.0]: https://…') may follow the link references at the end of the file.");
                continue;
            }

            // ---- headings ----
            if (line.StartsWith('#'))
            {
                if (line.StartsWith("### ", StringComparison.Ordinal) && !line.StartsWith("#### ", StringComparison.Ordinal)) { p.Category(ln, line[4..].Trim()); continue; }
                if (line.StartsWith("## ", StringComparison.Ordinal)) { p.ReleaseHeading(ln, line); continue; }
                if (line == Title) { p.Error(ln, $"'{Title}' may only appear once, at the top."); continue; }
                if (HeadingRx().IsMatch(line))
                {
                    p.Error(ln, p.Release is null
                        ? "Headings other than '# Changelog' are not allowed before '## [Unreleased]'."
                        : "Unexpected heading: only '## [version] - date' and the fixed '### Category' headings are allowed.");
                    continue;
                }
            }

            if (p.Release is null) continue; // preamble: free text

            // ---- entries ----
            if (line.StartsWith("- ", StringComparison.Ordinal) || line == "-") { p.Entry(ln, line); continue; }
            if (NestedBulletRx().IsMatch(raw)) { p.Error(ln, "Nested bullets are not allowed: write one change per top-level '- ' line."); continue; }
            if (line.StartsWith("* ", StringComparison.Ordinal) || line.StartsWith("+ ", StringComparison.Ordinal))
            {
                p.Error(ln, "Use '- ' for entries (not '*' or '+').");
                continue;
            }
            if (char.IsWhiteSpace(raw[0]))
            {
                p.Error(ln, "Entries must fit on one line: continuation lines are not allowed.");
                continue;
            }
            p.Error(ln, "Unexpected text: inside a release every line must be a '### Category' heading or a '- ' entry.");
        }

        if (!sawTitle) p.Error(1, $"The changelog is empty: it must start with '{Title}' followed by '{UnreleasedHeading}'.");
        p.CloseRelease();
        if (sawTitle && !p.SawUnreleased && !p.ReportedNotFirst) p.Error(Math.Max(1, p.FirstReleaseLine), $"Missing '{UnreleasedHeading}': it must be the first section.");

        p.Errors.Sort((a, b) => a.Line.CompareTo(b.Line));
        return new ChangelogParseResult(new Changelog(p.Releases), p.Errors);
    }

    internal static string[] SplitLines(string text) => text.TrimStart('﻿').Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

    /// <summary>Validates one entry line (without parsing context); returns the entry or an error message.</summary>
    public static (ChangelogEntry? Entry, string? Error) ParseEntry(string line, int lineNumber = 0)
    {
        if (line.TrimEnd() == "-") return (null, "Empty entry.");
        if (!line.StartsWith("- ", StringComparison.Ordinal)) return (null, "Entries start with '- '.");
        var body = line[2..].TrimEnd();
        if (body.Length == 0 || string.IsNullOrWhiteSpace(body)) return (null, "Empty entry.");
        if (char.IsWhiteSpace(body[0])) return (null, "Exactly one space after '-'.");
        if (PrBeforePeriodRx().IsMatch(body)) return (null, "Put the PR reference after the period: '- Sentence. (#123)'.");
        int? pr = null;
        var m = PrSuffixRx().Match(body);
        if (m.Success)
        {
            pr = int.Parse(m.Groups["pr"].Value, CultureInfo.InvariantCulture);
            body = body[..m.Index];
        }
        else if (body.Contains("(#", StringComparison.Ordinal) && LoosePrRx().IsMatch(body))
            return (null, "The PR reference must be the last thing on the line, written as ' (#123)'.");
        if (body.Length == 0) return (null, "Empty entry.");
        if (char.IsLower(body[0])) return (null, "Start the entry with a capital letter: it's a sentence.");
        if (!body.EndsWith('.')) return (null, "End the entry with a period.");
        if (body.EndsWith("..", StringComparison.Ordinal) && !body.EndsWith("...", StringComparison.Ordinal)) return (null, "The entry ends with two periods.");
        if (body.Length < 8) return (null, "The entry is too short to tell users what changed.");
        return (new ChangelogEntry(body, pr, lineNumber), null);
    }

    // =====================================================================================================

    private sealed class State
    {
        public readonly List<ChangelogRelease> Releases = [];
        public readonly List<ChangelogError> Errors = [];
        public bool SawUnreleased;
        public bool ReportedNotFirst;
        public int FirstReleaseLine;
        private readonly HashSet<SemVer> _versions = [];
        private SemVer? _lastVersion;
        private DateOnly? _lastDate;
        private bool _firstChecked;

        // the release being read
        public ReleaseBuilder? Release;
        private SectionBuilder? _section;

        public void Error(int line, string message) => Errors.Add(new ChangelogError(line, message));

        public void ReleaseHeading(int ln, string line)
        {
            CloseRelease();
            if (FirstReleaseLine == 0) FirstReleaseLine = ln;

            if (line == UnreleasedHeading)
            {
                if (SawUnreleased) Error(ln, $"Duplicate '{UnreleasedHeading}'.");
                else if (Releases.Count > 0 || _firstChecked) Error(ln, $"'{UnreleasedHeading}' must be the first section.");
                SawUnreleased = true;
                _firstChecked = true;
                Release = new ReleaseBuilder(null, null, ln);
                return;
            }

            if (UnreleasedLooseRx().IsMatch(line))
            {
                Error(ln, $"Write the unreleased section exactly as '{UnreleasedHeading}' (no date, no other text).");
                SawUnreleased = true;
                _firstChecked = true;
                Release = new ReleaseBuilder(null, null, ln, ignored: true);
                return;
            }
            var m = ReleaseHeadingRx().Match(line);
            if (!m.Success)
            {
                Error(ln, "Malformed release heading: expected '## [1.2.3] - YYYY-MM-DD' (or '## [Unreleased]').");
                Release = new ReleaseBuilder(null, null, ln, ignored: true);
                return;
            }
            if (!_firstChecked)
            {
                _firstChecked = true;
                ReportedNotFirst = true;
                Error(ln, $"'{UnreleasedHeading}' must be the first section (add it above this release).");
            }

            string vText = m.Groups["v"].Value, dText = m.Groups["d"].Value;
            SemVer? version = null;
            if (!SemVer.TryParse(vText, out var v) || vText.StartsWith('v') || v.Build is not null)
                Error(ln, $"'{vText}' is not a version: use X.Y.Z, e.g. '## [1.2.0] - 2026-10-05'.");
            else if (v.IsPrerelease)
                Error(ln, $"'{vText}' is a pre-release: pre-releases never get their own section; they are built from '{UnreleasedHeading}'.");
            else version = v;

            DateOnly? date = null;
            if (!DateRx().IsMatch(dText) || !DateOnly.TryParseExact(dText, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                Error(ln, $"Invalid date '{dText}': use YYYY-MM-DD, e.g. 2026-10-05.");
            else date = d;

            if (version is { } ver)
            {
                if (!_versions.Add(ver)) Error(ln, $"Duplicate version {ver}.");
                else if (_lastVersion is { } prev && ver >= prev)
                    Error(ln, $"Versions must be in descending order (newest first): {ver} comes after {prev}.");
                else if (date is { } dd && _lastDate is { } prevDate && dd > prevDate)
                    Error(ln, $"Release {ver} is dated {dd:yyyy-MM-dd}, after the newer release {_lastVersion} ({prevDate:yyyy-MM-dd}).");
                _lastVersion = ver;
                if (date is not null) _lastDate = date;
            }
            Release = new ReleaseBuilder(version, date, ln, ignored: version is null);
        }

        public void Category(int ln, string name)
        {
            if (Release is null)
            {
                Error(ln, $"'### {name}' must be inside a release ('{UnreleasedHeading}' or '## [x.y.z] - date').");
                return;
            }
            CloseSection();
            if (!ChangelogCategories.TryParseHeading(name, out var cat))
            {
                var hint = ChangelogCategories.Suggest(name) is { } s ? $" Did you mean '### {s.DisplayName()}'?" : "";
                Error(ln, $"Unknown category '### {name}'. Allowed, in this order: {CategoryList}.{hint}");
                Release.HasUnknownCategory = true;
                _section = new SectionBuilder(null, ln);
                return;
            }
            if (Release.Seen.Contains(cat))
                Error(ln, $"Duplicate category '### {name}' in {Release.Title}.");
            else if (Release.Seen.Count > 0 && Release.Seen[^1] > cat)
                Error(ln, $"'### {name}' must come before '### {Release.Seen[^1].DisplayName()}'. Order: {CategoryList}.");
            Release.Seen.Add(cat);
            _section = new SectionBuilder(cat, ln);
        }

        public void Entry(int ln, string line)
        {
            if (Release is null) return;
            if (_section is null)
            {
                Error(ln, "Entry outside a category: put it under one of " + string.Join(", ", ChangelogCategories.All.Select(c => "'### " + c.DisplayName() + "'")) + ".");
                return;
            }
            var (entry, error) = ParseEntry(line, ln);
            if (error is not null) { Error(ln, error); _section.Count++; return; }
            _section.Entries.Add(entry!);
            _section.Count++;
        }

        private void CloseSection()
        {
            if (_section is null || Release is null) return;
            if (_section.Count == 0)
                Error(_section.Line, _section.Category is { } c
                    ? $"Empty category '### {c.DisplayName()}': add an entry or remove the heading."
                    : "Empty category: add an entry or remove the heading.");
            if (_section.Category is { } cat && _section.Entries.Count > 0 && Release.Sections.All(s => s.Category != cat))
                Release.Sections.Add(new ChangelogSection(cat, _section.Entries.ToArray(), _section.Line));
            _section = null;
        }

        public void CloseRelease()
        {
            if (Release is null) return;
            CloseSection();
            var r = Release;
            Release = null;
            if (r.Ignored) return;
            if (r.Version is { } v && r.Seen.Count == 0 && !r.HasUnknownCategory)
                Error(r.Line, $"Release {v} has no entries.");
            Releases.Add(new ChangelogRelease(r.Version, r.Date, r.Sections.ToArray(), r.Line));
        }
    }

    private sealed class ReleaseBuilder(SemVer? version, DateOnly? date, int line, bool ignored = false)
    {
        public SemVer? Version { get; } = version;
        public DateOnly? Date { get; } = date;
        public int Line { get; } = line;
        public bool Ignored { get; } = ignored;
        public List<ChangelogSection> Sections { get; } = [];
        /// <summary>Valid category headings in file order (also empty or malformed ones), for the order/duplicate checks.</summary>
        public List<ChangelogCategory> Seen { get; } = [];
        public bool HasUnknownCategory { get; set; }
        public string Title => Version?.ToString() ?? "[Unreleased]";
    }

    private sealed class SectionBuilder(ChangelogCategory? category, int line)
    {
        public ChangelogCategory? Category { get; } = category;
        public int Line { get; } = line;
        public List<ChangelogEntry> Entries { get; } = [];
        /// <summary>Entry lines seen (valid or not), so a heading with only malformed entries isn't also reported as empty.</summary>
        public int Count { get; set; }
    }

    [GeneratedRegex(@"^## \[(?<v>[^\]]+)\] - (?<d>\S+)$")] private static partial Regex ReleaseHeadingRx();
    [GeneratedRegex(@"^##\s*\[?unreleased\]?", RegexOptions.IgnoreCase)] private static partial Regex UnreleasedLooseRx();
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$")] private static partial Regex DateRx();
    [GeneratedRegex(@"^#{1,6}(\s|$)")] private static partial Regex HeadingRx();
    [GeneratedRegex(@"^\[[^\]]+\]:\s*\S+")] private static partial Regex LinkRefRx();
    [GeneratedRegex(@"^\s+([-*+]|\d+[.)])\s")] private static partial Regex NestedBulletRx();
    [GeneratedRegex(@" \(#(?<pr>[1-9]\d*)\)$")] private static partial Regex PrSuffixRx();
    [GeneratedRegex(@"\(#\d+\)\.$")] private static partial Regex PrBeforePeriodRx();
    [GeneratedRegex(@"\(#\d+\)")] private static partial Regex LoosePrRx();
}
