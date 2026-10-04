using System.Text;

namespace NetSpider.Core.Changelog;

/// <summary>
/// Release notes as markdown (what Velopack ships as the update's notes and the GitHub release body), and the reverse:
/// reading such notes back into categories for the app's update dialog.
/// </summary>
public static class ChangelogMarkdown
{
    /// <summary>
    /// <code>
    /// ### New
    /// - Sentence. (#12)
    ///
    /// ### Fixed
    /// - Sentence.
    /// </code>
    /// Empty string for an empty release.
    /// </summary>
    public static string ReleaseNotes(ChangelogRelease release)
    {
        var sb = new StringBuilder();
        foreach (var s in release.Sections.Where(s => s.Entries.Count > 0).OrderBy(s => s.Category.SortOrder()))
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append("### ").Append(s.Category.DisplayName()).Append('\n');
            foreach (var e in s.Entries) sb.Append("- ").Append(e.Markdown).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>
    /// Reads release notes produced by <see cref="ReleaseNotes"/>. Lines before the first <c>###</c> heading (a title or an
    /// intro paragraph) are ignored. Returns null when the notes aren't in this format (unknown category, free text after
    /// the first category, no entries), so the caller can fall back to plain markdown rendering.
    /// </summary>
    public static ChangelogRelease? ParseNotes(string? markdown, SemVer? version = null)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return null;
        var sections = new List<ChangelogSection>();
        ChangelogCategory? current = null;
        var entries = new List<ChangelogEntry>();

        void Flush()
        {
            if (current is { } c && entries.Count > 0)
            {
                var existing = sections.FindIndex(s => s.Category == c);
                if (existing >= 0) sections[existing] = new ChangelogSection(c, sections[existing].Entries.Concat(entries).ToArray());
                else sections.Add(new ChangelogSection(c, entries.ToArray()));
            }
            entries = [];
        }

        foreach (var raw in ChangelogParser.SplitLines(markdown))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("### ", StringComparison.Ordinal))
            {
                Flush();
                if (!ChangelogCategories.TryParseHeading(line[4..].Trim(), out var cat)) return null;
                current = cat;
                continue;
            }
            if (current is null) continue; // preamble
            if (!line.StartsWith("- ", StringComparison.Ordinal)) return null;
            var (entry, _) = ChangelogParser.ParseEntry(line);
            // be lenient with style here (it's display only): keep the text even if it breaks a writing rule
            entries.Add(entry ?? new ChangelogEntry(line[2..].Trim()));
        }
        Flush();
        if (sections.Count == 0) return null;
        return new ChangelogRelease(version, null, sections.OrderBy(s => s.Category.SortOrder()).ToArray());
    }

    /// <summary>"2 new · 3 fixed · 1 security" (category order; empty categories left out).</summary>
    public static string Summary(ChangelogRelease release) => Summary([release]);

    /// <summary>Counts summed over several releases.</summary>
    public static string Summary(IEnumerable<ChangelogRelease> releases)
    {
        var list = releases.ToList();
        var parts = ChangelogCategories.All
            .Select(c => (c, n: list.Sum(r => r.Count(c))))
            .Where(x => x.n > 0)
            .Select(x => $"{x.n} {x.c.SummaryWord()}");
        return string.Join(" · ", parts);
    }
}
