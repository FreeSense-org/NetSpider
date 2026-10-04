namespace NetSpider.Core.Changelog;

/// <summary>Text-preserving edits of CHANGELOG.md (the file keeps its intro, spacing and link references).</summary>
public static class ChangelogEditor
{
    /// <summary>
    /// Moves the Unreleased entries into a new <c>## [version] - date</c> section right below an empty
    /// <c>## [Unreleased]</c>. Throws <see cref="InvalidOperationException"/> when the changelog is invalid, Unreleased
    /// is empty, the version is a pre-release, already exists or isn't newer than the latest release.
    /// </summary>
    public static string Release(string text, SemVer version, DateOnly date)
    {
        var parsed = ChangelogParser.ParseWithDiagnostics(text);
        if (!parsed.IsValid)
            throw new InvalidOperationException("CHANGELOG.md is invalid:\n" + string.Join("\n", parsed.Errors.Select(e => "  " + e)));
        if (version.IsPrerelease || version.Build is not null)
            throw new InvalidOperationException($"{version} is not a release version (X.Y.Z): pre-releases never get a changelog section.");
        var log = parsed.Changelog;
        var unreleased = log.Unreleased!;
        if (unreleased.IsEmpty) throw new InvalidOperationException("[Unreleased] is empty: there is nothing to release.");
        if (log.Find(version) is not null) throw new InvalidOperationException($"## [{version}] already exists.");
        if (log.LatestRelease is { Version: { } latest } && version <= latest)
            throw new InvalidOperationException($"{version} is not newer than the latest release {latest}.");
        if (log.LatestRelease is { Date: { } latestDate } && date < latestDate)
            throw new InvalidOperationException($"{date:yyyy-MM-dd} is before the latest release date {latestDate:yyyy-MM-dd}.");

        string nl = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var lines = ChangelogParser.SplitLines(text).ToList();
        int head = unreleased.Line - 1;
        // the Unreleased body runs to the next "## " heading, the first link reference, or the end of the file
        int end = head + 1;
        while (end < lines.Count && !lines[end].StartsWith("## ", StringComparison.Ordinal) && !IsLinkRef(lines[end])) end++;
        var body = lines.GetRange(head + 1, end - head - 1);
        while (body.Count > 0 && body[0].Trim().Length == 0) body.RemoveAt(0);
        while (body.Count > 0 && body[^1].Trim().Length == 0) body.RemoveAt(body.Count - 1);

        var replacement = new List<string> { ChangelogParser.UnreleasedHeading, "", $"## [{version}] - {date:yyyy-MM-dd}", "" };
        replacement.AddRange(body);
        replacement.Add("");
        lines.RemoveRange(head, end - head);
        lines.InsertRange(head, replacement);

        // keep exactly one trailing newline
        while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
        var result = string.Join(nl, lines) + nl;

        var check = ChangelogParser.ParseWithDiagnostics(result);
        if (!check.IsValid)
            throw new InvalidOperationException("Internal error: the released changelog is invalid:\n" + string.Join("\n", check.Errors.Select(e => "  " + e)));
        return result;
    }

    /// <summary>Unreleased entries in <paramref name="head"/> that are new or changed compared with <paramref name="baseLog"/>.</summary>
    public static IReadOnlyList<(ChangelogCategory Category, ChangelogEntry Entry)> NewUnreleasedEntries(Changelog? baseLog, Changelog head)
    {
        var before = new HashSet<(ChangelogCategory, string)>();
        if (baseLog?.Unreleased is { } bu)
            foreach (var s in bu.Sections)
                foreach (var e in s.Entries) before.Add((s.Category, e.Markdown));
        var result = new List<(ChangelogCategory, ChangelogEntry)>();
        if (head.Unreleased is { } hu)
            foreach (var s in hu.Sections)
                foreach (var e in s.Entries)
                    if (!before.Contains((s.Category, e.Markdown))) result.Add((s.Category, e));
        return result;
    }

    /// <summary>Released versions in <paramref name="baseLog"/> that were changed or removed in <paramref name="head"/> (released sections are frozen).</summary>
    public static IReadOnlyList<SemVer> ChangedReleases(Changelog? baseLog, Changelog head)
    {
        if (baseLog is null) return [];
        var changed = new List<SemVer>();
        foreach (var r in baseLog.Released)
        {
            var h = head.Find(r.Version!.Value);
            if (h is null || h.Date != r.Date || ChangelogMarkdown.ReleaseNotes(h) != ChangelogMarkdown.ReleaseNotes(r)) changed.Add(r.Version.Value);
        }
        return changed;
    }

    private static bool IsLinkRef(string line) => line.StartsWith('[') && line.Contains("]:", StringComparison.Ordinal);
}
