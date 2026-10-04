namespace NetSpider.Core.Changelog;

/// <summary>A parsed CHANGELOG.md: <c>## [Unreleased]</c> first, then the released versions, newest first.</summary>
public sealed class Changelog
{
    public Changelog(IReadOnlyList<ChangelogRelease> releases) => Releases = releases;

    /// <summary>All sections in file order (Unreleased first in a valid file).</summary>
    public IReadOnlyList<ChangelogRelease> Releases { get; }

    /// <summary>The <c>## [Unreleased]</c> section, or null if the file has none.</summary>
    public ChangelogRelease? Unreleased => Releases.FirstOrDefault(r => r.IsUnreleased);

    /// <summary>Released versions, newest first.</summary>
    public IEnumerable<ChangelogRelease> Released => Releases.Where(r => !r.IsUnreleased).OrderByDescending(r => r.Version!.Value);

    /// <summary>The newest released version, or null.</summary>
    public ChangelogRelease? LatestRelease => Released.FirstOrDefault();

    public ChangelogRelease? Find(SemVer version) => Releases.FirstOrDefault(r => r.Version is { } v && v == version);

    public static Changelog Empty { get; } = new([]);
}

/// <summary>One <c>## [x.y.z] - date</c> section, or <c>## [Unreleased]</c> (<see cref="Version"/> null).</summary>
public sealed class ChangelogRelease
{
    public ChangelogRelease(SemVer? version, DateOnly? date, IReadOnlyList<ChangelogSection> sections, int line = 0)
    {
        Version = version;
        Date = date;
        Sections = sections;
        Line = line;
    }

    public SemVer? Version { get; }
    public DateOnly? Date { get; }
    /// <summary>Category sections in file order.</summary>
    public IReadOnlyList<ChangelogSection> Sections { get; }
    /// <summary>1-based line of the heading (0 when not parsed from a file).</summary>
    public int Line { get; }

    public bool IsUnreleased => Version is null;
    public string Title => Version?.ToString() ?? "Unreleased";
    public int EntryCount => Sections.Sum(s => s.Entries.Count);
    public bool IsEmpty => EntryCount == 0;
    public IEnumerable<ChangelogEntry> Entries => Sections.SelectMany(s => s.Entries);

    public ChangelogSection? this[ChangelogCategory category] => Sections.FirstOrDefault(s => s.Category == category);
    public int Count(ChangelogCategory category) => this[category]?.Entries.Count ?? 0;
    public bool Has(ChangelogCategory category) => Count(category) > 0;
}

/// <summary>A <c>### Category</c> block with its entries.</summary>
public sealed class ChangelogSection
{
    public ChangelogSection(ChangelogCategory category, IReadOnlyList<ChangelogEntry> entries, int line = 0)
    {
        Category = category;
        Entries = entries;
        Line = line;
    }

    public ChangelogCategory Category { get; }
    public IReadOnlyList<ChangelogEntry> Entries { get; }
    public int Line { get; }
}

/// <summary>One <c>- sentence. (#123)</c> line: the sentence and the optional pull request number.</summary>
public sealed record ChangelogEntry(string Text, int? PullRequest = null, int Line = 0)
{
    /// <summary>The entry as written in the changelog, without the leading "- ".</summary>
    public string Markdown => PullRequest is { } pr ? $"{Text} (#{pr})" : Text;
}

/// <summary>A validation problem at a 1-based line of the changelog.</summary>
public sealed record ChangelogError(int Line, string Message)
{
    public override string ToString() => $"line {Line}: {Message}";
}
