namespace NetSpider.Core.Changelog;

/// <summary>
/// The fixed changelog categories, in the order they must appear in a release (see CHANGELOG-GUIDELINES.md).
/// The numeric value is the sort order.
/// </summary>
public enum ChangelogCategory
{
    /// <summary>Something that worked before needs action from the user. Triggers a major version.</summary>
    Breaking = 0,
    /// <summary>A new feature. Triggers a minor version.</summary>
    New = 1,
    /// <summary>An existing feature works better (faster, clearer, more accurate). Patch.</summary>
    Improved = 2,
    /// <summary>A bug fix. Patch.</summary>
    Fixed = 3,
    /// <summary>A security fix or hardening. Patch.</summary>
    Security = 4,
    /// <summary>A feature or option was removed. Patch (a removal that breaks a workflow is Breaking).</summary>
    Removed = 5,
    /// <summary>A feature still works but will be removed later. Patch.</summary>
    Deprecated = 6,
}

/// <summary>Display metadata for <see cref="ChangelogCategory"/> (heading, icon, badge text, summary word).</summary>
public static class ChangelogCategories
{
    /// <summary>All categories in their required order.</summary>
    public static IReadOnlyList<ChangelogCategory> All { get; } = Enum.GetValues<ChangelogCategory>().OrderBy(c => (int)c).ToArray();

    /// <summary>The heading text used in CHANGELOG.md (<c>### New</c>) and the badge label.</summary>
    public static string DisplayName(this ChangelogCategory c) => c switch
    {
        ChangelogCategory.Breaking => "Breaking",
        ChangelogCategory.New => "New",
        ChangelogCategory.Improved => "Improved",
        ChangelogCategory.Fixed => "Fixed",
        ChangelogCategory.Security => "Security",
        ChangelogCategory.Removed => "Removed",
        ChangelogCategory.Deprecated => "Deprecated",
        _ => c.ToString(),
    };

    /// <summary>Key of the icon the app draws on the category badge (<c>ChangelogIcon.&lt;key&gt;</c> in the theme).</summary>
    public static string IconKey(this ChangelogCategory c) => c switch
    {
        ChangelogCategory.Breaking => "warning",
        ChangelogCategory.New => "sparkles",
        ChangelogCategory.Improved => "arrow-up",
        ChangelogCategory.Fixed => "bug",
        ChangelogCategory.Security => "shield",
        ChangelogCategory.Removed => "minus",
        ChangelogCategory.Deprecated => "clock",
        _ => "dot",
    };

    /// <summary>A plain-text symbol for terminals and plain-text contexts.</summary>
    public static string Symbol(this ChangelogCategory c) => c switch
    {
        ChangelogCategory.Breaking => "⚠",
        ChangelogCategory.New => "✨",
        ChangelogCategory.Improved => "⬆",
        ChangelogCategory.Fixed => "🐛",
        ChangelogCategory.Security => "🛡",
        ChangelogCategory.Removed => "−",
        ChangelogCategory.Deprecated => "⏳",
        _ => "•",
    };

    public static int SortOrder(this ChangelogCategory c) => (int)c;

    /// <summary>Lower-case word for summary lines: "2 new · 3 fixed · 1 security".</summary>
    public static string SummaryWord(this ChangelogCategory c) => c.DisplayName().ToLowerInvariant();

    /// <summary>Exact, case-sensitive heading match ("New", not "new" or "Added").</summary>
    public static bool TryParseHeading(string? name, out ChangelogCategory category)
    {
        foreach (var c in All)
            if (string.Equals(c.DisplayName(), name, StringComparison.Ordinal)) { category = c; return true; }
        category = default;
        return false;
    }

    /// <summary>The category a common Keep-a-Changelog/other name maps to, for a helpful validation hint.</summary>
    public static ChangelogCategory? Suggest(string? name)
    {
        var n = name?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(n)) return null;
        foreach (var c in All)
            if (c.DisplayName().Equals(n, StringComparison.OrdinalIgnoreCase)) return c;
        return n switch
        {
            "added" or "features" or "feature" or "new features" => ChangelogCategory.New,
            "changed" or "changes" or "improvements" or "improvement" or "enhancements" or "performance" => ChangelogCategory.Improved,
            "fixes" or "fix" or "bug fixes" or "bugfixes" or "bugs" => ChangelogCategory.Fixed,
            "breaking changes" or "breaking change" => ChangelogCategory.Breaking,
            "deleted" => ChangelogCategory.Removed,
            "security fixes" => ChangelogCategory.Security,
            _ => null,
        };
    }
}
