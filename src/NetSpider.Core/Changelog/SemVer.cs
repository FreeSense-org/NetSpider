using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.RegularExpressions;

namespace NetSpider.Core.Changelog;

/// <summary>
/// Minimal SemVer 2.0 version (major.minor.patch[-prerelease][+build]) with SemVer precedence rules. Used by the
/// changelog tooling (version computation) and the app (what's new). Build metadata is kept but ignored for ordering.
/// </summary>
public readonly partial record struct SemVer(int Major, int Minor, int Patch, string? Prerelease = null, string? Build = null) : IComparable<SemVer>
{
    /// <summary>True for a version with a pre-release suffix (1.2.0-pre.3).</summary>
    public bool IsPrerelease => !string.IsNullOrEmpty(Prerelease);

    /// <summary>The version without pre-release and build metadata.</summary>
    public SemVer Core => new(Major, Minor, Patch);

    public SemVer NextMajor() => new(Major + 1, 0, 0);
    public SemVer NextMinor() => new(Major, Minor + 1, 0);
    public SemVer NextPatch() => new(Major, Minor, Patch + 1);
    public SemVer WithPrerelease(string? prerelease) => new(Major, Minor, Patch, string.IsNullOrEmpty(prerelease) ? null : prerelease);

    public static SemVer Parse(string text) =>
        TryParse(text, out var v) ? v : throw new FormatException($"'{text}' is not a SemVer version (e.g. 1.2.3 or 1.2.3-pre.1).");

    /// <summary>Parses "1.2.3", "v1.2.3", "1.2.3-pre.1" and "1.2.3+abc"; surrounding whitespace is ignored.</summary>
    public static bool TryParse([NotNullWhen(true)] string? text, out SemVer version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var m = SemVerRx().Match(text.Trim());
        if (!m.Success) return false;
        if (!int.TryParse(m.Groups["major"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int major) ||
            !int.TryParse(m.Groups["minor"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int minor) ||
            !int.TryParse(m.Groups["patch"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int patch)) return false;
        string? pre = m.Groups["pre"].Success ? m.Groups["pre"].Value : null;
        string? build = m.Groups["build"].Success ? m.Groups["build"].Value : null;
        // numeric pre-release identifiers must not have leading zeros (SemVer 2.0 §9)
        if (pre is not null && pre.Split('.').Any(id => id.Length > 1 && id[0] == '0' && id.All(char.IsAsciiDigit))) return false;
        version = new SemVer(major, minor, patch, pre, build);
        return true;
    }

    public int CompareTo(SemVer other)
    {
        int c = Major.CompareTo(other.Major);
        if (c != 0) return c;
        c = Minor.CompareTo(other.Minor);
        if (c != 0) return c;
        c = Patch.CompareTo(other.Patch);
        if (c != 0) return c;
        // a version without pre-release has higher precedence than one with (1.0.0-pre.1 < 1.0.0)
        if (!IsPrerelease) return other.IsPrerelease ? 1 : 0;
        if (!other.IsPrerelease) return -1;
        var a = Prerelease!.Split('.');
        var b = other.Prerelease!.Split('.');
        for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
        {
            bool an = long.TryParse(a[i], NumberStyles.None, CultureInfo.InvariantCulture, out long ai);
            bool bn = long.TryParse(b[i], NumberStyles.None, CultureInfo.InvariantCulture, out long bi);
            c = (an, bn) switch
            {
                (true, true) => ai.CompareTo(bi),
                (true, false) => -1, // numeric identifiers sort before alphanumeric ones
                (false, true) => 1,
                _ => string.CompareOrdinal(a[i], b[i]),
            };
            if (c != 0) return c;
        }
        return a.Length.CompareTo(b.Length);
    }

    /// <summary>Equality follows precedence (build metadata is ignored).</summary>
    public bool Equals(SemVer other) => CompareTo(other) == 0;
    public override int GetHashCode() => HashCode.Combine(Major, Minor, Patch, Prerelease ?? "");

    public static bool operator <(SemVer a, SemVer b) => a.CompareTo(b) < 0;
    public static bool operator >(SemVer a, SemVer b) => a.CompareTo(b) > 0;
    public static bool operator <=(SemVer a, SemVer b) => a.CompareTo(b) <= 0;
    public static bool operator >=(SemVer a, SemVer b) => a.CompareTo(b) >= 0;

    public override string ToString() =>
        $"{Major}.{Minor}.{Patch}" + (IsPrerelease ? "-" + Prerelease : "") + (string.IsNullOrEmpty(Build) ? "" : "+" + Build);

    [GeneratedRegex(@"^v?(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")]
    private static partial Regex SemVerRx();
}
