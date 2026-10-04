using System.Globalization;
using System.Text;
using NetSpider.Core.Changelog;
using NetSpider.Tools.ChangelogTool;

// CHANGELOG.md tool for CI and the release scripts. Same parser/validator as the app (NetSpider.Core.Changelog).
//
//   validate [path]                                  check the format; GitHub annotations + exit 1 on errors
//   check-pr --base <ref>                            fail unless [Unreleased] gained/changed an entry vs <ref> (and no released section changed)
//   next-version                                     next release version from the last vX.Y.Z tag + [Unreleased] (no tag → 1.0.0)
//   prerelease-version                               <next>-pre.<commits since the last release tag>
//   release --version X.Y.Z [--date YYYY-MM-DD]      move [Unreleased] into a new dated section
//   notes (--version X.Y.Z | --unreleased) [--out f] release-notes markdown for a section
//   info                                             key=value summary (for $GITHUB_OUTPUT)
//
// Common options: --file <CHANGELOG.md> (default: ./CHANGELOG.md, searched upwards), --last-tag <X.Y.Z|none> and
// --commits <n> (override git, for tests and dry runs).
// Exit codes: 0 ok · 1 invalid / check failed · 2 nothing to do (empty [Unreleased]) · 64 usage error.

Console.OutputEncoding = new UTF8Encoding(false);
try
{
    return Cli.Run(args);
}
catch (UsageException ex)
{
    Console.Error.WriteLine("error: " + ex.Message);
    Console.Error.WriteLine("usage: changelog <validate|check-pr|next-version|prerelease-version|release|notes|info> [options] (see tools/ChangelogTool/Program.cs)");
    return Cli.Usage;
}
catch (InvalidOperationException ex)
{
    Console.Error.WriteLine("error: " + ex.Message);
    return Cli.Failed;
}

internal sealed class UsageException(string message) : Exception(message);

internal static class Cli
{
    public const int Ok = 0, Failed = 1, NothingToDo = 2, Usage = 64;

    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help") throw new UsageException("no command given");
        var cmd = args[0];
        var opts = Options.Parse(args.Skip(1).ToArray());
        return cmd switch
        {
            "validate" => Validate(opts),
            "check-pr" => CheckPr(opts),
            "next-version" => NextVersion(opts),
            "prerelease-version" => PrereleaseVersion(opts),
            "release" => Release(opts),
            "notes" => Notes(opts),
            "info" => Info(opts),
            _ => throw new UsageException($"unknown command '{cmd}'"),
        };
    }

    // ------------------------------------------------------------------------------------------------ validate

    private static int Validate(Options o)
    {
        var path = o.ChangelogPath;
        var text = File.ReadAllText(path);
        var result = ChangelogParser.ParseWithDiagnostics(text);
        if (!result.IsValid)
        {
            foreach (var line in ChangelogValidator.ToGitHubAnnotations(result.Errors, o.DisplayPath)) Console.WriteLine(line);
            Console.Error.WriteLine($"{o.DisplayPath}: {result.Errors.Count} error(s). Format: CHANGELOG-GUIDELINES.md");
            return Failed;
        }
        var log = result.Changelog;
        Console.WriteLine($"{o.DisplayPath} is valid: {log.Released.Count()} release(s), {log.Unreleased?.EntryCount ?? 0} unreleased entr{((log.Unreleased?.EntryCount ?? 0) == 1 ? "y" : "ies")}.");
        return Ok;
    }

    private static Changelog LoadValid(Options o)
    {
        var text = File.ReadAllText(o.ChangelogPath);
        var result = ChangelogParser.ParseWithDiagnostics(text);
        if (result.IsValid) return result.Changelog;
        foreach (var line in ChangelogValidator.ToGitHubAnnotations(result.Errors, o.DisplayPath)) Console.Error.WriteLine(line);
        throw new InvalidOperationException($"{o.DisplayPath} is invalid ({result.Errors.Count} error(s)); run 'validate' for details.");
    }

    // ------------------------------------------------------------------------------------------------ check-pr

    private static int CheckPr(Options o)
    {
        var baseRef = o.Get("--base") ?? throw new UsageException("check-pr needs --base <ref> (e.g. origin/main)");
        var head = LoadValid(o);
        var baseText = Git.ShowFile(baseRef, o.ChangelogPath);
        Changelog? baseLog = baseText is null ? null : ChangelogParser.Parse(baseText);

        var changedReleases = ChangelogEditor.ChangedReleases(baseLog, head);
        var added = ChangelogEditor.NewUnreleasedEntries(baseLog, head);
        int line = head.Unreleased?.Line ?? 1;
        bool ok = true;

        if (changedReleases.Count > 0)
        {
            Console.WriteLine($"::error file={o.DisplayPath},line={line}::Released sections are frozen, but this PR changes {string.Join(", ", changedReleases)}. " +
                              "Add a new entry under [Unreleased] instead (see CHANGELOG-GUIDELINES.md).");
            ok = false;
        }
        if (added.Count == 0)
        {
            Console.WriteLine($"::error file={o.DisplayPath},line={line}::No changelog entry: add a user-facing line under '## [Unreleased]' " +
                              "(see CHANGELOG-GUIDELINES.md), or label the PR 'skip-changelog' if users won't notice the change (CI, docs, tests, refactoring).");
            ok = false;
        }
        else
        {
            Console.WriteLine($"New or changed [Unreleased] entries compared with {baseRef}:");
            foreach (var (cat, e) in added) Console.WriteLine($"  {cat.DisplayName(),-10} {e.Markdown}");
            var plan = ChangelogVersioning.BumpFor(head.Unreleased);
            Console.WriteLine($"[Unreleased] now means a {plan.ToString().ToLowerInvariant()} release.");
        }
        WriteStepSummary(ok
            ? "### Changelog\n" + string.Join("\n", added.Select(a => $"- **{a.Category.DisplayName()}**: {a.Entry.Markdown}")) + "\n"
            : "### Changelog\nNo new `[Unreleased]` entry (or a released section was edited). See CHANGELOG-GUIDELINES.md.\n");
        return ok ? Ok : Failed;
    }

    // ------------------------------------------------------------------------------------------------ versions

    private static (SemVer? Version, string? Tag) LastTag(Options o)
    {
        if (o.Get("--last-tag") is { } forced)
        {
            if (forced is "none" or "") return (null, null);
            var v = SemVer.TryParse(forced, out var fv) && !fv.IsPrerelease ? fv : throw new UsageException($"--last-tag '{forced}' is not X.Y.Z");
            return (v, "v" + v);
        }
        var latest = ChangelogVersioning.LatestReleaseTag(Git.TagsMergedIntoHead());
        return (latest, latest is { } l ? "v" + l : null);
    }

    private static int Commits(Options o, string? tag)
    {
        if (o.Get("--commits") is { } c)
            return int.TryParse(c, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : throw new UsageException("--commits needs a number");
        return Git.CommitsSince(tag);
    }

    private static int NextVersion(Options o)
    {
        var log = LoadValid(o);
        var (last, _) = LastTag(o);
        var plan = ChangelogVersioning.PlanRelease(log, last);
        if (plan.Warning is not null) Console.Error.WriteLine("warning: " + plan.Warning);
        Console.Error.WriteLine(plan.Reason);
        if (plan.Kind == ReleasePlanKind.Nothing) return NothingToDo;
        Console.WriteLine(plan.Version);
        return Ok;
    }

    private static int PrereleaseVersion(Options o)
    {
        var log = LoadValid(o);
        var (last, tag) = LastTag(o);
        var v = ChangelogVersioning.PrereleaseVersion(log, last, Commits(o, tag));
        if (log.Unreleased is null or { IsEmpty: true }) Console.Error.WriteLine("note: [Unreleased] is empty; using the next patch version.");
        Console.WriteLine(v);
        return Ok;
    }

    private static int Info(Options o)
    {
        var log = LoadValid(o);
        var (last, tag) = LastTag(o);
        var plan = ChangelogVersioning.PlanRelease(log, last);
        var pre = ChangelogVersioning.PrereleaseVersion(log, last, Commits(o, tag));
        Console.WriteLine($"last_tag={tag}");
        Console.WriteLine($"unreleased_entries={log.Unreleased?.EntryCount ?? 0}");
        Console.WriteLine($"bump={ChangelogVersioning.BumpFor(log.Unreleased).ToString().ToLowerInvariant()}");
        Console.WriteLine($"release_kind={plan.Kind switch { ReleasePlanKind.NewRelease => "new", ReleasePlanKind.PendingSection => "pending", _ => "none" }}");
        Console.WriteLine($"next_version={plan.Version}");
        Console.WriteLine($"prerelease_version={pre}");
        return Ok;
    }

    // ------------------------------------------------------------------------------------------------ release

    private static int Release(Options o)
    {
        var vText = o.Get("--version") ?? throw new UsageException("release needs --version X.Y.Z");
        if (!SemVer.TryParse(vText, out var version)) throw new UsageException($"'{vText}' is not a version");
        var date = DateOnly.FromDateTime(DateTime.UtcNow);
        if (o.Get("--date") is { } d && !DateOnly.TryParseExact(d, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out date))
            throw new UsageException($"--date '{d}' is not YYYY-MM-DD");
        var path = o.ChangelogPath;
        var text = File.ReadAllText(path);
        var updated = ChangelogEditor.Release(text, version, date);
        File.WriteAllText(path, updated, new UTF8Encoding(false));
        var section = ChangelogParser.Parse(updated).Find(version)!;
        Console.WriteLine($"Released {version} ({date:yyyy-MM-dd}) in {o.DisplayPath}: {ChangelogMarkdown.Summary(section)}.");
        return Ok;
    }

    // ------------------------------------------------------------------------------------------------ notes

    private static int Notes(Options o)
    {
        var log = LoadValid(o);
        ChangelogRelease? release;
        if (o.Has("--unreleased")) release = log.Unreleased;
        else if (o.Get("--version") is { } vText)
        {
            if (!SemVer.TryParse(vText, out var v)) throw new UsageException($"'{vText}' is not a version");
            release = log.Find(v) ?? throw new InvalidOperationException($"{o.DisplayPath} has no section ## [{v}].");
        }
        else throw new UsageException("notes needs --version X.Y.Z or --unreleased");

        if (release is null || release.IsEmpty)
        {
            Console.Error.WriteLine($"[{release?.Title ?? "Unreleased"}] has no entries: no release notes written.");
            return NothingToDo;
        }
        var md = ChangelogMarkdown.ReleaseNotes(release);
        if (o.Get("--out") is { } outFile)
        {
            var full = Path.GetFullPath(outFile);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, md, new UTF8Encoding(false));
            Console.Error.WriteLine($"Release notes for {release.Title} ({ChangelogMarkdown.Summary(release)}) written to {outFile}.");
        }
        else Console.Write(md);
        return Ok;
    }

    private static void WriteStepSummary(string markdown)
    {
        var file = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");
        if (string.IsNullOrEmpty(file)) return;
        try { File.AppendAllText(file, markdown + "\n"); } catch (IOException) { }
    }
}

/// <summary>Tiny option parser: "--name value", "--flag" and positional arguments.</summary>
internal sealed class Options
{
    private static readonly HashSet<string> Flags = ["--unreleased"];
    private static readonly HashSet<string> Valued = ["--file", "--base", "--version", "--date", "--out", "--last-tag", "--commits"];
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);
    private readonly List<string> _positional = [];

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (Flags.Contains(a)) o._flags.Add(a);
            else if (Valued.Contains(a))
            {
                if (i + 1 >= args.Length) throw new UsageException($"{a} needs a value");
                o._values[a] = args[++i];
            }
            else if (a.StartsWith("--", StringComparison.Ordinal)) throw new UsageException($"unknown option '{a}'");
            else o._positional.Add(a);
        }
        if (o._positional.Count > 1) throw new UsageException("too many arguments: " + string.Join(' ', o._positional));
        return o;
    }

    public string? Get(string name) => _values.TryGetValue(name, out var v) ? v : null;
    public bool Has(string flag) => _flags.Contains(flag);

    /// <summary>--file, the positional path (validate), or CHANGELOG.md in the current directory or the nearest parent.</summary>
    public string ChangelogPath
    {
        get
        {
            var explicitPath = Get("--file") ?? _positional.FirstOrDefault();
            if (explicitPath is not null)
                return File.Exists(explicitPath) ? explicitPath : throw new InvalidOperationException($"{explicitPath} not found.");
            for (var dir = new DirectoryInfo(Environment.CurrentDirectory); dir is not null; dir = dir.Parent)
            {
                var p = Path.Combine(dir.FullName, "CHANGELOG.md");
                if (File.Exists(p)) return p;
            }
            throw new InvalidOperationException("CHANGELOG.md not found (use --file).");
        }
    }

    /// <summary>The path as shown in messages and annotations (relative, forward slashes).</summary>
    public string DisplayPath
    {
        get
        {
            var rel = Path.GetRelativePath(Environment.CurrentDirectory, Path.GetFullPath(ChangelogPath)).Replace('\\', '/');
            return rel.StartsWith("../", StringComparison.Ordinal) ? Path.GetFullPath(ChangelogPath).Replace('\\', '/') : rel;
        }
    }
}
