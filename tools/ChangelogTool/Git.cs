using System.Diagnostics;
using System.Text;

namespace NetSpider.Tools.ChangelogTool;

/// <summary>The few git queries the tool needs (tags, commit counts, a file at a ref).</summary>
internal static class Git
{
    public sealed record Result(int ExitCode, string Output, string Error);

    public static Result Run(params string[] args)
    {
        var psi = new ProcessStartInfo("git")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("git did not start");
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            p.WaitForExit();
            return new Result(p.ExitCode, stdout.Result, stderr.Result);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return new Result(127, "", "git is not available: " + ex.Message);
        }
    }

    /// <summary>All tag names reachable from HEAD that start with "v".</summary>
    public static IReadOnlyList<string> TagsMergedIntoHead()
    {
        var r = Run("tag", "--list", "v*", "--merged", "HEAD");
        if (r.ExitCode != 0) throw new InvalidOperationException("git tag failed: " + r.Error.Trim());
        return r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>Commits in HEAD since <paramref name="tag"/> (all commits when null).</summary>
    public static int CommitsSince(string? tag)
    {
        var r = tag is null ? Run("rev-list", "--count", "HEAD") : Run("rev-list", "--count", tag + "..HEAD");
        if (r.ExitCode != 0) throw new InvalidOperationException("git rev-list failed: " + r.Error.Trim());
        return int.Parse(r.Output.Trim(), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>The file's content at <paramref name="gitRef"/>, or null when it doesn't exist there.</summary>
    public static string? ShowFile(string gitRef, string path)
    {
        // "./path" makes git resolve the path relative to the current directory (not the repository root)
        var rel = Path.GetRelativePath(Environment.CurrentDirectory, Path.GetFullPath(path)).Replace('\\', '/');
        var verify = Run("rev-parse", "--verify", "--quiet", gitRef + "^{commit}");
        if (verify.ExitCode != 0) throw new InvalidOperationException($"Unknown git ref '{gitRef}' (fetch it first, e.g. actions/checkout with fetch-depth: 0).");
        var r = Run("show", $"{gitRef}:./{rel}");
        return r.ExitCode == 0 ? r.Output : null;
    }
}
