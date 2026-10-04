using System.Globalization;
using System.Text;
using NetSpider.Core;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Writes <c>crash-&lt;yyyyMMdd-HHmmss&gt;.txt</c> into <see cref="AppPaths.Logs"/> for unhandled exceptions (version, arch, OS,
/// exception, last log lines) and detects on the next start whether the previous session ended in a crash.
/// Recovered (UI-thread / unobserved task) exceptions are written too, marked non-fatal and rate-limited.
/// </summary>
public static class CrashReporter
{
    private const string FatalMarker = "Fatal: yes";
    private const int TailLines = 200;
    private static readonly object Sync = new();
    private static DateTime _lastRecovered = DateTime.MinValue;
    private static int _recoveredCount;

    private static string LastRunFile => Path.Combine(AppPaths.Logs, ".lastrun");

    /// <summary>Writes a crash report. Never throws. Returns the file path (null when skipped or failed).</summary>
    public static string? Write(Exception? ex, string source, bool fatal)
    {
        try
        {
            lock (Sync)
            {
                if (!fatal)
                {
                    // a broken render loop can throw many times a second: keep at most one report a minute, 20 per session
                    if (DateTime.UtcNow - _lastRecovered < TimeSpan.FromMinutes(1) || _recoveredCount >= 20) return null;
                    _lastRecovered = DateTime.UtcNow;
                    _recoveredCount++;
                }
                var now = DateTime.Now;
                var path = Path.Combine(AppPaths.Logs, $"crash-{now:yyyyMMdd-HHmmss}.txt");
                for (int i = 2; File.Exists(path); i++) path = Path.Combine(AppPaths.Logs, $"crash-{now:yyyyMMdd-HHmmss}-{i}.txt");
                File.WriteAllText(path, Format(ex, source, fatal, now, ReadLogTail(TailLines)), Encoding.UTF8);
                Log.Error("Crash report written to {Path}", path);
                return path;
            }
        }
        catch { return null; }
    }

    public static string Format(Exception? ex, string source, bool fatal, DateTime time, IReadOnlyList<string> logTail)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{AppInfo.BrandTitle} crash report");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine($"Time:      {time.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)}");
        sb.AppendLine(fatal ? FatalMarker : "Fatal: no (recovered, the app kept running)");
        sb.AppendLine($"Source:    {source}");
        sb.AppendLine($"Version:   {AppInfo.InformationalVersion}");
        sb.AppendLine($"Arch:      {AppInfo.Architecture} (OS {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})");
        sb.AppendLine($"OS:        {AppInfo.OsVersion}");
        sb.AppendLine($"Runtime:   {AppInfo.RuntimeVersion}");
        sb.AppendLine($"Args:      {string.Join(' ', Environment.GetCommandLineArgs().Skip(1))}");
        sb.AppendLine();
        sb.AppendLine("Exception");
        sb.AppendLine(new string('-', 60));
        sb.AppendLine(ex?.ToString() ?? "(no exception object)");
        if (logTail.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Last {logTail.Count} log lines");
            sb.AppendLine(new string('-', 60));
            foreach (var l in logTail) sb.AppendLine(l);
        }
        return sb.ToString();
    }

    /// <summary>The last <paramref name="count"/> lines of the newest log file (shared read while Serilog writes it).</summary>
    public static IReadOnlyList<string> ReadLogTail(int count)
    {
        try
        {
            var file = new DirectoryInfo(AppPaths.Logs).GetFiles("netspider-*.log").OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault();
            if (file is null) return [];
            using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            // only the end of big files
            if (fs.Length > 256 * 1024) fs.Seek(-256 * 1024, SeekOrigin.End);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            var q = new Queue<string>(count + 1);
            while (sr.ReadLine() is { } line)
            {
                q.Enqueue(line);
                if (q.Count > count) q.Dequeue();
            }
            return q.ToArray();
        }
        catch { return []; }
    }

    /// <summary>
    /// Call once at startup: returns fatal crash reports written since the previous start (newest first) and records this start.
    /// </summary>
    public static IReadOnlyList<string> CheckPreviousSession()
    {
        try
        {
            DateTime? previous = null;
            if (File.Exists(LastRunFile) && long.TryParse(File.ReadAllText(LastRunFile).Trim(), out var ticks)) previous = new DateTime(ticks, DateTimeKind.Utc);
            File.WriteAllText(LastRunFile, DateTime.UtcNow.Ticks.ToString(CultureInfo.InvariantCulture));
            if (previous is null) return [];
            return new DirectoryInfo(AppPaths.Logs).GetFiles("crash-*.txt")
                .Where(f => f.LastWriteTimeUtc > previous && IsFatal(f.FullName))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .ToList();
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Checking for previous crashes failed");
            return [];
        }
    }

    private static bool IsFatal(string path)
    {
        try { return File.ReadLines(path).Take(6).Any(l => l.StartsWith(FatalMarker, StringComparison.Ordinal)); }
        catch { return false; }
    }

    /// <summary>Hidden <c>--test-crash [ui]</c> switch: "ui" throws a recovered UI-thread exception, anything else kills the process.</summary>
    public static void TriggerTestCrash(string? mode)
    {
        if (string.Equals(mode, "ui", StringComparison.OrdinalIgnoreCase))
            _ = Task.Delay(3000).ContinueWith(_ => Avalonia.Threading.Dispatcher.UIThread.Post(
                () => throw new InvalidOperationException("Test crash (--test-crash ui): recovered UI-thread exception")), TaskScheduler.Default);
        else
            new Thread(() =>
            {
                Thread.Sleep(3000);
                throw new InvalidOperationException("Test crash (--test-crash): unhandled exception on a background thread");
            }) { IsBackground = true, Name = "TestCrash" }.Start();
    }
}
