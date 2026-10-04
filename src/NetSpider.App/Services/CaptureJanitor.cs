using NetSpider.Core.Abstractions;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Keeps <see cref="AppPaths.Captures"/> under <see cref="Core.Model.AppSettings.CaptureFolderMaxMb"/>: at startup and hourly the
/// oldest <c>*.pcapng</c> files beyond the cap are deleted. The file currently being recorded is never touched.
/// </summary>
public sealed class CaptureJanitor : IDisposable
{
    public sealed record CaptureFile(string Path, long Length, DateTime LastWriteUtc);

    private readonly ISettingsStore _settings;
    private readonly IPacketRecorder? _recorder;
    private readonly string _folder;
    private Timer? _timer;
    private int _running;

    public CaptureJanitor(ISettingsStore settings, IPacketRecorder? recorder, string? folder = null)
    {
        _settings = settings;
        _recorder = recorder;
        _folder = folder ?? AppPaths.Captures;
    }

    /// <summary>
    /// Pure selection: which files to delete (oldest first) so the total of the remaining files is ≤ <paramref name="maxBytes"/>.
    /// Protected files (e.g. the active recording) are never selected but still count towards the total.
    /// </summary>
    public static IReadOnlyList<CaptureFile> SelectForDeletion(IEnumerable<CaptureFile> files, long maxBytes, IEnumerable<string?> protectedPaths)
    {
        var all = files.ToList();
        var prot = new HashSet<string>(protectedPaths.Where(p => !string.IsNullOrEmpty(p)).Select(p => System.IO.Path.GetFullPath(p!)), StringComparer.OrdinalIgnoreCase);
        long total = all.Sum(f => f.Length);
        var delete = new List<CaptureFile>();
        if (maxBytes < 0 || total <= maxBytes) return delete;
        foreach (var f in all.OrderBy(f => f.LastWriteUtc).ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
        {
            if (total <= maxBytes) break;
            if (prot.Contains(System.IO.Path.GetFullPath(f.Path))) continue;
            delete.Add(f);
            total -= f.Length;
        }
        return delete;
    }

    public void Start()
    {
        _timer = new Timer(_ => Run(), null, TimeSpan.FromSeconds(20), TimeSpan.FromHours(1));
    }

    /// <summary>Runs one cleanup pass (thread pool safe, never throws). Returns the number of deleted files.</summary>
    public int Run()
    {
        if (Interlocked.Exchange(ref _running, 1) == 1) return 0;
        try
        {
            int maxMb = _settings.Settings.CaptureFolderMaxMb;
            if (maxMb <= 0 || !Directory.Exists(_folder)) return 0;
            var files = new DirectoryInfo(_folder).GetFiles("*.pcapng", SearchOption.TopDirectoryOnly)
                .Select(f => new CaptureFile(f.FullName, f.Length, f.LastWriteTimeUtc)).ToList();
            string? active = _recorder?.IsRecording == true ? _recorder.Path : null;
            var victims = SelectForDeletion(files, (long)maxMb * 1024 * 1024, [active]);
            int deleted = 0;
            foreach (var v in victims)
            {
                try { File.Delete(v.Path); deleted++; }
                catch (Exception ex) { Log.Debug(ex, "Could not delete capture {Path}", v.Path); }
            }
            if (deleted > 0) Log.Information("Capture janitor deleted {Count} old capture(s) to stay under {Max} MB", deleted, maxMb);
            return deleted;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Capture janitor failed");
            return 0;
        }
        finally { Volatile.Write(ref _running, 0); }
    }

    public void Dispose() => _timer?.Dispose();
}
