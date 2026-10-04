using System.Globalization;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Fingerprint;

/// <summary>
/// IEEE MA-L / MA-M / MA-S registry with longest-prefix lookup (36 → 28 → 24 bits). Loads a cached copy from
/// <see cref="AppPaths.Data"/> (or the embedded snapshot) and refreshes from IEEE in the background when older than 30 days.
/// Names are normalized to short brands via <see cref="BrandNormalizer"/>.
/// </summary>
public sealed class OuiDatabase : IOuiLookup, IDisposable
{
    public const string MaLUrl = "https://standards-oui.ieee.org/oui/oui.csv";
    public const string MaMUrl = "https://standards-oui.ieee.org/oui28/mam.csv";
    public const string MaSUrl = "https://standards-oui.ieee.org/oui36/oui36.csv";
    internal const string EmbeddedResourceSuffix = "Data.oui.txt.gz";
    internal const string CacheFileName = "oui.txt.gz";
    internal static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);

    private readonly ILogger<OuiDatabase> _log;
    private readonly string _cacheDir;
    private readonly bool _allowDownload;
    private readonly HttpClient _http;
    private readonly object _loadSync = new();
    private readonly SemaphoreSlim _ensureGate = new(1, 1);
    private volatile Tables? _tables;
    private Task? _refresh;

    public OuiDatabase(ILogger<OuiDatabase> log) : this(log, null, null, true) { }

    internal OuiDatabase(ILogger<OuiDatabase> log, string? cacheDir, HttpMessageHandler? handler, bool allowDownload)
    {
        _log = log;
        _cacheDir = cacheDir ?? AppPaths.Data;
        _allowDownload = allowDownload;
        _http = handler is null ? new HttpClient(new HttpClientHandler { AutomaticDecompression = System.Net.DecompressionMethods.All }) : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(60);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(VendorLogoService.BrowserUserAgent);
        _http.DefaultRequestHeaders.Accept.ParseAdd("text/csv,text/plain,*/*");
    }

    public int Count => _tables?.Count ?? 0;

    /// <summary>The background refresh task, if one was started (for tests).</summary>
    internal Task? RefreshTask => _refresh;

    public string? Lookup(Mac mac)
    {
        if (mac.IsZero || mac.IsMulticast || mac.IsRandomized) return null;
        var t = _tables ?? LoadSync();
        if (t.S36.TryGetValue(mac.Value >> 12, out var n)) return n;
        if (t.M28.TryGetValue(mac.Value >> 20, out n)) return n;
        return t.L24.TryGetValue(mac.Value >> 24, out n) ? n : null;
    }

    public async Task EnsureLoadedAsync(CancellationToken ct = default)
    {
        await _ensureGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_tables is null) await Task.Run(LoadSync, ct).ConfigureAwait(false);
            if (_allowDownload && _refresh is null && NeedsRefresh())
                _refresh = Task.Run(() => RefreshAsync(CancellationToken.None));
        }
        finally { _ensureGate.Release(); }
    }

    private string CachePath => Path.Combine(_cacheDir, CacheFileName);

    private bool NeedsRefresh()
    {
        try
        {
            var fi = new FileInfo(CachePath);
            return !fi.Exists || DateTime.UtcNow - fi.LastWriteTimeUtc > MaxAge;
        }
        catch { return true; }
    }

    private Tables LoadSync()
    {
        lock (_loadSync)
        {
            if (_tables is { } existing) return existing;
            Tables? t = null;
            try
            {
                if (File.Exists(CachePath))
                {
                    using var fs = File.OpenRead(CachePath);
                    t = ReadCompact(fs);
                    if (t.Count < 1000) t = null; // corrupt/truncated cache
                    else _log.LogDebug("Loaded {Count} OUI entries from cache", t.Count);
                }
            }
            catch (Exception ex) { _log.LogWarning(ex, "OUI cache unreadable; using embedded snapshot"); t = null; }

            if (t is null)
            {
                try
                {
                    using var s = OpenEmbedded();
                    t = s is null ? Tables.Empty : ReadCompact(s);
                    _log.LogDebug("Loaded {Count} OUI entries from embedded snapshot", t.Count);
                }
                catch (Exception ex) { _log.LogError(ex, "Embedded OUI snapshot failed to load"); t = Tables.Empty; }
            }
            _tables = t;
            return t;
        }
    }

    internal static Stream? OpenEmbedded()
    {
        var asm = typeof(OuiDatabase).Assembly;
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith(EmbeddedResourceSuffix, StringComparison.OrdinalIgnoreCase));
        return name is null ? null : asm.GetManifestResourceStream(name);
    }

    private async Task RefreshAsync(CancellationToken ct)
    {
        try
        {
            _log.LogInformation("Refreshing OUI database from IEEE");
            var lines = new List<string>(60_000);
            foreach (var url in new[] { MaLUrl, MaMUrl, MaSUrl })
            {
                var csv = await _http.GetStringAsync(url, ct).ConfigureAwait(false);
                int before = lines.Count;
                foreach (var (assignment, org) in ParseIeeeCsv(csv)) lines.Add($"{assignment}\t{org}");
                if (lines.Count - before < 100) throw new InvalidDataException($"{url} returned too few rows");
            }
            lines.Sort(StringComparer.Ordinal);
            var bytes = Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n");
            Directory.CreateDirectory(_cacheDir);
            var tmp = CachePath + ".tmp";
            await using (var fs = File.Create(tmp))
            await using (var gz = new GZipStream(fs, CompressionLevel.SmallestSize))
                await gz.WriteAsync(bytes, ct).ConfigureAwait(false);
            File.Move(tmp, CachePath, true);
            using var ms = new MemoryStream(bytes);
            var t = ReadPlain(ms);
            _tables = t;
            _log.LogInformation("OUI database refreshed: {Count} entries", t.Count);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "OUI refresh failed; keeping existing data");
        }
    }

    // ---- parsing ----

    internal sealed class Tables(Dictionary<ulong, string> l24, Dictionary<ulong, string> m28, Dictionary<ulong, string> s36)
    {
        public static readonly Tables Empty = new(new(), new(), new());
        public Dictionary<ulong, string> L24 { get; } = l24;
        public Dictionary<ulong, string> M28 { get; } = m28;
        public Dictionary<ulong, string> S36 { get; } = s36;
        public int Count => L24.Count + M28.Count + S36.Count;
    }

    internal static Tables ReadCompact(Stream gz)
    {
        using var z = new GZipStream(gz, CompressionMode.Decompress);
        return ReadPlain(z);
    }

    /// <summary>Reads "HEXPREFIX\tOrganization" lines; prefix length (6/7/9 hex digits) gives 24/28/36 bits.</summary>
    internal static Tables ReadPlain(Stream s)
    {
        var l24 = new Dictionary<ulong, string>(40_000);
        var m28 = new Dictionary<ulong, string>(7_000);
        var s36 = new Dictionary<ulong, string>(8_000);
        var intern = new Dictionary<string, string?>(StringComparer.Ordinal);
        using var r = new StreamReader(s, Encoding.UTF8);
        string? line;
        while ((line = r.ReadLine()) is not null)
        {
            int tab = line.IndexOf('\t');
            if (tab is not (6 or 7 or 9)) continue;
            if (!ulong.TryParse(line.AsSpan(0, tab), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var key)) continue;
            var org = line[(tab + 1)..];
            if (!intern.TryGetValue(org, out var brand)) intern[org] = brand = BrandNormalizer.Normalize(org);
            if (brand is null) continue;
            (tab switch { 6 => l24, 7 => m28, _ => s36 })[key] = brand;
        }
        return new Tables(l24, m28, s36);
    }

    /// <summary>Parses IEEE registry CSV (Registry,Assignment,Organization Name,Organization Address).</summary>
    internal static IEnumerable<(string Assignment, string Organization)> ParseIeeeCsv(string csv)
    {
        using var r = new StringReader(csv);
        bool header = true;
        foreach (var fields in ReadCsv(r))
        {
            if (header) { header = false; if (fields.Count > 0 && fields[0].StartsWith("Registry", StringComparison.OrdinalIgnoreCase)) continue; }
            if (fields.Count < 3) continue;
            var a = fields[1].Trim().ToUpperInvariant();
            var org = string.Join(' ', fields[2].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            if (a.Length is 6 or 7 or 9 && org.Length > 0 && a.All(Uri.IsHexDigit)) yield return (a, org);
        }
    }

    private static IEnumerable<List<string>> ReadCsv(TextReader r)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;
        int c;
        while ((c = r.Read()) != -1)
        {
            char ch = (char)c;
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (r.Peek() == '"') { sb.Append('"'); r.Read(); }
                    else inQuotes = false;
                }
                else sb.Append(ch);
            }
            else if (ch == '"') inQuotes = true;
            else if (ch == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else if (ch == '\n')
            {
                fields.Add(sb.ToString()); sb.Clear();
                yield return fields;
                fields = new List<string>();
            }
            else if (ch != '\r') sb.Append(ch);
        }
        if (sb.Length > 0 || fields.Count > 0) { fields.Add(sb.ToString()); yield return fields; }
    }

    public void Dispose() { _http.Dispose(); _ensureGate.Dispose(); }
}
