using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Export.Persistence;

/// <summary>
/// Incident history in table <c>incidents</c> of the shared <c>netspider.db</c> (same file and connection settings as
/// <see cref="SqliteDeviceRepository"/>). Affected MACs and evidence are stored as JSON arrays.
/// </summary>
public sealed class SqliteIncidentRepository : IIncidentRepository, IDisposable
{
    private readonly ILogger<SqliteIncidentRepository> _log;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _initSync = new();
    private Task? _init;

    public SqliteIncidentRepository(ILogger<SqliteIncidentRepository> log) : this(log, Path.Combine(AppPaths.Data, "netspider.db")) { }

    public SqliteIncidentRepository(ILogger<SqliteIncidentRepository> log, string databasePath)
    {
        _log = log;
        DatabasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 10,
        }.ToString();
    }

    public string DatabasePath { get; }

    public Task InitializeAsync(CancellationToken ct = default)
    {
        lock (_initSync)
        {
            if (_init is null || _init.IsFaulted || _init.IsCanceled) _init = Task.Run(() => Run(InitCore, ct), ct);
            return _init;
        }
    }

    private static void InitCore(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS incidents (
                id             TEXT PRIMARY KEY NOT NULL,
                start          TEXT NOT NULL,
                end_time       TEXT,
                severity       TEXT NOT NULL,
                category       TEXT NOT NULL,
                title          TEXT NOT NULL,
                root_cause     TEXT NOT NULL,
                confidence     REAL NOT NULL,
                suspect_mac    TEXT,
                suspect_port   TEXT,
                suspect_link   TEXT,
                affected       TEXT NOT NULL DEFAULT '[]',
                evidence       TEXT NOT NULL DEFAULT '[]',
                pcap_path      TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_incidents_start ON incidents(start);
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task SaveIncidentAsync(Incident incident, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        await Task.Run(() => Run(c =>
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                INSERT OR REPLACE INTO incidents (id, start, end_time, severity, category, title, root_cause, confidence,
                    suspect_mac, suspect_port, suspect_link, affected, evidence, pcap_path)
                VALUES ($id, $start, $end, $sev, $cat, $title, $root, $conf, $mac, $port, $link, $affected, $evidence, $pcap)
                """;
            cmd.Parameters.AddWithValue("$id", incident.Id.ToString("D"));
            cmd.Parameters.AddWithValue("$start", SqliteDeviceRepository.FormatTime(incident.Start));
            cmd.Parameters.AddWithValue("$end", incident.End is { } e ? SqliteDeviceRepository.FormatTime(e) : DBNull.Value);
            cmd.Parameters.AddWithValue("$sev", incident.Severity.ToString());
            cmd.Parameters.AddWithValue("$cat", incident.Category.ToString());
            cmd.Parameters.AddWithValue("$title", incident.Title);
            cmd.Parameters.AddWithValue("$root", incident.RootCause);
            cmd.Parameters.AddWithValue("$conf", incident.Confidence);
            cmd.Parameters.AddWithValue("$mac", Db(incident.SuspectDevice?.ToString()));
            cmd.Parameters.AddWithValue("$port", Db(incident.SuspectPort));
            cmd.Parameters.AddWithValue("$link", Db(incident.SuspectLink));
            cmd.Parameters.AddWithValue("$affected", JsonSerializer.Serialize(incident.Affected.Select(m => m.ToString()).ToArray()));
            cmd.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(incident.Evidence.ToArray()));
            cmd.Parameters.AddWithValue("$pcap", Db(incident.PcapPath));
            return cmd.ExecuteNonQuery();
        }, ct), ct).ConfigureAwait(false);
    }

    /// <summary>The most recent <paramref name="max"/> incidents, oldest first.</summary>
    public async Task<IReadOnlyList<Incident>> LoadIncidentsAsync(int max, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        return await Task.Run(() => Run(c =>
        {
            var list = new List<Incident>();
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                SELECT id, start, end_time, severity, category, title, root_cause, confidence, suspect_mac, suspect_port, suspect_link,
                       affected, evidence, pcap_path
                FROM incidents ORDER BY start DESC LIMIT $max
                """;
            cmd.Parameters.AddWithValue("$max", Math.Max(0, max));
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                try
                {
                    list.Add(new Incident(
                        Guid.TryParse(r.GetString(0), out var id) ? id : Guid.NewGuid(),
                        SqliteDeviceRepository.ParseTime(r.GetString(1)),
                        Str(r, 2) is { } end ? SqliteDeviceRepository.ParseTime(end) : null,
                        Enum.TryParse<AlertSeverity>(r.GetString(3), out var sev) ? sev : AlertSeverity.Warning,
                        Enum.TryParse<IncidentCategory>(r.GetString(4), out var cat) ? cat : IncidentCategory.Unknown,
                        r.GetString(5), r.GetString(6), r.GetDouble(7),
                        Mac.TryParse(Str(r, 8), out var mac) ? mac : null,
                        Str(r, 9), Str(r, 10),
                        StringList(Str(r, 11)).Select(s => Mac.TryParse(s, out var m) ? m : (Mac?)null).OfType<Mac>().ToList(),
                        StringList(Str(r, 12)),
                        Str(r, 13)));
                }
                catch (Exception ex) { _log.LogDebug(ex, "Skipping unreadable incident row"); }
            }
            list.Reverse();
            return (IReadOnlyList<Incident>)list;
        }, ct), ct).ConfigureAwait(false);
    }

    private static List<string> StringList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch (JsonException) { return []; }
    }

    public async Task ClearAsync(CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        await Task.Run(() => Run(c =>
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "DELETE FROM incidents;";
            cmd.ExecuteNonQuery();
        }, ct), ct).ConfigureAwait(false);
    }

    private T Run<T>(Func<SqliteConnection, T> work, CancellationToken ct)
    {
        _gate.Wait(ct);
        try
        {
            using var c = new SqliteConnection(_connectionString);
            c.Open();
            return work(c);
        }
        finally { _gate.Release(); }
    }

    private void Run(Action<SqliteConnection> work, CancellationToken ct) => Run(c => { work(c); return 0; }, ct);

    private static object Db(string? s) => s is null ? DBNull.Value : s;
    private static string? Str(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);

    public void Dispose() => _gate.Dispose();
}
