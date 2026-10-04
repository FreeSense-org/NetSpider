using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using NetSpider.Export.Json;

namespace NetSpider.Export.Persistence;

/// <summary>
/// SQLite device history at <c>%LOCALAPPDATA%\NetSpider\Data\netspider.db</c> (WAL mode, parameterized statements).
/// All database work runs on the thread pool and is serialized by a semaphore.
/// </summary>
public sealed class SqliteDeviceRepository : IDeviceRepository, IDisposable
{
    private const int SchemaVersion = 1;
    private readonly ILogger<SqliteDeviceRepository> _log;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Task? _init;
    private readonly object _initSync = new();

    public SqliteDeviceRepository(ILogger<SqliteDeviceRepository> log) : this(log, Path.Combine(AppPaths.Data, "netspider.db")) { }

    public SqliteDeviceRepository(ILogger<SqliteDeviceRepository> log, string databasePath)
    {
        _log = log;
        DatabasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false, // keeps the file unlocked between operations (temp DBs, backups)
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

    private void InitCore(SqliteConnection c)
    {
        Exec(c, "PRAGMA journal_mode=WAL;");
        Exec(c, "PRAGMA synchronous=NORMAL;");
        Exec(c, """
            CREATE TABLE IF NOT EXISTS devices (
                mac         TEXT PRIMARY KEY NOT NULL,
                name        TEXT,
                brand       TEXT,
                model       TEXT,
                type        TEXT NOT NULL DEFAULT 'Unknown',
                user_label  TEXT,
                last_ip     TEXT,
                vendor      TEXT,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                details     TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id          TEXT PRIMARY KEY NOT NULL,
                time        TEXT NOT NULL,
                severity    TEXT NOT NULL,
                kind        TEXT NOT NULL,
                title       TEXT NOT NULL,
                details     TEXT,
                source_mac  TEXT,
                rate        REAL
            );
            CREATE INDEX IF NOT EXISTS ix_alerts_time ON alerts(time);
            CREATE INDEX IF NOT EXISTS ix_devices_last_seen ON devices(last_seen);
            """);
        Exec(c, $"PRAGMA user_version={SchemaVersion};");
    }

    public async Task<IReadOnlyList<KnownDevice>> LoadKnownAsync(CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        return await Task.Run(() => Run(c =>
        {
            var list = new List<KnownDevice>();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT mac, name, brand, model, type, user_label, last_ip, first_seen, last_seen FROM devices";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (!Mac.TryParse(r.GetString(0), out var mac)) continue;
                list.Add(new KnownDevice(mac, Str(r, 1), Str(r, 2), Str(r, 3),
                    Enum.TryParse<DeviceType>(Str(r, 4), out var t) ? t : DeviceType.Unknown,
                    Str(r, 5), Str(r, 6), ParseTime(Str(r, 7)), ParseTime(Str(r, 8))));
            }
            return list;
        }, ct), ct).ConfigureAwait(false);
    }

    public async Task SaveAsync(IEnumerable<Device> devices, CancellationToken ct = default)
    {
        var rows = devices.Where(d => !SyntheticNodes.IsGraphOnly(d.Mac)).Select(Row.From).ToList();
        if (rows.Count == 0) return;
        await InitializeAsync(ct).ConfigureAwait(false);
        await Task.Run(() => Run(c =>
        {
            using var tx = c.BeginTransaction();
            using var cmd = c.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO devices (mac, name, brand, model, type, user_label, last_ip, vendor, first_seen, last_seen, details)
                VALUES ($mac, $name, $brand, $model, $type, $label, $ip, $vendor, $first, $last, $details)
                ON CONFLICT(mac) DO UPDATE SET
                    name       = COALESCE(excluded.name, devices.name),
                    brand      = COALESCE(excluded.brand, devices.brand),
                    model      = COALESCE(excluded.model, devices.model),
                    type       = CASE WHEN excluded.type = 'Unknown' THEN devices.type ELSE excluded.type END,
                    user_label = COALESCE(excluded.user_label, devices.user_label),
                    last_ip    = COALESCE(excluded.last_ip, devices.last_ip),
                    vendor     = COALESCE(excluded.vendor, devices.vendor),
                    first_seen = MIN(devices.first_seen, excluded.first_seen),
                    last_seen  = MAX(devices.last_seen, excluded.last_seen),
                    details    = excluded.details;
                """;
            var pMac = cmd.Parameters.Add("$mac", SqliteType.Text);
            var pName = cmd.Parameters.Add("$name", SqliteType.Text);
            var pBrand = cmd.Parameters.Add("$brand", SqliteType.Text);
            var pModel = cmd.Parameters.Add("$model", SqliteType.Text);
            var pType = cmd.Parameters.Add("$type", SqliteType.Text);
            var pLabel = cmd.Parameters.Add("$label", SqliteType.Text);
            var pIp = cmd.Parameters.Add("$ip", SqliteType.Text);
            var pVendor = cmd.Parameters.Add("$vendor", SqliteType.Text);
            var pFirst = cmd.Parameters.Add("$first", SqliteType.Text);
            var pLast = cmd.Parameters.Add("$last", SqliteType.Text);
            var pDetails = cmd.Parameters.Add("$details", SqliteType.Text);
            cmd.Prepare();
            foreach (var row in rows)
            {
                ct.ThrowIfCancellationRequested();
                pMac.Value = row.Mac;
                pName.Value = Db(row.Name);
                pBrand.Value = Db(row.Brand);
                pModel.Value = Db(row.Model);
                pType.Value = row.Type;
                pLabel.Value = Db(row.UserLabel);
                pIp.Value = Db(row.LastIp);
                pVendor.Value = Db(row.Vendor);
                pFirst.Value = row.FirstSeen;
                pLast.Value = row.LastSeen;
                pDetails.Value = row.Details;
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
            return 0;
        }, ct), ct).ConfigureAwait(false);
    }

    public async Task SaveAlertAsync(Alert alert, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        await Task.Run(() => Run(c =>
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                INSERT OR REPLACE INTO alerts (id, time, severity, kind, title, details, source_mac, rate)
                VALUES ($id, $time, $sev, $kind, $title, $details, $src, $rate)
                """;
            cmd.Parameters.AddWithValue("$id", alert.Id.ToString("D"));
            cmd.Parameters.AddWithValue("$time", FormatTime(alert.Time));
            cmd.Parameters.AddWithValue("$sev", alert.Severity.ToString());
            cmd.Parameters.AddWithValue("$kind", alert.Kind.ToString());
            cmd.Parameters.AddWithValue("$title", alert.Title);
            cmd.Parameters.AddWithValue("$details", Db(alert.Details));
            cmd.Parameters.AddWithValue("$src", Db(alert.Source?.ToString()));
            cmd.Parameters.AddWithValue("$rate", alert.Rate is { } r ? r : DBNull.Value);
            return cmd.ExecuteNonQuery();
        }, ct), ct).ConfigureAwait(false);
    }

    /// <summary>Most recent alerts, newest first (for the alert timeline across sessions).</summary>
    public async Task<IReadOnlyList<Alert>> LoadAlertsAsync(int limit = 500, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        return await Task.Run(() => Run(c =>
        {
            var list = new List<Alert>();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT id, time, severity, kind, title, details, source_mac, rate FROM alerts ORDER BY time DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                Mac? src = Mac.TryParse(Str(r, 6), out var m) ? m : null;
                list.Add(new Alert(Guid.TryParse(r.GetString(0), out var id) ? id : Guid.NewGuid(), ParseTime(r.GetString(1)),
                    Enum.TryParse<AlertSeverity>(r.GetString(2), out var sev) ? sev : AlertSeverity.Info,
                    Enum.TryParse<AlertKind>(r.GetString(3), out var kind) ? kind : AlertKind.Info,
                    r.GetString(4), Str(r, 5) ?? "", src, r.IsDBNull(7) ? null : r.GetDouble(7)));
            }
            return list;
        }, ct), ct).ConfigureAwait(false);
    }

    /// <summary>Raw JSON details blob of one device (null when unknown).</summary>
    public async Task<string?> LoadDetailsJsonAsync(Mac mac, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        return await Task.Run(() => Run(c =>
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT details FROM devices WHERE mac = $mac";
            cmd.Parameters.AddWithValue("$mac", mac.ToString());
            return cmd.ExecuteScalar() as string;
        }, ct), ct).ConfigureAwait(false);
    }

    public async Task SetUserLabelAsync(Mac mac, string? label, CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        label = string.IsNullOrWhiteSpace(label) ? null : label.Trim();
        await Task.Run(() => Run(c =>
        {
            using var cmd = c.CreateCommand();
            var now = FormatTime(DateTimeOffset.Now);
            cmd.CommandText = """
                INSERT INTO devices (mac, user_label, first_seen, last_seen) VALUES ($mac, $label, $now, $now)
                ON CONFLICT(mac) DO UPDATE SET user_label = $label
                """;
            cmd.Parameters.AddWithValue("$mac", mac.ToString());
            cmd.Parameters.AddWithValue("$label", Db(label));
            cmd.Parameters.AddWithValue("$now", now);
            return cmd.ExecuteNonQuery();
        }, ct), ct).ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken ct = default)
    {
        await InitializeAsync(ct).ConfigureAwait(false);
        await Task.Run(() => Run(c => Exec(c, "DELETE FROM devices; DELETE FROM alerts;"), ct), ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ helpers

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

    private static void Exec(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static object Db(string? s) => s is null ? DBNull.Value : s;
    private static string? Str(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);

    /// <summary>UTC round-trip format so lexical order equals chronological order (used by MIN/MAX and ORDER BY).</summary>
    internal static string FormatTime(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    internal static DateTimeOffset ParseTime(string? s) =>
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) ? t.ToLocalTime() : DateTimeOffset.MinValue;

    private sealed record Row(string Mac, string? Name, string? Brand, string? Model, string Type, string? UserLabel, string? LastIp, string? Vendor,
        string FirstSeen, string LastSeen, string Details)
    {
        public static Row From(Device d)
        {
            var name = d.Hostname ?? (d.Brand is not null && d.Model is not null ? $"{d.Brand} {d.Model}" : null);
            var ip = d.PrimaryIPv4 ?? d.IPv6.Select(x => x.Address).FirstOrDefault(a => !a.IsIPv6LinkLocal) ?? d.IPv6.Select(x => x.Address).FirstOrDefault();
            return new Row(d.Mac.ToString(), name, d.Brand, d.Model, d.Type.ToString(), d.UserLabel, ip?.ToString(), d.OuiVendor,
                FormatTime(d.FirstSeen), FormatTime(d.LastSeen), JsonSerializer.Serialize(DeviceDetails.From(d), ExportJson.Compact));
        }
    }

    /// <summary>Extra per-device facts stored in the JSON details column.</summary>
    private sealed record DeviceDetails(string? Firmware, string? OsGuess, string[] Flags, string[] IPv4, string[] IPv6,
        IReadOnlyDictionary<string, string> Hostnames, PortInfo[] Ports, ServiceInfo[] Services, int[] Vlans, int? NativeVlan,
        Mac? UpstreamMac, string? UpstreamPort, WifiAssociation? Wifi, string? IconUrl, IReadOnlyDictionary<string, string> Properties)
    {
        public static DeviceDetails From(Device d) => new(d.Firmware, d.OsGuess, DeviceDto.FlagNames(d.Flags & ~DeviceFlags.New),
            d.IPv4.Select(a => a.ToString()).ToArray(), d.IPv6.Select(a => a.Address.ToString()).ToArray(), d.Hostnames, d.Ports, d.Services,
            d.Vlans, d.NativeVlan, d.UpstreamMac, d.UpstreamPort, d.Wifi, d.IconUrl, d.Properties);
    }

    public void Dispose() => _gate.Dispose();
}
