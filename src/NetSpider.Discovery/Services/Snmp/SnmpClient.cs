using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>
/// A resolved SNMP session: version + credentials that answered. Wraps GET and table-walk with a timeout and
/// best-effort v3 security (discovery + auth/priv providers).
/// </summary>
internal sealed class SnmpClient
{
    private readonly IPEndPoint _endpoint;
    private readonly VersionCode _version;
    private readonly OctetString _community; // v1/v2c community; for v3 holds the user name
    private readonly IPrivacyProvider? _privacy;
    private readonly ReportMessage? _report; // v3 engine discovery result
    private readonly int _timeoutMs;

    private SnmpClient(IPEndPoint endpoint, VersionCode version, OctetString community, IPrivacyProvider? privacy, ReportMessage? report, int timeoutMs)
    {
        _endpoint = endpoint;
        _version = version;
        _community = community;
        _privacy = privacy;
        _report = report;
        _timeoutMs = timeoutMs;
    }

    public VersionCode Version => _version;
    public string Credential => _version == VersionCode.V3 ? "v3:" + _community : _community.ToString();

    /// <summary>Tries v2c then v1 for each community, then v3 if configured. Returns null if nothing responds.</summary>
    public static async Task<SnmpClient?> EstablishAsync(IPAddress ip, IReadOnlyList<string> communities, int timeoutMs,
        string? v3User, string? authPass, string? privPass, string authProto, string privProto, CancellationToken ct)
    {
        var endpoint = new IPEndPoint(ip, 161);

        foreach (var version in new[] { VersionCode.V2, VersionCode.V1 })
            foreach (var community in communities)
            {
                ct.ThrowIfCancellationRequested();
                if (await ProbeAsync(endpoint, version, new OctetString(community), timeoutMs, ct).ConfigureAwait(false))
                    return new SnmpClient(endpoint, version, new OctetString(community), null, null, timeoutMs);
            }

        if (!string.IsNullOrWhiteSpace(v3User))
        {
            try
            {
                var (privacy, report) = await SetupV3Async(endpoint, v3User!, authPass, privPass, authProto, privProto, timeoutMs, ct).ConfigureAwait(false);
                if (report is not null)
                {
                    var client = new SnmpClient(endpoint, VersionCode.V3, new OctetString(v3User!), privacy, report, timeoutMs);
                    if (await client.CanReadAsync(ct).ConfigureAwait(false)) return client;
                }
            }
            catch { }
        }
        return null;
    }

    private static async Task<bool> ProbeAsync(IPEndPoint endpoint, VersionCode version, OctetString community, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            var vars = new List<Variable> { new(new ObjectIdentifier(Oids.SysObjectId)) };
            var result = await Messenger.GetAsync(version, endpoint, community, vars, cts.Token).ConfigureAwait(false);
            return result.Count > 0 && result[0].Data.TypeCode != SnmpType.NoSuchObject && result[0].Data.TypeCode != SnmpType.Null;
        }
        catch { return false; }
    }

    private static async Task<(IPrivacyProvider? Privacy, ReportMessage? Report)> SetupV3Async(IPEndPoint endpoint, string user,
        string? authPass, string? privPass, string authProto, string privProto, int timeoutMs, CancellationToken ct)
    {
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var report = await discovery.GetResponseAsync(endpoint, cts.Token).ConfigureAwait(false);

#pragma warning disable CS0618 // MD5/SHA1/DES remain in the SNMPv3 spec; offered only when the user configures them
        IAuthenticationProvider auth = string.IsNullOrWhiteSpace(authPass)
            ? DefaultAuthenticationProvider.Instance
            : authProto.ToUpperInvariant() switch
            {
                "MD5" => new MD5AuthenticationProvider(new OctetString(authPass)),
                "SHA256" => new SHA256AuthenticationProvider(new OctetString(authPass)),
                "SHA384" => new SHA384AuthenticationProvider(new OctetString(authPass)),
                "SHA512" => new SHA512AuthenticationProvider(new OctetString(authPass)),
                _ => new SHA1AuthenticationProvider(new OctetString(authPass)),
            };

        IPrivacyProvider privacy = string.IsNullOrWhiteSpace(privPass)
            ? new DefaultPrivacyProvider(auth)
            : privProto.ToUpperInvariant() switch
            {
                "DES" => new DESPrivacyProvider(new OctetString(privPass), auth),
                "AES192" => new AES192PrivacyProvider(new OctetString(privPass), auth),
                "AES256" => new AES256PrivacyProvider(new OctetString(privPass), auth),
                _ => new AESPrivacyProvider(new OctetString(privPass), auth),
            };
#pragma warning restore CS0618
        return (privacy, report);
    }

    private async Task<bool> CanReadAsync(CancellationToken ct)
    {
        var v = await GetAsync(new[] { Oids.SysObjectId }, ct).ConfigureAwait(false);
        return v.Count > 0;
    }

    public async Task<IReadOnlyList<Variable>> GetAsync(IEnumerable<string> oids, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeoutMs);
            var vars = oids.Select(o => new Variable(new ObjectIdentifier(o))).ToList();
            if (_version == VersionCode.V3 && _report is not null)
            {
#pragma warning disable CS0618 // this GetRequestMessage overload is the one that threads the v3 report/privacy
                var request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId,
                    _community, vars, _privacy!, Messenger.MaxMessageSize, _report);
#pragma warning restore CS0618
                var reply = await request.GetResponseAsync(_endpoint, cts.Token).ConfigureAwait(false);
                return reply.Pdu().Variables.ToList();
            }
            var direct = await Messenger.GetAsync(_version, _endpoint, _community, vars, cts.Token).ConfigureAwait(false);
            return direct.ToList();
        }
        catch { return []; }
    }

    public async Task<string?> GetStringAsync(string oid, CancellationToken ct)
    {
        var r = await GetAsync(new[] { oid }, ct).ConfigureAwait(false);
        if (r.Count == 0) return null;
        var data = r[0].Data;
        if (data.TypeCode is SnmpType.NoSuchObject or SnmpType.NoSuchInstance or SnmpType.Null or SnmpType.EndOfMibView) return null;
        return data.ToString();
    }

    /// <summary>Walks a table column and returns (rowSuffix → variable). Uses bulk walk for v2c/v3, plain walk for v1.</summary>
    public async Task<IReadOnlyList<Variable>> WalkAsync(string oid, CancellationToken ct, int maxRows = 4096)
    {
        var results = new List<Variable>();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(_timeoutMs * 4, 4000));
            var root = new ObjectIdentifier(oid);
            if (_version == VersionCode.V1)
                await Messenger.WalkAsync(_version, _endpoint, _community, root, results, WalkMode.WithinSubtree, cts.Token).ConfigureAwait(false);
            else
                await Messenger.BulkWalkAsync(_version, _endpoint, _community, OctetString.Empty, root, results, 20,
                    WalkMode.WithinSubtree, _privacy!, _report!, cts.Token).ConfigureAwait(false);
        }
        catch { }
        return results.Count > maxRows ? results.Take(maxRows).ToList() : results;
    }

    public async Task<bool> SetAsync(IEnumerable<Variable> vars, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeoutMs);
            var r = await Messenger.SetAsync(_version, _endpoint, _community, vars.ToList(), cts.Token).ConfigureAwait(false);
            return r.Count > 0;
        }
        catch { return false; }
    }

    /// <summary>Returns the trailing OID digits of <paramref name="variable"/> after the column <paramref name="columnOid"/>.</summary>
    public static uint[] RowSuffix(Variable variable, string columnOid)
    {
        var full = variable.Id.ToNumerical();
        var col = new ObjectIdentifier(columnOid).ToNumerical();
        if (full.Length <= col.Length) return [];
        return full[col.Length..];
    }
}
