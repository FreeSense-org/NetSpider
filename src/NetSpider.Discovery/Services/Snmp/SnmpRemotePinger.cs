using System.Net;
using Lextm.SharpSnmpLib;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Snmp;

/// <summary>
/// Best-effort device↔device latency via DISMAN-PING-MIB. Creates a pingCtlTable row with SET, polls
/// pingResultsAverageRtt, then cleans up. Works only against devices with a writable SNMP community; returns null otherwise.
/// </summary>
public sealed class SnmpRemotePinger : IRemotePinger
{
    private readonly ISettingsStore _settings;
    private readonly ILogger<SnmpRemotePinger> _log;

    public SnmpRemotePinger(ISettingsStore settings, ILogger<SnmpRemotePinger> log) { _settings = settings; _log = log; }

    public async Task<double?> PingFromAsync(Device from, IPAddress target, CancellationToken ct)
    {
        var ip = from.PrimaryIPv4;
        if (ip is null) return null;
        var s = _settings.Settings;
        try
        {
            var client = await SnmpClient.EstablishAsync(ip, s.SnmpCommunities, s.SnmpTimeoutMs,
                s.SnmpV3User, s.SnmpV3AuthPassword, s.SnmpV3PrivPassword, s.SnmpV3AuthProtocol, s.SnmpV3PrivProtocol, ct).ConfigureAwait(false);
            if (client is null) return null;

            // Row index: an ownerIndex + testName encoded as octet-string lengths. Use a simple ASCII index.
            var owner = "netspider";
            var testName = "p" + Environment.TickCount64.ToString("x");
            var rowIndex = EncodeStringIndex(owner) + "." + EncodeStringIndex(testName);

            var addrType = Oids.PingCtlTargetAddressType + "." + rowIndex;
            var addr = Oids.PingCtlTargetAddress + "." + rowIndex;
            var count = Oids.PingCtlProbeCount + "." + rowIndex;
            var admin = Oids.PingCtlAdminStatus + "." + rowIndex;
            var rowStatus = Oids.PingCtlRowStatus + "." + rowIndex;
            var avgRtt = Oids.PingResultsAverageRtt + "." + rowIndex;

            // createAndWait (5), then fill, then active (1).
            bool created = await client.SetAsync(new[]
            {
                new Variable(new ObjectIdentifier(rowStatus), new Integer32(5)),
                new Variable(new ObjectIdentifier(addrType), new Integer32(1)), // ipv4
                new Variable(new ObjectIdentifier(addr), new OctetString(target.GetAddressBytes())),
                new Variable(new ObjectIdentifier(count), new Integer32(3)),
                new Variable(new ObjectIdentifier(admin), new Integer32(1)),
            }, ct).ConfigureAwait(false);
            if (!created) return null;

            await client.SetAsync(new[] { new Variable(new ObjectIdentifier(rowStatus), new Integer32(1)) }, ct).ConfigureAwait(false);

            double? rtt = null;
            for (int i = 0; i < 6 && !ct.IsCancellationRequested; i++)
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
                var val = await client.GetStringAsync(avgRtt, ct).ConfigureAwait(false);
                if (int.TryParse(val, out var ms) && ms > 0) { rtt = ms; break; }
            }

            // destroy (6)
            await client.SetAsync(new[] { new Variable(new ObjectIdentifier(rowStatus), new Integer32(6)) }, ct).ConfigureAwait(false);
            return rtt;
        }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex) { _log.LogDebug(ex, "SNMP ping from {Ip}", ip); return null; }
    }

    /// <summary>SMIv2 string index: length byte followed by each character's decimal value, dotted.</summary>
    private static string EncodeStringIndex(string s)
    {
        var parts = new List<string> { s.Length.ToString() };
        foreach (var c in s) parts.Add(((int)c).ToString());
        return string.Join('.', parts);
    }
}
