using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Services.Smb;

/// <summary>
/// SMB2 NEGOTIATE + NTLMSSP session setup against port 445. Extracts the dialect, signing-required flag, server GUID
/// and the NTLM CHALLENGE AV pairs (NetBIOS/DNS names, OS version). Also probes SMB1 to flag legacy support.
/// </summary>
public sealed class SmbProbe : IDeviceProbe
{
    private const string Source = "smb";
    private readonly IDeviceStore _store;
    private readonly ILogger<SmbProbe> _log;

    public SmbProbe(IDeviceStore store, ILogger<SmbProbe> log) { _store = store; _log = log; }

    public string Name => "SMB negotiate";
    public int Order => 320;

    public bool AppliesTo(Device device, ScanContext ctx) =>
        device.PrimaryIPv4 is not null && device.Ports.Any(p => p.Port == 445 && p.State == PortState.Open);

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        bool changed = false;
        try { changed |= await Smb2Async(device, ip, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "SMB2 {Ip}", ip); }

        try { if (await Smb1AcceptedAsync(ip, ct).ConfigureAwait(false)) { if (!device.Has(DeviceFlags.SmbV1)) { device.SetFlag(DeviceFlags.SmbV1); changed = true; } } }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "SMB1 {Ip}", ip); }

        if (changed) _store.NotifyChanged(device, Source);
    }

    private async Task<bool> Smb2Async(Device device, IPAddress ip, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new TcpClient();
        await client.ConnectAsync(ip, 445, timeoutCts.Token).ConfigureAwait(false);
        var stream = client.GetStream();

        await WriteNbss(stream, SmbMessages.Smb2Negotiate(), timeoutCts.Token).ConfigureAwait(false);
        var negResp = await ReadNbss(stream, timeoutCts.Token).ConfigureAwait(false);
        bool changed = ParseNegotiate(device, negResp);

        await WriteNbss(stream, SmbMessages.Smb2SessionSetup(), timeoutCts.Token).ConfigureAwait(false);
        var sessResp = await ReadNbss(stream, timeoutCts.Token).ConfigureAwait(false);
        var challenge = FindNtlmChallenge(sessResp);
        if (challenge is not null) changed |= ParseNtlmChallenge(device, challenge);
        return changed;
    }

    /// <summary>Parses an SMB2 NEGOTIATE response (dialect, signing flags, server GUID).</summary>
    public static bool ParseNegotiate(Device device, byte[] resp)
    {
        // resp begins with the SMB2 header (0xFE 'S' 'M' 'B'), structure size 64, then negotiate response body.
        int smb = IndexOfSmb2(resp);
        if (smb < 0 || resp.Length < smb + 64 + 8) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(smb + 8)) != 0) return false; // NT status must be STATUS_SUCCESS
        int body = smb + 64;
        ushort securityMode = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 2));
        ushort dialect = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 4));
        bool changed = device.SetProperty("smb.dialect", DialectName(dialect));
        bool signingRequired = (securityMode & 0x0002) != 0;
        changed |= device.SetProperty("smb.signingRequired", signingRequired ? "true" : "false");
        if (resp.Length >= body + 24)
        {
            var guid = new Guid(resp.AsSpan(body + 8, 16).ToArray());
            changed |= device.SetProperty("smb.serverGuid", guid.ToString());
        }
        changed |= device.AddEvidence(Source, Fields.Service, "SMB " + DialectName(dialect), Confidence.NetBios);
        return changed;
    }

    public static string DialectName(ushort d) => d switch
    {
        0x0202 => "2.0.2", 0x0210 => "2.1", 0x0300 => "3.0", 0x0302 => "3.0.2", 0x0311 => "3.1.1", 0x02FF => "2.wildcard",
        _ => $"0x{d:X4}",
    };

    /// <summary>Parses NTLMSSP CHALLENGE target-info AV pairs and the Version field.</summary>
    public static bool ParseNtlmChallenge(Device device, byte[] ntlm)
    {
        // NTLMSSP\0 signature, type 2. TargetInfo fields at offset 40 (len/maxlen/offset).
        if (ntlm.Length < 48) return false;
        int tiLen = BinaryPrimitives.ReadUInt16LittleEndian(ntlm.AsSpan(40));
        int tiOff = BinaryPrimitives.ReadInt32LittleEndian(ntlm.AsSpan(44));
        bool changed = false;
        if (tiOff > 0 && tiOff + tiLen <= ntlm.Length)
        {
            int p = tiOff;
            while (p + 4 <= tiOff + tiLen)
            {
                ushort avId = BinaryPrimitives.ReadUInt16LittleEndian(ntlm.AsSpan(p));
                ushort avLen = BinaryPrimitives.ReadUInt16LittleEndian(ntlm.AsSpan(p + 2));
                p += 4;
                if (avId == 0 || p + avLen > ntlm.Length) break;
                var val = Encoding.Unicode.GetString(ntlm, p, avLen);
                p += avLen;
                switch (avId)
                {
                    case 1: changed |= device.SetHostname(Source, val); changed |= device.SetProperty("smb.computer", val); break; // NetBIOS computer
                    case 2: changed |= device.AddEvidence(Source, Fields.Domain, val, Confidence.NetBios); changed |= device.SetProperty("smb.domain", val); break; // NetBIOS domain
                    case 3: changed |= device.SetHostname(Source, val); changed |= device.SetProperty("smb.dnsComputer", val); break; // DNS computer
                    case 4: changed |= device.SetProperty("smb.dnsDomain", val); break;
                    case 5: changed |= device.SetProperty("smb.dnsForest", val); break;
                }
            }
        }
        // Version field at offset 48 (8 bytes) when the NegotiateVersion flag is set.
        if (ntlm.Length >= 56)
        {
            byte major = ntlm[48], minor = ntlm[49];
            ushort build = BinaryPrimitives.ReadUInt16LittleEndian(ntlm.AsSpan(50));
            if (major != 0)
            {
                var os = WindowsVersion(major, minor, build);
                changed |= device.AddEvidence(Source, Fields.Os, os, Confidence.NetBios);
            }
        }
        return changed;
    }

    public static string WindowsVersion(byte major, byte minor, int build) => (major, minor) switch
    {
        (10, 0) when build >= 22000 => $"Windows 11/Server 2022 (build {build})",
        (10, 0) => $"Windows 10/Server 2016+ (build {build})",
        (6, 3) => $"Windows 8.1/Server 2012 R2 (build {build})",
        (6, 2) => $"Windows 8/Server 2012 (build {build})",
        (6, 1) => $"Windows 7/Server 2008 R2 (build {build})",
        (6, 0) => $"Windows Vista/Server 2008 (build {build})",
        _ => $"Windows {major}.{minor} (build {build})",
    };

    private static async Task<bool> Smb1AcceptedAsync(IPAddress ip, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(2));
        using var client = new TcpClient();
        await client.ConnectAsync(ip, 445, timeoutCts.Token).ConfigureAwait(false);
        var stream = client.GetStream();
        await WriteNbss(stream, SmbMessages.Smb1Negotiate(), timeoutCts.Token).ConfigureAwait(false);
        var resp = await ReadNbss(stream, timeoutCts.Token).ConfigureAwait(false);
        // SMB1 response begins with 0xFF 'S' 'M' 'B'; a server that answers SMB1 supports the legacy dialect.
        int idx = IndexOf(resp, new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' });
        return idx >= 0;
    }

    // ---- NBSS framing (4-byte length prefix, big-endian) ----
    private static async Task WriteNbss(NetworkStream stream, byte[] smb, CancellationToken ct)
    {
        var frame = new byte[4 + smb.Length];
        frame[0] = 0;
        frame[1] = (byte)(smb.Length >> 16);
        frame[2] = (byte)(smb.Length >> 8);
        frame[3] = (byte)smb.Length;
        smb.CopyTo(frame, 4);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadNbss(NetworkStream stream, CancellationToken ct)
    {
        var hdr = new byte[4];
        await ReadExactly(stream, hdr, ct).ConfigureAwait(false);
        int len = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
        if (len is <= 0 or > 131072) return [];
        var body = new byte[len];
        await ReadExactly(stream, body, ct).ConfigureAwait(false);
        return body;
    }

    private static async Task ReadExactly(NetworkStream stream, byte[] buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(off), ct).ConfigureAwait(false);
            if (n <= 0) throw new EndOfStreamException();
            off += n;
        }
    }

    private static int IndexOfSmb2(byte[] data) => IndexOf(data, new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' });

    public static byte[]? FindNtlmChallenge(byte[] data)
    {
        var sig = Encoding.ASCII.GetBytes("NTLMSSP\0");
        int idx = IndexOf(data, sig);
        if (idx < 0) return null;
        // return from the signature to the end; parsers index relative to it.
        return data[idx..];
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (haystack[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }
}
