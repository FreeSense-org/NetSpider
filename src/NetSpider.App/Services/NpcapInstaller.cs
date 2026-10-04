using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using NetSpider.Core;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Guided Npcap setup (Npcap's license forbids bundling it): finds the latest installer on npcap.com, downloads it to %TEMP%,
/// verifies its Authenticode signature (valid, signed by "Nmap Software LLC") and runs it elevated with WinPcap compatibility
/// and loopback support preselected. The caller re-checks <see cref="Capture.NpcapEnvironment"/> afterwards.
/// </summary>
public static partial class NpcapInstaller
{
    public const string HomePage = "https://npcap.com/";
    public const string DistBase = "https://npcap.com/dist/";
    public const string ExpectedSigner = "Nmap Software LLC";
    public const string InstallerArguments = "/winpcap_mode=yes /loopback_support=yes";

    public sealed record Progress(string Stage, double Fraction);

    public sealed record Outcome(bool Success, string Message);

    [GeneratedRegex(@"dist/npcap-(?<v>\d+(?:\.\d+){1,3})\.exe", RegexOptions.IgnoreCase)]
    private static partial Regex InstallerLink();

    /// <summary>Pure: the newest <c>dist/npcap-X.YY.exe</c> referenced by the page, as an absolute URL (null when none).</summary>
    public static string? ParseLatestInstallerUrl(string html)
    {
        Version? best = null;
        string? bestText = null;
        foreach (Match m in InstallerLink().Matches(html))
        {
            var text = m.Groups["v"].Value;
            if (!Version.TryParse(text.Contains('.') ? text : text + ".0", out var v)) continue;
            if (best is null || v > best) { best = v; bestText = text; }
        }
        return bestText is null ? null : $"{DistBase}npcap-{bestText}.exe";
    }

    /// <summary>Downloads, verifies and runs the installer. Never throws; progress is reported on the caller's context.</summary>
    public static async Task<Outcome> InstallAsync(IProgress<Progress>? progress, CancellationToken ct = default)
    {
        string? file = null;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"NetSpider/{AppInfo.Version} (+{AppInfo.Website})");

            progress?.Report(new Progress("Looking up the latest Npcap release…", 0.02));
            var html = await http.GetStringAsync(HomePage, ct);
            var url = ParseLatestInstallerUrl(html);
            if (url is null) return new Outcome(false, "Could not find the Npcap installer on npcap.com. Download it manually from " + HomePage);
            Log.Information("Npcap installer: {Url}", url);

            file = Path.Combine(Path.GetTempPath(), Path.GetFileName(new Uri(url).LocalPath));
            progress?.Report(new Progress($"Downloading {Path.GetFileName(file)}…", 0.05));
            using (var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                resp.EnsureSuccessStatusCode();
                long? total = resp.Content.Headers.ContentLength;
                await using var src = await resp.Content.ReadAsStreamAsync(ct);
                await using var dst = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None);
                var buf = new byte[81920];
                long done = 0;
                int n;
                while ((n = await src.ReadAsync(buf, ct)) > 0)
                {
                    await dst.WriteAsync(buf.AsMemory(0, n), ct);
                    done += n;
                    if (total is > 0) progress?.Report(new Progress($"Downloading {Path.GetFileName(file)}… {done / 1048576.0:0.0} / {total.Value / 1048576.0:0.0} MB", 0.05 + 0.75 * done / total.Value));
                }
            }

            progress?.Report(new Progress("Verifying the digital signature…", 0.82));
            var check = VerifySignature(file);
            if (!check.Success)
            {
                Log.Warning("Npcap installer signature check failed: {Message}", check.Message);
                TryDelete(file);
                return check;
            }

            progress?.Report(new Progress("Waiting for the Npcap installer (confirm the Windows prompt)…", 0.88));
            int exit;
            try
            {
                using var p = Process.Start(new ProcessStartInfo(file, InstallerArguments) { UseShellExecute = true, Verb = "runas" })
                              ?? throw new InvalidOperationException("The installer could not be started");
                await p.WaitForExitAsync(ct);
                exit = p.ExitCode;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return new Outcome(false, "The installation was cancelled (administrator permission was declined).");
            }
            Log.Information("Npcap installer exited with {Code}", exit);
            progress?.Report(new Progress("Checking the installation…", 0.97));
            return exit == 0 ? new Outcome(true, "Npcap was installed.") : new Outcome(false, $"The Npcap installer exited with code {exit} (cancelled or failed).");
        }
        catch (OperationCanceledException) { return new Outcome(false, "Cancelled."); }
        catch (HttpRequestException ex) { return new Outcome(false, "Download failed: " + ex.Message); }
        catch (Exception ex)
        {
            Log.Warning(ex, "Npcap install failed");
            return new Outcome(false, "Npcap install failed: " + ex.Message);
        }
        finally { if (file is not null) _ = Task.Delay(TimeSpan.FromMinutes(1)).ContinueWith(_ => TryDelete(file)); }
    }

    /// <summary>WinVerifyTrust (full chain, revocation of the whole chain) plus the signer subject check.</summary>
    public static Outcome VerifySignature(string file)
    {
        int trust = WinVerifyTrust(file);
        if (trust != 0) return new Outcome(false, $"The downloaded installer is not validly signed (WinVerifyTrust 0x{trust:X8}); it was deleted.");
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            if (!cert.Subject.Contains(ExpectedSigner, StringComparison.OrdinalIgnoreCase))
                return new Outcome(false, $"The installer is signed by \"{cert.GetNameInfo(X509NameType.SimpleName, false)}\", not {ExpectedSigner}; it was deleted.");
            return new Outcome(true, $"Signed by {cert.GetNameInfo(X509NameType.SimpleName, false)}");
        }
        catch (Exception ex) { return new Outcome(false, "Could not read the installer's signature: " + ex.Message); }
    }

    private static void TryDelete(string f) { try { File.Delete(f); } catch { } }

    // ------------------------------------------------------------------ WinVerifyTrust

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;          // 2 = WTD_UI_NONE
        public uint fdwRevocationChecks; // 1 = WTD_REVOKE_WHOLECHAIN
        public uint dwUnionChoice;       // 1 = WTD_CHOICE_FILE
        public IntPtr pFile;
        public uint dwStateAction;       // 1 = verify, 2 = close
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;         // 0x80 = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);

    private static int WinVerifyTrust(string file)
    {
        var path = Marshal.StringToCoTaskMemUni(file);
        var fileInfo = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = path };
        var pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
        var pData = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustData>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 1,
                dwUnionChoice = 1,
                pFile = pFile,
                dwStateAction = 1,
                dwProvFlags = 0x80,
            };
            Marshal.StructureToPtr(data, pData, false);
            int result = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, pData);
            // release the state data
            data = Marshal.PtrToStructure<WinTrustData>(pData);
            data.dwStateAction = 2;
            Marshal.StructureToPtr(data, pData, true);
            WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, pData);
            return result;
        }
        finally
        {
            Marshal.FreeCoTaskMem(pData);
            Marshal.FreeCoTaskMem(pFile);
            Marshal.FreeCoTaskMem(path);
        }
    }
}
