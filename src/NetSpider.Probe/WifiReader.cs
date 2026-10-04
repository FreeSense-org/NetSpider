using System.Diagnostics;
using NetSpider.Core.Model;
using NetSpider.Diagnostics.Agents;

namespace NetSpider.Probe;

/// <summary>
/// Best-effort Wi-Fi link sample without P/Invoke: <c>netsh wlan show interfaces</c> on Windows,
/// <c>iw dev &lt;if&gt; link</c> on Linux. Disables itself when the tool is missing.
/// </summary>
public sealed class WifiReader(Action<string> log)
{
    private bool _disabled;

    public async Task<WifiLinkSample?> ReadAsync(string? interfaceName, CancellationToken ct)
    {
        if (_disabled) return null;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var text = await RunAsync("netsh", ["wlan", "show", "interfaces"], ct).ConfigureAwait(false);
                return text is null ? null : AgentWifiParsers.ParseNetsh(text, DateTimeOffset.Now);
            }
            if (OperatingSystem.IsLinux() && !string.IsNullOrEmpty(interfaceName))
            {
                var text = await RunAsync("iw", ["dev", interfaceName, "link"], ct).ConfigureAwait(false);
                return text is null ? null : AgentWifiParsers.ParseIwLink(text, DateTimeOffset.Now);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _disabled = true;
            log($"Wi-Fi details unavailable ({ex.Message}); continuing without them");
        }
        return null;
    }

    private static async Task<string?> RunAsync(string file, string[] args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"{file} did not start");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            var stdout = p.StandardOutput.ReadToEndAsync(cts.Token);
            _ = p.StandardError.ReadToEndAsync(cts.Token);
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return await stdout.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { p.Kill(true); } catch { }
            return null;
        }
    }
}
