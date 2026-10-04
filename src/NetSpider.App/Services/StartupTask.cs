using System.Diagnostics;
using System.Security;
using System.Security.Principal;
using System.Text;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// "Start with Windows". NetSpider requires elevation and a Run-key entry can't auto-elevate, so this registers a
/// Task Scheduler logon task ("FreeSense NetSpider", run with highest privileges, for the current user only) that starts
/// the current exe with <c>--minimized</c>. Uses <c>schtasks.exe /XML</c>, no extra packages.
/// Creating a highest-privilege task itself needs an elevated process (Debug builds run asInvoker → fails with a message).
/// </summary>
public static class StartupTask
{
    public const string TaskName = "FreeSense NetSpider";

    public sealed record Result(bool Success, string Message);

    /// <summary>The task XML (Task Scheduler schema 1.2). Pure — unit tested.</summary>
    public static string BuildXml(string exePath, string userId, string arguments = "--minimized", string? author = null)
    {
        string X(string s) => SecurityElement.Escape(s) ?? "";
        var workDir = Path.GetDirectoryName(exePath) ?? "";
        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>{X(author ?? userId)}</Author>
                <Description>Starts FreeSense NetSpider (network diagnostics) minimized to the tray when you sign in.</Description>
                <URI>\{X(TaskName)}</URI>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                  <UserId>{X(userId)}</UserId>
                  <Delay>PT10S</Delay>
                </LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{X(userId)}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <WakeToRun>false</WakeToRun>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>"{X(exePath)}"</Command>
                  <Arguments>{X(arguments)}</Arguments>
                  <WorkingDirectory>{X(workDir)}</WorkingDirectory>
                </Exec>
              </Actions>
            </Task>
            """;
    }

    public static string CurrentUserId
    {
        get { using var id = WindowsIdentity.GetCurrent(); return id.Name; }
    }

    public static string CurrentExe => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "NetSpider.exe");

    /// <summary>True when the logon task exists.</summary>
    public static async Task<bool> ExistsAsync()
    {
        var (code, _) = await RunSchtasksAsync($"/Query /TN \"{TaskName}\"");
        return code == 0;
    }

    public static async Task<Result> EnableAsync()
    {
        var xmlPath = Path.Combine(Path.GetTempPath(), $"netspider-task-{Guid.NewGuid():N}.xml");
        try
        {
            // schtasks reads UTF-16 reliably (matching the XML declaration)
            await File.WriteAllTextAsync(xmlPath, BuildXml(CurrentExe, CurrentUserId), Encoding.Unicode);
            var (code, output) = await RunSchtasksAsync($"/Create /TN \"{TaskName}\" /XML \"{xmlPath}\" /F");
            if (code == 0)
            {
                Log.Information("Created logon task {Task} for {Exe}", TaskName, CurrentExe);
                return new Result(true, "NetSpider will start minimized to the tray when you sign in.");
            }
            Log.Warning("Creating logon task failed ({Code}): {Output}", code, output);
            bool denied = output.Contains("denied", StringComparison.OrdinalIgnoreCase) || code == 5;
            return new Result(false, denied
                ? "Could not create the startup task: access denied. NetSpider must run as administrator to register a task with highest privileges."
                : "Could not create the startup task: " + Short(output));
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Creating logon task failed");
            return new Result(false, "Could not create the startup task: " + ex.Message);
        }
        finally { try { File.Delete(xmlPath); } catch { } }
    }

    public static async Task<Result> DisableAsync()
    {
        try
        {
            if (!await ExistsAsync()) return new Result(true, "NetSpider no longer starts with Windows.");
            var (code, output) = await RunSchtasksAsync($"/Delete /TN \"{TaskName}\" /F");
            if (code == 0)
            {
                Log.Information("Deleted logon task {Task}", TaskName);
                return new Result(true, "NetSpider no longer starts with Windows.");
            }
            Log.Warning("Deleting logon task failed ({Code}): {Output}", code, output);
            return new Result(false, "Could not remove the startup task: " + Short(output));
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Deleting logon task failed");
            return new Result(false, "Could not remove the startup task: " + ex.Message);
        }
    }

    private static string Short(string s)
    {
        s = s.Replace("ERROR:", "", StringComparison.OrdinalIgnoreCase).Trim();
        return s.Length > 200 ? s[..200] + "…" : s.Length == 0 ? "unknown error" : s;
    }

    private static async Task<(int Code, string Output)> RunSchtasksAsync(string args)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("schtasks.exe could not be started");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await p.WaitForExitAsync(cts.Token);
        return (p.ExitCode, ((await stdout) + " " + (await stderr)).Trim());
    }
}
