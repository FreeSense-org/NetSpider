using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// One NetSpider per user session. The first instance owns the named mutex <c>Global\FreeSense.NetSpider</c> and listens on the
/// pipe <c>FreeSense.NetSpider.Activate</c>; a second launch forwards its command line over the pipe (the first instance
/// restores/activates its window and applies e.g. <c>--page</c>) and exits.
/// <para>
/// Both objects get an explicit ACL granting the current user access, so an elevated first instance (release builds require
/// admin) can still be reached by a non-elevated second launch (whose token has Administrators as deny-only).
/// </para>
/// </summary>
public sealed class SingleInstance : IDisposable
{
    public const string MutexName = "FreeSense.NetSpider";
    public const string PipeName = "FreeSense.NetSpider.Activate";

    private readonly Mutex? _mutex;
    private readonly CancellationTokenSource _cts = new();
    private Thread? _listener;

    private SingleInstance(Mutex? mutex) => _mutex = mutex;

    /// <summary>The running first instance (null when single-instance handling is off or this process is a forwarding second instance).</summary>
    public static SingleInstance? Current { get; private set; }

    /// <summary>Raised on a pool thread with the forwarded arguments of a second launch.</summary>
    public event Action<string[]>? Activated;

    /// <summary>
    /// Returns true when this process should continue starting (it is the first instance, or the check failed and we fail open).
    /// Returns false after the arguments were forwarded to the running instance — the caller must exit.
    /// </summary>
    public static bool TryStart(string[] args)
    {
        var mutex = CreateMutex(out bool createdNew);
        if (!createdNew)
        {
            mutex?.Dispose();
            if (Forward(args)) return false;
            // The other instance is starting up or stuck: don't block the user, start anyway (without a listener).
            Log.Warning("Another NetSpider instance holds the mutex but did not answer on the pipe; starting anyway");
            return true;
        }
        Current = new SingleInstance(mutex);
        Current.StartListener();
        return true;
    }

    // ---------------------------------------------------------------------------------------------- mutex

    private static Mutex? CreateMutex(out bool createdNew)
    {
        foreach (var scope in new[] { "Global", "Local" })
        {
            var name = $@"{scope}\{MutexName}";
            try
            {
                var sec = new MutexSecurity();
                sec.AddAccessRule(new MutexAccessRule(CurrentUser, MutexRights.Synchronize | MutexRights.Modify, AccessControlType.Allow));
                sec.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), MutexRights.FullControl, AccessControlType.Allow));
                var m = MutexAcl.Create(true, name, out createdNew, sec);
                return m;
            }
            catch (UnauthorizedAccessException)
            {
                // The mutex exists but we may not open it: it belongs to a (differently elevated) running instance.
                if (scope == "Global") { createdNew = false; return null; }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Creating mutex {Name} failed", name);
            }
        }
        createdNew = true; // fail open
        return null;
    }

    private static SecurityIdentifier CurrentUser
    {
        get { using var id = WindowsIdentity.GetCurrent(); return id.User!; }
    }

    // ---------------------------------------------------------------------------------------------- second instance

    private static bool Forward(string[] args)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.None);
                pipe.Connect(1500);
                // Let the first instance take the foreground (we own the foreground right as the freshly launched process).
                if (GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid)) AllowSetForegroundWindow(pid);
                var payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(args) + "\n");
                pipe.Write(payload);
                pipe.Flush();
                // The arguments are delivered once written; the short reply only confirms the listener handled them.
                var buf = new byte[16];
                var read = pipe.ReadAsync(buf, 0, buf.Length);
                string reply = read.Wait(2000) ? Encoding.UTF8.GetString(buf, 0, read.Result).Trim() : "(no reply)";
                Log.Information("Forwarded command line to the running instance (pid {Pid}): {Reply}", pid, reply);
                return true;
            }
            catch (TimeoutException) { /* listener not up yet */ }
            catch (Exception ex) { Log.Debug(ex, "Forwarding to the running instance failed"); }
            Thread.Sleep(400);
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------------- first instance

    private void StartListener()
    {
        _listener = new Thread(ListenLoop) { IsBackground = true, Name = "SingleInstance pipe" };
        _listener.Start();
    }

    private void ListenLoop()
    {
        var ct = _cts.Token;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var sec = new PipeSecurity();
                sec.AddAccessRule(new PipeAccessRule(CurrentUser, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
                sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                using var server = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous, 0, 0, sec);
                server.WaitForConnectionAsync(ct).GetAwaiter().GetResult();
                using var reader = new StreamReader(server, Encoding.UTF8, false, 4096, leaveOpen: true);
                var readTask = reader.ReadLineAsync(ct).AsTask();
                if (!readTask.Wait(TimeSpan.FromSeconds(3), ct)) continue;
                var line = readTask.Result;
                string[] args = [];
                try { args = line is null ? [] : JsonSerializer.Deserialize<string[]>(line) ?? []; }
                catch (JsonException) { }
                try { server.Write("OK\n"u8); server.Flush(); } catch { }
                Log.Information("Activation request from a second launch (args: {Args})", string.Join(' ', args));
                try { Activated?.Invoke(args); }
                catch (Exception ex) { Log.Warning(ex, "Handling the activation request failed"); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                // broken client / access problems: back off and retry
                Log.Debug(ex, "Single-instance pipe error");
                try { Task.Delay(500, ct).Wait(ct); } catch { break; }
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        if (Current == this) Current = null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
