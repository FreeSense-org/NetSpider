using System.Runtime.InteropServices;
using NetSpider.Probe;

var options = ProbeOptions.Load(args, out var error);
if (options is null)
{
    Console.Error.WriteLine($"error: {error}");
    Console.Error.WriteLine();
    Console.Error.WriteLine(ProbeOptions.Usage);
    return 1;
}
if (options.Help)
{
    Console.WriteLine(ProbeOptions.Usage);
    return 0;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
PosixSignalRegistration? sigterm = null;
try { sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; cts.Cancel(); }); }
catch (PlatformNotSupportedException) { }

try
{
    return await new ProbeAgent(options).RunAsync(cts.Token);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"fatal: {ex.Message}");
    return 2;
}
finally
{
    sigterm?.Dispose();
}
