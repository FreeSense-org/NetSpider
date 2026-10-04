using System.Security.Principal;
using NetSpider.Core.Abstractions;

namespace NetSpider.Capture;

/// <summary>Detects whether Npcap is installed and whether the process is elevated.</summary>
public static class NpcapEnvironment
{
    public const string DownloadUrl = "https://npcap.com/#download";

    public static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return Environment.UserName == "root";
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static PcapStatus Check()
    {
        bool admin = IsAdministrator();
        if (OperatingSystem.IsWindows())
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            bool installed = File.Exists(Path.Combine(sys, "Npcap", "wpcap.dll")) || File.Exists(Path.Combine(sys, "wpcap.dll"));
            if (!installed)
                return new PcapStatus(false, admin, null, "Npcap is not installed. Install it (with \"WinPcap API-compatible mode\") from " + DownloadUrl);
            // Make the Npcap folder resolvable for wpcap.dll/Packet.dll.
            var npcapDir = Path.Combine(sys, "Npcap");
            if (Directory.Exists(npcapDir) && !(Environment.GetEnvironmentVariable("PATH") ?? "").Contains(npcapDir, StringComparison.OrdinalIgnoreCase))
                Environment.SetEnvironmentVariable("PATH", npcapDir + ";" + Environment.GetEnvironmentVariable("PATH"));
        }
        try
        {
            var version = SharpPcap.Pcap.Version;
            var msg = admin ? null : "Not running as administrator: capture and packet injection may fail.";
            return new PcapStatus(true, admin, version, msg);
        }
        catch (Exception ex) when (ex is DllNotFoundException or TypeInitializationException or BadImageFormatException)
        {
            return new PcapStatus(false, admin, null, "Npcap could not be loaded: " + ex.Message + ". Install from " + DownloadUrl);
        }
    }
}
