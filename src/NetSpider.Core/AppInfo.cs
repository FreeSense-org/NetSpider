using System.Reflection;
using System.Runtime.InteropServices;

namespace NetSpider.Core;

/// <summary>Product identity and FreeSense branding in one place (titles, About, installers, links).</summary>
public static class AppInfo
{
    public const string ProductName = "NetSpider";
    public const string Vendor = "FreeSense.org";
    public const string Project = "FreeSense";
    /// <summary>Window/brand title: "FreeSense – NetSpider".</summary>
    public const string BrandTitle = "FreeSense – NetSpider";
    /// <summary>Installed product name (Start menu, Apps &amp; Features, MSI).</summary>
    public const string InstalledName = "FreeSense NetSpider";

    public const string Website = "https://freesense.org";
    public const string Repository = "https://github.com/FreeSense-org/NetSpider";
    /// <summary>Installers and the update feed are published as GitHub releases of the main repository.</summary>
    public const string ReleasesRepository = Repository;
    public const string ReleasesPage = ReleasesRepository + "/releases";
    public const string IssuesUrl = Repository + "/issues/new";

    /// <summary>Full informational version, e.g. "1.2.3+abc1234".</summary>
    public static string InformationalVersion { get; } = ReadInformationalVersion();
    /// <summary>Semantic version without build metadata, e.g. "1.2.3" or "0.1.0-beta.1".</summary>
    public static string Version { get; } = InformationalVersion.Split('+')[0];
    /// <summary>Commit hash from the informational version's build metadata, if present.</summary>
    public static string? Commit => InformationalVersion.Contains('+') ? InformationalVersion[(InformationalVersion.IndexOf('+') + 1)..] : null;

    /// <summary>x64, Arm64 or X86 for the running process.</summary>
    public static string Architecture => RuntimeInformation.ProcessArchitecture.ToString();
    public static string RuntimeVersion => RuntimeInformation.FrameworkDescription;
    public static string OsVersion => RuntimeInformation.OSDescription;

    /// <summary>"FreeSense – NetSpider 1.2.3" (plus an optional suffix like "Live MTR").</summary>
    public static string WindowTitle(string? suffix = null) =>
        $"{BrandTitle} {Version}" + (string.IsNullOrEmpty(suffix) ? "" : $" · {suffix}");

    private static string ReadInformationalVersion()
    {
        var asm = Assembly.GetEntryAssembly() ?? typeof(AppInfo).Assembly;
        return asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
               ?? asm.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}
