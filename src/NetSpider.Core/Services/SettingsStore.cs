using System.Text.Json;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Core.Services;

public sealed class SettingsStore : ISettingsStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly string _path;

    public SettingsStore() : this(Path.Combine(AppPaths.Root, "settings.json")) { }

    public SettingsStore(string path)
    {
        _path = path;
        Settings = Load(path);
    }

    public AppSettings Settings { get; }
    public event Action? Saved;

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(Settings, Json));
        Saved?.Invoke();
    }

    private static AppSettings Load(string path)
    {
        try
        {
            if (File.Exists(path)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Json) ?? new AppSettings();
        }
        catch { /* corrupt settings: fall back to defaults */ }
        return new AppSettings();
    }
}

public static class AppPaths
{
    /// <summary>Data root; <c>NETSPIDER_HOME</c> overrides it (clean-profile testing, portable setups).</summary>
    public static string Root { get; } = Environment.GetEnvironmentVariable("NETSPIDER_HOME") is { Length: > 0 } home
        ? Path.GetFullPath(home)
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSpider");
    public static string Logos => Ensure(Path.Combine(Root, "Logos"));
    public static string Captures => Ensure(Path.Combine(Root, "Captures"));
    public static string Data => Ensure(Path.Combine(Root, "Data"));
    public static string Logs => Ensure(Path.Combine(Root, "Logs"));
    public static string Exports => Ensure(Path.Combine(Root, "Exports"));

    private static string Ensure(string p) { Directory.CreateDirectory(p); return p; }
}
