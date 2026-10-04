using Serilog.Core;
using Serilog.Events;

namespace NetSpider.App.Services;

/// <summary>Runtime-switchable minimum log level (Settings → Application → Log level).</summary>
public static class AppLogging
{
    /// <summary>Starts at Debug so startup is fully logged; <see cref="Apply"/> switches to the configured level once settings are loaded.</summary>
    public static LoggingLevelSwitch LevelSwitch { get; } = new(LogEventLevel.Debug);

    public static IReadOnlyList<string> Levels { get; } = ["Information", "Debug"];

    public static LogEventLevel Parse(string? level) =>
        string.Equals(level, "Debug", StringComparison.OrdinalIgnoreCase) || string.Equals(level, "Verbose", StringComparison.OrdinalIgnoreCase)
            ? LogEventLevel.Debug : LogEventLevel.Information;

    public static void Apply(string? level)
    {
        var l = Parse(level);
        if (LevelSwitch.MinimumLevel == l) return;
        LevelSwitch.MinimumLevel = l;
        Serilog.Log.Information("Log level set to {Level}", l);
    }
}
