using NetSpider.Core.Changelog;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>The CHANGELOG.md compiled into this build (Avalonia resource Assets/CHANGELOG.md), parsed once.</summary>
public static class EmbeddedChangelog
{
    public const string ResourceUri = "avares://NetSpider/Assets/CHANGELOG.md";
    private static Changelog? _cached;

    /// <summary>The parsed changelog; <see cref="Changelog.Empty"/> when the resource is missing. Never throws.</summary>
    public static Changelog Load()
    {
        if (_cached is not null) return _cached;
        try
        {
            var text = BrandAssets.ReadText(ResourceUri);
            if (text is null)
            {
                Log.Debug("Embedded changelog {Uri} not found", ResourceUri);
                return _cached = Changelog.Empty;
            }
            var result = ChangelogParser.ParseWithDiagnostics(text);
            if (!result.IsValid) Log.Warning("Embedded CHANGELOG.md has {Count} format error(s); first: {Error}", result.Errors.Count, result.Errors[0]);
            return _cached = result.Changelog;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Reading the embedded changelog failed");
            return _cached = Changelog.Empty;
        }
    }
}
