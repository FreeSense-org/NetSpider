using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>Brand images shipped as Avalonia resources (falls back to the vector spider icon when missing).</summary>
public static class BrandAssets
{
    public const string LogoUri = "avares://NetSpider/Assets/Brand/logo-256.png";
    private static Bitmap? _logo;
    private static bool _loaded;

    /// <summary>The 256 px app logo, or null when this build doesn't contain it.</summary>
    public static Bitmap? Logo
    {
        get
        {
            if (_loaded) return _logo;
            _loaded = true;
            try
            {
                var uri = new Uri(LogoUri);
                if (AssetLoader.Exists(uri)) _logo = new Bitmap(AssetLoader.Open(uri));
            }
            catch (Exception ex) { Log.Debug(ex, "Loading brand logo failed"); }
            return _logo;
        }
    }

    /// <summary>Text of an embedded resource (e.g. LICENSE), or null.</summary>
    public static string? ReadText(string avaresUri)
    {
        try
        {
            var uri = new Uri(avaresUri);
            if (!AssetLoader.Exists(uri)) return null;
            using var r = new StreamReader(AssetLoader.Open(uri));
            return r.ReadToEnd();
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Reading {Uri} failed", avaresUri);
            return null;
        }
    }
}
