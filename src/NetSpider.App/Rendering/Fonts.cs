using Avalonia.Platform;
using SkiaSharp;

namespace NetSpider.App.Rendering;

/// <summary>Typefaces for Skia drawing: Inter (from Avalonia.Fonts.Inter) when the asset loader is available, else Segoe UI.</summary>
public static class Fonts
{
    private static readonly Lazy<SKTypeface> _regular = new(() => Load("Inter-Regular.ttf", SKFontStyle.Normal));
    private static readonly Lazy<SKTypeface> _medium = new(() => Load("Inter-Medium.ttf", SKFontStyle.Normal));
    private static readonly Lazy<SKTypeface> _semi = new(() => Load("Inter-SemiBold.ttf", SKFontStyle.Bold));
    private static readonly Lazy<SKTypeface> _bold = new(() => Load("Inter-Bold.ttf", SKFontStyle.Bold));
    private static readonly Lazy<SKTypeface> _mono = new(() =>
        SKFontManager.Default.MatchFamily("Cascadia Mono") ?? SKFontManager.Default.MatchFamily("Consolas") ?? SKTypeface.Default);

    public static SKTypeface Regular => _regular.Value;
    public static SKTypeface Medium => _medium.Value;
    public static SKTypeface SemiBold => _semi.Value;
    public static SKTypeface Bold => _bold.Value;
    public static SKTypeface Mono => _mono.Value;

    private static SKTypeface Load(string file, SKFontStyle fallbackStyle)
    {
        try
        {
            using var s = AssetLoader.Open(new Uri($"avares://Avalonia.Fonts.Inter/Assets/{file}"));
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            ms.Position = 0;
            var tf = SKTypeface.FromStream(ms);
            if (tf is not null) return tf;
        }
        catch { /* asset loader not initialised (e.g. tests) */ }
        return SKTypeface.FromFamilyName("Segoe UI", fallbackStyle) ?? SKTypeface.Default;
    }
}
