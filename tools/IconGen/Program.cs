using SkiaSharp;
using Svg.Skia;

namespace NetSpider.Tools.IconGen;

/// <summary>
/// Renders the NetSpider brand assets from the master SVGs in <c>assets/brand</c>:
/// app icon (.ico: 32-bit DIB entries up to 128 px, PNG at 256 px), logo PNGs, installer art and tray icons. The outputs are committed, so builds never need this tool.
/// <code>dotnet run --project tools/IconGen -- --variant a --out src/NetSpider.App/Assets/Brand [--sheet]</code>
/// </summary>
internal static class Program
{
    private static readonly int[] IcoSizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];
    private static readonly int[] TraySizes = [16, 20, 24, 32];
    private static readonly string[] Variants = ["a", "b", "c"];

    /// <summary>At or below this pixel size the simplified "-small" SVG is used.</summary>
    private const int SmallMaxSize = 32;

    private static int Main(string[] args)
    {
        string variant = "c"; // chosen design: "N" web monogram
        string? outDir = null, brandDir = null;
        bool sheet = false, sheetOnly = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--variant": variant = args[++i].ToLowerInvariant(); break;
                case "--out": outDir = args[++i]; break;
                case "--brand": brandDir = args[++i]; break;
                case "--sheet": sheet = true; break;
                case "--sheet-only": sheet = sheetOnly = true; break;
                case "-h" or "--help":
                    Console.WriteLine("IconGen [--variant a|b|c] [--out <dir>] [--brand <dir>] [--sheet] [--sheet-only]");
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return 2;
            }
        }
        if (!Variants.Contains(variant))
        {
            Console.Error.WriteLine($"Unknown variant '{variant}' (expected a, b or c).");
            return 2;
        }

        var root = FindRepoRoot();
        brandDir = Path.GetFullPath(brandDir ?? Path.Combine(root, "assets", "brand"));
        outDir = Path.GetFullPath(outDir ?? Path.Combine(root, "src", "NetSpider.App", "Assets", "Brand"));

        if (sheet)
        {
            var sheetPath = Path.Combine(brandDir, "variants.png");
            SavePng(Art.VariantSheet(Variants.Select(v => new BrandSource(brandDir, v)).ToArray()), sheetPath);
            Console.WriteLine($"  {sheetPath}");
            if (sheetOnly) return 0;
        }

        var src = new BrandSource(brandDir, variant);
        Directory.CreateDirectory(outDir);
        Console.WriteLine($"Variant {variant.ToUpperInvariant()} -> {outDir}");

        WriteIco(outDir, "netspider.ico", IcoSizes.Select(s => (s, src.Render(s))));
        foreach (var size in new[] { 256, 512, 1024 })
            Write(outDir, $"logo-{size}.png", Encode(src.Render(size)));

        Write(outDir, "installer-banner.png", Encode(Art.InstallerBanner(src)));
        Write(outDir, "installer-dialog.png", Encode(Art.InstallerDialog(src)));
        Write(outDir, "velopack-splash.png", Encode(Art.Splash(src)));

        foreach (var (name, dot) in new (string, SKColor?)[] { ("normal", null), ("monitoring", Art.Green), ("alert", Art.Red) })
            WriteIco(outDir, $"tray-{name}.ico", TraySizes.Select(s => (s, Art.TrayIcon(src, s, dot))));

        return 0;
    }

    private static string FindRepoRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "NetworkScan.slnx")))
                    return dir.FullName;
        }
        return Directory.GetCurrentDirectory();
    }

    private static byte[] Encode(SKBitmap bmp)
    {
        using (bmp)
        using (var img = SKImage.FromBitmap(bmp))
        using (var data = img.Encode(SKEncodedImageFormat.Png, 100))
            return data.ToArray();
    }

    private static void SavePng(SKBitmap bmp, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, Encode(bmp));
    }

    private static void WriteIco(string dir, string name, IEnumerable<(int Size, SKBitmap Image)> images)
    {
        var list = images.ToList();
        try { Write(dir, name, IcoWriter.Build(list)); }
        finally { foreach (var (_, img) in list) img.Dispose(); }
    }

    private static void Write(string dir, string name, byte[] bytes)
    {
        var path = Path.Combine(dir, name);
        File.WriteAllBytes(path, bytes);
        Console.WriteLine($"  {name,-22} {bytes.Length,8:N0} bytes");
    }

    /// <summary>One design variant: the master SVG plus its simplified small-size SVG.</summary>
    internal sealed class BrandSource(string brandDir, string variant)
    {
        public string Variant { get; } = variant;
        private readonly SKPicture _master = Load(Path.Combine(brandDir, $"netspider-{variant}.svg"));
        private readonly SKPicture _small = Load(Path.Combine(brandDir, $"netspider-{variant}-small.svg"));

        private static SKPicture Load(string path)
        {
            if (!File.Exists(path)) throw new FileNotFoundException($"Brand SVG not found: {path}");
            var svg = new SKSvg();
            return svg.Load(path) ?? throw new InvalidOperationException($"Could not parse {path}");
        }

        /// <summary>Renders the icon at <paramref name="size"/> px (small variant at or below 32 px).</summary>
        public SKBitmap Render(int size, bool? small = null)
        {
            var bmp = new SKBitmap(new SKImageInfo(size, size, SKColorType.Bgra8888, SKAlphaType.Premul));
            using var canvas = new SKCanvas(bmp);
            canvas.Clear(SKColors.Transparent);
            Draw(canvas, new SKRect(0, 0, size, size), small ?? size <= SmallMaxSize);
            return bmp;
        }

        public void Draw(SKCanvas canvas, SKRect dest, bool? small = null)
        {
            var pic = small ?? dest.Width <= SmallMaxSize ? _small : _master;
            var cull = pic.CullRect;
            var scale = Math.Min(dest.Width / cull.Width, dest.Height / cull.Height);
            canvas.Save();
            canvas.Translate(dest.Left, dest.Top);
            canvas.Scale(scale);
            canvas.Translate(-cull.Left, -cull.Top);
            canvas.DrawPicture(pic);
            canvas.Restore();
        }
    }
}
