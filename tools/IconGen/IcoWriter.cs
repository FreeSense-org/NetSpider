using SkiaSharp;

namespace NetSpider.Tools.IconGen;

/// <summary>
/// Writes a Windows .ico container. Entries up to 128 px are classic 32-bit BGRA DIBs (readable by every consumer:
/// shell, GDI+, rc.exe, MSI/ARP); 256 px is PNG-compressed as Windows expects.
/// </summary>
internal static class IcoWriter
{
    private const int PngFromSize = 256;

    public static byte[] Build(IEnumerable<(int Size, SKBitmap Image)> images)
    {
        var entries = images.OrderBy(e => e.Size)
            .Select(e => (e.Size, Data: e.Size >= PngFromSize ? EncodePng(e.Image) : EncodeDib(e.Image)))
            .ToList();

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // ICONDIR
        w.Write((ushort)0);              // reserved
        w.Write((ushort)1);              // type: 1 = icon
        w.Write((ushort)entries.Count);

        // ICONDIRENTRY[]
        int offset = 6 + 16 * entries.Count;
        foreach (var (size, data) in entries)
        {
            if (size is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(images), $"Icon size {size} not in 1..256");
            w.Write((byte)(size == 256 ? 0 : size)); // width (0 means 256)
            w.Write((byte)(size == 256 ? 0 : size)); // height
            w.Write((byte)0);                       // palette colors
            w.Write((byte)0);                       // reserved
            w.Write((ushort)1);                     // color planes
            w.Write((ushort)32);                    // bits per pixel
            w.Write((uint)data.Length);             // image data size
            w.Write((uint)offset);                  // image data offset
            offset += data.Length;
        }

        foreach (var (_, data) in entries)
            w.Write(data);

        w.Flush();
        return ms.ToArray();
    }

    private static byte[] EncodePng(SKBitmap bmp)
    {
        using var img = SKImage.FromBitmap(bmp);
        using var data = img.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }

    /// <summary>BITMAPINFOHEADER + bottom-up BGRA pixels (straight alpha) + 1-bit AND mask.</summary>
    private static byte[] EncodeDib(SKBitmap src)
    {
        int size = src.Width;
        var info = new SKImageInfo(size, size, SKColorType.Bgra8888, SKAlphaType.Unpremul);
        using var bmp = new SKBitmap(info);
        using (var pm = src.PeekPixels())
            if (!pm.ReadPixels(info, bmp.GetPixels(), bmp.RowBytes, 0, 0))
                throw new InvalidOperationException("Could not convert icon pixels to unpremultiplied BGRA.");

        int maskStride = ((size + 31) / 32) * 4;
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(40);              // biSize
        w.Write(size);            // biWidth
        w.Write(size * 2);        // biHeight (XOR + AND masks)
        w.Write((ushort)1);       // biPlanes
        w.Write((ushort)32);      // biBitCount
        w.Write(0);               // biCompression = BI_RGB
        w.Write(size * size * 4 + maskStride * size); // biSizeImage
        w.Write(0); w.Write(0);   // resolution
        w.Write(0); w.Write(0);   // palette

        var pixels = bmp.Pixels; // SKColor, unpremultiplied
        for (int y = size - 1; y >= 0; y--)
            for (int x = 0; x < size; x++)
            {
                var c = pixels[y * size + x];
                w.Write(c.Blue); w.Write(c.Green); w.Write(c.Red); w.Write(c.Alpha);
            }

        for (int y = size - 1; y >= 0; y--)
        {
            var row = new byte[maskStride];
            for (int x = 0; x < size; x++)
                if (pixels[y * size + x].Alpha == 0)
                    row[x / 8] |= (byte)(0x80 >> (x % 8));
            w.Write(row);
        }

        w.Flush();
        return ms.ToArray();
    }
}
