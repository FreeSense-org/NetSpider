using System.Text;

namespace NetSpider.Fingerprint.Logos;

/// <summary>Detects image formats from magic bytes so only real images are cached, with the right extension.</summary>
public static class ImageSniffer
{
    public static readonly string[] Extensions = [".png", ".jpg", ".svg", ".ico", ".webp"];

    /// <summary>Returns ".png", ".jpg", ".svg", ".ico" or ".webp", or null when the bytes are not a supported image.</summary>
    public static string? Sniff(ReadOnlySpan<byte> b)
    {
        if (b.Length < 8) return null;
        if (b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47 && b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A) return ".png";
        if (b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return ".jpg";
        if (b[0] == 0x00 && b[1] == 0x00 && (b[2] == 0x01 || b[2] == 0x02) && b[3] == 0x00 && b[4] is > 0 and < 64 && b[5] == 0) return ".ico";
        if (b.Length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return ".webp";
        if (LooksLikeSvg(b)) return ".svg";
        return null;
    }

    private static bool LooksLikeSvg(ReadOnlySpan<byte> b)
    {
        var head = Encoding.UTF8.GetString(b[..Math.Min(b.Length, 2048)]).TrimStart('﻿', ' ', '\t', '\r', '\n');
        if (!(head.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || head.StartsWith("<svg", StringComparison.OrdinalIgnoreCase) ||
              head.StartsWith("<!--", StringComparison.Ordinal) || head.StartsWith("<!DOCTYPE svg", StringComparison.OrdinalIgnoreCase)))
            return false;
        return head.Contains("<svg", StringComparison.OrdinalIgnoreCase) && !head.Contains("<html", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Rejects responses whose declared type is clearly not an image (HTML error pages etc.).</summary>
    public static bool AcceptableContentType(string? mediaType)
    {
        if (string.IsNullOrEmpty(mediaType)) return true;
        var m = mediaType.ToLowerInvariant();
        return m.StartsWith("image/") || m.Contains("svg") || m is "application/octet-stream" or "binary/octet-stream" or "text/xml" or "application/xml" or "text/plain";
    }
}
