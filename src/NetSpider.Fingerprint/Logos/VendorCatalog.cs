using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSpider.Fingerprint.Logos;

public sealed record VendorEntry(
    [property: JsonPropertyName("brand")] string Brand,
    [property: JsonPropertyName("aliases")] IReadOnlyList<string>? Aliases);

/// <summary>
/// The embedded list of brands with a logo (Data/vendors.json, images in Data/Logos), with alias matching. Logos are
/// reviewed and shipped because a logo looked up from a company's name can belong to anyone: LCFC, a Lenovo subsidiary,
/// is also lcfc.com, a football club.
/// </summary>
public sealed class VendorCatalog
{
    private readonly Dictionary<string, VendorEntry> _byKey = new(StringComparer.OrdinalIgnoreCase);

    public VendorCatalog(IEnumerable<VendorEntry> entries)
    {
        Entries = entries.ToArray();
        foreach (var e in Entries)
        {
            _byKey.TryAdd(BrandNormalizer.Key(e.Brand), e);
            foreach (var a in e.Aliases ?? []) _byKey.TryAdd(BrandNormalizer.Key(a), e);
        }
    }

    public IReadOnlyList<VendorEntry> Entries { get; }

    public static VendorCatalog LoadEmbedded()
    {
        var asm = typeof(VendorCatalog).Assembly;
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("Data.vendors.json", StringComparison.OrdinalIgnoreCase));
        if (name is null) return new VendorCatalog([]);
        using var s = asm.GetManifestResourceStream(name)!;
        return new VendorCatalog(JsonSerializer.Deserialize<List<VendorEntry>>(s) ?? []);
    }

    /// <summary>Finds the entry for a brand, an alias, or a normalized company name.</summary>
    public VendorEntry? Find(string brand)
    {
        if (string.IsNullOrWhiteSpace(brand)) return null;
        if (_byKey.TryGetValue(BrandNormalizer.Key(brand), out var e)) return e;
        var norm = BrandNormalizer.Normalize(brand);
        return norm is not null && _byKey.TryGetValue(BrandNormalizer.Key(norm), out e) ? e : null;
    }
}
