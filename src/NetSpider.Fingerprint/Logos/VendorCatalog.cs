using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSpider.Fingerprint.Logos;

public sealed record VendorEntry(
    [property: JsonPropertyName("brand")] string Brand,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("aliases")] IReadOnlyList<string>? Aliases);

/// <summary>Embedded brand → homepage-domain map (Data/vendors.json) with alias matching.</summary>
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

    /// <summary>Candidate homepage domains: the mapped domain, or guesses derived from the brand name.</summary>
    public IReadOnlyList<string> CandidateDomains(string brand)
    {
        if (Find(brand) is { } e) return [e.Domain];
        var norm = BrandNormalizer.Normalize(brand) ?? brand;
        var stem = new string(norm.ToLowerInvariant().Where(char.IsAsciiLetterOrDigit).ToArray());
        if (stem.Length < 2) return [];
        var dashed = BrandNormalizer.Key(norm);
        var list = new List<string> { stem + ".com" };
        if (dashed != stem && dashed.Length > 0) list.Add(dashed + ".com");
        list.Add(stem + ".net");
        list.Add(stem + ".de");
        list.Add(stem + ".co.uk");
        return list;
    }
}
