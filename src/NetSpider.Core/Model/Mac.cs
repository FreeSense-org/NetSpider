using System.Globalization;

namespace NetSpider.Core.Model;

/// <summary>48-bit IEEE 802 MAC address stored in the low 48 bits of a ulong.</summary>
public readonly record struct Mac(ulong Value) : IComparable<Mac>
{
    public static readonly Mac Zero = new(0);
    public static readonly Mac Broadcast = new(0xFFFF_FFFF_FFFFUL);

    public static Mac FromBytes(ReadOnlySpan<byte> b)
    {
        if (b.Length < 6) throw new ArgumentException("MAC needs 6 bytes", nameof(b));
        ulong v = 0;
        for (int i = 0; i < 6; i++) v = (v << 8) | b[i];
        return new Mac(v);
    }

    public static Mac FromPhysicalAddress(System.Net.NetworkInformation.PhysicalAddress pa) => FromBytes(pa.GetAddressBytes());

    public static bool TryParse(string? s, out Mac mac)
    {
        mac = Zero;
        if (string.IsNullOrWhiteSpace(s)) return false;
        Span<char> hex = stackalloc char[12];
        int n = 0;
        foreach (var c in s)
        {
            if (Uri.IsHexDigit(c)) { if (n == 12) return false; hex[n++] = c; }
            else if (c is not (':' or '-' or '.' or ' ')) return false;
        }
        if (n != 12) return false;
        mac = new Mac(ulong.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
        return true;
    }

    public static Mac Parse(string s) => TryParse(s, out var m) ? m : throw new FormatException($"Invalid MAC '{s}'");

    public byte[] ToBytes() { var b = new byte[6]; WriteTo(b); return b; }

    public void WriteTo(Span<byte> dst)
    {
        for (int i = 0; i < 6; i++) dst[i] = (byte)(Value >> (8 * (5 - i)));
    }

    public byte this[int index] => (byte)(Value >> (8 * (5 - index)));

    /// <summary>24-bit organisationally unique identifier.</summary>
    public uint Oui24 => (uint)(Value >> 24);
    public bool IsMulticast => (this[0] & 0x01) != 0;
    public bool IsLocallyAdministered => (this[0] & 0x02) != 0;
    public bool IsBroadcast => Value == Broadcast.Value;
    public bool IsZero => Value == 0;
    /// <summary>Randomized/private MAC as used by phones (LAA unicast).</summary>
    public bool IsRandomized => IsLocallyAdministered && !IsMulticast;

    public Mac Offset(int delta) => new((ulong)((long)Value + delta) & 0xFFFF_FFFF_FFFFUL);

    public int CompareTo(Mac other) => Value.CompareTo(other.Value);

    public override string ToString() =>
        string.Create(17, Value, static (span, v) =>
        {
            const string hex = "0123456789ABCDEF";
            for (int i = 0; i < 6; i++)
            {
                var b = (byte)(v >> (8 * (5 - i)));
                span[i * 3] = hex[b >> 4];
                span[i * 3 + 1] = hex[b & 0xF];
                if (i < 5) span[i * 3 + 2] = ':';
            }
        });
}
