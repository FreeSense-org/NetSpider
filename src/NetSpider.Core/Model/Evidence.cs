namespace NetSpider.Core.Model;

/// <summary>One fact a probe learned about a device, with the confidence of that source.</summary>
public sealed record Evidence(string Source, string Field, string Value, double Confidence, DateTimeOffset Timestamp)
{
    public static Evidence Of(string source, string field, string value, double confidence) =>
        new(source, field, value, confidence, DateTimeOffset.Now);
}

/// <summary>Well-known evidence field names consumed by the classifier.</summary>
public static class Fields
{
    public const string Hostname = "hostname";
    public const string Vendor = "vendor";
    public const string Brand = "brand";
    public const string Model = "model";
    public const string ModelNumber = "modelNumber";
    public const string Firmware = "firmware";
    public const string Serial = "serial";
    public const string Os = "os";
    public const string DeviceType = "deviceType";
    public const string Service = "service";
    public const string Description = "description";
    public const string Capabilities = "capabilities";
    public const string Domain = "domain";
    public const string IconUrl = "iconUrl";
    public const string PresentationUrl = "presentationUrl";
    public const string DhcpFingerprint = "dhcpFingerprint";
    public const string DhcpVendorClass = "dhcpVendorClass";
    public const string Ttl = "ttl";
}

/// <summary>Base confidences per evidence source (see plan "Evidence-based confidence scoring").</summary>
public static class Confidence
{
    public const double Oui = 0.4;
    public const double Ttl = 0.3;
    public const double Port = 0.5;
    public const double Http = 0.6;
    public const double Dhcp = 0.7;
    public const double NetBios = 0.75;
    public const double Mdns = 0.85;
    public const double Ssdp = 0.9;
    public const double Tls = 0.95;
    public const double Lldp = 1.0;
    public const double Snmp = 1.0;
    public const double VendorProtocol = 1.0;
    public const double User = 1.0;
}
