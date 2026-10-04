using System.Collections.Concurrent;
using System.Net;

namespace NetSpider.Discovery.Services.Ssdp;

/// <summary>A parsed UPnP device description plus its embedded devices and service control URLs.</summary>
public sealed record UpnpService(string ServiceType, string? ControlUrl, string? ScpdUrl, string? EventSubUrl);

public sealed record UpnpDevice(
    string? DeviceType, string? FriendlyName, string? Manufacturer, string? ManufacturerUrl,
    string? ModelName, string? ModelNumber, string? ModelDescription, string? SerialNumber,
    string? Udn, string? PresentationUrl, string? IconUrl,
    IReadOnlyList<UpnpService> Services, IReadOnlyList<UpnpDevice> Children);

public sealed record SsdpDescription(
    IPAddress DeviceIp, Uri Location, string? Server, UpnpDevice Root)
{
    /// <summary>Flattened self + nested devices.</summary>
    public IEnumerable<UpnpDevice> AllDevices()
    {
        var stack = new Stack<UpnpDevice>();
        stack.Push(Root);
        while (stack.Count > 0)
        {
            var d = stack.Pop();
            yield return d;
            foreach (var c in d.Children) stack.Push(c);
        }
    }
}

/// <summary>
/// Shared registry of SSDP/UPnP descriptions so the gateway audit can find IGD control URLs without re-fetching.
/// Registered as a singleton.
/// </summary>
public sealed class SsdpRegistry
{
    private readonly ConcurrentDictionary<string, SsdpDescription> _byLocation = new(StringComparer.OrdinalIgnoreCase);

    public void Add(SsdpDescription description) => _byLocation[description.Location.AbsoluteUri] = description;

    public IReadOnlyCollection<SsdpDescription> All => _byLocation.Values.ToArray();

    public bool Contains(string location) => _byLocation.ContainsKey(location);

    /// <summary>Returns descriptions whose device tree advertises an InternetGatewayDevice.</summary>
    public IEnumerable<SsdpDescription> InternetGatewayDevices() =>
        _byLocation.Values.Where(d => d.AllDevices().Any(x =>
            x.DeviceType?.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase) == true));
}
