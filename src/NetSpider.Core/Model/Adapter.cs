using System.Net;

namespace NetSpider.Core.Model;

public sealed record IpWithPrefix(IPAddress Address, int PrefixLength)
{
    public override string ToString() => $"{Address}/{PrefixLength}";
}

/// <summary>A local network adapter that can be captured on.</summary>
public sealed record AdapterInfo
{
    public required string Id { get; init; }
    /// <summary>Npcap device name, e.g. \Device\NPF_{GUID}.</summary>
    public required string PcapName { get; init; }
    public required string Name { get; init; }
    public string Description { get; init; } = "";
    public Mac Mac { get; init; }
    public IReadOnlyList<IpWithPrefix> IPv4 { get; init; } = [];
    public IReadOnlyList<IPAddress> IPv6 { get; init; } = [];
    public IPAddress? GatewayV4 { get; init; }
    public IPAddress? GatewayV6 { get; init; }
    public IReadOnlyList<IPAddress> DnsServers { get; init; } = [];
    public IPAddress? DhcpServer { get; init; }
    public long SpeedMbps { get; init; }
    public bool IsUp { get; init; }
    public bool IsWireless { get; init; }
    public bool IsVirtual { get; init; }
    /// <summary>Hyper-V, WSL, Docker, VMware, VirtualBox, VPN, Loopback, or null for physical.</summary>
    public string? VirtualKind { get; init; }

    public IpWithPrefix? PrimaryV4 => IPv4.FirstOrDefault();
    public IPAddress? LinkLocalV6 => IPv6.FirstOrDefault(a => a.IsIPv6LinkLocal);

    public override string ToString() => $"{Name} ({PrimaryV4?.ToString() ?? "no IPv4"}){(IsVirtual ? $" [{VirtualKind}]" : "")}";
}

/// <summary>Everything an active probe needs to know about where it is scanning.</summary>
public sealed class ScanContext
{
    public required AdapterInfo Adapter { get; init; }
    public required AppSettings Settings { get; init; }
    /// <summary>Segments selected for this scan (local first).</summary>
    public required IReadOnlyList<NetworkSegment> Segments { get; init; }

    public Mac LocalMac => Adapter.Mac;
    public IPAddress? LocalIPv4 => Adapter.PrimaryV4?.Address;
    public IPAddress? LocalIPv6LinkLocal => Adapter.LinkLocalV6;
    public IPAddress? Gateway => Adapter.GatewayV4;
    public NetworkSegment? LocalSegment => Segments.FirstOrDefault(s => s.IsLocal);
}
