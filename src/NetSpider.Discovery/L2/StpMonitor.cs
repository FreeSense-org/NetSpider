using System.Globalization;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Passive STP / RSTP / MSTP (LLC 42/42) and Cisco PVST+ (SNAP 00000C/010B) listener. Records root bridge, bridge id,
/// path cost and protocol in <see cref="INetworkState.AddStp"/>, flags senders <see cref="DeviceFlags.Infrastructure"/>
/// (and <see cref="DeviceFlags.StpRoot"/> when the sender is the root).
/// <para>
/// For anomaly detection, <see cref="BpduSeen"/> is raised for every BPDU with (bridge MAC, topology-change flag);
/// <see cref="TopologyChangeCount"/> counts BPDUs carrying TC (or TCN BPDUs) since start.
/// </para>
/// Devices are keyed by the bridge MAC from the bridge identifier (the switch base MAC, which usually matches LLDP
/// chassis id and the management ARP MAC); the per-port source MAC is kept as property "srcMac".
/// </summary>
public sealed class StpMonitor : IFrameHandler
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    private static readonly TimeSpan RefreshEvery = TimeSpan.FromSeconds(30);

    private readonly ILogger<StpMonitor> _log;
    private readonly IDeviceStore _store;
    private readonly INetworkState _network;
    private readonly ActivityPublisher _activity;
    private readonly Dictionary<Mac, Mac> _srcToBridge = new();
    private readonly Dictionary<(Mac, int?), (StpInfo Info, DateTimeOffset At)> _last = new();
    private readonly HashSet<int> _pvstVlans = new();
    private long _tcCount;

    public StpMonitor(ILogger<StpMonitor> log, IDeviceStore store, INetworkState network, ActivityPublisher activity)
    {
        _log = log;
        _store = store;
        _network = network;
        _activity = activity;
    }

    /// <summary>Raised on the capture thread for every BPDU: (sending bridge MAC, topology change flag or TCN). Handlers must be fast.</summary>
    public event Action<Mac, bool>? BpduSeen;

    /// <summary>Total BPDUs seen with the TC flag set or TCN type.</summary>
    public long TopologyChangeCount => Interlocked.Read(ref _tcCount);

    public void OnFrame(CapturedFrame frame)
    {
        var eth = frame.Eth;
        if (frame.IsOutbound || !(eth.IsStp || eth.IsPvst)) return;
        try
        {
            var bpdu = StpParser.Parse(frame.Payload, pvst: eth.IsPvst);
            if (bpdu is null) return;
            Apply(bpdu, eth.Source, eth.VlanId);
        }
        catch (Exception ex) { _log.LogDebug(ex, "BPDU from {Mac}", eth.Source); }
    }

    internal Device? Apply(BpduInfo b, Mac src, int? frameVlan)
    {
        _activity.Publish(src, "STP");
        Mac bridge;
        if (b.IsTcn)
        {
            lock (_srcToBridge) bridge = _srcToBridge.TryGetValue(src, out var known) ? known : src;
        }
        else
        {
            bridge = b.BridgeMac.IsZero ? src : b.BridgeMac;
            lock (_srcToBridge) { if (_srcToBridge.Count > 4096) _srcToBridge.Clear(); _srcToBridge[src] = bridge; }
        }

        if (b.TopologyChange) Interlocked.Increment(ref _tcCount);
        try { BpduSeen?.Invoke(bridge, b.TopologyChange); } catch (Exception ex) { _log.LogDebug(ex, "BpduSeen subscriber"); }

        var d = _store.GetOrAdd(bridge);
        d.Touch();
        bool ch = false;
        if (!d.Has(DeviceFlags.Infrastructure)) { d.SetFlag(DeviceFlags.Infrastructure); ch = true; }
        if (b.IsTcn)
        {
            if (ch) _store.NotifyChanged(d, "stp");
            return d;
        }

        if (src != bridge) ch |= d.SetProperty("srcMac", src.ToString());
        ch |= d.AddEvidence("stp", Fields.Capabilities, "Bridge", 0.9);
        ch |= DeviceHints.HintType(d, "stp", DeviceType.AccessSwitch, 0.6);
        bool isRoot = b.IsRoot;
        if (d.Has(DeviceFlags.StpRoot) != isRoot && (isRoot || b.PvstVlan is null))
        {
            d.SetFlag(DeviceFlags.StpRoot, isRoot);
            ch = true;
        }
        ch |= d.SetProperty("stp.protocol", b.Protocol);
        ch |= d.SetProperty("stp.bridgeId", b.BridgeId);
        ch |= d.SetProperty("stp.rootId", b.RootId);
        ch |= d.SetProperty("stp.rootPathCost", b.RootPathCost.ToString(Inv));
        ch |= d.SetProperty("stp.portId", $"0x{b.PortId:X4}");
        ch |= d.SetProperty("stp.portRole", b.PortRole);
        ch |= d.SetProperty("stp.timers", $"hello {b.HelloTime:0.#}s, max age {b.MaxAge:0.#}s, fwd delay {b.ForwardDelay:0.#}s");
        ch |= d.SetProperty("stp.mstRegion", b.MstConfigName is null ? null : $"{b.MstConfigName} rev {b.MstRevision}");

        int? vlan = b.PvstVlan ?? frameVlan;
        if (b.PvstVlan is { } pv and > 0 and < 4095)
        {
            ch |= d.AddVlan(pv);
            bool isNew;
            lock (_pvstVlans) isNew = _pvstVlans.Add(pv);
            if (isNew) _network.AddVlan(new VlanInfo(pv, null, "stp", Native: false, Voice: false));
        }

        // Flag the root bridge too when we know it as a device.
        if (!isRoot && _store.TryGet(b.RootMac, out var root) && !root.Has(DeviceFlags.StpRoot))
        {
            root.SetFlag(DeviceFlags.StpRoot);
            root.SetFlag(DeviceFlags.Infrastructure);
            _store.NotifyChanged(root, "stp-root");
        }

        var info = new StpInfo(b.RootId, b.RootMac, b.RootPriority, b.RootPathCost, b.BridgeId, bridge,
            vlan is { } v ? $"{b.Protocol} (VLAN {v})" : b.Protocol, DateTimeOffset.Now);
        bool publish;
        lock (_last)
        {
            var key = (bridge, vlan);
            publish = !_last.TryGetValue(key, out var prev) || prev.Info with { Seen = info.Seen } != info || info.Seen - prev.At > RefreshEvery;
            if (publish) _last[key] = (info, info.Seen);
        }
        if (publish) _network.AddStp(info);

        if (ch) _store.NotifyChanged(d, "stp");
        return d;
    }
}
