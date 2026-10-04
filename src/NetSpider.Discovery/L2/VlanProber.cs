using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Discovery.L2.Protocols;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Scan stage 60: for every VLAN id learned so far (LLDP, CDP, VTP, PVST+, 802.1Q) other than our native VLAN, sends an
/// 802.1Q-tagged DHCPDISCOVER. An OFFER reveals that VLAN's subnet (yiaddr + mask) and gateway (option 3); it is added
/// as a segment with that <see cref="NetworkSegment.VlanId"/> and <c>IsLocal=false</c>.
/// Only works when our switch port is a trunk (or accepts tagged frames) and the NIC driver lets tags through; it is
/// skipped when <see cref="INetworkState.NicPassesVlanTags"/> is known to be false. No DHCPREQUEST is ever sent.
/// </summary>
public sealed class VlanProber : IActiveProbe
{
    private const int MaxVlans = 64;

    private readonly ILogger<VlanProber> _log;
    private readonly IFrameSource _frames;
    private readonly INetworkState _network;
    private readonly IDeviceStore _store;
    private readonly DhcpProbeRegistry _registry;
    private readonly DiscoveryContext _dctx;

    public VlanProber(ILogger<VlanProber> log, IFrameSource frames, INetworkState network, IDeviceStore store, DhcpProbeRegistry registry,
        DiscoveryContext dctx)
    {
        _log = log;
        _frames = frames;
        _network = network;
        _store = store;
        _registry = registry;
        _dctx = dctx;
    }

    public string Name => "VLAN DHCP probe";
    public ProbeLayer Layer => ProbeLayer.L2;
    public int Order => 60;

    public async Task RunAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        _dctx.Update(ctx);
        if (!ctx.Settings.ProbeVlans || !_frames.IsRunning) return;
        if (_network.NicPassesVlanTags == false) { _log.LogDebug("VLAN probe skipped: NIC strips 802.1Q tags"); return; }

        int? native = _store.TryGet(ctx.LocalMac, out var me) ? me.NativeVlan : null;
        native ??= ctx.LocalSegment?.VlanId;
        var vlans = _network.Vlans.Where(v => v.Id is > 0 and < 4095 && !v.Native && v.Id != native).Select(v => v.Id).Distinct().Take(MaxVlans).ToList();
        if (vlans.Count == 0) return;

        var xids = new Dictionary<uint, int>();
        foreach (var v in vlans) xids[_registry.NewXid(v)] = v;
        var collector = new DhcpOfferCollector(xids.Keys.ToHashSet());
        try
        {
            using (_frames.Subscribe(collector))
            {
                int i = 0;
                foreach (var (xid, vlan) in xids)
                {
                    ct.ThrowIfCancellationRequested();
                    await _frames.SendPacedAsync(DhcpBuilder.DiscoverFrame(ctx.LocalMac, xid, vlan), ct).ConfigureAwait(false);
                    progress?.Report(new ScanProgress(Name, 0.5 * ++i / xids.Count, $"VLAN {vlan}"));
                }
                await Task.Delay(DhcpDiscoverProbe.CollectFor, ct).ConfigureAwait(false);
            }

            int found = 0;
            foreach (var (offer, _, _, _) in collector.Offers)
            {
                if (!xids.TryGetValue(offer.Xid, out var vlan) || offer.SubnetMask is not { } mask || offer.YourIp.Equals(System.Net.IPAddress.Any)) continue;
                int prefix = IpUtil.PrefixFromMask(mask);
                var gw = offer.Routers.FirstOrDefault();
                var seg = _network.AddOrGetSegment(offer.YourIp, prefix, "vlan-dhcp", s =>
                {
                    s.VlanId = vlan;
                    s.IsLocal = false;
                    s.Gateway ??= gw;
                    if (s.Source == "vlan-dhcp") s.ScanEnabled = ctx.Settings.ScanOtherSubnets;
                });
                _network.AddVlan(new VlanInfo(vlan, null, "vlan-dhcp", Native: false, Voice: false));
                _log.LogInformation("VLAN {Vlan}: DHCP offered {Ip} in {Cidr} via {Gateway}", vlan, offer.YourIp, seg.Cidr, gw);
                found++;
            }
            progress?.Report(new ScanProgress(Name, 1, $"{found} VLAN subnet(s)"));
            // xids stay registered so late OFFERs (possibly untagged by the NIC) are never mistaken for rogue servers.
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "VLAN probe failed"); }
    }
}
