using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.L2;

/// <summary>
/// Wake-on-LAN: a raw EtherType 0x0842 magic frame via the capture adapter (when capture runs) plus the magic packet as
/// UDP broadcast to ports 7 and 9 (limited broadcast and each adapter's directed broadcast), always.
/// </summary>
public sealed class WakeOnLanSender : IWakeOnLan
{
    private readonly ILogger<WakeOnLanSender> _log;
    private readonly IFrameSource _frames;

    public WakeOnLanSender(ILogger<WakeOnLanSender> log, IFrameSource frames)
    {
        _log = log;
        _frames = frames;
    }

    public async Task SendAsync(Mac target, CancellationToken ct = default)
    {
        int sent = 0;
        try
        {
            if (_frames.IsRunning && _frames.Adapter is { } a)
            {
                _frames.Send(FrameBuilder.WakeOnLan(a.Mac, target));
                sent++;
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "Raw WoL frame failed"); }

        var magic = FrameBuilder.MagicPacket(target);
        var destinations = new List<IPAddress> { IPAddress.Broadcast };
        if (_frames.Adapter is { } adapter)
            foreach (var ip in adapter.IPv4)
                if (ip.PrefixLength is > 0 and < 31)
                    destinations.Add(IpUtil.FromUInt32(IpUtil.ToUInt32(ip.Address) | ~IpUtil.MaskOf(ip.PrefixLength)));

        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
            foreach (var dst in destinations.Distinct())
                foreach (var port in (int[])[7, 9])
                {
                    try
                    {
                        await udp.SendAsync(magic, new IPEndPoint(dst, port), ct).ConfigureAwait(false);
                        sent++;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex) { _log.LogDebug(ex, "WoL UDP to {Dst}:{Port} failed", dst, port); }
                }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _log.LogDebug(ex, "WoL UDP socket failed"); }
        _log.LogInformation("Wake-on-LAN for {Mac}: {Count} packets sent", target, sent);
    }
}
