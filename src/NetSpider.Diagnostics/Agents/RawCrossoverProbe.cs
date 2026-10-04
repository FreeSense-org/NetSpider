using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Model;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetSpider.Diagnostics.Agents;

/// <summary>Outcome of a raw crossover run from one local adapter to another.</summary>
public sealed record CrossoverResult(string From, string To, int Sent, int Received, double? OneWayAvgMs, double? OneWayMinMs, double? OneWayMaxMs,
    string Via, string? Error, DateTimeOffset Time)
{
    public double LossPercent => Sent == 0 ? 100 : 100.0 * (Sent - Received) / Sent;
    public bool Ok => Error is null && Received > 0;
}

/// <summary>
/// True LAN↔Wi-Fi crossover test on one PC. Windows short-circuits IP traffic between two of its own addresses inside
/// the stack, so a plain ping from the wired IP to the Wi-Fi IP never touches the network. This probe bypasses the
/// stack with Npcap: it injects ICMP echo frames on adapter A addressed at L2 to adapter B (same subnet) or to A's
/// gateway (routed), and captures them arriving on adapter B. Both pcap timestamps come from this PC's clock, so the
/// difference is a genuine <b>one-way</b> latency across switch → AP (or AP → switch). Frames carry a random nonce
/// and are matched on it; the receiving OS answers the echo internally, which is harmless.
/// </summary>
public sealed class RawCrossoverProbe
{
    public const ushort IcmpId = 0x4E58; // "NX"
    private static readonly byte[] Magic = "NSXO"u8.ToArray();
    private readonly ILogger _log;

    public RawCrossoverProbe(ILogger log) => _log = log;

    /// <summary>true when Npcap can be loaded in this process.</summary>
    public static bool Available
    {
        get
        {
            try { return LibPcapLiveDeviceList.Instance.Count > 0; }
            catch { return false; }
        }
    }

    public async Task<CrossoverResult> MeasureAsync(LocalVantage from, LocalVantage to, int count, CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        if (from.Mac is null || to.Mac is null || !Mac.TryParse(from.Mac, out var fromMac) || !Mac.TryParse(to.Mac, out var toMac))
            return new CrossoverResult(from.Name, to.Name, 0, 0, null, null, null, "", "adapter MAC unknown", now);

        LibPcapLiveDevice? tx = null, rx = null;
        try
        {
            var devices = LibPcapLiveDeviceList.New();
            tx = FindDevice(devices, fromMac);
            rx = FindDevice(devices, toMac);
            if (tx is null || rx is null)
                return new CrossoverResult(from.Name, to.Name, 0, 0, null, null, null, "", "Npcap device for adapter not found", now);

            // L2 next hop: the peer itself on a shared subnet, otherwise our gateway (the router forwards it to the peer).
            bool sameSubnet = IpUtil.InSubnet(to.Ip, IpUtil.NetworkAddress(from.Ip, from.PrefixLength), from.PrefixLength);
            Mac dstMac;
            string via;
            if (sameSubnet) { dstMac = toMac; via = "same subnet (switch ↔ AP bridge)"; }
            else if (from.Gateway is not null && ResolveMac(from.Gateway, from.Ip) is { } gwMac) { dstMac = gwMac; via = $"routed via {from.Gateway}"; }
            else return new CrossoverResult(from.Name, to.Name, 0, 0, null, null, null, "", "no L2 next hop (gateway MAC unresolved)", now);

            var nonce = RandomNumberGenerator.GetBytes(8);
            var sentAt = new ConcurrentDictionary<ushort, DateTime>();
            var arrivedAt = new ConcurrentDictionary<ushort, DateTime>();

            var cfg = new DeviceConfiguration
            {
                Mode = DeviceModes.MaxResponsiveness, ReadTimeout = 20, Immediate = true,
                TimestampResolution = TimestampResolution.Microsecond, TimestampType = TimestampType.HostHighPrecision,
            };
            rx.Open(cfg);
            rx.Filter = "icmp";
            rx.OnPacketArrival += (_, e) =>
            {
                if (TryMatch(e.Data, nonce, out var seq)) arrivedAt.TryAdd(seq, e.Header.Timeval.Date);
            };
            tx.Open(cfg);
            tx.Filter = "icmp";
            tx.OnPacketArrival += (_, e) =>
            {
                // our own injected frame looped back by Npcap: its pcap timestamp shares the receiver's clock
                if (TryMatch(e.Data, nonce, out var seq)) sentAt[seq] = e.Header.Timeval.Date;
            };
            rx.StartCapture();
            tx.StartCapture();
            await Task.Delay(150, ct).ConfigureAwait(false);

            for (ushort seq = 1; seq <= count; seq++)
            {
                ct.ThrowIfCancellationRequested();
                var frame = BuildFrame(fromMac, dstMac, from.Ip, to.Ip, seq, nonce);
                sentAt.TryAdd(seq, DateTime.UtcNow); // fallback when the loop-back copy is not seen
                tx.SendPacket(frame);
                await Task.Delay(100, ct).ConfigureAwait(false);
            }
            await Task.Delay(600, ct).ConfigureAwait(false);

            var oneWay = arrivedAt
                .Where(kv => sentAt.ContainsKey(kv.Key))
                .Select(kv => Math.Max(0, (kv.Value - sentAt[kv.Key]).TotalMilliseconds))
                .ToList();
            return new CrossoverResult(from.Name, to.Name, count, arrivedAt.Count,
                oneWay.Count > 0 ? oneWay.Average() : null, oneWay.Count > 0 ? oneWay.Min() : null, oneWay.Count > 0 ? oneWay.Max() : null,
                via, arrivedAt.IsEmpty ? "no frames arrived on the other adapter" : null, now);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Raw crossover {From} → {To} failed", from.Name, to.Name);
            return new CrossoverResult(from.Name, to.Name, 0, 0, null, null, null, "", ex.Message, now);
        }
        finally
        {
            foreach (var d in new[] { tx, rx })
            {
                if (d is null) continue;
                try { d.StopCapture(); } catch { }
                try { d.Close(); } catch { }
            }
        }
    }

    private static LibPcapLiveDevice? FindDevice(LibPcapLiveDeviceList devices, Mac mac) =>
        devices.FirstOrDefault(d =>
        {
            try { return d.Interface?.MacAddress is { } pa && pa.GetAddressBytes().Length == 6 && Mac.FromPhysicalAddress(pa) == mac; }
            catch { return false; }
        });

    /// <summary>Ethernet + IPv4 + ICMP echo request carrying "NSXO" + nonce, id <see cref="IcmpId"/>.</summary>
    public static byte[] BuildFrame(Mac src, Mac dst, IPAddress srcIp, IPAddress dstIp, ushort seq, ReadOnlySpan<byte> nonce)
    {
        var icmp = new byte[8 + Magic.Length + nonce.Length];
        icmp[0] = 8; // echo request
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(4), IcmpId);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(6), seq);
        Magic.CopyTo(icmp.AsSpan(8));
        nonce.CopyTo(icmp.AsSpan(8 + Magic.Length));
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2), FrameBuilder.Checksum(icmp));
        return FrameBuilder.Ip4Frame(src, dst, srcIp, dstIp, 1, icmp, ttl: 64);
    }

    /// <summary>Matches our crossover echo request (any L2 addressing, with or without a VLAN tag).</summary>
    public static bool TryMatch(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> nonce, out ushort seq)
    {
        seq = 0;
        var eth = EthernetView.Parse(frame);
        if (!eth.Valid || eth.EtherType != EthernetView.Ipv4) return false;
        var ip = frame[eth.PayloadOffset..];
        if (ip.Length < 20 || ip[9] != 1) return false;
        int ihl = (ip[0] & 0x0F) * 4;
        if (ip.Length < ihl + 8 + Magic.Length + nonce.Length) return false;
        var icmp = ip[ihl..];
        if (icmp[0] != 8 || BinaryPrimitives.ReadUInt16BigEndian(icmp[4..]) != IcmpId) return false;
        if (!icmp.Slice(8, Magic.Length).SequenceEqual(Magic) || !icmp.Slice(8 + Magic.Length, nonce.Length).SequenceEqual(nonce)) return false;
        seq = BinaryPrimitives.ReadUInt16BigEndian(icmp[6..]);
        return true;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

    /// <summary>Resolves a neighbour's MAC through a specific local source address (Windows SendARP).</summary>
    private static Mac? ResolveMac(IPAddress target, IPAddress source)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var mac = new byte[6];
            int len = mac.Length;
#pragma warning disable CS0618 // Address is the network-order uint SendARP expects
            int rc = SendARP((uint)target.Address, (uint)source.Address, mac, ref len);
#pragma warning restore CS0618
            return rc == 0 && len == 6 ? Mac.FromBytes(mac) : null;
        }
        catch { return null; }
    }
}
