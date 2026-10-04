using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

/// <summary>CoAP GET /.well-known/core (UDP 5683) to enumerate a constrained device's resources.</summary>
public sealed class CoapProbe : IDeviceProbe
{
    private readonly IDeviceStore _store;
    private readonly ILogger<CoapProbe> _log;

    public CoapProbe(IDeviceStore store, ILogger<CoapProbe> log) { _store = store; _log = log; }

    public string Name => "CoAP";
    public int Order => 361;

    public bool AppliesTo(Device device, ScanContext ctx) => device.PrimaryIPv4 is not null;

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        try
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(ctx.LocalIPv4 ?? IPAddress.Any, 0));
            await udp.SendToAsync(BuildWellKnownCoreGet(), SocketFlags.None, new IPEndPoint(ip, 5683), ct).ConfigureAwait(false);

            var buf = new byte[4096];
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(1000);
            var from = new IPEndPoint(IPAddress.Any, 0);
            var r = await udp.ReceiveFromAsync(buf, SocketFlags.None, from, timeoutCts.Token).ConfigureAwait(false);
            if (r.ReceivedBytes <= 4) return;

            var payload = ExtractPayload(buf.AsSpan(0, r.ReceivedBytes));
            bool changed = device.AddEvidence("coap", Fields.Service, "CoAP", Confidence.Port);
            changed |= device.AddEvidence("coap", Fields.DeviceType, nameof(DeviceType.IoT), Confidence.Port);
            if (payload.Length > 0) changed |= device.SetProperty("coap.resources", Encoding.UTF8.GetString(payload));
            if (changed) _store.NotifyChanged(device, "coap");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "CoAP {Ip}", ip); }
    }

    /// <summary>Confirmable GET for /.well-known/core (two Uri-Path options).</summary>
    public static byte[] BuildWellKnownCoreGet()
    {
        using var ms = new MemoryStream();
        // version 1, type CON(0), token length 0; code 0.01 GET (1); message id
        ms.WriteByte(0x40);
        ms.WriteByte(0x01);
        ushort mid = (ushort)Random.Shared.Next(1, 0xFFFF);
        ms.WriteByte((byte)(mid >> 8));
        ms.WriteByte((byte)(mid & 0xFF));
        // Uri-Path option 11: ".well-known" then "core". First option delta 11.
        WriteOption(ms, 11, 0, ".well-known");
        WriteOption(ms, 11, 11, "core");
        return ms.ToArray();
    }

    private static void WriteOption(Stream s, int optionNumber, int prevOption, string value)
    {
        int delta = optionNumber - prevOption;
        var val = Encoding.ASCII.GetBytes(value);
        int len = val.Length;
        int deltaNibble = delta < 13 ? delta : 13;
        int lenNibble = len < 13 ? len : 13;
        s.WriteByte((byte)((deltaNibble << 4) | lenNibble));
        if (delta >= 13) s.WriteByte((byte)(delta - 13));
        if (len >= 13) s.WriteByte((byte)(len - 13));
        s.Write(val);
    }

    private static ReadOnlySpan<byte> ExtractPayload(ReadOnlySpan<byte> msg)
    {
        // find the 0xFF payload marker
        int idx = msg.IndexOf((byte)0xFF);
        return idx >= 0 && idx + 1 < msg.Length ? msg[(idx + 1)..] : ReadOnlySpan<byte>.Empty;
    }
}
