using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Discovery.Vendor;

/// <summary>Sends an anonymous MQTT CONNECT to port 1883 and reads the CONNACK; return code 0 means an open broker.</summary>
public sealed class MqttProbe : IDeviceProbe
{
    private readonly IDeviceStore _store;
    private readonly ILogger<MqttProbe> _log;

    public MqttProbe(IDeviceStore store, ILogger<MqttProbe> log) { _store = store; _log = log; }

    public string Name => "MQTT";
    public int Order => 360;

    public bool AppliesTo(Device device, ScanContext ctx) =>
        device.PrimaryIPv4 is not null && device.Ports.Any(p => p.Port == 1883 && p.State == PortState.Open);

    public async Task ProbeAsync(Device device, ScanContext ctx, CancellationToken ct)
    {
        var ip = device.PrimaryIPv4;
        if (ip is null) return;
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(2));
            using var client = new TcpClient();
            await client.ConnectAsync(ip, 1883, timeoutCts.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            await stream.WriteAsync(BuildConnect(), timeoutCts.Token).ConfigureAwait(false);

            var buf = new byte[8];
            int n = await stream.ReadAsync(buf, timeoutCts.Token).ConfigureAwait(false);
            bool changed = device.AddEvidence("mqtt", Fields.Service, "MQTT broker", Confidence.Port);
            // CONNACK: 0x20, remaining length 0x02, flags, return code
            if (n >= 4 && buf[0] == 0x20)
            {
                byte rc = buf[3];
                if (rc == 0)
                {
                    changed |= device.SetProperty("mqtt.anonymous", "true");
                    changed |= device.AddEvidence("mqtt", Fields.Service, "MQTT broker (anonymous)", Confidence.VendorProtocol);
                }
                else changed |= device.SetProperty("mqtt.connack", rc.ToString());
                changed |= device.AddEvidence("mqtt", Fields.DeviceType, nameof(DeviceType.IoT), Confidence.Port);
            }
            if (changed) _store.NotifyChanged(device, "mqtt");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogDebug(ex, "MQTT {Ip}", ip); }
    }

    /// <summary>MQTT 3.1.1 CONNECT with a random client id, clean session, no credentials.</summary>
    public static byte[] BuildConnect()
    {
        var clientId = "netspider" + Random.Shared.Next(1000, 9999);
        var cidBytes = System.Text.Encoding.ASCII.GetBytes(clientId);
        using var ms = new MemoryStream();
        var vh = new MemoryStream();
        // protocol name "MQTT"
        vh.Write(new byte[] { 0x00, 0x04, (byte)'M', (byte)'Q', (byte)'T', (byte)'T' });
        vh.WriteByte(0x04);       // protocol level 4
        vh.WriteByte(0x02);       // connect flags: clean session
        vh.Write(new byte[] { 0x00, 0x3C }); // keepalive 60s
        // payload: client id
        vh.WriteByte((byte)(cidBytes.Length >> 8));
        vh.WriteByte((byte)(cidBytes.Length & 0xFF));
        vh.Write(cidBytes);
        var body = vh.ToArray();

        ms.WriteByte(0x10); // CONNECT
        WriteRemainingLength(ms, body.Length);
        ms.Write(body);
        return ms.ToArray();
    }

    private static void WriteRemainingLength(Stream s, int len)
    {
        do
        {
            byte b = (byte)(len % 128);
            len /= 128;
            if (len > 0) b |= 0x80;
            s.WriteByte(b);
        } while (len > 0);
    }
}
