using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetSpider.Discovery.Services.PortScan;

/// <summary>Result of a banner grab against one open port.</summary>
public sealed record BannerResult(
    string Protocol, string? Raw, string? ServerHeader, string? Title, string? Realm, string? RedirectLocation,
    bool HasLoginForm, bool IsHttps);

/// <summary>Light-touch banner grabbing for HTTP(S), SSH, FTP, SMTP, Telnet and RTSP. Pure parsing helpers are static.</summary>
public static partial class BannerGrabber
{
    [GeneratedRegex("<title>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TitleRegex();
    [GeneratedRegex("realm=\"([^\"]*)\"", RegexOptions.IgnoreCase)]
    private static partial Regex RealmRegex();

    public static async Task<BannerResult?> GrabAsync(IPAddress ip, int port, bool https, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port, timeoutCts.Token).ConfigureAwait(false);
            Stream stream = client.GetStream();
            if (https)
            {
                var ssl = new System.Net.Security.SslStream(stream, false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = ip.ToString() }, timeoutCts.Token).ConfigureAwait(false);
                stream = ssl;
            }

            if (IsHttpPort(port) || https) return await HttpAsync(stream, ip, port, https, timeoutCts.Token).ConfigureAwait(false);
            if (port is 554 or 8554) return await RtspAsync(stream, ip, port, timeoutCts.Token).ConfigureAwait(false);
            // line-oriented services (SSH/FTP/SMTP/Telnet) send a banner first
            return await LineAsync(stream, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return null; }
        catch { return null; }
    }

    private static bool IsHttpPort(int p) => p is 80 or 81 or 82 or 83 or 591 or 2082 or 2095 or 8000 or 8008 or 8080 or 8081 or 8088 or 8123 or 8443 or 9080 or 9090;

    private static async Task<BannerResult> HttpAsync(Stream stream, IPAddress ip, int port, bool https, CancellationToken ct)
    {
        var req = $"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetSpider\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(req), ct).ConfigureAwait(false);
        var text = await ReadAllAsync(stream, 16384, ct).ConfigureAwait(false);
        return ParseHttp(text, https);
    }

    public static BannerResult ParseHttp(string text, bool https)
    {
        var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerBlock = headerEnd >= 0 ? text[..headerEnd] : text;
        string? server = null, location = null;
        foreach (var line in headerBlock.Split('\n'))
        {
            var l = line.TrimEnd('\r');
            if (l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase)) server = l[7..].Trim();
            else if (l.StartsWith("Location:", StringComparison.OrdinalIgnoreCase)) location = l[9..].Trim();
        }
        var realmMatch = RealmRegex().Match(headerBlock);
        var titleMatch = TitleRegex().Match(text);
        var title = titleMatch.Success ? WebUtility(titleMatch.Groups[1].Value.Trim()) : null;
        bool loginForm = text.Contains("type=\"password\"", StringComparison.OrdinalIgnoreCase) || text.Contains("name=\"password\"", StringComparison.OrdinalIgnoreCase);
        return new BannerResult("http", Trunc(text, 512), server, title, realmMatch.Success ? realmMatch.Groups[1].Value : null, location, loginForm, https);
    }

    private static async Task<BannerResult> RtspAsync(Stream stream, IPAddress ip, int port, CancellationToken ct)
    {
        var req = $"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NetSpider\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(req), ct).ConfigureAwait(false);
        var text = await ReadAllAsync(stream, 4096, ct).ConfigureAwait(false);
        string? server = text.Split('\n').FirstOrDefault(l => l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))?[7..].Trim();
        return new BannerResult("rtsp", Trunc(text, 256), server, null, null, null, false, false);
    }

    private static async Task<BannerResult> LineAsync(Stream stream, CancellationToken ct)
    {
        var text = await ReadAllAsync(stream, 1024, ct).ConfigureAwait(false);
        var firstLine = text.Split('\n').FirstOrDefault()?.TrimEnd('\r');
        return new BannerResult("line", firstLine, null, null, null, null, false, false);
    }

    private static async Task<string> ReadAllAsync(Stream stream, int cap, CancellationToken ct)
    {
        var buf = new byte[cap];
        int total = 0;
        try
        {
            while (total < cap)
            {
                int n = await stream.ReadAsync(buf.AsMemory(total, cap - total), ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
                if (total >= 16 && stream is NetworkStream ns && !ns.DataAvailable) break;
            }
        }
        catch { }
        return Encoding.Latin1.GetString(buf, 0, total);
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n];
    private static string WebUtility(string s) => System.Net.WebUtility.HtmlDecode(s);
}
