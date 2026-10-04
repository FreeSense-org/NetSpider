using System.Globalization;
using System.Net;
using System.Text;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.Export.Exporters;

/// <summary>
/// One self-contained HTML file (inline CSS/JS/SVG, PNG as base64) in the app's dark neon style: health gauge and checks,
/// topology snapshot, alerts, sortable device inventory, WAN and port mappings, segments, VLANs and DHCP servers.
/// </summary>
public sealed class HtmlReportExporter : IExporter
{
    public string Name => "HTML report";
    public string FileExtension => ".html";

    public async Task ExportAsync(string path, ExportData data, CancellationToken ct = default)
    {
        var html = Build(data, DateTimeOffset.Now);
        ExportFile.EnsureDirectory(path);
        await File.WriteAllTextAsync(path, html, new UTF8Encoding(false), ct).ConfigureAwait(false);
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
    private static string N(double v, string fmt = "0") => v.ToString(fmt, CultureInfo.InvariantCulture);

    public static string Build(ExportData data, DateTimeOffset now)
    {
        var net = data.Network;
        var devices = data.Devices.Where(d => !SyntheticNodes.IsGraphOnly(d.Mac))
            .OrderBy(d => ExportText.IpSortKey(d.PrimaryIPv4)).ThenBy(d => d.Mac).ToList();
        var health = net.Health;
        var alerts = data.Alerts.OrderByDescending(a => a.Time).ToList();
        string networkName = ExportText.NetworkName(data);

        var sb = new StringBuilder(64 * 1024);
        sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
          .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
          .Append("<meta name=\"generator\" content=\"NetSpider ").Append(E(ExportText.AppVersion)).Append("\">\n")
          .Append("<title>NetSpider report: ").Append(E(networkName)).Append("</title>\n<style>").Append(Css).Append("</style>\n</head>\n<body>\n");

        // ---- header
        sb.Append("<header class=\"top\"><div class=\"brand\"><span class=\"logo\">").Append(SpiderSvg).Append("</span><span>NetSpider</span></div>")
          .Append("<div class=\"title\"><h1>").Append(E(networkName)).Append("</h1><div class=\"muted\">Network report generated ")
          .Append(E(ExportText.Time(now))).Append(data.Adapter is { } ad ? $" &middot; adapter {E(ad.Name)} ({E(ad.PrimaryV4?.ToString() ?? "no IPv4")})" : "")
          .Append("</div></div></header>\n<main>\n");

        // ---- KPIs
        int online = devices.Count(d => d.State == DeviceState.Online);
        int crit = alerts.Count(a => a.Severity == AlertSeverity.Critical), warn = alerts.Count(a => a.Severity == AlertSeverity.Warning);
        sb.Append("<section class=\"kpis\">");
        Kpi(sb, "Devices", devices.Count.ToString(CultureInfo.InvariantCulture), $"{online} online");
        Kpi(sb, "Links", data.Links.Count.ToString(CultureInfo.InvariantCulture), "topology edges");
        Kpi(sb, "Alerts", alerts.Count.ToString(CultureInfo.InvariantCulture), $"{crit} critical, {warn} warning");
        Kpi(sb, "Segments", net.Segments.Count.ToString(CultureInfo.InvariantCulture), $"{net.Vlans.Count} VLANs");
        Kpi(sb, "Health", health.Time == DateTimeOffset.MinValue ? "n/a" : N(health.OverallScore), "score / 100");
        sb.Append("</section>\n");

        // ---- health
        sb.Append("<section class=\"panel\" id=\"health\"><h2>Network health</h2><div class=\"health\">");
        sb.Append(Gauge(health.Time == DateTimeOffset.MinValue ? null : health.OverallScore));
        sb.Append("<div class=\"grow\">");
        if (health.Checks.Count == 0) sb.Append("<p class=\"muted\">No health checks have been run.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>Check</th><th>Status</th><th>Score</th><th>Summary</th></tr></thead><tbody>");
            foreach (var c in health.Checks)
            {
                sb.Append("<tr><td>").Append(E(c.Name)).Append("</td><td>").Append(Pill(c.Status.ToString(), c.Status switch
                {
                    HealthStatus.Pass => "ok", HealthStatus.Warn => "warn", HealthStatus.Fail => "bad", _ => "dim",
                })).Append("</td><td class=\"num\">").Append(c.Score).Append("</td><td>").Append(E(c.Summary));
                if (!string.IsNullOrWhiteSpace(c.Details)) sb.Append("<div class=\"muted small\">").Append(E(c.Details)).Append("</div>");
                sb.Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div></div></section>\n");

        // ---- topology
        if (data.TopologyPng is { Length: > 0 } png)
        {
            sb.Append("<section class=\"panel\" id=\"topology\"><h2>Topology snapshot</h2><img class=\"topo\" alt=\"Network topology\" src=\"data:image/png;base64,")
              .Append(Convert.ToBase64String(png)).Append("\"></section>\n");
        }

        // ---- alerts
        sb.Append("<section class=\"panel\" id=\"alerts\"><h2>Alerts</h2>");
        if (alerts.Count == 0) sb.Append("<p class=\"muted\">No alerts were raised.</p>");
        else
        {
            sb.Append("<div class=\"chips\">");
            foreach (var g in alerts.GroupBy(a => a.Kind).OrderByDescending(g => g.Max(a => a.Severity)).ThenByDescending(g => g.Count()))
                sb.Append("<span class=\"chip ").Append(SevClass(g.Max(a => a.Severity))).Append("\">").Append(E(g.Key.ToString())).Append(" <b>").Append(g.Count()).Append("</b></span>");
            sb.Append("</div><table class=\"sortable\"><thead><tr><th>Time</th><th>Severity</th><th>Kind</th><th>Title</th><th>Details</th><th>Source</th></tr></thead><tbody>");
            foreach (var a in alerts.Take(200))
            {
                sb.Append("<tr><td data-v=\"").Append(a.Time.ToUnixTimeMilliseconds()).Append("\">").Append(E(ExportText.Time(a.Time)))
                  .Append("</td><td data-v=\"").Append((int)a.Severity).Append("\">").Append(Pill(a.Severity.ToString(), SevClass(a.Severity)))
                  .Append("</td><td>").Append(E(a.Kind.ToString())).Append("</td><td>").Append(E(a.Title))
                  .Append("</td><td>").Append(E(a.Details)).Append("</td><td class=\"mono\">").Append(E(a.Source?.ToString())).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
            if (alerts.Count > 200) sb.Append("<p class=\"muted\">Showing the 200 most recent of ").Append(alerts.Count).Append(" alerts.</p>");
        }
        sb.Append("</section>\n");

        // ---- inventory
        sb.Append("<section class=\"panel\" id=\"devices\"><h2>Device inventory <span class=\"muted\">(").Append(devices.Count).Append(")</span></h2>")
          .Append("<input id=\"filter\" class=\"filter\" type=\"search\" placeholder=\"Filter devices...\" aria-label=\"Filter devices\">")
          .Append("<div class=\"scroll\"><table class=\"sortable\" id=\"inventory\"><thead><tr>")
          .Append("<th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Model</th><th>Type</th><th>OS</th><th>L2 ms</th><th>L3 ms</th><th>Open ports</th><th>State</th><th>First seen</th><th>Last seen</th>")
          .Append("</tr></thead><tbody>");
        foreach (var d in devices)
        {
            var ip = d.PrimaryIPv4;
            var l2 = d.Latency.Last(LatencyKind.Arp) ?? d.Latency.Last(LatencyKind.Ndp);
            var l3 = d.Latency.Last(LatencyKind.Icmp);
            string vendor = d.Brand ?? d.OuiVendor ?? "";
            sb.Append("<tr class=\"dev").Append(d.Has(DeviceFlags.New) ? " new" : "").Append("\">")
              .Append("<td>").Append(E(d.DisplayName));
            if (d.Has(DeviceFlags.New)) sb.Append(" <span class=\"pill info\">NEW</span>");
            if (d.Has(DeviceFlags.Gateway)) sb.Append(" <span class=\"pill acc\">GW</span>");
            if (d.Has(DeviceFlags.ThisHost)) sb.Append(" <span class=\"pill acc\">THIS PC</span>");
            sb.Append("</td><td class=\"mono\" data-v=\"").Append(ExportText.Ipv4Number(ip)).Append("\">")
              .Append(E(ip?.ToString() ?? d.IPv6.FirstOrDefault()?.Address.ToString()))
              .Append("</td><td class=\"mono\">").Append(E(d.Mac.ToString()))
              .Append("</td><td>").Append(E(vendor))
              .Append("</td><td>").Append(E(d.Model))
              .Append("</td><td>").Append(E(d.Type.ToString()))
              .Append("</td><td>").Append(E(d.OsGuess))
              .Append("</td><td class=\"num\" data-v=\"").Append(l2 is { } a2 ? N(a2, "0.###") : "").Append("\">").Append(E(ExportText.Ms(l2)))
              .Append("</td><td class=\"num\" data-v=\"").Append(l3 is { } a3 ? N(a3, "0.###") : "").Append("\">").Append(E(ExportText.Ms(l3)))
              .Append("</td><td>").Append(E(ExportText.OpenPorts(d)))
              .Append("</td><td>").Append(Pill(d.State.ToString(), d.State switch { DeviceState.Online => "ok", DeviceState.Flapping => "warn", _ => "dim" }))
              .Append("</td><td data-v=\"").Append(d.FirstSeen.ToUnixTimeSeconds()).Append("\">").Append(E(ExportText.Time(d.FirstSeen)))
              .Append("</td><td data-v=\"").Append(d.LastSeen.ToUnixTimeSeconds()).Append("\">").Append(E(ExportText.Time(d.LastSeen)))
              .Append("</td></tr>\n");
        }
        sb.Append("</tbody></table></div></section>\n");

        // ---- WAN + port mappings
        var wan = net.Wan;
        sb.Append("<section class=\"grid2\"><div class=\"panel\" id=\"wan\"><h2>WAN</h2>");
        if (wan is null) sb.Append("<p class=\"muted\">No gateway (UPnP IGD / NAT-PMP) information.</p>");
        else
        {
            sb.Append("<dl>");
            Dl(sb, "External IP", wan.ExternalIp?.ToString());
            Dl(sb, "Status", wan.ConnectionStatus);
            Dl(sb, "Connection", wan.ConnectionType);
            Dl(sb, "Uptime", ExportText.Duration(wan.Uptime));
            Dl(sb, "Gateway", wan.GatewayModel);
            Dl(sb, "Method", wan.Method);
            Dl(sb, "Updated", ExportText.Time(wan.Time));
            sb.Append("</dl>");
        }
        var path = net.InternetPath;
        if (path.Count > 0)
        {
            sb.Append("<h3>Internet path</h3><table><thead><tr><th>Hop</th><th>Address</th><th>Host</th><th>RTT ms</th></tr></thead><tbody>");
            foreach (var h in path)
                sb.Append("<tr><td class=\"num\">").Append(h.Ttl).Append("</td><td class=\"mono\">").Append(E(h.Address?.ToString() ?? "*"))
                  .Append("</td><td>").Append(E(h.Hostname)).Append("</td><td class=\"num\">").Append(E(ExportText.Ms(h.RttMs))).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div><div class=\"panel\" id=\"portmaps\"><h2>Port mappings</h2>");
        var maps = wan?.PortMappings ?? [];
        if (maps.Count == 0) sb.Append("<p class=\"muted\">No port mappings reported by the gateway.</p>");
        else
        {
            sb.Append("<table class=\"sortable\"><thead><tr><th>Proto</th><th>External</th><th>Internal client</th><th>Internal</th><th>Description</th><th>Enabled</th><th>Lease</th></tr></thead><tbody>");
            foreach (var m in maps)
                sb.Append("<tr><td>").Append(E(m.Protocol)).Append("</td><td class=\"num\">").Append(m.ExternalPort).Append("</td><td class=\"mono\">")
                  .Append(E(m.InternalClient?.ToString())).Append("</td><td class=\"num\">").Append(m.InternalPort).Append("</td><td>").Append(E(m.Description))
                  .Append("</td><td>").Append(m.Enabled ? Pill("yes", "ok") : Pill("no", "dim")).Append("</td><td>")
                  .Append(E(m.Lease is { } l && l > TimeSpan.Zero ? ExportText.Duration(l) : "permanent")).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div></section>\n");

        // ---- segments / VLANs / DHCP
        sb.Append("<section class=\"grid2\"><div class=\"panel\" id=\"vlans\"><h2>Segments &amp; VLANs</h2>");
        var segs = net.Segments;
        if (segs.Count > 0)
        {
            sb.Append("<table><thead><tr><th>Subnet</th><th>VLAN</th><th>Gateway</th><th>Hosts</th><th>Source</th></tr></thead><tbody>");
            foreach (var s in segs)
                sb.Append("<tr><td class=\"mono\">").Append(E(s.Cidr)).Append(s.IsLocal ? " <span class=\"pill acc\">local</span>" : "").Append("</td><td>")
                  .Append(E(s.VlanId?.ToString(CultureInfo.InvariantCulture))).Append(s.VlanName is { } vn ? " " + E(vn) : "")
                  .Append("</td><td class=\"mono\">").Append(E(s.Gateway?.ToString())).Append("</td><td class=\"num\">").Append(s.HostsFound)
                  .Append("</td><td>").Append(E(s.Source)).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        var vlans = net.Vlans;
        if (vlans.Count == 0) sb.Append("<p class=\"muted\">No VLANs detected").Append(net.NicPassesVlanTags == false ? " (this NIC strips 802.1Q tags)." : ".").Append("</p>");
        else
        {
            sb.Append("<h3>VLANs</h3><table><thead><tr><th>ID</th><th>Name</th><th>Role</th><th>Source</th></tr></thead><tbody>");
            foreach (var v in vlans)
                sb.Append("<tr><td class=\"num\">").Append(v.Id).Append("</td><td>").Append(E(v.Name)).Append("</td><td>")
                  .Append(v.Native ? Pill("native", "acc") + " " : "").Append(v.Voice ? Pill("voice", "info") : "")
                  .Append("</td><td>").Append(E(v.Source)).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div><div class=\"panel\" id=\"dhcp\"><h2>DHCP servers</h2>");
        var dhcp = net.DhcpServers;
        if (dhcp.Count == 0) sb.Append("<p class=\"muted\">No DHCP servers observed.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>Server</th><th>MAC</th><th>Offered</th><th>Router</th><th>DNS</th><th>Lease</th><th></th></tr></thead><tbody>");
            foreach (var s in dhcp)
                sb.Append("<tr").Append(s.IsRogue ? " class=\"rogue\"" : "").Append("><td class=\"mono\">").Append(E(s.ServerIp.ToString()))
                  .Append("</td><td class=\"mono\">").Append(E(s.ServerMac.ToString())).Append("</td><td class=\"mono\">").Append(E(s.OfferedIp?.ToString()))
                  .Append("</td><td class=\"mono\">").Append(E(s.Router?.ToString())).Append("</td><td class=\"mono\">").Append(E(string.Join(", ", s.Dns)))
                  .Append("</td><td>").Append(E(ExportText.Duration(s.Lease))).Append("</td><td>").Append(s.IsRogue ? Pill("ROGUE", "bad") : Pill("ok", "ok"))
                  .Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div></section>\n");

        // ---- footer
        sb.Append("</main>\n<footer>Generated by NetSpider ").Append(E(ExportText.AppVersion)).Append(" on ").Append(E(ExportText.Time(now)))
          .Append(" &middot; ").Append(devices.Count).Append(" devices &middot; latency values below 0.1 ms are shown as &lt;0.1</footer>\n");
        sb.Append("<script>").Append(Script).Append("</script>\n</body>\n</html>\n");
        return sb.ToString();
    }

    private static void Kpi(StringBuilder sb, string label, string value, string sub) =>
        sb.Append("<div class=\"kpi\"><div class=\"muted small\">").Append(E(label)).Append("</div><div class=\"big\">").Append(E(value))
          .Append("</div><div class=\"muted small\">").Append(E(sub)).Append("</div></div>");

    private static void Dl(StringBuilder sb, string k, string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return;
        sb.Append("<dt>").Append(E(k)).Append("</dt><dd>").Append(E(v)).Append("</dd>");
    }

    private static string Pill(string text, string cls) => $"<span class=\"pill {cls}\">{E(text)}</span>";

    private static string SevClass(AlertSeverity s) => s switch { AlertSeverity.Critical => "bad", AlertSeverity.Warning => "warn", _ => "info" };

    /// <summary>Inline SVG ring gauge for a 0-100 score.</summary>
    internal static string Gauge(int? score)
    {
        const double r = 52, c = 2 * Math.PI * r;
        double frac = score is { } s ? Math.Clamp(s, 0, 100) / 100.0 : 0;
        string color = score switch { null => "#3A4A66", >= 80 => "#2EE6A6", >= 50 => "#FFB547", _ => "#FF4D6D" };
        return $"""
            <svg class="gauge" viewBox="0 0 140 140" width="160" height="160" role="img" aria-label="Health score {(score?.ToString(CultureInfo.InvariantCulture) ?? "not available")}">
            <defs><filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
            <circle cx="70" cy="70" r="{N(r)}" fill="none" stroke="#14203A" stroke-width="12"/>
            <circle cx="70" cy="70" r="{N(r)}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round" filter="url(#glow)"
              stroke-dasharray="{N(c * frac, "0.##")} {N(c, "0.##")}" transform="rotate(-90 70 70)"/>
            <text x="70" y="78" text-anchor="middle" font-size="34" font-weight="700" fill="{color}">{(score?.ToString(CultureInfo.InvariantCulture) ?? "n/a")}</text>
            <text x="70" y="98" text-anchor="middle" font-size="10" fill="#7A8BA8">HEALTH</text>
            </svg>
            """;
    }

    private const string SpiderSvg = """<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#22D3EE" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 2v7M12 15v7M2 12h7M15 12h7M5 5l5 5M14 14l5 5M19 5l-5 5M10 14l-5 5"/></svg>""";

    private const string Css = """
        :root{--bg:#070B14;--panel:#0C1322;--panel2:#101A2E;--line:#1A2740;--text:#D6E2F5;--muted:#7A8BA8;--acc:#22D3EE;--ok:#2EE6A6;--warn:#FFB547;--bad:#FF4D6D;--info:#5B9DFF}
        *{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
        body{background:radial-gradient(1200px 600px at 10% -10%,rgba(34,211,238,.10),transparent 60%),radial-gradient(900px 500px at 110% 10%,rgba(91,157,255,.08),transparent 60%),var(--bg);min-height:100vh}
        .top{display:flex;gap:24px;align-items:center;padding:20px 28px;border-bottom:1px solid var(--line);background:rgba(7,11,20,.85)}
        .brand{display:flex;gap:8px;align-items:center;color:var(--acc);font-weight:700;letter-spacing:.08em;text-transform:uppercase;text-shadow:0 0 12px rgba(34,211,238,.6)}
        .logo svg{filter:drop-shadow(0 0 6px rgba(34,211,238,.8))}
        h1{margin:0;font-size:22px;font-weight:600}h2{margin:0 0 12px;font-size:16px;color:var(--acc);letter-spacing:.04em}h3{margin:16px 0 8px;font-size:14px;color:var(--muted)}
        main{padding:20px 28px;display:flex;flex-direction:column;gap:18px;max-width:1600px;margin:0 auto}
        .panel{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:0 0 0 1px rgba(34,211,238,.03),0 8px 24px rgba(0,0,0,.35);min-width:0}
        .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
        .kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 16px}.big{font-size:28px;font-weight:700;color:var(--acc);text-shadow:0 0 10px rgba(34,211,238,.35)}
        .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:18px}
        .health{display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap}.grow{flex:1;min-width:300px}
        .muted{color:var(--muted)}.small{font-size:12px}.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}.num{text-align:right;font-variant-numeric:tabular-nums}
        table{width:100%;border-collapse:collapse}th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
        th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0;background:var(--panel2)}
        table.sortable th{cursor:pointer;user-select:none}table.sortable th:hover{color:var(--acc)}th.asc::after{content:" \25B2";color:var(--acc)}th.desc::after{content:" \25BC";color:var(--acc)}
        tbody tr:hover{background:rgba(34,211,238,.05)}tr.new td:first-child{box-shadow:inset 3px 0 0 var(--info)}tr.rogue{background:rgba(255,77,109,.08)}
        .scroll{overflow:auto;max-height:75vh;border-radius:8px}
        .pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;line-height:1.5}
        .ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info{color:var(--info)}.acc{color:var(--acc)}.dim{color:var(--muted)}
        .chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.chip{border:1px solid currentColor;border-radius:8px;padding:3px 10px;font-size:12px}
        .topo{max-width:100%;border-radius:10px;border:1px solid var(--line);display:block;margin:0 auto;background:#05080F}
        .filter{width:100%;max-width:360px;margin:0 0 10px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--text)}
        .filter:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 2px rgba(34,211,238,.25)}
        dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}
        footer{padding:18px 28px 28px;color:var(--muted);font-size:12px;text-align:center;border-top:1px solid var(--line)}
        @media (max-width:700px){main,.top{padding:14px 16px}.grid2{grid-template-columns:1fr}.top{flex-direction:column;align-items:flex-start;gap:8px}}
        @media print{body{background:#fff;color:#000}.panel,.kpi{box-shadow:none}}
        """;

    private const string Script = """
        (function(){
          function val(td){var v=td.getAttribute('data-v');return v!==null&&v!==''?v:td.textContent.trim();}
          document.querySelectorAll('table.sortable').forEach(function(t){
            var ths=t.tHead?t.tHead.rows[0].cells:[];
            Array.prototype.forEach.call(ths,function(th,i){
              th.addEventListener('click',function(){
                var asc=!th.classList.contains('asc');
                Array.prototype.forEach.call(ths,function(h){h.classList.remove('asc','desc');});
                th.classList.add(asc?'asc':'desc');
                var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows);
                rows.sort(function(a,b){
                  var x=val(a.cells[i]),y=val(b.cells[i]),nx=parseFloat(x),ny=parseFloat(y);
                  var c=(!isNaN(nx)&&!isNaN(ny)&&isFinite(x)&&isFinite(y))?nx-ny:(x===''?1:y===''?-1:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'}));
                  return asc?c:-c;});
                rows.forEach(function(r){body.appendChild(r);});
              });
            });
          });
          var f=document.getElementById('filter');
          if(f){f.addEventListener('input',function(){var q=f.value.toLowerCase();
            document.querySelectorAll('#inventory tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';});});}
        })();
        """;
}
