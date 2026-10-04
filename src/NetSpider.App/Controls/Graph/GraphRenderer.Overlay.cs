using NetSpider.App.Rendering;
using NetSpider.Core.Model;
using NetSpider.Core.Services;
using SkiaSharp;

namespace NetSpider.App.Controls.Graph;

public sealed partial class GraphRenderer
{
    // =====================================================================================================
    //  port matrix (patch-panel view of managed switches)
    // =====================================================================================================

    public const float PortW = 44, PortH = 34, PortGap = 12, PanelHeader = 62, PanelGap = 46;

    public readonly record struct PanelLayout(SwitchPanel Panel, SKRect Rect, (PortCell Port, SKRect Rect, bool Top)[] Ports);

    /// <summary>World-space layout of all switch panels (centered on the origin).</summary>
    private static readonly SKFont MeasureFont = new(Fonts.Regular, 10.5f);
    private static readonly SKFont MeasureTitle = new(Fonts.Bold, 15f);

    public static string PanelSubtitle(SwitchPanel p) => string.Join("  ·  ", new[]
    {
        p.Model, p.Ip, $"{p.Ports.Length} ports", $"{p.Ports.Count(x => x.Up == true)} up",
        p.Ports.Sum(x => x.PoeWatts ?? 0) is var poe and > 0 ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"PoE {poe:0.#} W") : null,
    }.Where(s => !string.IsNullOrEmpty(s)));

    public static List<PanelLayout> LayoutPanels(GraphSnapshot snap)
    {
        var result = new List<PanelLayout>();
        float y = 0;
        foreach (var p in snap.Panels)
        {
            int cols = Math.Max(4, (p.Ports.Length + 1) / 2);
            float w = 56 + cols * (PortW + PortGap) + 40;
            float headerW;
            lock (MeasureFont) headerW = 74 + Math.Max(MeasureFont.MeasureText(PanelSubtitle(p)), MeasureTitle.MeasureText(p.Name)) + 30;
            if (result.Count == 0) headerW += 270; // the first panel carries the LED legend
            w = Math.Max(w, headerW);
            float h = PanelHeader + 30 + PortH * 2 + 14 + 34 + 10;
            var rect = new SKRect(-w / 2, y, w / 2, y + h);
            var ports = new (PortCell, SKRect, bool)[p.Ports.Length];
            for (int i = 0; i < p.Ports.Length; i++)
            {
                // real switches: odd ports on top, even ports below
                int col = i / 2;
                bool top = i % 2 == 0;
                float portsW = cols * (PortW + PortGap) - PortGap;
                float px = rect.Left + Math.Max(56, (w - portsW) / 2) + col * (PortW + PortGap);
                float py = rect.Top + PanelHeader + 30 + (top ? 0 : PortH + 14);
                ports[i] = (p.Ports[i], new SKRect(px, py, px + PortW, py + PortH), top);
            }
            result.Add(new PanelLayout(p, rect, ports));
            y += h + PanelGap;
        }
        float shift = -(y - PanelGap) / 2;
        for (int i = 0; i < result.Count; i++)
        {
            var l = result[i];
            var r = l.Rect; r.Offset(0, shift);
            result[i] = new PanelLayout(l.Panel, r, l.Ports.Select(pp => { var rr = pp.Rect; rr.Offset(0, shift); return (pp.Port, rr, pp.Top); }).ToArray());
        }
        return result;
    }

    private void DrawPortMatrix(SKCanvas c, GraphSnapshot snap, GraphViewState v, double time, List<(SKRect, SwitchPanel, PortCell)> hits)
    {
        float t = (float)time;
        if (snap.Panels.Length == 0)
        {
            DrawEmptyPorts(c);
            return;
        }
        var mouseWorld = v.ToWorld(v.Mouse.X, v.Mouse.Y);
        foreach (var pl in LayoutPanels(snap))
        {
            var r = pl.Rect;
            // chassis
            _fill.Color = SKColors.Black.A(0.45f);
            _fill.MaskFilter = _blur10;
            c.DrawRoundRect(new SKRect(r.Left + 4, r.Top + 10, r.Right + 4, r.Bottom + 14), 14, 14, _fill);
            _fill.MaskFilter = null;
            using (var metal = SKShader.CreateLinearGradient(new SKPoint(0, r.Top), new SKPoint(0, r.Bottom),
                       [SKColor.Parse("#1B2741"), SKColor.Parse("#111A2D"), SKColor.Parse("#0C1322")], [0, 0.5f, 1], SKShaderTileMode.Clamp))
            {
                _fill.Shader = metal;
                c.DrawRoundRect(r, 14, 14, _fill);
                _fill.Shader = null;
            }
            _stroke.PathEffect = null;
            _stroke.StrokeWidth = 1.2f;
            _stroke.Color = Neon.Cyan.A(0.25f);
            c.DrawRoundRect(r, 14, 14, _stroke);
            // rack ears
            _fill.Color = SKColor.Parse("#0A101D");
            foreach (var ex in new[] { r.Left + 14, r.Right - 14 })
            {
                c.DrawCircle(ex, r.Top + 22, 4, _fill);
                c.DrawCircle(ex, r.Bottom - 22, 4, _fill);
            }

            // header: glyph/logo, name, model, IP
            var node = snap.Find(pl.Panel.Switch);
            Glyphs.Draw(c, node?.Type ?? DeviceType.AccessSwitch, r.Left + 46, r.Top + 32, 30, Neon.Cyan);
            _text.Color = Neon.Text;
            c.DrawText(pl.Panel.Name, r.Left + 74, r.Top + 30, SKTextAlign.Left, _fTitle, _text);
            _text.Color = Neon.TextDim;
            c.DrawText(PanelSubtitle(pl.Panel), r.Left + 74, r.Top + 47, SKTextAlign.Left, _fSmall, _text);

            foreach (var (port, pr, top) in pl.Ports)
            {
                hits.Add((pr, pl.Panel, port));
                bool hov = v.MouseInside && pr.Contains(mouseWorld);
                bool up = port.Up == true;
                var led = Neon.LedForSpeed(port.SpeedMbps, port.Up);
                var health = _diag.Port(pl.Panel.Switch, port.Name);
                SKColor? problemCol = health?.Problem is null ? null : ProblemColor(health);
                if (problemCol is { } pc && up) led = pc;
                bool hasSel = v.Selected is { } sm && port.Devices.Any(d => d.Mac == sm);

                // RJ45 socket
                _fill.Color = SKColor.Parse(hov ? "#22345A" : "#070C17");
                c.DrawRoundRect(pr, 4, 4, _fill);
                _path.Reset();
                float mx = pr.MidX;
                // keystone notch: on top row it points up, bottom row down
                float iy0 = top ? pr.Top + 7 : pr.Bottom - 7, iy1 = top ? pr.Bottom - 5 : pr.Top + 5;
                float tab = top ? pr.Top + 3 : pr.Bottom - 3;
                _path.MoveTo(pr.Left + 6, iy1);
                _path.LineTo(pr.Left + 6, iy0);
                _path.LineTo(mx - 7, iy0);
                _path.LineTo(mx - 7, tab);
                _path.LineTo(mx + 7, tab);
                _path.LineTo(mx + 7, iy0);
                _path.LineTo(pr.Right - 6, iy0);
                _path.LineTo(pr.Right - 6, iy1);
                _path.Close();
                _fill.Color = SKColor.Parse("#02050B");
                c.DrawPath(_path, _fill);
                _stroke.StrokeWidth = 1;
                _stroke.Color = (up ? led : Neon.Border).A(up ? 0.6f : 0.9f);
                c.DrawPath(_path, _stroke);
                // gold pins
                if (up)
                {
                    _stroke.Color = Neon.Amber.A(0.35f);
                    for (int k = 0; k < 6; k++)
                    {
                        float px = pr.Left + 11 + k * 4.4f;
                        c.DrawLine(px, top ? iy1 - 1 : iy1 + 1, px, top ? iy1 - 4 : iy1 + 4, _stroke);
                    }
                }

                // link LED with glow (blinks with simulated activity)
                float ledY = top ? pr.Top - 7 : pr.Bottom + 7;
                float blink = up ? 0.75f + 0.25f * MathF.Sin(t * (4 + port.Index % 5) + port.Index) : 1;
                var ledRect = new SKRect(pr.Left + 4, ledY - 2.5f, pr.Left + 16, ledY + 2.5f);
                if (up)
                {
                    _fill.Color = led.A(0.35f * blink);
                    _fill.MaskFilter = _blur4;
                    c.DrawRoundRect(ledRect, 2, 2, _fill);
                    _fill.MaskFilter = null;
                }
                _fill.Color = up ? led.A(blink) : SKColor.Parse("#1A2235");
                c.DrawRoundRect(ledRect, 2, 2, _fill);

                // PoE lightning
                if (port.PoeWatts is > 0) DrawBolt(c, pr.Right - 9, ledY, 1f);

                // error badge (switch-port diagnostics): pulsing dot with "!" on the socket's corner
                if (problemCol is { } bc)
                {
                    float bx = pr.Right - 1, by = top ? pr.Bottom - 1 : pr.Top + 1; // corner away from the LED/PoE row
                    float bp = 0.5f + 0.5f * MathF.Sin(t * 5 + port.Index);
                    _fill.Color = bc.A(0.25f + 0.25f * bp);
                    c.DrawCircle(bx, by, 9.5f, _fill);
                    _fill.Color = bc;
                    c.DrawCircle(bx, by, 6.5f, _fill);
                    _stroke.StrokeWidth = 1.5f;
                    _stroke.Color = SKColor.Parse("#070C17");
                    c.DrawCircle(bx, by, 6.5f, _stroke);
                    _text.Color = SKColor.Parse("#070C17");
                    c.DrawText("!", bx, by + 3f, SKTextAlign.Center, _fTiny, _text);
                }

                // port number inside the socket
                _text.Color = up ? Neon.Text.A(0.9f) : Neon.TextFaint;
                c.DrawText(port.Index.ToString(), mx, (iy0 + iy1) / 2 + 3, SKTextAlign.Center, _fTiny, _text);

                // connected device (first) next to the port
                if (port.Devices.Count > 0)
                {
                    var label = FitText(port.Devices[0].Name, port.Devices.Count > 1 ? $" +{port.Devices.Count - 1}" : "", PortW + PortGap - 3);
                    _text.Color = (hasSel ? Neon.Cyan : Neon.TextDim);
                    c.DrawText(label, mx, top ? pr.Top - 16 : pr.Bottom + 25, SKTextAlign.Center, _fTiny, _text);
                }
                if (hasSel || hov)
                {
                    _stroke.StrokeWidth = 2;
                    _stroke.Color = hasSel ? Neon.Cyan : SKColors.White.A(0.6f);
                    c.DrawRoundRect(pr.Left - 3, pr.Top - 3, pr.Width + 6, pr.Height + 6, 6, 6, _stroke);
                }
            }

            if (pl.Panel != snap.Panels[0]) continue;
            // LED legend in the header, right aligned (first panel only)
            float lx = r.Right - 262, ly = r.Top + 30;
            foreach (var (label, col) in new[] { ("10G", Neon.Blue), ("1G", Neon.Green), ("100M", Neon.Amber), ("down", SKColor.Parse("#2A3550")) })
            {
                _fill.Color = col;
                c.DrawRoundRect(new SKRect(lx, ly - 6, lx + 12, ly - 1), 2, 2, _fill);
                _text.Color = Neon.TextDim;
                c.DrawText(label, lx + 16, ly, SKTextAlign.Left, _fTiny, _text);
                lx += 50;
            }
            DrawBolt(c, lx + 4, ly - 3.5f, 1f);
            _text.Color = Neon.TextDim;
            c.DrawText("PoE", lx + 11, ly, SKTextAlign.Left, _fTiny, _text);
        }
    }

    /// <summary>Red for a down port, CRC/FCS errors or flapping; amber for softer problems (speed/duplex, discards).</summary>
    private static SKColor ProblemColor(PortHealth h) =>
        h.Health == HopHealth.Down || h.FcsPerSec > 0.1 || h.FlapsLastHour >= 3 || h.ErrorsPerSec > 1 ? Neon.Red : Neon.Amber;

    private static string Rate(double bps) =>
        bps >= 1e9 ? $"{bps / 1e9:0.##} Gb/s" : bps >= 1e6 ? $"{bps / 1e6:0.#} Mb/s" : bps >= 1e3 ? $"{bps / 1e3:0} kb/s" : $"{bps:0} b/s";

    private void DrawBolt(SKCanvas c, float bx, float by, float s)
    {
        _path.Reset();
        _path.MoveTo(bx + 1.5f * s, by - 5 * s);
        _path.LineTo(bx - 3 * s, by + 0.5f * s);
        _path.LineTo(bx, by + 0.5f * s);
        _path.LineTo(bx - 1.5f * s, by + 5 * s);
        _path.LineTo(bx + 3.5f * s, by - 1 * s);
        _path.LineTo(bx + 0.5f * s, by - 1 * s);
        _path.Close();
        _fill.Color = Neon.Amber;
        c.DrawPath(_path, _fill);
    }

    private string FitText(string text, string suffix, float maxW)
    {
        if (_fTiny.MeasureText(text + suffix) <= maxW) return text + suffix;
        for (int n = text.Length - 1; n > 1; n--)
        {
            var t = text[..n] + "…" + suffix;
            if (_fTiny.MeasureText(t) <= maxW) return t;
        }
        return text[..1] + "…" + suffix;
    }

    private void DrawEmptyPorts(SKCanvas c)
    {
        var r = new SKRect(-290, -110, 290, 110);
        _fill.Color = Neon.Panel.A(0.92f);
        c.DrawRoundRect(r, 18, 18, _fill);
        _stroke.PathEffect = null;
        _stroke.StrokeWidth = 1.2f;
        _stroke.Color = Neon.Cyan.A(0.3f);
        c.DrawRoundRect(r, 18, 18, _stroke);
        Glyphs.Draw(c, DeviceType.CoreSwitch, 0, -58, 46, Neon.Cyan.A(0.85f));
        _text.Color = Neon.Text;
        c.DrawText("No managed switches discovered yet", 0, 2, SKTextAlign.Center, _fTitle, _text);
        _text.Color = Neon.TextDim;
        c.DrawText("The port matrix appears once NetSpider can read a switch's port table", 0, 30, SKTextAlign.Center, _fSmall, _text);
        c.DrawText("and forwarding database over SNMP. Add community strings or v3", 0, 46, SKTextAlign.Center, _fSmall, _text);
        c.DrawText("credentials under Settings → SNMP, then run a full scan.", 0, 62, SKTextAlign.Center, _fSmall, _text);
    }

    // =====================================================================================================
    //  legend + tooltips (screen space)
    // =====================================================================================================

    private void DrawLegend(SKCanvas c, GraphViewState v)
    {
        float x = 16, y = v.Height - 16 - 74;
        var rect = new SKRect(x, y, x + 418, y + 74);
        _fill.Color = Neon.Panel.A(0.78f);
        c.DrawRoundRect(rect, 10, 10, _fill);
        _stroke.PathEffect = null;
        _stroke.StrokeWidth = 1;
        _stroke.Color = Neon.Border;
        c.DrawRoundRect(rect, 10, 10, _stroke);

        float cx = x + 14, cy = y + 22;
        _text.Color = Neon.TextDim;
        c.DrawText("LATENCY", cx, cy, SKTextAlign.Left, _fTiny, _text);
        cx += 52;
        foreach (var (label, col) in new[] { ("<2 ms", Neon.Green), ("<20 ms", Neon.Yellow), ("<50 ms", Neon.Orange), (">50 ms", Neon.Red), ("offline", Neon.Grey) })
        {
            _fill.Color = col;
            c.DrawCircle(cx + 4, cy - 3, 4.5f, _fill);
            _text.Color = Neon.Text.A(0.85f);
            c.DrawText(label, cx + 12, cy, SKTextAlign.Left, _fSmall, _text);
            cx += 20 + _fSmall.MeasureText(label) + 8;
        }

        cy += 22; cx = x + 14;
        _text.Color = Neon.TextDim;
        c.DrawText("LINKS", cx, cy, SKTextAlign.Left, _fTiny, _text);
        cx += 52;
        void Sample(string label, float[]? dash, float w)
        {
            _stroke.StrokeWidth = w;
            _stroke.Color = Neon.Cyan;
            using var fx = dash is null ? null : SKPathEffect.CreateDash(dash, 0);
            _stroke.PathEffect = fx;
            c.DrawLine(cx, cy - 3.5f, cx + 26, cy - 3.5f, _stroke);
            _stroke.PathEffect = null;
            _text.Color = Neon.Text.A(0.85f);
            c.DrawText(label, cx + 32, cy, SKTextAlign.Left, _fSmall, _text);
            cx += 40 + _fSmall.MeasureText(label) + 8;
        }
        Sample("measured", null, 2);
        Sample("estimated", [5, 4], 2);
        Sample("Wi-Fi", [0.1f, 5], 2.6f);

        cy += 20; cx = x + 66;
        _stroke.StrokeWidth = 4.2f; _stroke.Color = Neon.TextDim; c.DrawLine(cx, cy - 3.5f, cx + 18, cy - 3.5f, _stroke);
        _text.Color = Neon.Text.A(0.85f); c.DrawText("10G", cx + 24, cy, SKTextAlign.Left, _fSmall, _text); cx += 58;
        _stroke.StrokeWidth = 2.2f; c.DrawLine(cx, cy - 3.5f, cx + 18, cy - 3.5f, _stroke); c.DrawText("1G", cx + 24, cy, SKTextAlign.Left, _fSmall, _text); cx += 50;
        _stroke.StrokeWidth = 1.3f; c.DrawLine(cx, cy - 3.5f, cx + 18, cy - 3.5f, _stroke); c.DrawText("100M", cx + 24, cy, SKTextAlign.Left, _fSmall, _text); cx += 66;
        _stroke.StrokeWidth = 4; _stroke.Color = Neon.Magenta; _stroke.PathEffect = null;
        c.DrawCircle(cx + 5, cy - 4, 4.5f, _stroke);
        c.DrawText("multicast", cx + 16, cy, SKTextAlign.Left, _fSmall, _text);
    }

    private void DrawCard(SKCanvas c, GraphViewState v, string title, string? subtitle, IReadOnlyList<(string K, string V, SKColor? Col)> rows, SKColor accent)
    {
        const float pad = 12, rowH = 17;
        float kw = rows.Count == 0 ? 0 : rows.Max(r => _fSmall.MeasureText(r.K));
        float vw = rows.Count == 0 ? 0 : rows.Max(r => _fSmallBold.MeasureText(r.V));
        float w = Math.Max(Math.Max(_fName.MeasureText(title), subtitle is null ? 0 : _fSmall.MeasureText(subtitle)), kw + vw + 16) + pad * 2;
        w = Math.Min(w, 420);
        float h = pad + 18 + (subtitle is null ? 0 : 15) + 8 + rows.Count * rowH + pad - 4;
        float x = v.Mouse.X + 18, y = v.Mouse.Y + 18;
        if (x + w > v.Width - 8) x = v.Mouse.X - w - 14;
        if (y + h > v.Height - 8) y = v.Height - h - 8;
        x = Math.Max(8, x); y = Math.Max(8, y);
        var rect = new SKRect(x, y, x + w, y + h);

        _fill.Color = SKColors.Black.A(0.5f);
        _fill.MaskFilter = _blur10;
        c.DrawRoundRect(new SKRect(rect.Left + 2, rect.Top + 6, rect.Right + 2, rect.Bottom + 8), 12, 12, _fill);
        _fill.MaskFilter = null;
        _fill.Color = SKColor.Parse("#0D1526").A(0.97f);
        c.DrawRoundRect(rect, 12, 12, _fill);
        _stroke.PathEffect = null;
        _stroke.StrokeWidth = 1.2f;
        _stroke.Color = accent.A(0.6f);
        c.DrawRoundRect(rect, 12, 12, _stroke);
        _fill.Color = accent;
        c.DrawRoundRect(new SKRect(rect.Left, rect.Top + 12, rect.Left + 3, rect.Top + 34), 1.5f, 1.5f, _fill);

        float ty = y + pad + 13;
        _text.Color = Neon.Text;
        c.DrawText(title, x + pad, ty, SKTextAlign.Left, _fName, _text);
        if (subtitle is not null)
        {
            ty += 15;
            _text.Color = Neon.TextDim;
            c.DrawText(subtitle, x + pad, ty, SKTextAlign.Left, _fSmall, _text);
        }
        ty += 8;
        _stroke.StrokeWidth = 1; _stroke.Color = Neon.Border;
        c.DrawLine(x + pad, ty, x + w - pad, ty, _stroke);
        foreach (var (k, val, col) in rows)
        {
            ty += rowH;
            _text.Color = Neon.TextFaint;
            c.DrawText(k, x + pad, ty - 4, SKTextAlign.Left, _fSmall, _text);
            _text.Color = col ?? Neon.Text;
            c.DrawText(val, x + pad + kw + 14, ty - 4, SKTextAlign.Left, _fSmallBold, _text);
        }
    }

    private void DrawTooltips(SKCanvas c, GraphSnapshot snap, float[] xs, float[] ys, GraphViewState v, List<(SKRect R, SwitchPanel P, PortCell C)> portHits)
    {
        if (!v.MouseInside || v.Dragging is not null) return;
        if (v.Mode == GraphViewMode.Ports)
        {
            var mw = v.ToWorld(v.Mouse.X, v.Mouse.Y);
            foreach (var (r, panel, port) in portHits)
            {
                if (!r.Contains(mw)) continue;
                var rows = new List<(string, string, SKColor?)>
                {
                    ("Status", port.Up == true ? "up" : port.Up == false ? "down" : "unknown", port.Up == true ? Neon.Green : Neon.Grey),
                    ("Speed", Neon.FormatSpeed(port.SpeedMbps) + (port.Duplex is { } dpx ? $" · {dpx} duplex" : ""), Neon.LedForSpeed(port.SpeedMbps, port.Up)),
                };
                if (port.PoeWatts is > 0) rows.Add(("PoE", $"{port.PoeWatts:0.0} W", Neon.Amber));
                var ph = _diag.Port(panel.Switch, port.Name);
                if (ph is not null)
                {
                    var inv = System.Globalization.CultureInfo.InvariantCulture;
                    if (ph.Problem is { } prob) rows.Insert(0, ("Problem", GraphBuilder.Truncate(prob, 52), ProblemColor(ph)));
                    rows.Add(("Link", $"{Neon.FormatSpeed(ph.SpeedMbps)} · {ph.Duplex ?? "?"} duplex" + (ph.SpeedDowngraded ? " (downgraded)" : "") + (ph.DuplexSuspect ? " · mismatch?" : ""),
                        ph.SpeedDowngraded || ph.DuplexSuspect ? Neon.Amber : null));
                    rows.Add(("In / out", $"{Rate(ph.InBps)} / {Rate(ph.OutBps)}", null));
                    rows.Add(("Errors/s", string.Format(inv, "{0:0.##}  (discards {1:0.##})", ph.ErrorsPerSec, ph.DiscardsPerSec), ph.ErrorsPerSec > 0.01 ? Neon.Amber : null));
                    rows.Add(("FCS/s", string.Format(inv, "{0:0.##}", ph.FcsPerSec), ph.FcsPerSec > 0.01 ? Neon.Red : null));
                    rows.Add(("Flaps (1 h)", ph.FlapsLastHour.ToString(inv), ph.FlapsLastHour > 0 ? Neon.Red : null));
                    rows.Add(("Bcast / mcast", string.Format(inv, "{0:0.#} / {1:0.#} pps", ph.BroadcastPps, ph.MulticastPps), ph.BroadcastPps > 200 ? Neon.Red : null));
                }
                if (port.Pvid is { } pv) rows.Add(("PVID", $"VLAN {pv}", null));
                if (port.Alias is { Length: > 0 } al) rows.Add(("Alias", al, null));
                if (port.Devices.Count == 0) rows.Add(("Devices", "none learned", Neon.TextFaint));
                foreach (var (m, name) in port.Devices.Take(8))
                    rows.Add((rows.Count(x => x.Item1 is "Device" or "") == 0 ? "Device" : "", $"{GraphBuilder.Truncate(name, 30)}  {m}", Neon.Cyan));
                if (port.Devices.Count > 8) rows.Add(("", $"… {port.Devices.Count - 8} more", Neon.TextDim));
                DrawCard(c, v, $"{panel.Name} · port {port.Index} ({port.Name})", panel.Model, rows, ph?.Problem is not null ? ProblemColor(ph) : Neon.LedForSpeed(port.SpeedMbps, port.Up));
                return;
            }
            return;
        }

        if (v.Hovered is { } hm && snap.Index.TryGetValue(hm, out var hi) && hi < xs.Length)
        {
            var n = snap.Nodes[hi];
            var rows = new List<(string, string, SKColor?)>();
            if (n.Ip is not null) rows.Add(("IP", n.Ip, SKColor.Parse("#7FEFFF")));
            if (!n.IsInternet && !n.IsInferred)
                rows.Add(("MAC", n.MacText + (n.Mac.IsRandomized && !SyntheticNodes.IsSynthetic(n.Mac) ? "  (private)" : ""), null));
            if (n.Vendor is not null) rows.Add(("Vendor", n.Vendor, null));
            rows.Add(("Type", n.Type.ToString(), null));
            if (!n.IsInferred)
            {
                rows.Add(("L2 (ARP/NDP)", Neon.FormatMs(n.L2), Neon.Latency(n.L2, snap.GoodMs, snap.WarnMs, snap.BadMs)));
                rows.Add(("L3 (ICMP)", Neon.FormatMs(n.L3), Neon.Latency(n.L3, snap.GoodMs, snap.WarnMs, snap.BadMs)));
                rows.Add(("Jitter", Neon.FormatMs(n.Jitter), null));
                rows.Add(("Loss", $"{n.Loss:0.#} %", n.Loss > 0 ? Neon.Orange : Neon.Green));
            }
            if (n.Vlans.Length > 0) rows.Add(("VLANs", string.Join(", ", n.Vlans), null));
            if (n.SecurityText is not null) rows.Add(("Warning", n.SecurityText, Neon.Amber));
            if (n.Offline) rows.Add(("State", "offline", Neon.Grey));
            var accent = n.Offline ? Neon.Grey : Neon.Latency(n.Best, snap.GoodMs, snap.WarnMs, snap.BadMs);
            DrawCard(c, v, n.Name, n.Subtitle ?? (n.IsInferred ? "Inferred unmanaged switch (heuristic)" : null), rows, accent);
            return;
        }

        if (v.HoveredEdge is { } he && snap.Index.TryGetValue(he.A, out var ia) && snap.Index.TryGetValue(he.B, out var ib))
        {
            var e = snap.Edges.FirstOrDefault(x => (x.A == ia && x.B == ib) || (x.A == ib && x.B == ia));
            if (e is null) return;
            var na = snap.Nodes[e.A];
            var nb = snap.Nodes[e.B];
            var rows = new List<(string, string, SKColor?)>
            {
                ("Kind", KindText(e.Kind), null),
            };
            if (e.PortA is not null || e.PortB is not null)
                rows.Add(("Ports", $"{e.PortA ?? "?"}  ⟷  {e.PortB ?? "?"}", null));
            rows.Add(("Speed", Neon.FormatSpeed(e.SpeedMbps) + (e.Duplex is { } dx ? $" · {dx}" : ""), null));
            if (e.PoeWatts is > 0) rows.Add(("PoE", $"{e.PoeWatts:0.0} W", Neon.Amber));
            var pair = snap.GetPair(e.A, e.B);
            if (pair is { } p)
                rows.Add(("Device↔device", $"{Neon.FormatMs(p.Ms)}  ({(p.Origin == LatencyOrigin.Measured ? "measured" : "estimated")}, {p.Method})",
                    Neon.Latency(p.Ms, snap.GoodMs, snap.WarnMs, snap.BadMs)));
            if (e.LatencyMs is { } lm)
                rows.Add(("Link latency", $"{Neon.FormatMs(lm)}  ({(e.Origin == LatencyOrigin.Measured ? "measured" : "estimated")})",
                    Neon.Latency(lm, snap.GoodMs, snap.WarnMs, snap.BadMs)));
            if (e.Confidence < 1) rows.Add(("Confidence", $"{e.Confidence:P0}", null));
            DrawCard(c, v, $"{GraphBuilder.Truncate(na.Name, 24)}  ⟷  {GraphBuilder.Truncate(nb.Name, 24)}", null, rows,
                Neon.Latency(e.LatencyMs ?? pair?.Ms, snap.GoodMs, snap.WarnMs, snap.BadMs));
        }
    }

    public static string KindText(LinkKind k) => k switch
    {
        LinkKind.LldpCdp => "LLDP / CDP neighbor",
        LinkKind.BridgeFdb => "Switch FDB (MAC table)",
        LinkKind.L3Hop => "Routed hop (traceroute)",
        LinkKind.InferredUnmanagedSwitch => "Inferred unmanaged switch",
        LinkKind.VirtualHypervisor => "Virtual (hypervisor)",
        LinkKind.WifiAssoc => "Wi-Fi association",
        LinkKind.GatewayStar => "Assumed (gateway star)",
        LinkKind.Wan => "WAN uplink",
        _ => k.ToString(),
    };

    // =====================================================================================================
    //  fitting
    // =====================================================================================================

    /// <summary>World-space bounds of what the given mode shows (including labels).</summary>
    public static SKRect ContentBounds(GraphSnapshot snap, float[] xs, float[] ys, GraphViewMode mode)
    {
        if (mode == GraphViewMode.Ports)
        {
            if (snap.Panels.Length == 0) return new SKRect(-300, -120, 300, 120);
            var ls = LayoutPanels(snap);
            return new SKRect(ls.Min(l => l.Rect.Left) - 20, ls.Min(l => l.Rect.Top) - 20, ls.Max(l => l.Rect.Right) + 20, ls.Max(l => l.Rect.Bottom) + 30);
        }
        if (snap.Nodes.Length == 0) return new SKRect(-400, -300, 400, 300);
        float minX = float.MaxValue, minY = float.MaxValue, maxX = float.MinValue, maxY = float.MinValue;
        foreach (var n in snap.Nodes)
        {
            float x = mode == GraphViewMode.Tree ? n.TreeX : n.Index < xs.Length ? xs[n.Index] : 0;
            float y = mode == GraphViewMode.Tree ? n.TreeY : n.Index < ys.Length ? ys[n.Index] : 0;
            float hw = Math.Max(n.Radius, n.LabelW / 2);
            minX = Math.Min(minX, x - hw); maxX = Math.Max(maxX, x + hw);
            minY = Math.Min(minY, y - n.Radius - 16); maxY = Math.Max(maxY, y + n.Radius + 8 + n.LabelH);
        }
        return new SKRect(minX - 30, minY - 30, maxX + 30, maxY + 30);
    }
}
