using NetSpider.Core.Model;
using SkiaSharp;

namespace NetSpider.App.Rendering;

/// <summary>Crisp procedural vector glyphs per <see cref="DeviceType"/> (used when no brand logo is available).</summary>
public static class Glyphs
{
    [ThreadStatic] private static SKPaint? _stroke;
    [ThreadStatic] private static SKPaint? _fill;
    [ThreadStatic] private static SKPath? _path;
    private static readonly SKPathEffect VmDash = SKPathEffect.CreateDash([0.16f, 0.1f], 0);

    /// <summary>Draws the glyph for <paramref name="type"/> centred at (cx, cy) inside a square of side <paramref name="size"/>.</summary>
    public static void Draw(SKCanvas c, DeviceType type, float cx, float cy, float size, SKColor color)
    {
        var s = _stroke ??= new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeCap = SKStrokeCap.Round, StrokeJoin = SKStrokeJoin.Round };
        var f = _fill ??= new SKPaint { IsAntialias = true, Style = SKPaintStyle.Fill };
        var p = _path ??= new SKPath();
        float u = size / 2f;
        s.Color = color;
        s.StrokeWidth = Math.Max(1f, size * 0.075f);
        s.PathEffect = null;
        f.Color = color;

        c.Save();
        c.Translate(cx, cy);
        c.Scale(u, u);
        s.StrokeWidth /= u;

        switch (type)
        {
            case DeviceType.Internet: Cloud(c, s, p); break;
            case DeviceType.Router: Router(c, s, f); break;
            case DeviceType.Firewall: Firewall(c, s, p); break;
            case DeviceType.CoreSwitch: Switch(c, s, f, true); break;
            case DeviceType.AccessSwitch: Switch(c, s, f, false); break;
            case DeviceType.UnmanagedSwitch: Switch(c, s, f, false); break;
            case DeviceType.AccessPoint: AccessPoint(c, s, f); break;
            case DeviceType.Server: Server(c, s, f, 3); break;
            case DeviceType.Nas: Nas(c, s, f); break;
            case DeviceType.Hypervisor: Hypervisor(c, s, f); break;
            case DeviceType.VirtualMachine: Vm(c, s, f); break;
            case DeviceType.Desktop: Desktop(c, s); break;
            case DeviceType.ThisComputer: Desktop(c, s); f.Color = color; c.DrawCircle(0, -0.2f, 0.16f, f); break;
            case DeviceType.Laptop: Laptop(c, s); break;
            case DeviceType.Phone: Phone(c, s, f, 0.42f, 0.78f); break;
            case DeviceType.Tablet: Phone(c, s, f, 0.62f, 0.8f); break;
            case DeviceType.Printer: Printer(c, s, f); break;
            case DeviceType.Camera: Camera(c, s, f); break;
            case DeviceType.Tv: Tv(c, s); break;
            case DeviceType.MediaStreamer: Streamer(c, s, f, p); break;
            case DeviceType.AudioStreamer: Speaker(c, s, f); break;
            case DeviceType.GameConsole: Gamepad(c, s, f, p); break;
            case DeviceType.SmartHomeHub: Hub(c, s, f, p); break;
            case DeviceType.SmartPlug: Plug(c, s, f); break;
            case DeviceType.Light: Bulb(c, s, p); break;
            case DeviceType.IoT: Chip(c, s); break;
            case DeviceType.VoipPhone: Voip(c, s, f, p); break;
            case DeviceType.Ups: Ups(c, s, f, p); break;
            default: Unknown(c, s, f); break;
        }
        c.Restore();
    }

    private static void Cloud(SKCanvas c, SKPaint s, SKPath p)
    {
        p.Reset();
        p.MoveTo(-0.62f, 0.42f);
        p.ArcTo(new SKRect(-0.95f, -0.02f, -0.35f, 0.42f + 0.02f), 90, 180, false);
        p.ArcTo(new SKRect(-0.55f, -0.55f, 0.15f, 0.15f), 190, 150, false);
        p.ArcTo(new SKRect(0.0f, -0.32f, 0.6f, 0.28f), 240, 130, false);
        p.ArcTo(new SKRect(0.42f, -0.02f, 0.92f, 0.44f), 290, 160, false);
        p.Close();
        c.DrawPath(p, s);
        // tiny globe meridian inside the cloud for a "net" feel
        s.StrokeWidth *= 0.6f;
        c.DrawLine(-0.3f, 0.18f, 0.35f, 0.18f, s);
        s.StrokeWidth /= 0.6f;
    }

    private static void Router(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRoundRect(new SKRect(-0.85f, 0.0f, 0.85f, 0.55f), 0.14f, 0.14f, s);
        c.DrawLine(-0.5f, 0.0f, -0.68f, -0.62f, s);
        c.DrawLine(0.5f, 0.0f, 0.68f, -0.62f, s);
        for (int i = 0; i < 4; i++) c.DrawCircle(-0.5f + i * 0.22f, 0.28f, 0.065f, f);
        c.DrawLine(0.4f, 0.28f, 0.62f, 0.28f, s);
        // signal arcs
        var r = new SKRect(-0.3f, -0.75f, 0.3f, -0.15f);
        c.DrawArc(r, 230, 80, false, s);
    }

    private static void Firewall(SKCanvas c, SKPaint s, SKPath p)
    {
        p.Reset();
        p.MoveTo(0, -0.85f);
        p.LineTo(0.7f, -0.6f);
        p.LineTo(0.62f, 0.15f);
        p.QuadTo(0.45f, 0.62f, 0, 0.85f);
        p.QuadTo(-0.45f, 0.62f, -0.62f, 0.15f);
        p.LineTo(-0.7f, -0.6f);
        p.Close();
        c.DrawPath(p, s);
        c.DrawLine(-0.45f, -0.15f, 0.45f, -0.15f, s);
        c.DrawLine(-0.38f, 0.25f, 0.38f, 0.25f, s);
        c.DrawLine(0, -0.15f, 0, 0.25f, s);
    }

    private static void Switch(SKCanvas c, SKPaint s, SKPaint f, bool core)
    {
        float top = core ? -0.05f : -0.38f;
        c.DrawRoundRect(new SKRect(-0.92f, top, 0.92f, top + 0.72f), 0.1f, 0.1f, s);
        for (int row = 0; row < 2; row++)
            for (int i = 0; i < 6; i++)
                c.DrawRect(new SKRect(-0.72f + i * 0.25f, top + 0.15f + row * 0.26f, -0.58f + i * 0.25f, top + 0.27f + row * 0.26f), f);
        if (core)
        {
            // bidirectional arrows on top
            c.DrawLine(-0.6f, -0.62f, 0.6f, -0.62f, s);
            c.DrawLine(0.6f, -0.62f, 0.4f, -0.78f, s);
            c.DrawLine(-0.6f, -0.32f, 0.6f, -0.32f, s);
            c.DrawLine(-0.6f, -0.32f, -0.4f, -0.16f, s);
        }
    }

    private static void AccessPoint(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawOval(new SKRect(-0.75f, 0.32f, 0.75f, 0.72f), s);
        c.DrawCircle(0, 0.52f, 0.07f, f);
        c.DrawCircle(0, -0.1f, 0.09f, f);
        c.DrawArc(new SKRect(-0.38f, -0.48f, 0.38f, 0.28f), 225, 90, false, s);
        c.DrawArc(new SKRect(-0.68f, -0.78f, 0.68f, 0.58f), 228, 84, false, s);
    }

    private static void Server(SKCanvas c, SKPaint s, SKPaint f, int units)
    {
        float h = 1.5f / units;
        for (int i = 0; i < units; i++)
        {
            float y = -0.75f + i * h;
            c.DrawRoundRect(new SKRect(-0.8f, y + 0.04f, 0.8f, y + h - 0.04f), 0.08f, 0.08f, s);
            c.DrawCircle(0.52f, y + h / 2, 0.07f, f);
            c.DrawLine(-0.6f, y + h / 2, 0.15f, y + h / 2, s);
        }
    }

    private static void Nas(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRoundRect(new SKRect(-0.62f, -0.82f, 0.62f, 0.82f), 0.14f, 0.14f, s);
        c.DrawRoundRect(new SKRect(-0.42f, -0.6f, -0.06f, 0.42f), 0.06f, 0.06f, s);
        c.DrawRoundRect(new SKRect(0.06f, -0.6f, 0.42f, 0.42f), 0.06f, 0.06f, s);
        c.DrawCircle(-0.3f, 0.62f, 0.06f, f);
        c.DrawCircle(-0.1f, 0.62f, 0.06f, f);
        c.DrawCircle(0.1f, 0.62f, 0.06f, f);
    }

    private static void Hypervisor(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRoundRect(new SKRect(-0.85f, 0.18f, 0.85f, 0.78f), 0.1f, 0.1f, s);
        c.DrawCircle(0.55f, 0.48f, 0.07f, f);
        c.DrawLine(-0.6f, 0.48f, 0.2f, 0.48f, s);
        var a = s.Color.Alpha;
        s.Color = s.Color.WithAlpha((byte)(a * 0.75f));
        c.DrawRoundRect(new SKRect(-0.7f, -0.28f, 0.0f, 0.06f), 0.06f, 0.06f, s);
        c.DrawRoundRect(new SKRect(0.08f, -0.28f, 0.78f, 0.06f), 0.06f, 0.06f, s);
        c.DrawRoundRect(new SKRect(-0.32f, -0.78f, 0.38f, -0.44f), 0.06f, 0.06f, s);
        s.Color = s.Color.WithAlpha(a);
    }

    private static void Vm(SKCanvas c, SKPaint s, SKPaint f)
    {
        s.PathEffect = VmDash;
        c.DrawRoundRect(new SKRect(-0.85f, -0.68f, 0.85f, 0.68f), 0.14f, 0.14f, s);
        s.PathEffect = null;
        c.DrawLine(-0.85f, -0.36f, 0.85f, -0.36f, s);
        c.DrawCircle(-0.62f, -0.52f, 0.05f, f);
        c.DrawCircle(-0.45f, -0.52f, 0.05f, f);
        c.DrawLine(-0.45f, -0.05f, -0.2f, 0.15f, s);
        c.DrawLine(-0.2f, 0.15f, -0.45f, 0.35f, s);
        c.DrawLine(0.0f, 0.38f, 0.42f, 0.38f, s);
    }

    private static void Desktop(SKCanvas c, SKPaint s)
    {
        c.DrawRoundRect(new SKRect(-0.88f, -0.72f, 0.88f, 0.4f), 0.1f, 0.1f, s);
        c.DrawLine(0, 0.4f, 0, 0.66f, s);
        c.DrawLine(-0.38f, 0.72f, 0.38f, 0.72f, s);
    }

    private static void Laptop(SKCanvas c, SKPaint s)
    {
        c.DrawRoundRect(new SKRect(-0.65f, -0.62f, 0.65f, 0.28f), 0.08f, 0.08f, s);
        c.DrawLine(-0.92f, 0.5f, 0.92f, 0.5f, s);
        c.DrawLine(-0.92f, 0.5f, -0.75f, 0.32f, s);
        c.DrawLine(0.92f, 0.5f, 0.75f, 0.32f, s);
    }

    private static void Phone(SKCanvas c, SKPaint s, SKPaint f, float w, float h)
    {
        c.DrawRoundRect(new SKRect(-w, -h, w, h), 0.16f, 0.16f, s);
        c.DrawLine(-0.12f, -h + 0.16f, 0.12f, -h + 0.16f, s);
        c.DrawCircle(0, h - 0.18f, 0.07f, f);
    }

    private static void Printer(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRect(new SKRect(-0.48f, -0.8f, 0.48f, -0.3f), s);
        c.DrawRoundRect(new SKRect(-0.88f, -0.3f, 0.88f, 0.42f), 0.12f, 0.12f, s);
        c.DrawRect(new SKRect(-0.48f, 0.18f, 0.48f, 0.78f), s);
        c.DrawLine(-0.28f, 0.42f, 0.28f, 0.42f, s);
        c.DrawLine(-0.28f, 0.6f, 0.15f, 0.6f, s);
        c.DrawCircle(0.62f, -0.06f, 0.07f, f);
    }

    private static void Camera(SKCanvas c, SKPaint s, SKPaint f)
    {
        // bullet camera on a wall mount
        c.Save();
        c.RotateDegrees(-12);
        c.DrawRoundRect(new SKRect(-0.85f, -0.48f, 0.55f, 0.12f), 0.14f, 0.14f, s);
        c.DrawRect(new SKRect(0.55f, -0.38f, 0.85f, 0.02f), s);
        c.DrawCircle(0.7f, -0.18f, 0.08f, f);
        c.Restore();
        c.DrawLine(-0.3f, 0.2f, -0.3f, 0.62f, s);
        c.DrawLine(-0.62f, 0.68f, 0.05f, 0.68f, s);
        c.DrawCircle(-0.5f, -0.1f, 0.06f, f);
    }

    private static void Tv(SKCanvas c, SKPaint s)
    {
        c.DrawRoundRect(new SKRect(-0.92f, -0.62f, 0.92f, 0.45f), 0.08f, 0.08f, s);
        c.DrawLine(-0.5f, 0.45f, -0.62f, 0.7f, s);
        c.DrawLine(0.5f, 0.45f, 0.62f, 0.7f, s);
    }

    private static void Streamer(SKCanvas c, SKPaint s, SKPaint f, SKPath p)
    {
        c.DrawRoundRect(new SKRect(-0.78f, -0.45f, 0.78f, 0.45f), 0.2f, 0.2f, s);
        p.Reset();
        p.MoveTo(-0.16f, -0.24f);
        p.LineTo(0.24f, 0);
        p.LineTo(-0.16f, 0.24f);
        p.Close();
        c.DrawPath(p, f);
        c.DrawLine(-0.5f, 0.64f, 0.5f, 0.64f, s);
    }

    private static void Speaker(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRoundRect(new SKRect(-0.56f, -0.85f, 0.56f, 0.85f), 0.2f, 0.2f, s);
        c.DrawCircle(0, 0.22f, 0.33f, s);
        c.DrawCircle(0, 0.22f, 0.09f, f);
        c.DrawCircle(0, -0.5f, 0.12f, s);
    }

    private static void Gamepad(SKCanvas c, SKPaint s, SKPaint f, SKPath p)
    {
        p.Reset();
        p.MoveTo(-0.55f, -0.38f);
        p.LineTo(0.55f, -0.38f);
        p.CubicTo(0.95f, -0.38f, 1.0f, 0.5f, 0.78f, 0.6f);
        p.CubicTo(0.6f, 0.68f, 0.45f, 0.3f, 0.3f, 0.2f);
        p.LineTo(-0.3f, 0.2f);
        p.CubicTo(-0.45f, 0.3f, -0.6f, 0.68f, -0.78f, 0.6f);
        p.CubicTo(-1.0f, 0.5f, -0.95f, -0.38f, -0.55f, -0.38f);
        p.Close();
        c.DrawPath(p, s);
        c.DrawLine(-0.6f, -0.08f, -0.3f, -0.08f, s);
        c.DrawLine(-0.45f, -0.23f, -0.45f, 0.07f, s);
        c.DrawCircle(0.42f, -0.16f, 0.07f, f);
        c.DrawCircle(0.58f, 0.0f, 0.07f, f);
    }

    private static void Hub(SKCanvas c, SKPaint s, SKPaint f, SKPath p)
    {
        p.Reset();
        p.MoveTo(-0.78f, -0.05f);
        p.LineTo(0, -0.78f);
        p.LineTo(0.78f, -0.05f);
        p.MoveTo(-0.58f, -0.22f);
        p.LineTo(-0.58f, 0.75f);
        p.LineTo(0.58f, 0.75f);
        p.LineTo(0.58f, -0.22f);
        c.DrawPath(p, s);
        c.DrawCircle(0, 0.42f, 0.08f, f);
        c.DrawArc(new SKRect(-0.22f, 0.02f, 0.22f, 0.46f), 225, 90, false, s);
        c.DrawArc(new SKRect(-0.4f, -0.16f, 0.4f, 0.64f), 228, 84, false, s);
    }

    private static void Plug(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawRoundRect(new SKRect(-0.7f, -0.7f, 0.7f, 0.7f), 0.3f, 0.3f, s);
        c.DrawCircle(-0.25f, 0, 0.1f, f);
        c.DrawCircle(0.25f, 0, 0.1f, f);
        c.DrawLine(0, -0.48f, 0, -0.32f, s);
    }

    private static void Bulb(SKCanvas c, SKPaint s, SKPath p)
    {
        p.Reset();
        p.MoveTo(-0.25f, 0.3f);
        p.CubicTo(-0.25f, 0.05f, -0.62f, -0.1f, -0.62f, -0.4f);
        p.ArcTo(new SKRect(-0.62f, -0.92f, 0.62f, 0.12f), 180, 180, false);
        p.CubicTo(0.62f, -0.1f, 0.25f, 0.05f, 0.25f, 0.3f);
        p.Close();
        c.DrawPath(p, s);
        c.DrawLine(-0.22f, 0.48f, 0.22f, 0.48f, s);
        c.DrawLine(-0.16f, 0.66f, 0.16f, 0.66f, s);
        c.DrawLine(-0.1f, -0.2f, 0.0f, 0.05f, s);
        c.DrawLine(0.1f, -0.2f, 0.0f, 0.05f, s);
    }

    private static void Chip(SKCanvas c, SKPaint s)
    {
        c.DrawRoundRect(new SKRect(-0.5f, -0.5f, 0.5f, 0.5f), 0.08f, 0.08f, s);
        c.DrawRect(new SKRect(-0.22f, -0.22f, 0.22f, 0.22f), s);
        for (int i = -1; i <= 1; i++)
        {
            float o = i * 0.28f;
            c.DrawLine(o, -0.5f, o, -0.8f, s);
            c.DrawLine(o, 0.5f, o, 0.8f, s);
            c.DrawLine(-0.5f, o, -0.8f, o, s);
            c.DrawLine(0.5f, o, 0.8f, o, s);
        }
    }

    private static void Voip(SKCanvas c, SKPaint s, SKPaint f, SKPath p)
    {
        c.DrawRoundRect(new SKRect(-0.85f, -0.1f, 0.85f, 0.75f), 0.12f, 0.12f, s);
        p.Reset();
        p.MoveTo(-0.75f, -0.25f);
        p.QuadTo(0, -0.85f, 0.75f, -0.25f);
        c.DrawPath(p, s);
        for (int r = 0; r < 2; r++)
            for (int i = 0; i < 3; i++) c.DrawCircle(-0.3f + i * 0.3f, 0.18f + r * 0.28f, 0.06f, f);
    }

    private static void Ups(SKCanvas c, SKPaint s, SKPaint f, SKPath p)
    {
        c.DrawRoundRect(new SKRect(-0.85f, -0.45f, 0.72f, 0.45f), 0.1f, 0.1f, s);
        c.DrawRect(new SKRect(0.72f, -0.18f, 0.88f, 0.18f), f);
        p.Reset();
        p.MoveTo(0.05f, -0.35f);
        p.LineTo(-0.25f, 0.06f);
        p.LineTo(-0.02f, 0.06f);
        p.LineTo(-0.12f, 0.35f);
        p.LineTo(0.22f, -0.08f);
        p.LineTo(-0.02f, -0.08f);
        p.Close();
        c.DrawPath(p, f);
    }

    private static void Unknown(SKCanvas c, SKPaint s, SKPaint f)
    {
        c.DrawArc(new SKRect(-0.38f, -0.72f, 0.38f, 0.02f), 180, 230, false, s);
        c.DrawLine(0.05f, 0.02f, 0, 0.28f, s);
        c.DrawCircle(0, 0.58f, 0.08f, f);
    }
}
