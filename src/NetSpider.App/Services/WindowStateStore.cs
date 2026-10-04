using Avalonia;
using Avalonia.Controls;
using NetSpider.App.ViewModels;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>A monitor's working area in physical pixels plus its DPI scaling (1.0 = 96 dpi).</summary>
public readonly record struct ScreenArea(int X, int Y, int Width, int Height, double Scaling)
{
    public int Right => X + Width;
    public int Bottom => Y + Height;
}

/// <summary>A window rectangle: position in physical pixels, size in DIPs (as Avalonia's Position / Width / Height).</summary>
public readonly record struct WindowRect(double X, double Y, double Width, double Height);

/// <summary>
/// Remembers the main window's placement (position, size, maximized), the current page and whether the inspector is open in
/// <see cref="AppSettings.Window"/>, and restores it on the next start — clamped to the monitors that are actually connected.
/// </summary>
public sealed class WindowStateStore
{
    /// <summary>At least this much of the window (physical px) must lie on a monitor, otherwise it is moved to the primary one.</summary>
    public const int MinVisible = 120;

    private readonly ISettingsStore _store;
    private WindowRect? _normal;

    public WindowStateStore(ISettingsStore store) => _store = store;

    /// <summary>
    /// Pure placement logic: keeps the window on the monitor it overlaps most (scaled for that monitor's DPI), shrinks it to the
    /// working area and moves it fully inside. When it would be (almost) invisible — e.g. its monitor was disconnected — it is
    /// centered on the primary (first) screen. Returns <paramref name="saved"/> unchanged when no screens are known.
    /// </summary>
    public static WindowRect Clamp(WindowRect saved, IReadOnlyList<ScreenArea> screens, double minWidth = 640, double minHeight = 480)
    {
        if (screens.Count == 0) return saved;
        double w = double.IsFinite(saved.Width) && saved.Width > 0 ? saved.Width : 1280;
        double h = double.IsFinite(saved.Height) && saved.Height > 0 ? saved.Height : 800;

        ScreenArea? best = null;
        double bestArea = 0;
        foreach (var s in screens)
        {
            double pw = w * s.Scaling, ph = h * s.Scaling;
            double ix = Math.Max(0, Math.Min(saved.X + pw, s.Right) - Math.Max(saved.X, s.X));
            double iy = Math.Max(0, Math.Min(saved.Y + ph, s.Bottom) - Math.Max(saved.Y, s.Y));
            // the title bar (top edge) must be reachable, otherwise the window can't be dragged back
            bool topVisible = saved.Y >= s.Y - 8 && saved.Y < s.Bottom - 30;
            if (ix >= MinVisible && iy >= Math.Min(MinVisible, ph) && topVisible && ix * iy > bestArea) { best = s; bestArea = ix * iy; }
        }

        var target = best ?? screens[0];
        double scale = target.Scaling > 0 ? target.Scaling : 1;
        double maxW = target.Width / scale, maxH = target.Height / scale;
        w = Math.Min(Math.Max(w, Math.Min(minWidth, maxW)), maxW);
        h = Math.Min(Math.Max(h, Math.Min(minHeight, maxH)), maxH);
        double physW = w * scale, physH = h * scale;

        double x, y;
        if (best is null)
        {
            x = target.X + (target.Width - physW) / 2;
            y = target.Y + (target.Height - physH) / 2;
        }
        else
        {
            x = Math.Clamp(saved.X, target.X, target.Right - physW);
            y = Math.Clamp(saved.Y, target.Y, target.Bottom - physH);
        }
        return new WindowRect(Math.Round(x), Math.Round(y), Math.Round(w), Math.Round(h));
    }

    private static List<ScreenArea> ScreensOf(Window w) =>
        w.Screens.All.Select(s => new ScreenArea(s.WorkingArea.X, s.WorkingArea.Y, s.WorkingArea.Width, s.WorkingArea.Height, s.Scaling))
            .OrderByDescending(s => w.Screens.Primary is { } p && p.WorkingArea.X == s.X && p.WorkingArea.Y == s.Y)
            .ToList();

    /// <summary>Applies the saved placement before the window is shown and starts tracking its normal (restored) bounds.</summary>
    public void Restore(Window window, MainWindowViewModel vm, bool applyPage)
    {
        var p = _store.Settings.Window;
        try
        {
            if (p is { Width: > 0, Height: > 0 })
            {
                var r = Clamp(new WindowRect(p.X, p.Y, p.Width, p.Height), ScreensOf(window), window.MinWidth, window.MinHeight);
                window.WindowStartupLocation = WindowStartupLocation.Manual;
                window.Position = new PixelPoint((int)r.X, (int)r.Y);
                window.Width = r.Width;
                window.Height = r.Height;
                _normal = r;
                if (p.Maximized) window.WindowState = WindowState.Maximized;
                Log.Debug("Restored window placement {X},{Y} {W}x{H} maximized={Max}", r.X, r.Y, r.Width, r.Height, p.Maximized);
            }
            if (p is not null)
            {
                if (applyPage && p.LastPage is { } page && vm.NavItems.FirstOrDefault(n => n.Key == page) is { } nav) vm.SelectedNav = nav;
                if (p.InspectorOpen) vm.InspectorOpen = true;
            }
        }
        catch (Exception ex) { Log.Warning(ex, "Restoring the window placement failed"); }

        window.PositionChanged += (_, _) => Track(window);
        window.PropertyChanged += (_, e) => { if (e.Property == Window.ClientSizeProperty || e.Property == Window.WindowStateProperty) Track(window); };
    }

    private void Track(Window w)
    {
        if (w.WindowState == WindowState.Normal && w.IsVisible)
            _normal = new WindowRect(w.Position.X, w.Position.Y, w.ClientSize.Width, w.ClientSize.Height);
    }

    /// <summary>Writes the current placement, page and inspector state into the settings and saves them.</summary>
    public void Save(Window window, MainWindowViewModel vm)
    {
        try
        {
            Track(window);
            var n = _normal ?? new WindowRect(window.Position.X, window.Position.Y, window.ClientSize.Width, window.ClientSize.Height);
            _store.Settings.Window = new WindowPlacement
            {
                X = n.X, Y = n.Y, Width = n.Width, Height = n.Height,
                Maximized = window.WindowState == WindowState.Maximized,
                LastPage = vm.SelectedNav?.Key,
                InspectorOpen = vm.InspectorOpen,
            };
            _store.Save();
        }
        catch (Exception ex) { Log.Warning(ex, "Saving the window placement failed"); }
    }
}
