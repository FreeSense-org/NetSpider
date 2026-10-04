using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using NetSpider.App.ViewModels;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Notification-area icon (Avalonia <see cref="TrayIcon"/>): status-colored icon (normal / monitoring / alert), a live tooltip,
/// and a menu (Open, Start/Stop monitoring, Full scan, Path Doctor, Incidents, About…, Quit). Left click restores the window.
/// </summary>
public sealed class TrayService : IDisposable
{
    public enum State { Normal, Monitoring, Alert }

    private readonly Window _window;
    private readonly MainWindowViewModel _vm;
    private readonly DiagnosticsFeed _feed;
    private readonly IScanOrchestrator? _orchestrator;
    private readonly Action _quit;
    private readonly Dictionary<State, WindowIcon> _icons = [];
    private TrayIcon? _tray;
    private NativeMenuItem? _monitorItem;
    private DispatcherTimer? _timer;
    private State? _state;

    public TrayService(Window window, MainWindowViewModel vm, DiagnosticsFeed feed, IScanOrchestrator? orchestrator, Action quit)
    {
        _window = window;
        _vm = vm;
        _feed = feed;
        _orchestrator = orchestrator;
        _quit = quit;
    }

    public void Start()
    {
        try
        {
            var menu = new NativeMenu();
            menu.Add(Item("Open NetSpider", () => ShellIntegration.RestoreWindow(_window)));
            menu.Add(new NativeMenuItemSeparator());
            _monitorItem = Item("Start monitoring", ToggleMonitoring);
            menu.Add(_monitorItem);
            menu.Add(Item("Full scan", () => { ShellIntegration.RestoreWindow(_window); Execute(_vm.FullScanCommand); }));
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(Item("Path Doctor", () => Open("path")));
            menu.Add(Item("Incidents", () => Open("incidents")));
            if (ShellIntegration.AboutCommand(_vm) is not null)
                menu.Add(Item("About…", () => { ShellIntegration.RestoreWindow(_window); Execute(ShellIntegration.AboutCommand(_vm)); }));
            menu.Add(new NativeMenuItemSeparator());
            menu.Add(Item("Quit NetSpider", _quit));

            _tray = new TrayIcon { Menu = menu, ToolTipText = AppInfo.BrandTitle, IsVisible = true };
            _tray.Clicked += (_, _) => ShellIntegration.RestoreWindow(_window);
            Update();
            if (Application.Current is { } app) TrayIcon.SetIcons(app, [_tray]);
            _timer = new DispatcherTimer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, (_, _) => Update());
            _timer.Start();
        }
        catch (Exception ex) { Log.Warning(ex, "Creating the tray icon failed"); }
    }

    private void Open(string page)
    {
        _vm.Navigate(page);
        ShellIntegration.RestoreWindow(_window);
    }

    private void ToggleMonitoring()
    {
        if (_vm.IsMonitoring || _vm.IsScanning) Execute(_vm.StopCommand);
        else Execute(_vm.StartMonitoringCommand);
        Dispatcher.UIThread.Post(Update, DispatcherPriority.Background);
    }

    private static void Execute(ICommand? cmd)
    {
        if (cmd?.CanExecute(null) == true) cmd.Execute(null);
    }

    private static NativeMenuItem Item(string header, Action action)
    {
        var item = new NativeMenuItem(header);
        item.Click += (_, _) =>
        {
            try { action(); }
            catch (Exception ex) { Log.Warning(ex, "Tray menu action {Header} failed", header); }
        };
        return item;
    }

    /// <summary>Pure: the tooltip text ("FreeSense – NetSpider — monitoring Ethernet · 43 devices"). Tray tooltips are limited to 127 characters.</summary>
    public static string Tooltip(bool monitoring, string? adapter, int devices, int activeIncidents)
    {
        string status = activeIncidents > 0
            ? $"{activeIncidents} active incident{(activeIncidents == 1 ? "" : "s")}"
            : monitoring ? $"monitoring {adapter ?? "adapter"} · {devices} device{(devices == 1 ? "" : "s")}"
            : devices > 0 ? $"idle · {devices} device{(devices == 1 ? "" : "s")}" : "idle";
        var text = $"{AppInfo.BrandTitle} — {status}";
        return text.Length > 127 ? text[..126] + "…" : text;
    }

    public void Update()
    {
        if (_tray is null) return;
        try
        {
            int incidents = _feed.Incidents?.Active.Count ?? 0;
            bool monitoring = _orchestrator?.IsMonitoring == true || _vm.IsMonitoring;
            var state = incidents > 0 ? State.Alert : monitoring ? State.Monitoring : State.Normal;
            if (state != _state)
            {
                _tray.Icon = IconFor(state);
                _state = state;
            }
            _tray.ToolTipText = Tooltip(monitoring, _vm.SelectedAdapter?.Title, _vm.DeviceCount, incidents);
            if (_monitorItem is not null)
            {
                _monitorItem.Header = _vm.IsMonitoring || _vm.IsScanning ? "Stop monitoring" : "Start monitoring";
                _monitorItem.IsEnabled = _vm.IsMonitoring || _vm.IsScanning || _vm.StartMonitoringCommand.CanExecute(null);
            }
        }
        catch (Exception ex) { Log.Debug(ex, "Tray update failed"); }
    }

    // ------------------------------------------------------------------ icons

    private WindowIcon IconFor(State s)
    {
        if (_icons.TryGetValue(s, out var icon)) return icon;
        var name = s switch { State.Alert => "tray-alert.ico", State.Monitoring => "tray-monitoring.ico", _ => "tray-normal.ico" };
        icon = TryAsset($"avares://NetSpider/Assets/Brand/{name}")
               ?? (s == State.Normal ? _window.Icon : null)
               ?? Render(s);
        _icons[s] = icon;
        return icon;
    }

    private static WindowIcon? TryAsset(string uri)
    {
        try
        {
            var u = new Uri(uri);
            if (!AssetLoader.Exists(u)) return null;
            using var s = AssetLoader.Open(u);
            return new WindowIcon(s);
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Tray icon {Uri} not usable", uri);
            return null;
        }
    }

    /// <summary>Fallback when the brand assets are missing: the in-app spider glyph on a dark tile plus a status dot.</summary>
    private static WindowIcon Render(State s)
    {
        const int size = 32;
        var rtb = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        using (var dc = rtb.CreateDrawingContext())
        {
            dc.DrawRectangle(new SolidColorBrush(Color.Parse("#0D1424")), null, new RoundedRect(new Rect(0, 0, size, size), 7));
            if (Application.Current?.TryGetResource("IconSpider", null, out var g) == true && g is Geometry geo)
            {
                var b = geo.Bounds;
                double scale = (size - 8) / Math.Max(b.Width, b.Height);
                var pen = new Pen(new SolidColorBrush(Color.Parse("#00E5FF")), 2.2 / scale, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
                using (dc.PushTransform(Matrix.CreateTranslation(-b.X, -b.Y) * Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(4, 4)))
                    dc.DrawGeometry(null, pen, geo);
            }
            if (s != State.Normal)
            {
                var color = s == State.Alert ? Color.Parse("#FF3D5A") : Color.Parse("#2BFF88");
                dc.DrawEllipse(new SolidColorBrush(color), new Pen(new SolidColorBrush(Color.Parse("#0D1424")), 2), new Point(size - 8, size - 8), 7, 7);
            }
        }
        return new WindowIcon(rtb);
    }

    public void Dispose()
    {
        _timer?.Stop();
        if (_tray is null) return;
        try
        {
            _tray.IsVisible = false;
            if (Application.Current is { } app) TrayIcon.SetIcons(app, []);
            _tray.Dispose();
        }
        catch { }
        _tray = null;
    }
}
