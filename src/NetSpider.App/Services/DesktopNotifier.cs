using System.Runtime.InteropServices;
using Avalonia.Threading;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// OS-level notifications for fresh alerts and new incidents at or above <see cref="AppSettings.ToastMinSeverity"/> while the
/// main window is minimized or hidden in the tray (when it is visible the in-app toasts suffice).
/// <para>
/// Implemented as a Shell_NotifyIcon balloon (NIF_INFO) on a private notify icon owned by a message-only window — Windows 10/11
/// render these as modern toasts — so no WinRT/TFM change is needed. Clicking the notification invokes <see cref="Clicked"/>.
/// </para>
/// </summary>
public sealed class DesktopNotifier : IDisposable
{
    private const int IconId = 0x4E53; // "NS"
    private const uint CallbackMessage = 0x8000 + 0x4E5; // WM_APP + n
    private static readonly TimeSpan MinSpacing = TimeSpan.FromSeconds(6);

    private readonly ISettingsStore _settings;
    private readonly IAlertService _alerts;
    private readonly DiagnosticsFeed _feed;
    private readonly Func<bool> _windowHidden;
    private readonly HashSet<Guid> _seenIncidents = [];
    private readonly List<(string Title, string Body, AlertSeverity Sev, string Page)> _pending = [];
    private WndProc? _wndProc; // keep the delegate alive
    private IntPtr _hwnd;
    private IntPtr _hIcon;
    private bool _iconAdded;
    private DateTime _lastShown = DateTime.MinValue;
    private bool _flushScheduled;
    private string _clickPage = "incidents";

    public DesktopNotifier(ISettingsStore settings, IAlertService alerts, DiagnosticsFeed feed, Func<bool> windowHidden)
    {
        _settings = settings;
        _alerts = alerts;
        _feed = feed;
        _windowHidden = windowHidden;
    }

    /// <summary>Raised on the UI thread with the page to open ("incidents" or "alerts") when the user clicks a notification.</summary>
    public event Action<string>? Clicked;

    public void Start()
    {
        _alerts.AlertRaised += OnAlert;
        _feed.IncidentsChanged += OnIncidentsChanged;
        // incidents that already exist (restored history) are not news
        foreach (var i in _feed.Incidents?.Incidents ?? []) _seenIncidents.Add(i.Id);
    }

    private bool Enabled(AlertSeverity s) => _settings.Settings.ToastNotifications && s >= _settings.Settings.ToastMinSeverity;

    private void OnAlert(Alert a)
    {
        if (DateTimeOffset.Now - a.Time > TimeSpan.FromSeconds(30)) return; // replayed history
        if (_feed.DemoActive || !Enabled(a.Severity)) return;
        Dispatcher.UIThread.Post(() => Enqueue(a.Title, a.Details, a.Severity, "alerts"));
    }

    private void OnIncidentsChanged()
    {
        if (_feed.DemoActive) return;
        Dispatcher.UIThread.Post(() =>
        {
            foreach (var i in _feed.Incidents?.Active ?? [])
            {
                if (!_seenIncidents.Add(i.Id)) continue;
                if (Enabled(i.Severity)) Enqueue("Incident: " + i.Title, i.RootCause, i.Severity, "incidents");
            }
        });
    }

    /// <summary>Shows (or coalesces) one notification if the window is hidden/minimized. UI thread.</summary>
    public void Enqueue(string title, string body, AlertSeverity severity, string page, bool force = false)
    {
        if (!force && !_windowHidden()) return;
        _pending.Add((title, body, severity, page));
        if (_flushScheduled) return;
        var wait = _lastShown + MinSpacing - DateTime.UtcNow;
        _flushScheduled = true;
        DispatcherTimer.RunOnce(Flush, wait > TimeSpan.Zero ? wait : TimeSpan.FromMilliseconds(50));
    }

    private void Flush()
    {
        _flushScheduled = false;
        if (_pending.Count == 0) return;
        var items = _pending.ToList();
        _pending.Clear();
        var top = items.OrderByDescending(i => i.Sev).First();
        string title = items.Count == 1 ? top.Title : $"{items.Count} new NetSpider notifications";
        string body = items.Count == 1 ? top.Body : string.Join("\n", items.Take(3).Select(i => "• " + i.Title)) + (items.Count > 3 ? $"\n… and {items.Count - 3} more" : "");
        _clickPage = items.Any(i => i.Page == "incidents") ? "incidents" : top.Page;
        _lastShown = DateTime.UtcNow;
        Show(title, body, top.Sev);
    }

    // ================================================================================================ Win32

    private void EnsureWindow()
    {
        if (_hwnd != IntPtr.Zero) return;
        _wndProc = WindowProc;
        var cls = new WNDCLASSEX
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEX>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = GetModuleHandle(null),
            lpszClassName = "NetSpiderNotifier_" + Environment.ProcessId,
        };
        RegisterClassEx(ref cls);
        _hwnd = CreateWindowEx(0, cls.lpszClassName, "NetSpider notifications", 0, 0, 0, 0, 0, new IntPtr(-3) /* HWND_MESSAGE */, IntPtr.Zero, cls.hInstance, IntPtr.Zero);
        if (_hwnd == IntPtr.Zero) throw new InvalidOperationException("CreateWindowEx failed: " + Marshal.GetLastWin32Error());

        var exe = Environment.ProcessPath;
        if (exe is not null)
        {
            var large = new IntPtr[1];
            var small = new IntPtr[1];
            if (ExtractIconEx(exe, 0, large, small, 1) > 0)
            {
                _hIcon = small[0] != IntPtr.Zero ? small[0] : large[0];
                if (small[0] != IntPtr.Zero && large[0] != IntPtr.Zero) DestroyIcon(large[0]);
            }
        }
    }

    private void EnsureIcon()
    {
        if (_iconAdded) return;
        var data = NewData();
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_STATE;
        data.uCallbackMessage = CallbackMessage;
        data.hIcon = _hIcon != IntPtr.Zero ? _hIcon : LoadIcon(IntPtr.Zero, new IntPtr(32512) /* IDI_APPLICATION */);
        data.szTip = "NetSpider notifications";
        // the visible tray icon is the Avalonia TrayIcon; this one only carries the notifications
        data.dwState = NIS_HIDDEN;
        data.dwStateMask = NIS_HIDDEN;
        if (!Shell_NotifyIcon(NIM_ADD, ref data)) Log.Debug("Shell_NotifyIcon(NIM_ADD) failed");
        data.uTimeoutOrVersion = 4; // NOTIFYICON_VERSION_4
        Shell_NotifyIcon(NIM_SETVERSION, ref data);
        _iconAdded = true;
    }

    private void Show(string title, string body, AlertSeverity severity)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            EnsureWindow();
            EnsureIcon();
            var data = NewData();
            data.uFlags = NIF_INFO;
            data.szInfoTitle = Trim(title, 63);
            data.szInfo = Trim(string.IsNullOrWhiteSpace(body) ? title : body, 255);
            data.dwInfoFlags = severity switch
            {
                AlertSeverity.Critical => NIIF_ERROR,
                AlertSeverity.Warning => NIIF_WARNING,
                _ => NIIF_INFO,
            };
            if (!Shell_NotifyIcon(NIM_MODIFY, ref data)) Log.Debug("Shell_NotifyIcon(NIF_INFO) failed");
            else Log.Debug("Desktop notification: {Title}", title);
        }
        catch (Exception ex) { Log.Warning(ex, "Showing a desktop notification failed"); }
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    private NOTIFYICONDATA NewData() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _hwnd,
        uID = IconId,
        szTip = "",
        szInfo = "",
        szInfoTitle = "",
    };

    private IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == CallbackMessage)
        {
            int evt = (int)((long)lParam & 0xFFFF);
            if (evt == NIN_BALLOONUSERCLICK)
            {
                var page = _clickPage;
                Dispatcher.UIThread.Post(() => Clicked?.Invoke(page));
            }
            return IntPtr.Zero;
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    public void Dispose()
    {
        _alerts.AlertRaised -= OnAlert;
        _feed.IncidentsChanged -= OnIncidentsChanged;
        try
        {
            if (_iconAdded) { var d = NewData(); Shell_NotifyIcon(NIM_DELETE, ref d); _iconAdded = false; }
            if (_hwnd != IntPtr.Zero) { DestroyWindow(_hwnd); _hwnd = IntPtr.Zero; }
            if (_hIcon != IntPtr.Zero) { DestroyIcon(_hIcon); _hIcon = IntPtr.Zero; }
        }
        catch { }
    }

    // ------------------------------------------------------------------ interop

    private const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIM_SETVERSION = 4;
    private const uint NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4, NIF_STATE = 0x8, NIF_INFO = 0x10;
    private const uint NIS_HIDDEN = 0x1;
    private const uint NIIF_INFO = 0x1, NIIF_WARNING = 0x2, NIIF_ERROR = 0x3;
    private const int NIN_BALLOONUSERCLICK = 0x0400 + 5;

    private delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIcon(uint message, ref NOTIFYICONDATA data);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint ExtractIconEx(string file, int index, IntPtr[]? large, IntPtr[]? small, uint count);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern ushort RegisterClassEx(ref WNDCLASSEX cls);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(uint exStyle, string cls, string name, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll")] private static extern IntPtr LoadIcon(IntPtr instance, IntPtr name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string? name);
}
