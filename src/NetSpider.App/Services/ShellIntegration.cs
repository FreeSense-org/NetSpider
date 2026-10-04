using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.ViewModels;
using NetSpider.App.Views;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Wires the "real app" essentials into the main window: crash notice, window-state memory, tray + close-to-tray,
/// start minimized, desktop notifications, capture janitor, single-instance activation, keyboard shortcuts, the first-run
/// welcome wizard, auto-start monitoring and the runtime log level. Called once from <c>App.OnFrameworkInitializationCompleted</c>.
/// </summary>
public static class ShellIntegration
{
    private static readonly List<IDisposable> Owned = [];
    private static TrayService? _tray;
    private static DesktopNotifier? _notifier;
    private static WindowStateStore? _windowState;
    private static bool _quitting;
    private static bool _trayHintShown;
    private static WindowState _restoreState = WindowState.Normal;

    public static void Attach(IClassicDesktopStyleApplicationLifetime desktop, Window window, MainWindowViewModel vm, IServiceProvider sp, AppOptions options)
    {
        var store = sp.GetRequiredService<ISettingsStore>();
        var settings = store.Settings;
        bool screenshotMode = options.HideBanners;

        Step("log level", () => AppLogging.Apply(settings.LogLevel));
        Step("crash notice", () => { if (!screenshotMode) vm.SetPreviousCrash(CrashReporter.CheckPreviousSession()); });
        Step("npcap status", () => vm.RecheckNpcap(refreshAdapters: false));
        Step("settings hooks", () =>
        {
            vm.Settings.AttachServices(sp);
            vm.Settings.ShowWelcomeAction = () => vm.ShowWelcomeCommand.Execute(null);
        });

        // ---- window placement / page / inspector ----
        Step("window state", () =>
        {
            _windowState = new WindowStateStore(store);
            if (!screenshotMode) _windowState.Restore(window, vm, applyPage: options.Page is null);
        });

        // ---- tray ----
        var feed = sp.GetRequiredService<DiagnosticsFeed>();
        Step("tray", () =>
        {
            _tray = new TrayService(window, vm, feed, sp.GetService<IScanOrchestrator>(), Quit);
            _tray.Start();
            Owned.Add(_tray);
        });

        // ---- desktop notifications ----
        Step("desktop notifier", () =>
        {
            _notifier = new DesktopNotifier(store, sp.GetRequiredService<IAlertService>(), feed, () => !window.IsVisible || window.WindowState == WindowState.Minimized);
            _notifier.Clicked += page => { vm.Navigate(page); RestoreWindow(window); };
            _notifier.Start();
            Owned.Add(_notifier);
        });

        // ---- capture janitor ----
        Step("capture janitor", () =>
        {
            var janitor = new CaptureJanitor(store, sp.GetService<IPacketRecorder>());
            janitor.Start();
            Owned.Add(janitor);
        });

        // ---- close to tray / save state on exit ----
        window.Closing += (_, e) =>
        {
            bool userClose = e.CloseReason is WindowCloseReason.WindowClosing && !e.IsProgrammatic;
            if (!_quitting && userClose && settings.CloseToTray && _tray is not null)
            {
                e.Cancel = true;
                _windowState?.Save(window, vm);
                HideToTray(window);
                return;
            }
            if (!screenshotMode) _windowState?.Save(window, vm);
        };
        desktop.Exit += (_, _) =>
        {
            foreach (var d in Owned.AsEnumerable().Reverse()) { try { d.Dispose(); } catch { } }
            Owned.Clear();
            SingleInstance.Current?.Dispose();
        };

        // ---- start minimized to the tray (--minimized from the logon task, or the setting) ----
        bool startHidden = (options.Minimized || settings.StartMinimizedToTray) && _tray is not null && !screenshotMode;
        if (startHidden)
        {
            _restoreState = window.WindowState == WindowState.Maximized ? WindowState.Maximized : WindowState.Normal;
            window.ShowInTaskbar = false;
            window.WindowState = WindowState.Minimized;
            void OnOpened(object? s, EventArgs e)
            {
                window.Opened -= OnOpened;
                window.Hide();
                window.ShowInTaskbar = true;
                Log.Information("Started minimized to the tray");
            }
            window.Opened += OnOpened;
        }

        // ---- second launch → activate ----
        if (SingleInstance.Current is { } single)
            single.Activated += args => Dispatcher.UIThread.Post(() =>
            {
                var o = AppOptions.Parse(args);
                if (o.Page is { } page) vm.Navigate(page);
                RestoreWindow(window);
            });

        // ---- keyboard shortcuts ----
        Step("shortcuts", () => AddShortcuts(window, vm));

        // ---- first-run welcome / auto-start monitoring / test switches ----
        bool showWelcome = !settings.WelcomeShown && !options.Demo && !screenshotMode && !options.NoWelcome && !startHidden;
        window.Opened += async (_, _) =>
        {
            try
            {
                if (showWelcome)
                {
                    await Task.Delay(400);
                    await WelcomeWindow.ShowAsync(vm, store);
                }
                // after an update: what's new (a first install just remembers the version)
                if (!startHidden) WhatsNewWindowViewModel.ShowAtStartup(store, options, firstRun: showWelcome || !settings.WelcomeShown);
                else if (settings.AutoStartMonitoring && !options.Demo && !screenshotMode) AutoStartMonitoring(vm, settings);
                if (options.TestCrash is { } mode) CrashReporter.TriggerTestCrash(mode);
                if (options.TestToast)
                    DispatcherTimer.RunOnce(() => _notifier?.Enqueue("Test notification", "NetSpider desktop notifications work. Click to open Incidents.", AlertSeverity.Warning, "incidents", force: true),
                        TimeSpan.FromSeconds(2));
            }
            catch (Exception ex) { Log.Warning(ex, "Startup actions failed"); }
        };
    }

    private static void Step(string name, Action a)
    {
        try { a(); }
        catch (Exception ex) { Log.Error(ex, "Shell integration step {Step} failed", name); }
    }

    private static void AutoStartMonitoring(MainWindowViewModel vm, AppSettings settings)
    {
        if (vm.SelectedAdapter is null || vm.SelectedAdapter.Adapter.Id != settings.LastAdapterId)
        {
            Log.Information("Auto-start monitoring skipped: the last adapter ({Id}) is not available", settings.LastAdapterId);
            return;
        }
        if (!vm.StartMonitoringCommand.CanExecute(null))
        {
            Log.Information("Auto-start monitoring skipped: monitoring is not possible (Npcap/adapter)");
            return;
        }
        Log.Information("Auto-starting monitoring on {Adapter}", vm.SelectedAdapter.Title);
        vm.StartMonitoringCommand.Execute(null);
    }

    // ================================================================================================ window

    public static void HideToTray(Window window)
    {
        if (window.WindowState != WindowState.Minimized) _restoreState = window.WindowState;
        window.Hide();
        if (!_trayHintShown)
        {
            _trayHintShown = true;
            _notifier?.Enqueue("NetSpider is still running in the tray",
                "Monitoring continues in the background. Use the tray icon to open NetSpider again or to quit.", AlertSeverity.Info, "web", force: true);
        }
    }

    /// <summary>Shows, un-minimizes and activates the main window (tray click, second launch, notification click).</summary>
    public static void RestoreWindow(Window window)
    {
        try
        {
            window.ShowInTaskbar = true;
            if (!window.IsVisible) window.Show();
            if (window.WindowState == WindowState.Minimized) window.WindowState = _restoreState;
            window.Activate();
            if (window.TryGetPlatformHandle()?.Handle is { } h && h != IntPtr.Zero)
            {
                SetForegroundWindow(h);
            }
        }
        catch (Exception ex) { Log.Warning(ex, "Restoring the window failed"); }
    }

    /// <summary>Real exit (tray Quit): bypasses close-to-tray.</summary>
    public static void Quit()
    {
        _quitting = true;
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
        {
            if (d.MainWindow is { } w) w.Close();
            else d.Shutdown();
        }
    }

    /// <summary>
    /// <c>MainWindowViewModel.ShowAboutCommand</c> if this build has it (the About dialog is a separate workstream);
    /// resolved by reflection so the tray menu works either way.
    /// </summary>
    public static ICommand? AboutCommand(MainWindowViewModel vm) =>
        typeof(MainWindowViewModel).GetProperty("ShowAboutCommand", BindingFlags.Public | BindingFlags.Instance)?.GetValue(vm) as ICommand;

    // ================================================================================================ shortcuts

    private static void AddShortcuts(Window window, MainWindowViewModel vm)
    {
        vm.ApplyShortcutTips();
        void Bind(Key key, KeyModifiers mods, ICommand command, object? parameter = null) =>
            window.KeyBindings.Add(new KeyBinding { Gesture = new KeyGesture(key, mods), Command = command, CommandParameter = parameter! });

        Bind(Key.F5, KeyModifiers.None, vm.FullScanCommand);
        Bind(Key.M, KeyModifiers.Control, vm.ToggleMonitoringCommand);
        Bind(Key.F, KeyModifiers.Control, vm.FocusSearchCommand);
        Bind(Key.OemComma, KeyModifiers.Control, vm.NavigateToCommand, "settings");
        for (int i = 1; i <= 9; i++)
        {
            Bind(Key.D0 + i, KeyModifiers.Control, vm.NavigateIndexCommand, i.ToString());
            Bind(Key.NumPad0 + i, KeyModifiers.Control, vm.NavigateIndexCommand, i.ToString());
        }

        vm.FocusSearchRequested += () =>
        {
            var box = window.GetVisualDescendants().OfType<WebView>().FirstOrDefault()?
                .GetVisualDescendants().OfType<TextBox>().FirstOrDefault(t => t.IsEffectivelyVisible);
            if (box is null) return;
            box.Focus();
            box.SelectAll();
        };
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);
}
