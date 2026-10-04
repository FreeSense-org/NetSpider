using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Services;
using NetSpider.App.ViewModels;
using NetSpider.App.Views;
using Serilog;

namespace NetSpider.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        // A bug in one view must never take the whole app down: log UI-thread exceptions and keep running.
        Avalonia.Threading.Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            Serilog.Log.Error(e.Exception, "Unhandled UI exception (recovered)");
            CrashReporter.Write(e.Exception, "UI thread (recovered)", fatal: false);
            e.Handled = true;
        };

        CompactSpinners.Register();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var sp = AppHost.Build();
            var vm = sp.GetRequiredService<MainWindowViewModel>();
            var mainWindow = new MainWindow { DataContext = vm };
            desktop.MainWindow = mainWindow;
            desktop.ShutdownMode = Avalonia.Controls.ShutdownMode.OnMainWindowClose;
            desktop.Exit += (_, _) =>
            {
                Log.Information("Shutting down");
                try { vm.Shutdown(); } catch (Exception ex) { Log.Warning(ex, "Shutdown failed"); }
                AppHost.Dispose();
            };
            AppHost.StartStartables(sp);
            vm.Initialize(AppHost.Options);
            // tray, close-to-tray, window state, welcome, crash notice, shortcuts, notifications, single-instance activation
            ShellIntegration.Attach(desktop, mainWindow, vm, sp, AppHost.Options);
        }
        base.OnFrameworkInitializationCompleted();
    }
}
