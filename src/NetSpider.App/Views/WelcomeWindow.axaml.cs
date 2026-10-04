using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using NetSpider.App.Services;
using NetSpider.App.ViewModels;
using NetSpider.Core;
using NetSpider.Core.Abstractions;
using Serilog;

namespace NetSpider.App.Views;

/// <summary>Modal first-run wizard (see <see cref="WelcomeViewModel"/>).</summary>
public partial class WelcomeWindow : Window
{
    private static bool _open;

    public WelcomeWindow()
    {
        AvaloniaXamlLoader.Load(this);
        Title = $"Welcome to {AppInfo.BrandTitle}";
    }

    /// <summary>Shows the wizard modally over the main window (no-op when it is already open).</summary>
    public static async Task ShowAsync(MainWindowViewModel main, ISettingsStore store)
    {
        if (_open) return;
        _open = true;
        try
        {
            var vm = new WelcomeViewModel(main, store);
            var win = new WelcomeWindow { DataContext = vm };
            if (Dialogs.Owner?.Icon is { } icon) win.Icon = icon;
            vm.CloseRequested += win.Close;
            win.Closed += (_, _) => vm.OnClosedWithoutFinishing();
            if (Dialogs.Owner is { IsVisible: true } owner) await win.ShowDialog(owner);
            else
            {
                var tcs = new TaskCompletionSource();
                win.Closed += (_, _) => tcs.TrySetResult();
                win.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                win.Show();
                await tcs.Task;
            }
        }
        catch (Exception ex) { Log.Error(ex, "Welcome wizard failed"); }
        finally { _open = false; }
    }
}
