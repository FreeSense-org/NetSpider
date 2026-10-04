using Avalonia.Controls;
using Avalonia.Interactivity;
using NetSpider.App.ViewModels;

namespace NetSpider.App.Views;

/// <summary>Modal update dialog (see <see cref="UpdateWindowViewModel"/>).</summary>
public partial class UpdateWindow : Window
{
    public UpdateWindow() => InitializeComponent();
}

/// <summary>Modal "What's new" dialog (see <see cref="WhatsNewWindowViewModel"/>).</summary>
public partial class WhatsNewWindow : Window
{
    public WhatsNewWindow() => InitializeComponent();
}

/// <summary>Modal About dialog (see <see cref="AboutWindowViewModel"/>).</summary>
public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is AboutWindowViewModel vm)
                vm.Clipboard = async text => { if (Clipboard is { } cb) await cb.SetTextAsync(text); };
        };
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
