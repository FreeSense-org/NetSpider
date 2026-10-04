using Avalonia;
using Avalonia.Controls;
using NetSpider.App.Services;
using NetSpider.App.ViewModels;

namespace NetSpider.App.Views;

public partial class MainWindow : Window
{
    /// <summary>Below this width the top bar hides secondary stat chips (links, dropped) so nothing gets clipped.</summary>
    private const double CompactWidth = 1800;

    public MainWindow()
    {
        InitializeComponent();
        Dialogs.Owner = this;
        ClientSizeProperty.Changed.AddClassHandler<MainWindow>((w, _) => w.UpdateCompact());
        DataContextChanged += (_, _) => UpdateCompact();
    }

    private void UpdateCompact()
    {
        if (DataContext is MainWindowViewModel vm) vm.CompactTopBar = ClientSize.Width < CompactWidth;
    }
}
