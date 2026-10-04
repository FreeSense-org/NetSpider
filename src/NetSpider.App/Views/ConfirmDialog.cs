using Avalonia;
using Avalonia.Controls;

using Avalonia.Layout;
using Avalonia.Media;
using NetSpider.App.Services;

namespace NetSpider.App.Views;

/// <summary>A small modal "are you sure" dialog in the neon style (used before anything that transmits on the network).</summary>
public static class ConfirmDialog
{
    public static async Task<bool> ShowAsync(string title, string message, string warning, string confirmText, Window? ownerWindow = null)
    {
        var owner = ownerWindow ?? Dialogs.Owner;
        bool result = false;
        var win = new Window
        {
            Title = title,
            Width = 520,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false,
            Background = new SolidColorBrush(Color.Parse("#0D1424")),
        };
        IBrush Res(string key) => Application.Current?.TryGetResource(key, null, out var v) == true && v is IBrush b ? b : Brushes.White;
        Geometry Geo(string key) => Application.Current?.TryGetResource(key, null, out var v) == true && v is Geometry g ? g : new StreamGeometry();

        var confirm = new Button { Content = confirmText, Classes = { "danger" }, MinWidth = 140, HorizontalContentAlignment = HorizontalAlignment.Center };
        var cancel = new Button { Content = "Cancel", Classes = { "ghost" }, MinWidth = 100, HorizontalContentAlignment = HorizontalAlignment.Center, IsDefault = true };
        confirm.Click += (_, _) => { result = true; win.Close(); };
        cancel.Click += (_, _) => win.Close();

        var warnBox = new Border
        {
            Classes = { "banner", "warn" },
            Margin = new Thickness(0, 4, 0, 0),
            Child = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                Children =
                {
                    new Avalonia.Controls.Shapes.Path { Data = Geo("IconWarn"), Stroke = Res("AmberBrush"), StrokeThickness = 1.7, Width = 18, Height = 18, Stretch = Stretch.Uniform, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 0, 0) },
                    new TextBlock { Text = warning, TextWrapping = TextWrapping.Wrap, FontSize = 12.5, Margin = new Thickness(12, 0, 0, 0), [Grid.ColumnProperty] = 1 },
                },
            },
        };
        win.Content = new StackPanel
        {
            Margin = new Thickness(22, 20, 22, 18),
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = title, Classes = { "h2" } },
                new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Classes = { "dim" } },
                warnBox,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 6, 0, 0), Children = { cancel, confirm } },
            },
        };
        if (owner is not null) await win.ShowDialog(owner);
        else
        {
            var tcs = new TaskCompletionSource();
            win.Closed += (_, _) => tcs.TrySetResult();
            win.Show();
            await tcs.Task;
        }
        return result;
    }
}
