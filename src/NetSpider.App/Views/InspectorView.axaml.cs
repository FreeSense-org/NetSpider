using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using NetSpider.App.ViewModels;

namespace NetSpider.App.Views;

public partial class InspectorView : UserControl
{
    public InspectorView()
    {
        InitializeComponent();
        // rename on Enter / focus loss
        NameBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) { Commit(); e.Handled = true; }
            else if (e.Key == Key.Escape && DataContext is InspectorViewModel vm) { vm.EditName = vm.Device?.UserLabel ?? vm.DisplayName; e.Handled = true; }
        };
        NameBox.LostFocus += (_, _) => Commit();
    }

    private void Commit()
    {
        if (DataContext is InspectorViewModel vm && vm.Device is not null && vm.EditName != vm.DisplayName && vm.RenameCommand.CanExecute(null))
            vm.RenameCommand.Execute(null);
    }
}
