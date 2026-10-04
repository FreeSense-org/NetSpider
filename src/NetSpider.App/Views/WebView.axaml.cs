using Avalonia;
using Avalonia.Controls;
using NetSpider.App.ViewModels;

namespace NetSpider.App.Views;

public partial class WebView : UserControl
{
    private WebViewModel? _vm;

    public WebView() => InitializeComponent();

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_vm is not null)
        {
            _vm.FitRequested -= OnFit;
            _vm.FitWhenSettledRequested -= OnFitWhenSettled;
            _vm.ZoomRequested -= OnZoom;
            _vm.PngRenderer = null;
        }
        _vm = DataContext as WebViewModel;
        if (_vm is not null)
        {
            _vm.FitRequested += OnFit;
            _vm.FitWhenSettledRequested += OnFitWhenSettled;
            _vm.ZoomRequested += OnZoom;
            _vm.PngRenderer = (w, h) => Graph.RenderToPng(w, h);
        }
    }

    private void OnFit() => Graph.FitAnimated();
    private void OnFitWhenSettled() => Graph.FitWhenSettled();
    private void OnZoom(double f) => Graph.ZoomBy(f);
}
