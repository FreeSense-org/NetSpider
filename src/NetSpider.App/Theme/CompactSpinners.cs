using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;

namespace NetSpider.App;

/// <summary>
/// Fluent's ButtonSpinner/NumericUpDown templates set MinWidth on the spin buttons and a negative Margin on the inner
/// TextBox inline (template priority beats styles), which clips our rounded frame. Override them as local values.
/// </summary>
internal static class CompactSpinners
{
    private static bool _registered;

    public static void Register()
    {
        if (_registered) return;
        _registered = true;
        TemplatedControl.TemplateAppliedEvent.AddClassHandler<NumericUpDown>((nud, e) =>
        {
            if (e.NameScope.Find<TextBox>("PART_TextBox") is { } tb) tb.Margin = new Thickness(0);
        });
        TemplatedControl.TemplateAppliedEvent.AddClassHandler<ButtonSpinner>((spinner, e) =>
        {
            foreach (var name in new[] { "PART_IncreaseButton", "PART_DecreaseButton" })
                if (e.NameScope.Find<RepeatButton>(name) is { } b)
                {
                    b.MinWidth = 22;
                    b.Width = 22;
                }
        });
    }
}
