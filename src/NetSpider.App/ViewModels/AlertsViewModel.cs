using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.App.ViewModels;

public sealed partial class AlertRow(Alert alert, string? sourceName, AlertsViewModel owner) : ObservableObject
{
    public Alert Alert { get; } = alert;
    public string Title => Alert.Title;
    public string Details => Alert.Details;
    public string Kind => Spaced(Alert.Kind.ToString());
    public string Severity => Alert.Severity.ToString().ToUpperInvariant();
    public IBrush Accent => AlertsViewModel.SeverityBrush(Alert.Severity);
    public IBrush AccentSoft => new SolidColorBrush(((ISolidColorBrush)Accent).Color, 0.12);
    public Geometry Icon => AlertsViewModel.SeverityIcon(Alert.Severity);
    public string Time => Alert.Time.ToString("HH:mm:ss");
    public string Date => Alert.Time.Date == DateTime.Today ? "today" : Alert.Time.ToString("MMM d");
    public string Ago => InspectorViewModel.Ago(Alert.Time);
    public bool HasSource => Alert.Source is not null;
    public string SourceText => sourceName is null ? Alert.Source?.ToString() ?? "" : $"{sourceName}  ·  {Alert.Source}";
    public string? RateText => Alert.Rate is { } r ? $"{r:0.#} pps" : null;
    public bool HasRate => Alert.Rate is not null;

    [RelayCommand] private void ShowSource() { if (Alert.Source is { } m) owner.NavigateToDevice?.Invoke(m); }

    private static string Spaced(string s) => string.Concat(s.Select((c, i) => i > 0 && char.IsUpper(c) && !char.IsUpper(s[i - 1]) ? " " + c : c.ToString()));
}

public sealed record SeverityFilter(AlertSeverity? Min, string Label)
{
    public override string ToString() => Label;
}

public sealed partial class AlertsViewModel : ObservableObject
{
    private readonly IAlertService _alerts;
    private readonly IDeviceStore _devices;
    private readonly List<AlertRow> _all = [];

    public AlertsViewModel(IAlertService alerts, IDeviceStore devices)
    {
        _alerts = alerts;
        _devices = devices;
        Filters = [new(null, "All severities"), new(AlertSeverity.Warning, "Warning +"), new(AlertSeverity.Critical, "Critical only")];
        _selectedFilter = Filters[0];
        alerts.AlertRaised += a => Dispatcher.UIThread.Post(() =>
        {
            if (_all.Any(r => r.Alert.Id == a.Id)) return;
            // raised before a demo/real reset but delivered after it: the alert no longer exists, don't resurrect it
            if (!_alerts.Alerts.Any(x => x.Id == a.Id)) return;
            _all.Insert(0, Make(a));
            Apply();
        });
        Dispatcher.UIThread.Post(Reload);
    }

    public ObservableCollection<AlertRow> Items { get; } = [];
    public IReadOnlyList<SeverityFilter> Filters { get; }
    public Action<Mac>? NavigateToDevice { get; set; }
    public int Count => _all.Count;

    [ObservableProperty] private SeverityFilter _selectedFilter;
    [ObservableProperty] private string? _searchText;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _warningCount;
    [ObservableProperty] private int _infoCount;
    public bool IsEmpty => Items.Count == 0;

    partial void OnSelectedFilterChanged(SeverityFilter value) => Apply();
    partial void OnSearchTextChanged(string? value) => Apply();

    private AlertRow Make(Alert a) => new(a, a.Source is { } m && _devices.TryGet(m, out var d) ? d.DisplayName : null, this);

    public void Reload()
    {
        _all.Clear();
        _all.AddRange(_alerts.Alerts.OrderByDescending(a => a.Time).Select(Make));
        Apply();
    }

    private void Apply()
    {
        var q = (SearchText ?? "").Trim();
        var min = SelectedFilter.Min;
        var rows = _all.Where(r => (min is null || r.Alert.Severity >= min) &&
                                   (q.Length == 0 || r.Title.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Kind.Contains(q, StringComparison.OrdinalIgnoreCase)
                                    || r.Details.Contains(q, StringComparison.OrdinalIgnoreCase) || r.SourceText.Contains(q, StringComparison.OrdinalIgnoreCase)))
            .Take(1000).ToList();
        Items.Clear();
        foreach (var r in rows) Items.Add(r);
        CriticalCount = _all.Count(r => r.Alert.Severity == AlertSeverity.Critical);
        WarningCount = _all.Count(r => r.Alert.Severity == AlertSeverity.Warning);
        InfoCount = _all.Count(r => r.Alert.Severity == AlertSeverity.Info);
        OnPropertyChanged(nameof(Count));
        OnPropertyChanged(nameof(IsEmpty));
    }

    [RelayCommand]
    private void Clear()
    {
        _alerts.Clear();
        _all.Clear();
        Apply();
    }

    public static IBrush SeverityBrush(AlertSeverity s) => s switch
    {
        AlertSeverity.Critical => Ui.Red,
        AlertSeverity.Warning => Ui.Amber,
        _ => Ui.Cyan,
    };

    public static Geometry SeverityIcon(AlertSeverity s)
    {
        var key = s switch { AlertSeverity.Critical => "IconCritical", AlertSeverity.Warning => "IconWarn", _ => "IconInfo" };
        return Avalonia.Application.Current?.TryGetResource(key, null, out var g) == true && g is Geometry geo ? geo : new StreamGeometry();
    }
}
