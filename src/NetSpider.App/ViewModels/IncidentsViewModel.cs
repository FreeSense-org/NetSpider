using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Services;
using NetSpider.Core.Model;

namespace NetSpider.App.ViewModels;

public sealed partial class IncidentRow : ObservableObject
{
    private readonly IncidentsViewModel _owner;

    public IncidentRow(Incident incident, IncidentsViewModel owner)
    {
        _owner = owner;
        Incident = incident;
        Update(incident);
    }

    public Guid Id => Incident.Id;
    [ObservableProperty] private Incident _incident;
    [ObservableProperty] private bool _isExpanded;
    [ObservableProperty] private string _duration = "";
    [ObservableProperty] private string _endText = "";
    [ObservableProperty] private string _affectedText = "";
    [ObservableProperty] private IReadOnlyList<string> _affectedNames = [];
    [ObservableProperty] private string _suspectText = "";

    public string Title => Incident.Title;
    public string RootCause => Incident.RootCause;
    public double Confidence => Incident.Confidence;
    public string ConfidenceText => $"{Incident.Confidence * 100:0} %";
    public IBrush ConfidenceBrush => Incident.Confidence >= 0.75 ? Ui.Cyan : Incident.Confidence >= 0.5 ? Ui.Amber : Ui.Grey;
    public bool Ongoing => Incident.Ongoing;
    public IBrush Accent => AlertsViewModel.SeverityBrush(Incident.Severity);
    public IBrush AccentSoft => new SolidColorBrush(((ISolidColorBrush)Accent).Color, Incident.Ongoing ? 0.55 : 0.14);
    public IBrush CardBackground => Incident.Ongoing ? new SolidColorBrush(Color.Parse("#160D1A")) : new SolidColorBrush(Color.Parse("#0D1424"));
    public string Severity => Incident.Severity.ToString().ToUpperInvariant();
    public string Category => IncidentsViewModel.CategoryName(Incident.Category);
    public Geometry CategoryIcon => Diag.Icon(Incident.Category switch
    {
        IncidentCategory.OwnLink => "IconCable",
        IncidentCategory.LocalNetwork => "IconSegments",
        IncidentCategory.SwitchPort => "IconPort",
        IncidentCategory.Wifi => "IconWifi",
        IncidentCategory.Router => "IconRouterBox",
        IncidentCategory.Modem => "IconRouterBox",
        IncidentCategory.Isp => "IconGlobe",
        IncidentCategory.Storm => "IconStorm",
        IncidentCategory.Loop => "IconLoop",
        _ => "IconInfo",
    });
    public string StartText => Incident.Start.ToString("HH:mm:ss");
    public string StartDate => Incident.Start.Date == DateTime.Today ? "today" : Incident.Start.ToString("MMM d");
    public IReadOnlyList<string> Evidence => Incident.Evidence;
    public bool HasEvidence => Incident.Evidence.Count > 0;
    public bool HasAffected => Incident.Affected.Count > 0;
    public bool HasPcap => !string.IsNullOrEmpty(Incident.PcapPath);
    public string PcapName => Path.GetFileName(Incident.PcapPath ?? "");
    public bool HasSuspect => Incident.SuspectDevice is not null;
    public bool HasLink => !string.IsNullOrEmpty(Incident.SuspectLink);
    public string LinkText => Incident.SuspectLink ?? "";
    public string ExpandText => IsExpanded ? "Hide devices" : "Show devices";
    partial void OnIsExpandedChanged(bool value) => OnPropertyChanged(nameof(ExpandText));

    public void Update(Incident i)
    {
        bool changed = !ReferenceEquals(i, Incident);
        Incident = i;
        Duration = Diag.Duration(i.Duration);
        EndText = i.End is { } e ? Diag.When(e) : "ongoing";
        AffectedText = i.Affected.Count == 1 ? "1 device affected" : $"{i.Affected.Count} devices affected";
        AffectedNames = i.Affected.Select(m => $"{_owner.Name(m)}  ·  {m}").ToList();
        SuspectText = i.SuspectDevice is { } s ? _owner.Name(s) + (i.SuspectPort is { } p ? $" · {p}" : "") : "";
        if (changed) OnPropertyChanged(string.Empty);
    }

    [RelayCommand] private void ToggleExpand() => IsExpanded = !IsExpanded;
    [RelayCommand] private void OpenPcap() => _owner.OpenPcap(Incident.PcapPath);
    [RelayCommand] private void ShowSuspect() { if (Incident.SuspectDevice is { } m) _owner.NavigateToDevice?.Invoke(m); }
}

public sealed record SignalRow(string Time, string Kind, string Summary, string Source, IBrush Brush);

/// <summary>Incidents page: correlated problems with a root-cause sentence, newest/ongoing first.</summary>
public sealed partial class IncidentsViewModel : ObservableObject
{
    private readonly DiagnosticsFeed _feed;
    private readonly Throttler _throttle;
    private readonly Dictionary<Guid, IncidentRow> _rows = new();
    private readonly DispatcherTimer _clock;

    public IncidentsViewModel(DiagnosticsFeed feed)
    {
        _feed = feed;
        Categories = ["All categories", .. Enum.GetValues<IncidentCategory>().Select(CategoryName)];
        _selectedCategory = Categories[0];
        _throttle = new Throttler(TimeSpan.FromMilliseconds(400), Refresh);
        feed.IncidentsChanged += _throttle.Signal;
        feed.SignalsChanged += _throttle.Signal;
        feed.SourceChanged += _throttle.Signal;
        // ongoing durations tick even without new events
        _clock = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, (_, _) =>
        {
            foreach (var r in Items) if (r.Ongoing) r.Duration = Diag.Duration(r.Incident.Duration);
        });
        _clock.Start();
        Refresh();
    }

    public Action<Mac>? NavigateToDevice { get; set; }
    public ObservableCollection<IncidentRow> Items { get; } = [];
    public ObservableCollection<SignalRow> Signals { get; } = [];
    public IReadOnlyList<string> Categories { get; }

    [ObservableProperty] private string _selectedCategory;
    [ObservableProperty] private bool _activeOnly;
    [ObservableProperty] private int _activeCount;
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private bool _isEmpty = true;
    [ObservableProperty] private string _emptyTitle = "";
    [ObservableProperty] private string _emptyText = "";
    [ObservableProperty] private bool _hasSignals;
    [ObservableProperty] private string? _message;
    [ObservableProperty] private bool _available;

    partial void OnSelectedCategoryChanged(string value) => Refresh();
    partial void OnActiveOnlyChanged(bool value) => Refresh();

    public static string CategoryName(IncidentCategory c) => c switch
    {
        IncidentCategory.OwnLink => "This PC's link",
        IncidentCategory.LocalNetwork => "Local network",
        IncidentCategory.SwitchPort => "Switch port",
        IncidentCategory.Wifi => "Wi-Fi",
        IncidentCategory.Router => "Router",
        IncidentCategory.Modem => "Modem",
        IncidentCategory.Isp => "ISP",
        IncidentCategory.Storm => "Storm",
        IncidentCategory.Loop => "Loop",
        _ => "Unknown",
    };

    public string Name(Mac m) => _feed.NameOf(m);

    public void OpenPcap(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (File.Exists(path)) { if (!Launcher.Open(path)) Launcher.Run("explorer.exe", $"/select,\"{path}\""); }
        else if (Directory.Exists(Path.GetDirectoryName(path))) { Launcher.Open(Path.GetDirectoryName(path)!); Message = $"{Path.GetFileName(path)} is no longer on disk — opened the captures folder."; }
        else Message = _feed.IsDemo ? $"Demo incident — {Path.GetFileName(path)} doesn't exist." : $"Capture not found: {path}";
    }

    [RelayCommand]
    private void Clear()
    {
        try { _feed.Incidents?.Clear(); }
        catch (Exception ex) { Message = "Clear failed: " + ex.Message; }
        _rows.Clear();
        Refresh();
    }

    private void Refresh()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }
        var svc = _feed.Incidents;
        Available = svc is not null;
        var all = svc?.Incidents ?? [];
        ActiveCount = all.Count(i => i.Ongoing);
        TotalCount = all.Count;
        IncidentCategory? cat = Enum.GetValues<IncidentCategory>().Cast<IncidentCategory?>().FirstOrDefault(c => CategoryName(c!.Value) == SelectedCategory);
        var wanted = all
            .Where(i => cat is null || i.Category == cat)
            .Where(i => !ActiveOnly || i.Ongoing)
            .OrderByDescending(i => i.Ongoing).ThenByDescending(i => i.Start)
            .Take(300).ToList();

        foreach (var gone in _rows.Keys.Where(k => all.All(i => i.Id != k)).ToList()) _rows.Remove(gone);
        var rows = new List<IncidentRow>(wanted.Count);
        foreach (var i in wanted)
        {
            if (_rows.TryGetValue(i.Id, out var r)) r.Update(i);
            else { r = new IncidentRow(i, this) { IsExpanded = false }; _rows[i.Id] = r; }
            rows.Add(r);
        }
        if (!rows.SequenceEqual(Items))
        {
            Items.Clear();
            foreach (var r in rows) Items.Add(r);
        }
        IsEmpty = Items.Count == 0;
        (EmptyTitle, EmptyText) = svc is null
            ? ("Incidents aren't available in this build", "The fault locator engine isn't installed yet. Turn on \"Demo network\" to see how incidents look.")
            : all.Count == 0
                ? ("No incidents — the path is clean", "When a hop, switch port, AP or your own link fails, NetSpider correlates the signals into an incident with a root-cause sentence, the affected devices and the evidence.")
                : ("Nothing matches the filter", "Clear the category filter or turn off \"Active only\".");

        var sig = _feed.Signals.Take(14).ToList();
        Signals.Clear();
        foreach (var s in sig)
            Signals.Add(new SignalRow(s.Time.ToString("HH:mm:ss"), s.Kind.ToString(), s.Summary, s.Source,
                s.Weight >= 0.75 ? Ui.Red : s.Weight >= 0.45 ? Ui.Amber : Ui.Cyan));
        HasSignals = Signals.Count > 0;
    }
}
