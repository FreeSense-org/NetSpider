using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Controls.Graph;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.App.ViewModels;

public sealed partial class FilterChip(TypeGroup group, string label, Action changed) : ObservableObject
{
    public TypeGroup Group { get; } = group;
    public string Label { get; } = label;
    /// <summary>Checked = hidden (chip renders "off").</summary>
    [ObservableProperty] private bool _isHidden;
    partial void OnIsHiddenChanged(bool value) => changed();
}

public sealed record VlanOption(int? Id, string Label)
{
    public override string ToString() => Label;
}

/// <summary>State of the Spider Web page (mode, search, filters) around the <see cref="Controls.NetworkWebControl"/>.</summary>
public sealed partial class WebViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    private readonly ISettingsStore _store;
    private readonly INetworkState _network;

    public WebViewModel(GraphEngine engine, SelectionService selection, ISettingsStore store, INetworkState network)
    {
        Engine = engine;
        Selection = selection;
        _store = store;
        _settings = store.Settings;
        _network = network;
        _showMac = _settings.ShowMacOnNodes;
        _animations = _settings.Animations;
        Chips =
        [
            new(TypeGroup.Infrastructure, "Infrastructure", UpdateMask),
            new(TypeGroup.Computers, "Computers", UpdateMask),
            new(TypeGroup.Mobile, "Mobile", UpdateMask),
            new(TypeGroup.Media, "Media", UpdateMask),
            new(TypeGroup.SmartHome, "Smart home", UpdateMask),
            new(TypeGroup.Cameras, "Cameras", UpdateMask),
            new(TypeGroup.Printers, "Printers", UpdateMask),
            new(TypeGroup.Other, "Other", UpdateMask),
        ];
        VlanOptions.Add(new VlanOption(null, "All VLANs"));
        _selectedVlan = VlanOptions[0];
        engine.SnapshotChanged += s => Avalonia.Threading.Dispatcher.UIThread.Post(() => RefreshVlans(s));
    }

    public GraphEngine Engine { get; }
    public SelectionService Selection { get; }
    public ObservableCollection<FilterChip> Chips { get; }
    public ObservableCollection<VlanOption> VlanOptions { get; } = [];

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsWebMode), nameof(IsTreeMode), nameof(IsPortsMode), nameof(ModeHint))] private GraphViewMode _mode;
    [ObservableProperty] private string? _searchText;
    [ObservableProperty] private VlanOption? _selectedVlan;
    [ObservableProperty] private int _hiddenGroups;
    [ObservableProperty] private bool _showMac;
    [ObservableProperty] private bool _animations;
    [ObservableProperty] private bool _hasDevices;
    [ObservableProperty] private bool _filtersOpen;

    public int? VlanFilter => SelectedVlan?.Id;
    partial void OnSelectedVlanChanged(VlanOption? value) => OnPropertyChanged(nameof(VlanFilter));

    public bool IsWebMode { get => Mode == GraphViewMode.Web; set { if (value) Mode = GraphViewMode.Web; } }
    public bool IsTreeMode { get => Mode == GraphViewMode.Tree; set { if (value) Mode = GraphViewMode.Tree; } }
    public bool IsPortsMode { get => Mode == GraphViewMode.Ports; set { if (value) Mode = GraphViewMode.Ports; } }

    public string ModeHint => Mode switch
    {
        GraphViewMode.Tree => "Hierarchy: Internet → gateway → switches → endpoints",
        GraphViewMode.Ports => "Managed switch ports (SNMP IF-MIB + FDB) · hover a port for details",
        _ => "Click a device to see device↔device latency threads · drag to pin · double-click to unpin",
    };

    partial void OnShowMacChanged(bool value) { _settings.ShowMacOnNodes = value; SaveQuietly(); Engine.MarkDirty(); }
    partial void OnAnimationsChanged(bool value) { _settings.Animations = value; SaveQuietly(); }

    private void SaveQuietly() { try { _store.Save(); } catch { /* best effort */ } }

    private void UpdateMask()
    {
        int m = 0;
        foreach (var c in Chips) if (c.IsHidden) m |= 1 << (int)c.Group;
        HiddenGroups = m;
    }

    private void RefreshVlans(GraphSnapshot s)
    {
        var ids = s.Nodes.SelectMany(n => n.Vlans).Concat(_network.Vlans.Select(v => v.Id)).Distinct().OrderBy(v => v).ToList();
        var have = VlanOptions.Where(o => o.Id is not null).Select(o => o.Id!.Value).ToList();
        if (ids.SequenceEqual(have)) return;
        var keep = SelectedVlan?.Id;
        while (VlanOptions.Count > 1) VlanOptions.RemoveAt(1);
        foreach (var id in ids)
        {
            var name = _network.Vlans.FirstOrDefault(v => v.Id == id)?.Name;
            VlanOptions.Add(new VlanOption(id, name is null ? $"VLAN {id}" : $"VLAN {id} · {name}"));
        }
        SelectedVlan = VlanOptions.FirstOrDefault(o => o.Id == keep) ?? VlanOptions[0];
    }

    // ---- view hooks (set by the view) ----
    public event Action? FitRequested;
    public event Action<double>? ZoomRequested;
    public Func<int, int, byte[]>? PngRenderer { get; set; }

    public void RequestFit() => FitRequested?.Invoke();

    /// <summary>Fit once the (re)built graph has nodes and the physics had a moment to spread them (after a demo/real reset).</summary>
    public event Action? FitWhenSettledRequested;
    public void RequestFitWhenSettled() => FitWhenSettledRequested?.Invoke();

    public byte[] RenderPng(int w, int h) => PngRenderer?.Invoke(w, h)
        ?? GraphExport.RenderPng(Engine, new GraphViewState { Mode = Mode, ShowMac = ShowMac }, w, h);

    [RelayCommand] private void Fit() => FitRequested?.Invoke();
    [RelayCommand] private void ZoomIn() => ZoomRequested?.Invoke(1.25);
    [RelayCommand] private void ZoomOut() => ZoomRequested?.Invoke(0.8);
    [RelayCommand] private void ResetPins() => Engine.ClearPins();
    [RelayCommand] private void ClearSearch() => SearchText = null;
    [RelayCommand] private void ShowAllGroups() { foreach (var c in Chips) c.IsHidden = false; }
    [RelayCommand] private void ClearSelection() => Selection.Selected = null;
}
