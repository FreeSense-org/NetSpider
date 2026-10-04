using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using NetSpider.Core.Services;

namespace NetSpider.App.ViewModels;

/// <summary>One row of the device grid; updated in place so sorting/selection survive refreshes.</summary>
public sealed partial class DeviceRow(Device device) : ObservableObject
{
    public Device Device { get; } = device;
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private DeviceType _type;
    [ObservableProperty] private string _typeText = "";
    [ObservableProperty] private string _brandModel = "";
    [ObservableProperty] private string _ip = "";
    [ObservableProperty] private string _ipSort = "";
    [ObservableProperty] private string _mac = "";
    [ObservableProperty] private string _vendor = "";
    [ObservableProperty] private double? _l2;
    [ObservableProperty] private double? _l3;
    [ObservableProperty] private string _l2Text = "—";
    [ObservableProperty] private string _l3Text = "—";
    [ObservableProperty] private IBrush _l2Brush = Ui.Dim;
    [ObservableProperty] private IBrush _l3Brush = Ui.Dim;
    [ObservableProperty] private double _loss;
    [ObservableProperty] private string _lossText = "";
    [ObservableProperty] private string _openPorts = "";
    [ObservableProperty] private string _vlan = "";
    [ObservableProperty] private DateTimeOffset _firstSeen;
    [ObservableProperty] private DateTimeOffset _lastSeen;
    [ObservableProperty] private string _lastSeenText = "";
    [ObservableProperty] private string _state = "";
    [ObservableProperty] private IBrush _stateBrush = Ui.Green;
    [ObservableProperty] private string? _logoPath;
    [ObservableProperty] private Avalonia.Media.Color _ringColor;
    [ObservableProperty] private bool _isNew;
    public string Search { get; private set; } = "";
    private int _version = -1;
    private long _tick;

    public void Update(AppSettings s, bool force = false)
    {
        var d = Device;
        // latency changes without a version bump; refresh at least every few ticks
        if (!force && d.Version == _version && ++_tick % 4 != 0) return;
        _version = d.Version;
        Name = d.DisplayName;
        Type = d.Type;
        TypeText = d.Type.ToString();
        BrandModel = string.Join(" ", new[] { d.Brand, d.Model }.Where(x => !string.IsNullOrWhiteSpace(x)));
        var ip = d.PrimaryIPv4;
        Ip = ip?.ToString() ?? d.IPv6.FirstOrDefault()?.Address.ToString() ?? "";
        IpSort = ip is null ? "~" : string.Join('.', ip.GetAddressBytes().Select(b => b.ToString("D3")));
        Mac = SyntheticNodes.IsSynthetic(d.Mac) ? "(synthetic)" : d.Mac.ToString();
        Vendor = d.Mac.IsRandomized && !SyntheticNodes.IsSynthetic(d.Mac) ? "Private MAC" : d.OuiVendor ?? "";
        L2 = d.Latency.Last(LatencyKind.Arp) ?? d.Latency.Last(LatencyKind.Ndp);
        L3 = d.Latency.Last(LatencyKind.Icmp);
        L2Text = Neon.FormatMs(L2);
        L3Text = Neon.FormatMs(L3);
        L2Brush = Ui.LatencyBrush(L2, s);
        L3Brush = Ui.LatencyBrush(L3, s);
        var sum = d.Latency.Summarize(LatencyKind.Icmp, 30);
        if (sum.Count == 0) sum = d.Latency.Summarize(LatencyKind.Arp, 30);
        Loss = sum.LossPercent;
        LossText = sum.Count == 0 ? "" : $"{sum.LossPercent:0.#} %";
        OpenPorts = string.Join(", ", d.Ports.Where(p => p.State == PortState.Open).Select(p => p.Port).Take(12));
        var vl = d.Vlans;
        Vlan = vl.Length > 0 ? string.Join(",", vl) : d.NativeVlan?.ToString() ?? "";
        FirstSeen = d.FirstSeen;
        LastSeen = d.LastSeen;
        LastSeenText = InspectorViewModel.Ago(d.LastSeen);
        State = d.State.ToString();
        StateBrush = d.State switch { DeviceState.Offline => Ui.Grey, DeviceState.Flapping => Ui.Amber, _ => Ui.Green };
        LogoPath = d.LogoPath;
        RingColor = d.State == DeviceState.Offline ? Ui.ToColor(Neon.Grey) : Ui.ToColor(Neon.Latency(L2 ?? L3, s));
        IsNew = d.Has(DeviceFlags.New);
        Search = $"{Name} {BrandModel} {Ip} {Mac} {Vendor} {TypeText} {d.Hostname}".ToLowerInvariant();
    }
}

public sealed partial class DevicesViewModel : ObservableObject
{
    private readonly IDeviceStore _store;
    private readonly AppSettings _settings;
    private readonly Dictionary<Mac, DeviceRow> _rows = new();
    private Throttler? _throttle;

    public DevicesViewModel(IDeviceStore store, AppSettings settings, SelectionService selection)
    {
        _store = store;
        _settings = settings;
        Selection = selection;
        store.DeviceAdded += _ => _throttle?.Signal();
        store.DeviceChanged += (_, _) => _throttle?.Signal();
        store.DeviceRemoved += _ => _throttle?.Signal();
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            _throttle = new Throttler(TimeSpan.FromMilliseconds(500), Refresh);
            // periodic refresh keeps latency columns live even without change events
            var t = new Avalonia.Threading.DispatcherTimer(TimeSpan.FromSeconds(2), Avalonia.Threading.DispatcherPriority.Background, (_, _) => _throttle.Signal());
            t.Start();
            Refresh();
        });
        selection.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(SelectionService.Selected)) return;
            var sel = selection.Selected;
            if (sel is not null && _rows.TryGetValue(sel.Mac, out var row) && SelectedRow != row) { _suppress = true; SelectedRow = row; _suppress = false; }
        };
    }

    private bool _suppress;
    public SelectionService Selection { get; }
    public ObservableCollection<DeviceRow> Rows { get; } = [];
    public Action<Device>? Activated { get; set; }

    [ObservableProperty] private string? _searchText;
    [ObservableProperty] private DeviceRow? _selectedRow;
    [ObservableProperty] private string _summary = "";

    partial void OnSearchTextChanged(string? value) => Refresh();
    partial void OnSelectedRowChanged(DeviceRow? value)
    {
        if (_suppress || value is null) return;
        Activated?.Invoke(value.Device);
    }

    public void Refresh()
    {
        var all = _store.All;
        var live = new HashSet<Mac>();
        foreach (var d in all)
        {
            live.Add(d.Mac);
            // a MAC can come back as a new Device object (store cleared by a demo/real switch): never keep a row of the old one
            if (!_rows.TryGetValue(d.Mac, out var row) || !ReferenceEquals(row.Device, d)) { row = new DeviceRow(d); _rows[d.Mac] = row; row.Update(_settings, true); }
            else row.Update(_settings);
        }
        foreach (var m in _rows.Keys.Where(m => !live.Contains(m)).ToList()) _rows.Remove(m);

        var q = (SearchText ?? "").Trim().ToLowerInvariant();
        var wanted = _rows.Values.Where(r => q.Length == 0 || r.Search.Contains(q)).ToHashSet();
        for (int i = Rows.Count - 1; i >= 0; i--) if (!wanted.Contains(Rows[i])) Rows.RemoveAt(i);
        var present = Rows.ToHashSet();
        foreach (var r in wanted.OrderBy(r => r.IpSort, StringComparer.Ordinal)) if (!present.Contains(r)) Rows.Add(r);

        int online = all.Count(d => d.State == DeviceState.Online);
        Summary = $"{all.Count} devices · {online} online · {all.Count(d => d.Has(DeviceFlags.New))} new" + (q.Length > 0 ? $" · {Rows.Count} match" : "");
    }

    /// <summary>Drops every cached row (demo/real switch) and rebuilds from the store.</summary>
    public void Reset()
    {
        _suppress = true;
        SelectedRow = null;
        _suppress = false;
        _rows.Clear();
        Rows.Clear();
        Refresh();
    }

    [RelayCommand] private void ClearSearch() => SearchText = null;
}
