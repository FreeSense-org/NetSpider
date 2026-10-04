using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Controls;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class InternetTargetRow : ObservableObject
{
    public required string Host { get; init; }
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _address = "";
    [ObservableProperty] private string _state = "";
    [ObservableProperty] private IBrush _stateBrush = Ui.Grey;
    [ObservableProperty] private string _last = "—";
    [ObservableProperty] private string _avg = "—";
    [ObservableProperty] private string _jitter = "—";
    [ObservableProperty] private string _loss = "—";
    [ObservableProperty] private string _range = "";
    [ObservableProperty] private IReadOnlyList<ChartSeries> _series = [];
}

public sealed record OutageRow(string Start, string End, string Duration, bool Ongoing);

/// <summary>Editable ping target in Settings and on the Internet page.</summary>
public sealed partial class EditableTarget : ObservableObject
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _host = "";
    [ObservableProperty] private bool _enabled = true;
}

/// <summary>Internet page: opt-in reachability monitor with user-defined ping targets.</summary>
public sealed partial class InternetViewModel : ObservableObject
{
    private static readonly Color[] Palette = [Color.Parse("#00E5FF"), Color.Parse("#FF2BD6"), Color.Parse("#3DFF8B"), Color.Parse("#FFC23D"), Color.Parse("#9B7BFF"), Color.Parse("#FF7A45")];

    private readonly IInternetMonitor? _monitor;
    private readonly ISettingsStore _settingsStore;
    private readonly Throttler _throttle;

    public InternetViewModel(IServiceProvider sp, ISettingsStore settingsStore)
    {
        _settingsStore = settingsStore;
        _monitor = sp.GetService<IInternetMonitor>();
        _throttle = new Throttler(TimeSpan.FromMilliseconds(400), Refresh);
        if (_monitor is not null) _monitor.Updated += _ => _throttle.Signal();
        // keep the page toggle in sync when the setting is changed on the Settings page
        settingsStore.Saved += () => Dispatcher.UIThread.Post(() => Enabled = S.InternetMonitorEnabled);
        LoadTargets();
        Refresh();
    }

    private AppSettings S => _settingsStore.Settings;

    public bool Available => _monitor is not null;
    public ObservableCollection<InternetTargetRow> Targets { get; } = [];
    public ObservableCollection<OutageRow> Outages { get; } = [];
    public ObservableCollection<EditableTarget> EditTargets { get; } = [];

    [ObservableProperty] private bool _enabled;
    [ObservableProperty] private string _stateText = "Disabled";
    [ObservableProperty] private string _stateDetail = "";
    [ObservableProperty] private IBrush _stateBrush = Ui.Grey;
    [ObservableProperty] private string _chipText = "Internet off";
    [ObservableProperty] private string _uptime = "—";
    [ObservableProperty] private string _bestLatency = "—";
    [ObservableProperty] private bool _hasOutages;
    [ObservableProperty] private string _newName = "";
    [ObservableProperty] private string _newHost = "";
    [ObservableProperty] private decimal? _interval;
    [ObservableProperty] private string? _message;

    public bool ShowEmpty => !Enabled;

    partial void OnEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowEmpty));
        if (S.InternetMonitorEnabled == value) return;
        S.InternetMonitorEnabled = value;
        Save();
    }

    private void LoadTargets()
    {
        _enabled = S.InternetMonitorEnabled;
        _interval = S.InternetIntervalSeconds;
        EditTargets.Clear();
        foreach (var t in S.InternetTargets) EditTargets.Add(new EditableTarget { Name = t.Name, Host = t.Host, Enabled = t.Enabled });
    }

    [RelayCommand]
    private void AddTarget()
    {
        var host = NewHost.Trim();
        if (host.Length == 0) { Message = "Enter an IP address or host name."; return; }
        if (EditTargets.Any(t => t.Host.Equals(host, StringComparison.OrdinalIgnoreCase))) { Message = $"{host} is already a target."; return; }
        EditTargets.Add(new EditableTarget { Name = string.IsNullOrWhiteSpace(NewName) ? host : NewName.Trim(), Host = host });
        NewName = NewHost = "";
        ApplyTargets();
    }

    [RelayCommand]
    private void RemoveTarget(EditableTarget? t)
    {
        if (t is null) return;
        EditTargets.Remove(t);
        ApplyTargets();
    }

    [RelayCommand]
    private void ApplyTargets()
    {
        S.InternetTargets = EditTargets.Where(t => !string.IsNullOrWhiteSpace(t.Host))
            .Select(t => new InternetTarget { Name = t.Name.Trim(), Host = t.Host.Trim(), Enabled = t.Enabled }).ToList();
        S.InternetIntervalSeconds = Math.Clamp((int)(Interval ?? 2), 1, 300);
        Save();
        Message = $"Saved {S.InternetTargets.Count(t => t.Enabled)} active target(s).";
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        var d = new AppSettings();
        EditTargets.Clear();
        foreach (var t in d.InternetTargets) EditTargets.Add(new EditableTarget { Name = t.Name, Host = t.Host });
        ApplyTargets();
    }

    private void Save()
    {
        try { _settingsStore.Save(); } // Saved event makes the monitor re-apply settings
        catch (Exception ex) { Log.Warning(ex, "Saving internet monitor settings failed"); Message = "Could not save settings: " + ex.Message; }
        _monitor?.ApplySettings();
        _throttle.Signal();
    }

    private void Refresh()
    {
        var st = _monitor?.Status ?? InternetStatus.Disabled;
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }

        (StateText, StateBrush) = st.State switch
        {
            InternetState.Online => ("Online", Ui.Green),
            InternetState.Degraded => ("Degraded", Ui.Amber),
            InternetState.Offline => ("Offline", Ui.Red),
            InternetState.Starting => ("Checking…", Ui.Cyan),
            _ => ("Disabled", Ui.Grey),
        };
        StateDetail = st.State == InternetState.Disabled
            ? "Internet monitoring is off. Turn it on to ping your targets continuously."
            : $"{StateText} since {st.Since:HH:mm:ss} · {st.Targets.Count(t => t.Up)}/{st.Targets.Count} targets answering";
        ChipText = st.State switch
        {
            InternetState.Disabled => "Internet off",
            InternetState.Offline => "Internet DOWN",
            InternetState.Starting => "Internet …",
            _ => st.BestMs is { } b ? $"Internet {Neon.FormatMs(b)}" : "Internet",
        };
        Uptime = st.State == InternetState.Disabled ? "—" : $"{st.UptimePercent:0.##} %";
        BestLatency = Neon.FormatMs(st.BestMs);

        // targets (update in place to keep chart controls stable)
        var hosts = st.Targets.Select(t => t.Host).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var gone in Targets.Where(r => !hosts.Contains(r.Host)).ToList()) Targets.Remove(gone);
        for (int i = 0; i < st.Targets.Count; i++)
        {
            var t = st.Targets[i];
            var row = Targets.FirstOrDefault(r => r.Host.Equals(t.Host, StringComparison.OrdinalIgnoreCase));
            if (row is null) { row = new InternetTargetRow { Host = t.Host }; Targets.Add(row); }
            var color = Palette[i % Palette.Length];
            row.Name = t.Name;
            row.Address = t.Address is null || t.Address.ToString() == t.Host ? t.Host : $"{t.Host} → {t.Address}";
            row.State = t.Up ? "Up" : t.Error is { } e ? $"Down · {e}" : "Down";
            row.StateBrush = t.Up ? (t.LastMs > S.InternetLatencyWarnMs ? Ui.Amber : Ui.Green) : Ui.Red;
            row.Last = Neon.FormatMs(t.LastMs);
            row.Avg = Neon.FormatMs(t.Summary.Avg);
            row.Jitter = Neon.FormatMs(t.Summary.Jitter);
            row.Loss = t.Summary.Count == 0 ? "—" : $"{t.Summary.LossPercent:0.#} %";
            row.Range = t.Summary.Min is { } mn && t.Summary.Max is { } mx ? $"{Neon.FormatMs(mn)} – {Neon.FormatMs(mx)}" : "";
            row.Series = [new ChartSeries(t.Name, color, t.Recent.Select(v => v ?? double.NaN).ToArray())];
        }

        Outages.Clear();
        foreach (var o in st.Outages.OrderByDescending(o => o.Start).Take(50))
            Outages.Add(new OutageRow(o.Start.ToString("yyyy-MM-dd HH:mm:ss"), o.End?.ToString("HH:mm:ss") ?? "ongoing",
                FormatDuration(o.Duration), o.Ongoing));
        HasOutages = Outages.Count > 0;
    }

    private static string FormatDuration(TimeSpan d) =>
        d.TotalHours >= 1 ? $"{(int)d.TotalHours}h {d.Minutes}m" : d.TotalMinutes >= 1 ? $"{d.Minutes}m {d.Seconds}s" : $"{Math.Max(1, (int)d.TotalSeconds)}s";
}
