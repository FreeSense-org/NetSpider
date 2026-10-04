using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Rendering;
using NetSpider.App.Services;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed record AgentTargetRow(string Target, string Value, IBrush Brush);

public sealed class AgentRow
{
    public required string Hostname { get; init; }
    public required string Ip { get; init; }
    public required string Medium { get; init; }
    public required string LastSeen { get; init; }
    public required bool Online { get; init; }
    public IBrush StateBrush => Online ? Ui.Green : Ui.Grey;
    public string StateText => Online ? "online" : "offline";
    public required IReadOnlyList<AgentTargetRow> Targets { get; init; }
    public bool HasTargets => Targets.Count > 0;
    public string? Version { get; init; }
}

/// <summary>Probe agents: hub settings (enable, port, shared key) and the list of remote NetSpider.Probe agents.</summary>
public sealed partial class AgentsViewModel : ObservableObject
{
    private readonly DiagnosticsFeed _feed;
    private readonly ISettingsStore _store;
    private readonly IFrameSource? _frames;
    private readonly Throttler _throttle;

    public AgentsViewModel(IServiceProvider sp, DiagnosticsFeed feed, ISettingsStore store)
    {
        _feed = feed;
        _store = store;
        _frames = sp.GetService<IFrameSource>();
        _throttle = new Throttler(TimeSpan.FromMilliseconds(800), Refresh);
        feed.AgentsChanged += _throttle.Signal;
        feed.SourceChanged += _throttle.Signal;
        store.Saved += () => Dispatcher.UIThread.Post(() => { OnPropertyChanged(nameof(HubEnabled)); OnPropertyChanged(nameof(Port)); Refresh(); });
        Refresh();
    }

    private AppSettings S => _store.Settings;

    public ObservableCollection<AgentRow> Remote { get; } = [];
    [ObservableProperty] private bool _showKey;
    [ObservableProperty] private string _hubStatus = "";
    [ObservableProperty] private IBrush _hubBrush = Ui.Grey;
    [ObservableProperty] private string _builtInText = "";
    [ObservableProperty] private bool _hasRemote;
    [ObservableProperty] private string? _message;

    public bool HubEnabled
    {
        get => S.ProbeAgentHubEnabled;
        set
        {
            if (S.ProbeAgentHubEnabled == value) return;
            S.ProbeAgentHubEnabled = value;
            if (value) EnsureKey();
            Save();
            OnPropertyChanged();
            OnPropertyChanged(nameof(Key));
            OnPropertyChanged(nameof(KeyDisplay));
            OnPropertyChanged(nameof(ExampleCommand));
        }
    }

    public decimal? Port
    {
        get => S.ProbeAgentPort;
        set
        {
            S.ProbeAgentPort = Math.Clamp((int)(value ?? 47810), 1024, 65535);
            OnPropertyChanged(nameof(ExampleCommand));
        }
    }

    public string Key => S.ProbeAgentKey ?? "";
    public string KeyDisplay => string.IsNullOrEmpty(S.ProbeAgentKey) ? "(generated when the hub is enabled)" : ShowKey ? S.ProbeAgentKey! : new string('●', 24);
    partial void OnShowKeyChanged(bool value) => OnPropertyChanged(nameof(KeyDisplay));

    public string ThisIp => _feed.IsDemo ? "192.168.1.50" : (_frames?.Adapter?.PrimaryV4?.Address ?? FirstLanIp())?.ToString() ?? "<this PC's IP>";

    public string ExampleCommand => $"netspider-probe --hub {ThisIp}" + (S.ProbeAgentPort != 47810 ? $" --port {S.ProbeAgentPort}" : "") + $" --key {(string.IsNullOrEmpty(S.ProbeAgentKey) ? "<key>" : S.ProbeAgentKey)}";

    private static IPAddress? FirstLanIp()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(u => u.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        }
        catch { return null; }
    }

    private void EnsureKey()
    {
        if (string.IsNullOrEmpty(S.ProbeAgentKey)) S.ProbeAgentKey = NewKey();
    }

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    [RelayCommand]
    private void RegenerateKey()
    {
        S.ProbeAgentKey = NewKey();
        Save();
        OnPropertyChanged(nameof(Key));
        OnPropertyChanged(nameof(KeyDisplay));
        OnPropertyChanged(nameof(ExampleCommand));
        Message = "New key generated — existing agents must be restarted with it.";
    }

    [RelayCommand]
    private async Task CopyKey()
    {
        EnsureKey();
        OnPropertyChanged(nameof(KeyDisplay));
        await Dialogs.CopyAsync(S.ProbeAgentKey);
        Message = "Key copied to the clipboard.";
    }

    [RelayCommand]
    private async Task CopyCommand()
    {
        await Dialogs.CopyAsync(ExampleCommand);
        Message = "Command line copied to the clipboard.";
    }

    private void Save()
    {
        try { _store.Save(); }
        catch (Exception ex) { Log.Warning(ex, "Saving probe agent settings failed"); Message = "Could not save: " + ex.Message; }
    }

    private void Refresh()
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(Refresh); return; }
        var hub = _feed.Agents;
        if (hub is null) { HubStatus = "Probe agent hub not available in this build"; HubBrush = Ui.Grey; }
        else if (hub.IsListening) { HubStatus = $"Listening on UDP {hub.Port}"; HubBrush = Ui.Green; }
        else { HubStatus = S.ProbeAgentHubEnabled ? "Enabled — starting…" : "Hub disabled"; HubBrush = S.ProbeAgentHubEnabled ? Ui.Amber : Ui.Grey; }

        var all = hub?.Agents ?? [];
        int builtIn = all.Count(a => a.AgentId.StartsWith("local:", StringComparison.OrdinalIgnoreCase));
        BuiltInText = builtIn == 0 ? "" : $"+ {builtIn} built-in agent(s) for this PC's own adapters — see Path Doctor › Dual-interface test.";
        Remote.Clear();
        foreach (var a in all.Where(a => !a.AgentId.StartsWith("local:", StringComparison.OrdinalIgnoreCase)).OrderByDescending(a => a.Online).ThenBy(a => a.Hostname))
        {
            var targets = (a.Latest?.Results ?? []).Select(r =>
            {
                bool fail = r.RttMs is null && r.AvgMs is null || r.LossPercent >= 50;
                var brush = fail ? Ui.Red : r.LossPercent > 2 ? Ui.Amber : Ui.Green;
                string v = fail ? (r.Error ?? "no reply") : Neon.FormatMs(r.AvgMs ?? r.RttMs) + (r.LossPercent > 0 ? $" · {Diag.Pct(r.LossPercent)}" : "");
                return new AgentTargetRow(r.Target, v, brush);
            }).ToList();
            Remote.Add(new AgentRow
            {
                Hostname = a.Hostname, Ip = a.Ip ?? "—", Medium = a.Medium, Online = a.Online, Targets = targets,
                LastSeen = a.Online ? "now" : InspectorViewModel.Ago(a.LastSeen), Version = a.Latest?.Version,
            });
        }
        HasRemote = Remote.Count > 0;
        OnPropertyChanged(nameof(ExampleCommand));
    }
}
