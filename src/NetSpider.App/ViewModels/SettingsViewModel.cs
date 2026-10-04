using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.ViewModels;

public sealed partial class EditableString(string value) : ObservableObject
{
    [ObservableProperty] private string _value = value;
}

public sealed partial class WebhookItem(WebhookConfig cfg) : ObservableObject
{
    [ObservableProperty] private string _name = cfg.Name;
    [ObservableProperty] private string _kind = cfg.Kind;
    [ObservableProperty] private string _url = cfg.Url;
    [ObservableProperty] private bool _enabled = cfg.Enabled;
    public WebhookConfig ToConfig() => new() { Name = Name, Kind = Kind, Url = Url, Enabled = Enabled };
}

/// <summary>Edits <see cref="AppSettings"/> directly (scalar fields bind straight to it); lists are staged and written on Save.</summary>
public sealed partial class SettingsViewModel : ObservableObject, IDisposable
{
    private readonly ISettingsStore _store;
    private readonly ILogoProvider? _logos;
    private CancellationTokenSource? _prefetchCts;

    public SettingsViewModel(IServiceProvider sp, ISettingsStore store)
    {
        _store = store;
        _logos = sp.GetService<ILogoProvider>();
        Agents = sp.GetRequiredService<AgentsViewModel>();
        Load();
    }

    public AppSettings Settings => _store.Settings;
    public IReadOnlyList<PortScanProfile> PortScanProfiles { get; } = Enum.GetValues<PortScanProfile>();
    public IReadOnlyList<AlertSeverity> Severities { get; } = Enum.GetValues<AlertSeverity>();
    public IReadOnlyList<string> WebhookKinds { get; } = ["Discord", "Slack", "Json"];
    public IReadOnlyList<string> AuthProtocols { get; } = ["MD5", "SHA", "SHA256", "SHA384", "SHA512"];
    public IReadOnlyList<string> PrivProtocols { get; } = ["DES", "AES", "AES192", "AES256"];

    public ObservableCollection<EditableString> Communities { get; } = [];
    public ObservableCollection<WebhookItem> Webhooks { get; } = [];
    [ObservableProperty] private string _newCommunity = "";
    [ObservableProperty] private string? _status;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(PrefetchLogosCommand))] private bool _isPrefetching;
    [ObservableProperty] private double _prefetchProgress;
    [ObservableProperty] private string _prefetchText = "";
    public bool LogosAvailable => _logos is not null;
    public string PrefetchTooltip => _logos is null ? "Logo service not available in this build" : "Download and cache the logos of every vendor in vendors.json";
    public string SettingsPath => Path.Combine(Core.Services.AppPaths.Root, "settings.json");

    // ---- typed proxies for numeric fields (NumericUpDown binds decimal?) ----
    public decimal? MinSweepPrefix { get => Settings.MinSweepPrefix; set => Settings.MinSweepPrefix = (int)(value ?? 20); }
    public decimal? MaxInjectPps { get => Settings.MaxInjectPps; set => Settings.MaxInjectPps = (int)(value ?? 400); }
    public decimal? SnmpTimeoutMs { get => Settings.SnmpTimeoutMs; set => Settings.SnmpTimeoutMs = (int)(value ?? 1500); }
    public decimal? SnmpPollMinutes { get => Settings.SnmpPollMinutes; set => Settings.SnmpPollMinutes = Math.Max(1, (int)(value ?? 5)); }
    public decimal? InternetOutageRounds { get => Settings.InternetOutageRounds; set => Settings.InternetOutageRounds = Math.Max(1, (int)(value ?? 3)); }
    public decimal? InternetLatencyWarnMs { get => (decimal)Settings.InternetLatencyWarnMs; set => Settings.InternetLatencyWarnMs = (double)(value ?? 100); }
    public decimal? LatencyIntervalSeconds { get => Settings.LatencyIntervalSeconds; set => Settings.LatencyIntervalSeconds = (int)(value ?? 3); }
    public decimal? LatencyGoodMs { get => (decimal)Settings.LatencyGoodMs; set => Settings.LatencyGoodMs = (double)(value ?? 2); }
    public decimal? LatencyWarnMs { get => (decimal)Settings.LatencyWarnMs; set => Settings.LatencyWarnMs = (double)(value ?? 20); }
    public decimal? LatencyBadMs { get => (decimal)Settings.LatencyBadMs; set => Settings.LatencyBadMs = (double)(value ?? 50); }
    public decimal? StormBroadcastPercent { get => (decimal)(Settings.StormBroadcastRatio * 100); set => Settings.StormBroadcastRatio = (double)(value ?? 15) / 100; }
    public decimal? StormBroadcastPps { get => (decimal)Settings.StormBroadcastPps; set => Settings.StormBroadcastPps = (double)(value ?? 500); }
    public decimal? StormMulticastPps { get => (decimal)Settings.StormMulticastPps; set => Settings.StormMulticastPps = (double)(value ?? 2000); }
    public decimal? StormPerMacPps { get => (decimal)Settings.StormPerMacPps; set => Settings.StormPerMacPps = (double)(value ?? 300); }
    public decimal? MacFlapThreshold { get => Settings.MacFlapThreshold; set => Settings.MacFlapThreshold = (int)(value ?? 3); }
    public decimal? TopTalkerPps { get => (decimal)Settings.TopTalkerPps; set => Settings.TopTalkerPps = (double)(value ?? 1000); }
    public decimal? PathIntervalSeconds { get => Settings.PathIntervalSeconds; set => Settings.PathIntervalSeconds = Math.Clamp((int)(value ?? 2), 1, 60); }
    public decimal? HopDownRounds { get => Settings.HopDownRounds; set => Settings.HopDownRounds = Math.Clamp((int)(value ?? 3), 1, 30); }
    public decimal? PortCounterPollSeconds { get => Settings.PortCounterPollSeconds; set => Settings.PortCounterPollSeconds = Math.Clamp((int)(value ?? 60), 10, 3600); }
    public decimal? PortErrorsPerMinWarn { get => (decimal)Settings.PortErrorsPerMinWarn; set => Settings.PortErrorsPerMinWarn = Math.Max(0.1, (double)(value ?? 10)); }
    public decimal? WifiWeakRssiDbm { get => Settings.WifiWeakRssiDbm; set => Settings.WifiWeakRssiDbm = Math.Clamp((int)(value ?? -75), -95, -40); }

    /// <summary>Probe agent hub settings + agent list (also summarised on the Path page).</summary>
    public AgentsViewModel Agents { get; }
    public decimal? SyslogPort { get => Settings.SyslogPort; set => Settings.SyslogPort = (int)(value ?? 514); }

    private void Load()
    {
        Communities.Clear();
        foreach (var c in Settings.SnmpCommunities) Communities.Add(new EditableString(c));
        Webhooks.Clear();
        foreach (var w in Settings.Webhooks) Webhooks.Add(new WebhookItem(w));
    }

    [RelayCommand]
    private void AddCommunity()
    {
        var c = NewCommunity.Trim();
        if (c.Length == 0 || Communities.Any(x => x.Value == c)) return;
        Communities.Add(new EditableString(c));
        NewCommunity = "";
    }

    [RelayCommand] private void RemoveCommunity(EditableString c) => Communities.Remove(c);
    [RelayCommand] private void AddWebhook() => Webhooks.Add(new WebhookItem(new WebhookConfig { Name = "New webhook", Kind = "Discord" }));
    [RelayCommand] private void RemoveWebhook(WebhookItem w) => Webhooks.Remove(w);

    [RelayCommand]
    private void Save()
    {
        try
        {
            Settings.SnmpCommunities = Communities.Select(c => c.Value.Trim()).Where(c => c.Length > 0).Distinct().ToList();
            Settings.Webhooks = Webhooks.Select(w => w.ToConfig()).Where(w => !string.IsNullOrWhiteSpace(w.Url)).ToList();
            if (Settings.LatencyWarnMs <= Settings.LatencyGoodMs) Settings.LatencyWarnMs = Settings.LatencyGoodMs * 5;
            if (Settings.LatencyBadMs <= Settings.LatencyWarnMs) Settings.LatencyBadMs = Settings.LatencyWarnMs * 2;
            _store.Save();
            Status = $"Saved {DateTime.Now:HH:mm:ss}";
            OnPropertyChanged(string.Empty);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Saving settings failed");
            Status = "Save failed: " + ex.Message;
        }
    }

    [RelayCommand] private void Revert() { Load(); OnPropertyChanged(string.Empty); Status = "Reverted unsaved list edits"; }

    private bool CanPrefetch() => _logos is not null && !IsPrefetching;

    [RelayCommand(CanExecute = nameof(CanPrefetch))]
    private async Task PrefetchLogos()
    {
        if (_logos is null) return;
        IsPrefetching = true;
        _prefetchCts = new CancellationTokenSource();
        var progress = new Progress<ScanProgress>(p => { PrefetchProgress = p.Fraction * 100; PrefetchText = p.Detail ?? p.Stage; });
        try
        {
            await Task.Run(() => _logos.PrefetchAllAsync(progress, _prefetchCts.Token));
            PrefetchText = "Logo cache is warm";
            PrefetchProgress = 100;
        }
        catch (OperationCanceledException) { PrefetchText = "Cancelled"; }
        catch (Exception ex)
        {
            Log.Warning(ex, "Logo prefetch failed");
            PrefetchText = "Failed: " + ex.Message;
        }
        finally { IsPrefetching = false; }
    }

    [RelayCommand] private void CancelPrefetch() => _prefetchCts?.Cancel();
    [RelayCommand] private void OpenDataFolder() => Services.Launcher.Open(Core.Services.AppPaths.Root);

    public void Dispose() => _prefetchCts?.Cancel();
}
