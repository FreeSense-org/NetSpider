using Microsoft.Extensions.Logging;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Model;

namespace NetSpider.Export.Notifications;

/// <summary>Persists every raised alert and forwards those at or above <see cref="AppSettings.NotifyMinSeverity"/> to all <see cref="INotifier"/>s.</summary>
public sealed class NotificationService : IStartable, IDisposable
{
    private readonly IAlertService _alerts;
    private readonly IDeviceRepository _repo;
    private readonly IReadOnlyList<INotifier> _notifiers;
    private readonly ISettingsStore _settings;
    private readonly ILogger<NotificationService> _log;
    private readonly CancellationTokenSource _cts = new();
    private int _inFlight;
    private bool _started;

    public NotificationService(IAlertService alerts, IDeviceRepository repo, IEnumerable<INotifier> notifiers, ISettingsStore settings, ILogger<NotificationService> log)
    {
        _alerts = alerts;
        _repo = repo;
        _notifiers = notifiers.ToList();
        _settings = settings;
        _log = log;
    }

    /// <summary>Number of alerts currently being persisted/forwarded (for tests and shutdown).</summary>
    public int InFlight => Volatile.Read(ref _inFlight);

    /// <summary>When set and <see cref="INetworkState.IsDemo"/> is true, alerts are neither persisted nor forwarded.</summary>
    public INetworkState? Network { get; set; }

    public void Start()
    {
        if (_started) return;
        _started = true;
        _alerts.AlertRaised += OnAlert;
    }

    private void OnAlert(Alert alert)
    {
        if (Network?.IsDemo == true) return;
        Interlocked.Increment(ref _inFlight);
        _ = Task.Run(async () =>
        {
            try { await HandleAsync(alert, _cts.Token).ConfigureAwait(false); }
            finally { Interlocked.Decrement(ref _inFlight); }
        });
    }

    /// <summary>Persists and forwards one alert. Never throws.</summary>
    public async Task HandleAsync(Alert alert, CancellationToken ct = default)
    {
        try
        {
            try { await _repo.SaveAlertAsync(alert, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "Could not persist alert {Kind}", alert.Kind); }

            if (alert.Severity < _settings.Settings.NotifyMinSeverity) return;
            var tasks = _notifiers.Select(n => SafeNotify(n, alert, ct));
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "Alert notification failed"); }
    }

    private async Task SafeNotify(INotifier n, Alert alert, CancellationToken ct)
    {
        try { await n.NotifyAsync(alert, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogWarning(ex, "{Notifier} failed for alert {Kind}", n.GetType().Name, alert.Kind); }
    }

    public void Dispose()
    {
        _alerts.AlertRaised -= OnAlert;
        try { _cts.Cancel(); } catch { }
        _cts.Dispose();
    }
}
