using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using NetSpider.App.Services;
using NetSpider.App.Views;
using NetSpider.Capture;
using NetSpider.Core.Abstractions;
using NetSpider.Core.Services;
using Serilog;

namespace NetSpider.App.ViewModels;

// Settings → "Application" card: startup / tray / notifications / logging / captures, plus export, import, reset and clear history.
public sealed partial class SettingsViewModel
{
    private IServiceProvider? _services;

    /// <summary>Set by the shell: opens the welcome wizard.</summary>
    public Action? ShowWelcomeAction { get; set; }

    public IReadOnlyList<string> LogLevels => AppLogging.Levels;
    public bool IsAdmin { get; } = NpcapEnvironment.IsAdministrator();

    [ObservableProperty] private bool _isBusyApp;
    [ObservableProperty] private string? _appStatus;
    [ObservableProperty] private bool _appStatusIsError;

    internal void AttachServices(IServiceProvider sp)
    {
        _services = sp;
        _ = RefreshStartWithWindowsAsync();
    }

    /// <summary>Re-reads the application settings (after the welcome wizard, import or reset).</summary>
    public void RefreshApplication()
    {
        _startWithWindowsUi = null;
        OnPropertyChanged(nameof(StartWithWindows));
        OnPropertyChanged(nameof(LogLevel));
        OnPropertyChanged(nameof(CaptureFolderMaxMb));
        OnPropertyChanged(nameof(Settings));
        Load();
        OnPropertyChanged(string.Empty);
    }

    // ---- start with Windows (Task Scheduler) ----

    public string StartWithWindowsHint => IsAdmin
        ? "Registers the \"FreeSense NetSpider\" sign-in task (highest privileges, starts minimized to the tray)."
        : "Registering the sign-in task needs NetSpider to run as administrator.";

    // UI-side value: it follows the checkbox immediately and snaps back when registering the task fails
    // (re-raising PropertyChanged with an unchanged source value would not uncheck the box).
    private bool? _startWithWindowsUi;

    public bool StartWithWindows
    {
        get => _startWithWindowsUi ?? Settings.StartWithWindows;
        set
        {
            if (value == (_startWithWindowsUi ?? Settings.StartWithWindows) || IsBusyApp) return;
            _startWithWindowsUi = value;
            OnPropertyChanged();
            if (value != Settings.StartWithWindows) _ = SetStartWithWindowsAsync(value);
        }
    }

    private async Task SetStartWithWindowsAsync(bool on)
    {
        IsBusyApp = true;
        try
        {
            var r = on ? await StartupTask.EnableAsync() : await StartupTask.DisableAsync();
            if (r.Success)
            {
                Settings.StartWithWindows = on;
                SaveQuietly();
            }
            SetAppStatus(r.Message, !r.Success);
        }
        finally
        {
            IsBusyApp = false;
            _startWithWindowsUi = Settings.StartWithWindows;
            OnPropertyChanged(nameof(StartWithWindows));
        }
    }

    private async Task RefreshStartWithWindowsAsync()
    {
        try
        {
            bool exists = await StartupTask.ExistsAsync();
            if (exists == Settings.StartWithWindows) return;
            Settings.StartWithWindows = exists;
            _startWithWindowsUi = exists;
            SaveQuietly();
            OnPropertyChanged(nameof(StartWithWindows));
        }
        catch (Exception ex) { Log.Debug(ex, "Querying the startup task failed"); }
    }

    // ---- log level / captures ----

    public string LogLevel
    {
        get => AppLogging.Parse(Settings.LogLevel) == Serilog.Events.LogEventLevel.Debug ? "Debug" : "Information";
        set
        {
            if (value is null) return;
            Settings.LogLevel = value;
            AppLogging.Apply(value);
            SaveQuietly();
            OnPropertyChanged();
        }
    }

    public decimal? CaptureFolderMaxMb
    {
        get => Settings.CaptureFolderMaxMb;
        set => Settings.CaptureFolderMaxMb = Math.Clamp((int)(value ?? 2048), 100, 1024 * 1024);
    }

    public string CapturesPath => AppPaths.Captures;

    [RelayCommand] private void OpenCapturesFolder() => Launcher.Open(AppPaths.Captures);
    [RelayCommand] private void OpenLogsFolder() => Launcher.Open(AppPaths.Logs);
    [RelayCommand] private void ShowWelcome() => ShowWelcomeAction?.Invoke();

    // ---- export / import / reset / clear ----

    [RelayCommand]
    private async Task ExportSettings()
    {
        try
        {
            var path = await Dialogs.SaveFileAsync("Export NetSpider settings", "json", $"netspider-settings-{DateTime.Now:yyyyMMdd}.json");
            if (path is null) return;
            await File.WriteAllTextAsync(path, SettingsPorter.Export(Settings));
            SetAppStatus($"Settings exported to {path}", false);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Exporting settings failed");
            SetAppStatus("Export failed: " + ex.Message, true);
        }
    }

    [RelayCommand]
    private async Task ImportSettings()
    {
        try
        {
            if (Dialogs.Owner?.StorageProvider is not { CanOpen: true } sp) return;
            var files = await sp.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Import NetSpider settings",
                AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("NetSpider settings (JSON)") { Patterns = ["*.json"] }],
            });
            var path = files.FirstOrDefault()?.TryGetLocalPath();
            if (path is null) return;
            var info = new FileInfo(path);
            if (info.Length > 4 * 1024 * 1024) { SetAppStatus("That file is too large to be a settings file.", true); return; }

            var result = SettingsPorter.Parse(await File.ReadAllTextAsync(path));
            if (!result.Success || result.Settings is null) { SetAppStatus(result.Message, true); return; }

            var changed = SettingsPorter.CopyInto(result.Settings, Settings);
            _store.Save();
            AppLogging.Apply(Settings.LogLevel);
            RefreshApplication();
            var restart = SettingsPorter.NeedsRestart(changed);
            var msg = changed.Count == 0 ? "Imported — no settings changed." : $"Imported {changed.Count} changed setting{(changed.Count == 1 ? "" : "s")}.";
            if (restart.Count > 0) msg += " Restart NetSpider to apply: " + string.Join(", ", restart) + ".";
            if (result.Warnings.Count > 0) msg += $" {result.Warnings.Count} value(s) were out of range and adjusted.";
            SetAppStatus(msg, false);
            Log.Information("Imported settings from {Path}: {Changed}; warnings: {Warnings}", path, string.Join(",", changed), string.Join("; ", result.Warnings));
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Importing settings failed");
            SetAppStatus("Import failed: " + ex.Message, true);
        }
    }

    [RelayCommand]
    private async Task ResetSettings()
    {
        if (!await ConfirmDialog.ShowAsync("Reset all settings?",
                "Every NetSpider setting (scanning, SNMP, thresholds, notifications, webhooks, application options) goes back to its default.",
                "This can't be undone — export your settings first if you might need them again. Device history and incidents are kept.",
                "Reset settings")) return;
        try
        {
            bool hadTask = Settings.StartWithWindows;
            var changed = SettingsPorter.CopyInto(new Core.Model.AppSettings(), Settings);
            _store.Save();
            AppLogging.Apply(Settings.LogLevel);
            if (hadTask)
            {
                var r = await StartupTask.DisableAsync();
                if (r.Success) { Settings.StartWithWindows = false; SaveQuietly(); }
            }
            RefreshApplication();
            var restart = SettingsPorter.NeedsRestart(changed);
            SetAppStatus("All settings were reset to their defaults." + (restart.Count > 0 ? " Restart NetSpider to apply: " + string.Join(", ", restart) + "." : ""), false);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Resetting settings failed");
            SetAppStatus("Reset failed: " + ex.Message, true);
        }
    }

    [RelayCommand]
    private async Task ClearHistory()
    {
        if (!await ConfirmDialog.ShowAsync("Clear device history and incidents?",
                "Deletes every remembered device (first/last seen, your labels), the stored alert history and all incidents from the local database.",
                "This can't be undone. Devices on the network are rediscovered on the next scan, but they will all be reported as new.",
                "Clear history")) return;
        IsBusyApp = true;
        try
        {
            var sp = _services ?? AppHost.Services;
            if (sp?.GetService<IDeviceRepository>() is { } devices) await devices.ClearAsync();
            if (sp?.GetService<IIncidentRepository>() is { } incidents) await incidents.ClearAsync();
            try { sp?.GetService<IIncidentService>()?.Clear(); } catch (Exception ex) { Log.Debug(ex, "Clearing live incidents failed"); }
            try { sp?.GetService<IAlertService>()?.Clear(); sp?.GetService<AlertsViewModel>()?.Reload(); } catch (Exception ex) { Log.Debug(ex, "Clearing live alerts failed"); }
            SetAppStatus("Device history, alerts and incidents were cleared.", false);
            Log.Information("Device history and incidents cleared by the user");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Clearing history failed");
            SetAppStatus("Clearing history failed: " + ex.Message, true);
        }
        finally { IsBusyApp = false; }
    }

    private void SetAppStatus(string message, bool error)
    {
        AppStatus = message;
        AppStatusIsError = error;
    }

    private void SaveQuietly()
    {
        try { _store.Save(); } catch (Exception ex) { Log.Warning(ex, "Saving settings failed"); }
    }
}
