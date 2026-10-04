using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using NetSpider.Core.Model;
using Serilog;

namespace NetSpider.App.Services;

/// <summary>
/// Coalesces high-rate signals from any thread into at most one UI-thread callback per interval
/// (e.g. DeviceChanged storms → a 2 Hz grid refresh). Must be constructed on the UI thread.
/// </summary>
public sealed class Throttler : IDisposable
{
    private readonly Action _action;
    private readonly DispatcherTimer _timer;
    private volatile bool _pending;

    public Throttler(TimeSpan interval, Action action)
    {
        _action = action;
        _timer = new DispatcherTimer(interval, DispatcherPriority.Background, (_, _) => Flush());
        _timer.Start();
    }

    public void Signal() => _pending = true;

    public void Flush()
    {
        if (!_pending) return;
        _pending = false;
        try { _action(); }
        catch (Exception ex) { Log.Error(ex, "UI refresh failed"); }
    }

    public void Dispose() => _timer.Stop();
}

/// <summary>The device selected anywhere in the UI (graph, grid, alerts); drives the inspector.</summary>
public sealed partial class SelectionService : ObservableObject
{
    [ObservableProperty] private Device? _selected;
}

/// <summary>Dialogs and clipboard; the main window registers itself as the owner.</summary>
public static class Dialogs
{
    public static Window? Owner { get; set; }

    public static async Task<string?> SaveFileAsync(string title, string extension, string suggestedName)
    {
        if (Owner?.StorageProvider is not { CanSave: true } sp) return null;
        var ext = extension.TrimStart('.');
        var file = await sp.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = ext,
            ShowOverwritePrompt = true,
            FileTypeChoices = [new FilePickerFileType($"{ext.ToUpperInvariant()} file") { Patterns = [$"*.{ext}"] }],
        });
        return file?.TryGetLocalPath();
    }

    public static async Task CopyAsync(string? text)
    {
        if (string.IsNullOrEmpty(text) || Owner?.Clipboard is not { } cb) return;
        await cb.SetTextAsync(text);
    }

    public static void ShowWindow(Window w)
    {
        if (Owner is not null) w.Show(Owner);
        else w.Show();
    }
}

/// <summary>Starts external tools (browser, Windows Terminal, mstsc) without throwing into the UI.</summary>
public static class Launcher
{
    public static bool Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Opening {Target} failed", target);
            return false;
        }
    }

    public static bool Run(string exe, string args)
    {
        try
        {
            Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true });
            return true;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Starting {Exe} failed", exe);
            return false;
        }
    }

    /// <summary>SSH via Windows Terminal, falling back to a plain console.</summary>
    public static bool Ssh(string ip) => Run("wt.exe", $"ssh {ip}") || Run("cmd.exe", $"/k ssh {ip}");

    public static bool Rdp(string ip) => Run("mstsc.exe", $"/v:{ip}");
}
