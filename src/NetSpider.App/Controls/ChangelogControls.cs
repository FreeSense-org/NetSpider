using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Shapes;
using Path = Avalonia.Controls.Shapes.Path;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using NetSpider.Core;
using NetSpider.Core.Changelog;

namespace NetSpider.App.Controls;

/// <summary>Category colours and icons for changelog badges, taken from Theme/NeonTheme.axaml.</summary>
public static class ChangelogPalette
{
    public static Color ColorOf(ChangelogCategory c) => c switch
    {
        ChangelogCategory.Breaking => Res("RedColor", "#FF3D5A"),
        ChangelogCategory.New => Res("CyanColor", "#00E5FF"),
        ChangelogCategory.Improved => Res("GreenColor", "#3DFF8B"),
        ChangelogCategory.Fixed => Res("AmberColor", "#FFC23D"),
        ChangelogCategory.Security => Res("MagentaColor", "#FF2BD6"),
        _ => Res("TextDimColor", "#8A9BB8"), // Removed, Deprecated
    };

    /// <summary>Theme geometry key per <see cref="ChangelogCategories.IconKey"/>.</summary>
    public static string GeometryKey(ChangelogCategory c) => c.IconKey() switch
    {
        "warning" => "IconWarn",
        "sparkles" => "IconSparkles",
        "arrow-up" => "IconArrowUp",
        "bug" => "IconBug",
        "shield" => "IconShield",
        "minus" => "IconMinusCircle",
        "clock" => "IconHourglass",
        _ => "IconInfo",
    };

    public static Geometry? GeometryOf(ChangelogCategory c) =>
        Application.Current?.TryGetResource(GeometryKey(c), null, out var g) == true ? g as Geometry : null;

    public static IBrush Brush(ChangelogCategory c, byte alpha = 0xFF)
    {
        var col = ColorOf(c);
        return new SolidColorBrush(Color.FromArgb(alpha, col.R, col.G, col.B));
    }

    internal static IBrush ThemeBrush(string key, IBrush fallback) =>
        Application.Current?.TryGetResource(key, null, out var v) == true && v is IBrush b ? b : fallback;

    private static Color Res(string key, string fallback) =>
        Application.Current?.TryGetResource(key, null, out var v) == true && v is Color c ? c : Color.Parse(fallback);
}

/// <summary>A small coloured pill with the category icon and name ("✨ NEW"), shared by the update dialog, What's new and About.</summary>
public sealed class ChangelogBadge : Border
{
    public static readonly StyledProperty<ChangelogCategory> CategoryProperty =
        AvaloniaProperty.Register<ChangelogBadge, ChangelogCategory>(nameof(Category));

    public ChangelogCategory Category { get => GetValue(CategoryProperty); set => SetValue(CategoryProperty, value); }

    public ChangelogBadge()
    {
        CornerRadius = new CornerRadius(7);
        Padding = new Thickness(7, 3, 9, 3);
        BorderThickness = new Thickness(1);
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Center;
        Build();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == CategoryProperty) Build();
    }

    private void Build()
    {
        var c = Category;
        Background = ChangelogPalette.Brush(c, 0x1F);
        BorderBrush = ChangelogPalette.Brush(c, 0x70);
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        if (ChangelogPalette.GeometryOf(c) is { } g)
            row.Children.Add(new Path
            {
                Data = g, Stroke = ChangelogPalette.Brush(c), StrokeThickness = 1.9, Width = 11, Height = 11, Stretch = Stretch.Uniform,
                StrokeLineCap = PenLineCap.Round, StrokeJoin = PenLineJoin.Round, VerticalAlignment = VerticalAlignment.Center,
            });
        row.Children.Add(new TextBlock
        {
            Text = c.DisplayName().ToUpperInvariant(), FontSize = 10.5, FontWeight = FontWeight.Bold, LetterSpacing = 0.9,
            Foreground = ChangelogPalette.Brush(c), VerticalAlignment = VerticalAlignment.Center,
        });
        Child = row;
        ToolTip.SetTip(this, c switch
        {
            ChangelogCategory.Breaking => "Needs action from you after updating",
            ChangelogCategory.New => "New features",
            ChangelogCategory.Improved => "Existing features work better",
            ChangelogCategory.Fixed => "Bug fixes",
            ChangelogCategory.Security => "Security fixes",
            ChangelogCategory.Removed => "Removed features",
            ChangelogCategory.Deprecated => "Still works, but will be removed later",
            _ => null,
        });
    }
}

/// <summary>
/// Renders changelog releases: category badges with their entries. With <see cref="ShowReleaseHeaders"/> each release is
/// a card with version, date and a summary (collapsible with <see cref="Collapsible"/>); the release matching
/// <see cref="CurrentVersion"/> is highlighted. Without headers only the entries are shown (single-release notes).
/// </summary>
public sealed class ChangelogView : StackPanel
{
    public static readonly StyledProperty<IReadOnlyList<ChangelogRelease>?> ReleasesProperty =
        AvaloniaProperty.Register<ChangelogView, IReadOnlyList<ChangelogRelease>?>(nameof(Releases));
    public static readonly StyledProperty<bool> ShowReleaseHeadersProperty =
        AvaloniaProperty.Register<ChangelogView, bool>(nameof(ShowReleaseHeaders), true);
    public static readonly StyledProperty<bool> CollapsibleProperty =
        AvaloniaProperty.Register<ChangelogView, bool>(nameof(Collapsible));
    public static readonly StyledProperty<string?> CurrentVersionProperty =
        AvaloniaProperty.Register<ChangelogView, string?>(nameof(CurrentVersion));

    public IReadOnlyList<ChangelogRelease>? Releases { get => GetValue(ReleasesProperty); set => SetValue(ReleasesProperty, value); }
    public bool ShowReleaseHeaders { get => GetValue(ShowReleaseHeadersProperty); set => SetValue(ShowReleaseHeadersProperty, value); }
    /// <summary>Release cards can be expanded/collapsed; only the current (or newest) release starts expanded.</summary>
    public bool Collapsible { get => GetValue(CollapsibleProperty); set => SetValue(CollapsibleProperty, value); }
    /// <summary>The running version (AppInfo.Version): its release (or Unreleased for a pre-release) is highlighted.</summary>
    public string? CurrentVersion { get => GetValue(CurrentVersionProperty); set => SetValue(CurrentVersionProperty, value); }

    public ChangelogView() => Spacing = 10;

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ReleasesProperty || change.Property == ShowReleaseHeadersProperty ||
            change.Property == CollapsibleProperty || change.Property == CurrentVersionProperty) Render();
    }

    /// <summary>Which release is "this version": Unreleased for a pre-release build (if it has entries), else the exact version.</summary>
    public static ChangelogRelease? CurrentRelease(IReadOnlyList<ChangelogRelease> releases, string? currentVersion)
    {
        if (!SemVer.TryParse(currentVersion, out var cur)) return null;
        if (cur.IsPrerelease) return releases.FirstOrDefault(r => r.IsUnreleased && !r.IsEmpty);
        return releases.FirstOrDefault(r => r.Version is { } v && v == cur);
    }

    private void Render()
    {
        Children.Clear();
        var releases = Releases?.Where(r => !r.IsEmpty).ToList() ?? [];
        if (releases.Count == 0)
        {
            Children.Add(new TextBlock
            {
                Text = "No changes are listed for this version.", FontStyle = FontStyle.Italic,
                Foreground = ChangelogPalette.ThemeBrush("TextDimBrush", Brushes.Gray),
            });
            return;
        }
        if (!ShowReleaseHeaders)
        {
            foreach (var r in releases) Children.Add(Body(r));
            return;
        }
        var current = CurrentRelease(releases, CurrentVersion);
        var expanded = current ?? releases[0];
        foreach (var r in releases) Children.Add(Card(r, r == current, !Collapsible || r == expanded));
    }

    private Control Card(ChangelogRelease release, bool isCurrent, bool expanded)
    {
        var cyan = ChangelogPalette.ThemeBrush("CyanBrush", Brushes.Cyan);
        var dim = ChangelogPalette.ThemeBrush("TextDimBrush", Brushes.Gray);

        // ---- header: chevron, version, date, "installed" pill, per-category counts ----
        var header = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,Auto,Auto,Auto,*,Auto") };
        var chevron = new Path
        {
            Data = Application.Current?.TryGetResource("IconChevronRight", null, out var g) == true ? g as Geometry : null,
            Stroke = dim, StrokeThickness = 2, Width = 10, Height = 10, Stretch = Stretch.Uniform, Margin = new Thickness(0, 0, 10, 0),
            VerticalAlignment = VerticalAlignment.Center, IsVisible = Collapsible,
            RenderTransform = new RotateTransform(expanded ? 90 : 0),
        };
        header.Children.Add(chevron);
        var title = new TextBlock
        {
            Text = release.IsUnreleased ? "Unreleased" : release.Title, FontSize = 16, FontWeight = FontWeight.SemiBold,
            VerticalAlignment = VerticalAlignment.Center, Foreground = isCurrent ? cyan : ChangelogPalette.ThemeBrush("TextBrush", Brushes.White),
        };
        Grid.SetColumn(title, 1);
        header.Children.Add(title);
        var date = new TextBlock
        {
            Text = release.Date is { } d ? d.ToString("MMMM d, yyyy", CultureInfo.InvariantCulture) : "in pre-releases",
            FontSize = 12, Foreground = dim, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 1, 0, 0),
        };
        Grid.SetColumn(date, 2);
        header.Children.Add(date);
        if (isCurrent)
        {
            var pill = new Border
            {
                CornerRadius = new CornerRadius(8), Padding = new Thickness(8, 1), Margin = new Thickness(10, 0, 0, 0),
                Background = new SolidColorBrush(Color.Parse("#2600E5FF")), BorderBrush = new SolidColorBrush(Color.Parse("#8800E5FF")),
                BorderThickness = new Thickness(1), VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock { Text = release.IsUnreleased ? "THIS PRE-RELEASE" : "INSTALLED", FontSize = 10, FontWeight = FontWeight.Bold, LetterSpacing = 0.8, Foreground = cyan },
            };
            Grid.SetColumn(pill, 3);
            header.Children.Add(pill);
        }
        var counts = Counts(release);
        Grid.SetColumn(counts, 5);
        header.Children.Add(counts);

        var body = Body(release);
        body.Margin = new Thickness(Collapsible ? 20 : 0, 12, 0, 2);
        body.IsVisible = expanded;

        Control top = header;
        if (Collapsible)
        {
            var toggle = new Button
            {
                Content = header, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0),
                HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Cursor = new Cursor(StandardCursorType.Hand), Classes = { "changelog-toggle" },
            };
            toggle.Click += (_, _) =>
            {
                body.IsVisible = !body.IsVisible;
                chevron.RenderTransform = new RotateTransform(body.IsVisible ? 90 : 0);
            };
            top = toggle;
        }

        return new Border
        {
            Background = new SolidColorBrush(Color.Parse(isCurrent ? "#0F1B30" : "#0A1020")),
            BorderBrush = isCurrent ? new SolidColorBrush(Color.Parse("#6600E5FF")) : ChangelogPalette.ThemeBrush("BorderBrushNeon", Brushes.Gray),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 12, 16, 12),
            BoxShadow = isCurrent ? BoxShadows.Parse("0 0 18 0 #2A00E5FF") : default,
            Child = new StackPanel { Children = { top, body } },
        };
    }

    private static ChangelogCounts Counts(ChangelogRelease release) =>
        new() { Releases = [release], FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };

    /// <summary>The category groups of one release: a badge, then its entries.</summary>
    public static StackPanel Body(ChangelogRelease release)
    {
        var panel = new StackPanel { Spacing = 14 };
        foreach (var s in release.Sections.Where(s => s.Entries.Count > 0).OrderBy(s => s.Category.SortOrder()))
        {
            var group = new StackPanel { Spacing = 6 };
            group.Children.Add(new ChangelogBadge { Category = s.Category, Margin = new Thickness(0, 0, 0, 2) });
            foreach (var e in s.Entries) group.Children.Add(Entry(s.Category, e));
            panel.Children.Add(group);
        }
        return panel;
    }

    private static Control Entry(ChangelogCategory category, ChangelogEntry entry)
    {
        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("16,*"), Margin = new Thickness(4, 0, 0, 0) };
        row.Children.Add(new Ellipse
        {
            Width = 5, Height = 5, Fill = ChangelogPalette.Brush(category, 0xCC),
            VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(1, 8, 0, 0),
        });
        var md = entry.PullRequest is { } pr ? $"{entry.Text} [#{pr}]({AppInfo.Repository}/pull/{pr})" : entry.Text;
        var text = MarkdownView.Paragraph(md, 13);
        Grid.SetColumn(text, 1);
        row.Children.Add(text);
        return row;
    }
}

/// <summary>"2 new · 3 fixed · 1 security" over one or more releases, each count in its category colour.</summary>
public sealed class ChangelogCounts : TextBlock
{
    public static readonly StyledProperty<IReadOnlyList<ChangelogRelease>?> ReleasesProperty =
        AvaloniaProperty.Register<ChangelogCounts, IReadOnlyList<ChangelogRelease>?>(nameof(Releases));

    public IReadOnlyList<ChangelogRelease>? Releases { get => GetValue(ReleasesProperty); set => SetValue(ReleasesProperty, value); }

    protected override Type StyleKeyOverride => typeof(TextBlock);

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ReleasesProperty) Build();
    }

    private void Build()
    {
        Inlines ??= new InlineCollection();
        Inlines.Clear();
        var releases = Releases ?? [];
        foreach (var c in ChangelogCategories.All)
        {
            int n = releases.Sum(r => r.Count(c));
            if (n == 0) continue;
            if (Inlines.Count > 0) Inlines.Add(new Run(" · ") { Foreground = ChangelogPalette.ThemeBrush("TextFaintBrush", Brushes.Gray) });
            Inlines.Add(new Run($"{n} {c.SummaryWord()}") { Foreground = ChangelogPalette.Brush(c, 0xE6) });
        }
    }
}
