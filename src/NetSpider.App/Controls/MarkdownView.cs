using System.Text.RegularExpressions;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using NetSpider.App.Services;

namespace NetSpider.App.Controls;

/// <summary>
/// Minimal markdown renderer for release notes: headings (#, ##, ###), bullets (-, *, +), numbered lists, paragraphs,
/// code fences, <c>**bold**</c>, <c>*italic*</c>, <c>`code`</c>, <c>[links](url)</c> and bare URLs. No extra packages.
/// </summary>
public sealed partial class MarkdownView : StackPanel
{
    public static readonly StyledProperty<string?> MarkdownProperty = AvaloniaProperty.Register<MarkdownView, string?>(nameof(Markdown));

    public string? Markdown { get => GetValue(MarkdownProperty); set => SetValue(MarkdownProperty, value); }

    public MarkdownView() => Spacing = 6;

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == MarkdownProperty) Render();
    }

    private static IBrush Res(string key, IBrush fallback) =>
        Application.Current?.TryGetResource(key, null, out var v) == true && v is IBrush b ? b : fallback;

    private void Render()
    {
        Children.Clear();
        var md = Markdown;
        if (string.IsNullOrWhiteSpace(md))
        {
            Children.Add(new TextBlock { Text = "No release notes were published for this version.", Foreground = Res("TextDimBrush", Brushes.Gray), FontStyle = FontStyle.Italic });
            return;
        }
        var para = new List<string>();
        var code = new List<string>();
        bool inCode = false;

        void FlushPara()
        {
            if (para.Count == 0) return;
            Children.Add(Paragraph(string.Join(" ", para), 13));
            para.Clear();
        }

        foreach (var raw in md.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.TrimStart().StartsWith("```"))
            {
                if (inCode)
                {
                    Children.Add(CodeBlock(string.Join("\n", code)));
                    code.Clear();
                }
                else FlushPara();
                inCode = !inCode;
                continue;
            }
            if (inCode) { code.Add(raw); continue; }

            var t = line.Trim();
            if (t.Length == 0) { FlushPara(); continue; }
            if (HeadingRx().Match(t) is { Success: true } h)
            {
                FlushPara();
                int level = h.Groups[1].Value.Length;
                var tb = Paragraph(h.Groups[2].Value.Trim().TrimEnd('#').Trim(), level switch { 1 => 18, 2 => 15.5, _ => 13.5 });
                tb.FontWeight = FontWeight.SemiBold;
                tb.Margin = new Thickness(0, Children.Count == 0 ? 0 : 8, 0, 0);
                if (level >= 3) tb.Foreground = Res("CyanBrush", Brushes.Cyan);
                Children.Add(tb);
                continue;
            }
            if (t is "---" or "***" or "___")
            {
                FlushPara();
                Children.Add(new Border { Height = 1, Background = Res("BorderBrushNeon", Brushes.Gray), Margin = new Thickness(0, 6) });
                continue;
            }
            if (BulletRx().Match(line) is { Success: true } b)
            {
                FlushPara();
                int indent = b.Groups[1].Value.Replace("\t", "    ").Length / 2;
                Children.Add(ListItem("•", b.Groups[2].Value, indent));
                continue;
            }
            if (NumberRx().Match(line) is { Success: true } n)
            {
                FlushPara();
                int indent = n.Groups[1].Value.Replace("\t", "    ").Length / 2;
                Children.Add(ListItem(n.Groups[2].Value + ".", n.Groups[3].Value, indent));
                continue;
            }
            para.Add(t);
        }
        if (inCode && code.Count > 0) Children.Add(CodeBlock(string.Join("\n", code)));
        FlushPara();
    }

    private static Control ListItem(string marker, string text, int indent)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("18,*"), Margin = new Thickness(6 + indent * 18, 0, 0, 0) };
        g.Children.Add(new TextBlock { Text = marker, Foreground = Res("CyanBrush", Brushes.Cyan), FontSize = 13, FontWeight = FontWeight.Bold });
        var body = Paragraph(text, 13);
        Grid.SetColumn(body, 1);
        g.Children.Add(body);
        return g;
    }

    private static Control CodeBlock(string text) => new Border
    {
        Background = new SolidColorBrush(Color.Parse("#0A1020")),
        BorderBrush = Res("BorderBrushNeon", Brushes.Gray),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(8),
        Padding = new Thickness(10, 8),
        Child = new SelectableTextBlock
        {
            Text = text, TextWrapping = TextWrapping.Wrap, FontSize = 12,
            FontFamily = Application.Current?.TryGetResource("MonoFont", null, out var f) == true && f is FontFamily ff ? ff : FontFamily.Default,
        },
    };

    /// <summary>A wrapping TextBlock with inline bold/italic/code/link formatting; links are underlined runs, hit-tested on click.</summary>
    public static TextBlock Paragraph(string text, double size)
    {
        var tb = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = size, LineHeight = size * 1.45 };
        tb.Inlines ??= new InlineCollection();
        var links = new List<(int Start, int Length, string Url)>();
        int pos = 0, offset = 0;
        void Add(Run r) { tb.Inlines!.Add(r); offset += r.Text?.Length ?? 0; }
        foreach (Match m in InlineRx().Matches(text))
        {
            if (m.Index > pos) Add(new Run(text[pos..m.Index]));
            if (m.Groups["bold"].Success) Add(new Run(m.Groups["bold"].Value) { FontWeight = FontWeight.Bold });
            else if (m.Groups["ital"].Success) Add(new Run(m.Groups["ital"].Value) { FontStyle = FontStyle.Italic });
            else if (m.Groups["code"].Success)
                Add(new Run(m.Groups["code"].Value)
                {
                    FontFamily = Application.Current?.TryGetResource("MonoFont", null, out var f) == true && f is FontFamily ff ? ff : FontFamily.Default,
                    Foreground = new SolidColorBrush(Color.Parse("#FFC4F3")),
                });
            else
            {
                var (label, url) = m.Groups["ltext"].Success ? (m.Groups["ltext"].Value, m.Groups["lurl"].Value) : (m.Groups["url"].Value, m.Groups["url"].Value);
                links.Add((offset, label.Length, url));
                Add(new Run(label) { Foreground = Res("CyanBrush", Brushes.Cyan), TextDecorations = TextDecorations.Underline });
            }
            pos = m.Index + m.Length;
        }
        if (pos < text.Length) Add(new Run(text[pos..]));
        if (links.Count > 0) AttachLinks(tb, links);
        return tb;
    }

    private static void AttachLinks(TextBlock tb, List<(int Start, int Length, string Url)> links)
    {
        string? LinkAt(Point p)
        {
            var hit = tb.TextLayout.HitTestPoint(p);
            if (!hit.IsInside) return null;
            int i = hit.TextPosition;
            foreach (var l in links) if (i >= l.Start && i < l.Start + l.Length) return l.Url;
            return null;
        }
        var hand = new Cursor(StandardCursorType.Hand);
        tb.PointerMoved += (_, e) =>
        {
            var url = LinkAt(e.GetPosition(tb));
            tb.Cursor = url is null ? Cursor.Default : hand;
            ToolTip.SetTip(tb, url);
        };
        tb.PointerPressed += (_, e) =>
        {
            if (LinkAt(e.GetPosition(tb)) is not { } url) return;
            if (Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp)) Launcher.Open(u.AbsoluteUri);
            e.Handled = true;
        };
    }

    [GeneratedRegex(@"^(#{1,6})\s+(.*)$")] private static partial Regex HeadingRx();
    [GeneratedRegex(@"^(\s*)[-*+]\s+(.*)$")] private static partial Regex BulletRx();
    [GeneratedRegex(@"^(\s*)(\d+)[.)]\s+(.*)$")] private static partial Regex NumberRx();
    [GeneratedRegex(@"\*\*(?<bold>.+?)\*\*|__(?<bold>.+?)__|(?<![\w*])\*(?<ital>[^*\s][^*]*?)\*(?![\w*])|`(?<code>[^`]+)`|\[(?<ltext>[^\]]+)\]\((?<lurl>[^)\s]+)\)|(?<url>https?://[^\s)<>]+)")]
    private static partial Regex InlineRx();
}
