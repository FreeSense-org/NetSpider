using NetSpider.App.Services;
using NetSpider.Core.Changelog;
using NetSpider.Core.Model;

namespace NetSpider.Tests.Unit.App;

/// <summary>App-side changelog wiring: debug switches, and settings that must survive an import.</summary>
public class ChangelogUiTests
{
    [Fact]
    public void Whats_new_switch_defaults_to_current_and_takes_a_version()
    {
        Assert.Equal("current", AppOptions.Parse(["--demo", "--whats-new"]).WhatsNew);
        Assert.Equal("current", AppOptions.Parse(["--whats-new", "--hide-banners"]).WhatsNew);
        Assert.Equal("0.9.0", AppOptions.Parse(["--whats-new", "0.9.0"]).WhatsNew);
        Assert.Null(AppOptions.Parse(["--demo"]).WhatsNew);
    }

    [Fact]
    public void About_tab_switch_opens_about_on_that_tab()
    {
        var o = AppOptions.Parse(["--about-tab", "Changelog"]);
        Assert.True(o.About);
        Assert.Equal("changelog", o.AboutTab);
    }

    [Fact]
    public void Last_seen_version_is_machine_local() =>
        Assert.Contains(nameof(AppSettings.LastSeenVersion), SettingsPorter.LocalOnly);

    [Fact]
    public void Every_category_badge_has_its_own_theme_icon()
    {
        // the badge control maps every IconKey to a theme geometry; an unknown key would silently fall back
        var keys = ChangelogCategories.All.Select(c => NetSpider.App.Controls.ChangelogPalette.GeometryKey(c)).ToList();
        Assert.DoesNotContain("IconInfo", keys);
        Assert.Equal(keys.Count, keys.Distinct().Count());
        var theme = File.ReadAllText(NetSpider.Tests.Unit.ChangelogSpec.ChangelogParserTests.FindRepoFile(Path.Combine("src", "NetSpider.App", "Theme", "NeonTheme.axaml")));
        Assert.All(keys, k => Assert.Contains($"x:Key=\"{k}\"", theme));
    }
}
