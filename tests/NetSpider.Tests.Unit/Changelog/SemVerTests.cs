using NetSpider.Core.Changelog;

namespace NetSpider.Tests.Unit.ChangelogSpec;

public class SemVerTests
{
    [Theory]
    [InlineData("1.2.3", 1, 2, 3, null)]
    [InlineData("v1.2.3", 1, 2, 3, null)]
    [InlineData(" 0.1.0 ", 0, 1, 0, null)]
    [InlineData("1.3.0-pre.12", 1, 3, 0, "pre.12")]
    [InlineData("1.0.0-alpha.0.5+abc1234", 1, 0, 0, "alpha.0.5")]
    public void Parses_versions(string text, int major, int minor, int patch, string? pre)
    {
        Assert.True(SemVer.TryParse(text, out var v));
        Assert.Equal((major, minor, patch, pre), (v.Major, v.Minor, v.Patch, v.Prerelease));
        Assert.Equal(pre is not null, v.IsPrerelease);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("01.2.3")]
    [InlineData("1.2.3-")]
    [InlineData("1.2.3-pre.01")]
    [InlineData("one.two.three")]
    public void Rejects_invalid_versions(string text) => Assert.False(SemVer.TryParse(text, out _));

    [Theory]
    [InlineData("1.0.0-pre.1", "1.0.0")]
    [InlineData("1.0.0-pre.2", "1.0.0-pre.10")]   // numeric identifiers compare numerically
    [InlineData("1.0.0-alpha", "1.0.0-alpha.1")]
    [InlineData("1.0.0-alpha.1", "1.0.0-beta")]
    [InlineData("1.0.0-1", "1.0.0-alpha")]         // numeric < alphanumeric
    [InlineData("1.9.9", "1.10.0")]
    [InlineData("1.10.0", "2.0.0")]
    [InlineData("0.1.0", "1.0.0-alpha.0.3")]
    public void Orders_by_semver_precedence(string lower, string higher)
    {
        Assert.True(SemVer.Parse(lower) < SemVer.Parse(higher));
        Assert.True(SemVer.Parse(higher) > SemVer.Parse(lower));
    }

    [Fact]
    public void Build_metadata_is_ignored_for_equality() =>
        Assert.Equal(SemVer.Parse("1.2.3+abc"), SemVer.Parse("1.2.3+def"));

    [Fact]
    public void Bumps_and_formats()
    {
        var v = SemVer.Parse("1.4.2");
        Assert.Equal("2.0.0", v.NextMajor().ToString());
        Assert.Equal("1.5.0", v.NextMinor().ToString());
        Assert.Equal("1.4.3", v.NextPatch().ToString());
        Assert.Equal("1.4.2-pre.3", v.WithPrerelease("pre.3").ToString());
        Assert.Equal("1.4.2", SemVer.Parse("1.4.2-pre.3+x").Core.ToString());
    }
}
