#Requires -Version 5.1
<#
.SYNOPSIS
  Local equivalent of the Release workflow (.github/workflows/release.yml): prepares the release PR for the next
  version computed from CHANGELOG.md.

.DESCRIPTION
  1. Checks that the working tree is clean and HEAD equals origin/main.
  2. Computes the version: tools/ChangelogTool next-version (last vX.Y.Z tag + [Unreleased]), or -Version.
  3. Creates branch release/vX.Y.Z, runs `ChangelogTool release --version X.Y.Z` ([Unreleased] → dated section) and
     commits "chore(release): vX.Y.Z".
  4. Unless -NoPush: pushes the branch, opens the PR with gh (body = release notes) and enables auto-merge (squash).
     The PR is yours, so pull_request CI runs normally; when it is merged, publish-release.yml tags and publishes it.

  Never push to main yourself and never tag by hand: the workflows do that.

.EXAMPLE
  ./build/prepare-release.ps1                 # next version from the changelog, push + PR
  ./build/prepare-release.ps1 -NoPush         # only the local branch and commit (inspect, then push yourself)
  ./build/prepare-release.ps1 -Version 2.0.0  # override the computed version
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Date,
    [switch]$NoPush,
    [switch]$NoAutoMerge
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    function Exec([string]$exe, [string[]]$argList) {
        Write-Host "  > $exe $($argList -join ' ')" -ForegroundColor DarkGray
        & $exe @argList
        if ($LASTEXITCODE -ne 0) { throw "'$exe $($argList -join ' ')' failed with exit code $LASTEXITCODE" }
    }
    function Tool([string[]]$argList) {
        $out = & dotnet @(@('run', '--project', 'tools/ChangelogTool', '-c', 'Release', '--no-build', '--') + $argList)
        return @{ Exit = $LASTEXITCODE; Out = ($out -join "`n").Trim() }
    }

    if (git status --porcelain) { throw 'The working tree has uncommitted changes; commit or stash them first.' }
    Exec git @('fetch', '--tags', 'origin', 'main')
    $head = (git rev-parse HEAD).Trim()
    $main = (git rev-parse origin/main).Trim()
    if ($head -ne $main) { throw "HEAD ($($head.Substring(0, 7))) is not origin/main ($($main.Substring(0, 7))). Check out main and pull first." }

    Exec dotnet @('build', 'tools/ChangelogTool', '-c', 'Release', '-nologo', '-v', 'q')
    $v = Tool @('validate', 'CHANGELOG.md')
    if ($v.Exit -ne 0) { Write-Host $v.Out; throw 'CHANGELOG.md is invalid.' }

    if (-not $Version) {
        $info = @{}
        (Tool @('info')).Out -split "`n" | ForEach-Object { $k, $val = $_ -split '=', 2; $info[$k] = $val }
        switch ($info['release_kind']) {
            'new' { $Version = $info['next_version'] }
            'pending' { throw "## [$($info['next_version'])] is already written but not tagged: run the Release workflow on GitHub, it publishes that section directly." }
            default { throw 'Nothing to release: [Unreleased] is empty.' }
        }
    }
    $Version = $Version.TrimStart('v')
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "'$Version' is not a release version (X.Y.Z)." }
    if (git tag --list "v$Version") { throw "v$Version is already tagged." }

    $branch = "release/v$Version"
    $title = "chore(release): v$Version"
    Write-Host "Preparing $title on $branch" -ForegroundColor Cyan
    Exec git @('switch', '-c', $branch)
    $releaseArgs = @('release', '--version', $Version)
    if ($Date) { $releaseArgs += @('--date', $Date) }
    $r = Tool $releaseArgs
    Write-Host $r.Out
    if ($r.Exit -ne 0) { throw 'ChangelogTool release failed.' }
    $notesFile = Join-Path ([IO.Path]::GetTempPath()) "netspider-release-notes-$Version.md"
    $n = Tool @('notes', '--version', $Version, '--out', $notesFile)
    if ($n.Exit -ne 0) { throw 'ChangelogTool notes failed.' }
    Exec git @('add', 'CHANGELOG.md')
    Exec git @('commit', '-m', $title)

    if ($NoPush) {
        Write-Host "Done (not pushed). Review with 'git show', then: git push -u origin $branch; gh pr create --base main --title `"$title`"" -ForegroundColor Green
        return
    }
    Exec git @('push', '-u', 'origin', $branch)
    $bodyFile = Join-Path ([IO.Path]::GetTempPath()) "netspider-release-body-$Version.md"
    $body = "Release **v$Version**: moves ``[Unreleased]`` in CHANGELOG.md into ``## [$Version]``.`n" +
            "When this PR is merged, *Publish release* tags ``v$Version`` and publishes it.`n`n## Release notes`n`n" + (Get-Content $notesFile -Raw)
    [IO.File]::WriteAllText($bodyFile, $body, (New-Object Text.UTF8Encoding $false))
    Exec gh @('pr', 'create', '--base', 'main', '--head', $branch, '--title', $title, '--body-file', $bodyFile)
    if (-not $NoAutoMerge) {
        & gh pr merge $branch --squash --auto --subject $title
        if ($LASTEXITCODE -ne 0) { Write-Warning "Couldn't enable auto-merge; merge the PR with 'Squash and merge' once the checks pass." }
    }
    Write-Host "Release PR for v$Version is open." -ForegroundColor Green
} finally { Pop-Location }
