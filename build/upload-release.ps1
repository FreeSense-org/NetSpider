#Requires -Version 5.1
<#
.SYNOPSIS
  Publishes an artifacts/<version>/ folder (from build/release.ps1) as GitHub release v<version> in the public
  FreeSense-org/NetSpider repo. Used by release.ps1 -Upload and by the release.yml workflow.

  1. `vpk upload github` once per channel found (assets.<channel>.json). All channels go into the SAME release:
     --merge lets later channels add their files (each channel has its own releases.<channel>.json feed index),
     the release stays a draft until the last channel, which passes --publish. --pre for pre-release versions.
  2. `gh release upload` the MSIs, probe zips and SHA256SUMS.txt (not part of the Velopack feed).
  3. `gh release edit` sets the release body: release notes + a download guide.

  Needs a token with contents:write on the repository (-Token, or RELEASES_TOKEN / GH_TOKEN env var).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ArtifactsDir,
    [string]$Token,
    [string]$ReleasesRepoUrl = 'https://github.com/FreeSense-org/NetSpider'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Token) { $Token = if ($env:RELEASES_TOKEN) { $env:RELEASES_TOKEN } else { $env:GH_TOKEN } }
if (-not $Token) { throw 'No token: pass -Token or set RELEASES_TOKEN.' }
$repo = ($ReleasesRepoUrl -replace '^https://github.com/', '').TrimEnd('/')
$tag = "v$Version"
$isPre = $Version.Contains('-')
$ArtifactsDir = (Resolve-Path $ArtifactsDir).Path

function Exec([string]$exe, [string[]]$argList, [string]$display) {
    Write-Host "  > $exe $(if ($display) { $display } else { $argList -join ' ' })" -ForegroundColor DarkGray
    & $exe @argList
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

$channels = @(Get-ChildItem $ArtifactsDir -Filter 'assets.*.json' | ForEach-Object { $_.Name -replace '^assets\.(.+)\.json$', '$1' } | Sort-Object)
if ($channels.Count -eq 0) { throw "No assets.<channel>.json in $ArtifactsDir; run build/release.ps1 first." }
Write-Host "Uploading $tag to $repo, channels: $($channels -join ', ')"

Push-Location $Root
try {
    Exec dotnet @('tool', 'restore')
    for ($i = 0; $i -lt $channels.Count; $i++) {
        $ch = $channels[$i]
        $up = @('vpk', 'upload', 'github', '--outputDir', $ArtifactsDir, '--channel', $ch, '--repoUrl', $ReleasesRepoUrl,
                '--token', $Token, '--merge', '--tag', $tag, '--releaseName', "FreeSense NetSpider $Version")
        if ($isPre) { $up += '--pre' }
        if ($i -eq $channels.Count - 1) { $up += '--publish' }
        Exec dotnet $up (($up -join ' ') -replace [regex]::Escape($Token), '***')
    }

    $env:GH_TOKEN = $Token
    $extra = @(Get-ChildItem $ArtifactsDir -File | Where-Object { $_.Extension -eq '.msi' -or $_.Name -like '*-Standalone.exe' -or $_.Name -like 'FreeSense-NetSpider-Probe-*' -or $_.Name -eq 'SHA256SUMS.txt' } |
        ForEach-Object { $_.FullName })
    if ($extra.Count -gt 0) {
        Exec gh (@('release', 'upload', $tag, '--repo', $repo, '--clobber') + $extra)
    }

    $notes = Join-Path $ArtifactsDir 'RELEASE-NOTES.md'
    # RELEASE-NOTES.md is the CHANGELOG.md section ("### New" / "### Fixed" … bullets), see build/release.ps1.
    $heading = if ($isPre) { "## What's new in this pre-release`n`nEverything under ``[Unreleased]`` in [CHANGELOG.md](https://github.com/$repo/blob/main/CHANGELOG.md) at this build." } else { "## What's new in $Version" }
    $body = if (Test-Path $notes) { "$heading`n`n" + (Get-Content $notes -Raw) } else { "## FreeSense NetSpider $Version`n" }
    $body += @"

## Downloads

| File | What it is |
|---|---|
| ``FreeSense-NetSpider-$Version-<arch>-Setup.exe`` | **Recommended.** Per-user install, Start menu + desktop shortcut, automatic updates$(if ($isPre) { ' on the **Pre-release** channel' } else { ' (Release channel)' }). |
$(if (-not $isPre) { "| ``FreeSense-NetSpider-$Version-<arch>-PreRelease-Setup.exe`` | Same, but follows the **Pre-release** channel (early builds + every release). Can be switched in Settings → Updates. |`n" })| ``FreeSense-NetSpider-$Version-<arch>-Standalone.exe`` | **Standalone:** one exe, nothing to install. Run it from anywhere (USB stick). Updates are manual. |
| ``FreeSense-NetSpider-$Version-<arch>.msi`` | Machine-wide install for IT (Intune / GPO / SCCM), ``msiexec /i <file> /qn``. Updated by deploying the newer MSI. |
| ``FreeSense-NetSpider-$Version-<arch>-Portable.zip`` | No install: unzip and run ``NetSpider.exe``. Manual updates. |
| ``FreeSense-NetSpider-Probe-$Version-<rid>.zip`` | Headless probe agent (second vantage point), Windows and Linux. |

``<arch>``: **win-x64** (most PCs), **win-arm64** (Snapdragon / ARM PCs), **win-x86** (32-bit Windows 10 only).
NetSpider needs **[Npcap](https://npcap.com)** for packet capture; the app guides you through installing it.
The ``*.nupkg`` and ``releases.*.json`` files are the auto-update feed. Checksums: ``SHA256SUMS.txt``.

NetSpider is a [FreeSense](https://freesense.org) project.
"@
    $bodyFile = Join-Path ([IO.Path]::GetTempPath()) "netspider-release-body-$Version.md"
    [IO.File]::WriteAllText($bodyFile, $body, (New-Object Text.UTF8Encoding $false))
    Exec gh @('release', 'edit', $tag, '--repo', $repo, '--notes-file', $bodyFile)
    Write-Host "Published https://github.com/$repo/releases/tag/$tag" -ForegroundColor Green
} finally { Pop-Location }
