#Requires -Version 5.1
<#
.SYNOPSIS
  Builds a FreeSense NetSpider release: Velopack Setup.exe + portable zip + update packages, a machine-wide MSI and the
  probe agent zips, for each Windows architecture. Works on a dev box (Windows PowerShell 5.1 or pwsh 7) and in CI.

.EXAMPLE
  ./build/release.ps1 -Version 1.0.0                      # all 3 RIDs, Release (+ Pre-release) channel, no upload
  ./build/release.ps1 -Version 1.1.0-pre.1 -Rids win-x64  # Pre-release channel only (any -suffix => prerelease)
  ./build/release.ps1 -Version 1.0.0 -Upload              # also publish to FreeSense-org/NetSpider (needs a token)

.NOTES
  Output: artifacts/<version>/
    FreeSense-NetSpider-<ver>-<rid>-Setup.exe      per-user Velopack installer (auto-updating, follows its channel)
    FreeSense-NetSpider-<ver>-<rid>-PreRelease-Setup.exe  (release versions) installer that follows the Pre-release channel
    FreeSense-NetSpider-<ver>-<rid>-Standalone.exe single-file exe, no install, manual updates
    FreeSense-NetSpider-<ver>-<rid>-Portable.zip   portable (contains current/install-mode.txt = "portable")
    FreeSense-NetSpider-<ver>-<rid>.msi            machine-wide MSI (WiX v5, installer/msi), no self-update
    FreeSense.NetSpider-<ver>-<channel>-full.nupkg (+ -delta.nupkg)   update packages (Velopack feed)
    releases.<channel>.json, assets.<channel>.json Velopack feed index / upload manifest
    FreeSense-NetSpider-Probe-<ver>-<rid>.zip      headless probe agent (win-x64/arm64/x86, linux-x64/arm64)
    RELEASE-NOTES.md, SHA256SUMS.txt
  Scratch (publish folders, vpk working dirs): artifacts/_work/<version>/

  Signing (disabled until a certificate exists): pass -SignParams "/fd SHA256 /f cert.pfx /p <pwd> /tr http://timestamp.digicert.com /td SHA256"
  (signtool) or -AzureTrustedSignFile metadata.json (Azure Trusted Signing). vpk then signs the app binaries,
  Update.exe and Setup.exe; this script signs the MSI and the Windows probe exes with signtool (-SignParams only).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string[]]$Rids = @('win-x64', 'win-arm64', 'win-x86'),
    # release: the version is published to the Release channel AND the Pre-release channel (pre-release users get
    # every release too). prerelease: only to the Pre-release channel. auto: by the version ('-suffix' => prerelease).
    [ValidateSet('auto', 'release', 'prerelease')][string]$Channel = 'auto',
    [switch]$SkipStandalone,
    [string]$OutDir = 'artifacts',
    [switch]$Upload,
    [switch]$SkipTests,
    [switch]$SkipMsi,
    [switch]$SkipProbe,
    # Probe agent RIDs. Default: the selected Windows RIDs, plus linux-x64/linux-arm64 when win-x64 is built.
    [string[]]$ProbeRids,
    # Markdown release notes. Default: from CHANGELOG.md via tools/ChangelogTool ([X.Y.Z] section for a release,
    # [Unreleased] for a pre-release); falls back to `git log` since the previous v* tag.
    [string]$ReleaseNotes,
    # GitHub token for the repository (vpk download/upload). Falls back to RELEASES_TOKEN, then GITHUB_TOKEN.
    [string]$Token,
    [string]$ReleasesRepoUrl = 'https://github.com/FreeSense-org/NetSpider',
    # Delta packages: download the previous release of each channel first. 'auto' = when -Upload or a token is set.
    [ValidateSet('auto', 'always', 'never')][string]$Deltas = 'auto',
    [string]$SignParams,
    [string]$AzureTrustedSignFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {

# ---------------------------------------------------------------------------------------------------------------- setup
function Step([string]$msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Exec([string]$exe, [string[]]$argList) {
    Write-Host "  > $exe $($argList -join ' ')" -ForegroundColor DarkGray
    & $exe @argList
    if ($LASTEXITCODE -ne 0) { throw "'$exe $($argList -join ' ')' failed with exit code $LASTEXITCODE" }
}
function Sign-File([string]$path) {
    if (-not $SignParams) { return }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found (install the Windows SDK) but -SignParams was given.' }
    # SignParams is a single string of signtool arguments, split like a command line.
    Exec $signtool.FullName (@('sign') + ($SignParams -split ' (?=(?:[^"]*"[^"]*")*[^"]*$)' | ForEach-Object { $_.Trim('"') }) + @($path))
}

if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { throw "Version '$Version' is not SemVer (e.g. 1.2.3 or 1.2.3-beta.1)." }
$IsPrerelease = $Version.Contains('-')
if ($Channel -eq 'auto') { $Channel = if ($IsPrerelease) { 'prerelease' } else { 'release' } }
if ($Channel -eq 'release' -and $IsPrerelease) { throw "Version '$Version' has a pre-release suffix; it can only go to the prerelease channel." }
$PreSuffix = '-prerelease'
if (-not $Token) { $Token = if ($env:RELEASES_TOKEN) { $env:RELEASES_TOKEN } else { $env:GITHUB_TOKEN } }
if ($Upload -and -not $Token) { throw '-Upload needs a GitHub token (-Token, or RELEASES_TOKEN / GITHUB_TOKEN env var).' }
$UseDeltas = ($Deltas -eq 'always') -or ($Deltas -eq 'auto' -and ($Upload -or $Token))
if (-not $ProbeRids) {
    $ProbeRids = @($Rids)
    if ($Rids -contains 'win-x64') { $ProbeRids += @('linux-x64', 'linux-arm64') }
}

$Art = Join-Path $Root (Join-Path $OutDir $Version)
$Work = Join-Path $Root (Join-Path $OutDir "_work\$Version")
$Brand = Join-Path $Root 'src\NetSpider.App\Assets\Brand'
New-Item -ItemType Directory -Force $Art, $Work | Out-Null

Write-Host "FreeSense NetSpider release $Version  (channel: $Channel, RIDs: $($Rids -join ', '), deltas: $UseDeltas, upload: $Upload)"
Write-Host "Artifacts: $Art"

Step 'Restore tools and packages'
Exec dotnet @('tool', 'restore')
Exec dotnet @('restore', 'NetworkScan.slnx')

if (-not $SkipTests) {
    Step 'Test'
    Exec dotnet @('test', 'NetworkScan.slnx', '-c', 'Release', '--no-restore', '--logger', 'trx', '--results-directory', (Join-Path $Work 'TestResults'))
}

# ---------------------------------------------------------------------------------------------------- release notes
# RELEASE-NOTES.md is what Velopack ships as the update's notes (the in-app update dialog renders it by category) and
# the GitHub release body. It comes from CHANGELOG.md via ChangelogTool: the "## [X.Y.Z]" section for a release,
# [Unreleased] for a pre-release. Fallback (tool failed, or nothing in the changelog): git log since the previous tag.
$NotesFile = Join-Path $Art 'RELEASE-NOTES.md'
$notesDone = $false
if ($ReleaseNotes) {
    Copy-Item $ReleaseNotes $NotesFile -Force
    $notesDone = $true
} else {
    $notesArgs = if ($IsPrerelease) { @('--unreleased') } else { @('--version', $Version) }
    Step "Release notes (CHANGELOG.md: notes $($notesArgs -join ' '))"
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & dotnet @(@('run', '--project', 'tools/ChangelogTool', '-c', 'Release', '--', 'notes') + $notesArgs + @('--out', $NotesFile))
    $notesExit = $LASTEXITCODE
    $ErrorActionPreference = $eap
    if ($notesExit -eq 0 -and (Test-Path $NotesFile) -and (Get-Item $NotesFile).Length -gt 0) { $notesDone = $true }
    else { Write-Warning "ChangelogTool notes failed (exit $notesExit); falling back to git log release notes." }
    $global:LASTEXITCODE = 0
}
if (-not $notesDone) {
    Step 'Release notes (fallback: git log since previous tag)'
    # Native stderr + EAP=Stop throws in Windows PowerShell 5.1, so relax it for these probing git calls.
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $prevEnc = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }   # git log emits UTF-8
    $headTags = @(git tag --points-at HEAD --list 'v*' 2>$null)
    $describeFrom = 'HEAD'
    if ($headTags.Count -gt 0) { $describeFrom = 'HEAD^' }
    $prevTag = git describe --tags --abbrev=0 --match 'v*' $describeFrom 2>$null
    if ($LASTEXITCODE -ne 0) { $prevTag = $null }
    $range = 'HEAD'
    if ($prevTag) { $range = "$prevTag..HEAD" }
    $log = @(git -c i18n.logOutputEncoding=UTF-8 log $range --no-merges '--pretty=format:- %s (%h)' -n 200 2>$null)
    try { [Console]::OutputEncoding = $prevEnc } catch { }
    $ErrorActionPreference = $eap
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("## FreeSense NetSpider $Version"); $lines.Add('')
    if ($prevTag) { $lines.Add("Changes since $prevTag`:") } else { $lines.Add('Changes:') }
    $lines.Add('')
    if ($log.Count -gt 0) { foreach ($l in $log) { $lines.Add($l) } } else { $lines.Add('- Maintenance release.') }
    [IO.File]::WriteAllText($NotesFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}
$global:LASTEXITCODE = 0


$icon = Join-Path $Brand 'netspider.ico'
if (-not (Test-Path $icon)) { Write-Warning "Icon $icon not found; packing without --icon."; $icon = $null }
$splash = @('splash.gif', 'splash.png', 'logo-512.png', 'logo-256.png') | ForEach-Object { Join-Path $Brand $_ } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
$msiBanner = Get-ChildItem $Brand -Filter '*banner*.bmp' -ErrorAction SilentlyContinue | Select-Object -First 1
$msiDialog = @(Get-ChildItem $Brand -Filter '*dialog*.bmp' -ErrorAction SilentlyContinue) +
             @(Get-ChildItem $Brand -Filter '*side*.bmp' -ErrorAction SilentlyContinue) | Select-Object -First 1

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$PackId = 'FreeSense.NetSpider'
$Pretty = "FreeSense-NetSpider-$Version"
$channels = @()

foreach ($rid in $Rids) {
    if ($rid -notin @('win-x64', 'win-arm64', 'win-x86')) { throw "Unsupported RID '$rid' (win-x64, win-arm64, win-x86)." }
    $pub = Join-Path $Work "publish\$rid"

    # ------------------------------------------------------------------------------------------------------ publish
    Step "[$rid] dotnet publish"
    if (Test-Path $pub) { Remove-Item $pub -Recurse -Force }
    Exec dotnet @('publish', 'src/NetSpider.App/NetSpider.App.csproj', '-c', 'Release', '-r', $rid, "-p:Version=$Version",
                  '-o', $pub, '-nologo')

    # ------------------------------------------------------------------------------------------- standalone single exe
    if (-not $SkipStandalone) {
        Step "[$rid] standalone single-file exe"
        $sa = Join-Path $Work "standalone\$rid"
        if (Test-Path $sa) { Remove-Item $sa -Recurse -Force }
        # Managed code runs straight from the bundle; only native DLLs (Skia/HarfBuzz/SQLite/ANGLE) are extracted on first run.
        # No compression (it would decompress on every start). LICENSE/notices are embedded as Avalonia resources.
        Exec dotnet @('publish', 'src/NetSpider.App/NetSpider.App.csproj', '-c', 'Release', '-r', $rid, "-p:Version=$Version",
                      '-p:PublishSingleFile=true', '-p:EnableCompressionInSingleFile=false',
                      '-p:DebugType=none', '-o', $sa, '-nologo')
        $saExe = Join-Path $Art "$Pretty-$rid-Standalone.exe"
        Copy-Item (Join-Path $sa 'NetSpider.exe') $saExe -Force
        Sign-File $saExe
    }

    # Release versions go to both channels (pre-release followers get every release); pre-releases only to "-prerelease".
    $packChannels = if ($Channel -eq 'release') { @($rid, "$rid$PreSuffix") } else { @("$rid$PreSuffix") }
    foreach ($ch in $packChannels) {
    $channels += $ch
    $isPreChannel = $ch.EndsWith($PreSuffix)
    # For a release version the pre-release channel gets its own installer ("...-PreRelease-Setup.exe": installs a copy
    # that follows pre-releases) but no second portable zip.
    $secondary = ($Channel -eq 'release') -and $isPreChannel
    $vpkDir = Join-Path $Work "vpk\$ch"

    # ------------------------------------------------------------------------------------------- previous release (deltas)
    if (Test-Path $vpkDir) { Remove-Item $vpkDir -Recurse -Force }
    New-Item -ItemType Directory -Force $vpkDir | Out-Null
    if ($UseDeltas) {
        Step "[$rid] vpk download github (previous '$ch' release, for delta packages)"
        $dl = @('vpk', 'download', 'github', '--repoUrl', $ReleasesRepoUrl, '--channel', $ch, '-o', $vpkDir)
        if ($Token) { $dl += @('--token', $Token) }
        if ($isPreChannel) { $dl += '--pre' }
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & dotnet @dl
        $dlExit = $LASTEXITCODE
        $ErrorActionPreference = $eap
        if ($dlExit -ne 0) { Write-Warning "No previous '$ch' release downloaded (first release?); building full packages only." }
        $global:LASTEXITCODE = 0
    }

    # -------------------------------------------------------------------------------------------------- vpk pack
    Step "[$rid] vpk pack"
    $pack = @('vpk', 'pack',
        '--packId', $PackId, '--packVersion', $Version, '--packDir', $pub, '--mainExe', 'NetSpider.exe',
        '--packTitle', 'FreeSense NetSpider', '--packAuthors', 'FreeSense.org',
        '--channel', $ch, '--runtime', $rid, '--outputDir', $vpkDir,
        '--releaseNotes', $NotesFile,
        # Start menu (root) + desktop shortcuts named after --packTitle; created/removed by Setup/Update.exe.
        '--shortcuts', 'Desktop,StartMenuRoot')
    if ($icon) { $pack += @('--icon', $icon) }
    if ($splash) { $pack += @('--splashImage', $splash) }
    if ($SignParams) { $pack += @('--signParams', $SignParams) }
    if ($AzureTrustedSignFile) { $pack += @('--azureTrustedSignFile', $AzureTrustedSignFile) }
    Exec dotnet $pack

    # ------------------------------------------------------------- collect: rename installer/portable, keep feed names
    Step "[$rid] collect Velopack artifacts"
    $assetsJson = Join-Path $vpkDir "assets.$ch.json"
    # (ForEach-Object unrolls the JSON array; Windows PowerShell 5.1 returns it as a single object.)
    $assets = @((Get-Content $assetsJson -Raw | ConvertFrom-Json) | ForEach-Object { $_ })
    if ($secondary) { $assets = @($assets | Where-Object { $_.Type -ne 'Portable' }) }
    foreach ($a in $assets) {
        $src = Join-Path $vpkDir $a.RelativeFileName
        $name = switch ($a.Type) {
            'Installer' { if ($secondary) { "$Pretty-$rid-PreRelease-Setup.exe" } else { "$Pretty-$rid-Setup.exe" } }
            'Portable'  { "$Pretty-$rid-Portable.zip" }
            default     { $a.RelativeFileName }   # Full / Delta nupkgs: feed names must stay as vpk wrote them
        }
        Copy-Item $src (Join-Path $Art $name) -Force
        $a.RelativeFileName = $name
        if ($a.Type -eq 'Portable') {
            # Portable marker next to the real NetSpider.exe (AppContext.BaseDirectory = <zip>/current/).
            $zip = [IO.Compression.ZipFile]::Open((Join-Path $Art $name), 'Update')
            try {
                $existing = $zip.GetEntry('current/install-mode.txt'); if ($existing) { $existing.Delete() }
                $e = $zip.CreateEntry('current/install-mode.txt')
                $w = New-Object IO.StreamWriter($e.Open()); $w.Write('portable'); $w.Dispose()
            } finally { $zip.Dispose() }
        }
    }
    # assets.<channel>.json is what `vpk upload` reads: point it at the renamed files.
    $json = '[' + (($assets | ForEach-Object { '{"RelativeFileName":"' + $_.RelativeFileName + '","Type":"' + $_.Type + '"}' }) -join ',') + ']'
    [IO.File]::WriteAllText((Join-Path $Art "assets.$ch.json"), $json, (New-Object Text.UTF8Encoding $false))
    Copy-Item (Join-Path $vpkDir "releases.$ch.json") $Art -Force
    }   # end foreach channel

    # -------------------------------------------------------------------------------------------------------- MSI
    if (-not $SkipMsi) {
        Step "[$rid] MSI (WiX v5)"
        $platform = $rid.Substring(4)   # x64 | arm64 | x86
        $msiOut = Join-Path $Work "msi\$rid"
        if (Test-Path $msiOut) { Remove-Item $msiOut -Recurse -Force }
        $msiArgs = @('build', 'installer/msi/NetSpider.Msi.wixproj', '-c', 'Release', "-p:Platform=$platform",
                     "-p:PublishDir=$pub\", "-p:ProductVersion=$Version", '-o', $msiOut, '-nologo')
        if ($icon) { $msiArgs += "-p:ProductIcon=$icon" }
        if ($msiBanner) { $msiArgs += "-p:BannerBmp=$($msiBanner.FullName)" }
        if ($msiDialog) { $msiArgs += "-p:DialogBmp=$($msiDialog.FullName)" }
        Exec dotnet $msiArgs
        $msi = Join-Path $Art "$Pretty-$rid.msi"
        Copy-Item (Join-Path $msiOut 'FreeSense-NetSpider.msi') $msi -Force
        Sign-File $msi
    }
}

# -------------------------------------------------------------------------------------------------------------- probe
if (-not $SkipProbe) {
    foreach ($prid in $ProbeRids) {
        Step "[probe $prid] dotnet publish (trimmed single file)"
        $ppub = Join-Path $Work "probe\$prid"
        if (Test-Path $ppub) { Remove-Item $ppub -Recurse -Force }
        Exec dotnet @('publish', 'src/NetSpider.Probe/NetSpider.Probe.csproj', '-c', 'Release', '-r', $prid, "-p:Version=$Version",
                      '-o', $ppub, '-nologo')
        if ($prid.StartsWith('win-')) { Sign-File (Join-Path $ppub 'netspider-probe.exe') }
        $pzip = Join-Path $Art "FreeSense-NetSpider-Probe-$Version-$prid.zip"
        if (Test-Path $pzip) { Remove-Item $pzip -Force }
        Copy-Item (Join-Path $Root 'LICENSE') (Join-Path $ppub 'LICENSE.txt') -Force
        [IO.Compression.ZipFile]::CreateFromDirectory($ppub, $pzip)
    }
}

# ----------------------------------------------------------------------------------------------------------- checksums
Step 'Checksums'
$sums = Get-ChildItem $Art -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Extension -in '.exe', '.zip', '.msi', '.nupkg' } |
    Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
[IO.File]::WriteAllText((Join-Path $Art 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))

Get-ChildItem $Art -File | Sort-Object Name | Format-Table Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize | Out-Host

if ($Upload) {
    & (Join-Path $PSScriptRoot 'upload-release.ps1') -Version $Version -ArtifactsDir $Art -Token $Token -ReleasesRepoUrl $ReleasesRepoUrl
}
Write-Host "Done: $Art" -ForegroundColor Green

} finally { Pop-Location }
