#Requires -Version 5.1
<#
.SYNOPSIS
    Fetches the latest official itm4n/PrivescCheck.ps1 release and re-embeds it into
    Invoke-SecurityAssessment.ps1, replacing the existing bundled copy in place.

.DESCRIPTION
    Downloads PrivescCheck.ps1 from itm4n's GitHub "latest release" asset URL (the same URL
    the project's own README recommends), checks that what was received is well formed
    PowerShell and not an error page, then replaces the block between the
    "PRIVESCCHECK-EMBED-START" and "PRIVESCCHECK-EMBED-END" sentinel comments in the target
    script with a freshly generated block carrying the new source, fetch date and SHA256.

    The downloaded script is never executed or dot-sourced by this updater. It is only
    parsed (syntax-checked) and spliced in as text, so this update step does not run
    third-party code.

    A timestamped backup of the target script is made before it is modified. The result is
    re-parsed after the edit; if it is not valid PowerShell, the backup is restored
    automatically and the script exits with an error.

.PARAMETER TargetPath
    Path to Invoke-SecurityAssessment.ps1. Defaults to that file name in this script's folder.

.PARAMETER Force
    Re-embed even if the downloaded SHA256 matches what is already embedded.

.PARAMETER NoBackup
    Skip creating a backup copy of the target file before modifying it. Not recommended.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Update-PrivescCheck.ps1
#>
[CmdletBinding()]
param(
    [string]$TargetPath,
    [switch]$Force,
    [switch]$NoBackup
)

$ErrorActionPreference = 'Stop'
$ReleaseUrl = 'https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1'
$ApiUrl     = 'https://api.github.com/repos/itm4n/PrivescCheck/releases/latest'
$StartTag   = '# >>> PRIVESCCHECK-EMBED-START (managed by Update-PrivescCheck.ps1, do not hand-edit this block) >>>'
$EndTag     = '# <<< PRIVESCCHECK-EMBED-END <<<'
$MinBytes   = 200000

function Write-Step { param([string]$Text) Write-Host "  - $Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "    $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "    $Text" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Text) Write-Host "    $Text" -ForegroundColor Red }

function Test-ValidPowerShell {
    param([string]$Path)
    $errs = $null
    $tok = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$errs)
    return ($errs.Count -eq 0)
}

Write-Host ''
Write-Host '  PrivescCheck Auto-Update' -ForegroundColor White
Write-Host ('  ' + ('-' * 60)) -ForegroundColor DarkGray

if (-not $TargetPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $TargetPath = Join-Path $base 'Invoke-SecurityAssessment.ps1'
}
if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
    Write-Err2 "Target script not found: $TargetPath"
    Write-Host '  Pass -TargetPath to point at Invoke-SecurityAssessment.ps1 explicitly.' -ForegroundColor Yellow
    exit 1
}
Write-Step "Target: $TargetPath"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# ------------------------------------------------------------------------------------------
# 1. Download the latest release asset
# ------------------------------------------------------------------------------------------
Write-Step 'Downloading latest PrivescCheck.ps1 from GitHub...'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('PrivescCheck_{0}.ps1' -f ([Guid]::NewGuid().ToString('N')))
try {
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $tmp -UseBasicParsing -MaximumRedirection 10
}
catch {
    Write-Err2 "Download failed: $($_.Exception.Message)"
    exit 1
}

$tag = $null
try {
    $rel = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing -Headers @{ 'User-Agent' = 'Update-PrivescCheck' }
    $tag = $rel.tag_name
}
catch {
    Write-Warn2 'Could not read the release tag from the GitHub API (non-fatal, continuing).'
}

# ------------------------------------------------------------------------------------------
# 2. Validate what was downloaded before trusting it
# ------------------------------------------------------------------------------------------
Write-Step 'Validating download...'
$bytes = [IO.File]::ReadAllBytes($tmp)
if ($bytes.Length -lt $MinBytes) {
    Write-Err2 "Downloaded file is only $($bytes.Length) bytes, smaller than the expected minimum ($MinBytes)."
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 1
}
$head = [Text.Encoding]::UTF8.GetString($bytes, 0, [Math]::Min(500, $bytes.Length))
if ($head -match '(?i)<html|<!DOCTYPE') {
    Write-Err2 'Downloaded content looks like an HTML page, not a PowerShell script (bad URL or GitHub outage).'
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 1
}
if (-not (Test-ValidPowerShell -Path $tmp)) {
    Write-Err2 'Downloaded file does not parse as valid PowerShell. Not embedding it.'
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 1
}
$newHash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
Write-Ok ("Size: {0:N0} bytes   SHA256: {1}" -f $bytes.Length, $newHash)
if ($tag) { Write-Ok "Release tag: $tag" }
Write-Host '  Note: the downloaded script was parsed, not executed. It is embedded as text only.' -ForegroundColor DarkGray

# ------------------------------------------------------------------------------------------
# 3. Locate the existing embedded block in the target script
# ------------------------------------------------------------------------------------------
$target = Get-Content -LiteralPath $TargetPath -Raw
$si = $target.IndexOf($StartTag)
$ei = $target.IndexOf($EndTag)
if ($si -lt 0 -or $ei -lt 0 -or $ei -lt $si) {
    Write-Err2 'Could not find the PRIVESCCHECK-EMBED-START / END markers in the target script.'
    Write-Host '  The target may have been edited by hand, or is not the expected file.' -ForegroundColor Yellow
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 1
}
$ei = $ei + $EndTag.Length

$existingHash = $null
$existingBlock = $target.Substring($si, $ei - $si)
if ($existingBlock -match 'SHA256\s*:\s*([0-9a-f]{64})') { $existingHash = $Matches[1] }

if ($existingHash -and ($existingHash -eq $newHash) -and (-not $Force)) {
    Write-Host ''
    Write-Ok 'Already up to date. The embedded copy matches the latest release.'
    Write-Host ('  Current SHA256: {0}' -f $existingHash) -ForegroundColor DarkGray
    Write-Host '  Use -Force to re-embed anyway.' -ForegroundColor DarkGray
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 0
}

# ------------------------------------------------------------------------------------------
# 4. Build the replacement block and splice it in
# ------------------------------------------------------------------------------------------
Write-Step 'Building replacement block...'
# Read as raw bytes -> string, with no newline translation of any kind, so the downloaded
# source's own line endings are carried through completely untouched (byte-for-byte).
$newSourceBytes = [IO.File]::ReadAllBytes($tmp)
$newSource = [Text.Encoding]::UTF8.GetString($newSourceBytes)
if (-not $newSource.EndsWith("`n")) { $newSource += "`n" }
$fetchedOn = Get-Date -Format 'yyyy-MM-dd'

$headerLines = [Collections.Generic.List[string]]::new()
$headerLines.Add($StartTag)
$headerLines.Add('# ----------------------------------------------------------------------------------------------')
$headerLines.Add('# Embedded: itm4n/PrivescCheck (https://github.com/itm4n/PrivescCheck), BSD-3-Clause license.')
$headerLines.Add("# Bundled verbatim, byte-for-byte, from the project's official release asset so that this tool")
$headerLines.Add('# stays a single file. Not modified in any way.')
$headerLines.Add("#   Source  : $ReleaseUrl")
$headerLines.Add("#   Fetched : $fetchedOn")
if ($tag) { $headerLines.Add("#   Release : $tag") }
$headerLines.Add("#   SHA256  : $newHash")
$headerLines.Add('# To refresh this block later: run Update-PrivescCheck.ps1, or download the asset above,')
$headerLines.Add("# confirm its SHA256, and replace the text between the '@ ... '@ markers below by hand.")
$headerLines.Add('# ----------------------------------------------------------------------------------------------')
$headerLines.Add("`$script:PrivescCheckSource = @'")
$headerText = ($headerLines -join "`n") + "`n"

$footerText = "'@`n" + '$script:Ctx.PrivescCheckSource = $script:PrivescCheckSource' + "`n" + $EndTag

$newBlock = $headerText + $newSource + $footerText

$updated = $target.Substring(0, $si) + $newBlock + $target.Substring($ei)

# ------------------------------------------------------------------------------------------
# 5. Back up, write, and self-check the result
# ------------------------------------------------------------------------------------------
$backupPath = $null
if (-not $NoBackup) {
    $backupPath = '{0}.bak.{1}' -f $TargetPath, (Get-Date -Format 'yyyyMMdd_HHmmss')
    Copy-Item -LiteralPath $TargetPath -Destination $backupPath -Force
    Write-Step "Backup saved: $backupPath"
}

Write-Step 'Writing updated script...'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($TargetPath, $updated, $utf8NoBom)

Write-Step 'Verifying the updated script still parses...'
if (Test-ValidPowerShell -Path $TargetPath) {
    Write-Ok 'Parse check passed.'
}
else {
    Write-Err2 'The updated script failed to parse.'
    if ($backupPath) {
        Copy-Item -LiteralPath $backupPath -Destination $TargetPath -Force
        Write-Warn2 'Restored the previous version from backup.'
    }
    else {
        Write-Warn2 'No backup was made (-NoBackup was used), target left in its broken state.'
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 1
}

Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ('  ' + ('-' * 60)) -ForegroundColor DarkGray
Write-Host '  Update complete' -ForegroundColor Green
if ($existingHash) { Write-Host "  Previous SHA256 : $existingHash" -ForegroundColor DarkGray }
Write-Host "  New SHA256      : $newHash" -ForegroundColor White
if ($tag) { Write-Host "  Release tag     : $tag" -ForegroundColor White }
Write-Host "  Target          : $TargetPath" -ForegroundColor White
if ($backupPath) { Write-Host "  Backup          : $backupPath" -ForegroundColor White }
Write-Host ''
