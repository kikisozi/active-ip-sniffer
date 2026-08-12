$ErrorActionPreference = "Stop"

$Repo = "kikisozi/active-ip-sniffer"
$Branch = "main"
$AppDir = Join-Path $env:LOCALAPPDATA "ActiveIPSniffer"
$Exe = Join-Path $AppDir "active-ip-sniffer.exe"
$WarpHelper = Join-Path $AppDir "warp-helper.ps1"
$VCmd = Join-Path $AppDir "v.cmd"

$archName = $env:PROCESSOR_ARCHITECTURE
switch ($archName.ToUpperInvariant()) {
    "AMD64" { $Arch = "amd64" }
    "ARM64" { $Arch = "arm64" }
    default { throw "Unsupported Windows architecture: $archName" }
}

$headers = @{ "User-Agent" = "Active-IP-Sniffer-Installer" }
$cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$commit = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Repo/commits/$Branch`?cb=$cacheBust"
$ref = [string]$commit.sha
if ($ref -notmatch '^[0-9a-f]{40}$') {
    throw "Cannot resolve current GitHub commit for $Repo`:$Branch"
}

New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
$binaryName = "dist/active-ip-sniffer-windows-$Arch.exe"
$binaryUrl = "https://raw.githubusercontent.com/$Repo/$ref/$binaryName`?cb=$cacheBust"
$sumsUrl = "https://raw.githubusercontent.com/$Repo/$ref/dist/SHA256SUMS`?cb=$cacheBust"
$warpHelperName = "warp-helper.ps1"
$warpHelperUrl = "https://raw.githubusercontent.com/$Repo/$ref/$warpHelperName`?cb=$cacheBust"
$tmpBinary = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".exe")
$tmpWarpHelper = Join-Path $env:TEMP ("active-ip-sniffer-warp-" + [guid]::NewGuid().ToString("N") + ".ps1")
$tmpSums = Join-Path $env:TEMP ("active-ip-sniffer-" + [guid]::NewGuid().ToString("N") + ".sha256")

try {
    Write-Host "Downloading Go binary ($Arch)..."
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $binaryUrl -OutFile $tmpBinary
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $warpHelperUrl -OutFile $tmpWarpHelper
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $sumsUrl -OutFile $tmpSums

    $expected = $null
    foreach ($line in Get-Content $tmpSums) {
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$' -and $Matches[2] -eq $binaryName) {
            $expected = $Matches[1].ToLowerInvariant()
            break
        }
    }
    if (-not $expected) { throw "Checksum for $binaryName not found" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmpBinary).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Binary SHA256 mismatch" }
    $expectedWarp = $null
    foreach ($line in Get-Content $tmpSums) {
        if ($line -match '^([0-9a-fA-F]{64})\s+(.+)$' -and $Matches[2] -eq $warpHelperName) { $expectedWarp = $Matches[1].ToLowerInvariant(); break }
    }
    if (-not $expectedWarp) { throw "Checksum for $warpHelperName not found" }
    $actualWarp = (Get-FileHash -Algorithm SHA256 -Path $tmpWarpHelper).Hash.ToLowerInvariant()
    if ($actualWarp -ne $expectedWarp) { throw "WARP helper SHA256 mismatch" }

    Copy-Item -Force $tmpBinary $Exe
    Copy-Item -Force $tmpWarpHelper $WarpHelper
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpBinary, $tmpWarpHelper, $tmpSums
}

@"
@echo off
if /I "%~1"=="probe" (
  "%~dp0active-ip-sniffer.exe" %*
) else if /I "%~1"=="warp" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0warp-helper.ps1" "%~2"
) else (
  "%~dp0active-ip-sniffer.exe" setup %*
)
"@ | Set-Content -Encoding ASCII -Path $VCmd

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$parts = @()
if ($userPath) { $parts = $userPath.Split(';') | Where-Object { $_ } }
if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $AppDir.TrimEnd('\') })) {
    $newPath = if ($userPath) { "$AppDir;$userPath" } else { $AppDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}
if (-not (($env:Path.Split(';')) | Where-Object { $_.TrimEnd('\') -ieq $AppDir.TrimEnd('\') })) {
    $env:Path = "$AppDir;$env:Path"
}

Write-Host ""
Write-Host "Active IP Sniffer installed: $Exe"
Write-Host "From now on, enter v in PowerShell or CMD to open the configuration UI."
Write-Host "Run v probe to start the localhost probe used by the remote WebUI."
Write-Host "Optional WARP Local Proxy: v warp on (127.0.0.1:40099), v warp status, v warp off."
Write-Host "Windows uses one-time foreground mode; closing it stops the service."
Write-Host ""

if ($env:AIS_INSTALL_WARP -eq "1") {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $WarpHelper on
}

& $Exe setup
