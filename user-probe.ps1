$ErrorActionPreference = "Stop"

$WebUrl = "__AIS_USER_WEB_URL__"
$Repo = "kikisozi/active-ip-sniffer"
$Branch = "main"
$Arch = if ([Environment]::Is64BitOperatingSystem -and $env:PROCESSOR_ARCHITECTURE -match "ARM64") { "arm64" } else { "amd64" }
$File = "dist/active-ip-user-probe-windows-$Arch.exe"
$Cache = Join-Path $env:LOCALAPPDATA "ActiveIPUserProbe"
$Sums = Join-Path $Cache "SHA256SUMS.$PID"
New-Item -ItemType Directory -Force -Path $Cache | Out-Null

try {
    $Ref = (Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/commits/$Branch?cb=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())").sha
    if (-not $Ref -or $Ref.Length -ne 40) { throw "无法获取 GitHub 当前版本" }
    # A commit-specific filename avoids Windows' running-EXE replacement lock
    # when a user starts a new probe before closing an older probe window.
    $Bin = Join-Path $Cache "active-ip-user-probe-$Ref.exe"
    $Tmp = "$Bin.new.$PID"
    Write-Host "下载轻量用户探针 windows/$Arch..."
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$Repo/$Ref/$File?cb=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" -OutFile $Tmp
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$Repo/$Ref/dist/SHA256SUMS?cb=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" -OutFile $Sums
    $Expected = ((Get-Content $Sums | Where-Object { $_ -match [regex]::Escape($File) } | Select-Object -First 1) -split '\s+')[0]
    $Actual = (Get-FileHash -Algorithm SHA256 $Tmp).Hash.ToLowerInvariant()
    if (-not $Expected -or $Expected.ToLowerInvariant() -ne $Actual) { throw "用户探针 SHA256 校验失败" }
    Move-Item -Force $Tmp $Bin
    Write-Host "用户探针已就绪。即将自动打开测速网页。"
    & $Bin --web-url $WebUrl
} finally {
    if ($Tmp) { Remove-Item -Force -ErrorAction SilentlyContinue $Tmp }
    Remove-Item -Force -ErrorAction SilentlyContinue $Sums
}
