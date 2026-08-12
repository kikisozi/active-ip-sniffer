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
    $Expected = $null
    $Bin = $null
    $Tmp = $null
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        $CacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $SumsUrl = "https://raw.githubusercontent.com/{0}/{1}/dist/SHA256SUMS?cb={2}" -f $Repo, $Branch, $CacheBust
        Invoke-WebRequest -UseBasicParsing $SumsUrl -OutFile $Sums
        $Expected = ((Get-Content $Sums | Where-Object { $_ -match [regex]::Escape($File) } | Select-Object -First 1) -split '\s+')[0]
        if (-not $Expected -or $Expected -notmatch '^[0-9a-fA-F]{64}$') {
            if ($Attempt -lt 3) { Start-Sleep -Seconds 2; continue }
            throw "无法获取用户探针 SHA256"
        }
        $Expected = $Expected.ToLowerInvariant()
        # Hash-specific filenames avoid Windows' running-EXE replacement lock
        # and remove the need to query the GitHub commits API.
        $Bin = Join-Path $Cache ("active-ip-user-probe-{0}.exe" -f $Expected.Substring(0,16))
        if (Test-Path $Bin) {
            $Cached = (Get-FileHash -Algorithm SHA256 $Bin).Hash.ToLowerInvariant()
            if ($Cached -eq $Expected) { break }
            Remove-Item -Force -ErrorAction SilentlyContinue $Bin
        }
        $Tmp = "$Bin.new.$PID"
        Write-Host "下载轻量用户探针 windows/$Arch..."
        $BinaryUrl = "https://raw.githubusercontent.com/{0}/{1}/{2}?cb={3}" -f $Repo, $Branch, $File, $CacheBust
        Invoke-WebRequest -UseBasicParsing $BinaryUrl -OutFile $Tmp
        $Actual = (Get-FileHash -Algorithm SHA256 $Tmp).Hash.ToLowerInvariant()
        if ($Actual -eq $Expected) {
            Move-Item -Force $Tmp $Bin
            $Tmp = $null
            break
        }
        Remove-Item -Force -ErrorAction SilentlyContinue $Tmp
        $Tmp = $null
        if ($Attempt -lt 3) { Start-Sleep -Seconds 2; continue }
        throw "用户探针 SHA256 校验失败"
    }
    if (-not $Bin -or -not (Test-Path $Bin)) { throw "用户探针下载失败" }
    Write-Host "用户探针已就绪。即将自动打开测速网页。"
    & $Bin --web-url $WebUrl
} finally {
    if ($Tmp) { Remove-Item -Force -ErrorAction SilentlyContinue $Tmp }
    Remove-Item -Force -ErrorAction SilentlyContinue $Sums
}
