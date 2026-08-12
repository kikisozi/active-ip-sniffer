param(
    [ValidateSet("on", "off", "status", "install", "disconnect")]
    [string]$Action = "status"
)
$ErrorActionPreference = "Stop"
$Port = 40099
$Proxy = "127.0.0.1:$Port"
$TraceUrl = "https://www.cloudflare.com/cdn-cgi/trace"
$Marker = "ActiveIPSniffer managed Local Proxy"
$MdmFile = Join-Path $env:ProgramData "Cloudflare\mdm.xml"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (Test-Admin) { return }
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $Action"
    $proc = Start-Process powershell.exe -Verb RunAs -ArgumentList $arg -Wait -PassThru
    exit $proc.ExitCode
}

function Find-WarpCli {
    $cmd = Get-Command warp-cli.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = @(
        (Join-Path $env:ProgramFiles "Cloudflare\Cloudflare WARP\warp-cli.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Cloudflare\Cloudflare WARP\warp-cli.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }
    if ($paths.Count -gt 0) { return $paths[0] }
    return $null
}

function Install-Warp {
    $cli = Find-WarpCli
    if ($cli) { return $cli }
    Ensure-Admin
    $tmp = Join-Path $env:TEMP ("cloudflare-warp-" + [guid]::NewGuid().ToString("N") + ".msi")
    try {
        Write-Host "Downloading Cloudflare One Client..."
        Invoke-WebRequest -UseBasicParsing -Uri "https://downloads.cloudflareclient.com/v1/download/windows/ga" -OutFile $tmp
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$tmp`" /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { throw "Cloudflare WARP MSI install failed: $($p.ExitCode)" }
    }
    finally { Remove-Item -Force -ErrorAction SilentlyContinue $tmp }
    Start-Sleep -Seconds 2
    $cli = Find-WarpCli
    if (-not $cli) { throw "cloudflare-warp installed but warp-cli.exe was not found" }
    return $cli
}

function Invoke-Warp([string]$Cli, [string[]]$Args) {
    & $Cli @Args
    return $LASTEXITCODE
}

function Ensure-Registration([string]$Cli) {
    & $Cli registration show *> $null
    if ($LASTEXITCODE -eq 0) { return }
    & $Cli --accept-tos registration new *> $null
    if ($LASTEXITCODE -ne 0) {
        & $Cli registration new *> $null
        if ($LASTEXITCODE -ne 0) { throw "WARP registration failed" }
    }
}

function Write-MdmFallback([string]$Cli) {
    Ensure-Admin
    if (Test-Path $MdmFile) {
        $existing = Get-Content -Raw $MdmFile
        if ($existing -notmatch [regex]::Escape($Marker)) {
            throw "Existing $MdmFile detected; refusing to overwrite Cloudflare policy. Configure service_mode=proxy and proxy_port=$Port manually."
        }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $MdmFile) | Out-Null
    @"
<!-- $Marker -->
<dict>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>$Port</integer>
</dict>
"@ | Set-Content -Encoding UTF8 -Path $MdmFile
    & $Cli mdm refresh *> $null
    if ($LASTEXITCODE -ne 0) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Cloudflare|warp' } | Select-Object -First 1
        if ($svc) { Restart-Service -Force $svc.Name -ErrorAction SilentlyContinue }
    }
}

function Configure-Proxy([string]$Cli) {
    & $Cli tunnel protocol set MASQUE *> $null
    & $Cli mode proxy *> $null
    $modeOk = ($LASTEXITCODE -eq 0)
    if ($modeOk) {
        & $Cli proxy port $Port *> $null
        if ($LASTEXITCODE -eq 0) { return }
        & $Cli proxy port set $Port *> $null
        if ($LASTEXITCODE -eq 0) { return }
    }
    Write-MdmFallback $Cli
}

function Get-ProxyTrace {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { return $null }
    $text = & $curl.Source -fsS --max-time 8 --socks5-hostname $Proxy $TraceUrl 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($text -join "`n")
}

function Test-Proxy {
    $trace = Get-ProxyTrace
    return ($trace -match '(?m)^warp=(on|plus)$')
}

function Show-Status {
    $cli = Find-WarpCli
    if ($cli) {
        & $cli status 2>$null
        & $cli settings 2>$null | Select-String -Pattern 'mode|proxy|protocol'
    } else { Write-Host "WARP client: not installed" }
    $trace = Get-ProxyTrace
    if ($trace -and $trace -match '(?m)^warp=(on|plus)$') {
        Write-Host "WARP Local Proxy: READY $Proxy"
        $trace -split "`n" | Where-Object { $_ -match '^(ip|warp|colo)=' }
        return $true
    }
    Write-Host "WARP Local Proxy: unavailable $Proxy; Active IP Sniffer Auto will use Direct"
    return $false
}

switch ($Action) {
    { $_ -in @("on", "install") } {
        Ensure-Admin
        $cli = Install-Warp
        Ensure-Registration $cli
        Configure-Proxy $cli
        & $cli connect *> $null
        if ($LASTEXITCODE -ne 0) { throw "warp-cli connect failed" }
        for ($i=0; $i -lt 15; $i++) {
            if (Test-Proxy) { [void](Show-Status); exit 0 }
            Start-Sleep -Seconds 1
        }
        throw "$Proxy did not pass warp=on/plus verification; Active IP Sniffer Auto will use Direct"
    }
    { $_ -in @("off", "disconnect") } {
        Ensure-Admin
        $cli = Find-WarpCli
        if ($cli) { & $cli disconnect *> $null }
        Write-Host "WARP disconnected; Active IP Sniffer Auto will use Direct"
    }
    "status" { if (Show-Status) { exit 0 } else { exit 1 } }
}
