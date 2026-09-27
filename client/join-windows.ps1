# =============================================================================
#  mc-p2p-lan / Windows client one-click join
#  (This file is intentionally kept pure ASCII: Windows PowerShell 5.1 reads
#   BOM-less UTF-8 as ANSI/GBK and would corrupt non-ASCII strings.)
#
#  Usage 1 (recommended, for AI tools) - run in an ADMIN PowerShell:
#     iex (irm https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-windows.ps1)
#     Join-Lan -Name "<network>" -Secret "<secret>" -Peer "tcp://1.2.3.4:11020"
#
#  Usage 2 (run the file directly):
#     powershell -ExecutionPolicy Bypass -File join-windows.ps1 -Name x -Secret y -Peer tcp://1.2.3.4:11020
#
#  Stop:  Join-Lan -Stop
#  Remove: Join-Lan -Uninstall
#  Requires: Administrator (EasyTier needs to create a virtual NIC)
# =============================================================================
param(
    [string]$Name,
    [string]$Secret,
    [string]$Peer,
    [string]$Ip = "",
    [string]$Version = "2.6.4",
    [switch]$Stop,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Base = "$env:LOCALAPPDATA\mc-p2p-lan"
$Bin  = "$Base\bin"

function Write-Log { param($m) Write-Host "[..] $m" -ForegroundColor Cyan }
function Write-Ok  { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn{ param($m) Write-Host "[!!] $m" -ForegroundColor Yellow }
function Write-Err { param($m) Write-Host "[XX] $m" -ForegroundColor Red }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FreePort {
    param([int[]]$Candidates = @(11010, 11011, 11012, 21010, 21011, 21012))
    foreach ($p in $Candidates) {
        $tcp = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
        $udp = Get-NetUDPEndpoint  -LocalPort $p -ErrorAction SilentlyContinue
        if (-not $tcp -and -not $udp) { return $p }
    }
    return 0
}

function Get-GhFile {
    param([string]$Url, [string]$Out)
    $mirrors = @('', 'https://ghfast.top/', 'https://gh-proxy.com/', 'https://gh.llkk.cc/')
    foreach ($m in $mirrors) {
        $u = "$m$Url"
        try {
            if ($m -ne '') { Write-Log "trying mirror: $m" }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $u -OutFile $Out -TimeoutSec 300 -UseBasicParsing
            if ((Get-Item $Out).Length -gt 0) {
                Write-Ok "download done"
                return $true
            }
        } catch {
            # try next mirror
        }
        if (Test-Path $Out) { Remove-Item $Out -Force -ErrorAction SilentlyContinue }
    }
    return $false
}

function Join-Lan {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Secret,
        [Parameter(Mandatory=$true)][string]$Peer,
        [string]$Ip = "",
        [string]$Version = "2.6.4"
    )

    if (-not (Test-Admin)) {
        Write-Err "Administrator rights required. Reopen PowerShell with 'Run as administrator'."
        return
    }

    Write-Host ""
    Write-Host "=== 1/3 prepare ===" -ForegroundColor White
    New-Item -ItemType Directory -Force -Path $Bin | Out-Null

    # The zip extracts into a subfolder (easytier-windows-x86_64/),
    # so always search recursively instead of assuming $bin\easytier-core.exe
    $exe = (Get-ChildItem -Path $Bin -Filter 'easytier-core.exe' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1).FullName

    if (-not $exe) {
        Write-Log "downloading EasyTier v$Version ..."
        $zip = Join-Path $env:TEMP "et.zip"
        $url = "https://github.com/EasyTier/EasyTier/releases/download/v$Version/easytier-windows-x86_64-v$Version.zip"
        if (-not (Get-GhFile -Url $url -Out $zip)) {
            Write-Err "download failed: $url"
            return
        }
        Expand-Archive -Path $zip -DestinationPath $Bin -Force
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Write-Ok "extracted to $Bin"

        $exe = (Get-ChildItem -Path $Bin -Filter 'easytier-core.exe' -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1).FullName
        if (-not $exe) {
            Write-Err "easytier-core.exe not found after extraction"
            return
        }
    } else {
        Write-Ok "EasyTier already installed, skip download"
    }
    Write-Log "binary: $exe"

    Write-Host ""
    Write-Host "=== 2/3 join virtual LAN ===" -ForegroundColor White
    $etArgs = @('--network-name', $Name, '--network-secret', $Secret, '-e', $Peer)
    if ($Ip -ne '') { $etArgs += @('-i', $Ip) }

    # EasyTier defaults to 11010, which collides with an already-running
    # EasyTier GUI (os error 10048) and the instance exits immediately.
    # Pick a free port so P2P hole punching still works.
    $lport = Get-FreePort
    if ($lport -gt 0) {
        $etArgs += @('-l', "$lport")
        Write-Log "listen port: $lport"
    } else {
        $etArgs += @('--no-listener')
        Write-Warn "no free port found, using --no-listener (may fall back to relay)"
    }

    $existing = Get-Process -Name 'easytier-core' -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "already running, restarting"
        $existing | Stop-Process -Force
        Start-Sleep -Seconds 2
    }

    $log = Join-Path $Base 'easytier.log'
    $p = Start-Process -FilePath $exe -ArgumentList $etArgs -WindowStyle Hidden `
         -RedirectStandardOutput "$log.out" -RedirectStandardError "$log.err" -PassThru
    Write-Ok "started (PID $($p.Id))"

    Write-Host ""
    Write-Host "=== 3/3 waiting for virtual IP ===" -ForegroundColor White
    $vip = $null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 1
        $vip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.InterfaceAlias -match 'tun|easytier|et_|wintun' } |
               Select-Object -ExpandProperty IPAddress -First 1
        if ($vip) { break }
    }

    Write-Host ""
    if ($vip) {
        Write-Host "============ JOINED OK ============" -ForegroundColor Green
        Write-Host "Your virtual IP : $vip"
        Write-Host "Give this IP to your friends, or connect to it directly in game."
        Write-Host "===================================" -ForegroundColor Green
    } else {
        Write-Warn "virtual IP not detected yet. Check manually:"
        Write-Host "  ipconfig | findstr /i tun"
        Write-Host "  log: $log.err"
    }
    Write-Host ""
    Write-Host "EasyTier keeps running after you close this window."
    Write-Host "To stop it:  Join-Lan -Stop"
}

function Stop-Lan {
    $proc = Get-Process -Name 'easytier-core' -ErrorAction SilentlyContinue
    if ($proc) {
        $proc | Stop-Process -Force
        Write-Ok "EasyTier stopped"
    } else {
        Write-Warn "EasyTier is not running"
    }
}

if ($Stop) {
    Stop-Lan
    return
}
if ($Uninstall) {
    Stop-Lan
    Remove-Item $Base -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "uninstalled"
    return
}

# When executed directly with full args -> run immediately.
# When dot-sourced / loaded via iex -> only define functions, wait for Join-Lan.
if ($Name -and $Secret -and $Peer) {
    Join-Lan -Name $Name -Secret $Secret -Peer $Peer -Ip $Ip -Version $Version
} else {
    Write-Host "mc-p2p-lan client loaded. To join a network run:" -ForegroundColor Yellow
    Write-Host '  Join-Lan -Name "<network>" -Secret "<secret>" -Peer "tcp://SERVER_IP:11020"' -ForegroundColor White
}
