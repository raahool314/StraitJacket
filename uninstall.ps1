#Requires -RunAsAdministrator
<#
    StraitJacket uninstaller. Stops and removes the service, strips the
    managed block from the hosts file, and deletes the install directory.

    Run from an elevated PowerShell:  .\uninstall.ps1
#>

$ErrorActionPreference = "Stop"
$ServiceName = "StraitJacket"
$InstallDir  = Join-Path ${env:ProgramFiles} "StraitJacket"
$HostsPath   = Join-Path $env:WinDir "System32\drivers\etc\hosts"
$BeginMarker = "# >>> StraitJacket BEGIN (managed - do not edit) >>>"
$EndMarker   = "# <<< StraitJacket END <<<"

Write-Host "==> Uninstalling $ServiceName" -ForegroundColor Cyan

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Write-Host "    Service removed."
} else {
    Write-Host "    Service not installed."
}

# --- strip the managed block from hosts ------------------------------------
if (Test-Path $HostsPath) {
    $text = Get-Content -Raw -Path $HostsPath
    $begin = $text.IndexOf($BeginMarker)
    if ($begin -ge 0) {
        $end = $text.IndexOf($EndMarker, $begin)
        $before = $text.Substring(0, $begin).TrimEnd()
        $after  = if ($end -ge 0) { $text.Substring($end + $EndMarker.Length) } else { "" }
        $clean  = ($before + $after).TrimEnd() + "`r`n"
        Set-Content -Path $HostsPath -Value $clean -Encoding ASCII -NoNewline
        Write-Host "    Hosts file cleaned."
    }
}

# --- restore DNS (sinkhole pinned it to 127.0.0.1) -------------------------
try {
    Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } |
        Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction SilentlyContinue
    Write-Host "    System DNS reset to automatic."
} catch { Write-Host "    (DNS reset skipped: $($_.Exception.Message))" }

# --- remove firewall rules -------------------------------------------------
netsh advfirewall firewall delete rule name="StraitJacket-Block" | Out-Null
Write-Host "    Firewall rules removed."

ipconfig /flushdns | Out-Null

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "    Install directory removed."
}

Write-Host ""
Write-Host "Done. $ServiceName has been removed." -ForegroundColor Green
