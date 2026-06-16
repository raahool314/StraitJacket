#Requires -RunAsAdministrator
<#
    StraitJacket installer.

    Compiles the service with the in-box .NET Framework C# compiler (no SDK
    required), installs it under Program Files, configures it to start
    automatically and to restart on failure, and locks it down so that only
    administrators / SYSTEM can stop or reconfigure it.

    Run from an elevated PowerShell:  .\install.ps1
#>

$ErrorActionPreference = "Stop"
$ServiceName = "StraitJacket"
$Root        = $PSScriptRoot
$InstallDir  = Join-Path ${env:ProgramFiles} "StraitJacket"
$ExePath     = Join-Path $InstallDir "StraitJacket.exe"

Write-Host "==> Installing $ServiceName" -ForegroundColor Cyan

# --- locate the in-box C# compiler -----------------------------------------
$csc = Join-Path $env:WinDir "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:WinDir "Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path $csc)) {
    throw "Could not find csc.exe (.NET Framework 4.x). Cannot compile the service."
}

# --- stop any previous install ---------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    Stopping existing service..."
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# --- lay down files (Program Files is not writable by standard users) -------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $Root "blocklist.txt")  (Join-Path $InstallDir "blocklist.txt")  -Force
Copy-Item (Join-Path $Root "hostsonly.txt")  (Join-Path $InstallDir "hostsonly.txt")  -Force
Copy-Item (Join-Path $Root "feeds.txt")      (Join-Path $InstallDir "feeds.txt")      -Force
Copy-Item (Join-Path $Root "safesearch.txt") (Join-Path $InstallDir "safesearch.txt") -Force

Write-Host "    Compiling service..."
$sources = Get-ChildItem (Join-Path $Root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
& $csc /nologo /target:exe /out:"$ExePath" `
    /reference:System.ServiceProcess.dll `
    $sources
if ($LASTEXITCODE -ne 0) { throw "Compilation failed." }

# --- create the service ----------------------------------------------------
Write-Host "    Registering service (auto-start, LocalSystem)..."
sc.exe create $ServiceName binPath= "`"$ExePath`"" start= auto obj= "LocalSystem" `
    DisplayName= "StraitJacket Website Blocker" | Out-Null
sc.exe description $ServiceName "Blocks access to a configured list of websites. Managed; do not disable." | Out-Null

# --- restart-on-failure ----------------------------------------------------
# Reset the failure counter daily; restart after 5s on the 1st, 2nd and
# subsequent failures. failureflag=1 also triggers recovery on clean-but-
# nonzero exits, not just crashes.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

# --- lock down: only SYSTEM + Administrators may control the service --------
# Interactive (IU) and Service (SU) users get query/read only, NOT start/stop.
$sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
        "(A;;CCLCSWLOCRRC;;;IU)" +
        "(A;;CCLCSWLOCRRC;;;SU)"
sc.exe sdset $ServiceName $sddl | Out-Null

# --- start -----------------------------------------------------------------
Write-Host "    Starting service..."
sc.exe start $ServiceName | Out-Null

Write-Host ""
Write-Host "Done. $ServiceName is installed and running." -ForegroundColor Green
Write-Host "  Blocklist: $(Join-Path $InstallDir 'blocklist.txt')"
Write-Host "  Log:       $(Join-Path $InstallDir 'straitjacket.log')"
Write-Host "  To change blocks: edit the blocklist above (as admin), then run:"
Write-Host "      sc.exe stop $ServiceName ; sc.exe start $ServiceName"
