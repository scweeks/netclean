param(
    [switch]$DryRun,
    [switch]$Force,
    [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups",
    [string]$LogPath = "$env:ProgramData\NetworkCleaner\Logs"
)

$script = Join-Path $PSScriptRoot "..\netclean.ps1"
if (-not (Test-Path $script)) { Write-Error "netclean.ps1 not found at $script"; exit 1 }

$args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script)
if ($DryRun) { $args += '-DryRun' }
if ($Force) { $args += '-Force' }
$args += '-CreateLog','-BackupPath',$BackupPath,'-LogPath',$LogPath

Write-Host "Launching netclean with args: $($args -join ' ')" -ForegroundColor Cyan
Start-Process -FilePath (Get-Command powershell).Source -ArgumentList $args -NoNewWindow -Wait
Write-Host "netclean run completed. Check logs under $LogPath" -ForegroundColor Green
