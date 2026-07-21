param(
    [switch]$DryRun,
    [switch]$Force,
    [string]$BackupPath = "$env:ProgramData\NetClean\Backups",
    [string]$LogPath = "$env:ProgramData\NetClean\Logs"
)

$script = Join-Path $PSScriptRoot "..\netclean.ps1"
if (-not (Test-Path $script)) { Write-Error "netclean.ps1 not found at $script"; exit 1 }

$procArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script)
if ($DryRun) { $procArgs += '-DryRun' }
if ($Force) { $procArgs += '-Force' }
$procArgs += '-CreateLog','-BackupPath',$BackupPath,'-LogPath',$LogPath

Write-Output "Launching netclean with args: $($procArgs -join ' ')"
Start-Process -FilePath (Get-Command powershell).Source -ArgumentList $procArgs -NoNewWindow -Wait
Write-Output "netclean run completed. Check logs under $LogPath"
