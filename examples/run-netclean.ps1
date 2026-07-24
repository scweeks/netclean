param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
    [string]$Mode,
    [switch]$DryRun,
    [switch]$Force,
    [string]$BackupPath = "$env:ProgramData\NetClean\Backups",
    [string]$LogPath = "$env:ProgramData\NetClean\Logs",
    [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
    [string]$PerformanceProfile
)

$script = Join-Path $PSScriptRoot "..\netclean.ps1"
if (-not (Test-Path $script)) { Write-Error "netclean.ps1 not found at $script"; exit 1 }

# NetClean requires PowerShell 7.4+ (pwsh); Windows PowerShell 5.1 cannot load
# the module manifest.
$pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwshCommand) {
    Write-Error 'Could not find pwsh.exe (PowerShell 7.4+) on this system. Install PowerShell 7.4 or later before running this wrapper.'
    exit 1
}

$procArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Mode', $Mode)
if ($DryRun) { $procArgs += '-DryRun' }
if ($Force) { $procArgs += '-Force' }
if ($Mode -eq 'PerformanceTune' -and $PerformanceProfile) { $procArgs += '-PerformanceProfile', $PerformanceProfile }
$procArgs += '-CreateLog', '-BackupPath', $BackupPath, '-LogPath', $LogPath

Write-Output "Launching netclean with args: $($procArgs -join ' ')"
$proc = Start-Process -FilePath $pwshCommand.Source -ArgumentList $procArgs -NoNewWindow -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    Write-Error "netclean exited with code $($proc.ExitCode). Check logs under $LogPath"
    exit $proc.ExitCode
}

Write-Output "netclean run completed successfully. Check logs under $LogPath"
