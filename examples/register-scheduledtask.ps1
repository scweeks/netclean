param(
    [string]$WrapperPath = "$PSScriptRoot\run-netclean.ps1",
    [string]$TaskName = 'NetClean-AutoRun',
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
    [string]$Mode,
    [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
    [string]$PerformanceProfile
)

if (-not (Test-Path $WrapperPath)) { Write-Error "Wrapper not found at $WrapperPath"; exit 1 }

# NetClean requires PowerShell 7.4+ (pwsh); Windows PowerShell 5.1 cannot load
# the module manifest.
$pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwshCommand) {
    Write-Error 'Could not find pwsh.exe (PowerShell 7.4+) on this system. Install PowerShell 7.4 or later before registering this scheduled task.'
    exit 1
}

# -Force is required here: a SYSTEM/startup task has no console to answer the
# interactive "Proceed?" confirmation, so unattended execution must bypass it.
$wrapperArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$WrapperPath`" -Mode $Mode -Force -CreateLog"
if ($Mode -eq 'PerformanceTune' -and $PerformanceProfile) {
    $wrapperArgs += " -PerformanceProfile $PerformanceProfile"
}

$action = New-ScheduledTaskAction -Execute $pwshCommand.Source -Argument $wrapperArgs
$trigger = New-ScheduledTaskTrigger -AtStartup

# Register or update existing task
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Description "Run netclean wrapper at startup (Mode=$Mode)" -Force
    Write-Output "Scheduled task '$TaskName' registered to run $WrapperPath -Mode $Mode at startup."
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit 1
}
