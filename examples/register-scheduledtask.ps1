param(
    [string]$WrapperPath = "$PSScriptRoot\run-netclean.ps1",
    [string]$TaskName = 'NetClean-AutoRun'
)

if (-not (Test-Path $WrapperPath)) { Write-Error "Wrapper not found at $WrapperPath"; exit 1 }

$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$WrapperPath`" -CreateLog"
$trigger = New-ScheduledTaskTrigger -AtStartup

# Register or update existing task
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Description 'Run netclean wrapper at startup' -Force
    Write-Host "Scheduled task '$TaskName' registered to run $WrapperPath at startup." -ForegroundColor Green
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit 1
}
