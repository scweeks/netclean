function Invoke-Safe {
    param(
        [ScriptBlock]$ScriptBlock,
        [int]$TimeoutSec = 5,
        [object[]]$ArgumentList = @()
    )
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    try {
        if (Wait-Job -Job $job -Timeout $TimeoutSec) {
            Receive-Job -Job $job
        }
        else {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            throw "Operation timed out after ${TimeoutSec}s"
        }
    }
    finally {
        Remove-Job -Job $job -ErrorAction SilentlyContinue
    }
}

Import-Module .\Netclean.psm1 -Force -Verbose
$r = Invoke-Safe -ScriptBlock { param($m) Import-Module -Name $m -Force; Export-ProtectedRegistryKey -Paths @('HKLM:\SOFTWARE\MyKey') -Dest (Join-Path $env:TEMP 'netclean_test') -DryRun } -ArgumentList @(Join-Path $PSScriptRoot '..\Netclean.psm1') -TimeoutSec 5
Write-Output "TYPE: $($r -ne $null ? $r.GetType().FullName : '<null>')"
Write-Output "ISARRAY: $($r -is [array])"
Write-Output "COUNT: $($r.Count)"
if ($r -is [array]) { $r | ForEach-Object { Write-Output ("ITEM: $_") } } else { Write-Output ("VALUE: $r") }