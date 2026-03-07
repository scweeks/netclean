function Invoke-Safe {
    [CmdletBinding()]
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

Export-ModuleMember -Function Invoke-Safe
