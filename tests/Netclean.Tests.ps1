Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop

# Helper to run potentially blocking calls in a job with a timeout to avoid infinite loops/hangs.
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

Describe 'Netclean module helpers' {
    Context 'Convert-RegKeyPath' {
        It 'removes provider prefix and normalizes HKLM' {
            $input = 'Microsoft.PowerShell.Core\Registry::HKLM:\SOFTWARE\\MyKey\\'
            $out = Convert-RegKeyPath -Path $input
            $out.TrimEnd('\') | Should Be 'HKLM\\SOFTWARE\\MyKey'
        }
        
    }

    Context 'Convert-NormalizeGuid' {
        It 'removes braces and lowercases' {
            (Convert-NormalizeGuid -Guid '{ABCDEF-1234}') | Should Be 'abcdef-1234'
        }
        
    }

    Context 'Derive-AVServicePatterns' {
        It 'matches known vendors' {
            $list = @('Bitdefender Endpoint Security')
            $patterns = Derive-AVServicePatterns -AvList $list
            ($patterns -match 'vsserv') | Should Be $true
        }
    }

    Context 'Get-InstalledAV' {
        It 'returns an array (may be empty) and does not hang' {
            $modulePath = (Join-Path $PSScriptRoot '..\\Netclean.psm1')
            $result = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Get-InstalledAV
            } -ArgumentList @($modulePath) -TimeoutSec 5

            # Ensure result is safe and is an array (or can be treated as one)
            ($result -is [array]) | Should Be $true
        }
    }

    Context 'Build-ProtectionLists' {
        It 'returns hashtable with expected keys and completes quickly' {
            $modulePath = (Join-Path $PSScriptRoot '..\\Netclean.psm1')
            $res = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Build-ProtectionLists
            } -ArgumentList @($modulePath) -TimeoutSec 10

            # Validate result type and expected keys
            ($res -is [hashtable]) | Should Be $true
            ($res.ContainsKey('Services')) | Should Be $true
            ($res.ContainsKey('Adapters')) | Should Be $true
        }
    }

    Context 'Approved-verb wrappers' {
        It 'Get-ProtectionList behaves like Build-ProtectionLists' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $res = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Get-ProtectionList
            } -ArgumentList @($modulePath) -TimeoutSec 8
            ($res -is [hashtable]) | Should Be $true
        }

        It 'Get-AVServicePattern behaves like Derive-AVServicePatterns' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $patterns = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Get-AVServicePattern -AvList @('Bitdefender Endpoint Security')
            } -ArgumentList @($modulePath) -TimeoutSec 5
            ($patterns -match 'vsserv') | Should Be $true
        }

        It 'Export-ProtectedRegistryKey supports DryRun and returns array' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $out = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Export-ProtectedRegistryKey -Paths @('HKLM:\SOFTWARE\MyKey') -Dest (Join-Path $env:TEMP 'netclean_test') -DryRun
            } -ArgumentList @($modulePath) -TimeoutSec 5
            # Accept native arrays or ArrayList (job deserialization may produce ArrayList)
            ( ($out -is [array]) -or ($out -is [System.Collections.ArrayList]) ) | Should Be $true
        }
    }
}
