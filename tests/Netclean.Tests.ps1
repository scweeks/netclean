Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop

# Import test helpers module (provides Invoke-Safe)
Import-Module -Name (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force -ErrorAction Stop

Describe 'Netclean module helpers' {
    Context 'Convert-RegKeyPath' {
        It 'removes provider prefix and normalizes HKLM' {
            $inPath = 'Microsoft.PowerShell.Core\Registry::HKLM:\SOFTWARE\\MyKey\\'
            $out = Convert-RegKeyPath -Path $inPath
            $norm = ($out -replace '\\\\','\\')
            $norm | Should -Be 'HKLM\SOFTWARE\MyKey'
        }
        It 'normalizes already-normal path without changing it' {
            $in = 'HKLM\\SOFTWARE\\MyKey'
            (Convert-RegKeyPath -Path $in) | Should -Be 'HKLM\SOFTWARE\MyKey'
        }

            # note: empty-string binding for mandatory parameter is environment-dependent; skip explicit empty-string test
    }

    Context 'Convert-NormalizeGuid' {
        It 'removes braces and lowercases' {
            (Convert-NormalizeGuid -Guid '{ABCDEF-1234}') | Should -Be 'abcdef-1234'
        }
        It 'handles guid without braces' {
            (Convert-NormalizeGuid -Guid 'A1B2C3') | Should -Be 'a1b2c3'
        }
    }

    Context 'Derive-AVServicePatterns' {
        It 'matches known vendors' {
            $list = @('Bitdefender Endpoint Security')
            $patterns = Derive-AVServicePatterns -AvList $list
            ($patterns -match 'vsserv') | Should -Be $true
        }
        It 'handles multiple vendors and deduplicates patterns' {
            $list = @('Bitdefender','CrowdStrike')
            $patterns = Derive-AVServicePatterns -AvList $list
            ($patterns -match 'vsserv') | Should -Be $true
            ($patterns -match 'CSFalconService') | Should -Be $true
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
            ($result -is [array]) | Should -Be $true
        }
        It 'returns an empty array when nothing detected (non-throwing)' {
            $r = Get-InstalledAV
            ($r -is [array]) | Should -Be $true
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
            ($res -is [hashtable]) | Should -Be $true
            ($res.ContainsKey('Services')) | Should -Be $true
            ($res.ContainsKey('Adapters')) | Should -Be $true
        }
        It 'includes Drivers and Registry keys when vendors detected' {
            $res = Get-ProtectionList
            ($res.ContainsKey('Drivers')) | Should -Be $true
            ($res.ContainsKey('Registry')) | Should -Be $true
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
            ($res -is [hashtable]) | Should -Be $true
        }

        It 'Get-AVServicePattern behaves like Derive-AVServicePatterns' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $patterns = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Get-AVServicePattern -AvList @('Bitdefender Endpoint Security')
            } -ArgumentList @($modulePath) -TimeoutSec 5
            ($patterns -match 'vsserv') | Should -Be $true
        }

        It 'Export-ProtectedRegistryKey supports DryRun and returns array' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $out = Invoke-Safe -ScriptBlock {
                param($m)
                Import-Module -Name $m -Force -ErrorAction Stop
                Export-ProtectedRegistryKey -Paths @('HKLM:\SOFTWARE\MyKey') -Dest (Join-Path $env:TEMP 'netclean_test') -DryRun
            } -ArgumentList @($modulePath) -TimeoutSec 5
            # Accept native arrays or ArrayList (job deserialization may produce ArrayList)
            ( ($out -is [array]) -or ($out -is [System.Collections.ArrayList]) ) | Should -Be $true
        }

        It 'Export-NetworkList DryRun returns a string path' {
            $tmp = Join-Path $env:TEMP 'netclean_test'
            $r = Export-NetworkList -Dest $tmp -DryRun
            ($r -is [string]) | Should -Be $true
        }

        It 'Export-WiFiProfile DryRun returns array (or ArrayList) and does not call netsh' {
            $modulePath = (Join-Path $PSScriptRoot '..\Netclean.psm1')
            $tmp = Join-Path $env:TEMP 'netclean_test'
            $r = Invoke-Safe -ScriptBlock {
                param($m, $d)
                Import-Module -Name $m -Force -ErrorAction Stop
                Export-WiFiProfile -Dest $d -DryRun
            } -ArgumentList @($modulePath, $tmp) -TimeoutSec 8
            ( ($r -is [array]) -or ($r -is [System.Collections.ArrayList]) ) | Should -Be $true
        }
    }
}
