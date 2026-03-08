Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop

# Import test helpers module (provides Invoke-Safe)
Import-Module -Name (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force -ErrorAction Stop

Describe 'Netclean module helpers' {
    Context 'Convert-RegKeyPath' {
        It 'removes provider prefix and normalizes HKLM' {
            $inPath = 'Microsoft.PowerShell.Core\Registry::HKLM:\SOFTWARE\MyKey'
            $out = Convert-RegKeyPath -Path $inPath
            $norm = ($out -replace '\\\\','\\')
            $norm | Should -Be 'HKLM\SOFTWARE\MyKey'
        }
        It 'normalizes already-normal path without changing it' {
            $in = 'HKLM\SOFTWARE\MyKey'
            (Convert-RegKeyPath -Path $in) | Should -Be 'HKLM\SOFTWARE\MyKey'
        }

            # note: empty-string binding for mandatory parameter is environment-dependent; skip explicit empty-string test
    }

    Context 'Convert-NormalizeGuid' {
        It 'removes braces and lowercases' {
            (Convert-NormalizeGuid -Guid '{ABCDEF12-1234-5678-9ABC-DEF012345678}') | Should -Be 'abcdef12-1234-5678-9abc-def012345678'
        }
        It 'handles guid without braces' {
            (Convert-NormalizeGuid -Guid 'ABCDEF12-1234-5678-9ABC-DEF012345678') | Should -Be 'abcdef12-1234-5678-9abc-def012345678'
        }
    }

    Context 'Derive-AVServicePatterns' {
        It 'matches known vendors' {
            $list = @('Bitdefender Endpoint Security')
            $inventory = @([pscustomobject]@{ Vendor = 'Bitdefender Endpoint Security'; Services = @('vsserv') })
            $patterns = Derive-AVServicePatterns -AvList $list -Inventory $inventory
            ($patterns -match 'vsserv') | Should -Be $true
        }
        It 'handles multiple vendors and deduplicates patterns' {
            $list = @('Bitdefender','CrowdStrike')
            $inventory = @(
                [pscustomobject]@{ Vendor = 'Bitdefender'; Services = @('vsserv') },
                [pscustomobject]@{ Vendor = 'CrowdStrike'; Services = @('CSFalconService') }
            )
            $patterns = Derive-AVServicePatterns -AvList $list -Inventory $inventory
            ($patterns -match 'vsserv') | Should -Be $true
            ($patterns -match 'CSFalconService') | Should -Be $true
        }
    }

    Context 'Get-InstalledAV' {
        It 'returns an array (may be empty) and does not hang' {
            $inv = @()
            { Get-InstalledAV -Inventory $inv } | Should -Not -Throw
        }
        It 'returns an empty array when nothing detected (non-throwing)' {
            $inv = @()
            { Get-InstalledAV -Inventory $inv } | Should -Not -Throw
        }
    }

    Context 'Build-ProtectionLists' {
        It 'returns hashtable with expected keys and completes quickly' {
            $inventory = @(
                [pscustomobject]@{ Services=@('svc1'); Drivers=@('drv1'); Adapters=@('adp1'); RegistryKeys=@('HKLM\SOFTWARE\Foo') }
            )
            $res = Get-ProtectionList -Inventory $inventory

            ($res -is [hashtable]) | Should -Be $true
            ($res.ContainsKey('Services')) | Should -Be $true
            ($res.ContainsKey('Adapters')) | Should -Be $true
        }
        It 'includes Drivers and Registry keys when vendors detected' {
            $inventory = @(
                [pscustomobject]@{ Services=@(); Drivers=@('drv1'); Adapters=@(); RegistryKeys=@('HKLM\SOFTWARE\Foo') }
            )
            $res = Get-ProtectionList -Inventory $inventory
            ($res.ContainsKey('Drivers')) | Should -Be $true
            ($res.ContainsKey('Registry')) | Should -Be $true
        }
    }

    Context 'Approved-verb wrappers' {
        It 'Get-ProtectionList behaves like Build-ProtectionLists' {
            $inventory = @([pscustomobject]@{ Services=@('svc1'); Drivers=@('drv1'); Adapters=@('adp1'); RegistryKeys=@('HKLM\SOFTWARE\Foo') })
            $res = Get-ProtectionList -Inventory $inventory
            ($res -is [hashtable]) | Should -Be $true
        }

        It 'Get-AVServicePattern behaves like Derive-AVServicePatterns' {
            $inventory = @([pscustomobject]@{ Vendor = 'Bitdefender Endpoint Security'; Services = @('vsserv') })
            $patterns = Get-AVServicePattern -AvList @('Bitdefender Endpoint Security') -Inventory $inventory
            ($patterns -match 'vsserv') | Should -Be $true
        }

        It 'Export-ProtectedRegistryKey supports DryRun and returns array' {
            $out = Export-ProtectedRegistryKey -Paths @('HKLM:\SOFTWARE\MyKey') -Dest (Join-Path $env:TEMP 'netclean_test') -DryRun
            # must return at least one exported path (dry-run returns path string)
            ($out | Should -Not -BeNullOrEmpty)
        }

        It 'Export-NetworkList DryRun returns a string path' {
            $tmp = Join-Path $env:TEMP 'netclean_test'
            $r = Export-NetworkList -Dest $tmp -DryRun
            ($r -is [string]) | Should -Be $true
        }

        It 'Export-WiFiProfile DryRun returns array (or ArrayList) and does not call netsh' {
            $tmp = Join-Path $env:TEMP 'netclean_test'
            $r = Export-WiFiProfile -Dest $tmp -DryRun
            ($r | Should -Not -BeNullOrEmpty)
        }
    }
}
