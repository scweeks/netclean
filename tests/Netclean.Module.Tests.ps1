Describe 'Netclean module - basic unit tests' {
    BeforeAll {
        # Import shared test helpers module
        Import-Module -Name (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force -ErrorAction Stop
        $modulePath = Join-Path $PSScriptRoot '..\Netclean.psm1'
        Import-Module -Name $modulePath -Force -ErrorAction Stop
    }

    It 'Convert-RegKeyPath normalizes registry provider paths' {
        $out = Convert-RegKeyPath -Path 'Microsoft.PowerShell.Core\Registry::HKLM:\Software\Foo'
        ($out -replace '\\\\','\\') | Should -Be 'HKLM\Software\Foo'
        (Convert-RegKeyPath -Path 'HKLM:\Software\Foo') | Should -Be 'HKLM\Software\Foo'
    }

    It 'Convert-Guid strips braces and lower-cases' {
        (Convert-Guid -Guid '{ABCDEF12-1234-5678-9ABC-DEF012345678}') | Should -Be 'abcdef12-1234-5678-9abc-def012345678'
    }

    It 'Aliases to Convert-Guid exist' {
        (Get-Command -Name Convert-NormalizeGuid -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Command -Name Normalize-Guid -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }

    It 'Get-AVServicePattern returns a collection for sample input' {
        $inventory = @(
            [pscustomobject]@{ Vendor = 'Windows Defender'; Services = @('WinDefService') },
            [pscustomobject]@{ Vendor = 'Bitdefender'; Services = @('vsserv') }
        )
        $patterns = Get-AVServicePattern -AvList @('Windows Defender','Bitdefender') -Inventory $inventory
        ($patterns -is [System.Collections.IEnumerable]) | Should -Be $true
    }
}
