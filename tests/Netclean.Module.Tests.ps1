Describe 'Netclean module - basic unit tests' {
    BeforeAll {
        # Import shared test helpers module
        Import-Module -Name (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force -ErrorAction Stop
        $modulePath = Join-Path $PSScriptRoot '..\Netclean.psm1'
        Import-Module -Name $modulePath -Force -ErrorAction Stop
    }

    It 'Convert-RegKeyPath normalizes registry provider paths' {
        $out = Convert-RegKeyPath 'Microsoft.PowerShell.Core\Registry::HKLM:\Software\Foo\'
        ($out -replace '\\\\','\\') | Should -Be 'HKLM\Software\Foo'
        (Convert-RegKeyPath 'HKLM:\Software\Foo') | Should -Be 'HKLM\Software\Foo'
        (Convert-RegKeyPath $null) | Should -BeNullOrEmpty
    }

    It 'Convert-Guid strips braces and lower-cases' {
        (Convert-Guid '{ABCDEF-1234-5678-9ABC-DEF012345678}') | Should -Be 'abcdef-1234-5678-9abc-def012345678'
        { Convert-Guid $null } | Should -Throw
    }

    It 'Aliases to Convert-Guid exist' {
        (Get-Command -Name Convert-NormalizeGuid -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Command -Name Normalize-Guid -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }

    It 'Get-AVServicePattern returns a collection for sample input' {
        $patterns = Get-AVServicePattern -AvList @('Windows Defender','Bitdefender')
        ($patterns -is [System.Collections.IEnumerable]) | Should -Be $true
    }
}
