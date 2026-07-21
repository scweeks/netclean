Describe 'NetClean module integration tests' {

    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $manifestPath = Join-Path $repoRoot 'NetClean.psd1'

        if (-not (Test-Path -LiteralPath $manifestPath)) {
            throw "NetClean.psd1 not found at path: $manifestPath"
        }

        Remove-Module NetClean -ErrorAction SilentlyContinue
        Import-Module $manifestPath -Force
    }

    It 'validates the module manifest' {
        { Test-ModuleManifest $manifestPath } | Should -Not -Throw
    }

    It 'imports the module manifest without throwing' {
        { Import-Module $manifestPath -Force } | Should -Not -Throw
    }

    It 'exports the expected primary phase functions' {
        $module = Get-Module 'NetClean'
        $module | Should -Not -BeNullOrEmpty

        $expected = @(
            'Invoke-NetCleanPhase1Detect',
            'Invoke-NetCleanPhase2Protect',
            'Invoke-NetCleanPhase3Clean',
            'Invoke-NetCleanPhase4Verify',
            'Invoke-NetCleanWorkflow',
            'Start-NetCleanLog',
            'Write-NetCleanLog'
        )

        foreach ($name in $expected) {
            $module.ExportedFunctions.Keys | Should -Contain $name
        }
    }

    It 'exports the expected aliases' {
        $module = Get-Module 'NetClean'
        $module | Should -Not -BeNullOrEmpty

        $module.ExportedAliases.Keys | Should -Contain 'Backup-NetworkList'
        $module.ExportedAliases.Keys | Should -Contain 'Backup-ProtectedRegistryKeys'
        $module.ExportedAliases.Keys | Should -Contain 'Backup-WiFiProfiles'
    }

    InModuleScope 'NetClean' {

        It 'can access internal helper functions within module scope' {
            { Get-Command Convert-RegKeyPath -ErrorAction Stop } | Should -Not -Throw
            { Get-Command Invoke-ExternalCommandSafe -ErrorAction Stop } | Should -Not -Throw
        }

        It 'can access phase implementation functions within module scope' {
            { Get-Command Invoke-NetCleanPhase1Detect -ErrorAction Stop } | Should -Not -Throw
            { Get-Command Invoke-NetCleanPhase2Protect -ErrorAction Stop } | Should -Not -Throw
            { Get-Command Invoke-NetCleanPhase3Clean -ErrorAction Stop } | Should -Not -Throw
            { Get-Command Invoke-NetCleanPhase4Verify -ErrorAction Stop } | Should -Not -Throw
        }
    }
}
