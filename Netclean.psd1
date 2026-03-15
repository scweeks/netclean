@{
    RootModule = 'Modules\NetClean.psm1'

    NestedModules = @(
        'Modules\NetCleanPhase1.psm1',
        'Modules\NetCleanPhase2.psm1',
        'Modules\NetCleanPhase3.psm1',
        'Modules\NetCleanPhase4.psm1'
    )
    ModuleVersion     = '1.0.0'
    GUID              = 'e6a9b5c4-0000-4000-8000-000000000001'
    Author            = 'Sean Weeks'
    CompanyName       = 'Open Source'
    Copyright         = '(c) Sean Weeks. All rights reserved.'
    Description       = 'Phase-oriented PowerShell toolkit for detecting, protecting, cleaning, and verifying network privacy artifacts.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Start-NetCleanLog',
        'Write-NetCleanLog',
        'Invoke-NetCleanPhase1Detect',
        'Invoke-NetCleanPhase2Protect',
        'Invoke-NetCleanPhase3Clean',
        'Invoke-NetCleanPhase4Verify',
        'Invoke-NetCleanWorkflow',
        'Invoke-AdvancedNetworkRepair',
        'Invoke-NetworkPerformanceTune',
        'Get-WiFiProfileNames',
        'Export-WiFiProfile',
        'Export-NetworkList',
        'Export-ProtectedRegistryKey',
        'Export-NetCleanManifest',
        'Clear-DnsCacheSafe',
        'Clear-ArpCacheSafe',
        'Clear-NetworkEventLogsSafe',
        'Clear-UserNetworkArtifactsSafe',
        'Remove-WiFiProfilesSafe',
        'Remove-RegistryPathSafe',
        'Remove-NetworkPrivacyArtifactsSafe',
        'Test-NetCleanPostState'
    )

    AliasesToExport   = @(
        'Backup-WiFiProfiles',
        'Backup-NetworkList',
        'Backup-ProtectedRegistryKeys'
    )

    PrivateData       = @{
        PSData = @{
            ProjectUri = 'https://github.com/scweeks/netclean'
            LicenseUri = 'https://github.com/scweeks/netclean/blob/ci/pester-v5-coverage/LICENSE'
            Tags       = @('PowerShell', 'Networking', 'Privacy', 'Diagnostics', 'Windows')
        }
    }
}