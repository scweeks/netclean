@{
    RootModule = 'Modules\NetClean.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e6a9b5c4-0000-4000-8000-000000000001'
    Author            = 'Sean Weeks'
    CompanyName       = 'Open Source'
    Copyright = '(c) Sean Weeks. All rights reserved.'
    Description = 'Phase-oriented PowerShell toolkit for detecting, protecting, cleaning, and verifying network privacy artifacts.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-NetCleanPhase1Detect',
        'Invoke-NetCleanPhase2Protect',
        'Invoke-NetCleanPhase3Clean',
        'Invoke-NetCleanPhase4Verify',
        'Invoke-NetCleanWorkflow',
        'Get-NetCleanLogFile',
        'Start-NetCleanLog',
        'Write-NetCleanLog',
        'Read-NetCleanPerformanceProfileSelection'
    )

    AliasesToExport = @(
        'Backup-NetworkList',
        'Backup-ProtectedRegistryKeys',
        'Backup-WiFiProfiles'
    )

    PrivateData = @{
        PSData = @{
            ProjectUri = 'https://github.com/scweeks/netclean'
            LicenseUri = 'https://github.com/scweeks/netclean/blob/main/LICENSE'
            Tags = @('PowerShell', 'Networking', 'Privacy', 'Diagnostics', 'Windows')
        }
    }
}
