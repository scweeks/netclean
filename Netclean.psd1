@{
    RootModule = 'modules\NetClean.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'e6a9b5c4-0000-4000-8000-000000000001'
    Author = 'NetworkCleaner'
    CompanyName = 'NetworkCleaner'
    Copyright = '(c) NetworkCleaner'
    Description = 'Core helpers for NetworkCleaner - testable functions'
    FunctionsToExport = @('Convert-RegKeyPath','Convert-NormalizeGuid','Get-InstalledAV','Derive-AVServicePatterns','Build-ProtectionLists')
    PrivateData = @{
        PSData = @{
            Tags = @('network','cleanup','test')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/example/NetworkCleaner'
        }
    }
}
