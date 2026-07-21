$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean safety regression tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            Mock Write-NetCleanLog {}
        }

        Context 'protected registry path boundaries' {

            It 'protects the exact configured path and its descendants' {
                $context = [pscustomobject]@{
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\Contoso')
                }

                Test-RegistryPathProtected -Path 'HKLM\SOFTWARE\Contoso' -Context $context |
                    Should -BeTrue
                Test-RegistryPathProtected -Path 'HKLM\SOFTWARE\Contoso\Agent' -Context $context |
                    Should -BeTrue
            }

            It 'protects a parent removal when it contains a protected descendant' {
                $context = [pscustomobject]@{
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\Contoso\Agent')
                }

                Test-RegistryPathProtected -Path 'HKLM\SOFTWARE\Contoso' -Context $context |
                    Should -BeTrue
            }

            It 'does not treat a sibling with the same text prefix as protected' {
                $context = [pscustomobject]@{
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\Contoso')
                }

                Test-RegistryPathProtected -Path 'HKLM\SOFTWARE\ContosoTools' -Context $context |
                    Should -BeFalse
            }
        }

        Context 'dry-run backup behavior' {

            BeforeEach {
                Mock New-DirectoryIfNotExist {}
                Mock Invoke-RegExport { $FilePath }
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        DryRun    = $true
                        Error     = $null
                    }
                }
                Mock Get-ProtectionRegistryMap { @() }
                Mock Get-SanitizableNetworkArtifact { @() }
            }

            It 'does not create directories for individual dry-run exports' {
                $null = Export-ProtectedRegistryKey -Paths @('HKLM\SOFTWARE\Contoso') -Dest 'C:\backup' -DryRun
                $null = Export-NetworkList -Dest 'C:\backup' -DryRun
                $null = Export-FirewallPolicy -Dest 'C:\backup' -DryRun
                $null = Export-ProtectionInventory -Dest 'C:\backup' -Inventory @() -DryRun
                $null = Export-ProtectionRegistryMap -Dest 'C:\backup' -Inventory @() -DryRun
                $null = Export-SanitizableNetworkArtifact -Dest 'C:\backup' -Inventory @() -DryRun
                $null = Export-NetCleanManifest -Dest 'C:\backup' -Manifest @{ BackupPath = 'C:\backup' } -DryRun

                Should -Invoke New-DirectoryIfNotExist -Times 0
            }

            It 'does not create the backup directory for a dry-run protect phase' {
                $context = [pscustomobject]@{
                    Phase                  = 'Detect'
                    Inventory              = @()
                    ProtectedRegistryPaths = @()
                }

                Mock Export-ProtectionInventory { 'C:\backup\ProtectionInventory.json' }
                Mock Export-ProtectionRegistryMap { 'C:\backup\ProtectionRegistryMap.json' }
                Mock Export-SanitizableNetworkArtifact { 'C:\backup\SanitizableNetworkArtifact.json' }
                Mock Export-NetworkList { 'C:\backup\NetworkList.reg' }
                Mock Export-WiFiProfile { @() }
                Mock Export-FirewallPolicy { 'C:\backup\FirewallPolicy.wfw' }
                Mock Export-NetCleanManifest { 'C:\backup\RestoreManifest.json' }

                $result = Invoke-NetCleanPhase2Protect -Context $context -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Protect'
                Should -Invoke New-DirectoryIfNotExist -Times 0
            }
        }
    }
}
