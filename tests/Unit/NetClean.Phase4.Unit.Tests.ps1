$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean Phase 4 unit tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:preInventory = @(
                [pscustomobject]@{
                    Vendor                  = 'Contoso Security'
                    Services                = @('ContosoAgent')
                    ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                }
            )

            $script:postInventory = @(
                [pscustomobject]@{
                    Vendor                  = 'Contoso Security'
                    Services                = @('ContosoAgent')
                    ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                }
            )

            $script:context = [pscustomobject]@{
                Phase      = 'Clean'
                BackupPath = 'C:\backup'
                Inventory  = $script:preInventory
            }

            Mock Get-ProtectionInventory { $script:postInventory }
            Mock Write-NetCleanLog {}
            Mock Write-Information {}
        }

        Context 'Test-NetCleanPostState' {

            It 'passes when protected vendors, GUIDs, and services remain present' {
                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeTrue
                @($result.VendorComparison.Missing).Count | Should -Be 0
                @($result.GuidComparison.Missing).Count | Should -Be 0
                @($result.ServiceComparison.Missing).Count | Should -Be 0
            }

            It 'fails when a protected vendor is missing' {
                $script:postInventory = @()

                (Test-NetCleanPostState -Context $script:context).Passed | Should -BeFalse
            }

            It 'fails when a protected interface GUID is missing' {
                $script:postInventory[0].ProtectedInterfaceGuids = @()

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.GuidComparison.Missing) | Should -Contain 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            }

            It 'fails when a protected service is missing' {
                $script:postInventory[0].Services = @()

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.ServiceComparison.Missing) | Should -Contain 'ContosoAgent'
            }

            It 'does not fail only because new protected items were detected' {
                $script:postInventory += [pscustomobject]@{
                    Vendor                  = 'Fabrikam Security'
                    Services                = @('FabrikamAgent')
                    ProtectedInterfaceGuids = @('11111111-2222-3333-4444-555555555555')
                }

                (Test-NetCleanPostState -Context $script:context).Passed | Should -BeTrue
            }
        }

        Context 'Invoke-NetCleanPhase4Verify' {

            It 'preserves the incoming context and adds a passing verification summary' {
                $result = Invoke-NetCleanPhase4Verify -Context $script:context

                $result.Phase | Should -Be 'Verify'
                $result.BackupPath | Should -Be 'C:\backup'
                $result.Verify.Passed | Should -BeTrue
                $result.Verify.Summary.Passed | Should -BeTrue
                $result.Verify.Summary.MissingVendorsCount | Should -Be 0
                $result.Verify.Summary.MissingGuidCount | Should -Be 0
                $result.Verify.Summary.MissingServiceCount | Should -Be 0
            }

            It 'reports all missing protected categories in the summary' {
                $script:postInventory = @()

                $result = Invoke-NetCleanPhase4Verify -Context $script:context

                $result.Verify.Passed | Should -BeFalse
                $result.Verify.Summary.Passed | Should -BeFalse
                $result.Verify.Summary.MissingVendorsCount | Should -Be 1
                $result.Verify.Summary.MissingGuidCount | Should -Be 1
                $result.Verify.Summary.MissingServiceCount | Should -Be 1
            }
        }
    }
}
