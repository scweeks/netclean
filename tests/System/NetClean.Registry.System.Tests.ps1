$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean isolated registry system-component tests' -Tag 'System', 'Registry' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null

            Remove-Item -LiteralPath 'TestRegistry:\Machine' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'TestRegistry:\User' -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -Path 'TestRegistry:\Machine' -Force | Out-Null
            New-Item -Path 'TestRegistry:\User' -Force | Out-Null

            $isolatedRoot = (Get-PSDrive -Name TestRegistry -ErrorAction Stop).Root
            Set-NetCleanRegistryRootMap -RootMap @{
                HKLM = "$isolatedRoot\Machine"
                HKCU = "$isolatedRoot\User"
            }

            $script:InterfaceGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            $script:ProfileGuid = '{11111111-2222-3333-4444-555555555555}'
            $script:ProtectedPath = 'HKLM\SOFTWARE\Contoso\SecurityAgent'

            $profilePath = "TestRegistry:\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\$script:ProfileGuid"
            New-Item -Path $profilePath -Force | Out-Null
            New-ItemProperty -LiteralPath $profilePath -Name 'ProfileName' -Value 'ConferenceSSID' -PropertyType String -Force | Out-Null

            foreach ($signatureType in @('Managed', 'Unmanaged')) {
                $signaturePath = "TestRegistry:\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\$signatureType\Signature1"
                New-Item -Path $signaturePath -Force | Out-Null
                New-ItemProperty -LiteralPath $signaturePath -Name 'FirstNetwork' -Value 'ConferenceSSID' -PropertyType String -Force | Out-Null
            }

            $tcpipPath = "TestRegistry:\Machine\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$script:InterfaceGuid}"
            New-Item -Path $tcpipPath -Force | Out-Null
            New-ItemProperty -LiteralPath $tcpipPath -Name 'EnableDHCP' -Value 0 -PropertyType DWord -Force | Out-Null

            $networkControlPath = "TestRegistry:\Machine\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$script:InterfaceGuid}\Connection"
            New-Item -Path $networkControlPath -Force | Out-Null
            New-ItemProperty -LiteralPath $networkControlPath -Name 'Name' -Value 'Synthetic Adapter' -PropertyType String -Force | Out-Null

            $protectedProviderPath = 'TestRegistry:\Machine\SOFTWARE\Contoso\SecurityAgent'
            New-Item -Path $protectedProviderPath -Force | Out-Null
            New-ItemProperty -LiteralPath $protectedProviderPath -Name 'Installed' -Value 1 -PropertyType DWord -Force | Out-Null
        }

        AfterEach {
            Clear-NetCleanRegistryRootMap
        }

        It 'discovers synthetic network history while preserving adapter configuration' {
            $candidates = @(Get-NetworkPrivacyArtifactCandidate -Inventory @())
            $sanitizable = @(Get-SanitizableNetworkArtifact -Inventory @())

            @($candidates | Where-Object ArtifactType -EQ 'NetworkList').Count | Should -Be 4
            @($sanitizable | Where-Object ArtifactType -NE 'NetworkList').Count | Should -Be 0

            $tcpipCandidate = $candidates |
                Where-Object { $_.ArtifactType -eq 'TcpipInterface' -and $_.InterfaceGuid -eq $script:InterfaceGuid }
            $tcpipCandidate.CanSanitize | Should -BeFalse

            $networkControlCandidates = @(
                $candidates |
                    Where-Object { $_.ArtifactType -eq 'NetworkControl' -and $_.InterfaceGuid -eq $script:InterfaceGuid }
            )
            $networkControlCandidates.Count | Should -Be 2
            @($networkControlCandidates | Where-Object CanSanitize).Count | Should -Be 0

            @(Get-NetworkListProfileName) | Should -Contain 'ConferenceSSID'
        }

        It 'validates map targets atomically and restores normal hive routing' {
            $mappedProviderPath = Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE'
            $mappedProviderPath | Should -Match '^Registry::HKEY_CURRENT_USER\\Software\\Pester\\'

            $isolatedRoot = (Get-PSDrive -Name TestRegistry -ErrorAction Stop).Root
            Set-NetCleanRegistryRootMap -RootMap @{
                HKLM = "$isolatedRoot\User"
            } -WhatIf
            Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE' | Should -Be $mappedProviderPath

            {
                Set-NetCleanRegistryRootMap -RootMap @{
                    HKLM = "$isolatedRoot\Missing"
                }
            } | Should -Throw

            Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE' | Should -Be $mappedProviderPath

            Clear-NetCleanRegistryRootMap
            Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE' |
                Should -Be 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE'
        }

        It 'backs up synthetic NetworkList and protected registry data with reg.exe' {
            $backupPath = Join-Path $TestDrive 'registry-backup'

            $networkListBackup = Export-NetworkList -Dest $backupPath
            $protectedBackups = @(
                Export-ProtectedRegistryKey -Paths @($script:ProtectedPath) -Dest $backupPath
            )

            Test-Path -LiteralPath $networkListBackup -PathType Leaf | Should -BeTrue
            $protectedBackups.Count | Should -Be 1
            Test-Path -LiteralPath $protectedBackups[0] -PathType Leaf | Should -BeTrue
            Get-Content -LiteralPath $networkListBackup -Raw | Should -Match 'ConferenceSSID'
            Get-Content -LiteralPath $protectedBackups[0] -Raw | Should -Match 'Installed'
        }

        It 'removes only sanitizable history and independently verifies the post-state' {
            $artifacts = [System.Collections.Generic.List[object]]::new()
            foreach ($artifact in @(Get-SanitizableNetworkArtifact -Inventory @())) {
                $artifacts.Add($artifact)
            }
            $artifacts.Add([pscustomobject]@{
                    ArtifactType = 'SecurityAgent'
                    RegistryPath = $script:ProtectedPath
                    CanSanitize  = $true
                    IsProtected  = $true
                    Reason       = 'Synthetic protection-boundary test'
                })

            $context = [pscustomobject]@{
                SanitizableArtifacts    = $artifacts.ToArray()
                ProtectedRegistryPaths = @($script:ProtectedPath)
            }

            $cleanup = Remove-NetworkPrivacyArtifactsSafe -Context $context -Confirm:$false
            $context | Add-Member -MemberType NoteProperty -Name Clean -Value ([pscustomobject]@{
                    DryRun            = $false
                    RegistryArtifacts = $cleanup
                })
            $verification = Test-NetCleanCleanupPostState -Context $context

            Test-RegistryPathExist -RegistryPath 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' |
                Should -BeFalse
            Test-RegistryPathExist -RegistryPath 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures' |
                Should -BeFalse
            Test-RegistryPathExist -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$script:InterfaceGuid}" |
                Should -BeTrue
            Test-RegistryPathExist -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$script:InterfaceGuid}\Connection" |
                Should -BeTrue
            Test-RegistryPathExist -RegistryPath $script:ProtectedPath | Should -BeTrue

            @($cleanup.Results | Where-Object Reason -EQ 'Protected').Count | Should -Be 1
            $verification.Applicable | Should -BeTrue
            $verification.Passed | Should -BeTrue
            @($verification.Checks | Where-Object VerificationType -EQ 'IndependentState').Count |
                Should -BeGreaterThan 0
            @($verification.Checks | Where-Object VerificationType -EQ 'ProtectionBoundary').Count |
                Should -Be 1
        }

        Context 'Test-RegistryPathExist against real registry state' {

            It 'returns true for an existing key' {
                Test-RegistryPathExist -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\$script:ProfileGuid" |
                    Should -BeTrue
            }

            It 'returns false for a missing key' {
                Test-RegistryPathExist -RegistryPath 'HKLM\SOFTWARE\Contoso\DoesNotExist12345' |
                    Should -BeFalse
            }

            It 'returns false for an unsupported registry root without ThrowOnError' {
                Test-RegistryPathExist -RegistryPath 'NOTAHIVE\SOFTWARE\Test' | Should -BeFalse
            }

            It 'throws for an unsupported registry root with ThrowOnError' {
                { Test-RegistryPathExist -RegistryPath 'NOTAHIVE\SOFTWARE\Test' -ThrowOnError } |
                    Should -Throw
            }
        }

        Context 'Get-RegistryValuesSafe against real registry state' {

            It 'returns the value bag for an existing key' {
                $result = Get-RegistryValuesSafe -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\$script:ProfileGuid"

                $result.ProfileName | Should -Be 'ConferenceSSID'
            }

            It 'returns a multi-string value with the correct array shape' {
                $tcpipPath = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$script:InterfaceGuid}"
                New-ItemProperty -LiteralPath (Convert-RegToProviderPath -RegistryPath $tcpipPath) -Name 'NameServer' -Value @('9.9.9.9', '149.112.112.112') -PropertyType MultiString -Force | Out-Null

                $result = Get-RegistryValuesSafe -RegistryPath $tcpipPath

                @($result.NameServer) | Should -Be @('9.9.9.9', '149.112.112.112')
            }

            It 'returns null for a missing key' {
                Get-RegistryValuesSafe -RegistryPath 'HKLM\SOFTWARE\Contoso\DoesNotExist12345' | Should -BeNullOrEmpty
            }

            It 'returns null for an unsupported registry root' {
                Get-RegistryValuesSafe -RegistryPath 'NOTAHIVE\SOFTWARE\Test' | Should -BeNullOrEmpty
            }
        }

        Context 'Get-RegistryChildKeyNamesSafe against real registry state' {

            It 'returns child key names for a key with subkeys' {
                $result = @(Get-RegistryChildKeyNamesSafe -RegistryPath 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')

                $result | Should -Contain $script:ProfileGuid
            }

            It 'returns an empty collection for a leaf key with no subkeys' {
                $result = @(Get-RegistryChildKeyNamesSafe -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\$script:ProfileGuid")

                $result.Count | Should -Be 0
            }

            It 'returns an empty collection for a missing key' {
                $result = @(Get-RegistryChildKeyNamesSafe -RegistryPath 'HKLM\SOFTWARE\Contoso\DoesNotExist12345')

                $result.Count | Should -Be 0
            }

            It 'returns an empty collection for an unsupported registry root' {
                $result = @(Get-RegistryChildKeyNamesSafe -RegistryPath 'NOTAHIVE\SOFTWARE\Test')

                $result.Count | Should -Be 0
            }
        }
    }
}
