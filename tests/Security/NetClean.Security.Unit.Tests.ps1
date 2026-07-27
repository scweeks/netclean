$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean security unit tests' -Tag 'Security' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
        }

        Context 'Test-NetCleanSafeIdentifier' {

            It 'rejects a value containing an embedded double quote' {
                Test-NetCleanSafeIdentifier -Value 'Evil" & calc.exe & "' | Should -BeFalse
            }

            It 'rejects a value containing a backtick' {
                Test-NetCleanSafeIdentifier -Value 'Evil`nName' | Should -BeFalse
            }

            It 'rejects a value containing a semicolon' {
                Test-NetCleanSafeIdentifier -Value 'Evil; rd /s /q C:\' | Should -BeFalse
            }

            It 'rejects a value containing an ampersand' {
                Test-NetCleanSafeIdentifier -Value 'Evil & calc.exe' | Should -BeFalse
            }

            It 'rejects a value containing a pipe' {
                Test-NetCleanSafeIdentifier -Value 'Evil | calc.exe' | Should -BeFalse
            }

            It 'rejects a value containing angle brackets' {
                Test-NetCleanSafeIdentifier -Value 'Evil < C:\secrets.txt' | Should -BeFalse
                Test-NetCleanSafeIdentifier -Value 'Evil > C:\out.txt' | Should -BeFalse
            }

            It 'rejects a value containing an embedded newline or carriage return' {
                Test-NetCleanSafeIdentifier -Value "Evil`nName" | Should -BeFalse
                Test-NetCleanSafeIdentifier -Value "Evil`rName" | Should -BeFalse
            }

            It 'rejects a null or empty value' {
                Test-NetCleanSafeIdentifier -Value $null | Should -BeFalse
                Test-NetCleanSafeIdentifier -Value '' | Should -BeFalse
            }

            It 'accepts ordinary profile names containing spaces, hyphens, and unicode characters' {
                Test-NetCleanSafeIdentifier -Value 'Coffee Shop - Guest WiFi' | Should -BeTrue
                Test-NetCleanSafeIdentifier -Value 'Café Réseau' | Should -BeTrue
                Test-NetCleanSafeIdentifier -Value 'HomeSSID_5G' | Should -BeTrue
            }
        }

        Context 'Remove-WiFiProfilesSafe command-injection resistance' {

            It 'rejects a malicious Wi-Fi profile name before it reaches any native command' {
                Mock Invoke-InParallel {}
                Mock Write-NetCleanLog {}

                $malicious = 'Evil" & calc.exe & "'

                $result = Remove-WiFiProfilesSafe -WifiProfiles @($malicious)

                $result.Removed | Should -Be 0
                @($result.Profiles) | Should -Not -Contain $malicious
                $result.Operations[0].Skipped | Should -BeTrue
                $result.Operations[0].Reason | Should -Be 'UnsafeName'
                Should -Invoke Invoke-InParallel -Times 0
                Should -Invoke Write-NetCleanLog -ParameterFilter {
                    $Level -eq 'WARN' -and $Message -match 'unsafe characters'
                }
            }

            It 'still removes a legitimately-named sibling profile when a malicious name is present in the same batch' {
                Mock Invoke-InParallel {
                    @($InputObjects | ForEach-Object {
                            [pscustomobject]@{ Name = $_; Succeeded = $true; Skipped = $false; Reason = 'Removed' }
                        })
                }
                Mock Write-NetCleanLog {}

                $malicious = 'Evil"; rd /s /q C:\ & "'

                $result = Remove-WiFiProfilesSafe -WifiProfiles @($malicious, 'HomeSSID')

                $result.Removed | Should -Be 1
                @($result.Profiles) | Should -Contain 'HomeSSID'
                @($result.Profiles) | Should -Not -Contain $malicious
                Should -Invoke Invoke-InParallel -Times 1 -Exactly -ParameterFilter {
                    @($InputObjects).Count -eq 1 -and $InputObjects -contains 'HomeSSID'
                }
            }

            It 'does not over-block legitimate profile names containing spaces or unicode characters' {
                Mock Invoke-InParallel {
                    @($InputObjects | ForEach-Object {
                            [pscustomobject]@{ Name = $_; Succeeded = $true; Skipped = $false; Reason = 'Removed' }
                        })
                }
                Mock Write-NetCleanLog {}

                $result = Remove-WiFiProfilesSafe -WifiProfiles @('Coffee Shop - Guest WiFi', 'Café Réseau')

                $result.Removed | Should -Be 2
                @($result.Profiles) | Should -Contain 'Coffee Shop - Guest WiFi'
                @($result.Profiles) | Should -Contain 'Café Réseau'
            }
        }

        Context 'Export-WiFiProfile command-injection resistance' {

            BeforeEach {
                Mock New-DirectoryIfNotExist {}
                Mock WriteAllLines {}
            }

            It 'rejects a malicious Wi-Fi profile name before invoking the per-profile netsh export' {
                Mock Write-NetCleanLog {}
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Export Wi-Fi profiles (bulk)'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }
                # Bulk export never produces a new file, forcing the per-profile fallback.
                Mock Get-ChildItem { @() }

                $malicious = 'Evil" & calc.exe & "'

                $result = @(Export-WiFiProfile -Dest 'C:\backup' -Profiles @($malicious))

                # Only the list file is produced; no XML export was attempted for the malicious name.
                $result.Count | Should -Be 1
                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -Exactly
                Should -Invoke Write-NetCleanLog -ParameterFilter {
                    $Level -eq 'WARN' -and $Message -match 'unsafe characters'
                }
            }
        }

        Context 'Wi-Fi credential logging' {

            BeforeEach {
                Mock New-DirectoryIfNotExist {}
                Mock WriteAllLines {}
            }

            It 'never logs Wi-Fi PSK/key material from an exported profile XML' {
                Mock Get-WiFiProfileName { @('HomeSSID') }

                $exportedXmlPath = Join-Path $TestDrive 'Wi-Fi-HomeSSID.xml'
                Set-Content -LiteralPath $exportedXmlPath -Value (
                    '<WLANProfile><MSM><security><sharedKey>' +
                    '<keyMaterial>SUPERSECRETPSK</keyMaterial>' +
                    '</sharedKey></security></MSM></WLANProfile>'
                )

                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Export Wi-Fi profiles (bulk)'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $script:BulkCallSeen = $false
                Mock Get-ChildItem {
                    if (-not $script:BulkCallSeen) {
                        $script:BulkCallSeen = $true
                        @()
                    }
                    else {
                        @([pscustomobject]@{ FullName = $exportedXmlPath })
                    }
                }

                $script:LoggedMessages = [System.Collections.Generic.List[string]]::new()
                Mock Write-NetCleanLog { $script:LoggedMessages.Add($Message) }

                $null = Export-WiFiProfile -Dest $TestDrive

                ($script:LoggedMessages -join "`n") | Should -Not -Match 'SUPERSECRETPSK'
            }
        }
    }
}
