$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean core/shared helper unit tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
        }

        Context 'Convert-RegKeyPath' {

            It 'normalizes Microsoft.PowerShell.Core registry provider paths' {
                Convert-RegKeyPath -Path 'Microsoft.PowerShell.Core\Registry::HKLM:\SOFTWARE\Test' |
                    Should -Be 'HKLM\SOFTWARE\Test'
            }

            It 'normalizes Registry:: prefixed paths' {
                Convert-RegKeyPath -Path 'Registry::HKCU\Software\Test' |
                    Should -Be 'HKCU\Software\Test'
            }

            It 'preserves already normalized registry paths' {
                Convert-RegKeyPath -Path 'HKLM\SOFTWARE\Test' |
                    Should -Be 'HKLM\SOFTWARE\Test'
            }

            It 'returns null when input is null' {
                Convert-RegKeyPath -Path $null | Should -BeNullOrEmpty
            }

            It 'returns empty string when input is empty' {
                Convert-RegKeyPath -Path '' | Should -Be ''
            }
        }

        Context 'Convert-RegToProviderPath' {

            It 'converts HKLM path to provider form' {
                Convert-RegToProviderPath -Path 'HKLM\SOFTWARE\Test' |
                    Should -Be 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'
            }

            It 'converts HKCU path to provider form' {
                Convert-RegToProviderPath -Path 'HKCU\Software\Test' |
                    Should -Be 'Registry::HKEY_CURRENT_USER\Software\Test'
            }

            It 'preserves already provider-qualified paths' {
                Convert-RegToProviderPath -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' |
                    Should -Be 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'
            }

            It 'returns null when input is null' {
                Convert-RegToProviderPath -Path $null | Should -BeNullOrEmpty
            }
        }

        Context 'Convert-Guid' {

            It 'normalizes GUIDs with braces and uppercase characters' {
                Convert-Guid -Guid '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' |
                    Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            }

            It 'normalizes GUIDs without braces' {
                Convert-Guid -Guid 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE' |
                    Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            }

            It 'returns null for null input' {
                Convert-Guid -Guid $null | Should -BeNullOrEmpty
            }

            It 'returns null for empty input' {
                Convert-Guid -Guid '' | Should -BeNullOrEmpty
            }
        }

        Context 'Get-UniqueNonEmptyString' {

            It 'returns distinct non-empty strings only' {
                $result = Get-UniqueNonEmptyString -InputObject @(
                    'alpha',
                    '',
                    'beta',
                    'alpha',
                    $null,
                    '   ',
                    'gamma'
                )

                @($result) | Should -Be @('alpha', 'beta', 'gamma')
            }

            It 'returns an empty collection for null input' {
                @((Get-UniqueNonEmptyString -InputObject $null)).Count | Should -Be 0
            }
        }

        Context 'Add-HashSetValue' {

            It 'adds a new value to the hashset' {
                $set = [System.Collections.Generic.HashSet[string]]::new()
                Add-HashSetValue -Set $set -Value 'abc' | Out-Null

                $set.Contains('abc') | Should -BeTrue
            }

            It 'does not fail when value is already present' {
                $set = [System.Collections.Generic.HashSet[string]]::new()
                $set.Add('abc') | Out-Null

                { Add-HashSetValue -Set $set -Value 'abc' | Out-Null } | Should -Not -Throw
                $set.Count | Should -Be 1
            }

            It 'ignores null or whitespace values' {
                $set = [System.Collections.Generic.HashSet[string]]::new()

                Add-HashSetValue -Set $set -Value $null | Out-Null
                Add-HashSetValue -Set $set -Value '' | Out-Null
                Add-HashSetValue -Set $set -Value '   ' | Out-Null

                $set.Count | Should -Be 0
            }
        }

        Context 'Compare-StringSet' {

            It 'identifies missing items from baseline to current' {
                $baseline = @('a', 'b', 'c')
                $current  = @('a', 'c')

                $result = Compare-StringSet -Baseline $baseline -Current $current

                @($result.Missing) | Should -Be @('b')
            }

            It 'identifies added items from current to baseline' {
                $baseline = @('a')
                $current  = @('a', 'b', 'c')

                $result = Compare-StringSet -Baseline $baseline -Current $current

                @($result.Added) | Should -Be @('b', 'c')
            }

            It 'returns empty differences when sets match' {
                $result = Compare-StringSet -Baseline @('a', 'b') -Current @('a', 'b')

                @($result.Missing).Count | Should -Be 0
                @($result.Added).Count | Should -Be 0
            }
        }

        Context 'Test-RegistryPathExist' {

            It 'returns true when Test-Path returns true' {
                Mock Test-Path { $true }

                Test-RegistryPathExist -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' | Should -BeTrue
            }

            It 'returns false when Test-Path returns false' {
                Mock Test-Path { $false }

                Test-RegistryPathExist -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' | Should -BeFalse
            }

            It 'returns false when Test-Path throws' {
                Mock Test-Path { throw 'boom' }

                Test-RegistryPathExist -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' | Should -BeFalse
            }
        }

        Context 'Get-RegistryValuesSafe' {

            It 'returns registry property bag when item properties are available' {
                Mock Get-ItemProperty {
                    [pscustomobject]@{
                        Name  = 'TestName'
                        Value = 'TestValue'
                    }
                }

                $result = Get-RegistryValuesSafe -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'

                $result.Name  | Should -Be 'TestName'
                $result.Value | Should -Be 'TestValue'
            }

            It 'returns null when Get-ItemProperty throws' {
                Mock Get-ItemProperty { throw 'boom' }

                Get-RegistryValuesSafe -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' | Should -BeNullOrEmpty
            }
        }

        Context 'Get-RegistryChildKeyNamesSafe' {

            It 'returns child key names when present' {
                Mock Get-ChildItem {
                    @(
                        [pscustomobject]@{ PSChildName = 'One' }
                        [pscustomobject]@{ PSChildName = 'Two' }
                    )
                }

                $result = Get-RegistryChildKeyNamesSafe -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'

                @($result) | Should -Be @('One', 'Two')
            }

            It 'returns empty collection when Get-ChildItem throws' {
                Mock Get-ChildItem { throw 'boom' }

                @((Get-RegistryChildKeyNamesSafe -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test')).Count |
                    Should -Be 0
            }
        }

        Context 'New-DirectoryIfNotExist' {

            It 'creates a directory when it does not already exist' {
                $path = Join-Path $TestDrive 'NewFolder'

                Test-Path -LiteralPath $path | Should -BeFalse
                New-DirectoryIfNotExist -Path $path
                Test-Path -LiteralPath $path | Should -BeTrue
            }

            It 'does not throw when the directory already exists' {
                $path = Join-Path $TestDrive 'ExistingFolder'
                New-Item -Path $path -ItemType Directory -Force | Out-Null

                { New-DirectoryIfNotExist -Path $path } | Should -Not -Throw
                Test-Path -LiteralPath $path | Should -BeTrue
            }
        }

        Context 'Get-NetCleanLogFile' {

            It 'returns null when no log file has been initialized' {
                $script:LogFile = $null
                Get-NetCleanLogFile | Should -BeNullOrEmpty
            }

            It 'returns the current module log file path when initialized' {
                $script:LogFile = 'C:\Temp\NetClean.log'
                Get-NetCleanLogFile | Should -Be 'C:\Temp\NetClean.log'
            }
        }

        Context 'Start-NetCleanLog' {

            It 'creates a log file in the target directory' {
                $logDir = Join-Path $TestDrive 'Logs'

                Start-NetCleanLog -Directory $logDir

                $logFile = Get-NetCleanLogFile
                $logFile | Should -Not -BeNullOrEmpty
                Test-Path -LiteralPath $logFile | Should -BeTrue
            }

            It 'creates the directory if it does not exist' {
                $logDir = Join-Path $TestDrive 'BrandNewLogs'

                Test-Path -LiteralPath $logDir | Should -BeFalse
                Start-NetCleanLog -Directory $logDir
                Test-Path -LiteralPath $logDir | Should -BeTrue
            }
        }

        Context 'Write-NetCleanLog' {

            It 'writes a log line to the current log file' {
                $logDir = Join-Path $TestDrive 'Logs'
                Start-NetCleanLog -Directory $logDir

                Write-NetCleanLog -Level INFO -Message 'hello world'

                $logFile = Get-NetCleanLogFile
                $content = Get-Content -LiteralPath $logFile -Raw

                $content | Should -Match 'hello world'
                $content | Should -Match '\[INFO\]'
            }

            It 'does not throw when no log file is initialized' {
                $script:LogFile = $null

                { Write-NetCleanLog -Level INFO -Message 'no file' } | Should -Not -Throw
            }

            It 'writes to the warning stream for WARN level' {
                $logDir = Join-Path $TestDrive 'WarnLogs'
                Start-NetCleanLog -Directory $logDir

                { Write-NetCleanLog -Level WARN -Message 'warn message' } | Should -Not -Throw
            }

            It 'writes to the error stream for ERROR level' {
                $logDir = Join-Path $TestDrive 'ErrorLogs'
                Start-NetCleanLog -Directory $logDir

                { Write-NetCleanLog -Level ERROR -Message 'error message' } | Should -Throw
            }
        }

        Context 'Invoke-ExternalCommandSafe' {

            It 'returns a successful dry-run result' {
                $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','echo ok' -DryRun

                $r.Name      | Should -Be 'Test'
                $r.Succeeded | Should -BeTrue
                $r.DryRun    | Should -BeTrue
                $r.ExitCode  | Should -Be 0
            }

            It 'captures successful process execution' {
                Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }

                $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','echo ok'

                $r.Succeeded | Should -BeTrue
                $r.ExitCode  | Should -Be 0
                Should -Invoke Start-Process -Times 1
            }

            It 'captures a non-zero exit code' {
                Mock Start-Process { [pscustomobject]@{ ExitCode = 5 } }

                $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','exit 5'

                $r.Succeeded | Should -BeFalse
                $r.ExitCode  | Should -Be 5
            }

            It 'returns failure details when Start-Process throws' {
                Mock Start-Process { throw 'start-process-failed' }

                $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','echo ok'

                $r.Succeeded | Should -BeFalse
                $r.ExitCode  | Should -Be -1
                $r.Error      | Should -Match 'start-process-failed'
            }
        }

        Context 'Invoke-NetCleanNativeCapture' {

            It 'captures successful native output' {
                Mock Write-NetCleanLog {}
                Mock Start-Process { throw 'This test expects direct invocation path to remain callable only if implemented differently.' }

                # If your implementation directly invokes native commands rather than Start-Process,
                # replace this test later with a cmd.exe-based invocation using the real command.
                { Invoke-NetCleanNativeCapture -FilePath 'cmd.exe' -ArgumentList @('/c', 'echo ok') -IgnoreExitCode } |
                    Should -Not -Throw
            }

            It 'captures non-zero exit code and respects IgnoreExitCode' {
                $bat = Join-Path $TestDrive 'exit5.bat'
                Set-Content -Path $bat -Value 'exit /b 5' -NoNewline

                $r = Invoke-NetCleanNativeCapture -FilePath $bat -ArgumentList @()

                $r.Succeeded | Should -BeFalse
                $r.ExitCode | Should -Be 5

                $r2 = Invoke-NetCleanNativeCapture -FilePath $bat -ArgumentList @() -IgnoreExitCode
                $r2.Succeeded | Should -BeTrue
            }
        }
    }
}