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
                Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE\Test' |
                    Should -Be 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'
            }

            It 'converts HKCU path to provider form' {
                Convert-RegToProviderPath -RegistryPath 'HKCU\Software\Test' |
                    Should -Be 'Registry::HKEY_CURRENT_USER\Software\Test'
            }

            It 'preserves already provider-qualified paths' {
                Convert-RegToProviderPath -RegistryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' |
                    Should -Be 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'
            }

            It 'returns null when input is null' {
                Convert-RegToProviderPath -Path $null | Should -BeNullOrEmpty
            }
        }

        Context 'Set-NetCleanRegistryRootMap' {

            BeforeEach {
                Clear-NetCleanRegistryRootMap
                Mock Get-Item {
                    [pscustomobject]@{ PSProvider = [pscustomobject]@{ Name = 'Registry' } }
                }
            }

            AfterEach {
                Clear-NetCleanRegistryRootMap
            }

            It 'rejects an empty root map' {
                { Set-NetCleanRegistryRootMap -RootMap @{} } |
                    Should -Throw '*at least one mapping*'
            }

            It 'rejects logical keys below a hive root' {
                { Set-NetCleanRegistryRootMap -RootMap @{ 'HKLM\SOFTWARE' = 'HKCU\Software\Test' } } |
                    Should -Throw '*must be a hive root*'
                Should -Invoke Get-Item -Times 0
            }

            It 'rejects aliases that duplicate the same logical hive' {
                {
                    Set-NetCleanRegistryRootMap -RootMap @{
                        HKLM               = 'HKCU\Software\First'
                        HKEY_LOCAL_MACHINE = 'HKCU\Software\Second'
                    }
                } | Should -Throw '*duplicate logical root*'
            }

            It 'rejects targets outside the Registry provider' {
                Mock Get-Item {
                    [pscustomobject]@{ PSProvider = [pscustomobject]@{ Name = 'FileSystem' } }
                }

                { Set-NetCleanRegistryRootMap -RootMap @{ HKLM = 'HKCU\Software\Test' } } |
                    Should -Throw '*not a Registry-provider key*'
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

            It 'flattens one nested collection level and ignores empty inner values' {
                $nested = [object[]]@(' beta ', $null, '', 'alpha')

                $result = Get-UniqueNonEmptyString -InputObject @($nested, 'gamma', 'alpha')

                @($result) | Should -Be @('alpha', 'beta', 'gamma')
            }
        }

        Context 'Add-HashSetValue' {

            It 'adds a new value to the hashset' {
                $set = [System.Collections.Generic.HashSet[string]]::new()
                Add-HashSetValue -Set $set -Values 'abc' | Out-Null

                $set.Contains('abc') | Should -BeTrue
            }

            It 'does not fail when value is already present' {
                $set = [System.Collections.Generic.HashSet[string]]::new()
                $set.Add('abc') | Out-Null

                { Add-HashSetValue -Set $set -Values 'abc' | Out-Null } | Should -Not -Throw
                $set.Count | Should -Be 1
            }

            It 'ignores null or whitespace values' {
                $set = [System.Collections.Generic.HashSet[string]]::new()

                Add-HashSetValue -Set $set -Values $null | Out-Null
                Add-HashSetValue -Set $set -Values '' | Out-Null
                Add-HashSetValue -Set $set -Values '   ' | Out-Null

                $set.Count | Should -Be 0
            }

            It 'adds normalized values from a nested collection' {
                $set = [System.Collections.Generic.HashSet[string]]::new()
                $nested = [object[]]@(' beta ', $null, '', 'alpha')

                Add-HashSetValue -Set $set -Values @($nested, 'gamma')

                $set.Count | Should -Be 3
                $set.Contains('alpha') | Should -BeTrue
                $set.Contains('beta') | Should -BeTrue
                $set.Contains('gamma') | Should -BeTrue
            }
        }

        Context 'Compare-StringSet' {

            It 'identifies missing items from baseline to current' {
                $before = @('a', 'b', 'c')
                $after  = @('a', 'c')

                $result = Compare-StringSet -Before $before -After $after

                @($result.Missing) | Should -Be @('b')
            }

            It 'identifies added items from current to baseline' {
                $baseline = @('a')
                $current  = @('a', 'b', 'c')

                $result = Compare-StringSet -Before $baseline -After $current

                @($result.Added) | Should -Be @('b', 'c')
            }

            It 'returns empty differences when sets match' {
                $result = Compare-StringSet -Before @('a', 'b') -After @('a', 'b')

                @($result.Missing).Count | Should -Be 0
                @($result.Added).Count | Should -Be 0
            }
        }

        Context 'Get-NetCleanDeviceManagementState' {

            It 'classifies a hybrid Entra/domain device as managed' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Succeeded = $true
                        Output    = @(
                            ' AzureAdJoined : YES',
                            ' DomainJoined : YES',
                            ' EnterpriseJoined : NO',
                            ' WorkplaceJoined : NO'
                        )
                        Error     = $null
                    }
                }
                Mock Get-ScheduledTask { @() }

                $result = Get-NetCleanDeviceManagementState

                $result.IsManaged | Should -BeTrue
                $result.JoinType | Should -Be 'MicrosoftEntraHybridJoined'
                $result.EntraJoined | Should -BeTrue
                $result.DomainJoined | Should -BeTrue
            }

            It 'classifies a workgroup device without MDM evidence as unmanaged' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Succeeded = $true
                        Output    = @(
                            ' AzureAdJoined : NO',
                            ' DomainJoined : NO',
                            ' EnterpriseJoined : NO',
                            ' WorkplaceJoined : NO'
                        )
                        Error     = $null
                    }
                }
                Mock Get-ScheduledTask { @() }

                $result = Get-NetCleanDeviceManagementState

                $result.IsManaged | Should -BeFalse
                $result.JoinType | Should -Be 'Workgroup'
                $result.MdmEnrolled | Should -BeFalse
            }

            It 'does not treat Workplace registration alone as device management' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Succeeded = $true
                        Output    = @(
                            ' AzureAdJoined : NO',
                            ' DomainJoined : NO',
                            ' EnterpriseJoined : NO',
                            ' WorkplaceJoined : YES'
                        )
                        Error     = $null
                    }
                }
                Mock Get-ScheduledTask { @() }

                $result = Get-NetCleanDeviceManagementState

                $result.IsManaged | Should -BeFalse
                $result.JoinType | Should -Be 'WorkplaceRegistered'
                $result.WorkplaceJoined | Should -BeTrue
                $result.MdmEnrolled | Should -BeFalse
            }

            It 'treats EnterpriseMgmt task evidence as managed conservatively' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Succeeded = $true
                        Output    = @(
                            ' AzureAdJoined : NO',
                            ' DomainJoined : NO',
                            ' EnterpriseJoined : NO',
                            ' WorkplaceJoined : NO'
                        )
                        Error     = $null
                    }
                }
                Mock Get-ScheduledTask {
                    @([pscustomobject]@{ TaskName = 'Schedule #3'; TaskPath = '\Microsoft\Windows\EnterpriseMgmt\{guid}\' })
                }

                $result = Get-NetCleanDeviceManagementState

                $result.IsManaged | Should -BeTrue
                $result.MdmEnrolled | Should -BeTrue
                $result.JoinType | Should -Be 'MdmEnrolled'
            }

            It 'falls back to the computer-system domain state when dsregcmd fails' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Succeeded = $false
                        Output    = @()
                        Error     = 'dsregcmd failed'
                    }
                }
                Mock Get-CimInstance {
                    [pscustomobject]@{ PartOfDomain = $true }
                } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
                Mock Get-ScheduledTask { @() }

                $result = Get-NetCleanDeviceManagementState

                $result.IsManaged | Should -BeTrue
                $result.DomainJoined | Should -BeTrue
                $result.JoinType | Should -Be 'DomainJoined'
                @($result.Warnings).Count | Should -BeGreaterThan 0
            }
        }

        Context 'Invoke-InParallel' {

            It 'returns an empty collection for empty input' {
                $result = @(Invoke-InParallel -ScriptBlock { param($item) $item } -InputObjects @())

                $result.Count | Should -Be 0
            }

            It 'collects one result for each independent input' {
                $result = @(
                    Invoke-InParallel -ScriptBlock {
                        param($item)
                        [pscustomobject]@{ Value = $item * 2 }
                    } -InputObjects @(1, 2, 3) -ThrottleLimit 2
                )

                @($result.Value | Sort-Object) | Should -Be @(2, 4, 6)
            }

            It 'isolates a failed worker and returns successful worker results' {
                $result = @(
                    Invoke-InParallel -ScriptBlock {
                        param($item)
                        if ($item -eq 2) { throw 'worker failed' }
                        $item
                    } -InputObjects @(1, 2, 3) -ThrottleLimit 2
                )

                @($result | Sort-Object) | Should -Be @(1, 3)
            }

            It 'rejects a non-positive throttle limit' {
                {
                    Invoke-InParallel -ScriptBlock { param($item) $item } -InputObjects @(1) -ThrottleLimit 0
                } | Should -Throw
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

            It 'rethrows provider failures for verification callers' {
                Mock Convert-RegToProviderPath { throw 'registry provider unavailable' }

                {
                    Test-RegistryPathExist -RegistryPath 'HKLM\SOFTWARE\Test' -ThrowOnError
                } | Should -Throw '*registry provider unavailable*'
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

                $result = Get-RegistryValuesSafe -RegistryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'

                $result.Name  | Should -Be 'TestName'
                $result.Value | Should -Be 'TestValue'
            }

            It 'returns null when Get-ItemProperty throws' {
                Mock Get-ItemProperty { throw 'boom' }

                Get-RegistryValuesSafe -RegistryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test' | Should -BeNullOrEmpty
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

                $result = Get-RegistryChildKeyNamesSafe -RegistryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Test'

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

        Context 'Set-NetCleanPrivateDirectoryAcl' {

            It 'applies a protected ACL to an existing directory' {
                Mock Set-Acl {}

                Set-NetCleanPrivateDirectoryAcl -Path $TestDrive

                Should -Invoke Set-Acl -Times 1 -ParameterFilter {
                    $LiteralPath -eq $TestDrive -and
                    $AclObject.AreAccessRulesProtected
                }
            }

            It 'honors WhatIf without applying an ACL' {
                Mock Set-Acl {}

                Set-NetCleanPrivateDirectoryAcl -Path $TestDrive -WhatIf

                Should -Invoke Set-Acl -Times 0
            }

            It 'fails closed when the directory does not exist' {
                {
                    Set-NetCleanPrivateDirectoryAcl -Path (Join-Path $TestDrive 'missing')
                } | Should -Throw
            }
        }

        Context 'Start-NetCleanLog' {

            It 'secures the directory before creating a log file' {
                $logDir = Join-Path $TestDrive 'PrivateLogs'
                Mock Set-NetCleanPrivateDirectoryAcl {}

                Start-NetCleanLog -Directory $logDir

                Should -Invoke Set-NetCleanPrivateDirectoryAcl -Times 1 -ParameterFilter {
                    $Path -eq $logDir
                }
            }

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

                $streamOutput = @(Write-NetCleanLog -Level ERROR -Message 'error message' 2>&1)

                @($streamOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count |
                    Should -BeGreaterThan 0
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

        Context 'Invoke-RegExport' {

            BeforeEach {
                Mock Resolve-NetCleanRegistryPath { $RegistryPath }
                Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
                Mock Test-Path { $true }
            }

            It 'returns the planned path without starting reg.exe during a dry run' {
                Invoke-RegExport -Key 'HKLM\SOFTWARE\Test' -FilePath 'C:\backup\test.reg' -DryRun |
                    Should -Be 'C:\backup\test.reg'
                Should -Invoke Start-Process -Times 0
            }

            It 'rejects double quotes in the key or output path' -ForEach @(
                @{ Key = 'HKLM\SOFTWARE\"Test'; FilePath = 'C:\backup\test.reg' }
                @{ Key = 'HKLM\SOFTWARE\Test'; FilePath = 'C:\backup\"test.reg' }
            ) {
                { Invoke-RegExport -Key $Key -FilePath $FilePath } |
                    Should -Throw '*must not contain double-quote*'
                Should -Invoke Start-Process -Times 0
            }

            It 'fails when reg.exe cannot be started' {
                Mock Start-Process { $null }

                { Invoke-RegExport -Key 'HKLM\SOFTWARE\Test' -FilePath 'C:\backup\test.reg' } |
                    Should -Throw '*Failed to start reg.exe*'
            }

            It 'fails when reg.exe returns a nonzero exit code' {
                Mock Start-Process { [pscustomobject]@{ ExitCode = 5 } }

                { Invoke-RegExport -Key 'HKLM\SOFTWARE\Test' -FilePath 'C:\backup\test.reg' } |
                    Should -Throw '*exit code 5*'
            }

            It 'fails when reg.exe reports success without creating the output file' {
                Mock Test-Path { $false }

                { Invoke-RegExport -Key 'HKLM\SOFTWARE\Test' -FilePath 'C:\backup\test.reg' } |
                    Should -Throw '*output file was not created*'
            }

            It 'quotes the normalized key and output path for a successful export' {
                $result = Invoke-RegExport `
                    -Key 'HKLM\SOFTWARE\Test' `
                    -FilePath 'C:\backup folder\test.reg'

                $result | Should -Be 'C:\backup folder\test.reg'
                Should -Invoke Start-Process -Times 1 -ParameterFilter {
                    $FilePath -eq 'reg.exe' -and
                    $ArgumentList[0] -eq 'export' -and
                    $ArgumentList[1] -eq '"HKLM\SOFTWARE\Test"' -and
                    $ArgumentList[2] -eq '"C:\backup folder\test.reg"' -and
                    $ArgumentList[3] -eq '/y' -and
                    $NoNewWindow -and $Wait -and $PassThru
                }
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

        Context 'Get-NormalizedFilePathFromCommandLine' {

            It 'returns null for null or whitespace input' -ForEach @(
                @{ CommandLine = $null }
                @{ CommandLine = '   ' }
            ) {
                Get-NormalizedFilePathFromCommandLine -CommandLine $CommandLine |
                    Should -BeNullOrEmpty
            }

            It 'expands environment variables before extracting an executable path' {
                $env:NETCLEAN_TEST_ROOT = 'C:\Tools'
                try {
                    Get-NormalizedFilePathFromCommandLine `
                        -CommandLine '%NETCLEAN_TEST_ROOT%\agent.exe --service' |
                        Should -Be 'C:\Tools\agent.exe'
                }
                finally {
                    Remove-Item Env:\NETCLEAN_TEST_ROOT -ErrorAction SilentlyContinue
                }
            }

            It 'normalizes a SystemRoot-prefixed driver path' {
                $expected = Join-Path $env:windir 'System32\drivers\agent.sys'

                Get-NormalizedFilePathFromCommandLine `
                    -CommandLine '\SystemRoot\System32\drivers\agent.sys -k' |
                    Should -Be $expected
            }

            It 'extracts quoted and unquoted executable paths' -ForEach @(
                @{
                    CommandLine = '"C:\Program Files\Contoso\agent.exe" --service'
                    Expected    = 'C:\Program Files\Contoso\agent.exe'
                }
                @{
                    CommandLine = 'C:\Tools\agent.com /quiet'
                    Expected    = 'C:\Tools\agent.com'
                }
                @{
                    CommandLine = 'C:\Program Files\Contoso\agent.exe --service'
                    Expected    = 'C:\Program Files\Contoso\agent.exe'
                }
            ) {
                Get-NormalizedFilePathFromCommandLine -CommandLine $CommandLine |
                    Should -Be $Expected
            }

            It 'returns a trimmed fallback when no recognized binary extension is present' {
                Get-NormalizedFilePathFromCommandLine -CommandLine ' "custom command" ' |
                    Should -Be 'custom command'
            }
        }

        Context 'Get-VendorRootsFromInstallPath' {

            It 'returns no roots for an empty install path' {
                @(Get-VendorRootsFromInstallPath -InstallPath $null).Count | Should -Be 0
            }

            It 'derives native and WOW6432Node roots from the leaf and its parent' {
                $result = Get-VendorRootsFromInstallPath `
                    -InstallPath '"C:\Program Files\CrowdStrike\Falcon Sensor"'

                @($result) | Should -Be @(
                    'HKLM\SOFTWARE\CrowdStrike'
                    'HKLM\SOFTWARE\Falcon Sensor'
                    'HKLM\SOFTWARE\WOW6432Node\CrowdStrike'
                    'HKLM\SOFTWARE\WOW6432Node\Falcon Sensor'
                )
            }

            It 'fails soft when the install path cannot be split' {
                Mock Split-Path { throw 'invalid path' }

                @(Get-VendorRootsFromInstallPath -InstallPath 'invalid').Count | Should -Be 0
            }
        }

        Context 'Test-VendorPatternMatch' {

            It 'trusts an exact inferred-vendor match' {
                $evidence = [pscustomobject]@{ InferredVendor = 'CrowdStrike' }

                Test-VendorPatternMatch `
                    -Vendor 'CrowdStrike' `
                    -Signature @{ Patterns = @('falcon') } `
                    -Evidence $evidence |
                    Should -BeTrue
            }

            It 'matches a pattern against the properties present on sparse evidence' {
                $evidence = [pscustomobject]@{ Name = 'CrowdStrike Falcon Sensor' }

                Test-VendorPatternMatch `
                    -Vendor 'CrowdStrike' `
                    -Signature @{ Patterns = @('falcon') } `
                    -Evidence $evidence |
                    Should -BeTrue
            }

            It 'returns false when sparse evidence has no vendor pattern' {
                $evidence = [pscustomobject]@{ DisplayName = 'Unrelated network component' }

                Test-VendorPatternMatch `
                    -Vendor 'CrowdStrike' `
                    -Signature @{ Patterns = @('crowdstrike', 'falcon') } `
                    -Evidence $evidence |
                    Should -BeFalse
            }
        }

        Context 'Get-FileMetadatum' {

            BeforeEach {
                Mock Get-NormalizedFilePathFromCommandLine { $CommandLine }
            }

            It 'returns null for an empty or unresolvable path' {
                Get-FileMetadatum -Path $null | Should -BeNullOrEmpty

                Mock Get-NormalizedFilePathFromCommandLine { $null }
                Get-FileMetadatum -Path 'unresolvable.exe' | Should -BeNullOrEmpty
            }

            It 'returns a structured absent-file result' {
                Mock Test-Path { $false }

                $result = Get-FileMetadatum -Path 'C:\missing\agent.exe'

                $result.Path | Should -Be 'C:\missing\agent.exe'
                $result.Exists | Should -BeFalse
                $result.SignatureStatus | Should -BeNullOrEmpty
            }

            It 'returns null when the normalized path cannot be queried' {
                Mock Test-Path { throw 'invalid path syntax' }

                Get-FileMetadatum -Path 'C:\invalid\agent.exe' | Should -BeNullOrEmpty
            }

            It 'returns version, signature, and inferred-vendor metadata for an existing file' {
                Mock Test-Path { $true }
                Mock Get-Item {
                    [pscustomobject]@{
                        FullName    = 'C:\Program Files\CrowdStrike\sensor.exe'
                        Name        = 'sensor.exe'
                        VersionInfo = [pscustomobject]@{
                            CompanyName      = 'CrowdStrike, Inc.'
                            FileDescription  = 'Falcon Sensor'
                            ProductName      = 'Falcon'
                            OriginalFilename = 'sensor.exe'
                            FileVersion      = '7.1.2.3'
                        }
                    }
                }
                Mock Get-AuthenticodeSignature {
                    [pscustomobject]@{
                        Status            = 'Valid'
                        SignerCertificate = [pscustomobject]@{
                            Subject    = 'CN=CrowdStrike'
                            Issuer     = 'CN=Trusted Issuer'
                            Thumbprint = 'ABC123'
                        }
                    }
                }
                Mock Resolve-VendorFromText { 'CrowdStrike' }

                $result = Get-FileMetadatum -Path '"C:\Program Files\CrowdStrike\sensor.exe" --service'

                $result.Exists | Should -BeTrue
                $result.CompanyName | Should -Be 'CrowdStrike, Inc.'
                $result.FileVersion | Should -Be '7.1.2.3'
                $result.SignerSubject | Should -Be 'CN=CrowdStrike'
                $result.SignatureStatus | Should -Be 'Valid'
                $result.InferredVendor | Should -Be 'CrowdStrike'
            }

            It 'retains file metadata when Authenticode inspection fails' {
                Mock Test-Path { $true }
                Mock Get-Item {
                    [pscustomobject]@{
                        FullName    = 'C:\Tools\unsigned.exe'
                        Name        = 'unsigned.exe'
                        VersionInfo = $null
                    }
                }
                Mock Get-AuthenticodeSignature { throw 'signature provider unavailable' }
                Mock Resolve-VendorFromText { $null }

                $result = Get-FileMetadatum -Path 'C:\Tools\unsigned.exe'

                $result.Exists | Should -BeTrue
                $result.CompanyName | Should -BeNullOrEmpty
                $result.SignerSubject | Should -BeNullOrEmpty
                $result.SignatureStatus | Should -BeNullOrEmpty
            }

            It 'returns null when an existing file cannot be read' {
                Mock Test-Path { $true }
                Mock Get-Item { throw 'access denied' }

                Get-FileMetadatum -Path 'C:\protected\agent.exe' | Should -BeNullOrEmpty
            }
        }

        Context 'Get-ServiceRegistryMap' {

            It 'maps service values and existing child registry paths by normalized service name' {
                Mock Get-RegistryChildKeyNamesSafe { @('CSFalconService', 'MinimalService') }
                Mock Get-RegistryValuesSafe {
                    if ($RegistryPath -like '*CSFalconService') {
                        [pscustomobject]@{
                            ImagePath   = 'C:\Program Files\CrowdStrike\sensor.exe'
                            DisplayName = 'CrowdStrike Falcon Sensor'
                            Type        = 16
                            Start       = 2
                            Group       = 'NetworkProvider'
                        }
                    }
                }
                Mock Test-RegistryPathExist {
                    $RegistryPath -match '\\(Enum|Parameters)$'
                }

                $result = Get-ServiceRegistryMap

                $result.Count | Should -Be 2
                $result.ContainsKey('csfalconservice') | Should -BeTrue
                $result.csfalconservice.DisplayName | Should -Be 'CrowdStrike Falcon Sensor'
                $result.csfalconservice.EnumPath | Should -Match '\\Enum$'
                $result.csfalconservice.LinkagePath | Should -BeNullOrEmpty
                $result.minimalservice.ImagePath | Should -BeNullOrEmpty
                Should -Invoke Test-RegistryPathExist -Times 8
            }

            It 'returns an empty map when the services root has no children' {
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = Get-ServiceRegistryMap

                $result | Should -BeOfType [hashtable]
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-AdapterRegistryCorrelation' {

            It 'correlates valid and fallback interface identifiers while skipping unusable class entries' {
                Mock Get-RegistryChildKeyNamesSafe { @('Metadata', '0000', '0001', '0002', '0003') }
                Mock Get-RegistryValuesSafe {
                    switch -Wildcard ($RegistryPath) {
                        '*\0000' { return $null }
                        '*\0001' {
                            return [pscustomobject]@{
                                ComponentId     = 'crowdstrike_filter'
                                DriverDesc      = 'CrowdStrike Network Filter'
                                ProviderName    = 'CrowdStrike, Inc.'
                                NetCfgInstanceId = '{11111111-2222-3333-4444-555555555555}'
                            }
                        }
                        '*\0002' {
                            return [pscustomobject]@{
                                ComponentId     = 'contoso_filter'
                                DriverDesc      = 'Contoso Filter'
                                ProviderName    = 'Contoso'
                                NetCfgInstanceId = '{NOT-A-GUID}'
                            }
                        }
                        '*\0003' {
                            return [pscustomobject]@{
                                ComponentId     = 'no_interface'
                                DriverDesc      = 'No Interface'
                                ProviderName    = 'Contoso'
                                NetCfgInstanceId = $null
                            }
                        }
                    }
                }
                Mock Test-RegistryPathExist { $true }

                $result = @(Get-AdapterRegistryCorrelation)

                $result.Count | Should -Be 2
                $result[0].InterfaceGuid | Should -Be '11111111-2222-3333-4444-555555555555'
                $result[1].InterfaceGuid | Should -Be 'not-a-guid'
                $result[0].ConnectionPath | Should -Match '\\Connection$'
                $result[0].TcpipPath | Should -Match '\\Interfaces\\\{11111111-2222-3333-4444-555555555555\}$'
                Should -Invoke Test-RegistryPathExist -Times 6
            }

            It 'returns empty when no adapter class entries are present' {
                Mock Get-RegistryChildKeyNamesSafe { @() }

                @(Get-AdapterRegistryCorrelation).Count | Should -Be 0
            }
        }
    }
}
