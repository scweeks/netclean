$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean isolated security system-component tests' -Tag 'System', 'Security' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
        }

        Context 'Set-NetCleanPrivateDirectoryAcl' {

            It 'restricts a real directory to only current user, Administrators, and SYSTEM with inheritance disabled' {
                $dir = Join-Path $TestDrive 'private-backup'
                New-Item -Path $dir -ItemType Directory -Force | Out-Null

                Set-NetCleanPrivateDirectoryAcl -Path $dir

                $acl = Get-Acl -LiteralPath $dir

                $acl.AreAccessRulesProtected | Should -BeTrue

                $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $expectedSids = @($currentUserSid, 'S-1-5-32-544', 'S-1-5-18') | Select-Object -Unique

                $actualSids = @(
                    $acl.Access | ForEach-Object {
                        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                ) | Select-Object -Unique

                foreach ($sid in $expectedSids) {
                    $actualSids | Should -Contain $sid
                }

                # No principal beyond the expected set was granted any access.
                foreach ($sid in $actualSids) {
                    $expectedSids | Should -Contain $sid
                }

                foreach ($rule in $acl.Access) {
                    $rule.AccessControlType | Should -Be ([System.Security.AccessControl.AccessControlType]::Allow)
                    $rule.FileSystemRights.ToString() | Should -Match 'FullControl'
                }
            }
        }
    }
}
