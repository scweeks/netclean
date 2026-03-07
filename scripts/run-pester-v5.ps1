# Install/Run Pester v5 and run tests
Install-Module -Name Pester -Force -Scope CurrentUser -MinimumVersion 5.0.0 -AllowClobber -ErrorAction Stop
Import-Module Pester -ErrorAction Stop
$r = Invoke-Pester -Script (Join-Path $PSScriptRoot '..\tests') -PassThru
Write-Host "Pester: Passed=$($r.PassedCount) Failed=$($r.FailedCount)"
if ($r.FailedCount -gt 0) { exit 3 } else { exit 0 }
