# Generates coverage JSON for NetClean.psm1
$result = Invoke-Pester -Script 'tests' -CodeCoverage @('NetClean.psm1')
if ($null -eq $result) { Write-Error 'Invoke-Pester returned no result'; exit 2 }
$cc = $result.CodeCoverage
if ($null -eq $cc) { Write-Output 'No CodeCoverage data'; exit 3 }
$cc | ConvertTo-Json -Depth 10 | Out-File -FilePath tests/TestResults/coverage.json -Encoding utf8
Write-Output 'WROTE_COVERAGE_JSON'