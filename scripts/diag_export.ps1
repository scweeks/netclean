Import-Module .\Netclean.psm1 -Force -Verbose
$r = Export-ProtectedRegistryKey -Paths @('HKLM:\SOFTWARE\MyKey') -Dest (Join-Path $env:TEMP 'netclean_test') -DryRun
Write-Output "TYPE: $($r -ne $null ? $r.GetType().FullName : '<null>')"
Write-Output "ISARRAY: $($r -is [array])"
Write-Output "COUNT: $($r.Count)"
if ($r -is [array]) { $r | ForEach-Object { Write-Output ("ITEM: $_") } } else { Write-Output ("VALUE: $r") }