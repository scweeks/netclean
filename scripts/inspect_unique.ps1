Import-Module -Name .\Netclean.psm1 -Force -ErrorAction Stop
$out = Get-UniqueNonEmptyStrings -InputObject $null
Write-Output "OUT: $out"
Write-Output "TYPE: $($out -is [array])"
Write-Output "COUNT: $(@($out).Count)"
