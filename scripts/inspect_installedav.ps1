Import-Module -Name .\Netclean.psm1 -Force -ErrorAction Stop
$r = Get-InstalledAV -Inventory @()
if ($null -eq $r) { Write-Output 'NULL' } else {
    Write-Output ("COUNT:$(@($r).Count)")
    Write-Output ("TYPE:$($r.GetType().FullName)")
    foreach ($i in $r) { Write-Output ("ITEM:$i") }
}
