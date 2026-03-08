Import-Module -Name .\Netclean.psm1 -Force -ErrorAction Stop
Write-Output 'Call with empty Inventory (@())'
$r = Get-InstalledAV -Inventory @()
Write-Output "Result (literal): '$r'"
Write-Output "IsNull: $([string]::ValueOf($r -eq $null))"
Write-Output "IsArray: $([string]::ValueOf($r -is [System.Array]))"
Write-Output "Enumerable: $([string]::ValueOf($r -is [System.Collections.IEnumerable]))"
Write-Output "Count: $(@($r).Count)"
Write-Output 'Call with Inventory containing one AV'
$inv = @([pscustomobject]@{ Categories = @('AV'); Vendor = 'AcmeAV' })
$r2 = Get-InstalledAV -Inventory $inv
Write-Output "Result2 COUNT: $(@($r2).Count)"
$r2 | ForEach-Object { Write-Output "ITEM: $_" }
