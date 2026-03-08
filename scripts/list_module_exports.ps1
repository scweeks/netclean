Import-Module -Name .\Netclean.psm1 -Force -ErrorAction Stop
$m = Get-Module -Name Netclean -ErrorAction SilentlyContinue
if ($m) {
    Get-Command -Module $m.Name -CommandType Function | ForEach-Object { Write-Output $_.Name }
}
else { Write-Output 'Module not loaded' }
