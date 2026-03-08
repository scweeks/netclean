Import-Module -Name .\Netclean.psm1 -Force -ErrorAction Stop
Get-Command -Name Get-InstalledAV -CommandType Function | Select-Object -ExpandProperty Definition
