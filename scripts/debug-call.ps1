Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop
$out1 = Convert-RegKeyPath -Path 'Microsoft.PowerShell.Core\Registry::HKLM:\Software\Foo'
$out2 = Convert-RegKeyPath -Path 'HKLM:\Software\Foo'
Write-Output "OUT1:'$out1'"
Write-Output "OUT2:'$out2'"
Write-Output "Chars OUT1: $([string]::Join(',',($out1.ToCharArray() | ForEach-Object {[int]$_})))"
Write-Output "Chars OUT2: $([string]::Join(',',($out2.ToCharArray() | ForEach-Object {[int]$_})))"
