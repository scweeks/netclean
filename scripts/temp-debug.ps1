Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop
$tests = @(
    'Microsoft.PowerShell.Core\\Registry::HKLM:\\Software\\Foo',
    'HKLM:\\Software\\Foo',
    'HKLM\\SOFTWARE\\MyKey',
    "Microsoft.PowerShell.Core\\Registry::HKLM:\\SOFTWARE\\MyKey\\",
    'HKLM:\\SOFTWARE\\MyKey\\'
)
foreach ($t in $tests) {
    $out = Convert-RegKeyPath -Path $t
    $chars = ($out.ToCharArray() | ForEach-Object {[int]$_}) -join ','
    "$t -> [$out] (Len=$($out.Length)) Chars=$chars" | Out-File -FilePath (Join-Path $PSScriptRoot 'tmp_debug_out.txt') -Append -Encoding UTF8
}
Write-Output "Wrote debug output to tmp_debug_out.txt"