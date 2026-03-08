Import-Module -Name (Join-Path $PSScriptRoot '..\Netclean.psm1') -Force -ErrorAction Stop
$cases = @(
    'Microsoft.PowerShell.Core\Registry::HKLM:\Software\Foo',
    'HKLM:\Software\Foo',
    'HKLM\\SOFTWARE\\MyKey',
    'HKLM:\\SOFTWARE\\MyKey\\'
)
$outFile = Join-Path $PSScriptRoot 'convert_inspect.txt'
"Inspecting Convert-RegKeyPath outputs" | Out-File -FilePath $outFile -Encoding UTF8
foreach ($c in $cases) {
    try {
        $o = Convert-RegKeyPath -Path $c
        $chars = ($o.ToCharArray() | ForEach-Object {[int]$_}) -join ','
        "IN: $c -> OUT: [$o] Len=$($o.Length) Chars=$chars" | Out-File -FilePath $outFile -Append -Encoding UTF8
    } catch {
        "IN: $c -> ERROR: $($_.Exception.Message)" | Out-File -FilePath $outFile -Append -Encoding UTF8
    }
}
Write-Output "Wrote $outFile"