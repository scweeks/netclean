Import-Module PSScriptAnalyzer -ErrorAction Stop
$r = Invoke-ScriptAnalyzer -Path . -Recurse
if ($null -ne $r) {
    $r | Select-Object ScriptName,Line,RuleName,Severity,Message | Format-Table -AutoSize
    exit 2
}
else { Write-Host 'No PSScriptAnalyzer findings'; exit 0 }
