Import-Module PSScriptAnalyzer -ErrorAction Stop
$results = Invoke-ScriptAnalyzer -Path . -Recurse | Where-Object { $_.RuleName -eq 'PSAvoidAssignmentToAutomaticVariable' }
if ($results) { $results | Select-Object ScriptName,Line,RuleName,Message | Format-List } else { Write-Host 'No PSAvoidAssignmentToAutomaticVariable findings' }
