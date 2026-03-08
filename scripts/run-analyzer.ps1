Import-Module PSScriptAnalyzer -ErrorAction Stop
$settings = Join-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent) -ChildPath '../PSScriptAnalyzerSettings.psd1'
if (Test-Path $settings) { $r = Invoke-ScriptAnalyzer -Path . -SettingsPath $settings -Recurse -ErrorAction SilentlyContinue }
else { $r = Invoke-ScriptAnalyzer -Path . -Recurse -ErrorAction SilentlyContinue }

if ($null -ne $r) {
    $r | Select-Object ScriptName,Line,RuleName,Severity,Message | Format-Table -AutoSize
    exit 2
}
else { Write-Host 'No PSScriptAnalyzer findings'; exit 0 }
