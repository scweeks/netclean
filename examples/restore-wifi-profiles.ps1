param(
    [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups"
)

if (-not (Test-Path $BackupPath)) { Write-Error "Backup path not found: $BackupPath"; exit 1 }

$xmlFiles = Get-ChildItem -Path $BackupPath -Filter 'WiFiProfile_*.xml' -File -ErrorAction SilentlyContinue
if (-not $xmlFiles) { Write-Output "No Wi-Fi profile exports found in $BackupPath"; exit 0 }

foreach ($f in $xmlFiles) {
    Write-Output "Importing profile: $($f.Name)"
    try { netsh wlan add profile filename="$($f.FullName)" | Out-Null; Write-Output "Imported: $($f.Name)" } catch { Write-Warning "Failed to import $($f.Name): $_" }
}
Write-Output "Wi-Fi restore complete."
