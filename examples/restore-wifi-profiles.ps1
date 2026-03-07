param(
    [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups"
)

if (-not (Test-Path $BackupPath)) { Write-Error "Backup path not found: $BackupPath"; exit 1 }

$xmlFiles = Get-ChildItem -Path $BackupPath -Filter 'WiFiProfile_*.xml' -File -ErrorAction SilentlyContinue
if (-not $xmlFiles) { Write-Host "No Wi‑Fi profile exports found in $BackupPath"; exit 0 }

foreach ($f in $xmlFiles) {
    Write-Host "Importing profile: $($f.Name)"
    try { netsh wlan add profile filename="$($f.FullName)" | Out-Null; Write-Host "Imported: $($f.Name)" -ForegroundColor Green } catch { Write-Warning "Failed to import $($f.Name): $_" }
}

Write-Host "Wi‑Fi restore complete." -ForegroundColor Green
