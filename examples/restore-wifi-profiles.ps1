param(
    [string]$BackupPath = "$env:ProgramData\NetClean\Backups"
)

if (-not (Test-Path $BackupPath)) { Write-Error "Backup path not found: $BackupPath"; exit 1 }

$xmlFiles = Get-ChildItem -LiteralPath $BackupPath -Filter '*.xml' -File -ErrorAction SilentlyContinue
if (-not $xmlFiles) { Write-Output "No Wi-Fi profile exports found in $BackupPath"; exit 0 }

$failed = [System.Collections.Generic.List[string]]::new()

foreach ($f in $xmlFiles) {
    Write-Output "Importing profile: $($f.Name)"
    $output = netsh wlan add profile filename="$($f.FullName)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Imported: $($f.Name)"
    }
    else {
        Write-Warning "Failed to import $($f.Name): $output"
        [void]$failed.Add($f.Name)
    }
}

if ($failed.Count -gt 0) {
    Write-Output "Wi-Fi restore complete with $($failed.Count) failure(s): $($failed -join ', ')"
    exit 1
}

Write-Output "Wi-Fi restore complete."
