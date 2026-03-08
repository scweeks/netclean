try {
    $text = Get-Content -Raw -Path "e:\DevRepos\NetworkCleaner\netclean\Netclean.psm1"
    [scriptblock]::Create($text) | Out-Null
    Write-Output "PARSE_OK"
}
catch {
    Write-Output "PARSE_ERROR"
    if ($_.Exception) { Write-Output $_.Exception.ToString() }
    if ($_.InvocationInfo) { Write-Output $_.InvocationInfo.PositionMessage }
    exit 1
}