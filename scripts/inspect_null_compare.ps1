Write-Output "( $null -eq @() ) => $($null -eq @())"
Write-Output "( @() -eq $null ) => $(@() -eq $null)"
Write-Output "( $null -eq @() ) type => $(( $null -eq @()).GetType().FullName)"
