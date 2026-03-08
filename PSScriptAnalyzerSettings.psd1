@{
    Rules = @{
        # Keep defaults but explicitly enable common best-practice rules
        PSAvoidUsingCmdletAliases = @{ Enable = $true; Severity = 'Error' }
        PSAvoidUsingWriteHost = @{ Enable = $true; Severity = 'Warning' }
        PSUseApprovedVerbs = @{ Enable = $false; Severity = 'Warning' }
        PSAvoidUsingInvokeExpression = @{ Enable = $true; Severity = 'Error' }
        PSAvoidGlobalVars = @{ Enable = $true; Severity = 'Warning' }
        PSUseShouldProcessForStateChangingFunctions = @{ Enable = $true; Severity = 'Warning' }
        UnexpectedAttribute = @{ Enable = $false; Severity = 'Warning' }
    }
}
