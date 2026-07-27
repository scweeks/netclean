@{
    Rules = @{
        # Keep defaults but explicitly enable common best-practice rules
        PSAvoidUsingCmdletAliases = @{ Enable = $true; Severity = 'Error' }
        PSAvoidUsingWriteHost = @{ Enable = $true; Severity = 'Warning' }
        PSUseApprovedVerbs = @{ Enable = $true; Severity = 'Warning' }
        # PSScriptAnalyzer 1.25.0 throws a NullReferenceException while this
        # rule resolves the module's explicit Export-ModuleMember command.
        # Keep the runner fail-closed and disable only the defective rule.
        PSReservedCmdletChar = @{ Enable = $false; Severity = 'Warning' }
        PSAvoidUsingInvokeExpression = @{ Enable = $true; Severity = 'Error' }
        PSAvoidGlobalVars = @{ Enable = $true; Severity = 'Warning' }
        PSUseShouldProcessForStateChangingFunctions = @{ Enable = $true; Severity = 'Warning' }
        UnexpectedAttribute = @{ Enable = $false; Severity = 'Warning' }
    }
}
