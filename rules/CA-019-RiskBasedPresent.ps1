# Rule: CA-019 - Risk-based policies present (positive check)
# Type: cross-policy | Tier: static

function Test-CACrossRule-019 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasUserRisk = $false
    $hasSignInRisk = $false

    foreach ($policy in $activePolicies) {
        $userRisk = @($policy.conditions.userRiskLevels | Where-Object { $_ })
        $signInRisk = @($policy.conditions.signInRiskLevels | Where-Object { $_ })

        if ($userRisk.Count -gt 0) { $hasUserRisk = $true }
        if ($signInRisk.Count -gt 0) { $hasSignInRisk = $true }
    }

    if ($hasUserRisk -and $hasSignInRisk) {
        return New-CAFinding -Id 'CA-019' `
            -Name 'Risk-based policies are in place' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'Active policies cover both user risk and sign-in risk conditions, providing Identity Protection coverage. This enables automatic response to compromised credentials and suspicious sign-ins.' `
            -Remediation 'Keep enabled. Confirm Entra ID P2 licensing covers all in-scope users (risk policies only evaluate for P2-licensed users).' `
            -Status 'Pass'
    }

    $missing = @()
    if (-not $hasUserRisk) { $missing += 'user risk' }
    if (-not $hasSignInRisk) { $missing += 'sign-in risk' }

    return New-CAFinding -Id 'CA-019' `
        -Name 'Conditional Access risk-based policies incomplete' `
        -Severity 'Medium' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active Conditional Access policy covers: $($missing -join ', '). Risk-based policies enable automatic response to compromised credentials and suspicious sign-ins via Entra ID Identity Protection." `
        -Remediation "Create policies for the missing risk condition(s). For user risk: require password change + MFA on high risk. For sign-in risk: require MFA on medium+ risk, block on high. Requires Entra ID P2 licensing." `
        -Status 'Fail'
}
