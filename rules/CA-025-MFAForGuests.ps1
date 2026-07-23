# Rule: CA-025 - No policy requires MFA for guest/external access
# Type: cross-policy | Tier: static

function Test-CACrossRule-025 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasMfaForGuests = $false

    foreach ($policy in $activePolicies) {
        # Has MFA or auth strength?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }

        # Risk-gated policies only enforce MFA for risky sign-ins, not
        # unconditionally, so they don't satisfy this baseline on their own.
        if (@($policy.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0 -or
            @($policy.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0) { continue }

        $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
        $hasAuthStrength = $null -ne $g.authenticationStrength
        if (-not ($hasMfa -or $hasAuthStrength)) { continue }

        # Targets guests or external users?
        $users = $policy.conditions.users

        # Check includeGuestsOrExternalUsers
        if ($users.includeGuestsOrExternalUsers.guestOrExternalUserTypes) {
            $hasMfaForGuests = $true
            break
        }

        # Also accept: "All users" includes guests by default
        $includeUsers = @($users.includeUsers | Where-Object { $_ })
        if ('All' -in $includeUsers -or 'GuestsOrExternalUsers' -in $includeUsers) {
            $hasMfaForGuests = $true
            break
        }
    }

    if (-not $hasMfaForGuests) {
        return New-CAFinding -Id 'CA-025' `
            -Name 'No Conditional Access policy requires MFA for guest access' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy requires MFA for guest or external users. External users (B2B guests, service providers) accessing your tenant resources without MFA is a significant risk, especially for organizations sharing sensitive data with partners.' `
            -Remediation 'Create a policy targeting guest/external user types (B2B collaboration guests at minimum) with MFA or authentication strength required. Consider phishing-resistant MFA for high-trust partners.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-025' `
            -Name 'MFA required for guest access' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires MFA for guest or external users.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
