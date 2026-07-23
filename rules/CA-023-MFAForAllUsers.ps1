# Rule: CA-023 - No policy requires MFA for all users
# Type: cross-policy | Tier: static

function Test-CACrossRule-023 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasMfaForAll = $false

    foreach ($policy in $activePolicies) {
        # Targets all users?
        $includeUsers = @($policy.conditions.users.includeUsers | Where-Object { $_ })
        if ('All' -notin $includeUsers) { continue }

        # Skip policies gated by a risk condition: they only enforce MFA for risky
        # sign-ins, not for all users unconditionally, so they don't satisfy the
        # "MFA for all users" baseline on their own.
        $userRisk = @($policy.conditions.userRiskLevels | Where-Object { $_ })
        $signInRisk = @($policy.conditions.signInRiskLevels | Where-Object { $_ })
        if ($userRisk.Count -gt 0 -or $signInRisk.Count -gt 0) { continue }

        # Has MFA or auth strength?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
        $hasAuthStrength = $null -ne $g.authenticationStrength
        if (-not ($hasMfa -or $hasAuthStrength)) { continue }

        # Targets all apps or broad scope?
        $includeApps = @($policy.conditions.applications.includeApplications | Where-Object { $_ })
        if ('All' -in $includeApps -or 'Office365' -in $includeApps) {
            $hasMfaForAll = $true
            break
        }
    }

    if (-not $hasMfaForAll) {
        return New-CAFinding -Id 'CA-023' `
            -Name 'No Conditional Access policy requires MFA for all users' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy requires MFA (or authentication strength) for all users across all apps or Office 365. This is the most fundamental Conditional Access baseline. Without it, users may access cloud resources with only a password.' `
            -Remediation 'Create a policy targeting All users, All cloud apps, with grant control set to Require MFA or an authentication strength. Exclude break-the-glass accounts.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-023' `
            -Name 'MFA required for all users' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires MFA or authentication strength for all users on a broad app scope.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
