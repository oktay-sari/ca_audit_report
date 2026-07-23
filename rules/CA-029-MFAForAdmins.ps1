# Rule: CA-029 - No policy requires MFA for admin roles
# Type: cross-policy | Tier: static
# NOTE: CA-004 checks the QUALITY of admin MFA (plain vs auth strength).
#       This rule checks whether admin MFA EXISTS at all.

function Test-CACrossRule-029 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasAdminMfa = $false

    foreach ($policy in $activePolicies) {
        # Has MFA, auth strength, or block?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }

        # Risk-gated policies only enforce MFA for risky sign-ins, not
        # unconditionally, so they don't satisfy this baseline on their own.
        if (@($policy.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0 -or
            @($policy.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0) { continue }

        $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
        $hasAuthStrength = $null -ne $g.authenticationStrength
        if (-not ($hasMfa -or $hasAuthStrength)) { continue }

        # Targets admin roles specifically?
        $roles = @($policy.conditions.users.includeRoles | Where-Object { $_ })
        if ($roles.Count -gt 0) {
            $hasAdminMfa = $true
            break
        }

        # "All users" with MFA also covers admins
        $includeUsers = @($policy.conditions.users.includeUsers | Where-Object { $_ })
        if ('All' -in $includeUsers) {
            $hasAdminMfa = $true
            break
        }
    }

    if (-not $hasAdminMfa) {
        return New-CAFinding -Id 'CA-029' `
            -Name 'No Conditional Access policy requires MFA for admin roles' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy requires MFA or authentication strength for admin directory roles. Admin accounts are the highest-value targets - without MFA, a compromised admin password gives an attacker full tenant control.' `
            -Remediation 'Create a policy targeting admin directory roles (Global Admin, User Admin, Exchange Admin, etc.) with authentication strength set to Phishing-resistant MFA. At minimum, require standard MFA.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-029' `
            -Name 'MFA required for admin roles' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires MFA or authentication strength for admin roles.' `
            -Remediation 'Keep enabled. See CA-004 for authentication strength quality.' `
            -Status 'Pass'
    }
}
