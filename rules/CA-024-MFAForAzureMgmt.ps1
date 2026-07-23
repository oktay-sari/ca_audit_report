# Rule: CA-024 - No policy requires MFA for Azure management
# Type: cross-policy | Tier: static

function Test-CACrossRule-024 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    # Azure management app IDs
    $azureMgmtApps = @(
        '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Windows Azure Service Management API
        'MicrosoftAdminPortals'                    # Microsoft Admin Portals
        'All'                                      # All apps also covers Azure mgmt
    )

    $hasMfaForAzure = $false

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

        # Targets Azure management apps?
        $includeApps = @($policy.conditions.applications.includeApplications | Where-Object { $_ })
        $targetsAzure = ($azureMgmtApps | Where-Object { $_ -in $includeApps }).Count -gt 0
        if ($targetsAzure) {
            $hasMfaForAzure = $true
            break
        }
    }

    if (-not $hasMfaForAzure) {
        return New-CAFinding -Id 'CA-024' `
            -Name 'No Conditional Access policy requires MFA for Azure management' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy requires MFA for Azure management (Azure portal, ARM API, or Microsoft Admin Portals). These are high-value targets - an attacker with a compromised password can manage subscriptions, modify tenant settings, or access billing.' `
            -Remediation 'Create a policy targeting Windows Azure Service Management API (797f4846-ba00-4fd7-ba43-dac1f8f63013) and/or Microsoft Admin Portals with MFA or authentication strength required.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-024' `
            -Name 'MFA required for Azure management' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires MFA for Azure management or admin portals.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
