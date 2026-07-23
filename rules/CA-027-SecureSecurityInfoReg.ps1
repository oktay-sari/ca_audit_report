# Rule: CA-027 - Security info registration not secured
# Type: cross-policy | Tier: static

function Test-CACrossRule-027 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasSecuredRegistration = $false

    foreach ($policy in $activePolicies) {
        # Targets user action: register security info?
        $actions = @($policy.conditions.applications.includeUserActions | Where-Object { $_ })
        if ('urn:user:registersecurityinfo' -notin $actions) { continue }

        # Has MFA, auth strength, or location restriction?
        $g = $policy.grantControls
        $hasMfa = $g -and $g.builtInControls -and ('mfa' -in $g.builtInControls)
        $hasAuthStrength = $g -and $null -ne $g.authenticationStrength

        # Or: restricts to trusted locations only
        $locations = $policy.conditions.locations
        $hasLocationRestriction = $null -ne $locations -and
            @($locations.includeLocations | Where-Object { $_ }).Count -gt 0

        if ($hasMfa -or $hasAuthStrength -or $hasLocationRestriction) {
            $hasSecuredRegistration = $true
            break
        }
    }

    if (-not $hasSecuredRegistration) {
        return New-CAFinding -Id 'CA-027' `
            -Name 'No Conditional Access policy secures security-info registration' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy secures the "Register security information" user action with MFA or a trusted location restriction. An attacker who compromises a password can register their own MFA methods from anywhere, locking out the real user and establishing persistent access.' `
            -Remediation 'Create a policy targeting the user action "Register security information" with MFA required, ideally combined with a trusted location restriction so MFA methods can only be registered from corporate networks.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-027' `
            -Name 'Security info registration is secured' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy secures the registration of security information (MFA methods) with MFA or location restrictions.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
