# Rule: CA-007 - All users / All apps with no MFA or device grant
# Type: per-policy | Tier: static
# NOTE: This flags policies that target everyone for everything but don't require
#       any authentication control. Typically misconfigurations or placeholder policies.

function Test-CARule-007 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Targets all users?
    $includeUsers = @($Policy.conditions.users.includeUsers | Where-Object { $_ })
    if ('All' -notin $includeUsers) { return }

    # Targets all apps?
    $includeApps = @($Policy.conditions.applications.includeApplications | Where-Object { $_ })
    if ('All' -notin $includeApps) { return }

    # Has any security grant?
    $g = $Policy.grantControls
    if ($null -eq $g) {
        return New-CAFinding -Id 'CA-007' `
            -Name 'All users / All apps with no grant controls' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail 'This policy targets all users and all applications but has no grant controls (session-only or empty). It applies universally but enforces nothing.' `
            -Remediation 'Add appropriate grant controls (MFA, compliant device, or authentication strength) or narrow the scope.' `
            -Status 'Fail'
    }

    $builtIn = @($g.builtInControls | Where-Object { $_ })
    $hasBlock = 'block' -in $builtIn
    $hasMfa = 'mfa' -in $builtIn
    $hasCompliant = 'compliantDevice' -in $builtIn
    $hasAuthStrength = $null -ne $g.authenticationStrength
    $hasAppProtection = 'compliantApplication' -in $builtIn

    # Block is fine - that's intentional
    if ($hasBlock) { return }

    # No meaningful control
    if (-not ($hasMfa -or $hasCompliant -or $hasAuthStrength -or $hasAppProtection)) {
        return New-CAFinding -Id 'CA-007' `
            -Name 'All users / All apps with no security grant' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This policy targets all users and all applications but the grant controls ($($builtIn -join ', ')) do not include MFA, compliant device, authentication strength, or app protection." `
            -Remediation 'Add MFA, compliant device, or authentication strength as a grant control, or narrow the policy scope.' `
            -Status 'Fail'
    }
}
