# Rule: CA-004 - Admins on plain MFA instead of authentication strength
# Type: per-policy | Tier: static

function Test-CARule-004 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Does this policy target admin roles?
    $roles = @($Policy.conditions.users.includeRoles | Where-Object { $_ })
    if ($roles.Count -eq 0) { return }

    # Does it use plain MFA (builtInControls) instead of authenticationStrength?
    $g = $Policy.grantControls
    if ($null -eq $g) { return }

    $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
    $hasAuthStrength = $null -ne $g.authenticationStrength

    if ($hasMfa -and -not $hasAuthStrength) {
        return New-CAFinding -Id 'CA-004' `
            -Name 'Admin roles use plain MFA, not authentication strength' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This policy targets $($roles.Count) directory role(s) but uses builtInControls 'mfa' instead of an authentication strength policy. Plain MFA allows weaker methods (SMS, voice) that are vulnerable to SIM-swap and MFA fatigue attacks. Privileged accounts should require phishing-resistant methods." `
            -Remediation "Switch the grant control from 'Require MFA' to an authentication strength policy (e.g., 'Phishing-resistant MFA' which requires FIDO2, Windows Hello, or certificate-based authentication)." `
            -Status 'Fail'
    }
}
