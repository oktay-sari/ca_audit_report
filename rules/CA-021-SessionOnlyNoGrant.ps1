# Rule: CA-021 - Policy with no grant controls (session-only)
# Type: per-policy | Tier: static

function Test-CARule-021 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    if ($null -ne $Policy.grantControls) { return }

    # Check if there are meaningful session controls
    $s = $Policy.sessionControls
    $hasSession = $false

    if ($null -ne $s) {
        if ($s.signInFrequency.isEnabled) { $hasSession = $true }
        if ($s.persistentBrowser.isEnabled) { $hasSession = $true }
        if ($s.cloudAppSecurity.isEnabled) { $hasSession = $true }
        if ($s.applicationEnforcedRestrictions.isEnabled) { $hasSession = $true }
    }

    if ($hasSession) {
        # Session-only with actual session controls - informational only
        return New-CAFinding -Id 'CA-021' `
            -Name 'Session-only policy (no grant controls)' `
            -Severity 'Info' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail 'This policy has session controls but no grant controls. It controls session behavior (sign-in frequency, app restrictions, MCAS) without requiring authentication. This is a valid pattern but should be intentional.' `
            -Remediation 'Verify this is by design. If the policy should also enforce MFA or device compliance, add grant controls.' `
            -Status 'Pass'
    }
    else {
        # No grant AND no session = no-op
        return New-CAFinding -Id 'CA-021' `
            -Name 'Policy with no grant or session controls' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail 'This policy has no grant controls and no session controls. It evaluates but enforces nothing - effectively a no-op.' `
            -Remediation 'Add appropriate controls or disable the policy if it serves no purpose.' `
            -Status 'Fail'
    }
}
