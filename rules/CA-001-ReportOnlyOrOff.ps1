# Rule: CA-001 - Security policy in Report-only or Off
# Type: per-policy | Tier: static

function Test-CARule-001 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    $state = [string]$Policy.state

    # Only flag policies that have security-bearing controls. Includes device-based
    # (compliant / Hybrid-joined) and app-protection (approved / compliant app, MAM)
    # grants, not just MFA/block/auth-strength.
    $g = $Policy.grantControls
    $bic = $g.builtInControls
    $hasMfa = $bic -and ('mfa' -in $bic)
    $hasBlock = $bic -and ('block' -in $bic)
    $hasDevice = $bic -and (('compliantDevice' -in $bic) -or ('domainJoinedDevice' -in $bic))
    $hasAppProt = $bic -and (('approvedApplication' -in $bic) -or ('compliantApplication' -in $bic))
    $hasAuthStrength = $null -ne $g.authenticationStrength
    $hasPasswordChange = $bic -and ('passwordChange' -in $bic)
    $isSecurityPolicy = $hasMfa -or $hasBlock -or $hasDevice -or $hasAppProt -or $hasAuthStrength -or $hasPasswordChange

    if (-not $isSecurityPolicy) { return }

    if ($state -eq 'disabled') {
        # An Off policy enforces nothing. Report it as an informational finding
        # (lowest severity) rather than High, so it does not inflate the risk
        # counts. Genuine gaps (e.g. no policy enforces MFA) are still caught by
        # the baseline-existence rules regardless of this policy being disabled.
        return New-CAFinding -Id 'CA-001' `
            -Name 'Security policy is Off' `
            -Severity 'Info' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "Policy state is 'Off'. This security policy is disabled and enforces no controls. Flagged as informational - confirm this is intentional." `
            -Remediation 'If this is a backup or deprecated policy, consider removing it to avoid confusion. If it should be protecting users, enable it.' `
            -Status 'Fail'
    }

    if ($state -eq 'enabledForReportingButNotEnforced') {
        return New-CAFinding -Id 'CA-001' `
            -Name 'Security policy is Report-only' `
            -Severity 'Info' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "Policy state is 'Report-only'. Controls are logged but not enforced - users are not protected by this policy. Flagged as informational; a report-only policy is often intentional (staging before enforcement)." `
            -Remediation 'Review sign-in logs for impact, then promote to On if no business disruption is expected.' `
            -Status 'Fail'
    }
}
