# Rule: CA-031 - Token protection not deployed
# Type: cross-policy | Tier: static
# Modern control (baseline "Could Have"): token protection (secureSignInSession)
# binds a sign-in session token to the device, defeating token replay/theft.

function Test-CACrossRule-031 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $present = $false
    foreach ($policy in $activePolicies) {
        if ($policy.sessionControls.secureSignInSession.isEnabled -eq $true) { $present = $true; break }
    }

    if ($present) {
        return New-CAFinding -Id 'CA-031' `
            -Name 'Token protection is deployed' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy enforces token protection (secureSignInSession).' `
            -Remediation 'Keep enabled and expand coverage to Exchange Online, SharePoint Online, and Cloud PC on Windows.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and $_.sessionControls.secureSignInSession.isEnabled -eq $true
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-031' `
        -Name 'No Conditional Access policy enforces token protection' `
        -Severity 'Low' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy enforces token protection. Token protection binds the sign-in session token to the device, so a stolen/replayed token cannot be used elsewhere. It is an emerging control, currently scoped to Exchange Online, SharePoint Online, and Cloud PC on Windows.$extraNote" `
        -Remediation 'Add a session control requiring token protection for Exchange Online / SharePoint Online / Cloud PC on Windows, targeting modern-auth clients.' `
        -Status 'Fail'
}
