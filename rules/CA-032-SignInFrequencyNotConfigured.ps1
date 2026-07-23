# Rule: CA-032 - Sign-in frequency not configured
# Type: cross-policy | Tier: static
# Modern control (baseline "Must Have"): sign-in frequency forces periodic
# re-authentication, limiting how long a stolen/persisted session stays usable.

function Test-CACrossRule-032 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $present = $false
    foreach ($policy in $activePolicies) {
        if ($policy.sessionControls.signInFrequency.isEnabled -eq $true) { $present = $true; break }
    }

    if ($present) {
        return New-CAFinding -Id 'CA-032' `
            -Name 'Sign-in frequency is configured' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy enforces a sign-in frequency session control.' `
            -Remediation 'Keep enabled; ensure admins and non-compliant/browser sessions are covered.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and $_.sessionControls.signInFrequency.isEnabled -eq $true
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-032' `
        -Name 'No Conditional Access policy configures sign-in frequency' `
        -Severity 'Medium' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy sets a sign-in frequency. Without it, sessions can persist far longer than intended, widening the window in which a stolen or hijacked token remains usable - especially for admins and browser sessions on non-compliant devices.$extraNote" `
        -Remediation 'Add a sign-in frequency session control for privileged roles and for browser access on non-compliant devices.' `
        -Status 'Fail'
}
