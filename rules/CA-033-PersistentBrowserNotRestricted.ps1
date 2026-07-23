# Rule: CA-033 - Persistent browser session not restricted
# Type: cross-policy | Tier: static
# Modern control (baseline "Must Have"): disabling browser persistence stops
# "stay signed in" from keeping sessions alive on shared/non-compliant devices.

function Test-CACrossRule-033 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $present = $false
    foreach ($policy in $activePolicies) {
        $pb = $policy.sessionControls.persistentBrowser
        if ($pb.isEnabled -eq $true -and $pb.mode -eq 'never') { $present = $true; break }
    }

    if ($present) {
        return New-CAFinding -Id 'CA-033' `
            -Name 'Persistent browser session is restricted' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy disables persistent browser sessions (mode = never).' `
            -Remediation 'Keep enabled; ensure admins and browser access on non-compliant devices are covered.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        $_.sessionControls.persistentBrowser.isEnabled -eq $true -and
        $_.sessionControls.persistentBrowser.mode -eq 'never'
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-033' `
        -Name 'No Conditional Access policy restricts persistent browser sessions' `
        -Severity 'Medium' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy disables persistent browser sessions. 'Stay signed in' can keep a session alive indefinitely on shared or non-compliant devices, so a walk-up attacker inherits an authenticated session.$extraNote" `
        -Remediation 'Add a persistent-browser session control with mode = never for admins and for browser access on non-compliant devices.' `
        -Status 'Fail'
}
