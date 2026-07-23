# Rule: CA-035 - MDCA session control not used
# Type: cross-policy | Tier: static
# Modern control (baseline "Could Have"): routing sessions through Defender for
# Cloud Apps (cloudAppSecurity) enables real-time monitoring / download blocking.

function Test-CACrossRule-035 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $present = $false
    foreach ($policy in $activePolicies) {
        if ($policy.sessionControls.cloudAppSecurity.isEnabled -eq $true) { $present = $true; break }
    }

    if ($present) {
        return New-CAFinding -Id 'CA-035' `
            -Name 'MDCA session control is used' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy routes sessions through Microsoft Defender for Cloud Apps (Conditional Access App Control).' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and $_.sessionControls.cloudAppSecurity.isEnabled -eq $true
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-035' `
        -Name 'No Conditional Access policy uses MDCA session control' `
        -Severity 'Info' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy routes sessions through Microsoft Defender for Cloud Apps (Conditional Access App Control). MDCA session control enables real-time session monitoring and download/upload blocking on unmanaged devices. It requires MDCA licensing, so it is optional depending on your tooling.$extraNote" `
        -Remediation 'If licensed for MDCA, add a Conditional Access App Control session control (Use Conditional Access App Control) for browser access on unmanaged/non-compliant devices.' `
        -Status 'Fail'
}
