# Rule: CA-034 - Terms of Use not enforced
# Type: cross-policy | Tier: static
# Modern control (baseline "Could Have"): a Terms of Use grant records explicit
# user acceptance - often a compliance/guest-governance requirement.

function Test-CACrossRule-034 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $present = $false
    foreach ($policy in $activePolicies) {
        if (@($policy.grantControls.termsOfUse | Where-Object { $_ }).Count -gt 0) { $present = $true; break }
    }

    if ($present) {
        return New-CAFinding -Id 'CA-034' `
            -Name 'Terms of Use is enforced' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires acceptance of a Terms of Use.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and @($_.grantControls.termsOfUse | Where-Object { $_ }).Count -gt 0
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-034' `
        -Name 'No Conditional Access policy enforces Terms of Use' `
        -Severity 'Info' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy requires acceptance of a Terms of Use. A ToU grant records explicit, auditable user consent and is commonly required for guest/external access governance. Whether this is needed depends on your compliance obligations.$extraNote" `
        -Remediation 'If required by policy, create a Terms of Use in Entra and require it via a Conditional Access grant control (commonly scoped to guests).' `
        -Status 'Fail'
}
