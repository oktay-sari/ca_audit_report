# Rule: CA-036 - Exchange ActiveSync not blocked
# Type: cross-policy | Tier: static
# Modern control (baseline "Must Have"): Exchange ActiveSync is a legacy client
# path that can bypass modern-auth controls; it should be explicitly blocked.
# Complements CA-008 (legacy authentication) with an EAS-specific check.

function Test-CACrossRule-036 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $blocks = $false
    foreach ($policy in $activePolicies) {
        $g = $policy.grantControls
        if ($null -eq $g -or -not ($g.builtInControls -and 'block' -in $g.builtInControls)) { continue }
        $clientApps = @($policy.conditions.clientAppTypes | Where-Object { $_ })
        if ('exchangeActiveSync' -in $clientApps) { $blocks = $true; break }
    }

    if ($blocks) {
        return New-CAFinding -Id 'CA-036' `
            -Name 'Exchange ActiveSync is blocked' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy blocks Exchange ActiveSync clients.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        $_.grantControls.builtInControls -and 'block' -in $_.grantControls.builtInControls -and
        'exchangeActiveSync' -in @($_.conditions.clientAppTypes | Where-Object { $_ })
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-036' `
        -Name 'No Conditional Access policy blocks Exchange ActiveSync' `
        -Severity 'Medium' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy explicitly blocks Exchange ActiveSync clients. EAS is a legacy client protocol that can bypass modern-auth Conditional Access; leaving it open is a common gap even when broader legacy-auth blocking (CA-008) is in place.$extraNote" `
        -Remediation 'Create or enable a policy for All users (except break-the-glass) with clientAppTypes including exchangeActiveSync and grant = Block.' `
        -Status 'Fail'
}
