# Rule: CA-005 - Deprecated grant control (approvedApplication alone)
# Type: per-policy | Tier: static

function Test-CARule-005 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    $g = $Policy.grantControls
    if ($null -eq $g) { return }

    $builtIn = @($g.builtInControls | Where-Object { $_ })

    # approvedApplication is deprecated as of March 2026
    if ('approvedApplication' -in $builtIn) {
        $isAlone = $builtIn.Count -eq 1
        $severity = if ($isAlone) { 'Medium' } else { 'Low' }
        $aloneNote = if ($isAlone) { ' It is the ONLY grant control, so this policy offers no protection once enforcement ends.' } else { '' }

        return New-CAFinding -Id 'CA-005' `
            -Name 'Deprecated grant control: Require approved client app' `
            -Severity $severity `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This policy uses 'Require approved client app' (approvedApplication) which Microsoft deprecated. Enforcement ends March 2026.$aloneNote" `
            -Remediation "Replace 'Require approved client app' with 'Require app protection policy' (compliantApplication) which provides equivalent or stronger protection." `
            -Status 'Fail'
    }
}
