# Rule: CA-008 - Legacy authentication not blocked
# Type: cross-policy | Tier: static

function Test-CACrossRule-008 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Look for any active policy that blocks legacy auth client types
    $legacyTypes = @('exchangeActiveSync', 'other')
    $blocksLegacy = $false

    foreach ($policy in $activePolicies) {
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $hasBlock = $g.builtInControls -and ('block' -in $g.builtInControls)
        if (-not $hasBlock) { continue }

        $clientApps = @($policy.conditions.clientAppTypes | Where-Object { $_ })
        # Check if this block policy targets legacy auth types
        $targetsLegacy = ($legacyTypes | Where-Object { $_ -in $clientApps }).Count -gt 0
        # Also accept 'all' client app types with a block
        if ($targetsLegacy -or ('all' -in $clientApps)) {
            $blocksLegacy = $true
            break
        }
    }

    if (-not $blocksLegacy) {
        return New-CAFinding -Id 'CA-008' `
            -Name 'No Conditional Access policy blocks legacy authentication' `
            -Severity 'Critical' `
            -Requires 'static' `
            -PolicyName '(none - cross-policy check)' `
            -Detail 'No active Conditional Access policy blocks legacy authentication (Exchange ActiveSync and Other clients). Legacy auth does not support MFA, making it the primary vector for password-spray and credential-stuffing attacks.' `
            -Remediation 'Create a policy that targets All users, All apps, with client app types set to Exchange ActiveSync + Other clients, and grant control set to Block.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-008' `
            -Name 'Legacy authentication is blocked' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(cross-policy check)' `
            -Detail 'At least one active policy blocks legacy authentication (Exchange ActiveSync / Other clients). This closes the most common MFA bypass vector.' `
            -Remediation 'Keep enabled. Monitor sign-in logs for remaining legacy auth attempts.' `
            -Status 'Pass'
    }
}
