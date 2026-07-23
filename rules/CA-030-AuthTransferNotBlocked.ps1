# Rule: CA-030 - Authentication transfer flow not blocked
# Type: cross-policy | Tier: static
# Modern control (baseline "Must Have"): blocking authentication transfer stops
# an AiTM phishing technique where a session is handed to an attacker device.

function Test-CACrossRule-030 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $blocks = $false
    foreach ($policy in $activePolicies) {
        $g = $policy.grantControls
        if ($null -eq $g -or -not ($g.builtInControls -and 'block' -in $g.builtInControls)) { continue }
        $methods = $policy.conditions.authenticationFlows.transferMethods
        if (-not $methods) { continue }
        $methodList = if ($methods -is [string]) { $methods -split ',' } else { @($methods) }
        if ('authenticationTransfer' -in ($methodList | ForEach-Object { $_.Trim() })) { $blocks = $true; break }
    }

    if ($blocks) {
        return New-CAFinding -Id 'CA-030' `
            -Name 'Authentication transfer is blocked' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy blocks the authentication transfer flow.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        $_.grantControls.builtInControls -and 'block' -in $_.grantControls.builtInControls -and
        $_.conditions.authenticationFlows.transferMethods -match 'authenticationTransfer'
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-030' `
        -Name 'No Conditional Access policy blocks the authentication-transfer flow' `
        -Severity 'High' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy blocks the authentication transfer flow. Authentication transfer lets a signed-in session be handed to another device; attackers abuse it in Adversary-in-the-Middle (AiTM) phishing to move a phished session onto their own device.$extraNote" `
        -Remediation 'Create or enable a policy for All users (except break-the-glass) using the authenticationFlows condition with transferMethods = authenticationTransfer and grant = Block.' `
        -Status 'Fail'
}
