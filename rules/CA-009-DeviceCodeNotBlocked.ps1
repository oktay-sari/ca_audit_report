# Rule: CA-009 - Device-code flow not blocked
# Type: cross-policy | Tier: static

function Test-CACrossRule-009 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    # Look for any enforced policy that blocks device code flow
    $blocksDeviceCode = $false

    foreach ($policy in $activePolicies) {
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $hasBlock = $g.builtInControls -and ('block' -in $g.builtInControls)
        if (-not $hasBlock) { continue }

        # Check for authenticationFlows condition targeting deviceCodeFlow
        $authFlows = $policy.conditions.authenticationFlows
        if ($authFlows) {
            $methods = $authFlows.transferMethods
            if ($methods) {
                $methodList = if ($methods -is [string]) { $methods -split ',' } else { @($methods) }
                if ('deviceCodeFlow' -in ($methodList | ForEach-Object { $_.Trim() })) {
                    $blocksDeviceCode = $true
                    break
                }
            }
        }
    }

    if (-not $blocksDeviceCode) {
        # Check if there's a report-only policy (potential intent)
        $reportOnly = $Policies | Where-Object {
            $_.state -eq 'enabledForReportingButNotEnforced' -and
            $_.grantControls.builtInControls -and
            'block' -in $_.grantControls.builtInControls -and
            $_.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow'
        }

        $extraNote = if ($reportOnly) {
            " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing."
        } else { '' }

        return New-CAFinding -Id 'CA-009' `
            -Name 'No Conditional Access policy blocks device-code flow' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail "No active (On) Conditional Access policy blocks the device-code authentication flow. Device-code phishing is a growing attack vector where attackers trick users into entering a code on a legitimate Microsoft page.$extraNote" `
            -Remediation 'Create or enable a policy that blocks the device-code flow for all users (except break-the-glass accounts). Use the authenticationFlows condition with transferMethods = deviceCodeFlow and grant = Block.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-009' `
            -Name 'Device-code flow is blocked' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy blocks device-code authentication flow.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
