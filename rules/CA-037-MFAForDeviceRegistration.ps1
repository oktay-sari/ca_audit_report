# Rule: CA-037 - MFA not required for device join/registration
# Type: cross-policy | Tier: static
# Modern control (baseline "Must Have"): the register-device user action should
# require MFA, so an attacker with only a password cannot register a device.

function Test-CACrossRule-037 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $covered = $false
    foreach ($policy in $activePolicies) {
        $actions = @($policy.conditions.applications.includeUserActions | Where-Object { $_ })
        if ('urn:user:registerdevice' -notin $actions) { continue }
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
        $hasAuthStrength = $null -ne $g.authenticationStrength
        if ($hasMfa -or $hasAuthStrength) { $covered = $true; break }
    }

    if ($covered) {
        return New-CAFinding -Id 'CA-037' `
            -Name 'MFA required for device join/registration' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires MFA (or authentication strength) for the register-device user action.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }

    $reportOnly = @($Policies | Where-Object {
        $_.state -eq 'enabledForReportingButNotEnforced' -and
        'urn:user:registerdevice' -in @($_.conditions.applications.includeUserActions | Where-Object { $_ }) -and
        (($_.grantControls.builtInControls -and 'mfa' -in $_.grantControls.builtInControls) -or $null -ne $_.grantControls.authenticationStrength)
    })
    $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

    return New-CAFinding -Id 'CA-037' `
        -Name 'No Conditional Access policy requires MFA for device join/registration' `
        -Severity 'Medium' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "No active (On) Conditional Access policy requires MFA for the register-device user action (urn:user:registerdevice). Without it, an attacker who has only a password can register or join a device, which can then be used to satisfy compliant/hybrid-device controls.$extraNote" `
        -Remediation 'Create or enable a policy targeting the register/join device user action with grant = Require MFA (or an authentication strength), excluding break-the-glass accounts.' `
        -Status 'Fail'
}
