# Rule: CA-012 - Grant operator OR weakens layered controls
# Type: per-policy | Tier: static

function Test-CARule-012 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    $g = $Policy.grantControls
    if ($null -eq $g) { return }
    if ($g.operator -ne 'OR') { return }

    $builtIn = @($g.builtInControls | Where-Object { $_ })
    $hasAuthStrength = $null -ne $g.authenticationStrength

    # OR only matters when there are 2+ controls
    $controlCount = $builtIn.Count + $(if ($hasAuthStrength) { 1 } else { 0 })
    if ($controlCount -lt 2) { return }

    # Specifically flag: MFA OR compliantDevice - compliant device alone satisfies, no MFA
    $hasMfa = 'mfa' -in $builtIn
    $hasCompliant = 'compliantDevice' -in $builtIn

    if ($hasMfa -and $hasCompliant) {
        return New-CAFinding -Id 'CA-012' `
            -Name 'OR operator: compliant device alone satisfies MFA requirement' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "Grant requires 'ONE of' MFA + compliant device. A compliant device alone satisfies this - no MFA challenge occurs. If the device is compromised or the compliance state is stale, there is no second factor." `
            -Remediation "Change the operator to 'Require ALL selected controls' (AND) so both MFA and compliant device are required, or remove one of the controls if OR is intentional." `
            -Status 'Fail'
    }
}
