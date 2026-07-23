# Rule: CA-026 - No policy requires compliant/hybrid device for admins
# Type: cross-policy | Tier: static

function Test-CACrossRule-026 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasDeviceForAdmins = $false

    foreach ($policy in $activePolicies) {
        # Has compliant device or domain-joined requirement?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $hasCompliant = $g.builtInControls -and ('compliantDevice' -in $g.builtInControls)
        $hasDomainJoined = $g.builtInControls -and ('domainJoinedDevice' -in $g.builtInControls)
        if (-not ($hasCompliant -or $hasDomainJoined)) { continue }

        # Targets admin roles?
        $roles = @($policy.conditions.users.includeRoles | Where-Object { $_ })
        if ($roles.Count -gt 0) {
            $hasDeviceForAdmins = $true
            break
        }

        # Also accept: "All users" with device requirement (admins are included)
        $includeUsers = @($policy.conditions.users.includeUsers | Where-Object { $_ })
        if ('All' -in $includeUsers) {
            $hasDeviceForAdmins = $true
            break
        }
    }

    if (-not $hasDeviceForAdmins) {
        return New-CAFinding -Id 'CA-026' `
            -Name 'No Conditional Access policy requires a managed device for admins' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'No active Conditional Access policy requires a compliant or Hybrid Entra joined device for admin roles. Admins can access tenant resources from unmanaged personal devices, which may not have endpoint protection, disk encryption, or security baselines.' `
            -Remediation 'Create a policy targeting admin directory roles with grant control set to Require compliant device or Require Hybrid Entra joined device.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-026' `
            -Name 'Managed device required for admins' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires a compliant or Hybrid Entra joined device for admin roles.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
