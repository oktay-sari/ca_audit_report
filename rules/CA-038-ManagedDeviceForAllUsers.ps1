# Rule: CA-038 - No policy requires a managed device for all users
# Type: cross-policy | Tier: static

function Test-CACrossRule-038 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    $hasManagedDeviceForAll = $false

    foreach ($policy in $activePolicies) {
        # Targets all users?
        $includeUsers = @($policy.conditions.users.includeUsers | Where-Object { $_ })
        if ('All' -notin $includeUsers) { continue }

        # Risk-gated policies only enforce for risky sign-ins, not unconditionally.
        if (@($policy.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0 -or
            @($policy.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0) { continue }

        # Requires a compliant or hybrid-joined (managed) device?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $b = @($g.builtInControls | Where-Object { $_ })
        if (-not (('compliantDevice' -in $b) -or ('domainJoinedDevice' -in $b))) { continue }

        # Broad app scope?
        $includeApps = @($policy.conditions.applications.includeApplications | Where-Object { $_ })
        if ('All' -in $includeApps -or 'Office365' -in $includeApps) {
            $hasManagedDeviceForAll = $true
            break
        }
    }

    if (-not $hasManagedDeviceForAll) {
        $reportOnly = @($Policies | Where-Object {
            $_.state -eq 'enabledForReportingButNotEnforced' -and
            'All' -in @($_.conditions.users.includeUsers | Where-Object { $_ }) -and
            (('compliantDevice' -in @($_.grantControls.builtInControls)) -or ('domainJoinedDevice' -in @($_.grantControls.builtInControls)))
        })
        $extraNote = if ($reportOnly) { " A Report-only policy exists ('$($reportOnly[0].displayName)') but is not enforcing." } else { '' }

        return New-CAFinding -Id 'CA-038' `
            -Name 'No Conditional Access policy requires a managed device for all users' `
            -Severity 'Low' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail "No active Conditional Access policy requires a compliant or hybrid-joined device for all users on a broad app scope. Requiring a managed device is a strong control, but it is a Should-Have (not universal): it blocks unmanaged/BYOD devices and external guests, who cannot be device-compliant.$extraNote" `
            -Remediation 'Consider a policy for All users requiring Require compliant device OR Require Hybrid Entra joined device. Exclude break-the-glass accounts, and exclude guests/external users (they cannot satisfy device compliance) or pair with an app-protection alternative.' `
            -Status 'Fail'
    }
    else {
        return New-CAFinding -Id 'CA-038' `
            -Name 'Managed device required for all users' `
            -Severity 'Good' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail 'At least one active policy requires a compliant or hybrid-joined device for all users on a broad app scope.' `
            -Remediation 'Keep enabled.' `
            -Status 'Pass'
    }
}
