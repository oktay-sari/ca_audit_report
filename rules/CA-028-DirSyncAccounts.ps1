# Rule: CA-028 - Directory sync accounts not properly handled
# Type: cross-policy | Tier: static
#
# Directory synchronization accounts (Entra Connect / Cloud Sync) must be excluded
# from CA policies or not scoped by them, because CA can break sync.
# The well-known role template ID for this role is d29b2b05-8046-44ba-8758-1e26182fcf32.

function Test-CACrossRule-028 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $dirSyncRoleId = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
    $activePolicies = @($Policies | Where-Object { $_.state -eq 'enabled' })

    # Check if any "All users" policy includes the dir sync role without excluding it
    $problemPolicies = @()
    # Count the policies this control could actually apply to (active, All-Users,
    # with a security-bearing grant). If there are none, there is nothing from
    # which to exclude sync accounts - the control is Not Applicable, NOT a pass.
    $candidateCount = 0

    foreach ($policy in $activePolicies) {
        $users = $policy.conditions.users
        $includeUsers = @($users.includeUsers | Where-Object { $_ })

        # Only relevant for policies that target "All users" (dir sync accounts are implicitly included)
        if ('All' -notin $includeUsers) { continue }

        # Does it have a security-bearing grant that could break sync?
        $g = $policy.grantControls
        if ($null -eq $g) { continue }
        $builtIn = @($g.builtInControls | Where-Object { $_ })
        $hasMfa = 'mfa' -in $builtIn
        $hasBlock = 'block' -in $builtIn
        $hasCompliant = 'compliantDevice' -in $builtIn
        $hasAuthStrength = $null -ne $g.authenticationStrength

        if (-not ($hasMfa -or $hasBlock -or $hasCompliant -or $hasAuthStrength)) { continue }

        # This policy is a candidate the control genuinely applies to.
        $candidateCount++

        # Is the dir sync role excluded?
        $excludeRoles = @($users.excludeRoles | Where-Object { $_ })
        if ($dirSyncRoleId -in $excludeRoles) { continue }

        # Dir sync accounts might be covered by an excluded group,
        # but we can't verify group membership offline
        $problemPolicies += $policy.displayName
    }

    if ($problemPolicies.Count -gt 0) {
        $names = $problemPolicies -join ', '
        return New-CAFinding -Id 'CA-028' `
            -Name 'Directory sync accounts may not be excluded from CA policies' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail "$($problemPolicies.Count) active All-Users policy/policies with MFA/device/block controls do not explicitly exclude the Directory Synchronization Accounts role ($dirSyncRoleId): $names. If Entra Connect or Cloud Sync service accounts are subject to these policies, synchronization may fail. Note: they may be excluded via a group - verify if exclusion groups contain sync accounts." `
            -Remediation 'Exclude the Directory Synchronization Accounts role from MFA/device/block policies, or ensure sync accounts are in an excluded group. Alternatively, use workload identity policies for sync accounts.' `
            -Status 'Fail'
    }

    if ($candidateCount -eq 0) {
        # No active All-Users policy with security-bearing controls exists, so there
        # is no enforcing policy from which sync accounts would need to be excluded.
        # This is Not Applicable - it must NOT count as a covered baseline control.
        return New-CAFinding -Id 'CA-028' `
            -Name 'Directory sync account exclusion not applicable (no enforcing policy)' `
            -Severity 'Info' `
            -Requires 'static' `
            -PolicyName '(baseline check)' `
            -Detail "No active All-Users Conditional Access policy with security-bearing controls (MFA / managed device / block) exists, so there is currently no enforcing policy from which the Directory Synchronization Accounts role ($dirSyncRoleId) would need to be excluded. This control cannot be satisfied or failed until such a policy is in place - it is reported as Not Applicable rather than covered." `
            -Remediation 'When you add an enforcing All-Users policy (e.g. Require MFA for all users), exclude the Directory Synchronization Accounts role, or place the sync accounts in an excluded group.' `
            -Status 'NotApplicable'
    }

    return New-CAFinding -Id 'CA-028' `
        -Name 'Directory sync accounts properly handled' `
        -Severity 'Good' `
        -Requires 'static' `
        -PolicyName '(baseline check)' `
        -Detail "All $candidateCount active All-Users policy/policies with security-bearing controls (MFA/device/block) exclude the Directory Synchronization Accounts role ($dirSyncRoleId). Offline check: if sync accounts are excluded via a group rather than the role, membership is not verified." `
        -Remediation 'Keep the Directory Synchronization Accounts role (or a group containing the sync accounts) excluded from MFA/device/block policies.' `
        -Status 'Pass'
}
