# Rule: CA-016 - Exclusion group is empty or deleted
# Type: cross-policy | Tier: group-membership (Tier 2)
# Offline: emits NotEvaluated. With -ResolveNames: evaluates membership.

function Test-CACrossRule-016 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Collect all unique exclude group IDs
    $excludeGroupIds = @{}
    foreach ($policy in $activePolicies) {
        foreach ($gid in @($policy.conditions.users.excludeGroups | Where-Object { $_ })) {
            if (-not $excludeGroupIds.ContainsKey($gid)) { $excludeGroupIds[$gid] = @() }
            $excludeGroupIds[$gid] += $policy.displayName
        }
    }

    if ($excludeGroupIds.Count -eq 0) { return }

    $enriched = Test-CAEnrichmentAvailable
    $findings = @()

    foreach ($gid in $excludeGroupIds.Keys) {
        $groupName = (Resolve-CAIdentity -Id $gid -Type Group).DisplayName
        $usedIn = $excludeGroupIds[$gid]
        $policyList = $usedIn -join ', '

        # Offline - cannot verify membership.
        if (-not $enriched) {
            $findings += New-CAFinding -Id 'CA-016' `
                -Name 'Exclusion group membership not verified' `
                -Severity 'Critical' `
                -Requires 'group-membership' `
                -PolicyName $policyList `
                -Detail "Group '$groupName' ($gid) is used as an exclusion in $($usedIn.Count) policy/policies. Cannot verify whether this group is empty, deleted, or contains unexpected members without directory access. An empty exclusion group is harmless, but a deleted dynamic group that was never noticed is the classic CA backdoor." `
                -Remediation 'Run with -ResolveNames to check group membership, or manually verify in the Entra portal: (1) group exists, (2) membership is expected, (3) no stale/test accounts.' `
                -Status 'NotEvaluated'
            continue
        }

        $info = Get-CAGroupEnrichment -Id $gid

        # Enrichment ran but this group was skipped (transient Graph error).
        if ($null -eq $info) {
            $findings += New-CAFinding -Id 'CA-016' `
                -Name 'Exclusion group membership not verified' `
                -Severity 'Critical' `
                -Requires 'group-membership' `
                -PolicyName $policyList `
                -Detail "Group '$groupName' ($gid) is excluded from $($usedIn.Count) policy/policies. Membership could not be retrieved from Graph (transient error or insufficient permissions)." `
                -Remediation 'Re-run with -ResolveNames, or manually verify the group exists and its membership is expected in the Entra portal.' `
                -Status 'NotEvaluated'
            continue
        }

        # Deleted / non-existent group referenced as an exclusion - the backdoor.
        if (-not $info.Exists) {
            $findings += New-CAFinding -Id 'CA-016' `
                -Name 'Exclusion references a deleted group' `
                -Severity 'Critical' `
                -Requires 'group-membership' `
                -PolicyName $policyList `
                -Detail "Group ID $gid is excluded from $($usedIn.Count) policy/policies but no longer exists in the directory. A dangling exclusion is dead weight at best; if the ID is ever reused it silently becomes a bypass. Policies: $policyList." `
                -Remediation 'Remove the deleted group ID from the exclusion list in each affected policy.' `
                -Status 'Fail'
            continue
        }

        $dynamicNote = if ($info.IsDynamic) { ' This is a dynamic group - its membership can change automatically as its rule matches new objects.' } else { '' }

        # Empty but existing - harmless today, but flagged (default: Low).
        if ($info.MemberCount -eq 0) {
            $findings += New-CAFinding -Id 'CA-016' `
                -Name 'Exclusion group is empty' `
                -Severity 'Low' `
                -Requires 'group-membership' `
                -PolicyName $policyList `
                -Detail "Group '$groupName' ($gid) is excluded from $($usedIn.Count) policy/policies but currently has 0 members. This is harmless while empty, but the exclusion is latent scope: anyone added to the group later bypasses these controls with no further review.$dynamicNote" `
                -Remediation 'Confirm the empty exclusion is intentional. Remove it if unused, or ensure membership changes are governed (access review / PIM).' `
                -Status 'Pass'
            continue
        }

        # Populated group - pass, but surface the count for the reviewer.
        $findings += New-CAFinding -Id 'CA-016' `
            -Name 'Exclusion group membership verified' `
            -Severity 'Good' `
            -Requires 'group-membership' `
            -PolicyName $policyList `
            -Detail "Group '$groupName' ($gid) exists with $($info.MemberCount) member(s), excluded from $($usedIn.Count) policy/policies.$dynamicNote Verify the member list matches the intended break-glass / exclusion population." `
            -Remediation 'Periodically review the excluded members against the intended exclusion population.' `
            -Status 'Pass'
    }

    return $findings
}
