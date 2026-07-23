# Rule: CA-006 - Same principal excluded from many policies
# Type: cross-policy | Tier: static

function Test-CACrossRule-006 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Count how many policies each group GUID is excluded from
    $groupExclusionCount = @{}

    foreach ($policy in $activePolicies) {
        $excludeGroups = @($policy.conditions.users.excludeGroups | Where-Object { $_ })
        foreach ($groupId in $excludeGroups) {
            if (-not $groupExclusionCount.ContainsKey($groupId)) {
                $groupExclusionCount[$groupId] = @()
            }
            $groupExclusionCount[$groupId] += $policy.displayName
        }
    }

    $findings = @()
    $threshold = 3  # Flag groups excluded from 3+ policies

    foreach ($groupId in $groupExclusionCount.Keys) {
        $policyNames = $groupExclusionCount[$groupId]
        if ($policyNames.Count -ge $threshold) {
            $groupName = (Resolve-CAIdentity -Id $groupId -Type Group).DisplayName
            $policyList = ($policyNames | Sort-Object) -join ', '

            $findings += New-CAFinding -Id 'CA-006' `
                -Name 'Group excluded from many policies' `
                -Severity 'High' `
                -Requires 'static' `
                -PolicyName ($policyNames -join ', ') `
                -Detail "Group '$groupName' ($groupId) is excluded from $($policyNames.Count) policies: $policyList. Members of this group bypass multiple security controls. If membership is not tightly controlled, this is a backdoor." `
                -Remediation 'Enumerate members of this group. Confirm each is authorized. Consider workload identity policies for service accounts instead of broad exclusions.' `
                -Status 'Fail'
        }
    }

    return $findings
}
