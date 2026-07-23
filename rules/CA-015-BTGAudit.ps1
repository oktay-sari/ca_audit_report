# Rule: CA-015 - Break-the-glass group audit
# Type: cross-policy | Tier: static
# NOTE: This is an Info-level finding - BTG exclusions are expected,
#       but their presence should be documented and verified.

function Test-CACrossRule-015 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Count exclusions per group. A group excluded from 50%+ of policies is likely BTG.
    $groupExclusionCount = @{}

    foreach ($policy in $activePolicies) {
        $excludeGroups = @($policy.conditions.users.excludeGroups | Where-Object { $_ })
        foreach ($groupId in $excludeGroups) {
            if (-not $groupExclusionCount.ContainsKey($groupId)) {
                $groupExclusionCount[$groupId] = 0
            }
            $groupExclusionCount[$groupId]++
        }
    }

    if ($activePolicies.Count -eq 0) { return }

    $findings = @()
    $threshold = [math]::Max(2, [math]::Floor($activePolicies.Count * 0.4))

    foreach ($groupId in $groupExclusionCount.Keys) {
        $count = $groupExclusionCount[$groupId]
        if ($count -ge $threshold) {
            $groupName = (Resolve-CAIdentity -Id $groupId -Type Group).DisplayName

            $findings += New-CAFinding -Id 'CA-015' `
                -Name 'Likely break-the-glass group detected' `
                -Severity 'Info' `
                -Requires 'static' `
                -PolicyName "(excluded from $count policies)" `
                -Detail "Group '$groupName' ($groupId) is excluded from $count of $($activePolicies.Count) active policies. This pattern indicates a break-the-glass (BTG) or emergency access group. BTG exclusions are expected but require verification." `
                -Remediation 'Verify: (1) BTG accounts use FIDO2 or very long passwords, (2) the group contains only authorized emergency accounts, (3) sign-in alerting is configured for BTG members, (4) credentials are stored securely (e.g., safe/vault).' `
                -Status 'Pass'
        }
    }

    return $findings
}
