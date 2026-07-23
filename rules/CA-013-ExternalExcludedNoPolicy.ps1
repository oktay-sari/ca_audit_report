# Rule: CA-013 - External principal excluded from multiple policies with no compensating policy
# Type: cross-policy | Tier: static

function Test-CACrossRule-013 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Collect external tenant IDs that are excluded via excludeGuestsOrExternalUsers
    $tenantExclusions = @{}  # tenantId -> list of policy names
    $tenantTargeted = @{}     # tenantId -> list of policy names that target this tenant

    foreach ($policy in $activePolicies) {
        $users = $policy.conditions.users

        # Check excludeGuestsOrExternalUsers for enumerated tenants
        $excludeGuests = $users.excludeGuestsOrExternalUsers
        if ($excludeGuests.externalTenants.members) {
            foreach ($tenantId in @($excludeGuests.externalTenants.members)) {
                if (-not $tenantExclusions.ContainsKey($tenantId)) { $tenantExclusions[$tenantId] = @() }
                $tenantExclusions[$tenantId] += $policy.displayName
            }
        }

        # Check includeGuestsOrExternalUsers for enumerated tenants (compensating policy)
        $includeGuests = $users.includeGuestsOrExternalUsers
        if ($includeGuests.externalTenants.members) {
            foreach ($tenantId in @($includeGuests.externalTenants.members)) {
                if (-not $tenantTargeted.ContainsKey($tenantId)) { $tenantTargeted[$tenantId] = @() }
                $tenantTargeted[$tenantId] += $policy.displayName
            }
        }
    }

    $findings = @()

    foreach ($tenantId in $tenantExclusions.Keys) {
        $excludedFrom = $tenantExclusions[$tenantId]
        if ($excludedFrom.Count -lt 2) { continue }

        # Is there a compensating policy for this tenant?
        $hasCompensating = $tenantTargeted.ContainsKey($tenantId)
        if ($hasCompensating) { continue }

        $tenantName = (Resolve-CAIdentity -Id $tenantId -Type Tenant).DisplayName

        $findings += New-CAFinding -Id 'CA-013' `
            -Name 'External tenant excluded with no compensating policy' `
            -Severity 'High' `
            -Requires 'static' `
            -PolicyName ($excludedFrom -join ', ') `
            -Detail "External tenant '$tenantName' ($tenantId) is excluded from $($excludedFrom.Count) policies ($($excludedFrom -join ', ')) but no policy specifically targets this tenant with strong authentication. Members of this external org may access resources without MFA or other controls." `
            -Remediation "Create a dedicated policy for this external tenant (e.g., require phishing-resistant MFA for B2B guests from this org) instead of blanket exclusions." `
            -Status 'Fail'
    }

    return $findings
}
