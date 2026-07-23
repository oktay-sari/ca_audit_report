# Rule: CA-002 - Include/exclude set overlap (self-negation)
# Type: per-policy | Tier: static

function Test-CARule-002 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    # Skip disabled policies
    if ($Policy.state -eq 'disabled') { return }

    $users = $Policy.conditions.users
    $findings = @()

    # Check groups overlap
    $includeGroups = @($users.includeGroups | Where-Object { $_ })
    $excludeGroups = @($users.excludeGroups | Where-Object { $_ })

    if ($includeGroups.Count -gt 0 -and $excludeGroups.Count -gt 0) {
        $overlap = $includeGroups | Where-Object { $_ -in $excludeGroups }
        if ($overlap) {
            $overlapList = ($overlap | ForEach-Object {
                (Resolve-CAIdentity -Id $_ -Type Group).DisplayName
            }) -join ', '

            $findings += New-CAFinding -Id 'CA-002' `
                -Name 'Include/exclude group overlap (self-negation)' `
                -Severity 'Critical' `
                -Requires 'static' `
                -PolicyName $Policy.displayName `
                -Detail "Group(s) appear in BOTH includeGroups and excludeGroups: $overlapList. Exclude wins in CA evaluation, so this policy never applies to these groups. The policy looks like it protects them but does not." `
                -Remediation 'Remove the overlapping group(s) from either the include or exclude list. If the intent is to block these groups, remove them from the exclude.' `
                -Status 'Fail'
        }
    }

    # Check users overlap
    $includeUsers = @($users.includeUsers | Where-Object { $_ -and $_ -notin @('All','None','GuestsOrExternalUsers') })
    $excludeUsers = @($users.excludeUsers | Where-Object { $_ -and $_ -notin @('All','None','GuestsOrExternalUsers') })

    if ($includeUsers.Count -gt 0 -and $excludeUsers.Count -gt 0) {
        $overlap = $includeUsers | Where-Object { $_ -in $excludeUsers }
        if ($overlap) {
            $findings += New-CAFinding -Id 'CA-002' `
                -Name 'Include/exclude user overlap (self-negation)' `
                -Severity 'Critical' `
                -Requires 'static' `
                -PolicyName $Policy.displayName `
                -Detail "User(s) appear in BOTH includeUsers and excludeUsers. Exclude wins - this policy never applies to these users." `
                -Remediation 'Remove the overlapping user(s) from either the include or exclude list.' `
                -Status 'Fail'
        }
    }

    # Check roles overlap
    $includeRoles = @($users.includeRoles | Where-Object { $_ })
    $excludeRoles = @($users.excludeRoles | Where-Object { $_ })

    if ($includeRoles.Count -gt 0 -and $excludeRoles.Count -gt 0) {
        $overlap = $includeRoles | Where-Object { $_ -in $excludeRoles }
        if ($overlap) {
            $findings += New-CAFinding -Id 'CA-002' `
                -Name 'Include/exclude role overlap (self-negation)' `
                -Severity 'Critical' `
                -Requires 'static' `
                -PolicyName $Policy.displayName `
                -Detail "Role(s) appear in BOTH includeRoles and excludeRoles. Exclude wins - this policy never applies to these roles." `
                -Remediation 'Remove the overlapping role(s) from either the include or exclude list.' `
                -Status 'Fail'
        }
    }

    return $findings
}
