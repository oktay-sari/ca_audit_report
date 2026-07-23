# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Export-CAReport.ps1

<#
.SYNOPSIS
    Row builders for the findings-based report tabs (Security Checks, Baseline
    Coverage, Platform Matrix, CA Policy Groups, Group Membership, Not Evaluated,
    Cross-Reference).

.DESCRIPTION
    Pure data builders - each Build-*Row function turns findings/policies into
    plain PSCustomObject rows. Export-CAHtml consumes these directly to render the
    interactive HTML report. (These once also fed an Excel export; that output was
    removed to drop the ImportExcel / EPPlus dependency - the row shapes are
    unchanged, so nothing about the report data changed.)
#>

# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

function Build-FindingRow {
    [CmdletBinding()]
    param([object[]] $FindingList)

    $num = 0
    $FindingList | ForEach-Object {
        $num++
        [PSCustomObject][ordered]@{
            '#'              = $num
            'Finding'        = $_.Name
            'Risk'           = $_.Severity
            'Why it matters' = $_.Detail
            'Affected policies' = $_.PolicyName
            'Recommendation' = $_.Remediation
        }
    }
}

function Build-BaselineCoverageRow {
    [CmdletBinding()]
    param([object[]] $FindingList)

    # Baseline existence rules mark themselves with PolicyName '(baseline check)'.
    $baseline = @($FindingList | Where-Object { $_.PolicyName -match 'baseline check' })
    if ($baseline.Count -eq 0) { return @() }

    $sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4; 'Good' = 5 }

    $rows = $baseline | ForEach-Object {
        # Prefer the post-processor's state; fall back to Status if absent.
        $state = [string]$_.CoverageState
        if (-not $state) {
            $state = switch ($_.Status) { 'Pass' { 'covered' } 'NotApplicable' { 'na' } default { 'gap' } }
        }
        $status = switch ($state) {
            'covered' { 'Covered' }
            'scoped'  { 'Covered (scoped)' }
            'na'      { 'N/A' }
            default   { 'Gap' }
        }

        # Details: base sentence + which policies cover it (capped) + scope/context note.
        $details = [string]$_.Detail
        $cov = @($_.CoveredBy)
        if ($cov.Count -gt 0) {
            $shown = if ($cov.Count -gt 5) { ((@($cov) | Select-Object -First 5) -join '; ') + "; +$($cov.Count - 5) more" }
                     else { $cov -join '; ' }
            $details += " Covered by: $shown ($($cov.Count) policy/policies)."
        }
        if ($_.ScopeNote) { $details = ($details + ' ' + [string]$_.ScopeNote).Trim() }

        [PSCustomObject][ordered]@{
            'Status'   = $status
            'Control'  = $_.Name
            'Priority' = $_.Severity
            'Details'  = $details
            'Action'   = $_.Remediation
        }
    }

    # Gaps first, then scoped (verify), then covered; within each, worst severity first.
    return @($rows | Sort-Object `
        @{ Expression = { switch ($_.Status) { 'Gap' { 0 } 'Covered (scoped)' { 1 } default { 2 } } } }, `
        @{ Expression = { $s = $sevOrder[$_.Priority]; if ($null -eq $s) { 9 } else { $s } } }, `
        'Control')
}

function Get-CAPrincipalLabel {
    [CmdletBinding()]
    param($Resolved, [string] $TypeTag)

    # Well-known tokens (All users, etc.) are self-describing - no type tag.
    if ($Resolved.Source -eq 'well-known-token') { return $Resolved.DisplayName }
    return "$($Resolved.DisplayName) ($TypeTag)"
}

function Get-CAPrincipalList {
    [CmdletBinding()]
    param(
        $Users,
        [Parameter(Mandatory)] [ValidateSet('include', 'exclude')] [string] $Which
    )

    if ($Which -eq 'include') {
        $userIds  = ConvertTo-SafeArray $Users.includeUsers
        $groupIds = ConvertTo-SafeArray $Users.includeGroups
        $roleIds  = ConvertTo-SafeArray $Users.includeRoles
        $guest    = Format-GuestOrExternal $Users.includeGuestsOrExternalUsers
    }
    else {
        $userIds  = ConvertTo-SafeArray $Users.excludeUsers
        $groupIds = ConvertTo-SafeArray $Users.excludeGroups
        $roleIds  = ConvertTo-SafeArray $Users.excludeRoles
        $guest    = Format-GuestOrExternal $Users.excludeGuestsOrExternalUsers
    }

    $items = @()
    foreach ($id in @($userIds  | Where-Object { $_ -and $_ -ne 'None' })) {
        $items += Get-CAPrincipalLabel (Resolve-CAIdentity -Id $id -Type User) 'User'
    }
    foreach ($id in @($groupIds | Where-Object { $_ })) {
        $items += Get-CAPrincipalLabel (Resolve-CAIdentity -Id $id -Type Group) 'Group'
    }
    foreach ($id in @($roleIds  | Where-Object { $_ })) {
        $items += Get-CAPrincipalLabel (Resolve-CAIdentity -Id $id -Type Role) 'Role'
    }
    if ($guest) { $items += $guest }

    return @($items)
}

function Build-PolicyGroupsRow {
    [CmdletBinding()]
    param([object[]] $PolicyList)

    if (@($PolicyList).Count -eq 0) { return @() }

    $stateMap = @{ 'enabled' = 'On'; 'disabled' = 'Off'; 'enabledForReportingButNotEnforced' = 'Report-only' }
    $cap = 12   # max principal columns per side; overflow collapses to "+N more"

    $records = foreach ($p in $PolicyList) {
        $u = $p.conditions.users
        [PSCustomObject]@{
            Name  = $p.displayName
            State = if ($stateMap.ContainsKey([string]$p.state)) { $stateMap[[string]$p.state] } else { [string]$p.state }
            Scope = Get-AppliesToSummary $u
            Incl  = @(Get-CAPrincipalList -Users $u -Which include)
            Excl  = @(Get-CAPrincipalList -Users $u -Which exclude)
        }
    }
    $records = @($records)

    $maxIncl = ($records | ForEach-Object { $_.Incl.Count } | Measure-Object -Maximum).Maximum
    $maxExcl = ($records | ForEach-Object { $_.Excl.Count } | Measure-Object -Maximum).Maximum
    $mIncl = [Math]::Min([int]$maxIncl, $cap)
    $mExcl = [Math]::Min([int]$maxExcl, $cap)

    $rows = foreach ($rec in $records) {
        $row = [ordered]@{
            'Policy Name' = $rec.Name
            'State'       = $rec.State
            'Scope'       = $rec.Scope
            '# Incl'      = $rec.Incl.Count
            '# Excl'      = $rec.Excl.Count
        }
        for ($i = 0; $i -lt $mIncl; $i++) {
            $row["Included $($i + 1)"] = Get-CASpreadCell -Items $rec.Incl -Index $i -SlotCount $mIncl
        }
        for ($i = 0; $i -lt $mExcl; $i++) {
            $row["Excluded $($i + 1)"] = Get-CASpreadCell -Items $rec.Excl -Index $i -SlotCount $mExcl
        }
        [PSCustomObject]$row
    }

    return @($rows)
}

# Returns the cell value for spreading $Items across $SlotCount columns. When
# there are more items than slots, the last slot collapses the remainder to
# "+N more" rather than truncating silently.
function Get-CASpreadCell {
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]] $Items, [int] $Index, [int] $SlotCount)

    $count = @($Items).Count
    if ($Index -ge $count) { return '' }
    if ($Index -eq ($SlotCount - 1) -and $count -gt $SlotCount) {
        return "+ $($count - ($SlotCount - 1)) more"
    }
    return $Items[$Index]
}

# ---------------------------------------------------------------------------
# Platform Matrix - approximate effective control per platform x client x
# device state, for All-users O365 policies. This is a first-pass computation,
# NOT a What-If replacement: it ignores device filters, IP/risk conditions,
# session controls, and group-scoped policies (those are listed separately).
# ---------------------------------------------------------------------------

function Test-CAPolicyTargetsO365 {
    [CmdletBinding()]
    param($Policy)
    $apps = @($Policy.conditions.applications.includeApplications | Where-Object { $_ })
    return ('All' -in $apps) -or ('Office365' -in $apps)
}

function Test-CAPolicyAllUsers {
    [CmdletBinding()]
    param($Policy)
    return 'All' -in @($Policy.conditions.users.includeUsers | Where-Object { $_ })
}

function Test-CAPolicyPlatform {
    [CmdletBinding()]
    param($Policy, [string] $Platform)
    $p = $Policy.conditions.platforms
    if ($null -eq $p) { return $true }   # no platform condition => all platforms
    $incl = @($p.includePlatforms | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
    $excl = @($p.excludePlatforms | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
    $plat = $Platform.ToLower()
    $inclMatch = ($incl.Count -eq 0) -or ('all' -in $incl) -or ($plat -in $incl)
    return $inclMatch -and ($plat -notin $excl)
}

function Test-CAPolicyClient {
    [CmdletBinding()]
    param($Policy, [ValidateSet('browser', 'apps')] [string] $Client)
    $cat = @($Policy.conditions.clientAppTypes | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
    if ($cat.Count -eq 0 -or 'all' -in $cat) { return $true }
    if ($Client -eq 'browser') { return 'browser' -in $cat }
    return 'mobileappsanddesktopclients' -in $cat
}

# Whether a policy can be represented in a platform x client x device matrix.
# Location- and risk-conditioned policies only apply under conditions the matrix
# cannot model (e.g. "block from country X"), so treating them as unconditional
# would falsely show "Blocked" everywhere. Such policies are excluded and
# reported in the footer instead.
function Test-CAPolicyMatrixEligible {
    [CmdletBinding()]
    param($Policy)
    $c = $Policy.conditions
    $loc = $c.locations
    if ($loc) {
        $incl = @($loc.includeLocations | Where-Object { $_ })
        $excl = @($loc.excludeLocations | Where-Object { $_ })
        if ($excl.Count -gt 0) { return $false }
        if ($incl.Count -gt 0 -and ('All' -notin $incl)) { return $false }
    }
    if (@($c.signInRiskLevels | Where-Object { $_ }).Count -gt 0) { return $false }
    if (@($c.userRiskLevels | Where-Object { $_ }).Count -gt 0) { return $false }
    # authenticationFlows-gated (device code / auth transfer) policies apply only
    # to those flows, not the general browser/apps experience.
    if ($c.authenticationFlows.transferMethods) { return $false }
    return $true
}

# Effective requirement a single policy imposes on a given device state.
function Get-CAPolicyEffect {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param($Policy, [ValidateSet('unmanaged', 'managed')] [string] $DeviceState)

    $g = $Policy.grantControls
    if ($null -eq $g) { return @{ Label = ''; Blocks = $false } }
    $ctrl = @($g.builtInControls | Where-Object { $_ })
    if ('block' -in $ctrl) { return @{ Label = 'Blocked'; Blocks = $true } }

    $op = if ($g.operator) { $g.operator.ToUpper() } else { 'AND' }
    $compliant = ('compliantDevice' -in $ctrl) -or ('domainJoinedDevice' -in $ctrl)
    $mfa = ('mfa' -in $ctrl) -or ($null -ne $g.authenticationStrength)
    $appProt = ('approvedApplication' -in $ctrl) -or ('compliantApplication' -in $ctrl)

    if ($op -eq 'OR') {
        # User satisfies with the easiest available control.
        if ($DeviceState -eq 'unmanaged') {
            if ($mfa)       { return @{ Label = 'MFA'; Blocks = $false } }
            if ($appProt)   { return @{ Label = 'App protection'; Blocks = $false } }
            if ($compliant) { return @{ Label = 'Blocked (needs compliant)'; Blocks = $true } }
        }
        else {
            if ($compliant) { return @{ Label = 'Compliant'; Blocks = $false } }
            if ($mfa)       { return @{ Label = 'MFA'; Blocks = $false } }
            if ($appProt)   { return @{ Label = 'App protection'; Blocks = $false } }
        }
        return @{ Label = ''; Blocks = $false }
    }

    # AND: all controls required.
    if ($DeviceState -eq 'unmanaged' -and $compliant) {
        return @{ Label = 'Blocked (needs compliant)'; Blocks = $true }
    }
    $reqs = @()
    if ($mfa) { $reqs += 'MFA' }
    if ($compliant -and $DeviceState -eq 'managed') { $reqs += 'Compliant' }
    if ($appProt) { $reqs += 'App protection' }
    return @{ Label = ($reqs -join ' + '); Blocks = $false }
}

# Combined effective control for a cell across all applicable All-users policies.
function Get-CACellEffect {
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]] $Policies, [string] $Platform, [string] $Client, [string] $DeviceState)

    $applicable = @($Policies | Where-Object {
        $_.state -eq 'enabled' -and
        (Test-CAPolicyTargetsO365 $_) -and (Test-CAPolicyAllUsers $_) -and
        (Test-CAPolicyMatrixEligible $_) -and
        (Test-CAPolicyPlatform $_ $Platform) -and (Test-CAPolicyClient $_ $Client)
    })
    if ($applicable.Count -eq 0) { return 'No control (password only)' }

    $labels = @(); $drivers = @(); $blocked = $false
    foreach ($p in $applicable) {
        $eff = Get-CAPolicyEffect -Policy $p -DeviceState $DeviceState
        if ($eff.Blocks) { $blocked = $true; $drivers = @($p.displayName); break }
        # Only count policies that actually contribute a grant control (skip
        # session-only policies, which impose no grant requirement here).
        if ($eff.Label) { $labels += ($eff.Label -split ' \+ '); $drivers += $p.displayName }
    }

    $uniqDrivers = @($drivers | Select-Object -Unique)
    $driverText = if ($uniqDrivers.Count -le 2) { $uniqDrivers -join '; ' }
        else { (($uniqDrivers | Select-Object -First 2) -join '; ') + "; +$($uniqDrivers.Count - 2)" }

    if ($blocked) { return "Blocked [$driverText]" }
    $uniqLabels = @($labels | Select-Object -Unique)
    if ($uniqLabels.Count -eq 0) { return "Allowed, no strong control [$driverText]" }
    return "$($uniqLabels -join ' + ') [$driverText]"
}

function Build-PlatformMatrixRow {
    [CmdletBinding()]
    param([object[]] $PolicyList)

    $platforms = @(
        @{ Display = 'Windows'; Token = 'windows' }
        @{ Display = 'macOS';   Token = 'macOS' }
        @{ Display = 'iOS';     Token = 'iOS' }
        @{ Display = 'Android'; Token = 'android' }
        @{ Display = 'Linux';   Token = 'linux' }
    )

    $rows = foreach ($plat in $platforms) {
        $bu = Get-CACellEffect -Policies $PolicyList -Platform $plat.Token -Client 'browser' -DeviceState 'unmanaged'
        $bm = Get-CACellEffect -Policies $PolicyList -Platform $plat.Token -Client 'browser' -DeviceState 'managed'
        $au = Get-CACellEffect -Policies $PolicyList -Platform $plat.Token -Client 'apps'    -DeviceState 'unmanaged'
        $am = Get-CACellEffect -Policies $PolicyList -Platform $plat.Token -Client 'apps'    -DeviceState 'managed'

        $gaps = @()
        if ($bu -match 'password only') { $gaps += 'Browser/unmanaged' }
        if ($bm -match 'password only') { $gaps += 'Browser/managed' }
        if ($au -match 'password only') { $gaps += 'Apps/unmanaged' }
        if ($am -match 'password only') { $gaps += 'Apps/managed' }
        $gap = if ($gaps.Count -gt 0) { 'Password-only: ' + ($gaps -join ', ') } else { 'None obvious' }

        [PSCustomObject][ordered]@{
            'Platform'            = $plat.Display
            'Browser - unmanaged' = $bu
            'Browser - managed'   = $bm
            'Apps - unmanaged'    = $au
            'Apps - managed'      = $am
            'Gap'                 = $gap
        }
    }
    return @($rows)
}

function Get-CAGroupScopedO365Policy {
    [CmdletBinding()]
    param([object[]] $PolicyList)
    return @($PolicyList | Where-Object {
        $_.state -eq 'enabled' -and (Test-CAPolicyTargetsO365 $_) -and -not (Test-CAPolicyAllUsers $_)
    } | ForEach-Object { $_.displayName })
}

function Build-GroupMembershipRow {
    [CmdletBinding()]
    param([object[]] $PolicyList)

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $active = @($PolicyList | Where-Object { $_.state -ne 'disabled' })

    # groupId -> @{ Include; Exclude }
    $usage = @{}
    foreach ($policy in $active) {
        $u = $policy.conditions.users
        foreach ($gid in @($u.includeGroups | Where-Object { $_ -match $guidPattern })) {
            if (-not $usage.ContainsKey($gid)) { $usage[$gid] = @{ Include = 0; Exclude = 0 } }
            $usage[$gid].Include++
        }
        foreach ($gid in @($u.excludeGroups | Where-Object { $_ -match $guidPattern })) {
            if (-not $usage.ContainsKey($gid)) { $usage[$gid] = @{ Include = 0; Exclude = 0 } }
            $usage[$gid].Exclude++
        }
    }

    if ($usage.Count -eq 0) { return @() }

    $rows = foreach ($gid in $usage.Keys) {
        $name = (Resolve-CAIdentity -Id $gid -Type Group).DisplayName
        $info = Get-CAGroupEnrichment -Id $gid

        $membership = '-'; $memberCount = '-'; $notes = ''
        if ($null -ne $info) {
            if (-not $info.Exists) {
                $notes = 'DELETED - group no longer exists'
            }
            else {
                $membership = if ($info.IsDynamic) { 'Dynamic' } else { 'Assigned' }
                $memberCount = $info.MemberCount
                if ($info.MemberCount -eq 0) { $notes = 'Empty group' }
            }
        }

        [PSCustomObject][ordered]@{
            'Group'          = $name
            'In include (#)' = $usage[$gid].Include
            'In exclude (#)' = $usage[$gid].Exclude
            'Membership'     = $membership
            'Members'        = $memberCount
            'Notes'          = $notes
        }
    }

    return @($rows | Sort-Object 'Group')
}

function Build-NotEvaluatedRow {
    [CmdletBinding()]
    param([object[]] $FindingList)

    # Assign priority based on severity
    $priorityMap = @{
        'Critical' = '1 - Critical'
        'High'     = '2 - High'
        'Medium'   = '3 - Medium'
        'Low'      = '4 - Low'
        'Info'     = '5 - Info'
    }

    $FindingList | ForEach-Object {
        $priority = if ($priorityMap.ContainsKey($_.Severity)) { $priorityMap[$_.Severity] } else { '5 - Info' }
        $dataNeeded = switch ($_.Requires) {
            'group-membership'       { 'Group membership (Graph -ResolveNames or companion file)' }
            'named-location-detail'  { 'Named location IP ranges (Graph -ResolveNames or companion file)' }
            'role-assignment'        { 'Role assignment data (Graph -ResolveNames)' }
            default                  { $_.Requires }
        }

        [PSCustomObject][ordered]@{
            'Priority'               = $priority
            'Finding that could not run' = $_.Name
            'What data is needed'    = $dataNeeded
            'Affected policies'      = $_.PolicyName
            'Why it matters'         = $_.Detail
        }
    }
}

function Build-CrossReferenceRow {
    [CmdletBinding()]
    param([object[]] $PolicyList)

    $activePolicies = @($PolicyList | Where-Object { $_.state -ne 'disabled' })

    # Collect all exclusions: principalKey -> @{ policyName -> controlTypes[] }
    $principalExclusions = @{}
    $principalTypes = @{}

    foreach ($policy in $activePolicies) {
        $users = $policy.conditions.users

        # What controls does this policy enforce? (for risk note)
        $controlLabels = Get-PolicyControlLabel $policy

        # Excluded groups
        foreach ($gid in @($users.excludeGroups | Where-Object { $_ })) {
            $key = "group:$gid"
            if (-not $principalExclusions.ContainsKey($key)) { $principalExclusions[$key] = @{} }
            $principalExclusions[$key][$policy.displayName] = $controlLabels
            $principalTypes[$key] = 'Group'
        }

        # Excluded users (skip well-known tokens)
        foreach ($uid in @($users.excludeUsers | Where-Object { $_ -and $_ -notin @('All','None','GuestsOrExternalUsers') })) {
            $key = "user:$uid"
            if (-not $principalExclusions.ContainsKey($key)) { $principalExclusions[$key] = @{} }
            $principalExclusions[$key][$policy.displayName] = $controlLabels
            $principalTypes[$key] = 'User'
        }

        # Excluded external tenants
        $excludeGuests = $users.excludeGuestsOrExternalUsers
        if ($excludeGuests.externalTenants.members) {
            foreach ($tid in @($excludeGuests.externalTenants.members)) {
                $key = "tenant:$tid"
                if (-not $principalExclusions.ContainsKey($key)) { $principalExclusions[$key] = @{} }
                $principalExclusions[$key][$policy.displayName] = $controlLabels
                $principalTypes[$key] = 'External tenant'
            }
        }
    }

    if ($principalExclusions.Count -eq 0) { return @() }

    # Filter: only principals excluded from 2+ policies are interesting
    # Exception: external tenants always shown (even 1 exclusion is worth noting)
    $filtered = @{}
    foreach ($key in $principalExclusions.Keys) {
        $count = $principalExclusions[$key].Count
        $isTenant = $principalTypes[$key] -eq 'External tenant'
        if ($count -ge 2 -or $isTenant) {
            $filtered[$key] = $principalExclusions[$key]
        }
    }

    if ($filtered.Count -eq 0) { return @() }

    # Only show policies that have at least one exclusion in the filtered set
    $relevantPolicies = @{}
    foreach ($exclusionMap in $filtered.Values) {
        foreach ($pName in $exclusionMap.Keys) {
            $relevantPolicies[$pName] = $true
        }
    }
    $policyColumns = @($relevantPolicies.Keys | Sort-Object)

    # Build short names for columns, handling collisions
    $shortNameMap = @{}  # fullName -> shortName (unique)
    $usedShortNames = @{}
    foreach ($pName in $policyColumns) {
        $candidate = if ($pName.Length -gt 35) { $pName.Substring(0, 32) + '...' } else { $pName }
        if ($usedShortNames.ContainsKey($candidate)) {
            # Collision - append a counter
            $counter = 2
            while ($usedShortNames.ContainsKey("$candidate ($counter)")) { $counter++ }
            $candidate = "$candidate ($counter)"
        }
        $usedShortNames[$candidate] = $true
        $shortNameMap[$pName] = $candidate
    }

    # Build rows
    $rows = @()

    foreach ($principalKey in ($filtered.Keys | Sort-Object)) {
        $parts = $principalKey -split ':', 2
        $principalType = $parts[0]
        $principalId = $parts[1]

        $resolveType = switch ($principalType) {
            'group'  { 'Group' }
            'user'   { 'User' }
            'tenant' { 'Tenant' }
            default  { 'Unknown' }
        }
        $principalName = (Resolve-CAIdentity -Id $principalId -Type $resolveType).DisplayName
        $typeLabel = $principalTypes[$principalKey]
        $exclusionMap = $filtered[$principalKey]
        $exclusionCount = $exclusionMap.Count

        # Build risk note based on what controls are bypassed
        $riskNote = Get-ExclusionRiskNote -ExclusionMap $exclusionMap -ExclusionCount $exclusionCount -TypeLabel $typeLabel

        $row = [ordered]@{
            'Principal' = "$principalName ($typeLabel)"
        }

        foreach ($pName in $policyColumns) {
            $colName = $shortNameMap[$pName]
            $row[$colName] = if ($exclusionMap.ContainsKey($pName)) { 'X' } else { '' }
        }

        $row['Exclusions'] = $exclusionCount
        $row['Risk note'] = $riskNote

        $rows += [PSCustomObject]$row
    }

    return @($rows | Sort-Object 'Exclusions' -Descending)
}

function Get-PolicyControlLabel {
    [CmdletBinding()]
    param($Policy)

    $labels = @()
    $g = $Policy.grantControls
    if ($null -eq $g) { return 'session-only' }

    $builtIn = @($g.builtInControls | Where-Object { $_ })
    if ('block' -in $builtIn)                { $labels += 'Block' }
    if ('mfa' -in $builtIn)                  { $labels += 'MFA' }
    if ('compliantDevice' -in $builtIn)      { $labels += 'Compliant device' }
    if ('domainJoinedDevice' -in $builtIn)   { $labels += 'Hybrid-joined device' }
    if ('approvedApplication' -in $builtIn)  { $labels += 'Approved app' }
    if ('compliantApplication' -in $builtIn) { $labels += 'App protection' }
    if ('passwordChange' -in $builtIn)       { $labels += 'Password change' }
    if ($g.authenticationStrength)            { $labels += 'Auth strength' }

    if ($labels.Count -eq 0) { return 'other' }
    return ($labels -join ', ')
}

function Get-ExclusionRiskNote {
    [CmdletBinding()]
    param(
        [hashtable] $ExclusionMap,
        [int] $ExclusionCount,
        [string] $TypeLabel
    )

    # Collect all bypassed control types
    $bypassedControls = @{}
    foreach ($controls in $ExclusionMap.Values) {
        foreach ($ctrl in ($controls -split ', ')) {
            $bypassedControls[$ctrl] = $true
        }
    }

    $bypassesMfa = $bypassedControls.ContainsKey('MFA') -or $bypassedControls.ContainsKey('Auth strength')
    $bypassesBlock = $bypassedControls.ContainsKey('Block')
    $bypassesDevice = $bypassedControls.ContainsKey('Compliant device') -or $bypassedControls.ContainsKey('Hybrid-joined device')

    # Determine risk level
    $parts = @()

    if ($ExclusionCount -ge 5) {
        $parts += "HIGH - excluded from $ExclusionCount policies"
    }
    elseif ($ExclusionCount -ge 3) {
        $parts += "MEDIUM - excluded from $ExclusionCount policies"
    }

    if ($TypeLabel -eq 'External tenant') {
        $parts += 'external partner - verify compensating policy exists'
    }

    if ($bypassesMfa -and $bypassesBlock) {
        $parts += 'bypasses both MFA and Block controls'
    }
    elseif ($bypassesMfa) {
        $parts += 'bypasses MFA'
    }
    elseif ($bypassesBlock) {
        $parts += 'bypasses Block'
    }

    if ($bypassesDevice) {
        $parts += 'bypasses device compliance'
    }

    if ($parts.Count -eq 0) {
        return "Excluded from $ExclusionCount policies"
    }

    return ($parts -join '; ')
}
