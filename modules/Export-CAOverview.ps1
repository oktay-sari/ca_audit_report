# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Export-CAOverview.ps1

<#
.SYNOPSIS
    Row builders for the Policy Overview and Policy Details report tabs.

.DESCRIPTION
    Pure data builders consumed by Export-CAHtml to render the interactive HTML
    report:

    ConvertTo-OverviewRow - one row per policy with 16 human-readable columns
    (condensed, grouped fields).

    Get-PolicyDetailRow - drill-down for values too long for the overview
    (e.g., many admin roles or excluded groups). One row per role/group/app per policy.

    (These once also fed an Excel export; that output was removed to drop the
    ImportExcel / EPPlus dependency - the row shapes are unchanged.)

.PARAMETER Policies
    Array of normalized CA policy objects (from Import-CAPolicySet).
#>

# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

function ConvertTo-OverviewRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [int] $RowNumber
    )

    $c = $Policy.conditions
    $g = $Policy.grantControls
    $s = $Policy.sessionControls

    # --- State ---
    $stateMap = @{
        'enabled' = 'On'
        'disabled' = 'Off'
        'enabledForReportingButNotEnforced' = 'Report-only'
    }
    $state = if ($stateMap.ContainsKey([string]$Policy.state)) { $stateMap[[string]$Policy.state] } else { $Policy.state }

    # --- Template ---
    $createdBy = if ($Policy.templateId) { 'Microsoft' } else { 'User' }

    # --- Users / roles INCLUDED ---
    $includeUsers = Format-IdentityList -Ids $c.users.includeUsers -Type 'User'
    $includeGroups = Format-IdentityList -Ids $c.users.includeGroups -Type 'Group'
    $includeRoles = Format-IdentityList -Ids $c.users.includeRoles -Type 'Role'
    $includeGuests = Format-GuestOrExternal $c.users.includeGuestsOrExternalUsers

    $includeParts = @($includeUsers, $includeGroups, $includeRoles, $includeGuests) | Where-Object { $_ }
    $appliesToSummary = Get-AppliesToSummary $c.users
    $includeText = ($includeParts -join "`n") | Out-String | ForEach-Object { $_.Trim() }

    # --- EXCLUDED ---
    $excludeUsers = Format-IdentityList -Ids $c.users.excludeUsers -Type 'User'
    $excludeGroups = Format-IdentityList -Ids $c.users.excludeGroups -Type 'Group'
    $excludeRoles = Format-IdentityList -Ids $c.users.excludeRoles -Type 'Role'
    $excludeGuests = Format-GuestOrExternal $c.users.excludeGuestsOrExternalUsers

    $excludeParts = @($excludeUsers, $excludeGroups, $excludeRoles, $excludeGuests) | Where-Object { $_ }
    $excludeText = if ($excludeParts.Count -gt 0) { ($excludeParts -join "`n").Trim() } else { 'None' }

    # --- Target resources ---
    $targetResources = Format-TargetResources $c.applications

    # --- Network / Locations ---
    $locations = Format-Locations $c.locations

    # --- Device platforms ---
    $platforms = Format-Platforms $c.platforms

    # --- Client apps ---
    $clientApps = Format-ClientApps $c.clientAppTypes

    # --- Other conditions ---
    $otherConditions = Format-OtherConditions -Conditions $c

    # --- Grant controls ---
    $grantText = Format-GrantControls $g

    # --- Grant logic ---
    $logic = if ($g.operator) {
        switch ($g.operator) {
            'OR'  { 'One' }
            'AND' { 'All' }
            default { $g.operator }
        }
    } else { '-' }

    # --- Session controls ---
    $sessionText = Format-SessionControls $s

    [PSCustomObject][ordered]@{
        '#'                    = $RowNumber
        'Policy name'          = $Policy.displayName
        'Created'              = $createdBy
        'State'                = $state
        'Applies to'           = $appliesToSummary
        'Users / roles INCLUDED' = $includeText
        'EXCLUDED (users/groups/roles)' = $excludeText
        'Target resources'     = $targetResources
        'Network / Locations'  = $locations
        'Device platforms'     = $platforms
        'Client apps'          = $clientApps
        'Other conditions'     = $otherConditions
        'Grant controls'       = $grantText
        'Logic'                = $logic
        'Session controls'     = $sessionText
        'Id'                   = $Policy.id
    }
}

function Get-PolicyDetailRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    $policyName = $Policy.displayName
    $c = $Policy.conditions
    $rows = @()

    # Include roles
    $roleIds = ConvertTo-SafeArray $c.users.includeRoles
    foreach ($id in $roleIds) {
        $resolved = Resolve-CAIdentity -Id $id -Type Role
        $rows += [PSCustomObject][ordered]@{
            'Policy name' = $policyName
            'Direction'   = 'Include'
            'Type'        = 'Role'
            'Display name' = $resolved.DisplayName
            'Object ID'   = $id
            'Resolved'    = $resolved.Resolved
        }
    }

    # Exclude roles
    $excludeRoleIds = ConvertTo-SafeArray $c.users.excludeRoles
    foreach ($id in $excludeRoleIds) {
        $resolved = Resolve-CAIdentity -Id $id -Type Role
        $rows += [PSCustomObject][ordered]@{
            'Policy name' = $policyName
            'Direction'   = 'Exclude'
            'Type'        = 'Role'
            'Display name' = $resolved.DisplayName
            'Object ID'   = $id
            'Resolved'    = $resolved.Resolved
        }
    }

    # Include/exclude groups
    foreach ($direction in @('include', 'exclude')) {
        $propName = "${direction}Groups"
        $groupIds = ConvertTo-SafeArray $c.users.$propName
        foreach ($id in $groupIds) {
            $resolved = Resolve-CAIdentity -Id $id -Type Group
            $rows += [PSCustomObject][ordered]@{
                'Policy name' = $policyName
                'Direction'   = if ($direction -eq 'include') { 'Include' } else { 'Exclude' }
                'Type'        = 'Group'
                'Display name' = $resolved.DisplayName
                'Object ID'   = $id
                'Resolved'    = $resolved.Resolved
            }
        }
    }

    # Include/exclude users
    foreach ($direction in @('include', 'exclude')) {
        $propName = "${direction}Users"
        $userIds = ConvertTo-SafeArray $c.users.$propName
        foreach ($id in $userIds) {
            # Skip well-known tokens
            if ($id -in @('All', 'None', 'GuestsOrExternalUsers')) { continue }
            $resolved = Resolve-CAIdentity -Id $id -Type User
            $rows += [PSCustomObject][ordered]@{
                'Policy name' = $policyName
                'Direction'   = if ($direction -eq 'include') { 'Include' } else { 'Exclude' }
                'Type'        = 'User'
                'Display name' = $resolved.DisplayName
                'Object ID'   = $id
                'Resolved'    = $resolved.Resolved
            }
        }
    }

    # Include/exclude apps (only GUIDs, not well-known tokens)
    foreach ($direction in @('include', 'exclude')) {
        $propName = "${direction}Applications"
        $appIds = ConvertTo-SafeArray $c.applications.$propName
        foreach ($id in $appIds) {
            if ($id -in @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { continue }
            $resolved = Resolve-CAIdentity -Id $id -Type App
            $rows += [PSCustomObject][ordered]@{
                'Policy name' = $policyName
                'Direction'   = if ($direction -eq 'include') { 'Include' } else { 'Exclude' }
                'Type'        = 'Application'
                'Display name' = $resolved.DisplayName
                'Object ID'   = $id
                'Resolved'    = $resolved.Resolved
            }
        }
    }

    return $rows
}

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

function Format-IdentityList {
    [CmdletBinding()]
    param(
        $Ids,
        [string] $Type
    )

    $arr = ConvertTo-SafeArray $Ids
    if ($arr.Count -eq 0) { return '' }

    # Well-known tokens
    $tokenOnly = $arr | Where-Object { $_ -in @('All', 'None', 'GuestsOrExternalUsers') }
    $guidOnly = $arr | Where-Object { $_ -notin @('All', 'None', 'GuestsOrExternalUsers') }

    $parts = @()

    foreach ($token in $tokenOnly) {
        $friendly = (Resolve-CAIdentity -Id $token -Type $Type).DisplayName
        $parts += $friendly
    }

    if ($guidOnly.Count -gt 0) {
        if ($guidOnly.Count -le 3) {
            foreach ($id in $guidOnly) {
                $resolved = (Resolve-CAIdentity -Id $id -Type $Type).DisplayName
                $parts += $resolved
            }
        }
        else {
            # Show count + first 3, reference details tab
            $first3 = $guidOnly[0..2] | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type $Type).DisplayName }
            $label = switch ($Type) {
                'Role'  { 'roles' }
                'Group' { 'groups' }
                'User'  { 'users' }
                'App'   { 'apps' }
                default { 'items' }
            }
            $parts += "$($guidOnly.Count) $label (see Details tab):"
            $parts += $first3
        }
    }

    $prefix = switch ($Type) {
        'Role'  { 'Roles: ' }
        'Group' { 'Groups: ' }
        'User'  { '' }
        default { '' }
    }

    if ($parts.Count -eq 0) { return '' }
    if ($parts.Count -eq 1 -and -not $prefix) { return $parts[0] }

    return "$prefix$($parts -join ', ')"
}

function Format-GuestOrExternal {
    [CmdletBinding()]
    param($GuestOrExternal)

    if ($null -eq $GuestOrExternal) { return '' }

    $types = $GuestOrExternal.guestOrExternalUserTypes
    if (-not $types) { return '' }

    # Parse comma-separated string into friendly names
    $typeList = $types -split ',' | ForEach-Object {
        switch ($_.Trim()) {
            'internalGuest'          { 'internal guest' }
            'b2bCollaborationGuest'  { 'B2B guest' }
            'b2bCollaborationMember' { 'B2B member' }
            'b2bDirectConnectUser'   { 'B2B direct connect' }
            'otherExternalUser'      { 'other external' }
            'serviceProvider'        { 'service provider' }
            default                  { $_ }
        }
    }

    $tenantScope = ''
    $tenants = $GuestOrExternal.externalTenants
    if ($tenants) {
        $kind = $tenants.membershipKind
        if ($kind -eq 'all') {
            $tenantScope = ' from all external orgs'
        }
        elseif ($kind -eq 'enumerated' -and $tenants.members) {
            $tenantIds = @($tenants.members) | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type Tenant).DisplayName }
            $tenantScope = " from $($tenantIds -join ', ')"
        }
    }

    return "Guest/external: $($typeList -join ', ')$tenantScope"
}

function Get-AppliesToSummary {
    [CmdletBinding()]
    param($Users)

    $hasAllUsers = 'All' -in (ConvertTo-SafeArray $Users.includeUsers)
    $hasRoles = (ConvertTo-SafeArray $Users.includeRoles).Count -gt 0
    $hasGroups = (ConvertTo-SafeArray $Users.includeGroups).Count -gt 0
    $hasUsers = ((ConvertTo-SafeArray $Users.includeUsers) | Where-Object { $_ -ne 'All' -and $_ -ne 'None' }).Count -gt 0
    $hasGuests = $null -ne $Users.includeGuestsOrExternalUsers

    if ($hasAllUsers) { return 'All users' }

    $parts = @()
    if ($hasRoles) { $parts += 'Directory roles' }
    if ($hasGroups) { $parts += 'Groups' }
    if ($hasUsers) { $parts += 'Specific users' }
    if ($hasGuests) { $parts += 'Guests/external' }

    if ($parts.Count -eq 0) { return 'Not configured' }
    return "Users and groups ($($parts -join ', '))"
}

function Format-TargetResources {
    [CmdletBinding()]
    param($Applications)

    if ($null -eq $Applications) { return 'Not configured' }

    $parts = @()

    # Include apps
    $includeApps = ConvertTo-SafeArray $Applications.includeApplications
    if ($includeApps.Count -gt 0) {
        $appNames = $includeApps | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type App).DisplayName }
        if ($appNames.Count -le 5) {
            $parts += $appNames
        }
        else {
            $parts += "$($appNames.Count) apps (see Details tab)"
        }
    }

    # Exclude apps
    $excludeApps = ConvertTo-SafeArray $Applications.excludeApplications
    if ($excludeApps.Count -gt 0) {
        $exNames = $excludeApps | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type App).DisplayName }
        $parts += "EXCLUDED: $($exNames -join ', ')"
    }

    # User actions
    $actions = ConvertTo-SafeArray $Applications.includeUserActions
    if ($actions.Count -gt 0) {
        $actionNames = $actions | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type Action).DisplayName }
        $parts += "User action: $($actionNames -join ', ')"
    }

    # App filter
    if ($Applications.applicationFilter.rule) {
        $parts += "App filter ($($Applications.applicationFilter.mode)): $($Applications.applicationFilter.rule)"
    }

    if ($parts.Count -eq 0) { return 'Not configured' }
    return ($parts -join "`n").Trim()
}

function Format-Locations {
    [CmdletBinding()]
    param($Locations)

    if ($null -eq $Locations) { return 'Not configured' }

    $parts = @()

    $includeLocs = ConvertTo-SafeArray $Locations.includeLocations
    if ($includeLocs.Count -gt 0) {
        $locNames = $includeLocs | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type Location).DisplayName }
        $parts += "Include: $($locNames -join ', ')"
    }

    $excludeLocs = ConvertTo-SafeArray $Locations.excludeLocations
    if ($excludeLocs.Count -gt 0) {
        $exLocNames = $excludeLocs | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type Location).DisplayName }
        $parts += "Exclude: $($exLocNames -join ', ')"
    }

    if ($parts.Count -eq 0) { return 'Not configured' }
    return ($parts -join '; ')
}

function Format-Platforms {
    [CmdletBinding()]
    param($Platforms)

    if ($null -eq $Platforms) { return 'Not configured' }

    $parts = @()

    $includePlats = ConvertTo-SafeArray $Platforms.includePlatforms
    if ($includePlats.Count -gt 0) {
        $parts += "Include: $($includePlats -join ', ')"
    }

    $excludePlats = ConvertTo-SafeArray $Platforms.excludePlatforms
    if ($excludePlats.Count -gt 0) {
        $parts += "Exclude: $($excludePlats -join ', ')"
    }

    if ($parts.Count -eq 0) { return 'Not configured' }
    return ($parts -join '; ')
}

function Format-ClientApps {
    [CmdletBinding()]
    param($ClientAppTypes)

    $arr = ConvertTo-SafeArray $ClientAppTypes
    if ($arr.Count -eq 0) { return 'Not configured' }

    # If all 4 types are selected, that's equivalent to "all"
    if ('all' -in $arr) { return 'All client apps' }

    $friendly = $arr | ForEach-Object {
        switch ($_) {
            'browser'                      { 'Browser' }
            'mobileAppsAndDesktopClients'  { 'Mobile apps and desktop clients' }
            'exchangeActiveSync'           { 'Exchange ActiveSync' }
            'other'                        { 'Other clients (legacy auth)' }
            default                        { $_ }
        }
    }
    return ($friendly -join ', ')
}

function Format-OtherConditions {
    [CmdletBinding()]
    param(
        $Conditions
    )

    $parts = @()

    # User risk
    $userRisk = ConvertTo-SafeArray $Conditions.userRiskLevels
    if ($userRisk.Count -gt 0) { $parts += "User risk: $($userRisk -join ', ')" }

    # Sign-in risk
    $signInRisk = ConvertTo-SafeArray $Conditions.signInRiskLevels
    if ($signInRisk.Count -gt 0) { $parts += "Sign-in risk: $($signInRisk -join ', ')" }

    # Insider risk
    $insiderRisk = ConvertTo-SafeArray $Conditions.insiderRiskLevels
    if ($insiderRisk.Count -gt 0) { $parts += "Insider risk: $($insiderRisk -join ', ')" }

    # Service principal risk
    $spRisk = ConvertTo-SafeArray $Conditions.servicePrincipalRiskLevels
    if ($spRisk.Count -gt 0) { $parts += "SP risk: $($spRisk -join ', ')" }

    # Authentication flows
    if ($Conditions.authenticationFlows) {
        $methods = $Conditions.authenticationFlows.transferMethods
        if ($methods) {
            # Can be comma-separated string or array
            $methodList = if ($methods -is [string]) { $methods -split ',' } else { @($methods) }
            $friendly = $methodList | ForEach-Object {
                switch ($_.Trim()) {
                    'deviceCodeFlow'           { 'Device code flow' }
                    'authenticationTransfer'    { 'Authentication transfer' }
                    default                    { $_ }
                }
            }
            $parts += "Auth flow: $($friendly -join ', ')"
        }
    }

    # Device filter
    if ($Conditions.devices.deviceFilter.rule) {
        $mode = $Conditions.devices.deviceFilter.mode
        $parts += "Device filter ($mode): $($Conditions.devices.deviceFilter.rule)"
    }

    if ($parts.Count -eq 0) { return 'None' }
    return ($parts -join "`n").Trim()
}

function Format-GrantControls {
    [CmdletBinding()]
    param($GrantControls)

    if ($null -eq $GrantControls) { return 'No grant controls (session-only)' }

    $parts = @()

    # Built-in controls
    $builtIn = ConvertTo-SafeArray $GrantControls.builtInControls
    foreach ($ctrl in $builtIn) {
        $parts += (Resolve-CAIdentity -Id $ctrl -Type Control).DisplayName
    }

    # Authentication strength
    if ($GrantControls.authenticationStrength) {
        $strength = $GrantControls.authenticationStrength
        $name = $strength.displayName
        $policyType = $strength.policyType
        $label = if ($policyType -eq 'custom') { "Auth strength (custom): $name" } else { "Auth strength: $name" }
        $parts += $label
    }

    # Terms of use
    $tou = ConvertTo-SafeArray $GrantControls.termsOfUse
    if ($tou.Count -gt 0) { $parts += 'Terms of use' }

    if ($parts.Count -eq 0) { return 'No controls configured' }
    return ($parts -join ' + ')
}

function Format-SessionControls {
    [CmdletBinding()]
    param($SessionControls)

    if ($null -eq $SessionControls) { return 'None' }

    $parts = @()

    # Sign-in frequency
    if ($SessionControls.signInFrequency.isEnabled) {
        $sif = $SessionControls.signInFrequency
        if ($sif.frequencyInterval -eq 'everyTime') {
            $parts += 'Sign-in frequency: every time'
        }
        elseif ($sif.value -and $sif.type) {
            $parts += "Sign-in frequency: $($sif.value) $($sif.type)"
        }
        else {
            $parts += 'Sign-in frequency: configured'
        }
    }

    # Persistent browser
    if ($SessionControls.persistentBrowser.isEnabled) {
        $parts += "Persistent browser: $($SessionControls.persistentBrowser.mode)"
    }

    # Cloud App Security / MCAS
    if ($SessionControls.cloudAppSecurity.isEnabled) {
        $casType = switch ($SessionControls.cloudAppSecurity.cloudAppSecurityType) {
            'mcasConfigured' { 'Defender for Cloud Apps (custom)' }
            'monitorOnly'    { 'Monitor only' }
            'blockDownloads' { 'Block downloads' }
            default          { $SessionControls.cloudAppSecurity.cloudAppSecurityType }
        }
        $parts += "MCAS: $casType"
    }

    # App-enforced restrictions
    if ($SessionControls.applicationEnforcedRestrictions.isEnabled) {
        $parts += 'App-enforced restrictions'
    }

    # Continuous Access Evaluation
    if ($SessionControls.continuousAccessEvaluation.mode) {
        $parts += "CAE: $($SessionControls.continuousAccessEvaluation.mode)"
    }

    # Resilience defaults
    if ($SessionControls.disableResilienceDefaults -eq $true) {
        $parts += 'Resilience defaults disabled'
    }

    if ($parts.Count -eq 0) { return 'None' }
    return ($parts -join '; ')
}
