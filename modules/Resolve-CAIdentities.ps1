# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Resolve-CAIdentities.ps1

<#
.SYNOPSIS
    Resolves Conditional Access policy GUIDs to human-readable display names.

.DESCRIPTION
    Provides a resolution chain for translating object IDs found in CA policy JSON
    into display names. The chain tries each source in order:

    1. Well-known maps (roles, apps, controls) - always available, no auth needed
    2. Name cache file (from a previous -ResolveNames run) - offline reuse
    3. Microsoft Graph API (if -ResolveNames was specified) - live lookup
    4. Companion file (e.g. MigrationTable.json) - offline GUID -> name map
    5. Placeholder - "type: <guid> (unresolved)" for offline mode

    The resolver is initialized once per run and shared across all modules.

.NOTES
    Graph scopes needed for full resolution (read-only):
    - Policy.Read.All (CA policies, named locations)
    - Directory.Read.All (users, groups, roles, and service principals)
    Application.Read.All is NOT needed: service principals are read under
    Directory.Read.All, and only the app IDs referenced by policies are resolved.
#>

# Module-level state
$script:WellKnownRoles    = @{}
$script:WellKnownApps     = @{}
$script:WellKnownControls = @{}
$script:NameCache         = @{}
$script:GraphConnected    = $false
$script:CacheFilePath     = ''
$script:LegacyCachePath   = ''
$script:CacheDirty        = $false

# Tier 2 enrichment store - populated only during a live Graph run.
# Member IDs and IP ranges are held in-memory for the run only; they are NOT
# persisted to the name cache (data sensitivity). Tier 2 rules query these via
# Get-CAGroupEnrichment / Get-CALocationEnrichment and fall back to
# NotEvaluated when Test-CAEnrichmentAvailable returns $false.
$script:EnrichmentReady   = $false
$script:GroupEnrichment   = @{}   # groupId  -> @{ Exists; MemberCount; MemberIds; IsDynamic }
$script:LocationEnrichment = @{}  # locationId -> @{ DisplayName; IsTrusted; IsCountryBased; IpRanges }

# Companion-file names (e.g. IntuneManagement MigrationTable.json). Kept in a
# SEPARATE map from NameCache so they are never persisted to ca-name-cache.json.
# GUIDs are globally unique, so a match here is always the correct object; a
# non-match simply stays unresolved. Cleared after each run for data hygiene.
$script:CompanionNames    = @{}   # objectId -> displayName

<#
.SYNOPSIS
    Initializes the name resolver - loads data files, cache, and optionally connects to Graph.

.PARAMETER DataFolder
    Path to the data/ folder containing WellKnownRoles.psd1, WellKnownApps.psd1, WellKnownControls.psd1.

.PARAMETER CacheFile
    Path to the name cache JSON file (read on init, written on save).

.PARAMETER ResolveNames
    Connect to Microsoft Graph for live name resolution.

.PARAMETER Policies
    The loaded policies - used to collect all GUIDs that need resolution when using Graph.
#>

<#
.SYNOPSIS
    Returns the default name-cache path in a per-user application-data directory
    (never inside the tool/repo, so resolved display names / UPNs don't sit next
    to the code). Cross-platform: %LOCALAPPDATA%\ca-audit on Windows,
    ~/.local/share/ca-audit (or $XDG_DATA_HOME) on macOS/Linux.
#>
function Get-CANameCacheDefaultPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $base = ''
    try { $base = [System.Environment]::GetFolderPath('LocalApplicationData') } catch { $base = '' }
    if ([string]::IsNullOrWhiteSpace($base)) {
        # Fallback for hosts that don't resolve LocalApplicationData.
        $homeDir = if ($env:HOME) { $env:HOME } elseif ($env:USERPROFILE) { $env:USERPROFILE } else { '.' }
        $base = Join-Path $homeDir '.local/share'
    }
    return (Join-Path (Join-Path $base 'ca-audit') 'ca-name-cache.json')
}

function Initialize-CANameResolver {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DataFolder,

        [string] $CacheFile = '',

        [string] $CompanionFile = '',

        [switch] $ResolveNames,

        [object[]] $Policies = @()
    )

    # Load well-known data files
    $rolesFile    = Join-Path $DataFolder 'WellKnownRoles.psd1'
    $appsFile     = Join-Path $DataFolder 'WellKnownApps.psd1'
    $controlsFile = Join-Path $DataFolder 'WellKnownControls.psd1'

    if (Test-Path $rolesFile) {
        $script:WellKnownRoles = Import-PowerShellDataFile $rolesFile
        Write-Verbose "Loaded $($script:WellKnownRoles.Count) well-known roles."
    }
    else { Write-Warning "Well-known roles file not found: $rolesFile" }

    if (Test-Path $appsFile) {
        $script:WellKnownApps = Import-PowerShellDataFile $appsFile
        Write-Verbose "Loaded $($script:WellKnownApps.Count) well-known apps."
    }
    else { Write-Warning "Well-known apps file not found: $appsFile" }

    if (Test-Path $controlsFile) {
        $script:WellKnownControls = Import-PowerShellDataFile $controlsFile
        Write-Verbose "Loaded $($script:WellKnownControls.Count) well-known controls."
    }
    else { Write-Warning "Well-known controls file not found: $controlsFile" }

    # Name-cache location. Default lives in a per-user app-data directory so
    # resolved display names / UPNs never sit next to the tool or in the repo.
    # An explicit -CacheFile still wins. A legacy cache that used to live in the
    # tool's data/ folder is migrated to the new location on save.
    if ($CacheFile) {
        $script:CacheFilePath = $CacheFile
    }
    else {
        $script:CacheFilePath = Get-CANameCacheDefaultPath
    }
    $script:LegacyCachePath = Join-Path $DataFolder 'ca-name-cache.json'

    # Read the new-location cache, or fall back to a legacy in-repo cache (one
    # time) so upgrading users don't lose their cached names.
    $loadFrom = if (Test-Path $script:CacheFilePath) { $script:CacheFilePath }
                elseif (-not $CacheFile -and (Test-Path $script:LegacyCachePath)) { $script:LegacyCachePath }
                else { '' }
    if ($loadFrom) {
        try {
            $cacheContent = Get-Content $loadFrom -Raw | ConvertFrom-Json
            foreach ($prop in $cacheContent.PSObject.Properties) {
                $script:NameCache[$prop.Name] = $prop.Value
            }
            Write-Host "Loaded $($script:NameCache.Count) cached name(s) from $loadFrom" -ForegroundColor DarkGray
        }
        catch {
            Write-Warning "Could not read name cache: $_"
        }
    }

    # Load companion name map (offline, e.g. MigrationTable.json). Loaded before
    # Graph so a live -ResolveNames run overrides it with authoritative names.
    if ($CompanionFile) {
        Import-CACompanionName -Path $CompanionFile
    }

    # Optionally connect to Graph and resolve all IDs
    if ($ResolveNames) {
        Invoke-GraphNameResolution -Policies $Policies
    }
}

<#
.SYNOPSIS
    Loads an offline companion name map (GUID -> display name) into a separate
    store used only as an offline resolution fallback.

.DESCRIPTION
    Supports the IntuneManagement MigrationTable.json shape ({ Objects: [ {
    DisplayName, Id, Type } ] }) and a plain { "<guid>": "<name>" } map. Parsing
    is fully defensive: any error warns and returns without aborting the audit.
    Names are stored in $script:CompanionNames and are NEVER written to the name
    cache on disk. Because object GUIDs are globally unique, a companion match is
    always the correct object; entries not present simply stay unresolved.

.PARAMETER Path
    Path to the companion JSON file.
#>
function Import-CACompanionName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "Companion file not found: $Path"
        return
    }

    try {
        # -Raw + auto encoding detection handles the UTF-16 that IntuneManagement writes.
        $obj = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not parse companion file '$Path': $_"
        return
    }

    $loaded = 0
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    if ($obj.Objects) {
        # MigrationTable shape
        foreach ($entry in @($obj.Objects)) {
            $id = [string]$entry.Id
            $name = [string]$entry.DisplayName
            if ($id -match $guidPattern -and $name) {
                $script:CompanionNames[$id] = $name
                $loaded++
            }
        }
    }
    else {
        # Plain { "<guid>": "<name>" } map
        foreach ($prop in $obj.PSObject.Properties) {
            if ($prop.Name -match $guidPattern -and $prop.Value) {
                $script:CompanionNames[$prop.Name] = [string]$prop.Value
                $loaded++
            }
        }
    }

    if ($loaded -gt 0) {
        Write-Host "Resolved $loaded name(s) from companion file '$(Split-Path -Leaf $Path)' (offline, not cached)." -ForegroundColor DarkGray
    }
    else {
        Write-Warning "Companion file '$Path' contained no usable GUID -> name entries."
    }
}

<#
.SYNOPSIS
    Clears in-memory resolver state after a run. Wipes companion names and Graph
    enrichment (group membership, location IP ranges) so no tenant-specific data
    lingers in the process. The on-disk name cache (a deliberate offline-reuse
    artifact of -ResolveNames) is written by Save-CANameCache before this runs.
#>
function Clear-CAResolverState {
    [CmdletBinding()]
    param()
    $script:CompanionNames.Clear()
    $script:GroupEnrichment.Clear()
    $script:LocationEnrichment.Clear()
    $script:NameCache.Clear()
    $script:EnrichmentReady = $false
    $script:CacheDirty = $false
}

<#
.SYNOPSIS
    Resolves a single ID to a display name using the resolution chain.

.PARAMETER Id
    The ID to resolve (GUID, well-known token, or URN).

.PARAMETER Type
    Hint for what kind of object this is: User, Group, Role, App, Location, Tenant, Control, Action.
    Used for the placeholder text when resolution fails.

.OUTPUTS
    PSCustomObject with: DisplayName, Id, Resolved (bool), Source (string).
#>
function Resolve-CAIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Id,

        [ValidateSet('User', 'Group', 'Role', 'App', 'Location', 'Tenant', 'Control', 'Action', 'Unknown')]
        [string] $Type = 'Unknown'
    )

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return [PSCustomObject]@{
            DisplayName = ''
            Id          = $Id
            Resolved    = $true
            Source      = 'empty'
        }
    }

    # Well-known non-GUID tokens - always resolve
    $friendlyToken = Get-FriendlyToken $Id
    if ($friendlyToken) {
        return [PSCustomObject]@{
            DisplayName = $friendlyToken
            Id          = $Id
            Resolved    = $true
            Source      = 'well-known-token'
        }
    }

    # Well-known maps by type
    $wellKnownName = $null
    if ($Type -eq 'Role' -and $script:WellKnownRoles.ContainsKey($Id)) {
        $wellKnownName = $script:WellKnownRoles[$Id]
    }
    elseif ($Type -eq 'App' -and $script:WellKnownApps.ContainsKey($Id)) {
        $wellKnownName = $script:WellKnownApps[$Id]
    }
    elseif ($Type -eq 'Action' -and $script:WellKnownApps.ContainsKey($Id)) {
        # User actions (URNs) are stored in the apps map
        $wellKnownName = $script:WellKnownApps[$Id]
    }
    elseif ($Type -eq 'Control') {
        $wellKnownName = Find-InControlsMap $Id
    }

    # Fall back to checking all maps if type-specific lookup missed
    if (-not $wellKnownName) {
        if ($script:WellKnownRoles.ContainsKey($Id))    { $wellKnownName = $script:WellKnownRoles[$Id] }
        elseif ($script:WellKnownApps.ContainsKey($Id)) { $wellKnownName = $script:WellKnownApps[$Id] }
        else { $wellKnownName = Find-InControlsMap $Id }
    }

    if ($wellKnownName) {
        return [PSCustomObject]@{
            DisplayName = $wellKnownName
            Id          = $Id
            Resolved    = $true
            Source      = 'well-known-map'
        }
    }

    # Name cache (from a previous or current Graph run)
    if ($script:NameCache.ContainsKey($Id)) {
        return [PSCustomObject]@{
            DisplayName = $script:NameCache[$Id]
            Id          = $Id
            Resolved    = $true
            Source      = 'cache'
        }
    }

    # Companion file (offline map, e.g. MigrationTable.json) - below Graph/cache
    if ($script:CompanionNames.ContainsKey($Id)) {
        return [PSCustomObject]@{
            DisplayName = $script:CompanionNames[$Id]
            Id          = $Id
            Resolved    = $true
            Source      = 'companion-file'
        }
    }

    # Unresolved - return placeholder with the GUID visible
    $typeLabel = $Type.ToLower()
    $shortId = if ($Id.Length -gt 13) { "$($Id.Substring(0,13))..." } else { $Id }
    return [PSCustomObject]@{
        DisplayName = "$typeLabel`: $shortId (unresolved)"
        Id          = $Id
        Resolved    = $false
        Source      = 'unresolved'
    }
}

<#
.SYNOPSIS
    Resolves an array of IDs and returns a semicolon-joined display name string.

.PARAMETER Ids
    Array of IDs to resolve.

.PARAMETER Type
    Type hint for all IDs in the array.
#>
function Resolve-CAIdentityList {
    [CmdletBinding()]
    param(
        $Ids,

        [string] $Type = 'Unknown'
    )

    $arr = ConvertTo-SafeArray $Ids
    if ($arr.Count -eq 0) { return '' }

    $resolved = $arr | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type $Type).DisplayName }
    return ($resolved -join '; ')
}

<#
.SYNOPSIS
    Saves the name cache to disk for offline reuse in future runs.
#>
function Save-CANameCache {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param()

    if (-not $script:CacheDirty) {
        Write-Verbose "Name cache unchanged - skipping save."
        return
    }

    if (-not $script:CacheFilePath) {
        Write-Warning "No cache file path configured - cannot save."
        return
    }

    try {
        # Ensure the (app-data) directory exists before writing.
        $cacheDir = Split-Path -Parent $script:CacheFilePath
        if ($cacheDir -and -not (Test-Path $cacheDir)) {
            New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
        }
        $script:NameCache | ConvertTo-Json -Depth 1 | Set-Content -Path $script:CacheFilePath -Encoding UTF8
        Write-Host "Saved name cache ($($script:NameCache.Count) entries) to $($script:CacheFilePath)" -ForegroundColor DarkGray

        # Migration cleanup: if a legacy in-repo cache still exists and we just
        # wrote to a DIFFERENT (app-data) location, remove the legacy copy so
        # resolved names no longer linger next to the tool/repo.
        if ($script:LegacyCachePath -and
            (Test-Path $script:LegacyCachePath) -and
            ($script:LegacyCachePath -ne $script:CacheFilePath)) {
            try {
                Remove-Item -Path $script:LegacyCachePath -Force -ErrorAction Stop
                Write-Host "Migrated name cache out of the tool folder (removed legacy $($script:LegacyCachePath))." -ForegroundColor DarkGray
            }
            catch {
                Write-Warning "Name cache moved to $($script:CacheFilePath), but the legacy copy at $($script:LegacyCachePath) could not be removed: $_"
            }
        }
    }
    catch {
        Write-Warning "Could not write name cache: $_"
    }
}

<#
.SYNOPSIS
    Returns $true when live Graph enrichment (group membership, named-location
    IP ranges) was collected this run. Tier 2 rules use this to decide whether
    to evaluate Pass/Fail or emit NotEvaluated.
#>
function Test-CAEnrichmentAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return $script:EnrichmentReady
}

<#
.SYNOPSIS
    Returns the enrichment record for a group, or $null if not collected.

.OUTPUTS
    Hashtable @{ Exists; MemberCount; MemberIds; IsDynamic } or $null.
#>
function Get-CAGroupEnrichment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Id)
    if ($script:GroupEnrichment.ContainsKey($Id)) { return $script:GroupEnrichment[$Id] }
    return $null
}


<#
.SYNOPSIS
    Returns the enrichment record for a named location, or $null if not collected.

.OUTPUTS
    Hashtable @{ DisplayName; IsTrusted; IsCountryBased; IpRanges } or $null.
#>
function Get-CALocationEnrichment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Id)
    if ($script:LocationEnrichment.ContainsKey($Id)) { return $script:LocationEnrichment[$Id] }
    return $null
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Searches the nested WellKnownControls map for a value across all sub-hashtables.
#>
function Find-InControlsMap {
    [CmdletBinding()]
    param([string] $Key)

    foreach ($subTable in $script:WellKnownControls.Values) {
        if ($subTable -is [hashtable] -and $subTable.ContainsKey($Key)) {
            return $subTable[$Key]
        }
    }
    return $null
}

<#
.SYNOPSIS
    Maps well-known non-GUID tokens to friendly names.
#>
function Get-FriendlyToken {
    [CmdletBinding()]
    param([string] $Token)

    switch ($Token) {
        'All'                   { return 'All' }
        'None'                  { return 'None' }
        'GuestsOrExternalUsers' { return 'Guests or external users' }
        'AllTrusted'            { return 'All trusted locations' }
        'Office365'             { return 'Office 365 (suite)' }
        'MicrosoftAdminPortals' { return 'Microsoft Admin Portals' }
        default                 { return $null }
    }
}

<#
.SYNOPSIS
    Null-safe array wrapper.
#>
function ConvertTo-SafeArray {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    return @($Value)
}

<#
.SYNOPSIS
    Connects to Microsoft Graph read-only (delegated, interactive). Idempotent:
    a second call reuses the existing connection. Shared by the live-tenant
    policy fetch and name resolution so the user signs in once.

.DESCRIPTION
    Requests ONLY read scopes (Policy.Read.All and, for name resolution,
    Directory.Read.All). Application.Read.All is intentionally not requested -
    Directory.Read.All is sufficient to read service principals. The tool never
    requests a write scope and never issues a write operation. Returns $true on
    success, $false if the module is missing or the connection fails.
#>
<#
.SYNOPSIS
    Prints a read-only banner identifying the Graph tenant we are about to use.
#>
function Show-CATenantInfo {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)

    # Org display name is best-effort (one read); tenant id + account are local.
    $org = 'Microsoft Entra tenant'
    if (Get-Command Get-CATenantName -ErrorAction SilentlyContinue) {
        try { $org = Get-CATenantName } catch { $null = $_ }
    }

    Write-Host ''
    Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '  |  Microsoft Graph sign-in (READ-ONLY)                        |' -ForegroundColor Cyan
    Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ("     Organization : {0}" -f $org) -ForegroundColor White
    Write-Host ("     Tenant ID    : {0}" -f $Context.TenantId) -ForegroundColor White
    Write-Host ("     Account      : {0}" -f $Context.Account) -ForegroundColor White
    Write-Host ''
}

<#
.SYNOPSIS
    Asks a yes/no question, returning $false on any non-yes answer or when no
    input is available (non-interactive session) - so we never proceed by default.
#>
function Get-CATenantConfirmation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Prompt)

    $ans = Read-Host "$Prompt [y/N]"
    if ($null -eq $ans) { return $false }   # EOF / non-interactive -> safe default No
    return ($ans.Trim() -match '^(y|yes)$')
}

function Connect-CAGraph {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string] $ExpectedTenantId = '',
        # Least-privilege read scopes. Policy.Read.All covers the CA policy fetch and
        # named locations; Directory.Read.All covers name resolution (users, groups,
        # roles, and service principals) and Tier-2 group membership. Application.Read.All
        # is intentionally NOT requested - Directory.Read.All can read service principals.
        [string[]] $Scopes = @('Policy.Read.All', 'Directory.Read.All')
    )

    if ($script:GraphConnected) { return $true }

    # Fall back to the tenant the caller pinned via -TenantId. This reads a script
    # variable set by the entry point; it works because the modules are DOT-SOURCED
    # (a dot-sourced function's $script: scope is the caller's script scope). If
    # these files are ever converted to a real module (Import-Module), pass the id
    # in explicitly via -ExpectedTenantId instead - otherwise the -TenantId
    # abort-on-mismatch guard would go dormant (it degrades safely: the cached-
    # session path still falls back to the interactive default-No confirmation).
    if (-not $ExpectedTenantId -and $script:CAExpectedTenantId) {
        $ExpectedTenantId = $script:CAExpectedTenantId
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Warning "Microsoft.Graph.Authentication is not installed."
        Write-Warning "Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
        return $false
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    # Pre-check: is there already a cached/active Graph session? Connect-MgGraph
    # would silently REUSE it, so an admin who works across tenants could read the
    # wrong one. Detect it before connecting and confirm the tenant.
    $existing = $null
    try { $existing = Get-MgContext } catch { $existing = $null }

    if ($existing -and $existing.TenantId) {
        Show-CATenantInfo -Context $existing
        if ($ExpectedTenantId) {
            if ($existing.TenantId -ne $ExpectedTenantId) {
                Write-Warning "Cached Graph session is tenant '$($existing.TenantId)', but -TenantId requested '$ExpectedTenantId'. Aborting to avoid the wrong tenant."
                Write-Host "  Run 'Disconnect-MgGraph' to clear the cached session, or omit -TenantId to confirm interactively." -ForegroundColor DarkYellow
                return $false
            }
            Write-Host "  Tenant matches -TenantId - continuing." -ForegroundColor DarkGreen
        }
        elseif (-not (Get-CATenantConfirmation -Prompt '  Continue with THIS tenant?')) {
            Write-Host '  Not this tenant - signing out of the cached session for a fresh sign-in...' -ForegroundColor Yellow
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { $null = $_ }
            $existing = $null
        }

        if ($existing) {
            $script:GraphConnected = $true
            Write-Host 'Using the existing Microsoft Graph session (read-only).' -ForegroundColor Green
            return $true
        }
    }

    try {
        # Read-only, delegated (interactive) sign-in. No write scopes, ever.
        Write-Host ("  Requesting read-only scopes: {0}" -f ($Scopes -join ', ')) -ForegroundColor DarkGray
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not connect to Microsoft Graph: $_"
        return $false
    }

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    if ($ctx) { Show-CATenantInfo -Context $ctx }

    # A fresh sign-in shows the account picker, so no extra confirmation is needed -
    # but if -TenantId was pinned, verify the sign-in landed on the right tenant.
    if ($ExpectedTenantId -and $ctx -and $ctx.TenantId -ne $ExpectedTenantId) {
        Write-Warning "Signed in to tenant '$($ctx.TenantId)', but -TenantId requested '$ExpectedTenantId'. Aborting."
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { $null = $_ }
        return $false
    }

    $script:GraphConnected = $true
    Write-Host "Connected to Microsoft Graph (read-only)." -ForegroundColor Green
    return $true
}

<#
.SYNOPSIS
    Connects to Microsoft Graph and batch-resolves all GUIDs found in the policies.
#>
function Invoke-GraphNameResolution {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [object[]] $Policies
    )

    # Check for the Graph module
    if (-not (Connect-CAGraph)) { return }

    # Collect all GUIDs that need resolution
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $objectIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # App IDs referenced by the policies themselves - so we resolve ONLY those apps
    # (via a targeted per-appId lookup) instead of enumerating every service
    # principal in the tenant. Well-known apps are already named offline.
    $appIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($policy in $Policies) {
        $users = $policy.conditions.users
        if ($users) {
            foreach ($id in (ConvertTo-SafeArray $users.includeUsers))  { if ($id -match $guidPattern) { [void]$objectIds.Add($id) } }
            foreach ($id in (ConvertTo-SafeArray $users.excludeUsers))  { if ($id -match $guidPattern) { [void]$objectIds.Add($id) } }
            foreach ($id in (ConvertTo-SafeArray $users.includeGroups)) { if ($id -match $guidPattern) { [void]$objectIds.Add($id) } }
            foreach ($id in (ConvertTo-SafeArray $users.excludeGroups)) { if ($id -match $guidPattern) { [void]$objectIds.Add($id) } }
            # Roles are resolved via well-known map first, but also try Graph for custom roles
            foreach ($id in (ConvertTo-SafeArray $users.includeRoles))  { if ($id -match $guidPattern -and -not $script:WellKnownRoles.ContainsKey($id)) { [void]$objectIds.Add($id) } }
            foreach ($id in (ConvertTo-SafeArray $users.excludeRoles))  { if ($id -match $guidPattern -and -not $script:WellKnownRoles.ContainsKey($id)) { [void]$objectIds.Add($id) } }
        }
        $apps = $policy.conditions.applications
        if ($apps) {
            foreach ($id in (ConvertTo-SafeArray $apps.includeApplications)) { if ($id -match $guidPattern -and -not $script:WellKnownApps.ContainsKey($id)) { [void]$appIds.Add($id) } }
            foreach ($id in (ConvertTo-SafeArray $apps.excludeApplications)) { if ($id -match $guidPattern -and -not $script:WellKnownApps.ContainsKey($id)) { [void]$appIds.Add($id) } }
        }
    }

    # Batch resolve via directoryObjects/getByIds (max 1000 per call)
    $idList = @($objectIds)
    if ($idList.Count -gt 0) {
        Write-Host "Resolving $($idList.Count) directory object(s) via Graph..." -ForegroundColor DarkGray
        for ($i = 0; $i -lt $idList.Count; $i += 1000) {
            $upperBound = [Math]::Min($i + 999, $idList.Count - 1)
            $batch = $idList[$i..$upperBound]
            try {
                $body = @{ ids = $batch; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 3
                $resp = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body $body
                foreach ($obj in $resp.value) {
                    $name = if ($obj.displayName) { $obj.displayName } else { $obj.userPrincipalName }
                    if ($name) {
                        $script:NameCache[$obj.id] = $name
                        $script:CacheDirty = $true
                    }
                }
            }
            catch { Write-Warning "getByIds batch failed: $_" }
        }
    }

    # Resolve directory role templates (for any custom roles not in the well-known map)
    try {
        $roleResp = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/directoryRoleTemplates'
        foreach ($role in $roleResp.value) {
            if (-not $script:WellKnownRoles.ContainsKey($role.id)) {
                $script:NameCache[$role.id] = $role.displayName
                $script:CacheDirty = $true
            }
        }
        Write-Verbose "Resolved directory role templates."
    }
    catch { Write-Warning "Role template lookup failed: $_" }

    # Resolve service principals for ONLY the app IDs the policies reference
    # (targeted lookup by appId), rather than enumerating every service principal
    # in the tenant. This needs no more than Directory.Read.All and reads the
    # least data necessary.
    $appIdList = @($appIds)
    if ($appIdList.Count -gt 0) {
        Write-Host "Resolving $($appIdList.Count) referenced app(s) via Graph..." -ForegroundColor DarkGray
        foreach ($appId in $appIdList) {
            try {
                # servicePrincipals(appId='...') addresses the SP by its app (client) id.
                $sp = Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals(appId='$appId')?`$select=appId,displayName"
                if ($sp -and $sp.displayName) {
                    $script:NameCache[$appId] = $sp.displayName
                    $script:CacheDirty = $true
                }
            }
            catch { Write-Verbose "App '$appId' not resolved (may not have a service principal): $_" }
        }
    }

    # Resolve named locations (name + Tier 2 enrichment: IP ranges / trust / country)
    try {
        $locResp = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/identity/conditionalAccess/namedLocations'
        foreach ($loc in $locResp.value) {
            $script:NameCache[$loc.id] = $loc.displayName
            $script:CacheDirty = $true

            $odataType = [string]$loc.'@odata.type'
            $isCountry = $odataType -match 'countryNamedLocation'
            $ipRanges = @()
            if (-not $isCountry) {
                foreach ($range in @($loc.ipRanges)) {
                    $cidr = if ($range.cidrAddress) { $range.cidrAddress } else { $range.ipAddress }
                    if ($cidr) { $ipRanges += $cidr }
                }
            }
            $script:LocationEnrichment[$loc.id] = @{
                DisplayName    = $loc.displayName
                IsTrusted      = [bool]$loc.isTrusted
                IsCountryBased = $isCountry
                IpRanges       = $ipRanges
            }
        }
        Write-Verbose "Resolved named locations."
    }
    catch { Write-Warning "Named location lookup failed: $_" }

    # Tier 2 enrichment: group membership (included + excluded groups)
    Get-CAGroupMembershipEnrichment -Policies $Policies

    $script:EnrichmentReady = $true
    Write-Host "Graph resolution complete. Resolved $($script:NameCache.Count) name(s)." -ForegroundColor Green
}

<#
.SYNOPSIS
    Fetches membership for every group used as an exclusion, for Tier 2 rules.

.DESCRIPTION
    For each unique excludeGroups GUID across active policies, queries
    /groups/{id}/members (id-only, paged) to record member count and IDs, and
    /groups/{id} for dynamic-group detection. A 404 marks the group as deleted
    (Exists = $false) - the classic stale-exclusion backdoor CA-016 looks for.
    Member IDs stay in-memory for the run; they are never written to the cache.
#>
function Get-CAGroupMembershipEnrichment {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([object[]] $Policies)

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $groupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($policy in $Policies) {
        if ($policy.state -eq 'disabled') { continue }
        # Both excluded groups (CA-016/017/018) and INCLUDED groups (baseline scope
        # coverage context) need membership counts.
        foreach ($gid in (ConvertTo-SafeArray $policy.conditions.users.excludeGroups)) {
            if ($gid -match $guidPattern) { [void]$groupIds.Add($gid) }
        }
        foreach ($gid in (ConvertTo-SafeArray $policy.conditions.users.includeGroups)) {
            if ($gid -match $guidPattern) { [void]$groupIds.Add($gid) }
        }
    }

    if ($groupIds.Count -eq 0) { return }
    Write-Host "Fetching membership for $($groupIds.Count) group(s) via Graph..." -ForegroundColor DarkGray

    foreach ($gid in $groupIds) {
        # Dynamic-group detection (best-effort; failure is non-fatal)
        $isDynamic = $false
        try {
            $meta = Invoke-MgGraphRequest -Method GET -Uri "v1.0/groups/$gid`?`$select=groupTypes"
            $isDynamic = @($meta.groupTypes) -contains 'DynamicMembership'
        }
        catch { Write-Verbose "Group metadata lookup failed for $gid" }

        # Membership (id-only, paged). A 404 here means the group is deleted.
        $memberIds = [System.Collections.Generic.List[string]]::new()
        $exists = $true
        try {
            $uri = "v1.0/groups/$gid/members?`$select=id&`$top=999"
            do {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
                foreach ($m in $resp.value) { if ($m.id) { $memberIds.Add([string]$m.id) } }
                $uri = $resp.'@odata.nextLink'
            } while ($uri)
        }
        catch {
            if ("$_" -match '404|NotFound|Request_ResourceNotFound|does not exist') {
                $exists = $false
            }
            else {
                Write-Warning "Membership lookup failed for group $gid`: $_"
                continue   # leave this group unenriched rather than assert a wrong count
            }
        }

        $script:GroupEnrichment[$gid] = @{
            Exists      = $exists
            MemberCount = $memberIds.Count
            MemberIds   = @($memberIds)
            IsDynamic   = $isDynamic
        }
    }
}

