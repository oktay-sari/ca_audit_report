# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Invoke-CABaselineCoverage.ps1

<#
.SYNOPSIS
    Post-processes the baseline-coverage findings to name the covering policies,
    classify coverage scope (covered / scoped / gap), flag Report-only near-misses,
    and (with Graph enrichment) add non-judgmental membership context.

.DESCRIPTION
    Runs AFTER the rule engine, so the individual baseline rules are never touched
    and their Pass/Fail verdicts are unchanged. It enriches each '(baseline check)'
    finding in place via a single matcher table that re-states each rule's control
    predicate plus the population that requirement expects. Fully offline: the
    membership context is added only when Tier 2 enrichment is available.
#>

# ---------------------------------------------------------------------------
# Population helpers (offline - read the policy JSON only)
# ---------------------------------------------------------------------------
function Test-CAPolicyTargetsAllUsers {
    [CmdletBinding()] [OutputType([bool])]
    param($Policy)
    return ('All' -in @($Policy.conditions.users.includeUsers | Where-Object { $_ }))
}

function Test-CAPolicyCoversGuests {
    [CmdletBinding()] [OutputType([bool])]
    param($Policy)
    $u = $Policy.conditions.users
    if ($u.includeGuestsOrExternalUsers.guestOrExternalUserTypes) { return $true }
    $inc = @($u.includeUsers | Where-Object { $_ })
    return (('All' -in $inc) -or ('GuestsOrExternalUsers' -in $inc))
}

function Test-CAPolicyCoversAdminRoles {
    [CmdletBinding()] [OutputType([bool])]
    param($Policy)
    if (@($Policy.conditions.users.includeRoles | Where-Object { $_ }).Count -gt 0) { return $true }
    return ('All' -in @($Policy.conditions.users.includeUsers | Where-Object { $_ }))
}

function Test-CAPolicyTargetsPopulation {
    [CmdletBinding()] [OutputType([bool])]
    param($Policy, [string] $Population)
    switch ($Population) {
        'AllUsers'   { return (Test-CAPolicyTargetsAllUsers $Policy) }
        'Guests'     { return (Test-CAPolicyCoversGuests $Policy) }
        'AdminRoles' { return (Test-CAPolicyCoversAdminRoles $Policy) }
        default      { return $true }   # 'Any' - population is not the point
    }
}

# ---------------------------------------------------------------------------
# Membership context (Tier 2, non-judgmental). Returns '' when there are no
# specific principals or when enrichment is unavailable (offline).
# ---------------------------------------------------------------------------
function Get-CACoveragePrincipalNote {
    [CmdletBinding()] [OutputType([string])]
    param([object[]] $Policies)

    $enriched = $false
    if (Get-Command Test-CAEnrichmentAvailable -ErrorAction SilentlyContinue) {
        $enriched = [bool](Test-CAEnrichmentAvailable)
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($p in @($Policies)) {
        $u = $p.conditions.users
        # Named users (offline count only)
        $namedUsers = @($u.includeUsers | Where-Object { $_ -and $_ -notin @('All', 'None', 'GuestsOrExternalUsers') })
        if ($namedUsers.Count -gt 0) {
            $key = 'users:' + ($namedUsers -join ',')
            if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $parts.Add("$($namedUsers.Count) named user(s)") }
        }
        # Groups (member count from Tier 2 enrichment when present)
        foreach ($gid in @($u.includeGroups | Where-Object { $_ })) {
            if ($seen.ContainsKey("g:$gid")) { continue }
            $seen["g:$gid"] = $true
            $name = (Resolve-CAIdentity -Id $gid -Type Group).DisplayName
            $suffix = ''
            if ($enriched -and (Get-Command Get-CAGroupEnrichment -ErrorAction SilentlyContinue)) {
                $ge = Get-CAGroupEnrichment -Id $gid
                if ($ge -and $null -ne $ge.MemberCount) {
                    $dyn = if ($ge.IsDynamic) { ', dynamic' } else { '' }
                    $suffix = " (~$($ge.MemberCount) member(s)$dyn)"
                }
            }
            $parts.Add("$name [group]$suffix")
        }
        # Roles - name only (a role-targeted policy is correctly scoped to that
        # role by definition; the per-role member count added many Graph calls for
        # little value, so it is intentionally not fetched).
        foreach ($rid in @($u.includeRoles | Where-Object { $_ })) {
            if ($seen.ContainsKey("r:$rid")) { continue }
            $seen["r:$rid"] = $true
            $name = (Resolve-CAIdentity -Id $rid -Type Role).DisplayName
            $parts.Add("$name [role]")
        }
    }

    if ($parts.Count -eq 0) { return '' }
    # Cap the list so a policy targeting many roles/groups doesn't produce a wall of text.
    $extra = $parts.Count - 6
    $list = if ($parts.Count -gt 6) { (($parts | Select-Object -First 6) -join ' | ') + " | +$extra more" }
            else { $parts -join ' | ' }
    $note = 'Targets: ' + $list + '.'
    if ($enriched) {
        $note += ' Group counts are point-in-time and do not resolve nested/dynamic membership or guests.'
    }
    return $note
}

# ---------------------------------------------------------------------------
# Matcher table: Id -> { Control = <control-only predicate>; Population }
# Rules NOT listed (CA-019 dual-risk, CA-028 inverse-exclusion) don't fit the
# "covered by a policy" model and are left with a Status-derived state only.
# ---------------------------------------------------------------------------
function Get-CABaselineMatcher {
    [CmdletBinding()] [OutputType([hashtable])]
    param()

    # Matcher scriptblocks share the $script:CAHasMfaOrStrength helper set by
    # Update-CABaselineCoverage before these are invoked.
    return @{
        'CA-023' = @{ Population = 'AllUsers'; Control = {
            param($p)
            if (-not (& $script:CAHasMfaOrStrength $p) -or (& $script:CAIsRiskGated $p)) { return $false }
            $apps = @($p.conditions.applications.includeApplications | Where-Object { $_ })
            return (('All' -in $apps) -or ('Office365' -in $apps))
        } }
        'CA-024' = @{ Population = 'AllUsers'; Control = {
            param($p)
            if (-not (& $script:CAHasMfaOrStrength $p) -or (& $script:CAIsRiskGated $p)) { return $false }
            $apps = @($p.conditions.applications.includeApplications | Where-Object { $_ })
            $azure = @('797f4846-ba00-4fd7-ba43-dac1f8f63013', 'MicrosoftAdminPortals', 'All')
            return (@($azure | Where-Object { $_ -in $apps }).Count -gt 0)
        } }
        'CA-025' = @{ Population = 'Guests';     Control = { param($p) (& $script:CAHasMfaOrStrength $p) -and -not (& $script:CAIsRiskGated $p) } }
        'CA-026' = @{ Population = 'AdminRoles'; Control = {
            param($p)
            $b = $p.grantControls.builtInControls
            return ($b -and (('compliantDevice' -in $b) -or ('domainJoinedDevice' -in $b)))
        } }
        'CA-027' = @{ Population = 'Any'; Control = {
            param($p)
            $actions = @($p.conditions.applications.includeUserActions | Where-Object { $_ })
            if ('urn:user:registersecurityinfo' -notin $actions) { return $false }
            $g = $p.grantControls
            $hasCtl = ($g -and $g.builtInControls -and ('mfa' -in $g.builtInControls)) -or ($g -and $null -ne $g.authenticationStrength)
            $hasLoc = ($null -ne $p.conditions.locations) -and (@($p.conditions.locations.includeLocations | Where-Object { $_ }).Count -gt 0)
            return ($hasCtl -or $hasLoc)
        } }
        'CA-029' = @{ Population = 'AdminRoles'; Control = { param($p) (& $script:CAHasMfaOrStrength $p) -and -not (& $script:CAIsRiskGated $p) } }
        'CA-030' = @{ Population = 'AllUsers'; Control = {
            param($p)
            $g = $p.grantControls
            if ($null -eq $g -or -not ($g.builtInControls -and ('block' -in $g.builtInControls))) { return $false }
            $m = $p.conditions.authenticationFlows.transferMethods
            if (-not $m) { return $false }
            $list = if ($m -is [string]) { $m -split ',' } else { @($m) }
            return ('authenticationTransfer' -in ($list | ForEach-Object { "$_".Trim() }))
        } }
        'CA-031' = @{ Population = 'AllUsers'; Control = { param($p) $p.sessionControls.secureSignInSession.isEnabled -eq $true } }
        'CA-032' = @{ Population = 'AllUsers'; Control = { param($p) $p.sessionControls.signInFrequency.isEnabled -eq $true } }
        'CA-033' = @{ Population = 'AllUsers'; Control = {
            param($p)
            $pb = $p.sessionControls.persistentBrowser
            return ($pb.isEnabled -eq $true -and $pb.mode -eq 'never')
        } }
        'CA-034' = @{ Population = 'Any'; Control = { param($p) @($p.grantControls.termsOfUse | Where-Object { $_ }).Count -gt 0 } }
        'CA-035' = @{ Population = 'Any'; Control = { param($p) $p.sessionControls.cloudAppSecurity.isEnabled -eq $true } }
        'CA-036' = @{ Population = 'AllUsers'; Control = {
            param($p)
            $g = $p.grantControls
            if ($null -eq $g -or -not ($g.builtInControls -and ('block' -in $g.builtInControls))) { return $false }
            return ('exchangeActiveSync' -in @($p.conditions.clientAppTypes | Where-Object { $_ }))
        } }
        'CA-037' = @{ Population = 'Any'; Control = {
            param($p)
            $actions = @($p.conditions.applications.includeUserActions | Where-Object { $_ })
            if ('urn:user:registerdevice' -notin $actions) { return $false }
            & $script:CAHasMfaOrStrength $p
        } }
        'CA-009' = @{ Population = 'AllUsers'; Control = {
            param($p)
            $g = $p.grantControls
            if ($null -eq $g -or -not ($g.builtInControls -and ('block' -in $g.builtInControls))) { return $false }
            $m = $p.conditions.authenticationFlows.transferMethods
            if (-not $m) { return $false }
            $list = if ($m -is [string]) { $m -split ',' } else { @($m) }
            return ('deviceCodeFlow' -in ($list | ForEach-Object { "$_".Trim() }))
        } }
        'CA-038' = @{ Population = 'AllUsers'; Control = {
            param($p)
            if (& $script:CAIsRiskGated $p) { return $false }
            $b = $p.grantControls.builtInControls
            if (-not ($b -and (('compliantDevice' -in $b) -or ('domainJoinedDevice' -in $b)))) { return $false }
            $apps = @($p.conditions.applications.includeApplications | Where-Object { $_ })
            return (('All' -in $apps) -or ('Office365' -in $apps))
        } }
    }
}

# ---------------------------------------------------------------------------
# Orchestrator: enrich baseline findings in place.
# ---------------------------------------------------------------------------
function Update-CABaselineCoverage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies
    )

    # Shared control helpers, exposed to the matcher scriptblocks via script scope.
    $script:CAHasMfaOrStrength = {
        param($p)
        $g = $p.grantControls
        if ($null -eq $g) { return $false }
        return (($g.builtInControls -and ('mfa' -in $g.builtInControls)) -or ($null -ne $g.authenticationStrength))
    }
    # A policy gated by a risk condition only enforces MFA for risky sign-ins.
    $script:CAIsRiskGated = {
        param($p)
        return (@($p.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0 -or
                @($p.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0)
    }

    $matchers = Get-CABaselineMatcher
    $active = @($Policies | Where-Object { $_.state -eq 'enabled' })
    $reportOnly = @($Policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    foreach ($f in @($Findings | Where-Object { $_.PolicyName -eq 'baseline check' -or $_.PolicyName -eq '(baseline check)' })) {
        $m = $matchers[$f.Id]

        if ($null -eq $m) {
            # Non-fitting rule (CA-019 / CA-028): derive state from Status only.
            # NotApplicable is neither covered nor a gap - it does not count either way.
            $f.CoverageState = switch ($f.Status) {
                'Pass'          { 'covered' }
                'NotApplicable' { 'na' }
                default         { 'gap' }
            }
            continue
        }

        $controlOn = @($active | Where-Object { & $m.Control $_ })
        if ($m.Population -eq 'AllUsers') {
            $full = @($controlOn | Where-Object { Test-CAPolicyTargetsAllUsers $_ })
            $scoped = @($controlOn | Where-Object { -not (Test-CAPolicyTargetsAllUsers $_) })
        }
        else {
            $full = @($controlOn | Where-Object { Test-CAPolicyTargetsPopulation $_ $m.Population })
            $scoped = @()
        }

        if ($full.Count -gt 0) {
            $f.CoverageState = 'covered'
            $f.CoveredBy = @($full | ForEach-Object { $_.displayName })
            $note = Get-CACoveragePrincipalNote -Policies $full
            # Note any exclusions on an All-users cover (neutral - often break-glass).
            $excl = @($full | Where-Object { @($_.conditions.users.excludeGroups).Count -gt 0 -or @($_.conditions.users.excludeUsers).Count -gt 0 })
            if ($m.Population -eq 'AllUsers' -and $excl.Count -gt 0) {
                $note = ($note + ' Some covering policy excludes specific principals - verify these are intended (e.g. break-glass).').Trim()
            }
            $f.ScopeNote = $note
        }
        elseif ($scoped.Count -gt 0) {
            $f.CoverageState = 'scoped'
            $f.CoveredBy = @($scoped | ForEach-Object { $_.displayName })
            $mem = Get-CACoveragePrincipalNote -Policies $scoped
            $f.ScopeNote = ('Scoped to specific groups/roles/users rather than All users - verify this covers your intended population. ' + $mem).Trim()
        }
        else {
            $f.CoverageState = 'gap'
            $roCover = @($reportOnly | Where-Object { & $m.Control $_ } | ForEach-Object { $_.displayName })
            if ($roCover.Count -gt 0) {
                $f.ReportOnlyCandidate = $roCover
                $f.ScopeNote = "A Report-only policy would cover this if promoted to On: $($roCover -join ', ')."
            }
        }

        # Flag when a COVERING policy looks like a test/staging policy - surfaced in
        # the Action column so it isn't missed. Only if the helper is available.
        if (Get-Command Test-CATestPolicyName -ErrorAction SilentlyContinue) {
            $covering = if ($full.Count -gt 0) { $full } elseif ($scoped.Count -gt 0) { $scoped } else { @() }
            $testCovers = @($covering | Where-Object { Test-CATestPolicyName ([string]$_.displayName) })
            if ($testCovers.Count -gt 0) {
                $tnames = (@($testCovers | ForEach-Object { $_.displayName }) | Select-Object -First 3) -join '; '
                $f.Remediation = ([string]$f.Remediation + " [!] Coverage relies on a policy that looks like a test/staging policy ($tnames) - confirm production coverage does not depend on it.").Trim()
            }
        }
    }
}
