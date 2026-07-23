# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/New-CAGapPolicy.ps1

<#
.SYNOPSIS
    Templates that turn a baseline GAP into a ready-to-deploy Conditional Access
    policy JSON (Microsoft Graph / portal "Upload policy file" schema).

.DESCRIPTION
    Single source of truth for both delivery paths: the PowerShell batch writer
    (-GenerateGapPolicies) and the HTML report's per-gap download buttons embed the
    SAME base objects produced here, so they can never drift.

    Safety model:
    - Default state is 'enabledForReportingButNotEnforced' (Report-only) - a
      Report-only policy enforces nothing, so it cannot lock anyone out.
    - A break-glass group id, when supplied, is injected into conditions.users
      .excludeGroups on every policy.
    - New-CAGapPolicyObject REFUSES to build an 'enabled' (On) policy unless a
      break-glass group id is supplied - the tool never hands you a file that is
      one upload away from a tenant lockout.

    The JSON conforms exactly to the documented conditionalAccessPolicy create
    body: required displayName + state + conditions(users, applications), plus
    grantControls and/or sessionControls; no read-only fields (id/createdDateTime/
    modifiedDateTime) are emitted. App ids and role template ids are the
    Microsoft well-known values.
#>

# The 15 privileged directory roles Microsoft's "require MFA for admins" template
# targets (role TEMPLATE ids, stable across tenants).
$script:CAGapAdminRoleIds = @(
    '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'   # Privileged Role Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'   # Security Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'   # SharePoint Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'   # Exchange Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'   # Conditional Access Administrator
    '729827e3-9c14-49f7-bb1b-9608f156bbb8'   # Helpdesk Administrator
    'b0f54661-2d74-4c50-afa3-1ec803f12efe'   # Billing Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'   # User Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'   # Authentication Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'   # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'   # Cloud Application Administrator
    '966707d0-3269-4727-9be2-8c3a10f19b9d'   # Password Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'   # Privileged Authentication Administrator
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451'   # Global Reader
)

# Well-known application id.
$script:CAGapAzureMgmtAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Microsoft Azure Management

<#
.SYNOPSIS
    Returns the ordered list of gap -> policy template definitions.

.DESCRIPTION
    Each definition: Id (baseline rule), FileName, Name (base displayName),
    Build (scriptblock -> the base policy object given $State; no excludeGroups),
    and Note. Baseline gaps NOT listed here cannot be auto-generated cleanly
    (Terms of Use needs an existing ToU object; MDCA needs MDCA configured;
    dir-sync exclusion is an edit to existing policies; risk-based needs P2) -
    Get-CAGapPolicyManualNote covers those.
#>
function Get-CAGapPolicyDefinition {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param()

    @(
        [ordered]@{
            Id = 'CA-023'; FileName = 'CA-023-require-mfa-all-users.json'
            Name = 'CA-023 - Require MFA for all users'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-024'; FileName = 'CA-024-require-mfa-azure-management.json'
            Name = 'CA-024 - Require MFA for Azure management'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @($script:CAGapAzureMgmtAppId) }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-025'; FileName = 'CA-025-require-mfa-guests.json'
            Name = 'CA-025 - Require MFA for guest and external users'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{
                            includeGuestsOrExternalUsers = [ordered]@{
                                guestOrExternalUserTypes = 'b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider,internalGuest'
                                externalTenants          = [ordered]@{ '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'; membershipKind = 'all' }
                            }
                        }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-026'; FileName = 'CA-026-require-managed-device-admins.json'
            Name = 'CA-026 - Require compliant or hybrid-joined device for admins'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeRoles = @($script:CAGapAdminRoleIds) }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('compliantDevice', 'domainJoinedDevice') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-027'; FileName = 'CA-027-secure-security-info-registration.json'
            Name = 'CA-027 - Require MFA to register security information'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        applications = [ordered]@{ includeUserActions = @('urn:user:registersecurityinfo') }
                        users        = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-029'; FileName = 'CA-029-require-mfa-admins.json'
            Name = 'CA-029 - Require MFA for admin roles'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeRoles = @($script:CAGapAdminRoleIds) }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-030'; FileName = 'CA-030-block-authentication-transfer.json'
            Name = 'CA-030 - Block authentication transfer flow'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes      = @('all')
                        applications        = [ordered]@{ includeApplications = @('All') }
                        users               = [ordered]@{ includeUsers = @('All') }
                        authenticationFlows = [ordered]@{ transferMethods = 'authenticationTransfer' }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-031'; FileName = 'CA-031-token-protection.json'
            Name = 'CA-031 - Require token protection for sign-in sessions (Windows)'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('mobileAppsAndDesktopClients')
                        applications   = [ordered]@{ includeApplications = @('Office365') }
                        users          = [ordered]@{ includeUsers = @('All') }
                        platforms      = [ordered]@{ includePlatforms = @('windows') }
                    }
                    sessionControls = [ordered]@{ secureSignInSession = [ordered]@{ isEnabled = $true } }
                }
            }
        }
        [ordered]@{
            Id = 'CA-032'; FileName = 'CA-032-sign-in-frequency.json'
            Name = 'CA-032 - Configure sign-in frequency'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    sessionControls = [ordered]@{ signInFrequency = [ordered]@{ isEnabled = $true; type = 'hours'; value = 8; frequencyInterval = 'timeBased' } }
                }
            }
        }
        [ordered]@{
            Id = 'CA-033'; FileName = 'CA-033-persistent-browser-never.json'
            Name = 'CA-033 - Restrict persistent browser sessions'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    sessionControls = [ordered]@{ persistentBrowser = [ordered]@{ isEnabled = $true; mode = 'never' } }
                }
            }
        }
        [ordered]@{
            Id = 'CA-036'; FileName = 'CA-036-block-exchange-activesync.json'
            Name = 'CA-036 - Block Exchange ActiveSync and legacy authentication'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('exchangeActiveSync', 'other')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-037'; FileName = 'CA-037-require-mfa-device-registration.json'
            Name = 'CA-037 - Require MFA to register or join devices'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        applications = [ordered]@{ includeUserActions = @('urn:user:registerdevice') }
                        users        = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-009'; FileName = 'CA-009-block-device-code-flow.json'
            Name = 'CA-009 - Block device code flow'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes      = @('all')
                        applications        = [ordered]@{ includeApplications = @('All') }
                        users               = [ordered]@{ includeUsers = @('All') }
                        authenticationFlows = [ordered]@{ transferMethods = 'deviceCodeFlow' }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
                }
            }
        }
        [ordered]@{
            Id = 'CA-038'; FileName = 'CA-038-require-managed-device-all-users.json'
            Name = 'CA-038 - Require managed device for all users'
            Build = {
                param($State, $DisplayName)
                [ordered]@{
                    displayName = $DisplayName; state = $State
                    conditions  = [ordered]@{
                        clientAppTypes = @('all')
                        applications   = [ordered]@{ includeApplications = @('All') }
                        users          = [ordered]@{ includeUsers = @('All') }
                    }
                    grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('compliantDevice', 'domainJoinedDevice') }
                }
            }
        }
    )
}

<#
.SYNOPSIS
    Short manual-remediation note for baseline gaps that cannot be auto-generated.
#>
function Get-CAGapPolicyManualNote {
    [CmdletBinding()] [OutputType([hashtable])]
    param()
    return @{
        'CA-019' = 'Risk-based policies need Microsoft Entra ID P2 and per-tenant tuning - create user-risk and sign-in-risk policies in the portal.'
        'CA-028' = 'This is an EXCLUSION to add to existing policies (exclude the Directory Synchronization Accounts role), not a new policy.'
        'CA-034' = 'Requires an existing Terms of Use object to reference - create the ToU in Entra first, then attach it via a grant control.'
        'CA-035' = 'Requires Microsoft Defender for Cloud Apps (MDCA) session controls to be configured before a policy can route sessions to it.'
    }
}

<#
.SYNOPSIS
    Builds a complete, deploy-ready CA policy object from a gap definition.

.DESCRIPTION
    Injects the break-glass group into conditions.users.excludeGroups when
    supplied, applies a display-name marker when it is NOT supplied, and enforces
    the safety rule that an 'enabled' (On) policy can never be built without a
    break-glass group id.
#>
function New-CAGapPolicyObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Definition,
        [string] $BreakGlassGroupId = '',
        [ValidateSet('enabledForReportingButNotEnforced', 'disabled', 'enabled')]
        [string] $State = 'enabledForReportingButNotEnforced'
    )

    if ($State -eq 'enabled' -and -not $BreakGlassGroupId) {
        throw "Refusing to build an 'enabled' (On) policy for $($Definition.Id) without -BreakGlassGroupId. Supply a break-glass group to exclude, or use Report-only/Off."
    }
    if ($BreakGlassGroupId -and $BreakGlassGroupId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw "-BreakGlassGroupId '$BreakGlassGroupId' is not a valid group GUID."
    }

    $name = [string]$Definition.Name
    if (-not $BreakGlassGroupId) { $name = "$name [ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]" }

    $policy = & $Definition.Build $State $name
    if ($BreakGlassGroupId) { $policy.conditions.users.excludeGroups = @($BreakGlassGroupId) }
    return $policy
}

<#
.SYNOPSIS
    Writes deploy-ready gap-remediation policy JSON files for the gaps found in an
    audit, plus a README, into an output folder. STRICTLY read-only w.r.t. the
    tenant: it only writes local files - nothing is sent to Graph.

.DESCRIPTION
    For each baseline control that is a GAP in this audit and has a template, it
    builds + validates the policy and writes <FileName>.json. Gaps without a
    template get a manual-remediation note in the README. Default state is
    Report-only; without -BreakGlassGroupId files carry a name marker and a loud
    warning (and 'enabled' state is refused upstream).
#>
function New-CAGapPolicySet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [string] $OutputFolder,
        [string] $BreakGlassGroupId = '',
        [ValidateSet('enabledForReportingButNotEnforced', 'disabled', 'enabled')]
        [string] $State = 'enabledForReportingButNotEnforced'
    )

    $gapIds = @($Findings |
        Where-Object { $_.PolicyName -match 'baseline check' -and $_.CoverageState -eq 'gap' } |
        ForEach-Object { $_.Id })
    if ($gapIds.Count -eq 0) {
        Write-Host 'No baseline gaps to remediate - nothing to generate.' -ForegroundColor Green
        return
    }

    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

    $defs = Get-CAGapPolicyDefinition
    $manualNotes = Get-CAGapPolicyManualNote
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $generated = [System.Collections.Generic.List[string]]::new()
    $manual = [System.Collections.Generic.List[string]]::new()

    foreach ($gapId in $gapIds) {
        $def = $defs | Where-Object { $_.Id -eq $gapId } | Select-Object -First 1
        if ($def) {
            $obj = New-CAGapPolicyObject -Definition $def -BreakGlassGroupId $BreakGlassGroupId -State $State
            $problems = Test-CAGapPolicyObject -Policy $obj
            if ($problems.Count -gt 0) {
                Write-Warning "Skipped $gapId - generated policy failed validation: $($problems -join ', ')"
                continue
            }
            $path = Join-Path $OutputFolder $def.FileName
            [System.IO.File]::WriteAllText($path, ($obj | ConvertTo-Json -Depth 12), $utf8NoBom)
            $generated.Add($def.FileName)
        }
        elseif ($manualNotes.ContainsKey($gapId)) {
            $manual.Add("$gapId - $($manualNotes[$gapId])")
        }
    }

    Write-CAGapReadme -OutputFolder $OutputFolder -Generated $generated -Manual $manual `
        -BreakGlassGroupId $BreakGlassGroupId -State $State -Encoding $utf8NoBom

    Write-Host ''
    Write-Host "Generated $($generated.Count) gap-remediation policy file(s) in: $OutputFolder" -ForegroundColor Green
    if (-not $BreakGlassGroupId) {
        Write-Host '  WARNING: no -BreakGlassGroupId was supplied. Files are Report-only (safe) and carry a name marker.' -ForegroundColor Yellow
        Write-Host '           Add your emergency-access group to excludeGroups BEFORE setting any policy to On.' -ForegroundColor Yellow
    }
    if ($manual.Count -gt 0) { Write-Host "  $($manual.Count) gap(s) need manual remediation - see README.txt." -ForegroundColor DarkGray }

    return [PSCustomObject]@{ OutputFolder = $OutputFolder; Generated = @($generated); Manual = @($manual) }
}

<#
.SYNOPSIS
    Writes the README.txt that explains how to deploy the generated policies safely.
#>
function Write-CAGapReadme {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputFolder,
        [object[]] $Generated, [object[]] $Manual,
        [string] $BreakGlassGroupId, [string] $State,
        [Parameter(Mandatory)] $Encoding
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('CA Policy Audit - generated gap-remediation policies')
    $lines.Add('====================================================')
    $lines.Add('')
    $lines.Add("These JSON files each close one recommended-baseline GAP found in the audit.")
    $lines.Add("They are generated LOCALLY only - nothing was written to your tenant.")
    $lines.Add('')
    $lines.Add("Default state: $State (Report-only enforces nothing - it cannot lock anyone out).")
    if ($BreakGlassGroupId) {
        $lines.Add("Break-glass exclusion: group $BreakGlassGroupId is excluded on every policy.")
    }
    else {
        $lines.Add('*** NO BREAK-GLASS EXCLUSION WAS SET ***')
        $lines.Add('  - Every file is Report-only and its displayName is marked')
        $lines.Add('    "[ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]".')
        $lines.Add('  - Before setting ANY policy to On, add your emergency-access group to')
        $lines.Add('    conditions.users.excludeGroups (or re-run with -BreakGlassGroupId <guid>).')
    }
    $lines.Add('')
    $lines.Add('How to deploy:')
    $lines.Add('  1. Entra portal > Protection > Conditional Access > Policies > Upload policy file.')
    $lines.Add('  2. Select one .json file and choose the Policy State (start with Report-only).')
    $lines.Add('  3. Review the impact in Insights & Reporting before setting to On.')
    $lines.Add('')
    $lines.Add("Generated files ($($Generated.Count)):")
    foreach ($g in $Generated) { $lines.Add("  - $g") }
    if ($Manual.Count -gt 0) {
        $lines.Add('')
        $lines.Add("Gaps needing MANUAL remediation ($($Manual.Count)) - no clean single-policy exists:")
        foreach ($m in $Manual) { $lines.Add("  - $m") }
    }
    [System.IO.File]::WriteAllText((Join-Path $OutputFolder 'README.txt'), ($lines -join [Environment]::NewLine), $Encoding)
}

<#
.SYNOPSIS
    Structurally validates a generated policy object against the create schema.
    Returns an array of problem strings (empty = valid).
#>
function Test-CAGapPolicyObject {
    [CmdletBinding()] [OutputType([string[]])]
    param([Parameter(Mandatory)] $Policy)

    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $Policy.displayName) { $problems.Add('missing displayName') }
    if ($Policy.state -notin @('enabled', 'disabled', 'enabledForReportingButNotEnforced')) { $problems.Add("invalid state '$($Policy.state)'") }
    if ($null -eq $Policy.conditions) { $problems.Add('missing conditions') }
    else {
        if ($null -eq $Policy.conditions.users) { $problems.Add('missing conditions.users') }
        if ($null -eq $Policy.conditions.applications) { $problems.Add('missing conditions.applications') }
    }
    $hasGrant = $null -ne $Policy.grantControls
    $hasSession = $null -ne $Policy.sessionControls
    if (-not ($hasGrant -or $hasSession)) { $problems.Add('policy has neither grantControls nor sessionControls') }
    # Read-only properties must never be present.
    foreach ($ro in @('id', 'createdDateTime', 'modifiedDateTime')) {
        if ($Policy.Contains($ro)) { $problems.Add("read-only property '$ro' must not be present") }
    }
    return $problems.ToArray()
}
