#Requires -Version 5.1
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path Invoke-CAPolicyAudit.ps1
#
# Suppressions:
#   PSAvoidUsingWriteHost - interactive CLI tool, colored console output is intentional

<#
.SYNOPSIS
    Audits Conditional Access policies from JSON exports (or a live tenant) and
    produces a self-contained interactive HTML report with a security scorecard,
    baseline gap analysis, and cross-reference matrix.

.DESCRIPTION
    Reads Conditional Access policies (from JSON exports or a live tenant via
    Microsoft Graph, read-only), analyzes them against 38 security rules, and
    generates a single self-contained interactive HTML report (no network calls,
    works offline) suitable for consulting deliverables. The report has a
    printable one-page summary you can Save as PDF.

    Report tabs:
      - Policy Overview:    One row per policy, all settings in readable columns
      - Security Checks:    Automated checks with risk rating and remediation
      - Baseline Coverage:  Recommended-baseline scorecard (Covered/Gap per control)
      - Platform Matrix:    Approximate effective control per device platform
      - Cross-Reference:    Exclusion matrix (who skips what)
      - CA Policy Groups:   Included/excluded principals per policy
      - Not Evaluated:      Checks that require Graph access (Tier 2)
      - Group Membership:   Live group members (only with -ResolveNames)
      - Reference:          What each rule id (CA-NNN) checks

    By default runs fully offline using well-known ID maps for roles, apps, and
    controls. Use -ResolveNames to connect read-only to Microsoft Graph and
    resolve all tenant-specific GUIDs to display names.

.PARAMETER Source
    Where policies come from: 'Files' (default) reads exported JSON from
    -JsonFolder; 'Tenant' fetches them live from Microsoft Graph (read-only,
    interactive sign-in) and auto-resolves names. Tenant mode never writes to the
    tenant.

.PARAMETER JsonFolder
    Path to the folder containing Conditional Access policy JSON files.
    Accepts single-policy files, arrays, or Graph API {value:[...]} wrappers.
    Optional: if omitted (and the host is interactive), a guided setup runs.

.PARAMETER Interactive
    Launch the guided setup wizard even when other parameters are supplied. The
    wizard also runs automatically when -JsonFolder is omitted. It offers a quick
    path (folder, saved to the current folder) and an advanced path (output
    location, Graph resolution, companion file, exclude pattern), and prints the
    equivalent command line for reuse.

.PARAMETER OutputPath
    Path to the .html report to create. Defaults to CA-Policy-Audit.html in the
    current directory. The report is a self-contained interactive HTML file
    (search, sort, severity filters, printable/PDF summary) that works offline.

.PARAMETER CompanionFile
    Path to a companion name map (IntuneManagement MigrationTable.json, or a
    plain { "<guid>": "<name>" } map) for offline GUID resolution. If omitted, a
    MigrationTable.json next to the policies (or its parent folder) is used
    automatically. Companion names are never written to the name cache.

.PARAMETER ExcludePattern
    Regex matched (case-insensitively) against each policy's displayName;
    matching policies are excluded before analysis. Example: -ExcludePattern
    'TEST' drops test/staging policies. Off by default.

.PARAMETER ResolveNames
    Connect to Microsoft Graph (read-only) and resolve tenant-specific IDs
    (users, groups, apps, named locations) to display names. Resolved names
    are cached to a per-user app-data directory (not the repo) for future
    offline runs - %LOCALAPPDATA%\ca-audit on Windows, ~/.local/share/ca-audit
    (or the platform equivalent) on macOS/Linux.

    Required Graph scopes: Policy.Read.All and Directory.Read.All (read-only).
    Application.Read.All is NOT required - service principals are read under
    Directory.Read.All, and only the app IDs referenced by policies are looked up.

    Before using any tenant data the tool prints the signed-in tenant
    (organization, tenant id, account). If a cached Graph session would be
    reused, it asks you to confirm the tenant first (default No) so you never
    read the wrong tenant by accident.

.PARAMETER TenantId
    Optional tenant GUID you expect to connect to. When supplied, the tool
    verifies the signed-in Graph tenant matches this id and aborts on mismatch,
    instead of prompting - useful for non-interactive / scheduled runs. Omit it
    to confirm the tenant interactively when a cached session is reused.

.PARAMETER GenerateGapPolicies
    Also write deploy-ready remediation policy JSON files - one per closable
    baseline GAP found in the audit - that you can upload via the Entra portal's
    "Upload policy file". Local files only; nothing is written to the tenant.
    Files default to Report-only state (enforces nothing, cannot lock anyone out).

.PARAMETER PolicyOutputFolder
    Folder for the generated gap-remediation policies (with -GenerateGapPolicies).
    Defaults to a 'generated-policies' folder next to the report output.

.PARAMETER BreakGlassGroupId
    Emergency-access (break-glass) group GUID to exclude on every generated gap
    policy. Strongly recommended: without it, generated files are Report-only and
    carry an "[ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]" name marker, and the
    tool refuses to generate any 'On'-state policy.

.PARAMETER Recurse
    Search subfolders for JSON files.

.EXAMPLE
    .\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies

    Offline audit with well-known ID maps. GUIDs for tenant-specific objects
    (users, groups, named locations) appear as placeholders.

.EXAMPLE
    .\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies -ResolveNames

    Full audit with Graph name resolution. All GUIDs resolved to display names.

.EXAMPLE
    .\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies -OutputPath .\Client-CA-Audit.html

    Custom output path for the interactive HTML report.

.NOTES
    Requirements:
      - PowerShell 5.1 or later
      - Microsoft.Graph.Authentication module (only for -ResolveNames)

    No third-party report dependency: the interactive HTML report is generated
    with built-in PowerShell only.

    Read-only. This script does not modify any policies or tenant configuration.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [ValidateSet('Files', 'Tenant')]
    [string] $Source = 'Files',

    [string] $JsonFolder = '',

    [switch] $Interactive,

    [string] $OutputPath = '.\CA-Policy-Audit.html',

    [string] $CompanionFile = '',

    [string] $ExcludePattern = '',

    [switch] $ResolveNames,

    [string] $TenantId = '',

    [switch] $GenerateGapPolicies,

    [string] $PolicyOutputFolder = '',

    [string] $BreakGlassGroupId = '',

    [switch] $Recurse
)

# ---------------------------------------------------------------------------
# 0. Setup
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# Dot-source modules (no third-party report dependency - HTML is built with
# built-in PowerShell only)
$modulesPath = Join-Path $scriptRoot 'modules'
. (Join-Path $modulesPath 'Import-CAPolicies.ps1')
. (Join-Path $modulesPath 'Import-CAGraph.ps1')
. (Join-Path $modulesPath 'Resolve-CAIdentities.ps1')
. (Join-Path $modulesPath 'Export-CAOverview.ps1')
. (Join-Path $modulesPath 'Invoke-CAFindings.ps1')
. (Join-Path $modulesPath 'Invoke-CABaselineCoverage.ps1')
. (Join-Path $modulesPath 'New-CAGapPolicy.ps1')
. (Join-Path $modulesPath 'Get-CARuleReference.ps1')
. (Join-Path $modulesPath 'Export-CAReport.ps1')
. (Join-Path $modulesPath 'Export-CAHtml.ps1')
. (Join-Path $modulesPath 'Invoke-CAInteractive.ps1')

# ---------------------------------------------------------------------------
# 0. Guided interactive setup (explicit -Interactive, or no -JsonFolder given)
# ---------------------------------------------------------------------------
if ($Interactive -or ([string]::IsNullOrWhiteSpace($JsonFolder) -and $Source -eq 'Files')) {
    if (-not [Environment]::UserInteractive) {
        throw "No -JsonFolder specified and the host is not interactive. Provide -JsonFolder (or -Source Tenant), e.g.: .\Invoke-CAPolicyAudit.ps1 -JsonFolder .\policies"
    }
    $setup = Start-CAInteractiveSetup
    if ($null -eq $setup) { return }
    $Source = $setup.Source
    $JsonFolder = $setup.JsonFolder
    $OutputPath = $setup.OutputPath
    $Recurse = [switch]$setup.Recurse
    $ResolveNames = [switch]$setup.ResolveNames
    $CompanionFile = $setup.CompanionFile
    $ExcludePattern = $setup.ExcludePattern
}

# Tenant mode fetches live via Graph and resolves names automatically.
if ($Source -eq 'Tenant') { $ResolveNames = [switch]$true }

# Optional expected-tenant guard. When set, Connect-CAGraph verifies the signed-in
# tenant matches (and aborts on mismatch) instead of prompting. Shared with the
# dot-sourced Graph functions via script scope.
if ($TenantId) {
    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw "-TenantId must be a tenant GUID (e.g. 1234abcd-89ef-4567-89ab-1234567890ab)."
    }
}
$script:CAExpectedTenantId = $TenantId

Write-Host ''
Write-Host '  CA Policy Audit Tool' -ForegroundColor Cyan
Write-Host '  ====================' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------------------
# 1. Import policies
# ---------------------------------------------------------------------------
if ($Source -eq 'Tenant') {
    Write-Host '[1/4] Fetching policies from the tenant (read-only)...' -ForegroundColor White
}
else {
    Write-Host '[1/4] Importing policies...' -ForegroundColor White
}
try {
    if ($Source -eq 'Tenant') {
        $policies = Get-CAPolicySetFromGraph -ExcludePattern $ExcludePattern
    }
    else {
        $policies = Import-CAPolicySet -JsonFolder $JsonFolder -ExcludePattern $ExcludePattern -Recurse:$Recurse
    }
}
catch {
    # Turn the "nothing to evaluate" conditions into a clean, actionable message
    # instead of a raw exception/stack trace. Unexpected errors still surface.
    $msg = "$($_.Exception.Message)"
    Write-Host ''
    switch -Regex ($msg) {
        'Invalid -ExcludePattern' {
            Write-Host '  The -ExcludePattern value is not a valid regular expression.' -ForegroundColor Yellow
            Write-Host "  $msg" -ForegroundColor Gray
        }
        'excluded by -ExcludePattern' {
            Write-Host '  Every policy was excluded by -ExcludePattern - nothing left to analyze.' -ForegroundColor Yellow
            Write-Host '  Loosen or remove the -ExcludePattern regex and try again.' -ForegroundColor Gray
        }
        'connect to Microsoft Graph|read Conditional Access policies from Graph' {
            Write-Host '  Could not read policies from the tenant.' -ForegroundColor Yellow
            Write-Host "  $msg" -ForegroundColor Gray
        }
        'Folder not found' {
            Write-Host '  No Conditional Access policies to evaluate.' -ForegroundColor Yellow
            Write-Host "  The folder was not found: $JsonFolder" -ForegroundColor White
            Write-Host '  Check the -JsonFolder path.' -ForegroundColor Gray
        }
        'No \.json files' {
            Write-Host '  No Conditional Access policies to evaluate.' -ForegroundColor Yellow
            Write-Host "  No .json files were found in: $JsonFolder" -ForegroundColor White
            Write-Host '  Point -JsonFolder at a folder of exported CA policy JSON files.' -ForegroundColor Gray
            Write-Host '  See the README section "How to Export CA Policies".' -ForegroundColor Gray
        }
        'No valid Conditional Access' {
            Write-Host '  No Conditional Access policies to evaluate.' -ForegroundColor Yellow
            if ($Source -eq 'Tenant') {
                Write-Host '  The tenant returned no Conditional Access policies.' -ForegroundColor White
            }
            else {
                Write-Host "  JSON files were found in $JsonFolder, but none look like Conditional Access policies" -ForegroundColor White
                Write-Host '  (each must have a "conditions" block and a "state").' -ForegroundColor White
                Write-Host '  Export policies as single JSON files, arrays, or a Graph {value:[...]} response.' -ForegroundColor Gray
                Write-Host '  See the README section "How to Export CA Policies".' -ForegroundColor Gray
            }
        }
        default { throw }   # unexpected - do not swallow real errors
    }
    Write-Host ''
    return
}

# Resolve companion name map: explicit -CompanionFile, else auto-detect a
# MigrationTable.json sitting next to the policies (or in the parent folder).
# It only resolves the GUIDs of the export it shipped with; a non-match is
# harmless (stays unresolved), so auto-detect is safe.
$companionPath = ''
if ($CompanionFile) {
    $companionPath = $CompanionFile
}
elseif ($Source -eq 'Files' -and $JsonFolder) {
    # Only meaningful for file sources; Tenant mode resolves names live.
    foreach ($candidate in @(
            (Join-Path $JsonFolder 'MigrationTable.json'),
            (Join-Path (Split-Path $JsonFolder -Parent) 'MigrationTable.json'))) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $companionPath = $candidate; break }
    }
}

# The resolver holds tenant-specific names/membership in memory; clear it in a
# finally so nothing lingers even if the run errors or is interrupted.
$findings = @()
try {
    # -----------------------------------------------------------------------
    # 2. Initialize name resolver
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[2/4] Initializing name resolver...' -ForegroundColor White
    $dataFolder = Join-Path $scriptRoot 'data'
    $resolveParams = @{
        DataFolder    = $dataFolder
        Policies      = $policies
        ResolveNames  = $ResolveNames
        CompanionFile = $companionPath
    }
    Initialize-CANameResolver @resolveParams

    # Output path: the interactive HTML report (extension derived from -OutputPath).
    $baseFull = [System.IO.Path]::GetFullPath($OutputPath)
    $htmlPath = if ($baseFull -match '\.html?$') { $baseFull } else { [System.IO.Path]::ChangeExtension($baseFull, '.html') }
    $outputsWritten = @()

    # -----------------------------------------------------------------------
    # 3. Run findings engine
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[3/4] Running security analysis...' -ForegroundColor White
    $rulesFolder = Join-Path $scriptRoot 'rules'
    $ruleCount = @(Get-ChildItem -Path $rulesFolder -Filter 'CA-*.ps1' -File -ErrorAction SilentlyContinue).Count
    $findings = Invoke-CAFindingSet -Policies $policies -RulesFolder $rulesFolder

    # -----------------------------------------------------------------------
    # 4. Write the interactive HTML report
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[4/4] Writing report...' -ForegroundColor White
    $sourceLabel = if ($Source -eq 'Tenant') { Get-CATenantName } else { Split-Path $JsonFolder -Leaf }
    $htmlMeta = @{
        Title     = 'Conditional Access Policy Audit'
        Tenant    = $sourceLabel
        RuleCount = $ruleCount
        Generated = (Get-Date -Format 'yyyy-MM-dd')
    }
    Export-CAHtmlReport -Findings $findings -Policies $policies -OutputPath $htmlPath -Meta $htmlMeta
    $outputsWritten += $htmlPath

    # -----------------------------------------------------------------------
    # 5b. Optional: generate deploy-ready remediation policy JSON for each gap.
    #     Local files only - strictly read-only w.r.t. the tenant.
    # -----------------------------------------------------------------------
    if ($GenerateGapPolicies) {
        $gapFolder = if ($PolicyOutputFolder) { $PolicyOutputFolder }
                     else { Join-Path (Split-Path $OutputPath -Parent) 'generated-policies' }
        Write-Host ''
        Write-Host '      Generating gap-remediation policy files...' -ForegroundColor White
        $null = New-CAGapPolicySet -Findings $findings -OutputFolder $gapFolder -BreakGlassGroupId $BreakGlassGroupId
    }

    # Save name cache if Graph was used (companion names are never saved)
    if ($ResolveNames) {
        Save-CANameCache
    }
}
finally {
    # Wipe tenant-specific names/membership from memory after the run.
    Clear-CAResolverState
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$failCount = @($findings | Where-Object { $_.Status -eq 'Fail' }).Count
$passCount = @($findings | Where-Object { $_.Status -eq 'Pass' }).Count
$naCount = @($findings | Where-Object { $_.Status -eq 'NotApplicable' }).Count
$notEvalCount = @($findings | Where-Object { $_.Status -eq 'NotEvaluated' }).Count
$critCount = @($findings | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
$highCount = @($findings | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' }).Count

Write-Host ''
Write-Host '  ==============================================' -ForegroundColor Cyan
Write-Host '  Audit Complete' -ForegroundColor Cyan
Write-Host '  ==============================================' -ForegroundColor Cyan
Write-Host "  Policies analyzed:   $($policies.Count)" -ForegroundColor White
Write-Host "  Rules evaluated:     $ruleCount" -ForegroundColor White
Write-Host "  Findings:            $failCount fail, $passCount pass, $naCount n/a, $notEvalCount not evaluated" -ForegroundColor White

if ($critCount -gt 0) {
    Write-Host "  Critical:            $critCount" -ForegroundColor Red
}
if ($highCount -gt 0) {
    Write-Host "  High:                $highCount" -ForegroundColor Yellow
}

Write-Host ''
foreach ($out in $outputsWritten) {
    Write-Host "  Report saved to: $out" -ForegroundColor Green
}
Write-Host ''

