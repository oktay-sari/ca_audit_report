# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Export-CAHtml.ps1

<#
.SYNOPSIS
    Renders the CA audit as a self-contained interactive HTML report.

.DESCRIPTION
    Produces a single .html file (inline CSS + JS, no network calls) with the
    same tabs as the Excel report: clickable summary tiles, live search,
    sortable columns, severity filters, expandable findings, a printable
    summary (paginates across pages), and a light/dark toggle.

    It reuses the exact same row-builder functions as the Excel export
    (Build-FindingRow's source data, Build-BaselineCoverageRow,
    Build-PlatformMatrixRow, Build-CrossReferenceRow, Build-PolicyGroupsRow,
    Build-GroupMembershipRow, Build-NotEvaluatedRow, ConvertTo-OverviewRow) so
    the two formats can never drift.

    All data is embedded as JSON with <, >, & escaped to \uXXXX to prevent
    </script> breakout; the page additionally HTML-escapes every value at render
    time, so tenant content (e.g. a policy displayName containing markup) can
    never execute.
#>

$script:CASevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4; 'Good' = 5 }

function Export-CAHtmlReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [object[]] $Policies,
        [Parameter(Mandatory)] [string] $OutputPath,
        [hashtable] $Meta = @{}
    )

    $data = Build-CAHtmlData -Findings $Findings -Policies $Policies -Meta $Meta
    $json = ConvertTo-CAJsonSafe $data

    $title = ConvertTo-CAHtmlText (Get-CAOrDefault ([string]$Meta.Title) 'Conditional Access Policy Audit')
    $tenant = ConvertTo-CAHtmlText (Get-CAOrDefault ([string]$Meta.Tenant) 'CA policy export')
    $policyCount = [int]$data.summary.policies
    $ruleCount = [int]$data.summary.rules
    $genDate = ConvertTo-CAHtmlText ([string]$data.summary.generated)

    $style = Get-CAHtmlStyle
    $script = Get-CAHtmlScript

    # All Things Cloud branding: embed the logo assets as base64 data URIs so the
    # report stays fully self-contained (no network calls). Falls back to the
    # built-in "CA" shield if the asset files are missing.
    $assetsDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'assets'
    $emblemUri = ''
    $logoFullUri = ''
    $emblemPath = Join-Path $assetsDir 'atc-logo-emblem.png'
    $logoPath = Join-Path $assetsDir 'atc-logo-full.png'
    if (Test-Path $emblemPath) {
        $emblemUri = 'data:image/png;base64,' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($emblemPath))
    }
    if (Test-Path $logoPath) {
        $logoFullUri = 'data:image/png;base64,' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($logoPath))
    }
    if ($emblemUri) {
        $brandMark = "<div class=""brand-logo""><img src=""$emblemUri"" alt=""All Things Cloud""></div>"
    }
    else {
        $brandMark = '<div class="shield">CA</div>'
    }

    $html = @"
<title>$title</title>
<style>
$style
</style>

<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      $brandMark
      <div>
        <h1>$title</h1>
        <p class="sub">Source <span class="mono">$tenant</span></p>
      </div>
    </div>
    <div class="spacer"></div>
    <div class="meta-pill">
      <span><b>$policyCount</b> policies</span>
      <span><b>$ruleCount</b> rules</span>
      <span>generated <b>$genDate</b></span>
    </div>
    <button class="icon-btn" id="printBtn" title="Preview a printable summary" aria-label="Printable summary" style="width:auto;padding:0 12px;gap:6px;font-size:12.5px;font-weight:600">&#128424;&#65039; Summary</button>
    <button class="icon-btn" id="themeBtn" title="Toggle light / dark" aria-label="Toggle theme">&#9681;</button>
  </div>
</header>

<div class="preview" id="preview" hidden aria-modal="true" role="dialog" aria-label="Printable summary preview">
  <div class="pv-bar">
    <div class="t">Printable summary <small>save as PDF or print &middot; paginates automatically</small></div>
    <div class="sp"></div>
    <button class="btn ghost" id="pvClose" title="Back to the interactive report">Close</button>
    <button class="btn primary" id="pvPrint" title="Open the print dialog (choose Save as PDF)">Print / Save PDF</button>
  </div>
  <div class="page" id="pvPage"></div>
</div>

<div class="wrap">
  <div class="posture" id="posture" style="margin-top:20px"></div>
  <div class="dash" id="dash"></div>
  <p class="hint">Click a tile or a posture segment to filter findings &middot; fully offline &mdash; search, sort, and expand any finding.</p>
  <nav class="tabs" id="tabs" role="tablist"></nav>
  <section class="panel" id="panel" role="tabpanel"></section>
  <div class="foot">
    <span>CA Policy Audit Tool &middot; interactive HTML report</span><span class="dot"></span>
    <span>All values HTML-escaped</span><span class="dot"></span>
    <span>Self-contained &middot; no network calls</span>
  </div>
</div>

<script>
const DATA = $json;
const ATC = { emblem: "$emblemUri", logo: "$logoFullUri" };
$script
</script>
"@

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
    Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Data assembly (reuses the shared row builders)
# ---------------------------------------------------------------------------
function Build-CAHtmlData {
    [CmdletBinding()]
    param([object[]] $Findings, [object[]] $Policies, [hashtable] $Meta)

    $fail = @($Findings | Where-Object { $_.Status -eq 'Fail' })
    $pass = @($Findings | Where-Object { $_.Status -eq 'Pass' })
    $na = @($Findings | Where-Object { $_.Status -eq 'NotApplicable' })
    $notEval = @($Findings | Where-Object { $_.Status -eq 'NotEvaluated' })

    $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0; Good = $pass.Count }
    foreach ($f in $fail) { if ($counts.Contains($f.Severity)) { $counts[$f.Severity]++ } }

    $baseline = @(Build-BaselineCoverageRow -FindingList $Findings)
    # 'Covered' is fully covered; 'Covered (scoped)' is counted separately (not as covered).
    # 'N/A' controls (no enforcing policy to evaluate) count toward NEITHER the covered
    # numerator NOR the applicable-controls denominator, so they can't inflate coverage.
    $covered = @($baseline | Where-Object { $_.Status -eq 'Covered' }).Count
    $scopedCount = @($baseline | Where-Object { $_.Status -eq 'Covered (scoped)' }).Count
    $baselineApplicable = @($baseline | Where-Object { $_.Status -ne 'N/A' }).Count

    $priority = @($fail | Where-Object { $_.Severity -in @('Critical', 'High') } |
        Sort-Object { $script:CASevOrder[$_.Severity] } |
        ForEach-Object { [ordered]@{ name = $_.Name; risk = $_.Severity; rec = $_.Remediation } })
    $gaps = @($baseline | Where-Object { $_.Status -eq 'Gap' } |
        ForEach-Object { [ordered]@{ control = $_.Control; priority = $_.Priority } })

    $matrix = @(Build-PlatformMatrixRow -PolicyList $Policies)
    $matrixSummary = @($matrix | ForEach-Object {
            [ordered]@{
                platform = $_.Platform
                bu = (Split-CACellMain $_.'Browser - unmanaged')
                bm = (Split-CACellMain $_.'Browser - managed')
                au = (Split-CACellMain $_.'Apps - unmanaged')
                am = (Split-CACellMain $_.'Apps - managed')
            }
        })

    $tabs = @()

    # --- Security Checks ---
    # Fail + Pass are the checks shown here. NotApplicable is included defensively
    # (no rule currently emits it) so any future N/A check would surface too.
    $fp = @($Findings | Where-Object { $_.Status -in @('Fail', 'Pass', 'NotApplicable') } |
        Sort-Object { $script:CASevOrder[$_.Severity] }, Name)
    $tabs += [ordered]@{
        id = 'findings'; label = 'Security Checks'; kind = 'table'
        columns = @(
            [ordered]@{ key = 'name'; label = 'Finding'; type = 'primary' }
            [ordered]@{ key = 'risk'; label = 'Risk'; type = 'sev' }
            [ordered]@{ key = 'status'; label = 'Status'; type = 'status' }
            [ordered]@{ key = 'affected'; label = 'Affected'; type = 'mono' }
            [ordered]@{ key = 'why'; label = 'Why it matters'; type = 'wrap'; detail = $true }
            [ordered]@{ key = 'rec'; label = 'Recommendation'; type = 'wrap'; detail = $true }
        )
        rows = @($fp | ForEach-Object { [ordered]@{ name = $_.Name; risk = $_.Severity; status = $_.Status; affected = $_.PolicyName; why = $_.Detail; rec = $_.Remediation } })
    }

    # --- Baseline Coverage ---
    if ($baseline.Count -gt 0) {
        $tabs += [ordered]@{
            id = 'baseline'; label = 'Baseline Coverage'; kind = 'table'
            note = ("$covered of $($baseline.Count) recommended controls fully covered (Microsoft + community baseline)." + $(if ($scopedCount -gt 0) { " $scopedCount covered but scoped - verify intended population." } else { '' }) + " Gaps first.")
            columns = @(
                [ordered]@{ key = 'status'; label = 'Status'; type = 'status' }
                [ordered]@{ key = 'control'; label = 'Recommended control'; type = 'primary' }
                [ordered]@{ key = 'priority'; label = 'Priority'; type = 'sev' }
                [ordered]@{ key = 'action'; label = 'Action to close'; type = 'wrap' }
                [ordered]@{ key = 'details'; label = 'Details'; type = 'wrap'; detail = $true }
            )
            rows = @($baseline | ForEach-Object { [ordered]@{ status = $_.Status; control = $_.Control; priority = $_.Priority; action = $_.Action; details = $_.Details } })
        }
    }

    # --- Platform Matrix ---
    if ($matrix.Count -gt 0) {
        $gs = @(Get-CAGroupScopedO365Policy -PolicyList $Policies)
        $note = 'Shows the effective control to Office 365 from All-users Conditional Access policies only. It ignores device filters, location/risk conditions, and session controls, and does NOT reflect protection from outside Conditional Access (Security Defaults, per-user MFA, authentication-methods policy). A "gap" here means no CA policy supplies the control - not that the tenant is unprotected. Always verify with Entra What-If.'
        if ($gs.Count -gt 0) { $note += ' Group-scoped O365 policies not shown: ' + ($gs -join '; ') + '.' }
        $tabs += [ordered]@{
            id = 'matrix'; label = 'Platform Matrix'; kind = 'matrix'; note = $note
            columns = @(
                [ordered]@{ key = 'platform'; label = 'Platform' }
                [ordered]@{ key = 'bu'; label = 'Browser - unmanaged' }
                [ordered]@{ key = 'bm'; label = 'Browser - managed' }
                [ordered]@{ key = 'au'; label = 'Apps - unmanaged' }
                [ordered]@{ key = 'am'; label = 'Apps - managed' }
            )
            rows = @($matrix | ForEach-Object {
                    [ordered]@{
                        platform = $_.Platform
                        bu = (Split-CACellPair $_.'Browser - unmanaged')
                        bm = (Split-CACellPair $_.'Browser - managed')
                        au = (Split-CACellPair $_.'Apps - unmanaged')
                        am = (Split-CACellPair $_.'Apps - managed')
                    }
                })
        }
    }

    # --- Policy Overview ---
    $ovRows = @()
    $n = 0
    foreach ($p in $Policies) {
        $n++
        $r = ConvertTo-OverviewRow -Policy $p -RowNumber $n
        $ovRows += [ordered]@{
            policy = $r.'Policy name'; state = $r.State; applies = $r.'Applies to'
            target = $r.'Target resources'; grant = $r.'Grant controls'; logic = $r.Logic; session = $r.'Session controls'
            included = $r.'Users / roles INCLUDED'; excluded = $r.'EXCLUDED (users/groups/roles)'
            locations = $r.'Network / Locations'; platforms = $r.'Device platforms'; clients = $r.'Client apps'; other = $r.'Other conditions'
        }
    }
    if ($ovRows.Count -gt 0) {
        $tabs += [ordered]@{
            id = 'overview'; label = 'Policy Overview'; kind = 'table'
            columns = @(
                [ordered]@{ key = 'policy'; label = 'Policy name'; type = 'primary' }
                [ordered]@{ key = 'state'; label = 'State'; type = 'state' }
                [ordered]@{ key = 'applies'; label = 'Applies to'; type = 'text' }
                [ordered]@{ key = 'target'; label = 'Target resources'; type = 'text' }
                [ordered]@{ key = 'grant'; label = 'Grant'; type = 'text' }
                [ordered]@{ key = 'logic'; label = 'Logic'; type = 'text' }
                [ordered]@{ key = 'session'; label = 'Session'; type = 'text' }
                [ordered]@{ key = 'included'; label = 'Included'; type = 'wrap'; detail = $true }
                [ordered]@{ key = 'excluded'; label = 'Excluded'; type = 'wrap'; detail = $true }
                [ordered]@{ key = 'locations'; label = 'Network / locations'; type = 'wrap'; detail = $true }
                [ordered]@{ key = 'platforms'; label = 'Device platforms'; type = 'text'; detail = $true }
                [ordered]@{ key = 'clients'; label = 'Client apps'; type = 'text'; detail = $true }
                [ordered]@{ key = 'other'; label = 'Other conditions'; type = 'wrap'; detail = $true }
            )
            rows = $ovRows
        }
    }

    # --- Cross-Reference (dynamic columns) ---
    $xref = @(Build-CrossReferenceRow -PolicyList $Policies)
    if ($xref.Count -gt 0) {
        $tabs += [ordered]@{
            id = 'crossref'; label = 'Cross-Reference'; kind = 'table'
            note = 'Principals excluded from multiple policies (and external tenants). X marks an exclusion.'
            columns = (Get-CADerivedColumns -Rows $xref -Overrides @{ 'Principal' = 'primary'; 'Exclusions' = 'num'; 'Risk note' = 'wrap' })
            rows = @($xref | ForEach-Object { ConvertTo-CAOrderedRow $_ })
        }
    }

    # --- CA Policy Groups (dynamic columns) ---
    $pg = @(Build-PolicyGroupsRow -PolicyList $Policies)
    if ($pg.Count -gt 0) {
        $tabs += [ordered]@{
            id = 'policygroups'; label = 'CA Policy Groups'; kind = 'table'
            note = 'Included and excluded principals (users, groups, roles, guests) per policy.'
            columns = (Get-CADerivedColumns -Rows $pg -Overrides @{ 'Policy Name' = 'primary'; 'State' = 'state'; '# Incl' = 'num'; '# Excl' = 'num' })
            rows = @($pg | ForEach-Object { ConvertTo-CAOrderedRow $_ })
        }
    }

    # --- Not Evaluated ---
    if ($notEval.Count -gt 0) {
        $ne = @(Build-NotEvaluatedRow -FindingList $notEval)
        $tabs += [ordered]@{
            id = 'noteval'; label = 'Not Evaluated'; kind = 'table'
            note = 'Checks that need directory data. Run with -ResolveNames (or a companion file) to evaluate these.'
            columns = @(
                [ordered]@{ key = 'Priority'; label = 'Priority'; type = 'sev' }
                [ordered]@{ key = 'Finding that could not run'; label = 'Finding'; type = 'primary' }
                [ordered]@{ key = 'What data is needed'; label = 'Data needed'; type = 'text' }
                [ordered]@{ key = 'Affected policies'; label = 'Affected'; type = 'mono' }
                [ordered]@{ key = 'Why it matters'; label = 'Why it matters'; type = 'wrap'; detail = $true }
            )
            rows = @($ne | ForEach-Object { ConvertTo-CAOrderedRow $_ })
        }
    }

    # --- Group Membership (only with Graph enrichment) ---
    if (Test-CAEnrichmentAvailable) {
        $gm = @(Build-GroupMembershipRow -PolicyList $Policies)
        if ($gm.Count -gt 0) {
            $tabs += [ordered]@{
                id = 'groupmembership'; label = 'Group Membership'; kind = 'table'
                note = 'Groups used in policy include/exclude sets, with live membership from Microsoft Graph.'
                columns = (Get-CADerivedColumns -Rows $gm -Overrides @{ 'Group' = 'primary'; 'In include (#)' = 'num'; 'In exclude (#)' = 'num'; 'Members' = 'num'; 'Notes' = 'wrap' })
                rows = @($gm | ForEach-Object { ConvertTo-CAOrderedRow $_ })
            }
        }
    }

    # --- Reference (what each CA-NNN rule id means) ---
    if (Get-Command Get-CARuleReference -ErrorAction SilentlyContinue) {
        $refRows = @(Get-CARuleReference)
        if ($refRows.Count -gt 0) {
            $tabs += [ordered]@{
                id = 'reference'; label = 'Reference'; kind = 'table'
                note = 'What each rule id (CA-NNN) checks. Category: Baseline control = a recommended control that should exist; Policy issue = a problem with an existing policy; Cross-policy gap = a gap spanning several policies; Directory data = needs a Graph lookup (run with -ResolveNames).'
                columns = @(
                    [ordered]@{ key = 'Rule'; label = 'Rule'; type = 'mono' }
                    [ordered]@{ key = 'Control'; label = 'Control'; type = 'primary' }
                    [ordered]@{ key = 'Category'; label = 'Category'; type = 'text' }
                    [ordered]@{ key = 'What it checks'; label = 'What it checks'; type = 'wrap' }
                )
                rows = @($refRows | ForEach-Object { ConvertTo-CAOrderedRow $_ })
            }
        }
    }

    # Policy Overview leads the report (user preference), then everything else in
    # its existing order. It also becomes the default-selected tab.
    $overviewTab = @($tabs | Where-Object { $_.id -eq 'overview' })
    $otherTabs = @($tabs | Where-Object { $_.id -ne 'overview' })
    $tabs = @($overviewTab + $otherTabs)

    # Gap-remediation templates for the Baseline Coverage download buttons. Reuses
    # the SAME New-CAGapPolicy definitions as the PowerShell writer. Base objects
    # are Report-only with a clean name + no excludeGroups; the browser injects the
    # break-glass group / name marker at download time.
    $gapPolicies = @()
    $gapManual = @()
    if ((Get-Command Get-CAGapPolicyDefinition -ErrorAction SilentlyContinue) -and $baseline.Count -gt 0) {
        $gapIds = @($Findings | Where-Object { $_.PolicyName -match 'baseline check' -and $_.CoverageState -eq 'gap' } | ForEach-Object { $_.Id })
        $defs = Get-CAGapPolicyDefinition
        $manual = Get-CAGapPolicyManualNote
        foreach ($gid in $gapIds) {
            $def = $defs | Where-Object { $_.Id -eq $gid } | Select-Object -First 1
            if ($def) {
                $base = & $def.Build 'enabledForReportingButNotEnforced' ([string]$def.Name)
                $gapPolicies += [ordered]@{ id = $def.Id; name = [string]$def.Name; fileName = [string]$def.FileName; policy = $base }
            }
            elseif ($manual.ContainsKey($gid)) {
                $gapManual += [ordered]@{ id = $gid; note = [string]$manual[$gid] }
            }
        }
    }

    return [ordered]@{
        gapPolicies = $gapPolicies
        gapManual   = $gapManual
        summary = [ordered]@{
            policies = @($Policies).Count
            rules = [int](Get-CAOrDefault $Meta.RuleCount 0)
            generated = [string](Get-CAOrDefault $Meta.Generated '')
            counts = $counts
            fail = $fail.Count
            pass = $pass.Count
            na = $na.Count
            notEval = $notEval.Count
            baselineCovered = $covered
            baselineTotal = $baselineApplicable
            priorityActions = $priority
            gaps = $gaps
            matrix = $matrixSummary
        }
        tabs = $tabs
    }
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Split-CACellMain {
    [CmdletBinding()] [OutputType([string])]
    param([string] $Cell)
    return (($Cell -split ' \[', 2)[0]).Trim()
}

function Split-CACellPair {
    [CmdletBinding()] [OutputType([object])]
    param([string] $Cell)
    $parts = $Cell -split ' \[', 2
    $main = $parts[0].Trim()
    $sub = if ($parts.Count -gt 1) { $parts[1].TrimEnd(']') } else { '' }
    return , @($main, $sub)
}

function ConvertTo-CAOrderedRow {
    [CmdletBinding()]
    param($Row)
    $h = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function Get-CADerivedColumns {
    [CmdletBinding()]
    param([object[]] $Rows, [hashtable] $Overrides = @{})
    if (@($Rows).Count -eq 0) { return @() }
    $keys = $Rows[0].PSObject.Properties.Name
    $first = $true
    $cols = foreach ($k in $keys) {
        $type = if ($Overrides.ContainsKey($k)) { $Overrides[$k] }
        elseif ($first) { 'primary' }
        elseif ($k -match '^#|count|\(#\)') { 'num' }
        elseif ($k -match 'note') { 'wrap' }
        else { 'text' }
        $first = $false
        [ordered]@{ key = $k; label = $k; type = $type }
    }
    return @($cols)
}

function ConvertTo-CAJsonSafe {
    [CmdletBinding()] [OutputType([string])]
    param($InputObject)
    $json = $InputObject | ConvertTo-Json -Depth 12 -Compress
    return $json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
}

function Get-CAOrDefault {
    [CmdletBinding()]
    param($Value, $Default)
    if ($null -ne $Value -and "$Value" -ne '') { return $Value }
    return $Default
}

function ConvertTo-CAHtmlText {
    [CmdletBinding()] [OutputType([string])]
    param([string] $Text)
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}


# ---------------------------------------------------------------------------
# Embedded CSS + JS (single-quoted here-strings: no PowerShell interpolation)
# ---------------------------------------------------------------------------
function Get-CAHtmlStyle {
    [CmdletBinding()] [OutputType([string])]
    param()
    return @'
/* ---------- tokens ---------- */
  :root {
    color-scheme: light dark;
    --font-ui: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;

    /* cool-biased neutrals (light) */
    --bg: #eef2f7;
    --surface: #ffffff;
    --surface-2: #f5f8fc;
    --border: #dbe3ee;
    --border-strong: #c3cedd;
    --text: #172033;
    --text-dim: #5a6883;
    --text-faint: #8593aa;

    /* All Things Cloud brand blues (sampled from the logo) */
    --accent: #0070b0;
    --accent-fg: #ffffff;
    --accent-soft: #e4f1f9;
    --brand-cyan: #00a0c0;

    /* severity: fg text, bg tint, stripe */
    --sev-critical-fg: #8f1414; --sev-critical-bg: #fbe4e2; --sev-critical-stripe: #b3261e;
    --sev-high-fg: #a5341f;     --sev-high-bg: #fdeae4;     --sev-high-stripe: #d9534f;
    --sev-medium-fg: #8a5a10;   --sev-medium-bg: #fbefd7;   --sev-medium-stripe: #d98a1e;
    --sev-low-fg: #6f6013;      --sev-low-bg: #f6f0d6;      --sev-low-stripe: #b8912a;
    --sev-info-fg: #3f5570;     --sev-info-bg: #e8eef5;     --sev-info-stripe: #5f7488;
    --sev-good-fg: #1f6b45;     --sev-good-bg: #e0f1e7;     --sev-good-stripe: #2f8f5b;

    --shadow: 0 1px 2px rgba(20,32,54,.06), 0 4px 16px rgba(20,32,54,.06);
    --radius: 10px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d1420; --surface: #151d2b; --surface-2: #1b2536;
      --border: #263248; --border-strong: #33415b;
      --text: #e6edf7; --text-dim: #9fb0c9; --text-faint: #6e7f9a;
      --accent: #4aa8e0; --accent-fg: #06101d; --accent-soft: #163049; --brand-cyan: #35bcd8;
      --sev-critical-fg: #ff9d94; --sev-critical-bg: #3a1a1a; --sev-critical-stripe: #e2564a;
      --sev-high-fg: #ffb098;     --sev-high-bg: #3a2018;     --sev-high-stripe: #e86b52;
      --sev-medium-fg: #f4c583;   --sev-medium-bg: #33260f;   --sev-medium-stripe: #dd9a34;
      --sev-low-fg: #ddc978;      --sev-low-bg: #2c2711;      --sev-low-stripe: #c2a53f;
      --sev-info-fg: #9db8d6;     --sev-info-bg: #1c2738;     --sev-info-stripe: #7089a6;
      --sev-good-fg: #8fdcae;     --sev-good-bg: #16301f;     --sev-good-stripe: #37a56b;
      --shadow: 0 1px 2px rgba(0,0,0,.3), 0 6px 20px rgba(0,0,0,.35);
    }
  }
  :root[data-theme="light"] {
    --bg: #eef2f7; --surface: #ffffff; --surface-2: #f5f8fc; --border: #dbe3ee; --border-strong: #c3cedd;
    --text: #172033; --text-dim: #5a6883; --text-faint: #8593aa;
    --accent: #0070b0; --accent-fg: #ffffff; --accent-soft: #e4f1f9; --brand-cyan: #00a0c0;
    --sev-critical-fg: #8f1414; --sev-critical-bg: #fbe4e2; --sev-critical-stripe: #b3261e;
    --sev-high-fg: #a5341f;     --sev-high-bg: #fdeae4;     --sev-high-stripe: #d9534f;
    --sev-medium-fg: #8a5a10;   --sev-medium-bg: #fbefd7;   --sev-medium-stripe: #d98a1e;
    --sev-low-fg: #6f6013;      --sev-low-bg: #f6f0d6;      --sev-low-stripe: #b8912a;
    --sev-info-fg: #3f5570;     --sev-info-bg: #e8eef5;     --sev-info-stripe: #5f7488;
    --sev-good-fg: #1f6b45;     --sev-good-bg: #e0f1e7;     --sev-good-stripe: #2f8f5b;
    --shadow: 0 1px 2px rgba(20,32,54,.06), 0 4px 16px rgba(20,32,54,.06);
  }
  :root[data-theme="dark"] {
    --bg: #0d1420; --surface: #151d2b; --surface-2: #1b2536; --border: #263248; --border-strong: #33415b;
    --text: #e6edf7; --text-dim: #9fb0c9; --text-faint: #6e7f9a;
    --accent: #4aa8e0; --accent-fg: #06101d; --accent-soft: #163049; --brand-cyan: #35bcd8;
    --sev-critical-fg: #ff9d94; --sev-critical-bg: #3a1a1a; --sev-critical-stripe: #e2564a;
    --sev-high-fg: #ffb098;     --sev-high-bg: #3a2018;     --sev-high-stripe: #e86b52;
    --sev-medium-fg: #f4c583;   --sev-medium-bg: #33260f;   --sev-medium-stripe: #dd9a34;
    --sev-low-fg: #ddc978;      --sev-low-bg: #2c2711;      --sev-low-stripe: #c2a53f;
    --sev-info-fg: #9db8d6;     --sev-info-bg: #1c2738;     --sev-info-stripe: #7089a6;
    --sev-good-fg: #8fdcae;     --sev-good-bg: #16301f;     --sev-good-stripe: #37a56b;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 6px 20px rgba(0,0,0,.35);
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    font-family: var(--font-ui);
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1440px; margin: 0 auto; padding: 0 20px 64px; }
  .mono { font-family: var(--font-mono); font-size: .92em; }
  .tnum { font-variant-numeric: tabular-nums; }

  /* ---------- top bar ---------- */
  header.topbar {
    position: sticky; top: 0; z-index: 30;
    background: color-mix(in srgb, var(--surface) 88%, transparent);
    backdrop-filter: saturate(1.4) blur(8px);
    border-bottom: 1px solid var(--border);
  }
  .topbar-inner { max-width: 1440px; margin: 0 auto; padding: 14px 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  @media (max-width: 680px) { .meta-pill { display: none; } }
  .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
  .shield {
    width: 34px; height: 38px; flex: none;
    background: linear-gradient(160deg, var(--accent), color-mix(in srgb, var(--accent) 60%, #14324f));
    clip-path: polygon(50% 0, 100% 16%, 100% 60%, 50% 100%, 0 60%, 0 16%);
    display: grid; place-items: center; color: var(--accent-fg); font-weight: 800; font-size: 15px;
  }
  /* All Things Cloud emblem sits on a white tile so it reads on both themes. */
  .brand-logo {
    width: 36px; height: 36px; flex: none; box-sizing: border-box; padding: 4px;
    background: #fff; border-radius: 8px; box-shadow: 0 0 0 1px rgba(15,23,42,.10);
    display: grid; place-items: center;
  }
  .brand-logo img { width: 100%; height: 100%; object-fit: contain; display: block; }
  .brand h1 { margin: 0; font-size: 15px; font-weight: 700; letter-spacing: -.01em; }
  .brand .sub { margin: 0; font-size: 11.5px; color: var(--text-dim); }
  .brand .sub .mono { color: var(--text); }
  .spacer { flex: 1 1 auto; }
  .meta-pill {
    font-size: 11.5px; color: var(--text-dim);
    display: flex; gap: 14px; align-items: center;
  }
  .meta-pill b { color: var(--text); font-weight: 600; }
  .icon-btn {
    appearance: none; border: 1px solid var(--border-strong); background: var(--surface);
    color: var(--text); border-radius: 8px; height: 34px; width: 34px; cursor: pointer;
    display: grid; place-items: center; font-size: 15px;
  }
  .icon-btn:hover { border-color: var(--accent); color: var(--accent); }

  /* ---------- eyebrow (mono uppercase, brand treatment) ---------- */
  .eyebrow { font-family: var(--font-mono); text-transform: uppercase; letter-spacing: .16em; font-size: 10px; font-weight: 600; color: var(--text-faint); }

  /* ---------- security posture band (signature element) ---------- */
  .posture {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 16px 18px 15px; margin: 12px 0 14px;
    border-top: 3px solid var(--accent);
  }
  .posture-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .posture-baseline { font-size: 12px; color: var(--text-dim); }
  .posture-baseline b { color: var(--text); font-weight: 700; }
  .posture-bar {
    display: flex; height: 26px; margin: 12px 0 0; border-radius: 6px; overflow: hidden;
    border: 1px solid var(--border-strong); background: var(--surface-2);
    clip-path: inset(0 100% 0 0); transition: clip-path .9s cubic-bezier(.22,.61,.36,1);
  }
  .posture-bar.filled { clip-path: inset(0 0 0 0); }
  .posture-seg { display: block; height: 100%; border: none; padding: 0; cursor: pointer; transition: filter .12s; }
  .posture-seg:hover { filter: brightness(1.08) saturate(1.1); }
  .posture-seg:focus-visible { outline: 2px solid var(--text); outline-offset: -2px; }
  .posture-legend { display: flex; flex-wrap: wrap; gap: 6px 15px; margin-top: 11px; font-size: 11.5px; color: var(--text-dim); }
  .posture-legend button { appearance: none; background: none; border: 0; font: inherit; color: inherit; cursor: pointer; padding: 0; display: inline-flex; align-items: center; gap: 6px; }
  .posture-legend button:hover { color: var(--text); }
  .posture-legend i { width: 9px; height: 9px; border-radius: 2px; flex: none; }
  .posture-legend b { color: var(--text); font-weight: 700; }
  .posture-verdict { margin: 12px 0 0; font-size: 13px; color: var(--text-dim); }
  .posture-verdict b { color: var(--text); font-weight: 700; }
  .posture-verdict .hi { color: var(--sev-high-stripe); }
  @media (prefers-reduced-motion: reduce) { .posture-bar { transition: none; } }

  /* ---------- dashboard tiles (secondary control strip under the band) ---------- */
  /* auto-fit so the row flows whether there are 6 tiles or 7 (Critical present). */
  .dash { display: grid; grid-template-columns: repeat(auto-fit, minmax(118px, 1fr)); gap: 9px; margin: 0 0 6px; }
  @media (max-width: 900px) { .dash { grid-template-columns: repeat(4, 1fr); } }
  @media (max-width: 520px) { .dash { grid-template-columns: repeat(2, 1fr); } }
  .tile {
    appearance: none; text-align: left; font: inherit; cursor: pointer;
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 9px 11px; box-shadow: var(--shadow); position: relative; overflow: hidden;
    transition: border-color .12s, transform .12s;
    display: flex; flex-direction: column; align-items: flex-start; justify-content: center;
  }
  .tile:hover { border-color: var(--accent); transform: translateY(-1px); }
  .tile[aria-pressed="true"] { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent), var(--shadow); }
  /* number on top, label underneath it */
  .tile .v { display: block; font-size: 19px; font-weight: 750; letter-spacing: -.02em; line-height: 1.05; }
  .tile .k { display: block; font-size: 9.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--text-dim); font-weight: 600; margin-top: 3px; }
  .tile .stripe { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
  .tile.s-total .v { color: var(--text); }
  .tile.s-critical .stripe { background: var(--sev-critical-stripe); } .tile.s-critical .v { color: var(--sev-critical-fg); }
  .tile.s-high .stripe { background: var(--sev-high-stripe); } .tile.s-high .v { color: var(--sev-high-fg); }
  .tile.s-medium .stripe { background: var(--sev-medium-stripe); } .tile.s-medium .v { color: var(--sev-medium-fg); }
  .tile.s-good .stripe { background: var(--sev-good-stripe); } .tile.s-good .v { color: var(--sev-good-fg); }
  .tile.s-eval .stripe { background: var(--accent); } .tile.s-eval .v { color: var(--accent); }
  .hint { font-size: 11.5px; color: var(--text-faint); margin: 2px 2px 0; }

  /* ---------- tabs ---------- */
  /* wrap tabs to a second row rather than letting the last one fall off-screen */
  nav.tabs { display: flex; flex-wrap: wrap; gap: 2px; margin: 22px 0 0; border-bottom: 1px solid var(--border); }
  .tab {
    appearance: none; background: transparent; border: none; font: inherit; cursor: pointer;
    padding: 10px 14px; color: var(--text-dim); font-weight: 600; font-size: 12.5px;
    border-bottom: 2px solid transparent; white-space: nowrap; display: flex; align-items: center; gap: 7px;
  }
  .tab:hover { color: var(--text); }
  .tab[aria-selected="true"] { color: var(--accent); border-bottom-color: var(--accent); }
  .tab .count { font-size: 11px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-dim); border-radius: 20px; padding: 0 7px; line-height: 17px; }
  .tab[aria-selected="true"] .count { background: var(--accent-soft); border-color: transparent; color: var(--accent); }

  /* ---------- panel + toolbar ---------- */
  /* flow-root establishes a block formatting context so the first child's top
     margin (e.g. the info banner) does not collapse through the borderless top. */
  .panel { background: var(--surface); border: 1px solid var(--border); border-top: none; border-radius: 0 0 var(--radius) var(--radius); box-shadow: var(--shadow); display: flow-root; }
  .toolbar { display: flex; align-items: center; gap: 10px; padding: 12px 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .search { position: relative; flex: 1 1 260px; min-width: 200px; }
  .search input {
    width: 100%; font: inherit; padding: 8px 10px 8px 32px; border-radius: 8px;
    border: 1px solid var(--border-strong); background: var(--surface-2); color: var(--text);
  }
  .search input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }
  .search svg { position: absolute; left: 9px; top: 50%; transform: translateY(-50%); color: var(--text-faint); }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .chip {
    appearance: none; font: inherit; cursor: pointer; font-size: 11.5px; font-weight: 600;
    border-radius: 20px; padding: 5px 11px; border: 1px solid var(--border-strong);
    background: var(--surface); color: var(--text-dim); display: inline-flex; align-items: center; gap: 6px;
  }
  .chip .dot { width: 8px; height: 8px; border-radius: 50%; }
  .chip[aria-pressed="true"] { color: var(--text); border-color: currentColor; }
  .chip[data-off="true"] { opacity: .45; text-decoration: line-through; }
  .toolbar-note { font-size: 11.5px; color: var(--text-faint); margin-left: auto; }

  /* ---------- tables ---------- */
  .tscroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    position: sticky; top: 0; background: var(--surface-2); z-index: 2;
    text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--text-dim); font-weight: 700; padding: 9px 12px; border-bottom: 1px solid var(--border);
    white-space: nowrap; cursor: pointer; user-select: none;
  }
  thead th.no-sort { cursor: default; }
  thead th:focus-visible, tr.expander:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
  thead th .arrow { color: var(--accent); font-size: 10px; margin-left: 3px; opacity: 0; }
  thead th[aria-sort] .arrow { opacity: 1; }
  tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 12px; }
  tbody tr:hover td { background: color-mix(in srgb, var(--accent) 5%, transparent); }
  tbody tr:last-child td { border-bottom: none; }
  .txt-dim { color: var(--text-dim); }
  .nowrap { white-space: nowrap; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }

  /* severity badge + row stripe */
  .badge {
    display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 700;
    border-radius: 6px; padding: 2px 8px; white-space: nowrap;
  }
  .badge::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .sev-critical { color: var(--sev-critical-fg); background: var(--sev-critical-bg); }
  .sev-high { color: var(--sev-high-fg); background: var(--sev-high-bg); }
  .sev-medium { color: var(--sev-medium-fg); background: var(--sev-medium-bg); }
  .sev-low { color: var(--sev-low-fg); background: var(--sev-low-bg); }
  .sev-info { color: var(--sev-info-fg); background: var(--sev-info-bg); }
  .sev-good { color: var(--sev-good-fg); background: var(--sev-good-bg); }
  /* light row tint for inactive policies (Off / Report-only) - Policy Overview,
     CA Policy Groups. The bold State cell keeps its own colour on top. */
  tr.frow.st-off td { background: color-mix(in srgb, var(--sev-high-stripe) 8%, transparent); }
  tr.frow.st-report td { background: color-mix(in srgb, var(--sev-medium-stripe) 10%, transparent); }
  tr.frow td:first-child { border-left: 3px solid transparent; }
  tr.rk-critical td:first-child { border-left-color: var(--sev-critical-stripe); }
  tr.rk-high td:first-child { border-left-color: var(--sev-high-stripe); }
  tr.rk-medium td:first-child { border-left-color: var(--sev-medium-stripe); }
  tr.rk-low td:first-child { border-left-color: var(--sev-low-stripe); }
  tr.rk-info td:first-child { border-left-color: var(--sev-info-stripe); }
  tr.rk-good td:first-child { border-left-color: var(--sev-good-stripe); }
  /* severity-based light row tint - Security Checks tab only (rows carry .sevrow) */
  tr.frow.sevrow.rk-critical td { background: color-mix(in srgb, var(--sev-critical-stripe) 9%, transparent); }
  tr.frow.sevrow.rk-high td { background: color-mix(in srgb, var(--sev-high-stripe) 7%, transparent); }
  tr.frow.sevrow.rk-medium td { background: color-mix(in srgb, var(--sev-medium-stripe) 8%, transparent); }
  tr.frow.sevrow.rk-low td { background: color-mix(in srgb, var(--sev-low-stripe) 11%, transparent); }
  tr.frow.sevrow.rk-info td { background: color-mix(in srgb, var(--sev-info-stripe) 9%, transparent); }
  tr.frow.sevrow.rk-good td { background: color-mix(in srgb, var(--sev-good-stripe) 9%, transparent); }

  .fname { font-weight: 600; }
  .expander { cursor: pointer; }
  .expander .caret { display: inline-block; transition: transform .15s; color: var(--text-faint); margin-right: 6px; }
  tr.open .caret { transform: rotate(90deg); }
  .detail td { background: var(--surface-2); }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 26px; }
  @media (max-width: 720px) { .detail-grid { grid-template-columns: 1fr; } }
  .detail-grid .lbl { font-size: 10px; text-transform: uppercase; letter-spacing: .07em; color: var(--text-faint); font-weight: 700; margin-bottom: 3px; }
  .detail-grid .val { color: var(--text); }
  .pill { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 8px; border-radius: 20px; border: 1px solid var(--border-strong); color: var(--text-dim); }
  .pill.on { color: var(--sev-good-fg); background: var(--sev-good-bg); border-color: transparent; }
  .pill.report { color: var(--sev-medium-fg); background: var(--sev-medium-bg); border-color: transparent; }
  .pill.off { color: var(--sev-high-fg); background: var(--sev-high-bg); border-color: transparent; }
  .pill.scoped { color: var(--sev-medium-fg); background: var(--sev-medium-bg); border-color: transparent; }
  .pill.na { color: var(--text-faint); background: var(--surface-2); border-color: var(--border); }

  /* matrix cells */
  .cell { display: block; font-weight: 600; }
  .cell small { display: block; font-weight: 400; color: var(--text-faint); margin-top: 2px; font-size: 12px; }
  td.m-blocked { background: var(--sev-high-bg); color: var(--sev-high-fg); }
  td.m-mfa { background: var(--sev-info-bg); color: var(--sev-info-fg); }
  td.m-compliant { background: var(--sev-good-bg); color: var(--sev-good-fg); }
  td.m-gap { background: var(--sev-critical-bg); color: var(--sev-critical-fg); }

  .empty { padding: 40px; text-align: center; color: var(--text-faint); }
  .foot { margin-top: 26px; font-size: 11.5px; color: var(--text-faint); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .foot .dot { width: 4px; height: 4px; border-radius: 50%; background: var(--text-faint); }
  .banner { background: var(--accent-soft); border: 1px solid color-mix(in srgb, var(--accent) 30%, transparent); color: var(--text); border-radius: 8px; padding: 9px 12px; margin: 14px 14px 12px; font-size: 12px; }
  .banner b { color: var(--accent); }
  /* Warning variant (amber) for approximations / caveats that must not be missed. */
  .banner.warn { background: var(--sev-medium-bg); border-color: color-mix(in srgb, var(--sev-medium-stripe) 45%, transparent); }
  .banner.warn b { color: var(--sev-medium-fg); }

  /* ---------- gap remediation panel (Baseline Coverage) ---------- */
  .remediation { margin: 0 14px 12px; border: 1px solid var(--border-strong); border-radius: 8px; background: var(--surface-2); overflow: hidden; }
  .rem-toggle { width: 100%; text-align: left; appearance: none; background: transparent; border: none; cursor: pointer; font: inherit; font-weight: 700; font-size: 12.5px; color: var(--text); padding: 11px 14px; display: flex; align-items: center; gap: 6px; }
  .rem-toggle:hover { color: var(--accent); }
  .rem-toggle small { font-weight: 400; color: var(--text-faint); margin-left: 6px; }
  .rem-toggle .caret { display: inline-block; transition: transform .15s; color: var(--text-faint); }
  .rem-toggle.open .caret { transform: rotate(90deg); }
  .rem-toggle .rem-hint { margin-left: auto; font-weight: 400; font-size: 11px; color: var(--accent); white-space: nowrap; }
  .rem-toggle .rem-hint::after { content: "Click to expand"; }
  .rem-toggle.open .rem-hint::after { content: "Click to collapse"; }
  .rem-body { padding: 0 14px 12px; }
  .rem-body[hidden] { display: none; }
  .rem-intro { font-size: 11.5px; color: var(--text-dim); line-height: 1.55; margin: 0 0 12px; }
  .rem-manual-head { font-weight: 600; font-size: 11.5px; color: var(--text-dim); margin: 4px 0 3px; }
  .rem-manual-item { font-size: 11px; color: var(--text-faint); line-height: 1.45; margin-bottom: 3px; }
  .rem-ctl { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 10px 0 6px; }
  .rem-ctl label { font-size: 12px; color: var(--text-dim); }
  .rem-ctl input { font: inherit; font-size: 12px; padding: 6px 9px; min-width: 300px; border-radius: 6px; border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); }
  .rem-ctl input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }
  .rem-note { font-size: 11px; color: var(--text-faint); margin-bottom: 8px; }
  .rem-note.bad { color: var(--sev-high-fg); }
  .rem-btn { appearance: none; cursor: pointer; font: inherit; font-size: 11.5px; font-weight: 600; border-radius: 6px; padding: 5px 11px; border: 1px solid var(--accent); background: var(--accent); color: var(--accent-fg); }
  .rem-btn:hover { filter: brightness(1.05); }
  .rem-all { margin-left: auto; }
  .rem-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 6px 16px; }
  .rem-row { display: flex; align-items: center; gap: 10px; justify-content: space-between; border-top: 1px solid var(--border); padding: 5px 0; }
  .rem-name { font-size: 12px; }
  .rem-row .rem-btn { background: var(--surface); color: var(--accent); }
  .rem-manual { margin-top: 8px; font-size: 11px; color: var(--text-faint); }

  /* ---------- printable summary (on-screen preview + print) ---------- */
  .preview[hidden] { display: none; }
  .preview {
    position: fixed; inset: 0; z-index: 60; background: color-mix(in srgb, #0a0f18 62%, transparent);
    display: flex; flex-direction: column; align-items: center; overflow: auto; padding: 20px;
  }
  .pv-bar {
    position: sticky; top: 0; align-self: stretch; display: flex; align-items: center; gap: 12px;
    max-width: 820px; margin: 0 auto 16px; color: #fff;
  }
  .pv-bar .t { font-weight: 700; font-size: 14px; }
  .pv-bar .t small { display: block; font-weight: 400; opacity: .7; font-size: 11.5px; }
  .pv-bar .sp { flex: 1; }
  .btn {
    appearance: none; font: inherit; font-weight: 600; font-size: 12.5px; cursor: pointer;
    border-radius: 8px; padding: 8px 14px; border: 1px solid transparent;
  }
  .btn.primary { background: var(--accent); color: var(--accent-fg); }
  .btn.ghost { background: transparent; color: #fff; border-color: rgba(255,255,255,.4); }
  .btn:hover { filter: brightness(1.06); }

  .page {
    background: #fff; color: #14203a; width: 100%; max-width: 820px; border-radius: 6px;
    box-shadow: 0 12px 40px rgba(0,0,0,.4); padding: 40px 44px; margin: 0 auto;
    --p-dim: #5a6883; --p-line: #e2e8f0;
  }
  .page h2 { font-size: 22px; margin: 0; letter-spacing: -.01em; }
  .page .doc-sub { color: var(--p-dim); font-size: 12.5px; margin: 4px 0 0; }
  .page .doc-head { display: flex; align-items: flex-start; gap: 14px; border-bottom: 2px solid #14203a; padding-bottom: 16px; }
  .page .doc-head .shield { width: 30px; height: 34px; }
  .page .doc-head .doc-logo { height: 50px; width: auto; display: block; flex: none; }
  .page .verdict { font-size: 14px; margin: 18px 0; padding: 12px 14px; border-radius: 8px; background: #f5f8fc; border: 1px solid var(--p-line); }
  .page .verdict b { color: var(--sev-high-stripe); }
  .page .s-title { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; color: var(--p-dim); margin: 26px 0 10px; }
  .page .glance { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }
  .page .gbox { border: 1px solid var(--p-line); border-radius: 8px; padding: 10px; }
  .page .gbox .k { font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--p-dim); font-weight: 600; }
  .page .gbox .v { font-size: 22px; font-weight: 750; margin-top: 3px; font-variant-numeric: tabular-nums; }
  .page .distbar { display: flex; height: 22px; border-radius: 5px; overflow: hidden; border: 1px solid var(--p-line); }
  .page .distbar span { display: block; }
  .page .distlegend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; font-size: 11px; color: var(--p-dim); }
  .page .distlegend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 5px; vertical-align: middle; }
  .page ol.actions { margin: 0; padding-left: 20px; }
  .page ol.actions li { margin-bottom: 11px; break-inside: avoid; }
  .page ol.actions .fn { font-weight: 700; }
  .page ol.actions .rk { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; padding: 1px 6px; border-radius: 4px; margin-left: 6px; }
  .page ol.actions .rec { color: var(--p-dim); font-size: 12px; }
  .page table.psum { width: 100%; border-collapse: collapse; font-size: 11.5px; }
  .page table.psum th, .page table.psum td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--p-line); }
  .page table.psum th { text-transform: uppercase; font-size: 9.5px; letter-spacing: .05em; color: var(--p-dim); }
  .page .gaplist { columns: 2; column-gap: 26px; font-size: 12px; margin: 0; padding: 0; list-style: none; }
  .page .gaplist li { break-inside: avoid; margin-bottom: 5px; padding-left: 14px; position: relative; }
  .page .gaplist li::before { content: "\2022"; position: absolute; left: 0; color: var(--sev-high-stripe); }
  .page .caveat { margin-top: 26px; padding-top: 14px; border-top: 1px solid var(--p-line); font-size: 10.5px; color: var(--p-dim); }
  .page .doc-foot { margin-top: 8px; font-size: 10px; color: #94a0b5; }

  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
  @media print {
    body.previewing > .wrap, body.previewing > header.topbar { display: none !important; }
    /* display:block (not flex) so a tall .page fragments across sheets instead of
       being clipped to a single sheet - flex items do not paginate reliably. */
    body.previewing .preview { display: block; position: static; background: #fff; padding: 0; overflow: visible; }
    body.previewing .pv-bar { display: none !important; }
    body.previewing .page { box-shadow: none; max-width: none; border-radius: 0; padding: 0; margin: 0; }
    .page, .page * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    /* keep logical blocks together and headings attached to their content */
    .page .verdict, .page .gbox, .page ol.actions li, .page .gaplist li, .page table.psum tr { break-inside: avoid; }
    .page .s-title { break-after: avoid; }
    .page table.psum thead { display: table-header-group; }
    /* fallback when printing the app directly */
    body:not(.previewing) header.topbar { position: static; }
    body:not(.previewing) nav.tabs, body:not(.previewing) .toolbar, body:not(.previewing) .icon-btn { display: none; }
  }
  td.wrapcol { white-space: normal; min-width: 220px; max-width: 520px; }

'@
}

function Get-CAHtmlScript {
    [CmdletBinding()] [OutputType([string])]
    param()
    return @'
(function () {
  "use strict";
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const RANKS = ["Critical","High","Medium","Low","Info","Good"];
  const SEVHEX = { Critical:"#b3261e", High:"#d9534f", Medium:"#d98a1e", Low:"#b8912a", Info:"#5f7488", Good:"#2f8f5b" };
  const SEVBG  = { Critical:"#fbe4e2", High:"#fdeae4", Medium:"#fbefd7", Low:"#f6f0d6", Info:"#e8eef5", Good:"#e0f1e7" };
  const sevOf = v => { if (v == null) return null; v = String(v); for (const r of RANKS) { if (v === r || v.indexOf(r) >= 0) return r; } return null; };
  const rankClass = r => "rk-" + r.toLowerCase();
  const sevClass = r => "sev-" + r.toLowerCase();

  (DATA.tabs || []).forEach(t => {
    if (!Array.isArray(t.rows)) t.rows = t.rows ? [t.rows] : [];
    if (!Array.isArray(t.columns)) t.columns = t.columns ? [t.columns] : [];
  });

  const state = { tab: (DATA.tabs[0] || {}).id, q: "", sevOff: new Set(), sevOnly: null, statusOnly: null, sort: {} };
  const S = DATA.summary, C = S.counts;
  // Guard against single-element arrays being unwrapped to a bare object by
  // ConvertTo-Json on Windows PowerShell 5.1, which would break .map/.length.
  ["priorityActions", "gaps", "matrix"].forEach(k => { if (!Array.isArray(S[k])) S[k] = S[k] ? [S[k]] : []; });

  const tiles = [
    { key:"total", cls:"s-total", label:"Checks", val: S.fail + S.pass + (S.na||0), tip:"All checks run (issues + passing). Click to clear filters." },
    ...(C.Critical > 0 ? [{ key:"Critical", cls:"s-critical", label:"Critical", val: C.Critical, tip:"Filter findings to Critical only" }] : []),
    { key:"High", cls:"s-high", label:"High", val: C.High, tip:"Filter findings to High only" },
    { key:"Medium", cls:"s-medium", label:"Medium", val: C.Medium, tip:"Filter findings to Medium only" },
    { key:"pass", cls:"s-good", label:"Passing", val: S.pass, tip:"Show passing checks only" },
    { key:"noteval", cls:"s-eval", label:"Not evaluated", val: S.notEval, tip:"Checks needing -ResolveNames" },
    { key:"score", cls:"s-total", label:"Baseline covered", val: S.baselineCovered + " / " + S.baselineTotal, tip:"Open the Baseline Coverage scorecard" }
  ];
  function renderDash() {
    document.getElementById("dash").innerHTML = tiles.map(t => {
      const pressed = (t.key === state.sevOnly) || (t.key === "pass" && state.statusOnly === "Pass");
      return `<button class="tile ${t.cls}" data-key="${t.key}" title="${esc(t.tip)}" aria-pressed="${pressed?"true":"false"}"><span class="stripe"></span><span class="v tnum">${esc(t.val)}</span><span class="k">${esc(t.label)}</span></button>`;
    }).join("");
  }
  // Signature "Security posture" band: one glance at the tenant's stance, worst
  // -> best. Reuses the same RANKS/SEVHEX/segment math as the printable summary
  // so the two views can never disagree. Rendered once (fills left->right on load).
  function renderPosture() {
    const total = RANKS.reduce((s, r) => s + (C[r] || 0), 0) || 1;
    const issues = ["Critical", "High", "Medium", "Low"].reduce((s, r) => s + (C[r] || 0), 0);
    const segs = RANKS.filter(r => C[r] > 0).map(r =>
      `<button class="posture-seg" data-sev="${r}" style="width:${(C[r] / total * 100).toFixed(2)}%;background:${SEVHEX[r]}" title="${r}: ${C[r]} - click to filter findings" aria-label="${r}: ${C[r]}"></button>`).join("");
    const legend = RANKS.filter(r => C[r] > 0).map(r =>
      `<button data-sev="${r}"><i style="background:${SEVHEX[r]}"></i>${r} <b class="tnum">${C[r]}</b></button>`).join("");
    const critClause = C.Critical > 0 ? `<b class="hi">${C.Critical} Critical</b> and ` : "";
    document.getElementById("posture").innerHTML =
      `<div class="posture-head"><span class="eyebrow">Security posture</span>` +
      `<span class="posture-baseline">Baseline <b class="tnum">${S.baselineCovered}</b> / <span class="tnum">${S.baselineTotal}</span> controls covered</span></div>` +
      `<div class="posture-bar" id="postureBar">${segs || `<span class="posture-seg" style="width:100%;background:var(--sev-good-stripe)"></span>`}</div>` +
      `<div class="posture-legend">${legend}</div>` +
      `<p class="posture-verdict"><b>${issues} issue${issues === 1 ? "" : "s"}</b> across ${esc(S.policies)} ${S.policies == 1 ? "policy" : "policies"} &middot; ${critClause}<b class="hi">${C.High} High</b>-severity gap${C.High === 1 ? "" : "s"}</p>`;
    const bar = document.getElementById("postureBar");
    // Double rAF so the initial clipped state paints before the fill transition.
    requestAnimationFrame(() => requestAnimationFrame(() => bar.classList.add("filled")));
  }
  function renderTabs() {
    document.getElementById("tabs").innerHTML = DATA.tabs.map(t =>
      `<button class="tab" role="tab" data-tab="${esc(t.id)}" aria-selected="${state.tab===t.id?"true":"false"}">${esc(t.label)} <span class="count tnum">${t.rows.length}</span></button>`).join("");
  }
  const curTab = () => DATA.tabs.find(t => t.id === state.tab) || DATA.tabs[0];

  function matchQ(row, cols) {
    if (!state.q) return true; const q = state.q.toLowerCase();
    return cols.some(c => { let v = row[c.key]; if (Array.isArray(v)) v = v.join(" "); return String(v==null?"":v).toLowerCase().includes(q); });
  }
  function cellHtml(col, val) {
    if (col.type === "sev") { const r = sevOf(val); return r ? `<span class="badge ${sevClass(r)}">${esc(val)}</span>` : esc(val); }
    if (col.type === "status") { const s = String(val); const scoped = /scoped/i.test(s); const on = !scoped && /^(Pass|Covered)$/i.test(s); const off = /^(Fail|Gap)$/i.test(s); const na = /^(NotApplicable|N\/A)$/i.test(s); const cls = on?"on":off?"off":scoped?"scoped":na?"na":""; return `<span class="pill ${cls}">${esc(na?"N/A":s)}</span>`; }
    if (col.type === "state") { const s = String(val); const cls = s==="On"?"on":s==="Report-only"?"report":s==="Off"?"off":""; return `<span class="pill ${cls}">${esc(s)}</span>`; }
    if (col.type === "mono") return `<span class="txt-dim">${esc(val)}</span>`;
    if (col.type === "num") return `<span class="tnum">${esc(val)}</span>`;
    return esc(val == null ? "" : val);
  }
  function th(c, s) {
    const active = s && s.col === c.key;
    const tip = active ? (s.dir==="asc"?"Sorted ascending - click to reverse":"Sorted descending - click to reverse") : "Click to sort by " + c.label;
    const cls = [c.type==="num"?"num":"", (c.type==="mono"||c.type==="sev"||c.type==="status"||c.type==="state")?"nowrap":""].join(" ");
    return `<th data-col="${esc(c.key)}" title="${esc(tip)}" tabindex="0" role="button" ${active?`aria-sort="${s.dir}"`:""} class="${cls}">${esc(c.label)}<span class="arrow">${active?(s.dir==="desc"?"&#9660;":"&#9650;"):""}</span></th>`;
  }
  function sevChips(t) {
    const sevCol = t.columns.find(c => c.type === "sev"); if (!sevCol) return "";
    const present = new Set(); t.rows.forEach(r => { const x = sevOf(r[sevCol.key]); if (x) present.add(x); });
    const order = RANKS.filter(r => present.has(r));
    return `<div class="chips" title="Toggle a severity on or off">` + order.map(r => {
      const off = state.sevOff.has(r);
      return `<button class="chip ${sevClass(r)}" data-sev="${r}" data-off="${off?"true":"false"}" aria-pressed="${off?"false":"true"}" title="${off?"Show":"Hide"} ${r} rows"><span class="dot" style="background:var(--sev-${r.toLowerCase()}-stripe)"></span>${r}</button>`;
    }).join("") + `</div>`;
  }
  function searchBox() {
    return `<div class="search"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg><input type="search" id="q" placeholder="Search this tab..." value="${esc(state.q)}" autocomplete="off" title="Filter rows in this tab as you type"></div>`;
  }
  function renderTable(t) {
    const cols = t.columns.filter(c => !c.detail), det = t.columns.filter(c => c.detail);
    const sevCol = t.columns.find(c => c.type === "sev");
    const statusCol = t.columns.find(c => c.type === "status");
    const stateCol = t.columns.find(c => c.type === "state");
    const isFindings = t.id === "findings";
    let rows = t.rows.filter(r => {
      if (sevCol && state.sevOff.has(sevOf(r[sevCol.key]))) return false;
      if (isFindings && state.sevOnly && sevCol && sevOf(r[sevCol.key]) !== state.sevOnly) return false;
      if (isFindings && state.statusOnly && statusCol && r[statusCol.key] !== state.statusOnly) return false;
      return matchQ(r, t.columns);
    });
    const s = state.sort[t.id];
    if (s) {
      const col = t.columns.find(c => c.key === s.col); const dir = s.dir === "desc" ? -1 : 1;
      rows = rows.slice().sort((a, b) => {
        const av = a[s.col], bv = b[s.col];
        if (col && col.type === "sev") return (RANKS.indexOf(sevOf(av)) - RANKS.indexOf(sevOf(bv))) * dir;
        if (col && col.type === "num") return ((+av||0) - (+bv||0)) * dir;
        return String(av==null?"":av).localeCompare(String(bv==null?"":bv)) * dir;
      });
    }
    const head = cols.map(c => th(c, s)).join("");
    const body = rows.length ? rows.map((r, i) => {
      const rc = sevCol ? rankClass(sevOf(r[sevCol.key]) || "Info") : "";
      const stv = stateCol ? String(r[stateCol.key]) : "";
      const stc = stv === "Off" ? "st-off" : stv === "Report-only" ? "st-report" : "";
      const sevRow = isFindings ? "sevrow" : "";
      const exp = det.length ? "expander" : "";
      const tip = det.length ? ` title="Click to expand details" tabindex="0" role="button" aria-expanded="false"` : "";
      const tds = cols.map((c, ci) => {
        const first = ci === 0;
        const inner = (first && det.length ? `<span class="caret">&#8250;</span>` : "") + (c.type === "primary" ? `<span class="fname">${esc(r[c.key])}</span>` : cellHtml(c, r[c.key]));
        const cls = [c.type==="num"?"num":"", c.type==="wrap"?"wrapcol":"", (c.type==="mono"||c.type==="sev"||c.type==="status"||c.type==="state")?"nowrap":""].join(" ");
        return `<td class="${cls}">${inner}</td>`;
      }).join("");
      let out = `<tr class="frow ${rc} ${stc} ${sevRow} ${exp}" data-row="${i}"${tip}>${tds}</tr>`;
      if (det.length) {
        out += `<tr class="detail" data-detail="${i}" hidden><td colspan="${cols.length}"><div class="detail-grid">` +
          det.map(c => `<div><div class="lbl">${esc(c.label)}</div><div class="val">${esc(r[c.key])}</div></div>`).join("") + `</div></td></tr>`;
      }
      return out;
    }).join("") : `<tr><td colspan="${cols.length||1}"><div class="empty">No rows match the current filters.</div></td></tr>`;
    const banner = t.note ? `<div class="banner">${esc(t.note)}</div>` : "";
    const remed = t.id === "baseline" ? remediationPanel() : "";
    return `${banner}${remed}<div class="toolbar">${searchBox()}${sevChips(t)}<span class="toolbar-note">${rows.length} shown</span></div><div class="tscroll"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }
  // ---- gap-policy remediation (client-side JSON download; no network) ----
  const GAPS = Array.isArray(DATA.gapPolicies) ? DATA.gapPolicies : (DATA.gapPolicies ? [DATA.gapPolicies] : []);
  const GAPMAN = Array.isArray(DATA.gapManual) ? DATA.gapManual : (DATA.gapManual ? [DATA.gapManual] : []);
  const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  function remediationPanel() {
    if (!GAPS.length && !GAPMAN.length) return "";
    const items = GAPS.map(g =>
      `<div class="rem-row"><span class="rem-name">${esc(g.name)}</span><button class="rem-btn" data-gap="${esc(g.id)}" title="Download this policy as JSON">Download</button></div>`).join("");
    const manual = GAPMAN.length
      ? `<div class="rem-manual"><div class="rem-manual-head">Need manual setup &mdash; no single-policy fix (${GAPMAN.length}):</div>` +
        GAPMAN.map(m => `<div class="rem-manual-item"><b>${esc(m.id)}</b> &ndash; ${esc(m.note)}</div>`).join("") + `</div>`
      : "";
    const all = GAPS.length ? `<button class="rem-btn rem-all" id="gapAll" title="Download every gap policy (individual files)">Download all ${GAPS.length}</button>` : "";
    const n = GAPS.length;
    const summary = n
      ? `Remediate gaps &middot; ${n} deploy-ready ${n === 1 ? "policy" : "policies"} to download`
      : "Remediate gaps &middot; manual steps";
    return `<div class="remediation">
      <button class="rem-toggle" id="remToggle" aria-expanded="false" title="Click to expand or collapse"><span class="caret">&#8250;</span> ${summary} <small>Report-only &middot; nothing is sent anywhere</small><span class="rem-hint"></span></button>
      <div class="rem-body" id="remBody" hidden>
        <p class="rem-intro">Each button downloads a ready-to-upload Conditional Access policy that closes one gap below. They start in <b>Report-only</b> (they log what would happen but enforce nothing, so they cannot lock anyone out). To deploy one: download it, then in the Entra portal go to <b>Conditional Access &rarr; Policies &rarr; Upload policy file</b>, keep the state on Report-only, and review the impact in <b>Insights &amp; Reporting</b> before switching it On. Generation is fully offline &mdash; nothing leaves this page.</p>
        <div class="rem-ctl">
          <label for="gapBtg">Break-glass group ID (optional):</label>
          <input id="gapBtg" type="text" spellcheck="false" placeholder="00000000-0000-0000-0000-000000000000" autocomplete="off">
          ${all}
        </div>
        <div class="rem-note" id="gapNote">Enter your emergency-access group GUID to exclude it from every policy. Left blank, files are name-marked and you must add the exclusion before enabling anything.</div>
        <div class="rem-list">${items}</div>
        ${manual}
      </div>
    </div>`;
  }
  function buildGapPolicy(g, btg) {
    const p = JSON.parse(JSON.stringify(g.policy));   // deep clone
    if (btg) { p.conditions.users.excludeGroups = [btg]; p.displayName = g.name; }
    else { p.displayName = g.name + " [ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]"; }
    return JSON.stringify(p, null, 2);
  }
  function downloadText(fileName, text) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = fileName; document.body.appendChild(a); a.click();
    document.body.removeChild(a); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function currentBtg() {
    const el = document.getElementById("gapBtg");
    const note = document.getElementById("gapNote");
    const v = (el && el.value || "").trim();
    if (!v) return { ok: true, value: "" };
    if (!GUID_RE.test(v)) { if (note) { note.textContent = "That is not a valid group GUID - fix it or clear the field."; note.classList.add("bad"); } return { ok: false }; }
    if (note) { note.classList.remove("bad"); note.textContent = "Break-glass group " + v + " will be excluded on every downloaded policy."; }
    return { ok: true, value: v };
  }
  function downloadGap(id) {
    const g = GAPS.find(x => x.id === id); if (!g) return;
    const btg = currentBtg(); if (!btg.ok) return;
    downloadText(g.fileName, buildGapPolicy(g, btg.value));
  }
  function mcls(v) { const s = String(v).toLowerCase(); if (s.startsWith("blocked")) return "m-blocked"; if (s.startsWith("no control")) return "m-gap"; if (s.includes("compliant")) return "m-compliant"; if (s.includes("mfa")||s.includes("app protection")) return "m-mfa"; return ""; }
  function renderMatrix(t) {
    const head = t.columns.map(c => `<th class="no-sort">${esc(c.label)}</th>`).join("");
    const body = t.rows.map(r => "<tr>" + t.columns.map((c, ci) => {
      const v = r[c.key];
      if (ci === 0) return `<td class="fname nowrap">${esc(v)}</td>`;
      const main = Array.isArray(v) ? v[0] : v, sub = Array.isArray(v) ? v[1] : "";
      return `<td class="${mcls(main)}"><span class="cell">${esc(main)}<small>${esc(sub)}</small></span></td>`;
    }).join("") + "</tr>").join("");
    // The matrix is a heuristic - always show its limitations prominently.
    const banner = `<div class="banner warn"><b>Approximation - verify before acting.</b> ${esc(t.note)}</div>`;
    return `${banner}<div class="tscroll"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }
  function renderPanel(focus) {
    const t = curTab();
    if (!t) { document.getElementById("panel").innerHTML = `<div class="empty">No data to display.</div>`; return; }
    document.getElementById("panel").innerHTML = (t.kind === "matrix") ? renderMatrix(t) : renderTable(t);
    if (focus) { const q = document.getElementById("q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }
  }
  function renderAll() { renderDash(); renderTabs(); renderPanel(false); }

  document.getElementById("dash").addEventListener("click", e => {
    const t = e.target.closest(".tile"); if (!t) return;
    const key = t.dataset.key;
    const goFind = () => { if (DATA.tabs.some(x => x.id === "findings")) state.tab = "findings"; };
    if (key === "Critical" || key === "High" || key === "Medium") { state.sevOnly = state.sevOnly === key ? null : key; state.statusOnly = null; goFind(); }
    else if (key === "pass") { state.statusOnly = state.statusOnly === "Pass" ? null : "Pass"; state.sevOnly = null; goFind(); }
    else if (key === "total") { state.sevOnly = null; state.statusOnly = null; goFind(); }
    else if (key === "noteval") { if (DATA.tabs.some(x => x.id === "noteval")) state.tab = "noteval"; }
    else if (key === "score") { if (DATA.tabs.some(x => x.id === "baseline")) state.tab = "baseline"; }
    renderAll();
  });
  // Posture band: click a segment or legend entry to filter findings to that severity.
  document.getElementById("posture").addEventListener("click", e => {
    const el = e.target.closest("[data-sev]"); if (!el) return;
    const sev = el.dataset.sev;
    state.sevOnly = state.sevOnly === sev ? null : sev;
    state.statusOnly = null;
    if (DATA.tabs.some(x => x.id === "findings")) state.tab = "findings";
    renderAll();
  });
  document.getElementById("tabs").addEventListener("click", e => {
    const t = e.target.closest(".tab"); if (!t) return;
    state.tab = t.dataset.tab; state.q = ""; state.sevOff.clear();   // per-tab fresh search/filters
    renderTabs(); renderPanel(false);
  });
  document.getElementById("panel").addEventListener("input", e => {
    if (e.target.id === "q") {
      const pos = e.target.selectionStart; state.q = e.target.value; renderPanel(true);
      const nq = document.getElementById("q"); if (nq) nq.setSelectionRange(pos, pos);   // keep caret in place
    }
  });
  document.getElementById("panel").addEventListener("click", e => {
    const remTog = e.target.closest("#remToggle");
    if (remTog) {
      const body = document.getElementById("remBody");
      const willOpen = body.hidden; body.hidden = !willOpen;
      remTog.setAttribute("aria-expanded", willOpen ? "true" : "false");
      remTog.classList.toggle("open", willOpen);
      return;
    }
    const gapBtn = e.target.closest(".rem-btn[data-gap]");
    if (gapBtn) { downloadGap(gapBtn.dataset.gap); return; }
    if (e.target.closest("#gapAll")) {
      const btg = currentBtg(); if (!btg.ok) return;
      GAPS.forEach((g, i) => setTimeout(() => downloadText(g.fileName, buildGapPolicy(g, btg.value)), i * 250));
      return;
    }
    const chip = e.target.closest(".chip");
    if (chip) { const sv = chip.dataset.sev; state.sevOff.has(sv) ? state.sevOff.delete(sv) : state.sevOff.add(sv); renderPanel(false); return; }
    const thEl = e.target.closest("th[data-col]");
    if (thEl && !thEl.classList.contains("no-sort")) {
      const col = thEl.dataset.col; const cur = state.sort[state.tab];
      state.sort[state.tab] = (cur && cur.col === col) ? { col, dir: cur.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" };
      renderPanel(false); return;
    }
    const row = e.target.closest("tr.expander");
    if (row) {
      const i = row.dataset.row; const det = document.querySelector(`tr[data-detail="${i}"]`);
      const open = row.classList.toggle("open");
      row.setAttribute("aria-expanded", open ? "true" : "false");
      if (det) det.hidden = !open;
    }
  });
  // Keyboard activation for sortable headers and expandable rows.
  document.getElementById("panel").addEventListener("keydown", e => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const target = e.target.closest("th[data-col]:not(.no-sort), tr.expander");
    if (target) { e.preventDefault(); target.click(); }
  });

  function buildSummary() {
    // "Issues" = actionable fails only. Info-level fails (e.g. Off / Report-only
    // policies) are informational, so they are excluded from the headline count
    // (they still appear in the distribution bar and the findings table).
    const totalIssues = ["Critical","High","Medium","Low"].reduce((s, r) => s + (C[r]||0), 0);
    const critClause = C.Critical > 0 ? `<b>${C.Critical} Critical</b> and ` : "";
    const critBox = C.Critical > 0 ? `<div class="gbox"><div class="k">Critical</div><div class="v" style="color:${SEVHEX.Critical}">${C.Critical}</div></div>` : "";
    const distTotal = RANKS.reduce((s, r) => s + (C[r]||0), 0) || 1;
    const bar = RANKS.filter(r => C[r] > 0).map(r => `<span style="width:${(C[r]/distTotal*100).toFixed(1)}%;background:${SEVHEX[r]}" title="${r}: ${C[r]}"></span>`).join("");
    const legend = RANKS.filter(r => C[r] > 0).map(r => `<span><i style="background:${SEVHEX[r]}"></i>${r} ${C[r]}</span>`).join("");
    const actions = (S.priorityActions||[]).map(f => `<li><span class="fn">${esc(f.name)}</span><span class="rk" style="color:${SEVHEX[f.risk]};background:${SEVBG[f.risk]}">${esc(f.risk)}</span><div class="rec">${esc(f.rec)}</div></li>`).join("");
    const gapItems = (S.gaps||[]).map(g => `<li>${esc(g.control)} <span style="color:${SEVHEX[g.priority]||"#5a6883"};font-weight:600">(${esc(g.priority)})</span></li>`).join("");
    const matrixRows = (S.matrix||[]).map(m => `<tr><td style="font-weight:600">${esc(m.platform)}</td><td>${esc(m.bu)}</td><td>${esc(m.bm)}</td><td>${esc(m.au)}</td><td>${esc(m.am)}</td></tr>`).join("");
    const hasMatrix = (S.matrix||[]).length > 0;
    return `
      <div class="doc-head">${(typeof ATC!=="undefined" && ATC.logo) ? `<img class="doc-logo" src="${ATC.logo}" alt="All Things Cloud">` : `<div class="shield">CA</div>`}<div><h2>Conditional Access Policy Audit</h2>
        <p class="doc-sub">${esc(S.policies)} policies &middot; ${esc(S.rules)} rules &middot; generated ${esc(S.generated)}</p></div></div>
      <div class="verdict"><b>${totalIssues} issues</b> across ${esc(S.policies)} policies, including ${critClause}<b>${C.High} High</b>-severity gaps. ${S.baselineCovered} of ${S.baselineTotal} baseline controls covered.</div>
      <div class="s-title">At a glance</div>
      <div class="glance">
        <div class="gbox"><div class="k">Issues</div><div class="v">${totalIssues}</div></div>
        ${critBox}
        <div class="gbox"><div class="k">High</div><div class="v" style="color:${SEVHEX.High}">${C.High}</div></div>
        <div class="gbox"><div class="k">Medium</div><div class="v" style="color:${SEVHEX.Medium}">${C.Medium}</div></div>
        <div class="gbox"><div class="k">Passing</div><div class="v" style="color:${SEVHEX.Good}">${S.pass}</div></div>
        <div class="gbox"><div class="k">Baseline</div><div class="v">${S.baselineCovered}/${S.baselineTotal}</div></div>
      </div>
      <div class="s-title">Severity distribution</div><div class="distbar">${bar}</div><div class="distlegend">${legend}</div>
      <div class="s-title">Priority actions &middot; High &amp; Critical</div><ol class="actions">${actions || "<li>None &mdash; no High or Critical findings.</li>"}</ol>
      <div class="s-title">Baseline coverage &middot; ${(S.gaps||[]).length} gap(s) of ${S.baselineTotal}</div><ul class="gaplist">${gapItems || "<li>All baseline controls covered.</li>"}</ul>
      ${hasMatrix ? `<div class="s-title">Platform matrix &middot; effective control to Office 365</div><table class="psum"><thead><tr><th>Platform</th><th>Browser &middot; unmgd</th><th>Browser &middot; mgd</th><th>Apps &middot; unmgd</th><th>Apps &middot; mgd</th></tr></thead><tbody>${matrixRows}</tbody></table>` : ""}
      <div class="caveat"><b>Scope &amp; caveats:</b> this reports on <b>Conditional Access policies only</b>. A "gap" means no CA policy supplies the control &mdash; it does <b>not</b> account for Security Defaults, per-user MFA, or the authentication-methods policy, which are outside this tool's scope. The platform matrix is an approximation (ignores device filters, location/risk conditions, and session controls &mdash; verify with Entra What-If). Group-membership checks require -ResolveNames.</div>
      <div class="doc-foot">CA Policy Audit Tool &middot; printable summary</div>`;
  }
  const preview = document.getElementById("preview");
  function openPreview() { document.getElementById("pvPage").innerHTML = buildSummary(); preview.hidden = false; document.body.classList.add("previewing"); const b = document.getElementById("pvPrint"); if (b) b.focus(); }
  function closePreview() { preview.hidden = true; document.body.classList.remove("previewing"); }
  document.getElementById("printBtn").addEventListener("click", openPreview);
  document.getElementById("pvClose").addEventListener("click", closePreview);
  document.getElementById("pvPrint").addEventListener("click", () => window.print());
  preview.addEventListener("click", e => { if (e.target === preview) closePreview(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && !preview.hidden) closePreview(); });

  document.getElementById("themeBtn").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "dark" ? "light" : cur === "light" ? "dark" : (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", next);
  });

  renderAll();
  renderPosture();
})();
'@
}
