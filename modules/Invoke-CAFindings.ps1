# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Invoke-CAFindings.ps1

<#
.SYNOPSIS
    Runs all CA audit rules against a set of policies and returns findings.

.DESCRIPTION
    The findings engine dot-sources every .ps1 file in the rules/ folder
    (except _RuleTemplate.ps1), then invokes each rule function.

    Rules come in two shapes:
    - Per-policy: called once for each policy. Function name: Test-CARule-XXXX
    - Cross-policy: called once with all policies. Function name: Test-CACrossRule-XXXX

    Each rule returns zero or more PSCustomObject findings with a fixed schema.

.PARAMETER Policies
    Array of normalized CA policy objects (from Import-CAPolicySet).

.PARAMETER RulesFolder
    Path to the rules/ folder. Defaults to ../rules relative to this module.

.OUTPUTS
    PSCustomObject[] - findings sorted by severity then rule ID.
#>
function Invoke-CAFindingSet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $Policies,

        [string] $RulesFolder = ''
    )

    # Default rules folder: sibling of modules/
    if (-not $RulesFolder) {
        $RulesFolder = Join-Path (Split-Path $PSScriptRoot -Parent) 'rules'
    }

    if (-not (Test-Path $RulesFolder)) {
        throw "Rules folder not found: $RulesFolder"
    }

    # Load all rule files
    $ruleFiles = Get-ChildItem -Path $RulesFolder -Filter '*.ps1' -File |
        Where-Object { $_.Name -ne '_RuleTemplate.ps1' }

    if (-not $ruleFiles) {
        Write-Warning "No rule files found in $RulesFolder"
        return @()
    }

    foreach ($file in $ruleFiles) {
        try {
            . $file.FullName
            Write-Verbose "Loaded rule: $($file.Name)"
        }
        catch {
            Write-Warning "Failed to load rule $($file.Name): $_"
        }
    }

    Write-Host "Loaded $($ruleFiles.Count) rule file(s)." -ForegroundColor Cyan

    # Discover rule functions
    $perPolicyRules = Get-Command -Name 'Test-CARule-*' -CommandType Function -ErrorAction SilentlyContinue
    $crossPolicyRules = Get-Command -Name 'Test-CACrossRule-*' -CommandType Function -ErrorAction SilentlyContinue

    $totalRules = @($perPolicyRules).Count + @($crossPolicyRules).Count
    Write-Host "Discovered $totalRules rule(s) ($(@($perPolicyRules).Count) per-policy, $(@($crossPolicyRules).Count) cross-policy)." -ForegroundColor Cyan

    # Run per-policy rules
    $findings = @()

    foreach ($rule in @($perPolicyRules)) {
        foreach ($policy in $Policies) {
            try {
                $results = & $rule.Name -Policy $policy
                $findings += @($results | Where-Object { $_ })
            }
            catch {
                Write-Warning "Rule $($rule.Name) failed on '$($policy.displayName)': $_"
            }
        }
    }

    # Run cross-policy rules
    foreach ($rule in @($crossPolicyRules)) {
        try {
            $results = & $rule.Name -Policies $Policies
            $findings += @($results | Where-Object { $_ })
        }
        catch {
            Write-Warning "Cross-policy rule $($rule.Name) failed: $_"
        }
    }

    # Sort by severity order, then rule ID
    $severityOrder = @{
        'Critical' = 0
        'High'     = 1
        'Medium'   = 2
        'Low'      = 3
        'Info'     = 4
        'Good'     = 5
    }

    $sorted = @($findings | Sort-Object {
        $s = $severityOrder[$_.Severity]
        if ($null -eq $s) { 99 } else { $s }
    }, Id)

    # Enrich baseline-coverage findings in place: name covering policies, classify
    # coverage scope, flag Report-only near-misses, add membership context. Rules
    # themselves are untouched (their Pass/Fail is unchanged).
    if (Get-Command Update-CABaselineCoverage -ErrorAction SilentlyContinue) {
        Update-CABaselineCoverage -Findings $sorted -Policies $Policies
    }

    Write-Host "Generated $($sorted.Count) finding(s)." -ForegroundColor Cyan

    return @($sorted)
}

<#
.SYNOPSIS
    Helper to create a properly structured finding object.

.DESCRIPTION
    Used by rules to emit findings with a consistent schema.
    Validates that required fields are present.
#>
<#
.SYNOPSIS
    Returns the test/staging keyword a policy name matches (whole-word, case-
    insensitive), or '' if none. Single source of truth for CA-020 and the
    baseline "covered by a test policy" flag.
#>
function Test-CATestPolicyName {
    [CmdletBinding()] [OutputType([string])]
    param([string] $Name)
    foreach ($k in @('test', 'tst', 'testing', 'tmp', 'temp', 'poc', 'demo', 'draft', 'pilot', 'sandbox', 'staging', 'dev', 'uat')) {
        if ($Name -match "\b$k\b") { return $k }
    }
    return ''
}

function New-CAFinding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Info','Good')] [string] $Severity,
        [Parameter(Mandatory)] [ValidateSet('static','group-membership','named-location-detail','role-assignment')] [string] $Requires,
        [string] $PolicyName = '',
        [Parameter(Mandatory)] [string] $Detail,
        [string] $Remediation = '',
        [Parameter(Mandatory)] [ValidateSet('Pass','Fail','NotEvaluated','NotApplicable')] [string] $Status
    )

    return [PSCustomObject][ordered]@{
        Id          = $Id
        Name        = $Name
        Severity    = $Severity
        Requires    = $Requires
        PolicyName  = $PolicyName
        Detail      = $Detail
        Remediation = $Remediation
        Status      = $Status
        # Baseline-coverage enrichment (populated post-hoc by Update-CABaselineCoverage
        # for '(baseline check)' findings; empty/neutral for everything else).
        CoveredBy           = @()   # displayNames of the On policies that satisfy the control
        CoverageState       = ''    # '', 'covered', 'scoped', or 'gap' (baseline rows only)
        ScopeNote           = ''    # neutral scope / membership context
        ReportOnlyCandidate = @()   # Report-only policy names that would cover a gap if enabled
    }
}
