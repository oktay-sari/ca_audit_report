# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Invoke-CAInteractive.ps1

<#
.SYNOPSIS
    Guided, interactive setup for the CA Policy Audit Tool.

.DESCRIPTION
    Start-CAInteractiveSetup walks the user through the audit options and returns
    a hashtable of parameters for Invoke-CAPolicyAudit. It offers a quick path
    (just folder + format, saved to the current working folder) and an advanced
    path (output location, Graph resolution, companion file, exclude pattern,
    raw flatten). Any prompt accepts 'q' to cancel; on cancel the orchestrator
    returns $null.
#>

# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------
function Assert-CANotCancelled {
    [CmdletBinding()]
    param([string] $Value)
    if ($Value -in @('q', 'quit', 'Q', 'QUIT')) {
        throw [System.OperationCanceledException]::new('Wizard cancelled by user.')
    }
}

# Read a line, treating end-of-input (Read-Host returns $null when stdin is
# exhausted or redirected from an empty source) as a cancellation.
function Read-CALine {
    [CmdletBinding()] [OutputType([string])]
    param([string] $Prompt)
    $v = Read-Host $Prompt
    if ($null -eq $v) { throw [System.OperationCanceledException]::new('No input available.') }
    return $v
}

function Read-CAYesNo {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Prompt, [bool] $Default = $false)
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $ans = (Read-CALine "$Prompt [$hint]").Trim()
        Assert-CANotCancelled $ans
        if ($ans -eq '') { return $Default }
        if ($ans -match '^(y|yes)$') { return $true }
        if ($ans -match '^(n|no)$') { return $false }
        Write-Host "  Please answer y or n (or q to quit)." -ForegroundColor DarkYellow
    }
}

function Read-CAMenuChoice {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Prompt, [Parameter(Mandatory)] [string[]] $Options, [int] $Default = 1)
    Write-Host $Prompt -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $marker = if (($i + 1) -eq $Default) { '(default)' } else { '' }
        Write-Host ("    {0}) {1} {2}" -f ($i + 1), $Options[$i], $marker) -ForegroundColor Gray
    }
    while ($true) {
        $ans = (Read-CALine "  Choose 1-$($Options.Count)").Trim()
        Assert-CANotCancelled $ans
        if ($ans -eq '') { return $Default }
        $n = 0
        if ([int]::TryParse($ans, [ref] $n) -and $n -ge 1 -and $n -le $Options.Count) { return $n }
        Write-Host "  Please enter a number between 1 and $($Options.Count)." -ForegroundColor DarkYellow
    }
}

function Read-CAFolder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Prompt, [string] $Default = '')
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { '' }
        $ans = (Read-CALine "$Prompt$suffix").Trim().Trim('"').Trim("'")
        Assert-CANotCancelled $ans
        if ($ans -eq '' -and $Default) { $ans = $Default }
        if ($ans -eq '') { Write-Host "  A folder is required." -ForegroundColor DarkYellow; continue }
        if (-not (Test-Path -LiteralPath $ans -PathType Container)) {
            Write-Host "  Folder not found: $ans" -ForegroundColor DarkYellow; continue
        }
        if (-not (Test-CAFolderHasPolicies $ans)) {
            Write-Host "  No policy .json files found in that folder. Try another." -ForegroundColor DarkYellow; continue
        }
        return (Resolve-Path -LiteralPath $ans).Path
    }
}

function Read-CAText {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Prompt, [string] $Default = '')
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $ans = (Read-CALine "$Prompt$suffix").Trim()
    Assert-CANotCancelled $ans
    if ($ans -eq '' -and $Default) { return $Default }
    return $ans
}

# ---------------------------------------------------------------------------
# Small detection helpers
# ---------------------------------------------------------------------------
function Test-CAFolderHasPolicies {
    [CmdletBinding()] [OutputType([bool])]
    param([string] $Folder)
    $json = @(Get-ChildItem -Path $Folder -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'MigrationTable.json' })
    return $json.Count -gt 0
}

function Test-CAHasSubfolderJson {
    [CmdletBinding()] [OutputType([bool])]
    param([string] $Folder)
    $sub = @(Get-ChildItem -Path $Folder -Directory -ErrorAction SilentlyContinue)
    foreach ($d in $sub) {
        if (@(Get-ChildItem -Path $d.FullName -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0) { return $true }
    }
    return $false
}

function Find-CACompanionInFolder {
    [CmdletBinding()] [OutputType([string])]
    param([string] $Folder)
    foreach ($c in @((Join-Path $Folder 'MigrationTable.json'), (Join-Path (Split-Path $Folder -Parent) 'MigrationTable.json'))) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return ''
}

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
function Start-CAInteractiveSetup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param()

    try {
        Write-Host ''
        Write-Host '  +--------------------------------------------+' -ForegroundColor Cyan
        Write-Host '  |   CA Policy Audit - guided setup           |' -ForegroundColor Cyan
        Write-Host '  +--------------------------------------------+' -ForegroundColor Cyan
        Write-Host '  Answer the prompts (Enter accepts the default, q quits).' -ForegroundColor DarkGray
        Write-Host ''

        # 1. Source
        $srcIdx = Read-CAMenuChoice -Prompt 'Audit from:' -Options @('Exported JSON files', 'Live tenant (Microsoft Graph, read-only sign-in)') -Default 1
        $source = @('Files', 'Tenant')[$srcIdx - 1]
        Write-Host ''

        $folder = ''
        $companionAuto = ''
        $cwd = (Get-Location).Path
        if ($source -eq 'Files') {
            $folderDefault = if (Test-CAFolderHasPolicies $cwd) { $cwd } else { '' }
            $folder = Read-CAFolder -Prompt 'Folder with CA policy JSON exports' -Default $folderDefault
            $companionAuto = Find-CACompanionInFolder $folder
            if ($companionAuto) {
                Write-Host "  Found companion name map ($(Split-Path -Leaf $companionAuto)) - group names will resolve offline." -ForegroundColor DarkGreen
            }
        }
        else {
            Write-Host "  Live tenant selected - you'll sign in read-only to Microsoft Graph when the audit runs." -ForegroundColor DarkGreen
        }
        Write-Host ''

        # The report is a self-contained interactive HTML file (no format choice).
        $defaultOut = Join-Path $cwd 'CA-Policy-Audit.html'

        # Defaults for the quick path
        $recurse = $false; $resolve = $false; $companion = ''; $exclude = ''
        $outPath = $defaultOut

        # 2. Fork
        $advanced = Read-CAYesNo -Prompt 'Configure advanced options?' -Default $false
        Write-Host ''

        if ($advanced) {
            $outPath = Read-CAText -Prompt 'Output file path (.html)' -Default $defaultOut
            if ($source -eq 'Files') {
                if (Test-CAHasSubfolderJson $folder) {
                    $recurse = Read-CAYesNo -Prompt 'Search subfolders for policies (recurse)?' -Default $false
                }
                $resolve = Read-CAYesNo -Prompt 'Resolve names via Microsoft Graph (read-only sign-in; needs Microsoft.Graph.Authentication)?' -Default $false
                if (-not $companionAuto) {
                    $companion = Read-CAText -Prompt 'Companion name-map file (MigrationTable.json), blank to skip' -Default ''
                }
            }
            $exclude = Read-CAText -Prompt "Exclude policies whose name matches a regex (e.g. TEST), blank for none" -Default ''
            Write-Host ''
        }

        # 3. Summary + confirm
        Write-Host '  Review:' -ForegroundColor White
        if ($source -eq 'Tenant') {
            Write-Host "    Source        : Live tenant (Microsoft Graph, read-only)" -ForegroundColor Gray
        }
        else {
            Write-Host "    Source        : $folder" -ForegroundColor Gray
        }
        Write-Host "    Report        : $outPath" -ForegroundColor Gray
        if ($advanced) {
            if ($source -eq 'Files') {
                Write-Host "    Recurse       : $recurse" -ForegroundColor Gray
                Write-Host "    Resolve names : $resolve" -ForegroundColor Gray
                if ($companion) { Write-Host "    Companion file: $companion" -ForegroundColor Gray }
            }
            if ($exclude) { Write-Host "    Exclude regex : $exclude" -ForegroundColor Gray }
        }
        Write-Host ''
        if (-not (Read-CAYesNo -Prompt 'Proceed with these settings?' -Default $true)) {
            return $null
        }

        # 4. Echo equivalent command for next time
        if ($source -eq 'Tenant') {
            $cmd = ".\Invoke-CAPolicyAudit.ps1 -Source Tenant -OutputPath '$outPath'"
        }
        else {
            $cmd = ".\Invoke-CAPolicyAudit.ps1 -JsonFolder '$folder' -OutputPath '$outPath'"
            if ($recurse) { $cmd += ' -Recurse' }
            if ($resolve) { $cmd += ' -ResolveNames' }
            if ($companion) { $cmd += " -CompanionFile '$companion'" }
        }
        if ($exclude) { $cmd += " -ExcludePattern '$exclude'" }
        Write-Host '  Tip - run the same audit non-interactively next time with:' -ForegroundColor DarkGray
        Write-Host "    $cmd" -ForegroundColor DarkGray
        Write-Host ''

        return @{
            Source         = $source
            JsonFolder     = $folder
            OutputPath     = $outPath
            Recurse        = $recurse
            ResolveNames   = $resolve
            CompanionFile  = $companion
            ExcludePattern = $exclude
        }
    }
    catch [System.OperationCanceledException] {
        Write-Host ''
        Write-Host '  Setup cancelled.' -ForegroundColor Yellow
        return $null
    }
}
