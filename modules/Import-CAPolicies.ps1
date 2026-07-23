# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Import-CAPolicies.ps1
#
# Suppressions:
#   PSAvoidUsingWriteHost - interactive CLI tool, colored console output is intentional

<#
.SYNOPSIS
    Loads Conditional Access policy JSON files from a folder and returns normalized policy objects.

.DESCRIPTION
    Reads all *.json files from the specified folder. Handles three export formats:
    - Single policy object per file (Entra portal "Download policy")
    - Array of policies in one file
    - Graph API response wrapper: { "value": [...] }

    Strips OData annotation keys, deduplicates by policy ID (keeps most recent),
    and returns clean PSCustomObject arrays ready for the overview and findings engine.

.PARAMETER JsonFolder
    Path to the folder containing policy JSON files.

.PARAMETER Recurse
    Search subfolders for JSON files.

.OUTPUTS
    PSCustomObject[] - normalized CA policy objects.
#>
function Import-CAPolicySet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $JsonFolder,

        [string] $ExcludePattern = '',

        [switch] $Recurse
    )

    if (-not (Test-Path $JsonFolder)) {
        throw "Folder not found: $JsonFolder"
    }

    $files = Get-ChildItem -Path $JsonFolder -Filter '*.json' -File -Recurse:$Recurse |
        Where-Object { $_.Name -ne 'MigrationTable.json' }   # companion name map, not a policy
    if (-not $files) {
        throw "No .json files found in $JsonFolder"
    }
    Write-Host "Found $($files.Count) JSON file(s) in $JsonFolder" -ForegroundColor Cyan

    # Parse all files, flatten arrays and wrappers
    $rawPolicies = @()
    $skippedFiles = @()

    foreach ($file in $files) {
        try {
            $content = Get-Content $file.FullName -Raw -ErrorAction Stop
            $obj = $content | ConvertFrom-Json -ErrorAction Stop

            # Handle {value:[...]} wrapper (Graph API response)
            if ($null -ne $obj.value -and $obj.value -is [System.Collections.IEnumerable]) {
                $rawPolicies += @($obj.value)
            }
            # Handle array of policies
            elseif ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
                $rawPolicies += @($obj)
            }
            # Single policy object
            else {
                $rawPolicies += $obj
            }
        }
        catch {
            Write-Warning "Skipping $($file.Name): $_"
            $skippedFiles += $file.Name
        }
    }

    $deduped = ConvertTo-CAPolicySet -RawPolicies $rawPolicies -ExcludePattern $ExcludePattern -SourceLabel 'the JSON files'

    if ($skippedFiles.Count -gt 0) {
        Write-Warning "Skipped $($skippedFiles.Count) file(s): $($skippedFiles -join ', ')"
    }

    return $deduped
}

<#
.SYNOPSIS
    Shared normalization for a set of raw CA policy objects, from files or Graph.

.DESCRIPTION
    Filters to objects that are actually CA policies (a conditions block plus a
    recognised state), optionally applies -ExcludePattern, strips OData
    annotations, and deduplicates by policy ID. Used by both Import-CAPolicySet
    (files) and Get-CAPolicySetFromGraph (live tenant) so the two never drift.

.PARAMETER SourceLabel
    Human-readable source for the "no policies found" error (e.g. 'the JSON
    files' or 'the tenant').
#>
function ConvertTo-CAPolicySet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [object[]] $RawPolicies,
        [string] $ExcludePattern = '',
        [string] $SourceLabel = 'the input'
    )

    $caStates = @('enabled', 'disabled', 'enabledForReportingButNotEnforced')
    $validPolicies = @($RawPolicies | Where-Object {
        $null -ne $_.conditions -and $_.state -in $caStates
    })

    $nonPolicyCount = @($RawPolicies).Count - $validPolicies.Count
    if ($nonPolicyCount -gt 0) {
        Write-Host "Skipped $nonPolicyCount non-policy object(s) (no CA conditions/state)." -ForegroundColor DarkGray
    }

    if ($validPolicies.Count -eq 0) {
        throw "No valid Conditional Access policies found in $SourceLabel."
    }

    # Optionally exclude policies whose displayName matches a regex (e.g. 'TEST'
    # to drop test/staging policies). Validated up front for a clear error.
    if ($ExcludePattern) {
        # Compile once with a match timeout so a pathological (operator-supplied)
        # pattern can't hang on a hostile displayName (catastrophic backtracking).
        try {
            $excludeRegex = [regex]::new(
                $ExcludePattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [timespan]::FromSeconds(2))
        }
        catch {
            throw "Invalid -ExcludePattern regex '$ExcludePattern': $($_.Exception.Message)"
        }

        $beforeCount = $validPolicies.Count
        try {
            $validPolicies = @($validPolicies | Where-Object { -not $excludeRegex.IsMatch([string]$_.displayName) })
        }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
            throw "-ExcludePattern '$ExcludePattern' timed out while matching (possible catastrophic backtracking). Simplify the pattern."
        }
        $excludedCount = $beforeCount - $validPolicies.Count
        Write-Host "Excluded $excludedCount policy/policies matching -ExcludePattern '$ExcludePattern'." -ForegroundColor DarkGray

        if ($validPolicies.Count -eq 0) {
            throw "All policies were excluded by -ExcludePattern '$ExcludePattern'. Nothing left to analyze."
        }
    }

    # Strip OData annotations recursively, then deduplicate by policy ID.
    $cleanPolicies = @($validPolicies | ForEach-Object { ConvertTo-CleanPolicy $_ })
    $deduped = Select-UniquePolicy $cleanPolicies

    Write-Host "Loaded $($deduped.Count) unique policies." -ForegroundColor Cyan
    return $deduped
}

<#
.SYNOPSIS
    Recursively strips OData annotation keys from a policy object.

.DESCRIPTION
    Strips keys matching the pattern *@odata.* (e.g., @odata.context,
    authenticationStrength@odata.context, combinationConfigurations@odata.context).
    These are metadata injected by the Graph API and are not policy configuration.
#>
function ConvertTo-CleanPolicy {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    # PSCustomObject - filter properties
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $clean = [PSCustomObject]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            # Skip OData annotation keys
            if ($prop.Name -match '@odata\.') {
                continue
            }
            $cleanValue = ConvertTo-CleanPolicy $prop.Value
            $clean | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $cleanValue
        }
        return $clean
    }

    # Hashtable / dictionary (e.g. from Invoke-MgGraphRequest) - clean like an
    # object. MUST come before the IEnumerable check: a hashtable is enumerable,
    # and iterating it yields DictionaryEntry pairs, which would destroy the shape.
    if ($InputObject -is [System.Collections.IDictionary]) {
        $clean = [PSCustomObject]@{}
        foreach ($key in @($InputObject.Keys)) {
            if ("$key" -match '@odata\.') { continue }
            $clean | Add-Member -NotePropertyName "$key" -NotePropertyValue (ConvertTo-CleanPolicy $InputObject[$key])
        }
        return $clean
    }

    # Array - recurse into each element
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $result = @($InputObject | ForEach-Object { ConvertTo-CleanPolicy $_ })
        return $result
    }

    # Scalar - return as-is
    return $InputObject
}

<#
.SYNOPSIS
    Deduplicates policies by ID, keeping the most recently modified version.

.DESCRIPTION
    If the same policy ID appears in multiple files (e.g., duplicate exports),
    keeps the one with the most recent modifiedDateTime and warns about the others.
#>
function Select-UniquePolicy {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $PolicyList
    )

    $seen = @{}
    $duplicateCount = 0

    foreach ($policy in $PolicyList) {
        $policyId = $policy.id
        if (-not $policyId) {
            # No ID - keep it but warn
            Write-Warning "Policy '$($policy.displayName)' has no id field."
            $seen["no-id-$([guid]::NewGuid())"] = $policy
            continue
        }

        if ($seen.ContainsKey($policyId)) {
            $duplicateCount++
            # Keep the more recently modified one
            $existingDate = $seen[$policyId].modifiedDateTime
            $newDate = $policy.modifiedDateTime
            if ($newDate -and $existingDate -and $newDate -gt $existingDate) {
                Write-Verbose "Duplicate policy '$($policy.displayName)' ($policyId) - keeping newer version."
                $seen[$policyId] = $policy
            }
            else {
                Write-Verbose "Duplicate policy '$($policy.displayName)' ($policyId) - keeping existing version."
            }
        }
        else {
            $seen[$policyId] = $policy
        }
    }

    if ($duplicateCount -gt 0) {
        Write-Warning "Found $duplicateCount duplicate policy ID(s) - kept the most recently modified version of each."
    }

    return @($seen.Values | Sort-Object displayName)
}
