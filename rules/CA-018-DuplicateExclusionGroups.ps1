# Rule: CA-018 - Duplicate/nested exclusion groups
# Type: cross-policy | Tier: group-membership (Tier 2)
# Offline: emits NotEvaluated for pairs that co-occur in 3+ policies.
# With -ResolveNames: compares actual membership of co-occurring pairs and
# flags nested (subset) or heavily overlapping (Jaccard >= 0.5) groups.

function Test-CACrossRule-018 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Build a map of which groups co-occur in exclusions
    $coOccurrence = @{}  # "groupA|groupB" -> count

    foreach ($policy in $activePolicies) {
        $excludeGroups = @($policy.conditions.users.excludeGroups | Where-Object { $_ }) | Sort-Object
        if ($excludeGroups.Count -lt 2) { continue }

        # Check all pairs
        for ($i = 0; $i -lt $excludeGroups.Count; $i++) {
            for ($j = $i + 1; $j -lt $excludeGroups.Count; $j++) {
                $pair = "$($excludeGroups[$i])|$($excludeGroups[$j])"
                if (-not $coOccurrence.ContainsKey($pair)) { $coOccurrence[$pair] = 0 }
                $coOccurrence[$pair]++
            }
        }
    }

    if ($coOccurrence.Count -eq 0) { return }

    $enriched = Test-CAEnrichmentAvailable
    $findings = @()

    foreach ($pair in $coOccurrence.Keys) {
        $count = $coOccurrence[$pair]
        $ids = $pair -split '\|'
        $name1 = (Resolve-CAIdentity -Id $ids[0] -Type Group).DisplayName
        $name2 = (Resolve-CAIdentity -Id $ids[1] -Type Group).DisplayName

        # Offline - keep the original heuristic (co-occur in 3+ policies).
        if (-not $enriched) {
            if ($count -ge 3) {
                $findings += New-CAFinding -Id 'CA-018' `
                    -Name 'Possibly duplicate exclusion groups' `
                    -Severity 'Medium' `
                    -Requires 'group-membership' `
                    -PolicyName "(co-occur in $count policies)" `
                    -Detail "Groups '$name1' and '$name2' are excluded together from $count policies. This pattern suggests they may be nested variants (e.g., a group and its SG- prefix copy). Cannot verify membership overlap without directory access." `
                    -Remediation 'Run with -ResolveNames to compare membership, or manually check if these groups have overlapping members. Consolidate if they serve the same purpose.' `
                    -Status 'NotEvaluated'
            }
            continue
        }

        # Enriched - compare actual membership.
        $infoA = Get-CAGroupEnrichment -Id $ids[0]
        $infoB = Get-CAGroupEnrichment -Id $ids[1]

        # Skip if either group is missing, deleted, or empty (CA-016 covers those).
        if ($null -eq $infoA -or $null -eq $infoB) { continue }
        if (-not $infoA.Exists -or -not $infoB.Exists) { continue }
        if ($infoA.MemberCount -eq 0 -or $infoB.MemberCount -eq 0) { continue }

        $overlap = Measure-CAMembershipOverlap -MembersA $infoA.MemberIds -MembersB $infoB.MemberIds

        if ($overlap.Relationship -eq 'subset') {
            $sub = if ($overlap.SubsetOf -eq 'A') { "'$name1' is entirely contained in '$name2'" } else { "'$name2' is entirely contained in '$name1'" }
            $findings += New-CAFinding -Id 'CA-018' `
                -Name 'Nested exclusion groups' `
                -Severity 'Medium' `
                -Requires 'group-membership' `
                -PolicyName "(co-occur in $count policy/policies)" `
                -Detail "$sub. Both are excluded together from $count policy/policies, so the smaller group is redundant - every member is already excluded by the larger one." `
                -Remediation 'Remove the redundant (subset) group from the exclusion list; the larger group already covers its members.' `
                -Status 'Fail'
        }
        elseif ($overlap.Jaccard -ge 0.5) {
            $pct = [math]::Round($overlap.Jaccard * 100)
            $findings += New-CAFinding -Id 'CA-018' `
                -Name 'Heavily overlapping exclusion groups' `
                -Severity 'Medium' `
                -Requires 'group-membership' `
                -PolicyName "(co-occur in $count policy/policies)" `
                -Detail "Groups '$name1' ($($infoA.MemberCount) members) and '$name2' ($($infoB.MemberCount) members) share $($overlap.Intersection) member(s) - $pct% overlap (Jaccard). Excluded together from $count policy/policies, they likely serve the same purpose." `
                -Remediation 'Review whether both groups are needed. Consolidate into one exclusion group if they represent the same population.' `
                -Status 'Fail'
        }
        # Disjoint / low overlap -> not a finding (distinct populations).
    }

    return $findings
}

# Computes membership overlap between two ID sets.
# Returns @{ Intersection; Union; Jaccard; Relationship; SubsetOf }.
# Relationship is 'subset' when one set is fully contained in the other.
function Measure-CAMembershipOverlap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string[]] $MembersA,
        [string[]] $MembersB
    )

    $setA = [System.Collections.Generic.HashSet[string]]::new([string[]]@($MembersA), [System.StringComparer]::OrdinalIgnoreCase)
    $setB = [System.Collections.Generic.HashSet[string]]::new([string[]]@($MembersB), [System.StringComparer]::OrdinalIgnoreCase)

    $inter = 0
    foreach ($id in $setA) { if ($setB.Contains($id)) { $inter++ } }
    $union = $setA.Count + $setB.Count - $inter

    $relationship = 'partial'
    $subsetOf = ''
    if ($inter -gt 0) {
        if ($inter -eq $setA.Count) { $relationship = 'subset'; $subsetOf = 'A' }
        elseif ($inter -eq $setB.Count) { $relationship = 'subset'; $subsetOf = 'B' }
    }
    elseif ($inter -eq 0) {
        $relationship = 'disjoint'
    }

    $jaccard = if ($union -gt 0) { $inter / $union } else { 0 }

    return @{
        Intersection = $inter
        Union        = $union
        Jaccard      = $jaccard
        Relationship = $relationship
        SubsetOf     = $subsetOf
    }
}
