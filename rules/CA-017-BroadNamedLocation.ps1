# Rule: CA-017 - Named location may be overly broad
# Type: cross-policy | Tier: named-location-detail (Tier 2)
# Offline: emits NotEvaluated. With -ResolveNames: evaluates IP scope.
# "Broad" default: any single IPv4 range wider than /16, or a country-based
# location used as a trusted exclusion.

function Test-CACrossRule-017 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $activePolicies = @($Policies | Where-Object { $_.state -ne 'disabled' })

    # Collect all named location IDs used in exclusions
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $excludedLocationIds = @{}

    foreach ($policy in $activePolicies) {
        $excludeLocs = @($policy.conditions.locations.excludeLocations | Where-Object { $_ })
        foreach ($locId in $excludeLocs) {
            # Skip well-known tokens
            if ($locId -eq 'AllTrusted') { continue }
            if ($locId -notmatch $guidPattern) { continue }

            if (-not $excludedLocationIds.ContainsKey($locId)) { $excludedLocationIds[$locId] = @() }
            $excludedLocationIds[$locId] += $policy.displayName
        }
    }

    if ($excludedLocationIds.Count -eq 0) { return }

    $enriched = Test-CAEnrichmentAvailable
    $findings = @()

    foreach ($locId in $excludedLocationIds.Keys) {
        $locName = (Resolve-CAIdentity -Id $locId -Type Location).DisplayName
        $usedIn = $excludedLocationIds[$locId]
        $policyList = $usedIn -join ', '

        # Offline - cannot inspect the IP scope.
        if (-not $enriched) {
            $findings += New-CAFinding -Id 'CA-017' `
                -Name 'Named location IP scope not verified' `
                -Severity 'High' `
                -Requires 'named-location-detail' `
                -PolicyName $policyList `
                -Detail "Named location '$locName' ($locId) is excluded from $($usedIn.Count) policy/policies. Cannot verify the IP range scope without directory access. An overly broad named location (e.g., a /8 network) used as a trusted location exclusion weakens MFA across the tenant." `
                -Remediation 'Run with -ResolveNames to inspect the IP ranges, or manually verify in the Entra portal that each IP range is a narrow, controlled egress point.' `
                -Status 'NotEvaluated'
            continue
        }

        $info = Get-CALocationEnrichment -Id $locId

        if ($null -eq $info) {
            $findings += New-CAFinding -Id 'CA-017' `
                -Name 'Named location IP scope not verified' `
                -Severity 'High' `
                -Requires 'named-location-detail' `
                -PolicyName $policyList `
                -Detail "Named location '$locName' ($locId) is excluded from $($usedIn.Count) policy/policies. Its definition could not be retrieved from Graph (transient error or the location was deleted)." `
                -Remediation 'Re-run with -ResolveNames, or manually verify the IP ranges in the Entra portal.' `
                -Status 'NotEvaluated'
            continue
        }

        # Country-based location used as an exclusion - IP breadth is not the
        # right lens; whole countries as trusted exclusions are inherently broad.
        if ($info.IsCountryBased) {
            $findings += New-CAFinding -Id 'CA-017' `
                -Name 'Country-based location used as exclusion' `
                -Severity 'High' `
                -Requires 'named-location-detail' `
                -PolicyName $policyList `
                -Detail "Named location '$locName' ($locId) is country/region-based and excluded from $($usedIn.Count) policy/policies. Excluding an entire country trusts every IP originating there, which is far broader than a controlled egress point." `
                -Remediation 'Prefer excluding specific, controlled IP ranges over whole countries. If country scoping is required, ensure compensating controls apply.' `
                -Status 'Fail'
            continue
        }

        # Evaluate IPv4 CIDR breadth. Broadest = smallest prefix length.
        $broadRanges = @()
        $minPrefix = 33
        foreach ($cidr in @($info.IpRanges)) {
            $prefix = Get-CidrPrefixLength $cidr
            if ($null -eq $prefix) { continue }   # IPv6 or unparseable - skip
            if ($prefix -lt $minPrefix) { $minPrefix = $prefix }
            if ($prefix -lt 16) { $broadRanges += "$cidr (/$prefix)" }
        }

        $trustNote = if ($info.IsTrusted) { ' The location is marked Trusted.' } else { '' }

        if ($broadRanges.Count -gt 0) {
            $findings += New-CAFinding -Id 'CA-017' `
                -Name 'Named location is overly broad' `
                -Severity 'High' `
                -Requires 'named-location-detail' `
                -PolicyName $policyList `
                -Detail "Named location '$locName' ($locId) is excluded from $($usedIn.Count) policy/policies and contains range(s) wider than /16: $($broadRanges -join ', ').$trustNote A broad trusted-location exclusion weakens MFA for everyone inside that range." `
                -Remediation 'Narrow the IP ranges to controlled egress points (typically /24 or tighter). Split large ranges and remove unused ones.' `
                -Status 'Fail'
            continue
        }

        $tightest = if ($minPrefix -le 32) { "/$minPrefix" } else { 'n/a' }
        $findings += New-CAFinding -Id 'CA-017' `
            -Name 'Named location IP scope verified' `
            -Severity 'Good' `
            -Requires 'named-location-detail' `
            -PolicyName $policyList `
            -Detail "Named location '$locName' ($locId) is excluded from $($usedIn.Count) policy/policies. All IPv4 ranges are /16 or narrower (broadest: $tightest).$trustNote" `
            -Remediation 'Periodically confirm the IP ranges still map to controlled egress points.' `
            -Status 'Pass'
    }

    return $findings
}

# Parses the prefix length from an IPv4 CIDR string (e.g. "10.0.0.0/8" -> 8).
# A bare IPv4 address is treated as /32. Returns $null for IPv6 or unparseable.
function Get-CidrPrefixLength {
    [CmdletBinding()]
    [OutputType([object])]
    param([string] $Cidr)

    if ([string]::IsNullOrWhiteSpace($Cidr)) { return $null }
    if ($Cidr -match ':') { return $null }   # IPv6 - out of scope for /16 heuristic

    $parts = $Cidr -split '/', 2
    $ipv4Pattern = '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if ($parts[0] -notmatch $ipv4Pattern) { return $null }

    if ($parts.Count -eq 1) { return 32 }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref] $prefix)) { return $null }
    if ($prefix -lt 0 -or $prefix -gt 32) { return $null }
    return $prefix
}
