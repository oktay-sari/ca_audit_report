# Rule: CA-003 - Location exclusion on security-bearing grant
# Type: per-policy | Tier: static

function Test-CARule-003 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Does this policy have a security-bearing grant?
    $g = $Policy.grantControls
    if ($null -eq $g) { return }
    $bic = $g.builtInControls
    $hasMfa = $bic -and ('mfa' -in $bic)
    $hasDevice = $bic -and (('compliantDevice' -in $bic) -or ('domainJoinedDevice' -in $bic))
    $hasAppProt = $bic -and (('approvedApplication' -in $bic) -or ('compliantApplication' -in $bic))
    $hasAuthStrength = $null -ne $g.authenticationStrength
    $hasPasswordChange = $bic -and ('passwordChange' -in $bic)

    if (-not ($hasMfa -or $hasDevice -or $hasAppProt -or $hasAuthStrength -or $hasPasswordChange)) { return }

    # Does it exclude locations?
    $excludedLocs = @($Policy.conditions.locations.excludeLocations | Where-Object { $_ })
    if ($excludedLocs.Count -eq 0) { return }

    $hasAllTrusted = 'AllTrusted' -in $excludedLocs
    $locNames = ($excludedLocs | ForEach-Object { (Resolve-CAIdentity -Id $_ -Type Location).DisplayName }) -join ', '

    $controlNames = @()
    if ($hasMfa) { $controlNames += 'MFA' }
    if ($hasDevice) { $controlNames += 'managed device' }
    if ($hasAppProt) { $controlNames += 'app protection' }
    if ($hasAuthStrength) { $controlNames += "auth strength ($($g.authenticationStrength.displayName))" }
    if ($hasPasswordChange) { $controlNames += 'password change' }

    $severity = if ($hasAllTrusted) { 'High' } else { 'Medium' }
    $allTrustedNote = if ($hasAllTrusted) { ' ALL trusted locations are excluded, so the entire posture depends on how narrow those named locations are.' } else { '' }

    return New-CAFinding -Id 'CA-003' `
        -Name 'Location exclusion on security-bearing grant' `
        -Severity $severity `
        -Requires 'static' `
        -PolicyName $Policy.displayName `
        -Detail "This policy requires $($controlNames -join ' + ') but excludes locations: $locNames. Sign-ins from excluded locations skip these controls.$allTrustedNote" `
        -Remediation 'Audit the excluded named locations. Confirm each is a narrow, controlled egress IP. Remove overly broad entries. Consider requiring controls from all locations.' `
        -Status 'Fail'
}
