# Rule: CA-011 - Platform exclusion creates coverage gap
# Type: per-policy | Tier: static

function Test-CARule-011 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Does this policy require compliant device or block?
    $g = $Policy.grantControls
    if ($null -eq $g) { return }
    $hasCompliant = $g.builtInControls -and ('compliantDevice' -in $g.builtInControls)
    $hasBlock = $g.builtInControls -and ('block' -in $g.builtInControls)
    if (-not ($hasCompliant -or $hasBlock)) { return }

    # Are platforms configured with exclusions?
    $platforms = $Policy.conditions.platforms
    if ($null -eq $platforms) { return }

    $excludePlats = @($platforms.excludePlatforms | Where-Object { $_ })
    if ($excludePlats.Count -eq 0) { return }

    $controlType = if ($hasCompliant) { 'compliant device' } else { 'Block' }

    return New-CAFinding -Id 'CA-011' `
        -Name 'Platform exclusion creates coverage gap' `
        -Severity 'High' `
        -Requires 'static' `
        -PolicyName $Policy.displayName `
        -Detail "This policy requires $controlType but excludes platforms: $($excludePlats -join ', '). Devices on excluded platforms can access the targeted resources without this control." `
        -Remediation "Verify that excluded platforms are covered by other policies (e.g., BYOD app protection, separate platform-specific policies). If not, remove the platform exclusion or create compensating policies." `
        -Status 'Fail'
}
