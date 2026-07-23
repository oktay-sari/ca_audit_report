# Rule: CA-010 - Browser missing from client app types on MFA policy
# Type: per-policy | Tier: static

function Test-CARule-010 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Does this policy require MFA or auth strength?
    $g = $Policy.grantControls
    if ($null -eq $g) { return }
    $hasMfa = $g.builtInControls -and ('mfa' -in $g.builtInControls)
    $hasAuthStrength = $null -ne $g.authenticationStrength
    if (-not ($hasMfa -or $hasAuthStrength)) { return }

    # What client app types are configured?
    $clientApps = @($Policy.conditions.clientAppTypes | Where-Object { $_ })
    if ($clientApps.Count -eq 0) { return }

    # 'all' means all client types - browser is included
    if ('all' -in $clientApps) { return }

    # Is browser missing?
    if ('browser' -notin $clientApps) {
        $configuredTypes = ($clientApps | ForEach-Object {
            switch ($_) {
                'mobileAppsAndDesktopClients' { 'Mobile apps and desktop clients' }
                'exchangeActiveSync'          { 'Exchange ActiveSync' }
                'other'                       { 'Other clients' }
                default                       { $_ }
            }
        }) -join ', '

        return New-CAFinding -Id 'CA-010' `
            -Name 'Browser missing from MFA policy client app types' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This MFA policy only targets: $configuredTypes. Browser sign-ins are not covered by this policy, meaning web-based access to resources may not require MFA." `
            -Remediation "Add 'Browser' to the client app types, or create a separate browser-specific MFA policy. Verify no other policy covers browser MFA for the same scope." `
            -Status 'Fail'
    }
}
