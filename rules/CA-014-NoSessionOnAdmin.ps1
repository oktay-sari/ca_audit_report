# Rule: CA-014 - No session controls on admin-targeted policy
# Type: per-policy | Tier: static

function Test-CARule-014 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    # Does this policy target admin roles?
    $roles = @($Policy.conditions.users.includeRoles | Where-Object { $_ })
    if ($roles.Count -eq 0) { return }

    # Does it have any session controls?
    $s = $Policy.sessionControls
    $hasSession = $false

    if ($null -ne $s) {
        if ($s.signInFrequency.isEnabled) { $hasSession = $true }
        if ($s.persistentBrowser.isEnabled) { $hasSession = $true }
        if ($s.cloudAppSecurity.isEnabled) { $hasSession = $true }
        if ($s.applicationEnforcedRestrictions.isEnabled) { $hasSession = $true }
        if ($s.continuousAccessEvaluation.mode) { $hasSession = $true }
    }

    if (-not $hasSession) {
        return New-CAFinding -Id 'CA-014' `
            -Name 'No session controls on admin policy' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This policy targets $($roles.Count) admin role(s) but has no session controls (sign-in frequency, persistent browser, etc.). Admin sessions may remain active for extended periods, increasing the window for session hijacking." `
            -Remediation 'Add sign-in frequency (e.g., 4-12 hours) and set persistent browser to Never for admin-targeted policies.' `
            -Status 'Fail'
    }
}
