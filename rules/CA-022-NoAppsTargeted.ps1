# Rule: CA-022 - Policy targeting no applications
# Type: per-policy | Tier: static

function Test-CARule-022 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -eq 'disabled') { return }

    $apps = @($Policy.conditions.applications.includeApplications | Where-Object { $_ })
    $actions = @($Policy.conditions.applications.includeUserActions | Where-Object { $_ })

    if ($apps.Count -eq 0 -and $actions.Count -eq 0) {
        return New-CAFinding -Id 'CA-022' `
            -Name 'Policy targets no applications or user actions' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail 'includeApplications is empty and no user actions are targeted. This policy matches no resources and has no effect.' `
            -Remediation 'Add target applications or user actions, or disable the policy.' `
            -Status 'Fail'
    }

    if ($apps.Count -eq 1 -and 'None' -in $apps -and $actions.Count -eq 0) {
        return New-CAFinding -Id 'CA-022' `
            -Name 'Policy explicitly targets no applications' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "includeApplications is set to 'None'. This policy matches no resources - likely a placeholder or misconfiguration." `
            -Remediation 'Add target applications or disable the policy.' `
            -Status 'Fail'
    }
}
