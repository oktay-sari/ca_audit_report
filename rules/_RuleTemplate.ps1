# Rule: CA-XXX - <Short description>
# Type: per-policy | cross-policy
# Tier: static | group-membership | named-location-detail
#
# Copy this file, rename to CA-XXX-ShortName.ps1, and implement the function.
# Per-policy rules:  function name must start with Test-CARule-
# Cross-policy rules: function name must start with Test-CACrossRule-

function Test-CARule-XXX {
    # Template stub: $Policy is unused until you implement the check below.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    # Skip policies that don't apply to this rule
    # if (<not relevant>) { return }

    # Check condition
    # if (<problem found>) {
    #     return New-CAFinding -Id 'CA-XXX' `
    #         -Name 'Short description' `
    #         -Severity 'High' `
    #         -Requires 'static' `
    #         -PolicyName $Policy.displayName `
    #         -Detail 'What was found and why it matters.' `
    #         -Remediation 'What to do about it.' `
    #         -Status 'Fail'
    # }
}
