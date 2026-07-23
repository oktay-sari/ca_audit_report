# Rule: CA-020 - Test policy left enabled in production
# Type: per-policy | Tier: static

function Test-CARule-020 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.state -ne 'enabled') { return }

    $name = $Policy.displayName
    $matchedPattern = Test-CATestPolicyName $name

    if ($matchedPattern) {
        return New-CAFinding -Id 'CA-020' `
            -Name 'Test policy left enabled in production' `
            -Severity 'Medium' `
            -Requires 'static' `
            -PolicyName $Policy.displayName `
            -Detail "This policy name contains '$matchedPattern' but state is On. Test policies left enabled in production may have unintended effects (overly permissive grants, unscoped blocks, or conflicts with production policies)." `
            -Remediation 'Review the policy. If it is a test: disable or delete it. If it is production despite the name: rename to remove the test keyword.' `
            -Status 'Fail'
    }
}
