# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Get-CARuleReference.ps1

<#
.SYNOPSIS
    Static reference for every rule id (CA-001 .. CA-038): what it checks. Powers
    the Reference tab so any "CA-033"-style callout in the report is explainable.

.DESCRIPTION
    Tenant-independent. Category is one of: Baseline control (a "should exist"
    control on the Baseline Coverage scorecard), Policy issue (something wrong with
    an existing policy), Cross-policy gap (a gap across policies), Directory data
    (needs a Graph directory lookup via -ResolveNames).
#>
function Get-CARuleReference {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $ref = @(
        @('CA-001', 'Security policy in Report-only or Off', 'Policy issue', 'A security-bearing policy that is Off or Report-only is enforcing nothing - flagged as informational to confirm it is intentional.'),
        @('CA-002', 'Include/exclude set overlap (self-negation)', 'Policy issue', 'The same principal is both included and excluded, so the policy can never apply to anyone.'),
        @('CA-003', 'Location exclusion on a security grant', 'Policy issue', 'A policy requiring MFA/managed device excludes locations, so sign-ins from those locations skip the control.'),
        @('CA-004', 'Admins on plain MFA, not authentication strength', 'Policy issue', 'Admin-targeted policy uses "Require MFA" rather than a phishing-resistant authentication strength.'),
        @('CA-005', 'Deprecated grant control (approved app alone)', 'Policy issue', 'Relies on the deprecated approvedApplication (approved client app) grant on its own.'),
        @('CA-006', 'Same principal excluded from many policies', 'Cross-policy gap', 'One group/principal is excluded from several policies - a broad, easily-missed blind spot.'),
        @('CA-007', 'All users / All apps with no MFA or device grant', 'Policy issue', 'A broad policy that requires neither MFA nor a managed device provides little protection.'),
        @('CA-008', 'Legacy authentication not blocked', 'Cross-policy gap', 'No active Conditional Access policy blocks legacy auth, which cannot do MFA and is the top password-spray vector.'),
        @('CA-009', 'Device-code flow not blocked', 'Baseline control', 'No active Conditional Access policy blocks the device-code authentication flow, a growing phishing technique.'),
        @('CA-010', 'Browser missing from MFA client app types', 'Policy issue', 'An MFA policy that omits "browser" leaves browser sign-ins uncovered.'),
        @('CA-011', 'Platform exclusion creates a coverage gap', 'Policy issue', 'A device-platform exclusion leaves those platforms without the control.'),
        @('CA-012', 'Grant operator OR weakens layered controls', 'Policy issue', 'Combining controls with OR means any single one satisfies the policy (weaker than AND).'),
        @('CA-013', 'External principal excluded, no compensating policy', 'Cross-policy gap', 'An external/guest principal is excluded from multiple policies with nothing else covering it.'),
        @('CA-014', 'No session controls on an admin policy', 'Policy issue', 'An admin-targeted policy sets no sign-in frequency or persistent-browser session control.'),
        @('CA-015', 'Break-the-glass group audit', 'Cross-policy gap', 'Reviews the emergency-access (break-glass) group exclusions for consistency and intent.'),
        @('CA-016', 'Exclusion group empty or deleted', 'Directory data', 'A group used as an exclusion is empty or deleted - a stale-exclusion backdoor. Needs -ResolveNames.'),
        @('CA-017', 'Named location may be overly broad', 'Directory data', 'A trusted-location exclusion spans a wide IP range or a whole country. Needs -ResolveNames.'),
        @('CA-018', 'Duplicate or nested exclusion groups', 'Directory data', 'Exclusion groups overlap or nest, widening the exclusion more than intended. Needs -ResolveNames.'),
        @('CA-019', 'Risk-based policies present', 'Baseline control', 'Checks that active policies cover both user risk and sign-in risk (Identity Protection, needs P2).'),
        @('CA-020', 'Test policy left enabled in production', 'Policy issue', 'An enabled policy whose name looks like a test/staging policy (test, dev, uat, pilot, ...).'),
        @('CA-021', 'Session-only policy (no grant controls)', 'Policy issue', 'A policy with only session controls and no grant - confirm that is intentional.'),
        @('CA-022', 'Policy targeting no applications', 'Policy issue', 'A policy that includes no applications never applies to anything.'),
        @('CA-023', 'MFA required for all users', 'Baseline control', 'The most fundamental baseline: an active policy requires MFA for all users on a broad app scope.'),
        @('CA-024', 'MFA required for Azure management', 'Baseline control', 'MFA required for the Azure portal / ARM API / Microsoft admin portals.'),
        @('CA-025', 'MFA required for guest access', 'Baseline control', 'MFA required for guest and external (B2B) users.'),
        @('CA-026', 'Managed device required for admins', 'Baseline control', 'A compliant or hybrid-joined device required for admin directory roles.'),
        @('CA-027', 'Security-info registration secured', 'Baseline control', 'The "Register security information" user action protected with MFA or a trusted location.'),
        @('CA-028', 'Directory sync accounts handled', 'Baseline control', 'Directory Synchronization Accounts excluded from enforcing policies (they cannot do interactive MFA).'),
        @('CA-029', 'MFA required for admin roles', 'Baseline control', 'MFA (or authentication strength) required for admin directory roles.'),
        @('CA-030', 'Authentication transfer flow blocked', 'Baseline control', 'The authentication-transfer flow blocked - defends against Adversary-in-the-Middle session hijack.'),
        @('CA-031', 'Token protection deployed', 'Baseline control', 'Token protection (secure sign-in session) enforced to bind tokens to the device.'),
        @('CA-032', 'Sign-in frequency configured', 'Baseline control', 'A sign-in frequency session control that periodically forces reauthentication.'),
        @('CA-033', 'Persistent browser session restricted', 'Baseline control', 'Persistent browser sessions disabled (mode = never) so cookies do not survive browser close.'),
        @('CA-034', 'Terms of Use enforced', 'Baseline control', 'A Terms of Use acceptance required via a grant control.'),
        @('CA-035', 'MDCA session control used', 'Baseline control', 'Sessions routed through Microsoft Defender for Cloud Apps (Conditional Access App Control).'),
        @('CA-036', 'Exchange ActiveSync blocked', 'Baseline control', 'Exchange ActiveSync (a legacy protocol) blocked.'),
        @('CA-037', 'MFA required for device registration', 'Baseline control', 'MFA required for the register/join device user action, so a stolen password cannot enroll a device.'),
        @('CA-038', 'Managed device required for all users', 'Baseline control', 'Should-Have: a compliant/hybrid-joined device required for all users (blocks BYOD/guests - use with care).')
    )

    return @($ref | ForEach-Object {
        [PSCustomObject][ordered]@{
            'Rule'          = $_[0]
            'Control'       = $_[1]
            'Category'      = $_[2]
            'What it checks' = $_[3]
        }
    })
}
