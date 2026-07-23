# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path modules/Import-CAGraph.ps1

<#
.SYNOPSIS
    Fetches Conditional Access policies from a live tenant via Microsoft Graph.

.DESCRIPTION
    READ-ONLY. Uses the shared read-only Graph connection (Connect-CAGraph,
    which requests only *.Read.All scopes) and issues only GET requests. The tool
    never creates, modifies, or deletes anything in the tenant.

    Policies are fetched (paged) and passed through the same ConvertTo-CAPolicySet
    normalization as the file import path, so file and tenant sources never drift.
#>

function Get-CAPolicySetFromGraph {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param([string] $ExcludePattern = '')

    if (-not (Connect-CAGraph)) {
        throw "Could not connect to Microsoft Graph. Install Microsoft.Graph.Authentication and sign in, or use -Source Files with exported JSON."
    }

    Write-Host 'Fetching Conditional Access policies from the tenant (read-only)...' -ForegroundColor Cyan
    $rawPolicies = @()
    $uri = 'v1.0/identity/conditionalAccess/policies'
    try {
        do {
            # GET only. Fetch as raw JSON and ConvertFrom-Json so the objects are
            # PSCustomObjects identical to the file path (Invoke-MgGraphRequest's
            # object output returns hashtables, which the shared cleaner mangles).
            # The @odata.nextLink is a full URL that Invoke-MgGraphRequest accepts.
            $json = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Json -ErrorAction Stop
            $resp = $json | ConvertFrom-Json
            $rawPolicies += @($resp.value)
            $uri = $resp.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        throw "Failed to read Conditional Access policies from Graph: $($_.Exception.Message). Ensure the signed-in account is consented to Policy.Read.All."
    }

    Write-Host "Fetched $(@($rawPolicies).Count) policy/policies from the tenant." -ForegroundColor Cyan
    return ConvertTo-CAPolicySet -RawPolicies $rawPolicies -ExcludePattern $ExcludePattern -SourceLabel 'the tenant'
}

<#
.SYNOPSIS
    Returns the tenant's organization display name (read-only), for the report
    header. Falls back to the tenant id, then a generic label.
#>
function Get-CATenantName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $json = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=displayName' -OutputType Json -ErrorAction Stop
        $org = $json | ConvertFrom-Json
        $name = @($org.value)[0].displayName
        if ($name) { return $name }
    }
    catch { $null = $_ }

    try {
        $ctx = Get-MgContext
        if ($ctx -and $ctx.TenantId) { return "tenant $($ctx.TenantId)" }
    }
    catch { $null = $_ }

    return 'Microsoft Entra tenant'
}
