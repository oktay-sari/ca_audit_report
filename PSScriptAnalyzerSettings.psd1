@{
    # PSScriptAnalyzer settings for the CA Policy Audit Tool.
    # Run:  Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    #
    # Two rules are intentionally excluded (documented in CLAUDE.md):
    #   PSUseSingularNouns          - internal collection helpers read naturally with
    #                                 plural nouns (Get-CAPrincipalList aside, e.g.
    #                                 Test-CAFolderHasPolicies, Format-Locations).
    #   PSUseBOMForUnicodeEncodedFile - scripts are pure ASCII on purpose (no BOM).
    ExcludeRules = @(
        'PSUseSingularNouns'
        'PSUseBOMForUnicodeEncodedFile'
        'PSUseOutputTypeCorrectly'   # Information-level; adding [OutputType] to every helper adds noise, not value
    )
}
