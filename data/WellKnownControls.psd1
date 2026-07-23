# Well-known Conditional Access control identifiers
# Grouped by context to avoid key collisions (PowerShell hashtables are case-insensitive)
@{
    GrantControl = @{
        'mfa'                  = 'Require MFA'
        'compliantDevice'      = 'Require compliant device'
        'domainJoinedDevice'   = 'Require Hybrid Entra joined device'
        'approvedApplication'  = 'Require approved client app'
        'compliantApplication' = 'Require app protection policy'
        'passwordChange'       = 'Require password change'
        'block'                = 'Block access'
        'unknownFutureValue'   = 'Unknown future value'
    }

    GrantOperator = @{
        'OR'  = 'Require ONE of the selected controls'
        'AND' = 'Require ALL selected controls'
    }

    ClientAppType = @{
        'all'                          = 'All client apps'
        'browser'                      = 'Browser'
        'mobileAppsAndDesktopClients'  = 'Mobile apps and desktop clients'
        'exchangeActiveSync'           = 'Exchange ActiveSync'
        'other'                        = 'Other clients (legacy auth)'
    }

    PolicyState = @{
        'enabled'                           = 'On'
        'disabled'                          = 'Off'
        'enabledForReportingButNotEnforced' = 'Report-only'
    }

    CloudAppSecurity = @{
        'mcasConfigured'  = 'Use Defender for Cloud Apps (custom policy)'
        'monitorOnly'     = 'Monitor only'
        'blockDownloads'  = 'Block downloads'
    }

    SignInFrequencyInterval = @{
        'timeBased'  = 'Time-based'
        'everyTime'  = 'Every time'
    }

    PersistentBrowserMode = @{
        'always' = 'Always persistent'
        'never'  = 'Never persistent'
    }

    FilterMode = @{
        'include' = 'Include filtered devices'
        'exclude' = 'Exclude filtered devices'
    }

    GuestOrExternalUserType = @{
        'internalGuest'          = 'Internal guest'
        'b2bCollaborationGuest'  = 'B2B collaboration guest'
        'b2bCollaborationMember' = 'B2B collaboration member'
        'b2bDirectConnectUser'   = 'B2B direct connect user'
        'otherExternalUser'      = 'Other external user'
        'serviceProvider'        = 'Service provider'
    }

    ExternalTenantMembership = @{
        'all'        = 'All external tenants'
        'enumerated' = 'Specific external tenants'
    }

    AuthenticationStrength = @{
        '00000000-0000-0000-0000-000000000002' = 'Multifactor authentication'
        '00000000-0000-0000-0000-000000000003' = 'Passwordless MFA'
        '00000000-0000-0000-0000-000000000004' = 'Phishing-resistant MFA'
    }
}
