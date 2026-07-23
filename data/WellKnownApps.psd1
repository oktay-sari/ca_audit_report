# Well-known Microsoft application IDs for Conditional Access
# Maps application identifiers (string constants, GUIDs, and URNs) to display names
# Source: https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
@{
    # ---------------------------------------------------------------
    # Graph API string constants (used in includeApplications / excludeApplications)
    # ---------------------------------------------------------------
    'All'                                  = 'All cloud apps'
    'None'                                 = 'None'
    'Office365'                            = 'Office 365 (suite)'
    'MicrosoftAdminPortals'                = 'Microsoft Admin Portals'

    # ---------------------------------------------------------------
    # User action URNs (used in includeUserActions)
    # ---------------------------------------------------------------
    'urn:user:registersecurityinfo'        = 'Register security information'
    'urn:user:registerdevice'              = 'Register or join devices'

    # ---------------------------------------------------------------
    # First-party Microsoft applications (appId GUIDs)
    # ---------------------------------------------------------------

    # --- Office 365 core services ---
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
    '66a88757-258c-4c72-893c-3e8bed4d6899' = 'Office 365 Search Service'

    # --- Microsoft Graph and directory services ---
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0000-c000-000000000000' = 'Windows Azure Active Directory (legacy Graph)'

    # --- Azure and management ---
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'

    # --- Microsoft Teams ---
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'
    'cf53fce8-def6-4aeb-8d30-b158e7b1cf83' = 'Microsoft Teams Services'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams (new)'
    '5e3ce6c0-2b1f-4285-8d4b-75ee78787346' = 'Microsoft Teams Web Client'

    # --- Microsoft Intune ---
    '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment'
    'c161e42e-d4df-4a3d-9b42-e7a3c31f59d4' = 'Microsoft Intune API'

    # --- Power Platform ---
    'a672d62c-fc7b-4e81-a576-e60dc46e951d' = 'Microsoft Power BI Service'
    '871c010f-5e61-4fb1-83ac-98610a7e9110' = 'Microsoft Power BI'
    '7df0a125-d3be-4c96-aa54-591f83ff541c' = 'Microsoft Flow (Power Automate)'
    '475226c6-020e-4fb2-8571-c63571b7bfb7' = 'Microsoft Power Apps'
    '6cb51f25-5eb3-4b6b-8092-6102a0260a5c' = 'Microsoft Power Apps Runtime Service'

    # --- Dynamics 365 ---
    '00000007-0000-0000-c000-000000000000' = 'Dynamics CRM Online (Dataverse)'
    '2db8765a-0ab4-4cf0-8491-4d72a43d8dba' = 'Dynamics 365 Business Central'

    # --- Office Online and apps ---
    '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7' = 'Office Online (Office.com)'
    '67ad5377-2d78-4ac2-a867-6a3c3826ca8f' = 'Office Online Client AAD - Augmentation Loop'
    '93d53678-613d-4013-afc1-62e9e444a0a5' = 'Office on the Web'
    '2abdc806-e091-4495-9b10-b04d93c3f040' = 'Office Hive'
    'c9a559d2-7aab-4f13-a6ed-e7e9c52aec87' = 'Microsoft Forms'
    '09abbdfd-ed23-44ee-a2d9-a627aa1c90f3' = 'Microsoft Planner'
    '66c37151-0987-4bc9-9e80-b97bfe6c221a' = 'Microsoft To-Do'
    'cf36b471-5b44-428c-9ce7-313bf84528de' = 'Microsoft Stream'
    '57fb890c-0dab-48a5-b458-275463025e4f' = 'Microsoft Stream Portal'
    'c1c74fed-04c9-4704-80dc-9f79a2e515cb' = 'Cortana'

    # --- Yammer / Viva Engage ---
    '00000005-0000-0ff1-ce00-000000000000' = 'Yammer (Viva Engage)'

    # --- Skype for Business ---
    '00000004-0000-0ff1-ce00-000000000000' = 'Skype for Business Online'

    # --- DevOps and developer tools ---
    '499b84ac-1321-427f-aa17-267ca6975798' = 'Azure DevOps'

    # --- Security and compliance ---
    '80ccca67-54bd-44ab-8625-4b79c4dc7775' = 'Microsoft 365 Compliance Center'
    '65d91a3d-ab74-42e6-8a2f-0add61688c74' = 'Microsoft 365 Security & Compliance Center'
    '33e01921-4d64-4f8c-a055-5bdaffd5e33d' = 'Microsoft 365 Security Center'

    # --- Azure Virtual Desktop / Windows 365 ---
    '9cdead84-a403-4b54-93c0-b2b5426fd0c7' = 'Azure Virtual Desktop (classic)'
    'a4a365df-50f1-4397-bc59-1a1564b8bb9c' = 'Azure Virtual Desktop'
    '0af06dc6-e4b5-4f28-818e-e78e62d137a5' = 'Windows 365'

    # --- Azure Key Vault ---
    'cfa8b339-82a2-471a-a3c9-0fc0be7a4093' = 'Azure Key Vault'

    # --- Other first-party Microsoft services ---
    '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'
    '00000009-0000-0000-c000-000000000000' = 'Power BI Service'
    '48af08dc-f6d2-435f-b2a7-069abd99c086' = 'Connectors'
    'fc780465-2017-40d4-a0c5-307022471b92' = 'My Apps'
    '0000000c-0000-0000-c000-000000000000' = 'Microsoft App Access Panel'
    'e9f49c6b-5ce5-44c8-925d-015017e9f7ad' = 'Azure Data Lake'
    '73c2949e-da2d-457a-9607-fcc665198967' = 'Azure Storage'
    'e406a681-f3d4-42a8-90b6-c2b029497af1' = 'Azure SQL Database'
    '18fbca16-2224-45f6-85b0-f7bf2b39b3f3' = 'Microsoft Docs'
    '28b567f6-162c-4f54-99a0-6887f387bbcc' = 'Microsoft Defender for Cloud Apps'
    '3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7' = 'Microsoft Defender for Endpoint'
    'dd340f98-03ef-4462-8b5c-a3c23c406b2a' = 'Microsoft Defender XDR'
    '27922004-5251-4030-b22d-91ecd9a37ea4' = 'Outlook Mobile'
    'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Graph Explorer'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft To-Do Web App'
    'c1f33bc0-bdb4-4248-ba9b-096807ddb43e' = 'Universal Print'
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Authentication Broker'
    '4765445b-32c6-49b0-83e6-1d93765276ca' = 'Microsoft eCDN (Teams Live Events)'
    '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management APIs'
    '94c63fef-13a3-47bc-8074-75af8c65887a' = 'ACOM Azure Website'
    '5572c4c0-d078-44ce-b81c-6cbf8d3ed39e' = 'Viva Learning'
    'a0c73c16-a7e3-4564-9a95-2bdf47383716' = 'Exchange Online Protection'
    'd73f4b35-55c9-48c7-8b10-651f6f2acb2e' = 'Microsoft Substrate Management'
    '80f0a025-7643-4b87-93fa-5e2ab5ff6301' = 'Microsoft Copilot'
    'fb8d773d-7ef7-4a5b-8e68-726cb651492b' = 'Microsoft Copilot Studio'
}
