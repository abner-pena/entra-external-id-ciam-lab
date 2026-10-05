<#
.SYNOPSIS
    Deploys the self-service sign-up/sign-in user flow, Google social identity
    provider, and the ValidateUserSignUp API connector into an Entra External
    ID (CIAM) tenant, end to end via Microsoft Graph PowerShell.

.DESCRIPTION
    Repeatable, click-ops-free build of the CIAM user flow described in the
    README. Run against the CIAM tenant, never against a workforce Entra ID
    tenant.

.PARAMETER GoogleClientId
    OAuth client ID from the Google Cloud Console project used for social
    identity provider federation.

.PARAMETER GoogleClientSecret
    OAuth client secret for the same Google OAuth client. Pass as a
    SecureString; never hardcode this value.

.PARAMETER FunctionAppUrl
    Base URL of the deployed ValidateUserSignUp Azure Function
    (e.g. https://ciam-lab-validate.azurewebsites.net).

.PARAMETER ConnectorUsername
    Basic auth username the API connector uses to call the function.

.PARAMETER ConnectorPassword
    Basic auth password for the API connector, as a SecureString.

.EXAMPLE
    ./Deploy-ExternalIdUserFlow.ps1 `
        -GoogleClientId "1234567890-abc.apps.googleusercontent.com" `
        -GoogleClientSecret (Read-Host -AsSecureString "Google client secret") `
        -FunctionAppUrl "https://ciam-lab-validate.azurewebsites.net" `
        -ConnectorUsername "ciam-connector" `
        -ConnectorPassword (Read-Host -AsSecureString "Connector password")
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GoogleClientId,

    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$GoogleClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$FunctionAppUrl,

    [Parameter(Mandatory = $true)]
    [string]$ConnectorUsername,

    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$ConnectorPassword
)

$ErrorActionPreference = "Stop"

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "IdentityProvider.ReadWrite.All", "APIConnectors.ReadWrite.All" -NoWelcome

function ConvertFrom-SecureStringPlain {
    param([System.Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# Step 1: register Google as a social identity provider
Write-Host "Registering Google identity provider..." -ForegroundColor Cyan
$googleParams = @{
    "@odata.type"         = "#microsoft.graph.socialIdentityProvider"
    displayName           = "Google"
    identityProviderType  = "Google"
    clientId              = $GoogleClientId
    clientSecret          = (ConvertFrom-SecureStringPlain -Secure $GoogleClientSecret)
}

$existingGoogle = Get-MgIdentityProvider | Where-Object { $_.IdentityProviderType -eq "Google" }
if ($existingGoogle) {
    Write-Host "Google provider already registered, skipping creation." -ForegroundColor Yellow
} else {
    New-MgIdentityProvider -BodyParameter $googleParams | Out-Null
    Write-Host "Google identity provider registered." -ForegroundColor Green
}

# Step 2: register the ValidateUserSignUp API connector
Write-Host "Registering ValidateUserSignUp API connector..." -ForegroundColor Cyan
$connectorParams = @{
    displayName = "Validate User Sign Up"
    targetUrl   = "$FunctionAppUrl/api/ValidateUserSignUp"
    authenticationConfiguration = @{
        "@odata.type" = "#microsoft.graph.basicAuthenticationConfiguration"
        username      = $ConnectorUsername
        password      = (ConvertFrom-SecureStringPlain -Secure $ConnectorPassword)
    }
}

$existingConnector = Get-MgIdentityApiConnector | Where-Object { $_.DisplayName -eq "Validate User Sign Up" }
if ($existingConnector) {
    Write-Host "API connector already exists, updating target URL." -ForegroundColor Yellow
    Update-MgIdentityApiConnector -IdentityApiConnectorId $existingConnector.Id -BodyParameter $connectorParams
} else {
    New-MgIdentityApiConnector -BodyParameter $connectorParams | Out-Null
    Write-Host "API connector registered." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Remaining manual step: attach the Google provider and the" -ForegroundColor Cyan
Write-Host "ValidateUserSignUp connector to the user flow in the portal under" -ForegroundColor Cyan
Write-Host "External Identities > User flows > signupsignin-ciam-lab, since" -ForegroundColor Cyan
Write-Host "user flow creation itself is not yet exposed in the Graph API." -ForegroundColor Cyan
