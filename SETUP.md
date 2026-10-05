# Setup

Environment prerequisites for the Entra External ID CIAM lab. This lab stands up its own tenant, so it does not touch or depend on any workforce Entra ID tenant used in the other labs in this portfolio.

## Prerequisites

- An Azure subscription with permission to create a new Microsoft Entra External ID (CIAM) tenant. This is a separate tenant type from a standard Entra ID workforce tenant, created from Entra ID > Manage tenants > Create, or via `az rest` as shown in the README.
- Global Administrator in the new External ID tenant (you are the first user created when the tenant is provisioned).
- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- Azure Functions Core Tools, for deploying the API connector: `npm install -g azure-functions-core-tools@4`
- Node.js 18+ for the API connector function app.
- A Google Cloud project with an OAuth 2.0 client ID and secret, for the social identity provider federation step. Create one at console.cloud.google.com > APIs & Services > Credentials > Create OAuth client ID > Web application, with the authorized redirect URI set to `https://<tenant-subdomain>.ciamlogin.com/<tenant-subdomain>.onmicrosoft.com/oauth2/authresp`.
- A test relying application, or use the built-in sample at `https://<tenant-subdomain>.ciamlogin.com` to exercise the sign-up flow without building a front end.

## Required Graph permissions

Grant these as application or delegated permissions depending on whether scripts run interactively or as a service principal:

- `IdentityProvider.ReadWrite.All`
- `APIConnectors.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `IdentityRiskyUser.Read.All`
- `AuditLog.Read.All`

## Cost notes

Entra External ID bills per monthly active user (MAU) beyond a free tier of 50,000 MAU, which comfortably covers lab-scale testing at no cost. Azure Functions on the Consumption plan bills per execution; a handful of test signups during the lab build stays within the free monthly grant. No cost beyond the Azure subscription's existing resources is required to complete this lab.

## Isolation note

Keep this tenant separate from any workforce tenant. Do not federate the API connector's authentication credentials, the Google OAuth client, or the Conditional Access policies in `policies/` into a workforce tenant. The two identity systems in this portfolio, workforce and customer, are deliberately kept apart, which is also the correct production pattern.
