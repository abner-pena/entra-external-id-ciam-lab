# Entra External ID CIAM Lab

**IAM & Cloud Security Engineering** · Microsoft Entra External ID · Customer Identity and Access Management (CIAM) · Self-Service User Flows · API Connectors · Conditional Access for External Users · KQL

**Author:** Abner Peña, IAM & Cloud Security Engineer

Every lab in this portfolio so far secures workforce identity: employees, admins, service principals. This one secures the other half of the identity problem that most IAM job postings also ask for: the customer. Any product with a sign-up button has a customer identity system behind it, and that system is attacked differently than a workforce tenant. There is no help desk to call when a customer's account is compromised, the attacker can create as many accounts as a form will allow, and the business wants friction near zero while security wants it near total. Customer Identity and Access Management (CIAM) is the discipline that resolves that tension.

This lab builds a working CIAM tenant on **Microsoft Entra External ID**: self-service sign-up and sign-in, social identity provider federation, a custom API connector that rejects disposable email domains and enriches the user object before the account is created, risk-based Conditional Access scoped to external users instead of employees, and KQL hunting queries tuned for the attack patterns that target public sign-up forms instead of corporate sign-in pages.

---

## Why this matters

| Workforce identity (the rest of this portfolio) | Customer identity (this lab) |
|---|---|
| Identities are provisioned by HR/IT, finite and known | Identities are self-registered by strangers, unbounded |
| Help desk can verify and reset | No help desk; recovery must be self-service and still secure |
| MFA adoption can be mandated | MFA adoption has to be sold with UX, or customers churn |
| Attack volume is bounded by headcount | Attack volume is bounded only by how fast a bot can POST a form |
| Governance question: who still needs this access? | Governance question: is this signup a real human, once? |

A company running both an Entra ID workforce tenant and a customer-facing product almost always needs an engineer who can speak to both. This lab is the second half of that pairing, built on the same Microsoft identity platform so the skills transfer directly: Graph API, Conditional Access, KQL, and PowerShell all carry over, just pointed at a different population of users.

---

## What this lab builds

1. **A self-service sign-up and sign-in user flow.** Local account creation with email verification, configurable attribute collection (display name, country, marketing consent), and token claims scoped to exactly what the relying application needs, nothing more.
2. **Social identity provider federation.** Google used as the example external IdP, so a customer can sign up with an existing account instead of creating a new password the business then has to protect.
3. **A custom API connector.** An Azure Function that Entra External ID calls mid-signup, before the account is created, to block disposable email domains, check the email against a denylist, and inject a `riskTier` custom claim the relying app and Conditional Access can both read.
4. **Risk-based Conditional Access scoped to the external tenant.** Unlike every other Conditional Access lab in this portfolio, this policy set targets the customer population: block sign-up from anonymized IP ranges, require step-up verification on elevated user risk, and never assume the device is compliant since nobody manages it.
5. **KQL detections tuned for public sign-up abuse.** Mass account creation from one IP or ASN, disposable-domain bypass attempts, and credential-stuffing patterns against the sign-in endpoint, which look nothing like the detections written for a workforce tenant because the baseline of "normal" is completely different.

---

## Architecture

```
Customer browser
      |
      v
Relying application (web or mobile)
      |
      v
Entra External ID tenant  <-- isolated from the Entra ID workforce tenant
      |
      |-- Self-service sign-up/sign-in user flow
      |       |-- Local account (email + password)
      |       |-- Google federation (OIDC)
      |       |-- API connector (pre sign-up submit) --> Azure Function
      |                                                      |-- Disposable domain check
      |                                                      |-- Denylist check
      |                                                      |-- riskTier claim injection
      |
      |-- Conditional Access (external user scope)
      |       |-- Block anonymized IP sign-up
      |       |-- Step-up MFA on elevated user risk
      |       |-- Session controls, no device compliance assumption
      |
      v
Log Analytics (Entra External ID sign-in + audit logs)
      |
      v
KQL detections: mass signup, disposable domain bypass, credential stuffing
```

---

## Step 1: Stand up the Entra External ID tenant

External ID for customers runs in its own tenant, separate from a workforce Entra ID tenant. Create it from Entra ID > Manage tenants > Create > Customer identity and access management (CIAM), or via the Azure CLI:

```bash
az login
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.AzureActiveDirectory/ciamDirectories/{directoryName}?api-version=2023-05-17-preview" \
  --body '{
    "location": "United States",
    "sku": { "name": "Standard", "tier": "A0" },
    "properties": { "createTenantProperties": { "displayName": "Abner Pena CIAM Lab", "countryCode": "US" } }
  }'
```

Register a relying application in the new tenant (App registrations > New registration), note the Application (client) ID, and add a redirect URI for the test app.

---

## Step 2: Build the self-service user flow

`user-flows/signup-signin-userflow-config.json` is the attribute collection and token claims configuration used when creating the flow under **External Identities > User flows > New user flow**. It collects display name, country, and a marketing-consent checkbox at sign-up, and returns `displayName`, `country`, `emails`, `riskTier`, and `newUser` as token claims, keeping the token payload minimal on purpose: a CIAM token that leaks shouldn't hand an attacker more than it has to.

Enable **Email with password** as the local account method and add the Google identity provider for federation.

---

## Step 3: Federate Google as a social identity provider

Create an OAuth client in Google Cloud Console, then register it in the tenant:

```powershell
Connect-MgGraph -Scopes "IdentityProvider.ReadWrite.All"

$params = @{
    "@odata.type" = "#microsoft.graph.socialIdentityProvider"
    displayName   = "Google"
    identityProviderType = "Google"
    clientId      = "<google-oauth-client-id>"
    clientSecret  = "<google-oauth-client-secret>"
}

New-MgIdentityProvider -BodyParameter $params
```

Add the Google provider to the user flow's identity provider list so it shows up on the sign-up/sign-in page alongside the local account option.

---

## Step 4: Deploy the API connector

The API connector is the enforcement point that runs **before** Entra External ID creates the account. `api-connectors/ValidateUserSignUp/index.js` is an Azure Function that:

- Rejects sign-up if the email domain matches a disposable-email-provider list (`mailinator.com`, `10minutemail.com`, and similar)
- Rejects sign-up if the email matches an internal denylist (abuse reports, prior ban)
- Computes a `riskTier` (`low`, `medium`, `high`) from signal quality and returns it as a claim the relying app and Conditional Access can both evaluate downstream
- Returns a validation error with a user-facing message when blocking, so the signup form shows something better than a generic failure

Deploy it and register it as an API connector pointed at the "Before creating the user" step:

```powershell
# deploy the function app first (func azure functionapp publish <app-name>), then register the connector
Connect-MgGraph -Scopes "IdentityProvider.ReadWrite.All", "APIConnectors.ReadWrite.All"

$connector = @{
    displayName  = "Validate User Sign Up"
    targetUrl    = "https://<function-app>.azurewebsites.net/api/ValidateUserSignUp"
    authenticationConfiguration = @{
        "@odata.type" = "#microsoft.graph.basicAuthenticationConfiguration"
        username      = "<connector-auth-username>"
        password      = "<connector-auth-password>"
    }
}

New-MgIdentityApiConnector -BodyParameter $connector
```

`scripts/Deploy-ExternalIdUserFlow.ps1` runs steps 2 through 4 end to end via Graph PowerShell so the whole build is repeatable instead of click-ops.

---

## Step 5: Scope Conditional Access to the external population

Every other Conditional Access policy in this portfolio assumes a managed device and a known employee. None of that holds here, so `policies/ca-external-risk-based-access.json` is built around what is actually knowable about an anonymous customer: network reputation and behavioral risk.

| Control | Why it's different for CIAM |
|---|---|
| Block sign-up and sign-in from anonymized IP ranges (Tor, known VPN-for-abuse ranges) | Bot farms and fraud rings hide behind anonymizers; real customers rarely need one to sign up |
| Require step-up verification (email OTP) when Identity Protection flags elevated user risk | There is no admin to call and confirm identity, so the system has to self-serve the challenge |
| No device compliance or managed-device requirement | The business does not and cannot manage customer devices |
| Session sign-in frequency left permissive on low-risk sessions | Forcing frequent re-auth on customers increases churn more than it reduces risk; save friction for actual risk signals |

Deploy with the same Graph PowerShell pattern used in `conditional-access-as-code`:

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
$policy = Get-Content ./policies/ca-external-risk-based-access.json -Raw | ConvertFrom-Json
New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

---

## Step 6: Hunt for sign-up and sign-in abuse

Stream the External ID tenant's sign-in and audit logs to a Log Analytics workspace (Entra ID > Diagnostic settings), then run:

| File | Detects |
|---|---|
| `kql/fraudulent-signup-detection.kql` | More than 15 account creations from a single IP or ASN inside one hour, the signature of scripted mass registration |
| `kql/external-user-anomalous-signin.kql` | A customer account signing in from two countries within an implausible travel window, or a sudden spike in failed password attempts against one account consistent with credential stuffing |

`scripts/Audit-ExternalUserRiskySignins.ps1` pulls Identity Protection risk detections scoped to the external tenant's risky users and exports them for the fraud or trust-and-safety team, since in a CIAM context the consumer of this data often isn't a SOC, it's a fraud analyst.

---

## Key takeaways

- CIAM and workforce IAM run on the same Microsoft identity platform primitives, Conditional Access, Graph API, user flows, and KQL, but every control has to be reconsidered because the population, the threat model, and the business tolerance for friction are all different.
- The API connector is the real enforcement point in self-service signup. Anything that should block or shape account creation belongs there, before the account exists, not as cleanup after.
- Scoping Conditional Access to an anonymous customer population means leaning on network reputation and behavioral risk, because device and identity assurance signals that work for employees don't exist here.
- Detection content has to be rebuilt for the CIAM population too. A query tuned to catch one compromised employee account looks nothing like a query tuned to catch a bot farm registering accounts at scale.

---

## Technologies used

Microsoft Entra External ID, Microsoft Graph PowerShell SDK, Azure Functions (Node.js), Conditional Access, Microsoft Entra ID Protection, Google Identity Platform (OIDC), Azure CLI, KQL, Log Analytics.

See `SETUP.md` for environment prerequisites.
