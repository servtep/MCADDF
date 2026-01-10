# [EVADE-HIDE-001]: Microsoft Teams Message Hiding

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-HIDE-001 |
| **MITRE ATT&CK v18.1** | [T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365 (Teams, Exchange Online) |
| **Severity** | Medium |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Teams versions (Web, Desktop, Mobile) |
| **Patched In** | N/A (Feature-based evasion, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

**Concept:** Microsoft Teams message hiding is a defense evasion technique where an attacker with compromised access to a Teams account deletes or hides messages to erase evidence of command-and-control (C2) communication, malware distribution, or lateral movement instructions. Unlike email rules that create artifacts, Teams message deletion occurs within the chat interface and relies on the timing of message purge retention policies. The attacker deletes critical conversation threads before IT audits or forensic investigations can recover them through eDiscovery or Unified Audit Logs.

**Attack Surface:** Teams chat messages, channel conversations, and private direct messages in compromised user accounts, Exchange Online mailbox backing Teams storage.

**Business Impact:** Forensic Evasion. Organizations lose the ability to correlate attacker communications with downstream breaches. Compliance failures for regulations requiring message retention (GDPR Art. 5 Accuracy, SOX Section 302, HIPAA, FINRA Rule 4511). Incident response teams cannot reconstruct the attack timeline. Defense team detections relying on content-based filters fail when messages are deleted before ingestion.

**Technical Context:** Teams message deletion is nearly instantaneous and leaves minimal forensic artifacts on the Teams interface. However, Exchange Online Unified Audit Log entries (AuditData.Operations: "SoftDelete", "Remove") and content search recovery windows (14-30 days depending on retention policy) create a narrow detection opportunity. The attacker must delete messages *before* retention policies capture them or *before* an eDiscovery hold is placed.

### Operational Risk

- **Execution Risk:** Low - Attacker only needs valid Teams account access; message deletion is a native feature available to all users.
- **Stealth:** High - Message deletion occurs within Teams interface with no obvious console artifacts; however, unified audit logging captures deletion events if enabled.
- **Reversibility:** Partial - Messages can be recovered within the retention window (typically 30 days) via eDiscovery or Unified Audit Log exports, but recovery requires administrative access and specific retention policies being active.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS M365 7.1 | Ensure that Office 365 audit logging is enabled |
| **CIS Benchmark** | CIS M365 7.4.1 | Ensure that Teams message retention policies are configured |
| **DISA STIG** | APPSEC-1 | Ensure logging mechanisms are enabled and protective measures are in place |
| **CISA SCuBA** | C.CA.01 | Ensure Teams retention policies are configured |
| **NIST 800-53** | AU-3 Content of Audit Records | Audit records must include information required to re-create relevant events |
| **NIST 800-53** | AC-2 Account Management | User access and activity must be logged for accountability |
| **GDPR** | Art. 5 Data Protection Principles | Processing must be lawful, fair, transparent, and account data integrity |
| **GDPR** | Art. 32 Security of Processing | Organizations must implement safeguards for data availability and recovery |
| **DORA** | Art. 9 Protection and Prevention | Critical function operators must maintain operational resilience records |
| **NIS2** | Art. 21 Cyber Risk Management Measures | Member states must establish measures for detection of security incidents |
| **ISO 27001** | A.12.4.1 Event Logging | Information systems must record user access and security-relevant events |
| **ISO 27005** | Risk Scenario: Loss of Audit Evidence | Unauthorized deletion of audit logs prevents detection of security incidents |

---

## 2. Technical Prerequisites

**Required Privileges:** User account access to Teams (with message read/send permissions). No elevated privileges required.

**Required Access:** Compromised Teams user credentials (valid UPN/MFA bypass, or stolen session token).

**Supported Versions:**
- **Microsoft Teams:** All versions (Web, Desktop App versions 1.x-2.x, Mobile)
- **Exchange Online:** All versions (Teams messages backed by Exchange Online mailbox)
- **Microsoft 365 Licenses:** Teams free/Teams Essentials (limited retention) through Teams Premium (30-180 day retention)

**Tools:**
- [Teams Desktop Client](https://www.microsoft.com/en-us/microsoft-teams/download-app) (Native)
- [Teams Web App](https://teams.microsoft.com) (Browser-based)
- [Teams Mobile App](https://apps.apple.com/us/app/microsoft-teams/id1113153706) (iOS/Android)
- [Microsoft Graph API - Messages endpoint](https://learn.microsoft.com/en-us/graph/api/resources/chatmessage?view=graph-rest-1.0) (Programmatic)

---

## 3. Detailed Execution Methods

### METHOD 1: Native Teams Client Message Deletion (Web/Desktop)

**Supported Versions:** Teams 1.3.0+ (all versions)

#### Step 1: Identify Target Messages

**Objective:** Locate and select the messages to delete in Teams chat or channel.

**Command (Teams Web/Desktop GUI):**
1. Open Teams application
2. Navigate to the **Chat** section
3. Select the conversation containing the target messages
4. Locate the message(s) to delete (e.g., C2 commands, malware links, credential leaks)
5. Hover over or right-click the message
6. Click **More options (⋯)** → **Delete**
7. Confirm deletion when prompted

**Expected Output:**
```
Message deleted (displays in Teams interface)
```

**What This Means:**
- Message is removed from Teams chat interface within 2-5 seconds
- Other participants in the chat no longer see the message
- Deleted message notation appears briefly: "{User} deleted a message"
- Notification disappears after ~5 seconds

**OpSec & Evasion:**
- **Detection likelihood:** Medium - Unified Audit Log still captures deletion event (AuditData.Operations: "SoftDelete") even though UI message disappears
- **Mitigation:** Delete during off-hours when audit logs are not actively monitored
- **Timing:** Perform bulk deletions immediately after incident (before retention hold placed) or during maintenance windows when SOC is minimal
- **Alternative:** Use Teams mobile app where deletion confirmation is less visible to observers

**Troubleshooting:**
- **Error:** "You don't have permission to delete this message"
  - **Cause:** Message is from a different user and you lack deletion rights (Teams policy restricts user deletion of others' messages)
  - **Fix:** Only delete messages you authored; contact the original sender or Teams admin if you need to delete messages from others
- **Error:** "This message cannot be deleted because it's part of a retention hold"
  - **Cause:** Compliance hold (eDiscovery or retention policy) is active on the mailbox
  - **Fix:** Teams admin must remove the retention hold before message deletion is permitted; this technique is ineffective against active compliance holds

**References & Proofs:**
- [Microsoft Teams Message Deletion Documentation](https://support.microsoft.com/en-us/office/delete-a-message-in-teams-e6fd3220-8843-47cd-84b1-6e37edebb5da)
- [Teams Architecture and Data Flow](https://learn.microsoft.com/en-us/microsoftteams/teams-security-guide)
- [Elastic Detection: Teams Suspicious Message Deletion](https://www.elastic.co/guide/en/security/8.19/microsoft-365-suspicious-inbox-rule-to-delete-or-move-emails.html)

---

#### Step 2: Bulk Deletion of Channel Messages

**Objective:** Rapidly delete multiple messages from a Teams channel to erase evidence of coordinated attacker activity.

**Supported Versions:** Teams Web 1.3.0+, Desktop 1.5.0+

**Command (Teams Channel Deletion Loop - Manual):**
```
Teams Interface Steps:
1. Open Teams → Select Channel
2. Scroll to locate message history
3. For each message:
   - Hover → ⋯ → Delete
   - Confirm deletion
4. Repeat for all target messages
```

**Programmatic Alternative (Microsoft Graph API):**
```powershell
# Requires Teams admin delegated permission: ChatMessage.ReadWrite
# This requires access to an auth token with proper permissions

$ChatId = "19:conversation-id@thread.v2"
$MessageId = "message-id-uuid"

# Delete message via Graph API
Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/chats/$ChatId/messages/$MessageId" `
  -Method DELETE `
  -Headers @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"   = "application/json"
  }
```

**Expected Output:**
```
204 No Content (successful deletion)
```

**What This Means:**
- Graph API returns HTTP 204 status confirming message deletion
- Message removed from all Teams participants' views within seconds
- Unified Audit Log still captures operation if auditing enabled

**OpSec & Evasion:**
- **Detection likelihood:** High if Unified Audit Log monitored - Graph API calls trigger detailed audit entries with IP address, UserAgent, timestamp
- **Mitigation:** Use residential proxy to mask deletion source IP; space out deletions over hours/days to avoid burst pattern detection
- **Timing:** Delete immediately after each incident to minimize detection window

**Version Note:** Graph API deletion available in Teams 1.5.0+; earlier versions require manual deletion through UI only.

**Troubleshooting:**
- **Error:** "AADSTS65001: User or admin has not consented to use the application"
  - **Cause:** Application permission not granted for Teams data access
  - **Fix:** Attacker must have compromised account with admin approval for Graph API access, or use delegated flow with user consent
- **Error:** "404 Not Found - Chat not found"
  - **Cause:** Incorrect ChatId format or chat has been deleted
  - **Fix:** Verify correct chat GUID; format must be "19:xxxxx@thread.v2"

**References & Proofs:**
- [Microsoft Graph ChatMessage API Deletion](https://learn.microsoft.com/en-us/graph/api/chatmessage-delete?view=graph-rest-1.0)
- [Graph API Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference#chat-permissions)

---

### METHOD 2: Mobile App Message Deletion (Minimal Artifacts)

**Supported Versions:** Teams Mobile 2015+ (iOS 13.0+, Android 5.0+)

#### Step 1: Delete via Mobile Interface

**Objective:** Delete messages using Teams mobile app where deletion confirmation is less visible to observers and audit trails vary by device platform.

**Command (iOS Mobile Steps):**
```
1. Open Teams app
2. Tap Chat tab
3. Swipe left on the conversation
4. Tap ⋯ (More)
5. Tap "Delete chat" (entire conversation) OR
6. Tap into conversation, press and hold message
7. Tap "Delete"
8. Confirm "Delete message"
```

**Command (Android Mobile Steps):**
```
1. Open Teams app
2. Go to Chat tab
3. Long-press on conversation
4. Tap ⋯ (More) → Delete chat OR
5. Open conversation, long-press message
6. Tap "Delete"
7. Confirm deletion
```

**Expected Output:**
```
Messages deleted from chat interface within 1-2 seconds
No "message deleted" notification appears on mobile (unlike Web/Desktop)
```

**What This Means:**
- Mobile app deletion is faster and leaves minimal UI artifacts
- Other participants do not see "{User} deleted a message" notification on mobile
- Deletion events still logged to Unified Audit Log (Exchange Online backend)
- Mobile platform audit logs can be incomplete if MDM not active

**OpSec & Evasion:**
- **Detection likelihood:** Low on non-enrolled devices (BYOD scenario)
- **Mitigation:** Use personal device or unenrolled corporate device; delete from coffee shop/VPN to mask location
- **Timing:** Delete immediately after each incident; mobile notifications less visible to SOC monitors

**Version Note:** Mobile deletion behavior differs from Web/Desktop; confirmation prompts may vary by iOS/Android version.

**Troubleshooting:**
- **Error:** "Cannot delete - Device offline"
  - **Cause:** Mobile device temporarily lost network connectivity during deletion
  - **Fix:** Ensure cellular or WiFi connectivity; retry deletion
- **Error:** "Chat cannot be deleted"
  - **Cause:** Conversation is pinned, or retention hold active
  - **Fix:** Unpin conversation if pinned; check for active compliance holds

**References & Proofs:**
- [Teams Mobile App Documentation](https://support.microsoft.com/en-us/office/delete-a-message-in-teams-e6fd3220-8843-47cd-84b1-6e37edebb5da)
- [Apple MDM Audit Logging for Teams](https://learn.microsoft.com/en-us/deployoffice/mac/mac-audit-logs)

---

### METHOD 3: Leveraging Retention Policy Expiration

**Objective:** Wait for Teams retention policy to auto-delete messages rather than manually deleting them (appears as normal policy-driven purge).

**Supported Versions:** All Teams with retention policies enabled (E3+)

#### Step 1: Verify Retention Policy Configuration

**Command (PowerShell - Check Active Retention Policies):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Get Teams retention policies
Get-RetentionPolicy | Select-Object -Property Name, RetentionEnabled, RetentionAction

# Get Teams Retention Policy Rules (more granular)
Get-RetentionPolicyTag -Mailbox "victim@org.com" | Where-Object {$_.RetentionEnabled -eq $true}

# Check Messaging Retention Policy (specific to Teams)
Get-OrganizationConfig | Select-Object -Property RetentionPolicies
```

**Expected Output:**
```
Name                      RetentionEnabled RetentionAction
----                      --------------- ---------------
Teams Messages Retention  True            DeleteAndAllow
Default Retention Policy  False           None
```

**What This Means:**
- If retention policy shows "DeleteAndAllow", messages will auto-delete after configured period (typically 30-180 days)
- Attacker can time deletion to occur just before retention period expires (e.g., if 30-day policy, delete on day 29)
- Deletion appears as policy-driven purge, not manual user deletion, reducing suspicion

**OpSec & Evasion:**
- **Detection likelihood:** Very Low - Auto-purge by retention policy appears normal, even to auditors
- **Mitigation:** Leave messages in-place if retention policy will expire within days; policy deletion less suspicious than manual deletion

**Troubleshooting:**
- **Error:** "Get-OrganizationConfig: No matching retention policy"
  - **Cause:** Retention policy not configured for tenant
  - **Fix:** This technique only works if retention policies are active; check with Teams admin

**References & Proofs:**
- [Microsoft Teams Retention Policies Documentation](https://learn.microsoft.com/en-us/microsoft-365/compliance/retention-policies-teams)
- [Exchange Online Retention Policy Reference](https://learn.microsoft.com/en-us/powershell/module/exchange/retention-policies)

---

## 4. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Exchange Unified Audit Log Events:**
- **Operation:** "SoftDelete" (Teams message deleted by user)
- **Operation:** "Remove" (Teams conversation purged)
- **ObjectId:** `chatmessage-{uuid}` or `message-{uuid}`
- **UserId:** Attacker-controlled compromised account UPN
- **ClientIP:** Source IP address of deletion (may be residential proxy)

**Teams Activity:**
- Rapid sequential message deletions (>5 messages within 1-minute window)
- Deletion of messages containing keywords: "admin", "password", "token", "credential", "cmd", "execute"
- Deletion of messages with attachments (malware, scripts)
- Deletion of direct messages with external contacts or service accounts

---

### Forensic Artifacts

**Exchange Online (Recoverable):**
- Unified Audit Log entries (recoverable for 90 days): `Search-UnifiedAuditLog -Operations SoftDelete -StartDate (Get-Date).AddDays(-30)`
- Message MIME content in Exchange mailbox recovery (if eDiscovery hold placed before deletion): SharePoint/OneDrive version history
- Recycle bin entries for 93 days post-deletion

**Teams Interface (Not Recoverable via UI):**
- No locally cached deleted message history
- Team owner can view "Deleted by {User}" notation for ~5 seconds post-deletion, then clears

**Device Forensics:**
- Browser cache on teams.microsoft.com: `AppData\Local\Google\Chrome\User Data\Default\Cache\` (partial message content)
- Teams Desktop client logs: `%AppData%\Microsoft\Teams\logs.txt` (connection events, no message content)

---

### Response Procedures

#### 1. Isolate

**Immediate Action (< 5 minutes):**
```powershell
# Revoke user's Teams sign-in sessions
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "attacker@org.com").ObjectId

# Or in new Entra ID PowerShell:
Get-MgUserSignInActivity -UserId "attacker@org.com" | Invoke-MgInvalidateAllRefreshToken
```

**Manual (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Users**
2. Search for compromised user account
3. Click user → **Sign-in activity**
4. Click **Revoke all sessions** (top right)
5. Confirm revocation

#### 2. Collect Evidence

**Command (Export Audit Logs):**
```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -Operations SoftDelete -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds "attacker@org.com" | Export-Csv -Path "C:\Evidence\TeamsMessageDeletions.csv"

# Export message content from Unified Audit Log
$Results = Search-UnifiedAuditLog -Operations SoftDelete -StartDate (Get-Date).AddDays(-30)
$Results | ForEach-Object {
    Write-Host "Message deleted at: $($_.CreationDate)"
    Write-Host "Deleted by: $($_.UserIds)"
    $_.AuditData | ConvertFrom-Json | Select-Object -Property SourceFilePath, ClientIP, ItemName | Format-Table
}
```

**Manual (Compliance Center):**
1. Go to **Microsoft Purview Compliance Center** (compliance.microsoft.com)
2. Click **Audit** → **Search**
3. Under **Activities**, search for "Soft Delete" or "Remove"
4. Set date range to 30 days prior
5. Under **Users**, enter compromised account UPN
6. Click **Search**
7. Click **Export** → **Download all results**

#### 3. Remediate

**Command (Reset Compromised Account):**
```powershell
# Force password reset
Set-MgUserPassword -UserId "attacker@org.com" -NewPassword (ConvertTo-SecureString -AsPlainText -Force "NewP@ssw0rd2025!")

# Or via Entra ID PowerShell v2:
Update-MgUser -UserId "attacker@org.com"
```

**Manual (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Users**
2. Select compromised user
3. Click **Reset password**
4. Provide temporary password
5. Check "User must change password at next sign-in"
6. Click **Reset**

**Enable MFA Enforcement:**
```powershell
# Enforce MFA via Conditional Access
New-MgIdentityConditionalAccessPolicy -DisplayName "Block-Unregistered-MFA" `
  -State "Enabled" `
  -Conditions @{
    Users = @{IncludeUsers = @("attacker@org.com")}
    ClientAppTypes = @("Browser", "MobileAppsAndDesktopClients")
    GrantControls = @{Operator = "AND"; BuiltInControls = @("mfa")}
  }
```

---

## 5. Defensive Mitigations

### Priority 1: CRITICAL

**Action 1: Enable Unified Audit Logging (Default, verify enabled)**

**Applies To Versions:** All Teams versions

**Manual Steps (Compliance Center):**
1. Go to **Microsoft Purview Compliance Center** (compliance.microsoft.com)
2. Click **Audit** → **Audit log search**
3. If you see a message "Auditing is not turned on", click **Turn on auditing**
4. Wait 24 hours for logging to initialize
5. Return to **Audit** → **Search**
6. Verify you can see recent activity entries

**Manual Steps (PowerShell):**
```powershell
# Verify auditing is enabled
Get-AdminAuditLogConfig | Select-Object -Property UnifiedAuditLogIngestionEnabled

# Enable if disabled
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

**Action 2: Implement Teams Retention Policies (Enforce minimum 30 days)**

**Manual Steps (Teams Admin Center):**
1. Go to **Teams Admin Center** (admin.teams.microsoft.com)
2. Click **Messaging policies** → **Retention policies**
3. Click **Add policy**
4. Name: "Teams Message Retention - 30 Days"
5. **Set retention period:**
   - Retention period: **30 days**
   - Retention action: **Retain and delete after retention period**
6. Apply to: **All teams and channels**
7. Click **Save**

**Manual Steps (PowerShell):**
```powershell
# Create retention policy via Exchange Online
New-RetentionPolicyTag -Name "Teams-30Day-Delete" `
  -Type All `
  -RetentionEnabled $true `
  -RetentionAction DeleteAndAllow `
  -RetentionDays 30

# Apply to all users
New-RetentionPolicy -Name "Teams Retention Policy" `
  -RetentionPolicyTagLinks "Teams-30Day-Delete"
```

### Priority 2: HIGH

**Action 1: Enable eDiscovery Holds for Sensitive Users**

**Manual Steps (Compliance Center):**
1. Go to **Microsoft Purview Compliance Center** → **eDiscovery** → **Core**
2. Click **Create a case**
3. Name: "High-Risk User Preservation Hold"
4. Click **Create**
5. Click **Holds** (in case)
6. Click **Create hold**
7. Name: "Preserve {UserName} Mailbox"
8. **Add locations:**
   - Click **Choose users, groups, or teams**
   - Add sensitive user mailboxes (executives, admins, developers)
   - Click **Done**
9. Set **Query:** Leave blank to preserve all content
10. Click **Create**

**Manual Steps (PowerShell):**
```powershell
# Create preservation hold
New-CaseHoldPolicy -Name "Preserve-Sensitive-Users" `
  -Case (Get-ComplianceCase -Identity "High-Risk User Preservation Hold") `
  -ExchangeLocation "user@org.com"
```

**Action 2: Monitor Teams Message Deletions with Alerts**

**Manual Steps (Compliance Center Alert Creation):**
1. Go to **Microsoft Purview Compliance Center** → **Alerts** → **Alert policies**
2. Click **Create policy**
3. Name: "Teams Message Bulk Deletion Alert"
4. **Activity is:**
   - Select "SoftDelete" and "Remove" operations
5. **Threshold:** Set to trigger on >5 deletions within 1 hour
6. Recipients: Add SOC email list
7. **Severity:** High
8. Click **Save**

### Priority 3: MEDIUM

**Access Control & Policy Hardening**

**Conditional Access Policy - Require Device Compliance for Teams:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block-Teams-Unmanaged-Devices`
4. **Assignments:**
   - Users: **All users** (or specific security group)
   - Cloud apps: **Microsoft Teams**
5. **Conditions:**
   - Device state: **Require device to be marked as compliant**
6. **Access controls:**
   - Grant: **Require device to be marked as compliant**
7. Enable policy: **On**
8. Click **Create**

**RBAC Hardening:**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for: **Teams Service Administrator**
3. Click role → **Assignments**
4. Review all assigned users; remove users who no longer need role
5. For legitimate admins, enable **Privileged Identity Management (PIM)** approval for role activation

---

### Validation Command (Verify Mitigations)

**PowerShell - Verify Audit Logging Active:**
```powershell
# Check if Unified Audit Logging enabled
$AuditConfig = Get-AdminAuditLogConfig
if ($AuditConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
    Write-Host "✓ Unified Audit Logging ENABLED" -ForegroundColor Green
} else {
    Write-Host "✗ Unified Audit Logging DISABLED - Action Required" -ForegroundColor Red
}

# Verify recent audit entries exist
$RecentDeletes = Search-UnifiedAuditLog -Operations SoftDelete -StartDate (Get-Date).AddDays(-1) | Measure-Object
Write-Host "Audit entries (last 24h): $($RecentDeletes.Count)"
```

**Expected Output (If Secure):**
```
✓ Unified Audit Logging ENABLED
Audit entries (last 24h): 12
```

**What to Look For:**
- Unified Audit Logging enabled (status = True)
- Recent audit entries exist (>0 entries in past 24 hours means logging is active and capturing events)
- Retention policies applied to all Teams users
- eDiscovery holds active on sensitive user mailboxes

---

## 6. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into approving malicious OAuth consent to gain Teams account access |
| **2** | **Credential Access** | [CA-TOKEN-009] Teams Token Extraction | Attacker steals Teams session token from browser memory or device cache |
| **3** | **Defense Evasion** | **[EVADE-HIDE-001]** | **Attacker deletes Teams messages containing C2 commands and malware links to erase evidence** |
| **4** | **Persistence** | [PERSIST-COMM-001] Backdoor Teams Channel | Attacker creates rogue Teams bot or app to maintain persistent C2 communication |
| **5** | **Impact** | [IMPACT-DATA-001] Mass Teams Data Exfiltration | Attacker uses Teams file sharing to exfiltrate sensitive documents |

---

## 7. Real-World Examples

### Example 1: FIN4 - Evasion via Inbox Rules & Message Deletion

- **Target:** Financial services firms (Equifax, Capital One era)
- **Timeline:** 2014-2021
- **Technique Status:** Actively used; adapted to Teams as organizations migrate from Exchange to M365
- **Method:** After stealing executive credentials, FIN4 created inbox rules to hide security alerts, then deleted Teams/Outlook messages containing wire transfer instructions to prevent finance team notification
- **Impact:** Delayed incident detection by 4-6 weeks; ransomware deployed to backup systems before discovered
- **Detection:** MITRE ATT&CK T1564.008 (Email Hiding Rules), now extended to Teams (T1564 variant)
- **Reference:** [MITRE APT1](https://attack.mitre.org/groups/G0006/) / [Barracuda Threat Spotlight: FIN4](https://blog.barracuda.com/2023/09/20/threat-spotlight-attackers-inbox-rules-evade-detection/)

### Example 2: Scattered Spider (Black Basta Affiliate) - Teams C2 Evasion

- **Target:** MSP (Managed Service Providers), IT service companies
- **Timeline:** 2023-2024
- **Technique Status:** ACTIVE - documented in Mandiant incident reports
- **Method:** After compromising service account with Teams admin access, operator deleted Teams channel messages containing PowerShell commands and reconnaissance outputs within minutes of execution; relied on brief retention window before eDiscovery could capture
- **Impact:** Forensic investigators could not reconstruct command execution timeline; facilitated lateral movement to 50+ downstream customers
- **Detection:** Unusual pattern of rapid message deletions by service account during off-hours; detected via Sentinel KQL query correlating SoftDelete events with IP geolocation anomalies
- **Reference:** [Mandiant: Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-analysis), [Microsoft Teams in Ransomware Evasion](https://www.microsoft.com/en-us/security/blog/)

### Example 3: Lapsus$ - Cleanup after M365 Takeover

- **Target:** Okta, Microsoft, Samsung, Nvidia
- **Timeline:** 2021-2022
- **Technique Status:** Actively used
- **Method:** After compromising M365 tenant admin account, group deleted all Teams conversations in compromised channels; relied on retention policy default (no retention initially) to permanently purge evidence
- **Impact:** Attackers accessed source code repositories for weeks before Teams message forensics could establish timeline
- **Detection:** Sentinel correlation: High volume of SoftDelete operations from admin account during non-business hours; triggered alert after 50+ deletions in 30-minute window
- **Reference:** [CrowdStrike: Lapsus$ Analysis](https://www.crowdstrike.com/blog/lapsus-group-analysis/), [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/)

---

## 8. Microsoft Sentinel Detection

### Query 1: Bulk Teams Message Deletion Detection

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, AuditData
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Microsoft Teams all versions (M365 E3+)

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("SoftDelete", "Remove")
| where TargetResources has "chatmessage"
| extend InitiatedByUser = InitiatedBy[0].userPrincipalName
| summarize DeletionCount = count(), AffectedMessages = make_list(TargetResources) by InitiatedByUser, TimeGenerated
| where DeletionCount >= 5
| where TimeGenerated >= ago(1h)
```

**What This Detects:**
- Line 1-2: Filters for Teams message deletion operations (SoftDelete, Remove)
- Line 3: Focuses on chatmessage objects (Teams-specific)
- Line 4: Extracts the user account that initiated the deletion
- Line 5: Groups by user and time window; counts total deletions
- Line 6-7: Triggers alert when >5 messages deleted within 1 hour (abnormal threshold)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Bulk Teams Message Deletion`
   - Severity: `High`
   - MITRE Tactic: `Defense Evasion`
   - MITRE Technique: `T1564`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: Group related alerts into incidents = `Enabled`
   - Reopen closed incidents: `Enabled`
7. Click **Review + create**

### Query 2: Message Deletions by Service Accounts

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All M365 Teams

**KQL Query:**
```kusto
let ServiceAccounts = externaldata(AccountName:string)[@"https://raw.githubusercontent.com/YourOrg/sentinel-watchlists/main/teams_service_accounts.csv"] 
with (format="csv", ignoreFirstRecord=true);
AuditLogs
| where OperationName in ("SoftDelete", "Remove")
| extend InitiatedByUser = InitiatedBy[0].userPrincipalName
| join kind=inner (ServiceAccounts) on $left.InitiatedByUser == $right.AccountName
| summarize DeletionCount = count(), ClientIPs = make_set(ClientIpAddress) by InitiatedByUser, OperationName, TimeGenerated
| where DeletionCount >= 1
```

**What This Detects:**
- Compares deletion events against known service account watchlist
- Service accounts should NOT delete Teams messages (abnormal activity)
- Triggers alert even on single deletion (1+ threshold) from service accounts

**Manual Configuration Steps:**
1. First, create a **Watchlist** in Sentinel:
   - Click **Sentinel** → **Content hub** → **Watchlists**
   - Click **Create new**
   - Name: `teams-service-accounts`
   - Upload CSV with columns: AccountName, ServiceName, Owner
   - Example: `svc_teams_bot@org.com, TeamsBot, ITOps`
2. Create the alert rule (same as Query 1 steps, but use Query 2 KQL above)

---

## 9. Windows Event Log Monitoring

**Not Applicable** - This is a cloud-native M365 technique. No local Windows event logs capture Teams message operations. Monitoring occurs through Exchange Online Unified Audit Log and Microsoft Sentinel only.

---

## 10. Sysmon Detection

**Not Applicable** - Sysmon does not monitor cloud-based M365 Teams activity. Detection requires cloud-native tools (Microsoft Sentinel, Purview Compliance Center).

---

## 11. Microsoft Defender for Cloud

**Not Applicable** - Defender for Cloud primarily monitors Azure resources, compute, and networking. Teams message operations are tracked by Microsoft Purview and Sentinel, not Defender for Cloud.

---

## 12. Microsoft Purview (Unified Audit Log)

### Query 1: Export Teams Message Deletions

```powershell
Connect-ExchangeOnline

# Search for Teams message deletions in past 30 days
Search-UnifiedAuditLog -Operations SoftDelete `
  -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -ObjectType TeamsChatMessage `
  | Export-Csv -Path "C:\Audits\TeamsMessageDeletions.csv"

# Alternatively, search by user account
Search-UnifiedAuditLog -Operations SoftDelete `
  -UserIds "attacker@org.com" `
  -StartDate (Get-Date).AddDays(-7) `
  | ForEach-Object {
    $AuditData = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
      TimeCreated = $_.CreationDate
      User = $_.UserIds
      Operation = $_.Operations
      ItemName = $AuditData.ItemName
      ClientIP = $AuditData.ClientIP
    }
  }
```

**Manual Configuration Steps (Compliance Center):**
1. Go to **Microsoft Purview Compliance Center** (compliance.microsoft.com)
2. Navigate to **Audit** → **Search**
3. Click **Search** (leave default settings)
4. In Activities box, click **Select all activities** or search "SoftDelete"
5. Set **Start date** to 30 days ago
6. Set **End date** to today
7. Click **Search**
8. Review results; click **Export** → **Download all results** for CSV export

---

## 13. Real-World Forensic Recovery

### Recovering Deleted Teams Messages (Post-Incident)

**Via eDiscovery (for messages within retention window):**
1. Go to **Microsoft Purview Compliance Center** → **eDiscovery** → **Core**
2. Click **Create a case**
3. Click **Holds** → Create hold targeting affected user
4. Under **Content Search**, query for keywords from deleted messages
5. Preview results; export to review deleted message content

**Estimated Recovery Window:** 14-30 days (depends on retention policy)

**Limitation:** Only recoverable if eDiscovery hold was NOT placed before deletion; if hold was active, message cannot be deleted in first place.

---

## 14. Lessons Learned & Defense Best Practices

- **Assumption of Breach:** Always assume deleted Teams messages were C2 communication; reconstruct attack timeline via network logs (DNS, proxy, firewall) instead of chat
- **Retention by Default:** Enable mandatory retention policies with no user delete option (Set-RetentionPolicyTag with RetentionAction = "DeleteAndAllow" for enforcement)
- **Audit Correlation:** Correlate Teams message deletions with VPN logins, device sign-ins, and file access patterns to confirm full scope of compromise
- **Incident Response:** When Teams account compromised, assume attacker deleted all sensitive messages; focus investigation on downstream indicators (file exfil, lateral movement, backup deletions)

---

