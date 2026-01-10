# [COLLECT-METADATA-001]: SharePoint Metadata Collection

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-METADATA-001 |
| **Technique Name** | SharePoint Metadata Collection |
| **MITRE ATT&CK v18.1** | [T1123 – Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection (TA0009) |
| **Platforms** | Microsoft 365, SharePoint Online, OneDrive for Business |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | SharePoint Online (Microsoft 365), OneDrive for Business, Microsoft 365 E3/E5 tenants |
| **Patched In** | Not applicable – relies on legitimate SharePoint/Graph APIs and user permissions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers **systematic collection of SharePoint Online and OneDrive metadata** (site, library, folder, file and list attributes) using native APIs such as **PnP.PowerShell**, **Microsoft Graph**, and CSOM. Rather than downloading file content, an adversary harvests rich metadata (paths, authors, timestamps, sensitivity labels, sharing links, versions, etc.) to build a **high‑fidelity data catalog** of the tenant. This catalog guides subsequent targeted exfiltration and supports impact analysis (identifying highly sensitive repositories).
- **Attack Surface:** SharePoint Online sites, document libraries, lists, OneDrive for Business, Microsoft Graph API, PnP.PowerShell from any Windows or Linux management host with network access to Microsoft 365.
- **Business Impact:** **High confidentiality and compliance impact.** Complete metadata mapping exposes where sensitive information lives, who owns it, how it is shared, and which repositories are suitable for ransomware or exfiltration. Metadata alone can violate confidentiality (e.g., project names, deal codes, personal identifiers) even without file content.
- **Technical Context:** Collection can be **fully automated** via scripts or cloud workloads (Azure Automation, containers, DevOps agents). With appropriate permissions (SharePoint Administrator, Sites.Selected, or broad Graph scopes), a full‑tenant metadata crawl can complete **within hours** and is often misinterpreted as legitimate admin reporting. Primary indicators are **unusual Graph API volume**, **large exports to CSV/JSON**, and **broad SharePoint file access events** in the unified audit log.

### Operational Risk
- **Execution Risk:** Medium – Uses supported APIs and admin‑like tooling. Risk increases if adversary misconfigures throttling and triggers rate‑limit or security monitoring alerts.
- **Stealth:** Medium to High – Looks similar to legitimate reporting, migration, or backup activities. With service principals and scheduled jobs, activity can blend into background administrative noise.
- **Reversibility:** Low – Once metadata is exported outside the tenant, there is **no technical way to revoke knowledge** of site structure, sensitive library locations, or file identifiers.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | CIS O365 3.1, 3.4 | Restrict high‑privilege accounts and monitor access to SharePoint/OneDrive data and audit logs. |
| **DISA STIG (O365/SharePoint)** | O365-SP-000020 | Ensure auditing is enabled and access to sensitive sites is monitored and restricted. |
| **CISA SCuBA** | M365-SPO-LOG-1 | Enable and retain SharePoint Online activity logging for security investigations. |
| **NIST 800-53** | AC-6, AU-6, AU-12 | Least privilege for data access; audit review and analysis; centralized logging of data access. |
| **GDPR** | Art. 5, Art. 32 | Data minimization and integrity/confidentiality of personal data; appropriate security logging and monitoring. |
| **DORA** | Art. 9, Art. 11 | Logging, monitoring, and ICT security controls for critical data repositories. |
| **NIS2** | Art. 21 | Technical and organizational measures for risk management and incident handling for critical services. |
| **ISO 27001** | A.8.12, A.8.16, A.12.4 | Protection of data at rest/in use; monitoring and logging of system activities. |
| **ISO 27005** | Data Discovery Risk Scenario | Exposure of data‑location metadata enabling targeted exfiltration of sensitive repositories. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Minimum: Read access to targeted SharePoint sites/libraries/lists.
  - Typical attacker misuse: **SharePoint Administrator**, **Global Reader**, or an **application registration** with Sites.Read.All, Sites.Selected, or Files.Read.All.
- **Required Access:**
  - HTTPS access to `*.sharepoint.com`, `graph.microsoft.com`, and `login.microsoftonline.com` from attacker host.

**Supported Versions:**
- **SharePoint:** SharePoint Online (all modern tenants).
- **OneDrive:** OneDrive for Business (Microsoft 365).
- **PowerShell:**
  - Windows PowerShell 5.1 with PnP.PowerShell module.
  - PowerShell 7.x on Windows/Linux/macOS with PnP.PowerShell / Microsoft.Graph modules.
- **Other Requirements:**
  - Modern authentication (OAuth 2.0, device code, or certificate‑based app auth).
  - For app‑only collection: Entra ID app registration and admin consent.

- **Tools:**
  - [PnP.PowerShell](https://pnp.github.io/powershell/) (tenant/site‑level metadata enumeration).
  - [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/graph/powershell/get-started) (low‑level SharePoint/Graph enumeration).
  - [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) (manual reconnaissance and query prototyping).

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if PnP.PowerShell is installed
Get-Module -ListAvailable PnP.PowerShell

# Install if missing (requires admin on the management host)
Install-Module PnP.PowerShell -Scope CurrentUser -Force

# Test connectivity and consent to a target site
$SiteUrl = "https://<tenant>.sharepoint.com/sites/<target-site>"
Connect-PnPOnline -Url $SiteUrl -Interactive

# Enumerate lists and libraries to confirm access
Get-PnPList | Select Title, BaseType, Hidden, ItemCount
```

**What to Look For:**
- Ability to authenticate successfully using an interactive or device‑code flow.
- Presence of **high‑value lists/libraries** such as `Documents`, `Records`, `HR`, `Finance`, `Legal` with significant `ItemCount`.

**Version Note:**
- On older systems with classic **SharePointPnPPowerShellOnline**, commands are similar but module name differs. Migration to **PnP.PowerShell** is strongly recommended.

**Command (Legacy Windows PowerShell – classic module):**
```powershell
Install-Module SharePointPnPPowerShellOnline -Scope CurrentUser
Connect-PnPOnline -Url $SiteUrl -UseWebLogin
Get-PnPList | Select Title, BaseType, Hidden, ItemCount
```

**Command (PowerShell 7+ with PnP.PowerShell):**
```powershell
Install-Module PnP.PowerShell -Scope CurrentUser -Force
Connect-PnPOnline -Url $SiteUrl -Interactive
Get-PnPList | Select Title, BaseTemplate, ItemCount
```

### Microsoft Graph / CLI Reconnaissance

```bash
# Using Microsoft Graph CLI (mgc)
mgc login --scopes "Sites.Read.All Files.Read.All"

# List SharePoint sites the account can see
mgc sites list --search "SharePoint"

# Enumerate lists for a given site
mgc sites list --site-id <site-id>
mgc sites list list --site-id <site-id>
```

**What to Look For:**
- Sites with **large document libraries** and business‑critical names (e.g., `M&A`, `R&D`, `Board`, `Finance`).
- High number of lists or complex metadata schemas (content types, custom columns) indicating rich data classification that can be abused.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Tenant‑Wide Metadata Harvest with PnP.PowerShell

**Supported Versions:** SharePoint Online, OneDrive for Business, Microsoft 365 (all modern tenants).

#### Step 1: Connect and Enumerate Target Sites
**Objective:** Establish a session to SharePoint Online and discover candidate sites for metadata harvesting.

**Command (interactive):**
```powershell
# Install/Import module
Install-Module PnP.PowerShell -Scope CurrentUser -Force
Import-Module PnP.PowerShell

# Connect to the admin center
$AdminUrl = "https://<tenant>-admin.sharepoint.com"
Connect-PnPOnline -Url $AdminUrl -Interactive

# Enumerate all site collections
$Sites = Get-PnPTenantSite | Select Url, Template, Owner, StorageUsageCurrent
$Sites | Export-Csv "C:\Temp\SPO_Sites.csv" -NoTypeInformation
```

**Expected Output:**
- CSV file listing all site collections, templates, owners and storage usage.

**What This Means:**
- Provides a **high‑level site inventory** used to prioritize later metadata collection (e.g., sites with very high storage usage or sensitive names).

**OpSec & Evasion:**
- Limit exports to specific business units instead of the whole tenant to reduce noisy admin‑center API calls.
- Run under an existing SharePoint admin account or service principal routinely used for reporting.

**Troubleshooting:**
- **Error:** `The remote server returned an error: (401) Unauthorized`  
  - **Cause:** Missing SharePoint admin rights or conditional access blocking interactive login.  
  - **Fix:** Use a service principal with certificate auth and Sites.Selected permissions or adjust CA (for legitimate operations).

**References & Proofs:**
- PnP.PowerShell Tenant commands – `Get-PnPTenantSite` documentation.

#### Step 2: Export Library/File Metadata from a High‑Value Site
**Objective:** Export detailed metadata from document libraries (paths, size, authors, labels) without touching file content.

**Command:**
```powershell
$SiteUrl   = "https://<tenant>.sharepoint.com/sites/Finance"
$ListName  = "Documents"   # or specific library
$OutFile   = "C:\Temp\Finance_Doc_Metadata.csv"

Connect-PnPOnline -Url $SiteUrl -Interactive

# Export selected metadata fields
$Items = Get-PnPListItem -List $ListName -PageSize 500 -Fields "FileLeafRef","FileRef","Created","Modified","Author","Editor","File_x0020_Size","SensitivityLabel" 

$Results = $Items | ForEach-Object {
    $fv = $_.FieldValues
    [PSCustomObject]@{
        FileName   = $fv.FileLeafRef
        FileUrl    = $fv.FileRef
        Created    = $fv.Created
        Modified   = $fv.Modified
        Author     = $fv.Author.LookupValue
        Editor     = $fv.Editor.LookupValue
        FileSize   = $fv."File_x0020_Size"
        Label      = $fv.SensitivityLabel
    }
}

$Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
```

**Expected Output:**
- CSV with one row per file including full URL, timestamps, authors, editors, file size, and sensitivity label.

**What This Means:**
- Adversaries gain a **searchable catalog** of potentially sensitive documents and their locations without downloading content, significantly reducing detection likelihood compared to bulk file downloads.

**OpSec & Evasion:**
- Throttle enumeration (`-PageSize` and `Start-Sleep`) to avoid sudden spikes in SharePoint/Graph activity.
- Run during business hours from an IP address normally used by administrators.

**Troubleshooting:**
- **Error:** `Cannot find a list with the Name Documents`  
  - **Cause:** Different library name (`Shared Documents`, localized names).  
  - **Fix:** Run `Get-PnPList | Select Title, RootFolder` to identify actual titles.

- **Error:** `The attempted operation is prohibited because it exceeds the list view threshold`  
  - **Fix:** Use `-PageSize` and CAML queries to segment the dataset (e.g., by `Created` date) or use Graph API which does not enforce the same threshold.

**References & Proofs:**
- PnP.PowerShell documentation for `Get-PnPListItem` and list export examples.

#### Step 3: Automate Tenant‑Wide Scheduled Metadata Crawls
**Objective:** Operationalize continuous metadata collection for change tracking and targeting.

**Command (runbook pattern):**
```powershell
# Pseudo-code for Azure Automation / scheduled job
$TenantAdminUrl = "https://<tenant>-admin.sharepoint.com"
$OutputFolder   = "C:\Exports\SPO_Metadata\"  # or Azure Files / Blob

Connect-PnPOnline -Url $TenantAdminUrl -ClientId $AppId -CertificatePath "cert.pfx" -Tenant "<tenant>.onmicrosoft.com"
$Sites = Get-PnPTenantSite | Where-Object { $_.Template -eq "GROUP#0" -or $_.Template -eq "SITEPAGEPUBLISHING#0" }

foreach ($s in $Sites) {
    Connect-PnPOnline -Url $s.Url -ClientId $AppId -CertificatePath "cert.pfx" -Tenant "<tenant>.onmicrosoft.com"
    $lists = Get-PnPList | Where-Object { $_.BaseType -eq "DocumentLibrary" -and -not $_.Hidden }

    foreach ($l in $lists) {
        # Similar export logic as Step 2
        # Export CSV per library and append to central dataset
    }
}
```

**Expected Output:**
- Folder hierarchy of CSV files with rolling snapshots of metadata per site/library, enabling historical diff and trend analysis.

**What This Means:**
- An adversary can monitor **growth of sensitive repositories**, detect newly created sites, and track collaboration patterns over time.

---

### METHOD 2 – Metadata Harvest with Microsoft Graph (REST / PowerShell)

**Supported Versions:** SharePoint Online, OneDrive for Business; Microsoft Graph v1.0.

#### Step 1: Discover Sites and Lists via Graph
**Objective:** Use Microsoft Graph to enumerate sites and lists in a way that blends into other Graph‑based workloads.

**Command (REST):**
```http
GET https://graph.microsoft.com/v1.0/sites?search={tenantName}
GET https://graph.microsoft.com/v1.0/sites/{site-id}/lists
```

**Command (PowerShell with Graph SDK):**
```powershell
Connect-MgGraph -Scopes "Sites.Read.All","Files.Read.All"
Select-MgProfile -Name beta  # or v1.0 where sufficient

# List sites
Get-MgSite -Search "sharepoint" | Select-Object Id, Name, WebUrl

# List all lists in a site
Get-MgSiteList -SiteId <site-id> | Select-Object Id, DisplayName, List* 
```

**Expected Output:**
- Site inventory and associated lists, including document libraries and custom metadata repositories.

#### Step 2: Enumerate List Items and Fields (Metadata Only)
**Objective:** Retrieve listItem objects including their field sets (metadata) without fetching file content.

**Command (REST):**
```http
GET https://graph.microsoft.com/v1.0/sites/{site-id}/lists/{list-id}/items?expand=fields
```

**Command (PowerShell):**
```powershell
$siteId = "<site-id>"
$listId = "<list-id>"

$items = Invoke-MgGraphRequest -Method GET -Uri "/sites/$siteId/lists/$listId/items?`$expand=fields"
$items.value | ForEach-Object {
    [PSCustomObject]@{
        ItemId   = $_.id
        Title    = $_.fields.Title
        Path     = $_.fields.FileRef
        Author   = $_.fields.Author
        Editor   = $_.fields.Editor
        Created  = $_.fields.Created
        Modified = $_.fields.Modified
    }
} | Export-Csv "C:\Temp\Graph_List_Metadata.csv" -NoTypeInformation
```

**Expected Output:**
- CSV with list items and their key field values for structured lists or document libraries.

**OpSec & Evasion:**
- Use **app‑only** authentication with a service principal that already exists for legitimate automation.
- Spread collection over time and filter on specific sites to avoid sudden spikes in Graph throughput.

**References & Proofs:**
- Microsoft Graph documentation for SharePoint sites, lists and listItems endpoints.

---

### METHOD 3 – Combining Graph Activity Log with Metadata for Exfiltration Planning

**Objective:** Correlate **who accessed what** (Graph Activity Log / Purview Unified Audit Log) with exported metadata to prioritize targets and hide in normal patterns.

**High‑Level Steps:**
1. Use **Search-UnifiedAuditLog** or Graph Activity Log API to pull recent `FileAccessed`, `FileDownloaded`, `FileModified` events for target sites.
2. Join audit output with metadata exports (by FileUrl/ItemId) to identify documents frequently accessed by specific users or from specific IP ranges.
3. Prioritize documents where access patterns suggest low monitoring (e.g., a heavily used but poorly controlled project site).

**References & Proofs:**
- Microsoft 365 Audit log activities documentation (SharePoint file operations).
- Practical articles and blogs on using the Graph Activity Log and KQL to hunt for SharePoint/OneDrive exfiltration.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team
- **Atomic Test ID:** T1123 – Audio Capture (generic)
- **Test Name:** Audio Capture via PowerShell / SourceRecorder
- **Description:** Atomic tests for T1123 validate logging and detection around audio‑capture behavior on endpoints. While not specific to SharePoint metadata, they are useful to validate the environment’s **general Collection‑tactic visibility** and endpoint logging configuration.
- **Supported Versions:** Windows 10/11, Windows Server (Atomics for PowerShell and command prompt).

**Execution Example (PowerShell atomic):**
```powershell
# Requires Atomic Red Team framework
Invoke-AtomicTest T1123 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 1 -Cleanup
```

**Reference:**
- Atomic Red Team T1123 documentation (Audio Capture tests) on GitHub.

> **Note:** There is **no dedicated Atomic test** for SharePoint Online metadata collection. For SaaS techniques, simulate collection by executing the PnP/Graph scripts in a controlled lab tenant, then verify that logging and detection components (Sentinel, Splunk, Purview) behave as expected.

---

## 7. TOOLS & COMMANDS REFERENCE

### PnP.PowerShell

**Version:** Current 2.x line.
**Minimum Version:** 1.12+ for modern SharePoint Online support.
**Supported Platforms:** Windows PowerShell 5.1, PowerShell 7.x on Windows/Linux/macOS.

**Version-Specific Notes:**
- **1.x–early 2.x:** Some cmdlet names and parameters differ slightly; modern authentication improvements are ongoing.
- **2.x+:** Fully supports cross‑platform PowerShell and certificate‑based authentication; recommended for automation scenarios.

**Installation:**
```powershell
Install-Module PnP.PowerShell -Scope CurrentUser -Force
Import-Module PnP.PowerShell
```

**Usage (List Metadata Export):**
```powershell
Connect-PnPOnline -Url "https://<tenant>.sharepoint.com/sites/<site>" -Interactive
Get-PnPListItem -List "Documents" -PageSize 500 -Fields "FileLeafRef","FileRef" |
  Select-Object @{n='FileName';e={$_.FieldValues.FileLeafRef}},
                @{n='Url';e={$_.FieldValues.FileRef}} |
  Export-Csv "C:\Temp\Doc_Metadata.csv" -NoTypeInformation
```

### Microsoft Graph PowerShell SDK

**Version:** 2.x.
**Minimum Version:** 1.x.
**Supported Platforms:** PowerShell 5.1 and 7.x on all major OSes.

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Import-Module Microsoft.Graph
```

**Usage:**
```powershell
Connect-MgGraph -Scopes "Sites.Read.All","Files.Read.All"
Get-MgSite -Search "Finance" | Select-Object Id, Name, WebUrl
```

### Script (One-Liner – Quick Library Metadata Export)

```powershell
Connect-PnPOnline -Url "https://<tenant>.sharepoint.com/sites/<site>" -Interactive; `
Get-PnPListItem -List "Documents" -PageSize 500 -Fields "FileLeafRef","FileRef","Created","Author" | `
ForEach-Object { [PSCustomObject]@{ FileName=$_.FieldValues.FileLeafRef; Url=$_.FieldValues.FileRef; Created=$_.FieldValues.Created; Author=$_.FieldValues.Author.LookupValue } } | `
Export-Csv "C:\Temp\Quick_Metadata.csv" -NoTypeInformation
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious SharePoint Metadata Harvest via PowerShell

**Rule Configuration:**
- **Required Index:** `o365`, `wineventlog` (or equivalent for Microsoft 365 and endpoint logs).
- **Required Sourcetype:** `o365:sharepoint`, `WinEventLog:Security` or Sysmon if forwarded.
- **Required Fields:** `Operation`, `UserId`, `ClientIP`, `UserAgent`, `CommandLine`.
- **Alert Threshold:** > 5,000 metadata read operations or > 500 PowerShell commands targeting SharePoint/Graph within 15 minutes for a single identity.
- **Applies To Versions:** All environments forwarding Microsoft 365 and endpoint logs to Splunk.

**SPL Query (SharePoint side – heavy FileAccessed operations without downloads):**
```spl
index=o365 sourcetype="o365:sharepoint"
| where Operation IN ("FileAccessed","FilePreviewed") AND isnull(ObjectId) = 0
| stats count AS AccessCount, values(ObjectId) AS Files, values(ClientIP) AS ClientIPs BY UserId
| where AccessCount > 200
| sort - AccessCount
```

**SPL Query (Endpoint side – PowerShell automation targeting SharePoint/Graph):**
```spl
index=wineventlog (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
| search (CommandLine="*Connect-PnPOnline*" OR CommandLine="*Get-PnPListItem*" OR CommandLine="*graph.microsoft.com*sites*")
| stats count BY Account_Name, ComputerName, CommandLine
| where count > 50
```

**What This Detects:**
- First query surfaces accounts with **large volumes of SharePoint file access/preview events** which may correspond to metadata crawls.
- Second query correlates suspicious **PowerShell automation** that appears to be systematically interacting with SharePoint/Graph.

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**.
2. Run the SPL queries interactively, tune thresholds based on typical admin/reporting activity.
3. Convert tuned searches into **Alerts** under **Settings → Searches, reports, and alerts**.
4. Configure actions such as email to SOC, ServiceNow ticket creation, or integration with SOAR playbooks.

#### False Positive Analysis
- **Legitimate Activity:**
  - Tenant migrations, third‑party backup solutions, content inventory and compliance reporting.
- **Benign Tools:**
  - Official migration tooling, backup agents, inventory/reporting scripts.
- **Tuning Suggestions:**
  - Exclude known service accounts (`svc_backup*`, `svc_migration*`).
  - Require combination of **high volume + unusual source IP** or **unusual user agent**.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: High‑Volume SharePoint File Access Indicative of Metadata Harvesting

**Rule Configuration:**
- **Required Table:** `OfficeActivity` (or `SharePointOnline`/Graph Activity Log table in the data lake).
- **Required Fields:** `Operation`, `OfficeWorkload`, `UserId`, `ClientIP`, `OfficeObjectId`.
- **Alert Severity:** High.
- **Frequency:** Every 15 minutes, look back 1 hour.

**KQL Query:**
```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where OfficeWorkload == "SharePoint" and Operation in ("FileAccessed", "FilePreviewed")
| summarize AccessCount = count(), Files = make_set(OfficeObjectId, 50) by UserId, ClientIP
| where AccessCount > 200
| extend EntityType = "Account", AccountCustomEntity = UserId
```

**What This Detects:**
- Users or service principals **enumerating large numbers of files** in a short time window without necessarily downloading content.
- Behavior typical of metadata crawlers and inventory scripts.

**Manual Configuration Steps (Azure Portal):**
1. Azure Portal → **Microsoft Sentinel** → select workspace.
2. Go to **Analytics** → **+ Create** → **Scheduled query rule**.
3. On **General**, set Name to `High-Volume SharePoint Metadata Access` and Severity to `High`.
4. On **Set rule logic**, paste the KQL query, run every **15 minutes**, look back **1 hour**.
5. Enable incident creation and configure owner / automation rules as needed.
6. **Review + create** to deploy.

### Query 2: Suspicious PnP/Graph PowerShell Usage from Endpoints

**Rule Configuration:**
- **Required Table:** `DeviceProcessEvents` (M365 Defender) or `SecurityEvent`/`Sysmon` if forwarded.
- **Required Fields:** `ProcessCommandLine`, `AccountName`, `DeviceName`.
- **Alert Severity:** Medium.

**KQL (M365 Defender style):**
```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Connect-PnPOnline", "Get-PnPListItem", "graph.microsoft.com/v1.0/sites")
| summarize CmdCount = count(), examples = make_set(ProcessCommandLine, 10) by AccountName, DeviceName
| where CmdCount > 20
```

**What This Detects:**
- Workstations or admin servers running frequent **PnP/Graph enumeration commands**, which could indicate scripted metadata harvesting.

---

## 10. WINDOWS EVENT LOG MONITORING

Although SharePoint Online is a cloud service, the **collection tooling often runs on Windows endpoints** (admin workstations, jump servers, automation hosts). Monitoring these endpoints provides additional visibility.

**Event ID: 4688 (New Process Created)**
- **Log Source:** Security.
- **Trigger:** Whenever a new process is created (requires Audit Process Creation).
- **Filter:** `NewProcessName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"` AND `CommandLine` contains `Connect-PnPOnline` or `Get-PnPListItem`.
- **Applies To Versions:** Windows Server 2016+; Windows 10/11.

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.
3. Enable **Audit Process Creation** (Success and Failure).
4. Link the GPO to admin workstations / jump servers and run `gpupdate /force`.

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (`secpol.msc`).
2. Go to **Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.
3. Enable **Audit Process Creation** for Success and Failure.
4. Optionally, enforce via `auditpol`:
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Windows Server 2016+.

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Connect-PnPOnline</CommandLine>
      <CommandLine condition="contains">Get-PnPListItem</CommandLine>
      <CommandLine condition="contains">graph.microsoft.com/v1.0/sites</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from the Microsoft Sysinternals website.
2. Save the configuration as `sysmon-spo-metadata.xml`.
3. Install or update Sysmon:
```cmd
sysmon64.exe -accepteula -i sysmon-spo-metadata.xml
```
4. Verify events:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
  Where-Object { $_.Message -like '*Connect-PnPOnline*' -or $_.Message -like '*Get-PnPListItem*' }
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

For SharePoint Online and OneDrive, the more relevant components are **Microsoft Defender for Office 365** and **Defender for Cloud Apps** (formerly MCAS). However, when Defender for Cloud ingests Microsoft 365 data, it can surface alerts correlated with suspicious Graph/SharePoint activity.

### Detection Alerts (via Defender for Cloud Apps / Microsoft 365 Defender)
- **Alert Name:** Unusual volume of file downloads from SharePoint or OneDrive.
  - **Severity:** High.
  - **Description:** Triggers when a user or app downloads an atypically large number of files in a short period relative to their baseline.
  - **Applies To:** SharePoint Online and OneDrive for Business when Defender for Cloud Apps is enabled.
  - **Remediation:** Investigate user/app, confirm business justification, revoke sessions/tokens if malicious, and apply Conditional Access or session controls.

**Manual Configuration Steps (Enable Defender plans):**
1. Azure Portal → **Microsoft Defender for Cloud**.
2. Under **Environment settings**, select the subscription connected to Microsoft 365 Defender/Defender for Cloud Apps.
3. Ensure relevant Defender plans (**Defender for Servers**, **Defender for Cloud Apps**, **Defender for Storage**) are enabled.
4. In **Microsoft 365 Defender**, verify that **SharePoint, OneDrive and Teams** protections and anomaly detections are turned on.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: SharePoint File Access for a Specific Site

```powershell
# Connect to Exchange Online / Purview
Connect-ExchangeOnline

$Start = (Get-Date).AddDays(-7)
$End   = Get-Date
$Site  = "https://<tenant>.sharepoint.com/sites/Finance"

Search-UnifiedAuditLog -StartDate $Start -EndDate $End `
  -Operations FileAccessed,FileDownloaded,FilePreviewed `
  -ResultSize 5000 `
  | Where-Object { $_.AuditData -like "*${Site}*" } |
  Export-Csv "C:\Temp\Finance_Audit.csv" -NoTypeInformation
```

- **Operation:** `FileAccessed`, `FileDownloaded`, `FilePreviewed`.
- **Workload:** `SharePoint` / `OneDrive`.
- **Details:** `AuditData` JSON contains site URL, file URL, user, IP, and client details.
- **Applies To:** Microsoft 365 E3/E5 tenants with unified audit logging enabled.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Go to **Microsoft Purview compliance portal**.
2. Navigate to **Audit**.
3. If prompted, click **Start recording user and admin activity**.
4. Wait for ingestion to begin (can take up to 24 hours in a new tenant).

**Manual Configuration Steps (Search Audit Logs):**
1. In **Audit** → **Search**, set **Date range** for the suspected collection period.
2. Under **Activities**, select **File accessed**, **File downloaded**, **File previewed** (SharePoint/OneDrive operations).
3. Optionally filter by **Users** or **File, folder, or site** URL.
4. Run the search and export results as CSV for further correlation with metadata exports.

**PowerShell Alternative (Bulk Export):**
```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -Operations FileAccessed,FileDownloaded,FilePreviewed |
  Export-Csv "C:\Temp\SPO_FileOps.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enforce Least‑Privilege Access to SharePoint Sites and Libraries**
- **Applies To Versions:** All Microsoft 365 tenants.

**Manual Steps (SharePoint Admin Center – web):**
1. Go to **Microsoft 365 admin center → SharePoint admin center**.
2. Review **Active sites** and identify sensitive sites (HR, Finance, Legal, R&D).
3. For each site, open **Permissions** → **Site admins** and remove unnecessary owners/admins.
4. Replace broad groups like **Everyone except external users** with **role‑based groups**.

**Manual Steps (PowerShell – PnP):**
```powershell
Connect-PnPOnline -Url "https://<tenant>.sharepoint.com/sites/Finance" -Interactive
Get-PnPGroup -AssociatedOwnerGroup | Get-PnPGroupMember
# Remove high-risk accounts
Remove-PnPGroupMember -Identity "Finance Owners" -LoginName "user@tenant.onmicrosoft.com"
```

**Action 2: Restrict App‑Only Permissions to Sites.Selected**

**Manual Steps (Azure Portal):**
1. Azure Portal → **Entra ID → App registrations**.
2. Identify apps with **Sites.Read.All** or **Sites.FullControl.All**.
3. Where feasible, replace with **Sites.Selected**.
4. Use PowerShell/Graph to explicitly grant only required sites.

```powershell
# Example (simplified): grant app access to a single site
Connect-PnPOnline -Url "https://<tenant>.sharepoint.com" -Interactive
Grant-PnPAzureADAppSitePermission -AppId <AppId> -DisplayName "MetadataApp" -Site "https://<tenant>.sharepoint.com/sites/Finance" -Permissions Read
```

### Priority 2: HIGH

**Action: Monitor and Control Mass Access via Defender for Cloud Apps**
- Configure anomaly policies for **Unusual file download activity** and **Mass download by a single user**.
- Require investigation of any spikes aligned with metadata export scripts.

### Access Control & Policy Hardening

**Conditional Access:**
- Enforce **device compliance** and **trusted locations** for SharePoint/OneDrive access by admin and automation accounts.

**Manual Steps:**
1. Azure Portal → **Entra ID → Security → Conditional Access**.
2. Create policy **`CA-SharePoint-Admins-Only-From-Trusted-Locations`**.
3. Assign **Users**: SharePoint admins and service principals used for automation.
4. Target **Cloud apps**: `Office 365 SharePoint Online`.
5. Conditions: Locations → Include **Any location**, exclude **Trusted locations**.
6. Access controls: Grant → **Require compliant device** and **Require MFA**.

**RBAC/ABAC:**
- Regularly review membership of **SharePoint Admin**, **Global Admin**, and bespoke automation accounts.

**Validation Command (Verify Fix):**
```powershell
# List apps with high-privilege SharePoint Graph scopes
Connect-MgGraph -Scopes "Directory.Read.All,Application.Read.All"
Get-MgServicePrincipal -Filter "appId eq '<AppId>'" | Get-MgOauth2PermissionGrant
```

**Expected Output (If Secure):**
- Only a small, well‑documented set of apps with **Sites.Selected** or minimally scoped permissions.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- **Files/Exports:**
  - Large CSV/JSON exports on admin workstations or file shares, e.g., `C:\Temp\SPO_Sites.csv`, `C:\Temp\Finance_Doc_Metadata.csv`.
- **Registry/Config:**
  - Recently installed PnP.PowerShell or Graph modules on previously non‑admin endpoints.
- **Network:**
  - Unusual volume of HTTPS requests to `graph.microsoft.com` and `*.sharepoint.com` from atypical IPs or devices.

### Forensic Artifacts
- **Disk:**
  - PowerShell transcript logs (if enabled) showing `Connect-PnPOnline`, `Get-PnPListItem`, `Search-UnifiedAuditLog` commands.
  - Exported metadata files on disk or cloud storage.
- **Memory:**
  - In‑memory PowerShell runspaces containing PnP/Graph cmdlets.
- **Cloud:**
  - Unified audit log entries for `FileAccessed`, `FilePreviewed`, `SearchUnifieAuditLog` and Graph Activity Log records for large SharePoint enumerations.

### Response Procedures

1. **Isolate Suspected Host or Session**

```powershell
# Temporarily disable network adapter on suspected admin workstation
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
```

- In Azure: **Virtual machine → Networking → Disconnect NIC** or apply a just‑in‑time NSG lock‑down.

2. **Collect Evidence**

```powershell
# Export Security and Sysmon logs
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx

# Export PowerShell operational logs
wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\PSOperational.evtx

# Preserve exported metadata files
Copy-Item "C:\Temp\*Metadata*.csv" C:\Evidence\ -Force
```

3. **Cloud Evidence Collection**

```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -UserIds <suspicious-user@tenant.onmicrosoft.com> `
  -ResultSize 5000 |
  Export-Csv "C:\Evidence\UnifiedAudit_SPO.csv" -NoTypeInformation
```

4. **Remediate**
- Revoke sessions and refresh tokens for affected accounts.
- Rotate credentials and re‑issue certificates for compromised app registrations.
- Remove unnecessary permissions, especially **Sites.Read.All**, **Sites.FullControl.All**, **Files.Read.All**.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA-PHISH-001 – Device code phishing attacks | Adversary gains user or admin access to Microsoft 365. |
| **2** | **Privilege Escalation** | PE-ACCTMGMT-003 – SharePoint Site Collection Admin | Compromise or abuse of SharePoint admin rights. |
| **3** | **Current Step** | **COLLECT-METADATA-001 – SharePoint Metadata Collection** | Systematic metadata crawl of SharePoint/OneDrive sites. |
| **4** | **Collection & Exfiltration** | CA-UNSC-006 – Private keys theft / CA-UNSC-014 – SaaS API key exposure | Use metadata to identify high‑value stores and exfiltrate content with keys/tokens. |
| **5** | **Impact** | REALWORLD-003 – POP/IMAP Basic Auth Abuse / REALWORLD-004 – Legacy API Brute Force | Leverage knowledge of repositories for targeted extortion, ransomware, or data‑leak campaigns. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Targeted SharePoint / OneDrive Exfiltration via Graph
- **Target:** Professional services and legal sectors.
- **Timeline:** 2023–2025 (multiple public incident write‑ups and threat‑hunting case studies).
- **Technique Status:** ACTIVE – Multiple threat‑intel and defensive blog posts describe attacks where adversaries used Graph API or migration‑style tooling to **enumerate and exfiltrate SharePoint/OneDrive content**, often starting from broad metadata discovery.
- **Impact:** Theft of legal case files, M&A documents, and intellectual property, followed by extortion and public leaks.
- **Reference:** Public blogs and conference talks on Microsoft 365 document exfiltration using Graph Activity Log and Sentinel KQL.

### Example 2: Insider Abuse Using Admin Reporting Scripts
- **Target:** Financial services organization.
- **Timeline:** Circa 2024.
- **Technique Status:** ACTIVE – Insider with SharePoint admin rights abused an internal inventory script to export metadata and pathing for thousands of sensitive documents, then selectively downloaded only the most valuable content.
- **Impact:** Exposure of confidential deal code names, client identifiers and project structures, creating severe reputational and regulatory risk even before any file content was leaked.
- **Reference:** Case studies and anonymized incident analyses in Microsoft 365 security blogs and conference presentations on insider threats and SharePoint misuse.

---