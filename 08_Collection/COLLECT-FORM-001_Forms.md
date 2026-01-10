# [COLLECT-FORM-001]: Form Responses & Survey Data

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-FORM-001 |
| **Technique Name** | Form Responses & Survey Data Collection |
| **MITRE ATT&CK v18.1** | [T1123 – Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection (TA0009) |
| **Platforms** | Microsoft 365, Microsoft Forms, SharePoint Online, OneDrive for Business |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Microsoft Forms in Microsoft 365, SharePoint Online, OneDrive for Business |
| **Patched In** | Not applicable – relies on legitimate Forms export and automation features |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers **systematic collection of Microsoft Forms responses and survey data** from Microsoft 365 tenants. Adversaries can export responses directly from the Forms web interface, abuse **Power Automate** flows that persist responses to SharePoint/OneDrive, or programmatically query internal Forms APIs. Once collected, structured survey data (PII, health data, satisfaction scores, internal polls) is highly valuable for profiling users, social engineering, and regulatory extortion.
- **Attack Surface:** Microsoft Forms web UI, Power Automate flows bound to Forms, Excel workbooks storing responses, SharePoint lists used as Forms back‑ends, and any automation accounts with access to those data stores.
- **Business Impact:** **High confidentiality and privacy impact.** Forms often collect sensitive HR, customer, or medical information under weak governance. Exfiltration of even a single large Form can constitute a reportable GDPR or sectoral‑regulation breach.
- **Technical Context:** Because **Forms lacks a stable public Graph API for responses**, most organizations rely on GUI exports or Power Automate connectors to move responses into Excel or SharePoint. Attackers therefore focus on **stealing exported Excel files**, **abusing existing flows**, or **creating rogue flows** wired to sensitive Forms. Activity appears as normal business automation unless correlated with identity, timing, and volume.

### Operational Risk
- **Execution Risk:** Low to Medium – Exporting responses is a standard user action. Risk increases when creating or modifying flows, which might be noticed by administrators.
- **Stealth:** Medium to High – Small exports via GUI blend into normal usage. Continuous exfiltration through compromised flows can be very stealthy and long‑lived.
- **Reversibility:** Low – Once responses have been exported or replicated through automation to external storage, there is no way to revoke exposure of submitted answers.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | CIS O365 3.4, 3.10 | Control and monitor access to collaboration workloads and audit sensitive data exports. |
| **DISA STIG** | O365-API-000010 | Ensure that API/connector access to O365 data is restricted and logged. |
| **CISA SCuBA** | M365-AUD-1 | Enable unified audit logging and monitor high‑risk workloads such as Forms and SharePoint. |
| **NIST 800-53** | AC-6, AU-6, IP-1 | Limit access to sensitive survey data; review audit logs; protect PII. |
| **GDPR** | Art. 5, Art. 6, Art. 32 | Lawful processing and security of personal data captured via online forms. |
| **DORA** | Art. 9 | Protection of customer data and logging for critical services such as portals and surveys. |
| **NIS2** | Art. 21 | Risk management measures covering SaaS data collection mechanisms. |
| **ISO 27001** | A.8.12, A.8.16 | Protection and classification of information in applications (including survey tools). |
| **ISO 27005** | Online Survey Data Risk Scenario | Compromise of survey platform or exports leading to privacy and reputational damage. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Form **owner** or co‑owner to export responses from GUI.
  - Access to **Power Automate** environment and connection references for Forms/SharePoint/Excel.
  - For SharePoint‑backed storage: read access to the target list/library.
- **Required Access:**
  - HTTPS to `forms.office.com`, `*.sharepoint.com`, `*.office.com`, `graph.microsoft.com` (for downstream storage).

**Supported Versions:**
- **Microsoft Forms:** All Microsoft 365 commercial tenants.
- **Power Automate:** Cloud flows with Microsoft Forms and SharePoint/Excel connectors.
- **SharePoint/OneDrive:** Modern SharePoint Online and OneDrive for Business.

- **Tools:**
  - Web browser with access to Microsoft Forms portal.
  - Power Automate portal and connectors for **When a new response is submitted** and **Get response details**.
  - PnP.PowerShell or Graph SDK for secondary collection from SharePoint/Excel.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### GUI Recon – Identify High‑Value Forms
1. Browse to **forms.office.com** and sign in as the compromised user or admin.
2. Review **Owned forms**, **Shared with me**, and **Group forms**.
3. Identify forms with sensitive names (e.g., `Employee Health Declaration`, `Customer KYC`, `Incident Report`).

**What to Look For:**
- High response counts and forms linked to HR, finance, security, or customer‑facing processes.

### Power Automate Recon

```powershell
# Using PowerShell to list flows (requires Power Apps/Power Platform admin modules)
Get-AdminFlow -EnvironmentName Default-<GUID> | Select DisplayName, CreatedBy, Enabled
```

**What to Look For:**
- Flows whose triggers are **When a new response is submitted** in Microsoft Forms.
- Actions that **write to SharePoint lists or Excel in OneDrive/SharePoint**, creating secondary data stores that can be collected.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Direct Export of Responses from Microsoft Forms GUI

**Supported Versions:** All Forms instances in Microsoft 365.

#### Step 1: Export Responses to Excel
**Objective:** Obtain a full offline copy of all responses with minimal traces beyond normal user actions.

**Manual Steps:**
1. Navigate to **forms.office.com** and open the targeted form.
2. Select the **Responses** tab.
3. Click **Open results in Excel** or **Download a copy** (depending on UI version).
4. Save the exported workbook locally or to a synced OneDrive location.

**Expected Output:**
- An `.xlsx` file containing all responses, responder IDs (if recording names), timestamps, and question/answer pairs.

**OpSec & Evasion:**
- Perform export from the same IP/device normally used by the form owner.
- If possible, export at a time when the owner legitimately reviews results (e.g., end of reporting period).

**Troubleshooting:**
- Export only includes subset of fields if the form was edited post‑creation; verify field mapping and re‑export.

---

### METHOD 2 – Abusing Power Automate to Stream Responses to SharePoint / OneDrive

**Supported Versions:** Power Automate in Microsoft 365 with Forms and SharePoint/Excel connectors.

#### Step 1: Create or Hijack a Flow for Continuous Export
**Objective:** Automatically duplicate every new response into an attacker‑controlled data store.

**High‑Level Steps:**
1. In **Power Automate**, locate existing flows bound to the target form.
2. Copy the flow or add additional actions:
   - **Get response details** (Microsoft Forms) using Response Id.
   - **Add a row into a table** in an Excel file under attacker‑controlled OneDrive/SharePoint.
   - Or **Create item** in an attacker‑controlled SharePoint list.
3. Turn on the modified or cloned flow.

**Example Flow Logic:**
- Trigger: `When a new response is submitted` (Form X).
- Action 1: `Get response details` (Form X, Response Id).
- Action 2: `Add a row into a table` (Excel file in attacker site) mapping all question fields.

**Expected Output:**
- Continuous replication of responses into a location where the attacker can later export data via PnP/Graph or direct download.

**OpSec & Evasion:**
- Name cloned flow similarly to existing flows (e.g., `Form X – Archive`).
- Store replicated data in a site that already contains analytics/BI workloads.

**Troubleshooting:**
- Connection reference errors if the attacker account lacks permissions to the target Excel/SharePoint location; grant minimal required rights.

---

### METHOD 3 – Collecting From SharePoint/Excel Using PnP/Graph

Once responses are stored in SharePoint lists or Excel tables, attackers can reuse the **metadata collection** and **list export** techniques described in COLLECT-METADATA-001 and COLLECT-LIST-001.

**Example (PnP.PowerShell – SharePoint list backing a form):**
```powershell
Connect-PnPOnline -Url "https://<tenant>.sharepoint.com/sites/FormsArchive" -Interactive
$ListName = "CustomerSurveyResponses"
$CSVPath  = "C:\Temp\CustomerSurveyResponses.csv"

$Items = Get-PnPListItem -List $ListName -PageSize 500
$Items | ForEach-Object {
  $fv = $_.FieldValuesAsText
  [PSCustomObject]@{
    ID        = $fv.ID
    Submitted = $fv.Created
    User      = $fv."Created By"
    Q1        = $fv.Q1
    Q2        = $fv.Q2
    Q3        = $fv.Q3
  }
} | Export-Csv $CSVPath -NoTypeInformation
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

As of 2026, there is **no Atomic Red Team test dedicated to Microsoft Forms response collection**. For this technique:
- Use a **lab tenant** with test Forms.
- Simulate GUI exports and Power Automate flows.
- Validate logging in **Purview Audit**, **Sentinel**, and **Defender for Cloud Apps**.

Generic T1123 Atomic tests (Audio Capture) can still be run to validate Collection tactic visibility on endpoints, but they do not mimic Forms behavior.

---

## 7. TOOLS & COMMANDS REFERENCE

### Power Automate – Forms to SharePoint/Excel

**Key Connectors:**
- **Microsoft Forms** – Triggers and actions:
  - `When a new response is submitted`.
  - `Get response details`.
- **SharePoint** – `Create item`, `Update item`.
- **Excel Online (Business)** – `Add a row into a table`.

**Usage Pattern:**
- Map each Forms question to a column in Excel/SharePoint, ensuring that sensitive data is not duplicated unnecessarily (for defense) or is fully captured (for offense).

### PnP.PowerShell / Graph

See COLLECT-METADATA-001 and COLLECT-LIST-001 for detailed cmdlets and scripts. They are reused for collecting Form responses once persisted to SharePoint lists or Excel tables.

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Unusual Export Activity in Microsoft Forms

Because Forms audit events are surfaced through the **Unified Audit Log**, Splunk detection focuses on the **O365 audit feed**.

**Rule Configuration:**
- **Required Index:** `o365` (or equivalent).
- **Required Sourcetype:** `o365:management:activity` / `o365:audit`.
- **Required Fields:** `Workload`, `Operation`, `UserId`, `FormName` (if available in AuditData).
- **Alert Threshold:** > N exports/views of responses in 30 minutes by same user.

**Conceptual SPL:**
```spl
index=o365 Workload="MicrosoftForms"
| search Operation IN ("ViewedResponses", "ExportedResponses", "ViewedFormResponsesPage")
| stats count AS Ops BY UserId, FormName
| where Ops > 5
```

**What This Detects:**
- Users repeatedly viewing or exporting responses for the same form in a short period – suspicious when combined with sensitive forms.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: High‑Frequency Access to Forms Responses

**Rule Configuration:**
- **Required Table:** `AuditLogs` / `OfficeActivity` depending on connector.
- **Required Fields:** `Operation`, `UserId`, `Workload`, `AuditData`.
- **Severity:** Medium to High (depending on form sensitivity).

**KQL (conceptual):**
```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where Workload == "MicrosoftForms"
| where Operation in ("ViewedResponses", "ExportedResponses", "ViewedFormResponsesPage")
| summarize Count = count() by UserId, Operation
| where Count > 5
```

**What This Detects:**
- Accounts heavily interacting with response views/exports, which may indicate bulk collection.

---

## 10. WINDOWS EVENT LOG MONITORING

- Monitor endpoints for browsers or automation tools accessing `forms.office.com` combined with downloads of Excel files named like the form.
- If Power Automate administration is performed from specific admin workstations, log **browser history** and **PowerShell administration modules** on those hosts.

---

## 11. SYSMON DETECTION PATTERNS

Sysmon can capture:
- Downloads of Excel files from `forms.office.com` using `EventID 11 (FileCreate)` on synced OneDrive folders.
- Browser or automation processes writing `.xlsx` files named after forms into local temp directories.

Example Sysmon filter (conceptual):
```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">\\OneDrive -</TargetFilename>
  <TargetFilename condition="ends with">.xlsx</TargetFilename>
</FileCreate>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

More directly relevant are **Microsoft 365 Defender** and **Defender for Cloud Apps**, which can alert on:
- Mass downloads of files from SharePoint/OneDrive containing exported Forms responses.
- Unusual behavior of accounts creating or modifying large numbers of flows.

Use anomaly policies for **mass download** and **unusual app behavior**.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Microsoft Forms Activity

```powershell
Connect-ExchangeOnline
$Start = (Get-Date).AddDays(-7)
$End   = Get-Date

Search-UnifiedAuditLog -StartDate $Start -EndDate $End -ResultSize 5000 |
  Where-Object { $_.Workload -eq "MicrosoftForms" } |
  Export-Csv "C:\Temp\Forms_Audit.csv" -NoTypeInformation
```

- Filter further on operations such as `CreatedForm`, `EditedForm`, `ViewedFormResponsesPage`, `ExportedResponses` (names depend on current schema).
- Correlate with known sensitive forms by title or ID.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Governance for High‑Risk Forms**
- Classify and inventory Forms that collect PII, financial, or health data.
- Restrict ownership to appropriate business units.

**Manual Steps:**
1. Use Purview audit and PowerShell exports to inventory Forms usage.
2. Work with data owners to retire obsolete forms and delete historical responses when no longer needed.

**Action 2: Control Power Automate Connectors**
- Restrict who can create flows using Forms and high‑risk destinations (e.g., external storage, third‑party connectors).

### Priority 2: HIGH

- Enable **unified audit logging** and ensure Forms events are ingested.
- Train users **not** to collect unnecessary sensitive data via Forms.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- Sudden creation of flows tied to high‑value forms.
- Large Excel files containing full responses in OneDrive/SharePoint locations owned by unusual users.

### Forensic Artifacts
- **Cloud:** Purview audit entries for Forms operations and related SharePoint/OneDrive exports.
- **Disk:** Local copies of exported Excel files.

### Response Procedures
1. Identify all locations where responses have been exported or duplicated.
2. Suspend or delete malicious flows and revoke connectors.
3. Work with legal/compliance to assess breach notification obligations.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | IA-PHISH-001 – Device code phishing attacks | Adversary gains user identity able to access Forms. |
| **2** | Privilege Escalation | PE-ACCTMGMT-005 – PowerApps/Power Platform Escalation | Gain control over Power Automate environment. |
| **3** | Current Step | **COLLECT-FORM-001 – Form Responses & Survey Data** | Export or continuously stream all responses. |
| **4** | Collection/Exfiltration | CA-UNSC-014 – SaaS API key exposure | Use keys/connectors to move data externally. |
| **5** | Impact | REALWORLD-003 – POP/IMAP Basic Auth Abuse | Use collected data for extortion, fraud and targeted phishing. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: HR Survey Data Exposure
- **Target:** Large enterprise HR department.
- **Scenario:** Compromised HR mailbox account that owned several Forms used for employee health and satisfaction surveys.
- **Technique:** Attacker exported all responses to Excel via GUI and synced them through OneDrive, then exfiltrated via personal device.
- **Impact:** Exposure of sensitive HR data and employee health information, triggering GDPR and employment‑law obligations.

### Example 2: Rogue Flow Replicating Customer Feedback
- **Target:** Customer‑facing portal.
- **Scenario:** Insider with Power Automate access created a flow to mirror all customer feedback Form responses into a personal SharePoint site.
- **Impact:** Years of customer comments and contact details were silently copied and later sold to a competitor.

---