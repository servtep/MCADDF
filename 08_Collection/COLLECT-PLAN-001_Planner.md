# [COLLECT-PLAN-001]: Microsoft Planner Task Collection

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-PLAN-001 |
| **Technique Name** | Microsoft Planner Task Collection |
| **MITRE ATT&CK v18.1** | [T1123 – Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection (TA0009) |
| **Platforms** | Microsoft 365, Planner, Microsoft 365 Groups |
| **Severity** | Medium to High (depends on task sensitivity) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Microsoft Planner in Microsoft 365, Planner APIs in Microsoft Graph |
| **Patched In** | Not applicable – relies on legitimate Planner and Graph APIs |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers **enumeration and export of Microsoft Planner tasks, buckets, plans, and comments** using Planner Graph APIs, GUI exports to Excel, and mailbox/Group conversations. Task data frequently includes project timelines, owners, URLs to sensitive documents, and free‑text notes that may reveal credentials or operational details.
- **Attack Surface:** Planner web UI, mobile apps, Graph API (`/planner/plans`, `/planner/tasks`, `/groups/{id}/planner`), Excel exports, and underlying Microsoft 365 Groups and Exchange mailboxes that store comments and conversation threads.
- **Business Impact:** **Medium to High.** While Planner is not always treated as a high‑sensitivity system, tasks and checklists often contain **links and context** that point to critical resources, internal projects, and schedule of operations. Leakage enables adversaries to map projects, identify key personnel, and time their attacks for maximum impact.
- **Technical Context:** Planner data is accessible via **Graph APIs** for group‑based plans. There is no API for private To Do tasks, but Planner tasks for Microsoft 365 Groups can be fully enumerated with correct permissions. Exports to Excel are commonly used for reporting; attackers can replicate or hijack these flows and extract JSON via Graph.

### Operational Risk
- **Execution Risk:** Low – Exporting tasks via GUI or Graph is normal for reporting and migration.
- **Stealth:** Medium – Large‑scale enumeration via Graph can be noisy in audit logs but often overlooked; GUI exports are indistinguishable from legitimate user activity.
- **Reversibility:** Low – Once task metadata (titles, descriptions, attachments, comments) is exported, there is no way to recall the information.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | CIS O365 3.4 | Control and monitor access to collaboration workloads, including Planner. |
| **DISA STIG** | O365-PLN-000010 | Ensure Planner task data is subject to the same access and audit requirements as other workloads. |
| **CISA SCuBA** | M365-MOD-1 | Monitor modern collaboration workloads (Teams, Planner) for misuse. |
| **NIST 800-53** | AC-6, AU-6 | Least privilege and logging for project/task management systems. |
| **GDPR** | Art. 5, Art. 32 | Secure handling of personal data embedded in tasks (e.g., PII in descriptions). |
| **DORA** | Art. 9 | Logging and security for ICT tools supporting operational resilience. |
| **NIS2** | Art. 21 | Measures for ICT project tools in essential/important entities. |
| **ISO 27001** | A.8.12, A.8.16 | Governance for information in collaborative tools and project trackers. |
| **ISO 27005** | Project Management Data Risk Scenario | Exposure of internal project plans and timelines. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Membership in Microsoft 365 Groups owning the target plans.
  - For app‑only Graph access: appropriate delegated or application permissions (e.g., `Group.Read.All`, `Tasks.Read`, Planner scopes per current Graph schema).
- **Required Access:**
  - HTTPS to `tasks.office.com`, `planner.office.com`, `graph.microsoft.com`, and group mailboxes if harvesting comments.

**Supported Versions:**
- **Planner:** All Microsoft Planner workloads in Microsoft 365.
- **Graph:** Planner APIs in Microsoft Graph v1.0 and beta (plans, buckets, tasks, assignments, details).

- **Tools:**
  - Planner web UI and **Export plan to Excel** feature.
  - Microsoft Graph Explorer / Graph PowerShell SDK for programmatic access.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### GUI Recon – Identify High‑Value Plans
1. Open **planner.office.com** and sign in.
2. Review **Recent plans**, **Pinned plans**, and plans under **My groups** or **Portfolios**.
3. Identify plans with names indicating sensitive content (e.g., `Security Roadmap`, `Incident Response`, `M&A`, `Regulatory Audit`).

### Graph Recon – Discover Plans by Group

```powershell
Connect-MgGraph -Scopes "Group.Read.All,Tasks.Read"

# List groups and their associated planner plans
$groups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" -ConsistencyLevel eventual -Count groupCount

foreach ($g in $groups) {
  try {
    $plans = Invoke-MgGraphRequest -Method GET -Uri "/groups/$($g.Id)/planner/plans"
    if ($plans.value) {
      $plans.value | Select-Object id, title, owner | ForEach-Object {
        [PSCustomObject]@{
          GroupName = $g.DisplayName
          PlanTitle = $_.title
          PlanId    = $_.id
        }
      }
    }
  } catch {}
}
```

**What to Look For:**
- Plans associated with security, privileged operations, or strategic projects.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Export Plan to Excel via GUI

**Supported Versions:** All Planner web clients.

#### Step 1: Manual Export
1. Open the target plan in **planner.office.com**.
2. Use the **... (More options)** menu and select **Export plan to Excel**.
3. Save the Excel file locally or to OneDrive.

**Expected Output:**
- Workbook containing tasks, bucket names, labels, assignments, due dates, completion status.

**OpSec & Evasion:**
- Occasional exports for reporting are common; repeated exports in short periods are more suspicious.

---

### METHOD 2 – Harvest Tasks via Microsoft Graph

**Supported Versions:** Planner Graph APIs for group plans.

#### Step 1: Enumerate Tasks for a Plan

```powershell
Connect-MgGraph -Scopes "Group.Read.All,Tasks.Read"

$planId = "<plan-id>"
$tasks  = Invoke-MgGraphRequest -Method GET -Uri "/planner/plans/$planId/tasks"

$tasks.value | Select-Object id, title, dueDateTime, createdDateTime, percentComplete, assignments |
  Export-Csv "C:\Temp\Planner_Tasks.csv" -NoTypeInformation
```

**Expected Output:**
- CSV with basic task metadata.

#### Step 2: Retrieve Task Details (Descriptions, References, Checklist)

```powershell
$taskDetails = foreach ($t in $tasks.value) {
  $details = Invoke-MgGraphRequest -Method GET -Uri "/planner/tasks/$($t.id)/details"
  [PSCustomObject]@{
    TaskId      = $t.id
    Title       = $t.title
    Description = $details.description
    References  = ($details.references | ConvertTo-Json -Compress)
    Checklist   = ($details.checklist  | ConvertTo-Json -Compress)
  }
}

$taskDetails | Export-Csv "C:\Temp\Planner_TaskDetails.csv" -NoTypeInformation
```

**What This Means:**
- `description`, `references`, and `checklist` often contain URLs to sensitive documents, admin portals, or internal runbooks.

**OpSec & Evasion:**
- Use throttling and respect Graph rate limits to avoid spikes.
- Run as a service principal used for project reporting.

---

### METHOD 3 – Extracting Comments via Group Mailbox Threads

Planner comments are stored in the **Microsoft 365 Group mailbox** as conversations.

**High‑Level Steps:**
1. Identify group ID for the plan.
2. Use Graph to query `/groups/{id}/conversations` and `/threads`.
3. Extract messages with subjects referencing Planner tasks or including Planner‑specific headers.

**Use Cases:**
- Build full discussion history around high‑risk tasks (e.g., incident response actions), even if the plan itself appears benign.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

- No dedicated Atomic test exists for Planner.
- Validate detections using a **test plan**:
  - Populate tasks and comments.
  - Export via GUI and Graph scripts.
  - Confirm that Purview audit logs, Sentinel rules, and Defender alerts capture the behavior.

---

## 7. TOOLS & COMMANDS REFERENCE

### Microsoft Graph – Planner API

Key endpoints (v1.0):
- `/me/planner/plans`
- `/groups/{id}/planner/plans`
- `/planner/plans/{id}/tasks`
- `/planner/tasks/{id}/details`

The Planner API currently **does not support private To Do tasks** – only group‑plan tasks are exposed.

---

## 8. SPLUNK DETECTION RULES

### Rule: High‑Volume Planner Task Enumeration

**Conceptual SPL:**
```spl
index=o365 sourcetype="o365:management:activity"
| search Workload="Planner"
| stats count AS Ops BY UserId, Operation
| where Ops > 200
```

- Tune `Ops` threshold based on typical tenant usage.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Unusual Planner Activity Volume

```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where Workload == "Planner"
| summarize Ops = count() by UserId, Operation
| where Ops > 200
```

- Focus on operations such as plan creation, membership changes, and bulk task reads.

---

## 10. WINDOWS EVENT LOG MONITORING

- Monitor admin workstations for `graph.microsoft.com` calls in PowerShell and CLI tools used to automate Planner exports.

---

## 11. SYSMON DETECTION PATTERNS

- Detect PowerShell processes that call Planner Graph endpoints, as with other Graph‑based collection tooling.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

- Use Defender for Cloud Apps / Microsoft 365 Defender to detect:
  - Unusual creation and modification of Planner plans and tasks.
  - Suspicious access from atypical locations or devices.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

- Ensure **Planner audit events** are ingested (requires appropriate Purview Audit tier).

```powershell
Connect-ExchangeOnline
$Start = (Get-Date).AddDays(-7)
$End   = Get-Date

Search-UnifiedAuditLog -StartDate $Start -EndDate $End -ResultSize 5000 |
  Where-Object { $_.Workload -eq "Planner" } |
  Export-Csv "C:\Temp\Planner_Audit.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

- Limit who can create and administer sensitive plans (e.g., security projects, incident response).
- Periodically export and review membership and ownership of high‑risk plans.
- Apply Conditional Access to enforce compliant devices and MFA for users heavily interacting with Planner.

---

## 15. DETECTION & INCIDENT RESPONSE

- Investigate:
  - Sudden large exports of plans or tasks.
  - Graph applications with new permissions to Planner scopes.
- Respond by:
  - Revoking tokens and app permissions.
  - Re‑ownering sensitive plans away from compromised accounts.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-PHISH-001 – Device code phishing attacks | Compromise of project owner account. |
| 2 | Privilege Escalation | PE-ACCTMGMT-003 – SharePoint/Teams Admin | Gain broad group/Teams ownership. |
| 3 | Current Step | **COLLECT-PLAN-001 – Microsoft Planner Task Collection** | Enumerate and export task data. |
| 4 | Collection/Exfiltration | CA-TOKEN-004 – Graph API token theft | Use tokens to automate continuous task harvesting. |
| 5 | Impact | REALWORLD-003 – POP/IMAP Basic Auth Abuse | Use project insight to time and target further attacks. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Project Portfolio Intelligence Gathering
- Adversaries with access to a project management account exported all security and IT roadmaps from Planner.
- They used due dates and milestones to schedule attacks before key hardening projects completed.

### Example 2: Insider Collection of Incident Response Tasks
- An insider with access to the corporate incident‑response plan harvested Planner tasks and comments describing playbooks and contact trees.
- The data was later used to craft tailored ransomware runbooks designed to evade known response procedures.

---