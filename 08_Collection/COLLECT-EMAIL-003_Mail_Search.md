# [COLLECT-EMAIL-003]: Mail Search via PowerShell

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-EMAIL-003 |
| **MITRE ATT&CK v18.1** | Email Collection (T1114) – Remote Email Collection (T1114.002) via Exchange PowerShell / Compliance Search |
| **Tactic** | Collection |
| **Platforms** | M365 (Exchange Online), Exchange 2013–2019 |
| **Severity** | High |
| **Technique Status** | ACTIVE (Search-Mailbox retired in EXO; Compliance Search / Graph API now primary) |
| **Last Verified** | 2024-09-30 |
| **Affected Versions** | Exchange Online; Exchange 2013–2019 (on‑prem Search-Mailbox still supported) |
| **Patched In** | N/A – functionality replaced/redirected in Exchange Online; risk mitigated via RBAC and audit logging |
| **Environment** | M365 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers **searching mailboxes from PowerShell** using Exchange cmdlets such as `Search-Mailbox` (on‑prem), `New-ComplianceSearch`, `New-ComplianceSearchAction`, and `Search-UnifiedAuditLog`. Adversaries with admin or eDiscovery roles can execute server‑side searches across multiple mailboxes, optionally copying or exporting matches to special mailboxes or PST files. This is a powerful way to perform **targeted email collection** without interactive access to Outlook or EWS coding.
- **Attack Surface:** Exchange Online PowerShell endpoint, Compliance/eDiscovery APIs, and on‑prem Exchange Management Shell. High‑privilege roles (Discovery Management, Compliance Administrator, Organization Management) are especially sensitive.
- **Business Impact:** **Targeted theft of sensitive conversations and attachments across many users.** Attackers can search for specific keywords (credentials, deal names, project codes), legal entities, or individuals and exfiltrate only the most valuable content while keeping volumes small and stealthy.
- **Technical Context:** In Exchange Online, `Search-Mailbox` is retired; attackers rely on **Compliance Search (content search)** and `New-ComplianceSearchAction -Export` to stage results for PST export. On‑prem, `Search-Mailbox` can copy or delete messages directly. All of these actions are logged in the Unified Audit Log and Exchange admin logs, but detection depends on ingesting and analyzing those events.

### Operational Risk
- **Execution Risk:** Medium – Misuse of search/copy/delete switches can disrupt investigations or destroy evidence.
- **Stealth:** Medium – Admin/eDiscovery search is normal in many tenants; abuse can hide in baseline activity if SOC does not monitor search frequency and scope.
- **Reversibility:** Partial – Exported data cannot be revoked; destructive usage of `-DeleteContent` on‑prem is often irreversible without backups.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | M365 / Exchange Online – eDiscovery role minimization | Over‑privileged discovery roles allow bulk search and export of regulated communications. |
| **DISA STIG** | O365 STIG – privileged role management | Inadequate separation of duties around compliance/eDiscovery roles. |
| **CISA SCuBA** | Admin and eDiscovery controls | Weak guardrails around content search and export functions. |
| **NIST 800-53** | AC-5, AC-6, AU-2, AU-12 | Excessive admin privileges and missing audit/alerting for mass search/export. |
| **GDPR** | Art. 32, Art. 25 | Failure to enforce least privilege and logging when processing personal data via search/export. |
| **DORA** | Art. 9 | Non‑monitored access to historical communications breaches ICT logging and monitoring duties. |
| **NIS2** | Art. 21 | Insufficient risk‑management around powerful search/export operations on critical communications. |
| **ISO 27001** | A.5, A.8.12, A.8.16 | Missing controls and monitoring on use of admin/eDiscovery tooling. |
| **ISO 27005** | Abuse of admin/eDiscovery channels | High‑impact risk scenario where trusted tooling is turned into an exfiltration vector.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Exchange Online: Membership in eDiscovery Manager / Compliance Administrator / Organization Management to create and export content searches.
  - On‑prem: `Mailbox Search` rights or `Discovery Management` role for `Search-Mailbox`.
- **Required Access:**
  - PowerShell connectivity to Exchange Online or on‑prem Exchange Management Shell.

**Supported Versions:**
- **Exchange Online:** `New-ComplianceSearch`, `New-ComplianceSearchAction`.
- **Exchange on‑prem 2013–2019:** `Search-Mailbox`, `New-MailboxExportRequest`.

- **Tools:**
  - ExchangeOnlineManagement PowerShell module.
  - Security & Compliance (now Purview) PowerShell session for compliance searches.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance – Role and Search Discovery
```powershell
# Connect to Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

# List high-privilege discovery roles
Get-RoleGroup | Where-Object { $_.Name -like '*Discovery*' -or $_.Name -like '*Compliance*' } |
  Select-Object Name, ManagedBy

# List existing compliance searches
Get-ComplianceSearch | Select-Object Name, Status, ExchangeLocation, ContentMatchQuery

# List recent compliance search actions (including exports)
Get-ComplianceSearchAction | Select-Object Name, Action, Status, Workload
```

**What to Look For:**
- Users with both admin and eDiscovery roles.
- Broad, recurring searches targeting many mailboxes.
- Completed export actions not associated with known investigations.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exchange Online Compliance Search and Export

**Supported Versions:** Exchange Online.

#### Step 1: Create Content Search
**Objective:** Define a KQL query and target mailboxes for collection.

**Command:**
```powershell
Connect-IPPSSession  # Purview / Compliance PowerShell

New-ComplianceSearch -Name 'HR-Keyword-Scan' `
  -ExchangeLocation 'All' `
  -ContentMatchQuery '"confidential" OR "wire transfer" OR "password"'

Start-ComplianceSearch -Identity 'HR-Keyword-Scan'
```

**Expected Output:**
- Search status becomes `Starting` then `Running`, later `Completed`.

#### Step 2: Export Search Results
**Objective:** Stage results for PST export.

**Command:**
```powershell
New-ComplianceSearchAction -SearchName 'HR-Keyword-Scan' -Export -ExchangeArchiveFormat PerUserPST

Get-ComplianceSearchAction -SearchName 'HR-Keyword-Scan' -Action Export | fl Name,Status,Results
```

**Expected Output:**
- Export action with a downloadable URL and SAS token exposed in the portal; PST per mailbox.

**OpSec & Evasion:**
- Use narrow `ContentMatchQuery` to keep exported volume small and focused.
- Name searches to mimic legitimate audits (for example, quarterly review).

**References & Proofs:**
- Microsoft and community guides on exporting Office 365 mailboxes to PST using eDiscovery / content search.

### METHOD 2 – On‑Prem Search-Mailbox (Copy to Target Mailbox)

**Supported Versions:** Exchange 2013–2019 (on‑prem, not Exchange Online).

#### Step 1: Search and Copy
**Objective:** Search a source mailbox and copy results to a target mailbox/folder for later export.

**Command:**
```powershell
# Example – copy all mail from a user into a discovery mailbox
Search-Mailbox -Identity 'user@corp.local' `
  -TargetMailbox 'DiscoveryMailbox{GUID}' `
  -TargetFolder 'User-Collection' `
  -LogLevel Full
```

**Expected Output:**
- Messages recopied into the discovery mailbox; log item generated.

**OpSec & Evasion:**
- Use specific date ranges or subjects to avoid huge copy operations that draw attention.

**References & Proofs:**
- Microsoft docs for `Search-Mailbox`.
- Community examples for copying mail between mailboxes.

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Technique:** T1114.002 – Email Collection: Remote Email Collection.
- **Description:** Some atomic tests simulate mailbox search and export behavior (for example, using EWS or administrative search APIs).
- **Command:**
  ```powershell
  Invoke-AtomicTest T1114.002 -TestNumbers 1
  ```

## 7. TOOLS & COMMANDS REFERENCE

#### Exchange Online Management

**Installation:**
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
```

**Usage:**
- `Get-ComplianceSearch`, `New-ComplianceSearch`, `New-ComplianceSearchAction`, `Search-UnifiedAuditLog`.

#### Script (One-Liner) – Quick Unified Audit Search for Compliance Actions
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations New-ComplianceSearch, New-ComplianceSearchAction `
  -ResultSize 5000
```

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious ComplianceSearch and Export Activity
**Rule Configuration:**
- **Required Index:** O365 management logs.
- **Required Sourcetype:** O365 audit.

**SPL Query:**
```spl
index=o365 Workload="SecurityComplianceCenter"
| eval op=coalesce(Operation, operation)
| where op IN ("New-ComplianceSearch","New-ComplianceSearchAction")
| stats count AS op_count,
        values(op) AS operations,
        values(UserId) AS users
  by UserId, SearchName
| where op_count >= 2
```

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: New Compliance Search + Export
**KQL Query:**
```kusto
OfficeActivity
| where OfficeWorkload =~ "SecurityComplianceCenter"
| where Operation in ("New-ComplianceSearch","New-ComplianceSearchAction")
| summarize Count = count(), Ops = make_set(Operation) by UserId, SearchName, bin(TimeGenerated, 1h)
| where Count >= 2 and array_length(Ops) == 2
```

## 10. WINDOWS EVENT LOG MONITORING

- Focus on privileged admin workstations and PowerShell logging (Script Block Logging, Module Logging) to capture heavy use of compliance cmdlets.

## 11. SYSMON DETECTION PATTERNS

- Detect PowerShell processes invoking `Connect-IPPSSession`, `New-ComplianceSearch`, or `New-ComplianceSearchAction`.

## 12. MICROSOFT DEFENDER FOR CLOUD / M365 DEFENDER

- Use Microsoft 365 Defender advanced hunting to monitor spikes in compliance search and export activity.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

- `Search-UnifiedAuditLog` with `Operations` = `New-ComplianceSearch`, `New-ComplianceSearchAction`, `Search-Mailbox` (on‑prem hybrid scenarios) to reconstruct who ran what search, when, and against which locations.

## 14. DEFENSIVE MITIGATIONS

- Strictly limit and regularly review membership of eDiscovery/Compliance/Admin role groups.
- Implement approvals and change management for any large or cross‑tenant content searches.

## 15. DETECTION & INCIDENT RESPONSE

- During incidents, always pull recent Unified Audit Logs focusing on ComplianceSearch operations to see whether an attacker staged email for export.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | Compromised admin or compliance account | Entry point. |
| **2** | Collection | **COLLECT-EMAIL-003 – Mail Search via PowerShell** | Targeted search across many mailboxes. |
| **3** | Exfiltration | Export PST + download | Final data theft. |

## 17. REAL-WORLD EXAMPLES

- Multiple public Office 365 BEC and espionage cases reference misuse of eDiscovery/Compliance Search to identify and steal high‑value mail content while staying below the radar of endpoint‑based monitoring.

---