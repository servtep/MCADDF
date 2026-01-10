# [COLLECT-ARCHIVE-001]: Archive Mailbox Data Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-ARCHIVE-001 |
| **MITRE ATT&CK v18.1** | Email Collection (T1114) – Remote Email Collection (T1114.002) applied to In-Place Archive / Recoverable Items |
| **Tactic** | Collection |
| **Platforms** | M365 (Exchange Online), Exchange 2013–2019 with In-Place Archive |
| **Severity** | High |
| **Technique Status** | ACTIVE (archive mailboxes and Recoverable Items can be exported via content search and specialized scripts) |
| **Last Verified** | 2024-09-30 |
| **Affected Versions** | Exchange Online; Exchange 2013–2019 with In-Place Archive enabled |
| **Patched In** | N/A – feature; risk controlled by RBAC, eDiscovery governance and retention policies |
| **Environment** | M365 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique focuses on **extraction of data from In-Place Archive mailboxes and Recoverable Items trees** (including Deletions, Purges, Versions). Archive mailboxes are often considered long‑term storage and may hold copies of messages no longer present in primary mailboxes. Adversaries with sufficient rights can use Purview Content Search, PowerShell scripts and compliance actions to collect archive content into PST files or discovery mailboxes.
- **Attack Surface:** Exchange Online archive mailboxes, Recoverable Items, and inactive mailboxes. Access is typically via eDiscovery/Compliance Search, but can also involve EWS or specialized PowerShell scripts that target archive folder IDs and build KQL folder queries.
- **Business Impact:** **Exposure of “hard‑to‑delete” historical communications thought to be safe in archive.** Archive mailboxes frequently contain sensitive legal and regulatory data. Successful extraction undermines retention strategies, allows reconstruction of long timelines and can reveal prior incidents, investigations or negotiations.
- **Technical Context:** In Exchange Online, content searches automatically process both primary and archive mailboxes by default. However, targeted collection of only the archive (or only Recoverable Items) usually requires **folder ID enumeration** and KQL queries that constrain the search. Community scripts exist that read mailbox folder statistics, identify archive folders and generate `folderid:` queries for use in `New-ComplianceSearch`. Attackers can abuse the same patterns to silently drain archive content.

### Operational Risk
- **Execution Risk:** Medium – Poorly scoped archive searches can be very large, impacting search queues and storage, but rarely cause direct service outage.
- **Stealth:** Medium – Archive exports are rarer than primary mailbox searches and can stand out if SOC monitors eDiscovery operations; however, they still look like legitimate admin work.
- **Reversibility:** Low – Once exported PSTs are downloaded, the archive data cannot be revoked. Deleting archive content may break legal hold/compliance and introduce additional risk.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | M365 / Exchange Online – mailbox retention and eDiscovery governance | Failure to govern archive access and export capabilities. |
| **DISA STIG** | O365 STIG – role-based access; legal hold | Over‑permissive archive/eDiscovery access violates separation of duties. |
| **CISA SCuBA** | Data retention and exfiltration protections | Inadequate monitoring of archive and inactive mailbox access. |
| **NIST 800-53** | AU-9, MP-5, AC-6 | Weak protection of archived audit/record data and excessive privileges. |
| **GDPR** | Art. 5, Art. 32 | Archive mailboxes often contain personal data beyond stated retention; uncontrolled export breaks principles of storage limitation and security. |
| **DORA** | Art. 9 | Archive of regulated communications must be controlled and monitored; mass export without governance is non‑compliant. |
| **NIS2** | Art. 21 | Poor safeguards for long‑term records and incident evidence in critical sectors. |
| **ISO 27001** | A.5, A.8.12, A.8.10 | Controls for retention, media protection, and logging of access to archived information. |
| **ISO 27005** | Misuse of archive/eDiscovery capabilities | High‑impact risk scenario for long‑term data stores.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Exchange Online / Purview: eDiscovery Manager, Compliance Administrator or equivalent roles to create and run content searches and exports.
- **Required Access:**
  - PowerShell access to Purview Compliance Center.
  - Browser access to Purview portal for export/download.

**Supported Versions:**
- Exchange Online with In-Place Archive and Purview Content Search.
- On‑prem Exchange 2013–2019 with archive mailboxes (similar concepts, but this module focuses on M365).

- **Tools:**
  - ExchangeOnlineManagement / Compliance PowerShell.
  - Community scripts that enumerate archive folders and build `folderid:` KQL queries.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell – Discover Archive Mailboxes and Sizes
```powershell
Connect-ExchangeOnline

# List mailboxes with archive enabled
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ArchiveStatus -eq 'Active' } |
  Select-Object DisplayName,PrimarySmtpAddress,ArchiveName,ArchiveQuota

# Optional: get archive sizes (can be expensive)
Get-MailboxStatistics -Archive -Identity user@tenant.onmicrosoft.com |
  Select-Object DisplayName, TotalItemSize, ItemCount
```

**What to Look For:**
- High‑value accounts (executives, legal, compliance) with large archives.
- Inactive mailboxes on hold or preserved for litigation.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Purview Content Search Targeting Archive Mailboxes

**Supported Versions:** Exchange Online.

#### Step 1: Enumerate Archive Folder IDs (Scripted)
**Objective:** Build a KQL query that restricts search to archive mailbox folders.

**Concept:** Community scripts use `Get-MailboxFolderStatistics -Archive` to enumerate folders, then transform the folder IDs into KQL `folderid:` tokens consumable by Content Search.

**Example (high‑level PowerShell pattern):
```powershell
Connect-ExchangeOnline

$emailAddress = 'user@tenant.onmicrosoft.com'
$folderStats = Get-MailboxFolderStatistics -Identity $emailAddress -Archive

# Filter to Recoverable Items or specific archive folders
$targetFolders = $folderStats | Where-Object { $_.FolderPath -like '*Recoverable Items*' }

# For each folder, build folderid: query terms from the FolderId/FolderType
# (actual scripts convert the HexEntryId to the base64 ID expected by KQL)
```

Attacker uses published scripts that output a full `folderid:("id1" OR "id2" ...)` expression.

#### Step 2: Create Archive‑Only Compliance Search
**Objective:** Use folderid‑based KQL to search only archive content.

**Command (pattern):**
```powershell
Connect-IPPSSession

$kql = 'folderid:("<ArchiveFolderId1>" OR "<ArchiveFolderId2>")'

New-ComplianceSearch -Name 'User-Archive-Only' `
  -ExchangeLocation 'user@tenant.onmicrosoft.com' `
  -ContentMatchQuery $kql

Start-ComplianceSearch -Identity 'User-Archive-Only'
```

**Expected Output:**
- Search processes only the user’s archive folders as defined in the KQL.

#### Step 3: Export Search Results (Archive PST)
**Objective:** Stage archive‑only data for download.

**Command:**
```powershell
New-ComplianceSearchAction -SearchName 'User-Archive-Only' -Export -ExchangeArchiveFormat PerUserPST

Get-ComplianceSearchAction -SearchName 'User-Archive-Only' -Action Export
```

**Expected Output:**
- Purview portal exposes an export with PST containing archive data.

**OpSec & Evasion:**
- Name searches and exports to look like routine compliance or backup operations.
- Limit scope (per‑user or small set of mailboxes) to avoid massive jobs.

**References & Proofs:**
- Microsoft and community documentation on exporting In-Place Archive mailboxes to PST with content search and PowerShell helper scripts.

### METHOD 2 – Targeted Collection of Recoverable Items

**Supported Versions:** Exchange Online with archive/Recoverable Items.

**Objective:** Abuse the fact that Recoverable Items may contain deleted messages not visible in the normal mailbox view, but still discoverable by eDiscovery.

**High‑Level Pattern:**
1. Use a helper script to identify folder IDs for `Recoverable Items`, `Purges`, `Versions`.
2. Build a `folderid:` KQL query for these IDs.
3. Run `New-ComplianceSearch` constrained to those folder IDs.
4. Export and download results.

This allows an adversary to recover messages that users attempted to delete permanently.

## 6. ATTACK SIMULATION & VERIFICATION

- Use lab tenants with archive mailboxes and run Microsoft’s sample or community scripts to validate the ability to target archive / Recoverable Items only.

## 7. TOOLS & COMMANDS REFERENCE

- **ExchangeOnlineManagement** for mailbox and folder statistics.
- **Purview / Compliance PowerShell** for content search and export.
- Community scripts for folder ID translation (for example, targeted collections of Recoverable Items and inactive mailbox data).

## 8. SPLUNK DETECTION RULES

#### Rule 1: Archive‑Focused Content Searches
**Concept:** Detect Purview content searches whose KQL includes `folderid:` or that explicitly reference archive/inactive mailboxes.

**SPL Pattern (pseudo):**
```spl
index=o365 Workload="SecurityComplianceCenter" Operation="New-ComplianceSearch"
| eval query=coalesce(ContentMatchQuery, Query)
| where like(query, "%folderid:%") OR like(query, "%Recoverable Items%")
| stats count BY UserId, Name, query
```

## 9. MICROSOFT SENTINEL DETECTION

- Similar logic using `OfficeActivity` table where `Operation == "New-ComplianceSearch"` and `AuditData` contains `folderid:` or well‑known archive folder names.

## 10. WINDOWS EVENT LOG MONITORING

- Archive extraction is primarily a **cloud‑side** phenomenon; focus on Purview/Exchange logs rather than Windows Security logs.

## 11. SYSMON DETECTION PATTERNS

- Use Sysmon/EDR to detect large downloads from the Purview export service to admin workstations (huge .pst/.zip files), but this overlaps with general data exfiltration detection.

## 12. MICROSOFT DEFENDER FOR CLOUD / M365 DEFENDER

- Configure alerts for high‑volume or unusual eDiscovery exports, especially involving inactive or archive mailboxes.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

- Use `Search-UnifiedAuditLog` with `Operations` including `New-ComplianceSearch`, `New-ComplianceSearchAction`, and inspect `AuditData` for `ExchangeLocation` entries pointing to archive/inactive mailboxes and for KQL containing `folderid:`.

## 14. DEFENSIVE MITIGATIONS

- Restrict eDiscovery and archive access roles to a very small, monitored group.
- Document and preapprove archive export workflows; alert on any deviation.
- Use legal hold and retention policies carefully to avoid creating excessive long‑term data that is not strictly required.

## 15. DETECTION & INCIDENT RESPONSE

- During incident response, always check whether the attacker accessed archive mailboxes or Recoverable Items via Purview searches.
- Correlate large Purview exports with endpoint download activity and external transfers.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | Compromised admin/compliance account | Attacker gains required roles. |
| **2** | Collection | COLLECT-EMAIL-001 / COLLECT-EMAIL-003 | Primary mailbox or search‑based collection. |
| **3** | Collection (Archive) | **COLLECT-ARCHIVE-001 – Archive Mailbox Data Extraction** | Targeted archive/Recoverable Items export. |
| **4** | Exfiltration | PST download + transfer | Archive data leaves tenant. |

## 17. REAL-WORLD EXAMPLES

- Real tenant‑to‑tenant migration and backup scenarios show exactly how archive and Recoverable Items can be exported using content search and PST export tools. Adversaries can repurpose the same workflows to silently drain archives once they control an eDiscovery‑capable account.

---