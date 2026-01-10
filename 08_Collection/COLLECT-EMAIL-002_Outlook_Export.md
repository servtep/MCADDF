# [COLLECT-EMAIL-002]: Outlook Mailbox Export

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-EMAIL-002 |
| **MITRE ATT&CK v18.1** | Local Email Collection (T1114.001) |
| **Tactic** | Collection |
| **Platforms** | Windows endpoint with Outlook (M365 Apps / Outlook 2013+), M365 backend mailbox |
| **Severity** | High |
| **Technique Status** | ACTIVE (local PST export fully supported; detection and controls vary) |
| **Last Verified** | 2024-09-30 |
| **Affected Versions** | Outlook 2013, 2016, 2019, Microsoft 365 Apps on Windows 10/11; Exchange Online / on‑prem Exchange as mailbox source |
| **Patched In** | N/A – feature working as designed; risk mitigated via DLP, rights management, and endpoint controls |
| **Environment** | M365 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique covers **local mailbox export** from Outlook to `.pst` or secondary data files. Adversaries with access to a workstation profile configured for a target mailbox can use Outlook’s Import/Export wizard, manual PST creation, or scripted approaches to export all or selected folders. The resulting PST or OST files can then be staged and exfiltrated, representing classic **local email collection** under T1114.001.
- **Attack Surface:** Outlook desktop client profiles (cached `.ost` and `.pst`), local profile directories, removable media, and user‑initiated exports via the Outlook GUI or add‑ins. On‑prem or cloud mailboxes are equally exposed once synchronized locally.
- **Business Impact:** **Full offline copy of a user’s mailbox, including historical mail and attachments.** Attackers can walk away with multi‑year communications, contracts, legal discussions, and internal decision‑making, with little or no visibility from server‑side logs if exfiltration happens over non‑corporate channels (USB, personal cloud, print). 
- **Technical Context:** Local collection hinges on an already configured Outlook profile or the ability to add one. Once the OST/PST exists, standard filesystem access is enough to copy or compress data. While Unified Audit Logs record mailbox access, they **do not** log local file copying. Detection therefore relies on **endpoint telemetry** (Sysmon, EDR), DLP, and controls preventing PST creation or access to profile paths.

### Operational Risk
- **Execution Risk:** Low – Exporting PST via Outlook is a normal user operation and rarely causes service issues.
- **Stealth:** High – Local PST exports look like routine user behavior, especially for roles that legitimately archive email.
- **Reversibility:** Low – Once the PST file is copied externally, it cannot be revoked. Deleting local PSTs only reduces further leakage.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Windows Endpoint Hardening | Failure to control PST export and removable storage allows uncontrolled copies of regulated communications. |
| **DISA STIG** | MS Outlook / Windows 10 STIG – removable media, data at rest | Weak control of local mail stores and USB usage conflicts with DoD data handling requirements. |
| **CISA SCuBA** | Endpoint & SaaS data exfiltration safeguards | Lack of DLP and EDR around PST/OST files undermines secure baseline guidance. |
| **NIST 800-53** | AC-3, MP-5, SC-28 | Inadequate access control and media protection for local email archives. |
| **GDPR** | Art. 5, Art. 32 | Exporting full mailboxes to unmanaged PSTs breaches data minimization and security of processing. |
| **DORA** | Art. 9 | Uncontrolled export of regulated communications violates ICT security and monitoring obligations. |
| **NIS2** | Art. 21 | Lack of technical and organizational measures to control offline copies of critical communications. |
| **ISO 27001** | A.5, A.8.12, A.8.14, A.8.16 | Missing controls for removable media, local storage of sensitive information and endpoint hardening. |
| **ISO 27005** | Insider data exfiltration via local email archives | High‑impact insider threat scenario requiring explicit treatment.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Interactive access to a Windows workstation where the victim’s mailbox is configured in Outlook.
  - For some scripted exports, local admin may be required to install tools or disable controls.
- **Required Access:**
  - Logged‑on Windows session with access to Outlook profile.
  - Ability to create PST files in local or network paths.

**Supported Versions:**
- **Windows:** 10, 11.
- **Outlook:** 2013, 2016, 2019, Microsoft 365 Apps for enterprise.
- **Exchange:** Exchange Online, Exchange 2013–2019.

- **Tools:**
  - Native **Outlook Import/Export wizard**.
  - Optional: Forensic tools or scripts to copy `.pst` / `.ost` files directly.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance (Local Endpoint)
```powershell
# List Outlook data files for current user
$paths = @(
  "$env:USERPROFILE\Documents\Outlook Files",
  "$env:LOCALAPPDATA\Microsoft\Outlook"
)

Get-ChildItem -Path $paths -Filter *.pst -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime

Get-ChildItem -Path $paths -Filter *.ost -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
```

**What to Look For:**
- Large `.pst` or `.ost` files (hundreds of MB or GB) indicating full mailbox caches.
- Recently created PSTs in non‑standard locations (for example, desktop, temp, user‑created folders).

**Version Note:**
- Paths are consistent across Outlook 2013+ on Windows 10/11.

#### Linux/Bash / CLI Reconnaissance (Remote Collection via SMB)
```bash
# From a Linux host with access to user profile shares
find /mnt/usershares -iname "*.pst" -o -iname "*.ost" -size +100M
```

**What to Look For:**
- Centralized or redirected folders containing large mail archives ready for exfiltration.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Outlook GUI Export to PST

**Supported Versions:** Outlook 2013–2019, Microsoft 365 Apps.

#### Step 1: Launch Export Wizard
**Objective:** Start the Outlook Import/Export wizard.

**Command / Actions:**
- Open Outlook.
- Go to **File → Open & Export → Import/Export**.
- Choose **Export to a file** → **Next**.

**Expected Output:**
- Import/Export wizard with file export options.

**What This Means:**
- Operator is about to create a PST containing mailbox data.

#### Step 2: Select Mailbox and Destination
**Objective:** Export entire mailbox (or selected folders) into PST.

**Actions:**
1. In the wizard, choose **Outlook Data File (.pst)** → **Next**.
2. Select the root mailbox and tick **Include subfolders**.
3. Click **Next**, choose a destination folder (for example, `C:\Users\Public\Exports\user_mailbox.pst`).
4. Choose handling for duplicates and click **Finish**.
5. Optionally set a PST password (attackers typically leave this blank).

**Expected Output:**
- A PST file appears at the chosen path; Outlook status bar may show export progress.

**OpSec & Evasion:**
- Run exports outside business hours to avoid user noticing UI changes.
- Store PST in benign‑looking directory (shared working folder) before exfiltration.

**Troubleshooting:**
- Organization may disable PST export via Group Policy; attackers may then pivot to direct `.ost` / `.pst` copying.

**References & Proofs:**
- Microsoft Support – *Export emails, contacts, and calendar items to Outlook using a PST file*.

### METHOD 2 – Direct Copy of OST/PST for Later Processing

**Supported Versions:** All Outlook on Windows with cached mode.

#### Step 1: Identify Data Files
**Objective:** Locate mailbox cache and archive files on disk.

**Command:**
```powershell
$paths = @(
  "$env:USERPROFILE\Documents\Outlook Files",
  "$env:LOCALAPPDATA\Microsoft\Outlook"
)
Get-ChildItem -Path $paths -Include *.pst,*.ost -Recurse -ErrorAction SilentlyContinue
```

#### Step 2: Stage and Compress
**Objective:** Stage files for exfiltration.

**Command:**
```powershell
$src = "$env:LOCALAPPDATA\Microsoft\Outlook"
$dst = 'C:\Temp\OutlookDump'
New-Item -ItemType Directory -Path $dst -Force | Out-Null

Copy-Item -Path (Join-Path $src '*.ost') -Destination $dst -Force
Compress-Archive -Path "$dst\*" -DestinationPath 'C:\Temp\mailbackup.zip' -Force
```

**Expected Output:**
- `mailbackup.zip` containing entire local mailbox cache.

**OpSec & Evasion:**
- Use encryption (for example, 7‑Zip with password) before upload to external storage.
- Wipe temporary paths and use secure deletion if possible.

**Troubleshooting:**
- OST may be locked by Outlook; attackers may kill Outlook process or export outside business hours.

**References & Proofs:**
- MITRE ATT&CK T1114.001 – Local Email Collection (PST/OST theft).

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Atomic Test ID:** T1114.001 – Local Email Collection.
- **Test Name:** Search and compress Outlook data files.
- **Description:** Script locates `.pst` / `.ost` and creates an archive to emulate collection.
- **Supported Versions:** Windows endpoints with Outlook.
- **Command:**
  ```powershell
  Invoke-AtomicTest T1114.001 -TestNumbers 1
  ```
- **Cleanup Command:**
  ```powershell
  Invoke-AtomicTest T1114.001 -TestNumbers 1 -Cleanup
  ```
- **Reference:** Atomic Red Team – T1114.001 Local Email Collection.

## 7. TOOLS & COMMANDS REFERENCE

#### Outlook Import/Export Wizard

**Supported Platforms:** Outlook on Windows.

**Usage:**
- File → Open & Export → Import/Export → Export to a file → Outlook Data File (.pst).

#### Script (One-Liner) – PST/OST Discovery
```powershell
Get-ChildItem "$env:USERPROFILE" -Include *.pst,*.ost -Recurse -ErrorAction SilentlyContinue `
  | Sort-Object Length -Descending `
  | Select-Object -First 20 FullName, Length
```

## 8. SPLUNK DETECTION RULES

#### Rule 1: Large PST/OST Creation on Endpoints
**Rule Configuration:**
- **Required Index:** Endpoint/EDR index.
- **Required Sourcetype:** Process/File events (for example, Sysmon, EDR telemetry).
- **Required Fields:** `Image`, `TargetFilename`, `ProcessGuid`, `User`.
- **Alert Threshold:** New PST/OST over 500 MB created outside business hours.

**SPL Query (Sysmon example):**
```spl
index=endpoint sourcetype=sysmon (TargetFilename="*.pst" OR TargetFilename="*.ost")
| stats latest(_time) AS last_seen, values(Image) AS processes, values(User) AS users, sum(FileSize) AS total_bytes BY TargetFilename
| where total_bytes > 500000000
```

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Local PST Creation (via Defender for Endpoint data)
**Rule Configuration:**
- **Required Table:** `DeviceFileEvents`.
- **Required Fields:** `FileName`, `FolderPath`, `FileSize`, `InitiatingProcessFileName`.
- **Alert Severity:** Medium/High.

**KQL Query:**
```kusto
DeviceFileEvents
| where FileName endswith '.pst' or FileName endswith '.ost'
| summarize TotalSize = max(FileSize),
            Processes = make_set(InitiatingProcessFileName),
            Hosts      = make_set(DeviceName)
  by FileName, FolderPath, bin(Timestamp, 1h)
| where TotalSize > 500000000
```

## 10. WINDOWS EVENT LOG MONITORING

- Focus on Sysmon / EDR rather than native event IDs for file creation. Enable advanced auditing for file system where possible and forward to SIEM.

## 11. SYSMON DETECTION PATTERNS

```xml
<RuleGroup name="PST Creation" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename condition="ends with">.pst</TargetFilename>
    <TargetFilename condition="contains">Outlook Files</TargetFilename>
  </FileCreate>
</RuleGroup>
```

## 12. MICROSOFT DEFENDER FOR CLOUD / M365 DEFENDER

- Use Defender for Endpoint policies to block or audit access to PST/OST in high‑risk scenarios and enforce DLP for email content.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

- Server‑side logs do not capture local PST copying, but they may show if the user recently signed in or performed mailbox searches prior to local export.

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL
* Disable PST export where possible via Group Policy and Outlook administrative templates.
* Enforce endpoint DLP policies inspecting PST/OST writes and transfers.

#### Priority 2: HIGH
* Restrict Outlook cached mode for high‑risk roles; prefer OWA with server‑side logging.
* Use EDR to monitor large file creations and USB writes involving PST/OST.

## 15. DETECTION & INCIDENT RESPONSE

- Treat unexpected large PST/OST creation and movement to removable media or personal cloud as potential exfiltration.
- Capture full disk images and memory from compromised endpoints when investigating.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | Compromised workstation/profile | Attacker gains interactive access. |
| **2** | Collection | **COLLECT-EMAIL-002 – Outlook Mailbox Export** | Local PST/OST export. |
| **3** | Exfiltration | Data staging and transfer | PST/OST moved to external destination. |

## 17. REAL-WORLD EXAMPLES

#### Example 1: Energy Sector Intrusions (Local Email Collection)
- Threat actors collected local Outlook address books and mail archives to fuel future phishing and lateral targeting, as documented under T1114.001 scenarios.

#### Example 2: Insider Exfiltration via PST Export
- Multiple insider‑threat cases involve employees exporting their mailbox to PST before resignation and taking contracts and customer lists to competitors.

---