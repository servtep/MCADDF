# [MISCONFIG-009]: Disabled Audit Logging

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-009 |
| **MITRE ATT&CK v18.1** | [T1562.002 – Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) / [T1562.008 – Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Multi-Env (Windows Server/Endpoint, Windows AD, Entra ID, Azure, Microsoft 365) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All supported Windows client/server versions; Entra ID (all SKUs); Azure Subscriptions; Microsoft 365 tenants |
| **Patched In** | N/A (configuration-based risk; mitigated by policy and hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Disabled or impaired audit logging is a critical misconfiguration and defense-evasion enabler where host, cloud, or SaaS logging is intentionally or accidentally turned off, selectively filtered, or prevented from reaching central SIEM. This includes disabling Windows Event Logging with `auditpol`, `wevtutil` or service tampering, turning off Microsoft 365 Unified Audit Log ingestion, and removing Azure/Entra diagnostic settings and connectors. Once visibility is lost, attackers can perform credential theft, privilege escalation, and data exfiltration with minimal forensic trace.
- **Attack Surface:** Windows Event Log service, Local/Domain Audit Policy, Sysmon, Entra ID sign-in and audit logs, Azure Resource diagnostic settings, Microsoft 365 Unified Audit Log, SIEM ingestion pipelines and connectors.
- **Business Impact:** **Severe loss of visibility and regulatory non-compliance.** Incident reconstruction, root-cause analysis, and breach notification become unreliable or impossible, directly impacting regulatory duties (GDPR, NIS2, DORA) and insurance claims. Undetected persistence, lateral movement, and data theft are significantly more likely.
- **Technical Context:** Disabling or degrading logging typically requires high privilege (Local Admin, Domain Admin, Global Admin, Security Admin, Subscription Owner). Well-configured EDR/SIEM can still detect the disabling attempt itself, but if successful, subsequent actions may be nearly invisible. Typical indicators are abrupt drops in event volume, log gaps, and configuration changes on logging endpoints.

### Operational Risk
- **Execution Risk:** High – changes are usually persistent, tenant wide, and may impact legal defensibility of investigations.
- **Stealth:** Medium/High – once logs are disabled, subsequent activity is very hard to detect; however, the disabling action can itself be monitored.
- **Reversibility:** Partial – configuration can be re-enabled, but historical events during the blind period are unrecoverable.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Controls v8 8.2 / 8.3 | Collect and centralize audit logs, protect logging configuration from unauthorized changes. |
| **DISA STIG** | AU-0001 / AU-0002 (Win/AD STIG families) | Ensure audit policy is enabled and modification of audit configuration is restricted. |
| **CISA SCuBA** | Logging Baseline LB-1, LB-2 | Require cloud and SaaS audit logging, prohibit disabling of mailbox and admin logs. |
| **NIST 800-53** | AU-2, AU-6, AU-9 | Event logging, audit review, and protection of audit information from modification. |
| **GDPR** | Art. 5, 30, 32 | Accountability and security of processing; inability to trace access hinders breach notification and DPIA. |
| **DORA** | Art. 9, 10 | ICT monitoring and logging controls for incident detection and reporting. |
| **NIS2** | Art. 21 | Technical and operational measures including logging and event monitoring. |
| **ISO 27001** | A.8.16, A.8.15 | Logging, monitoring, and protection of log information against tampering. |
| **ISO 27005** | Risk Scenario | Loss of logging leading to undetected compromise and incomplete forensic evidence.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Windows: Local Administrator / Domain Administrator to change audit policy or EventLog service.
  - Entra ID / M365: Global Admin, Security Admin, or role with Audit / OrgConfig / DiagnosticSettings write permissions.
  - Azure: Subscription Owner, Contributor, or Monitoring Contributor to modify diagnostic settings and data connectors.

- **Required Access:**
  - Windows hosts reachable via RDP/WinRM or local console.
  - Azure / Entra / M365 admin portals or PowerShell/CLI API access.

**Supported Versions:**
- **Windows:** Client (10, 11) and Server (2016, 2019, 2022, 2025).
- **PowerShell:** 5.1+ (Windows), 7.x (Core) for cloud automation.
- **Cloud:** All current Entra ID, Azure, and Microsoft 365 SKUs.

- **Tools:**
  - `auditpol.exe` (built-in Windows audit policy management).
  - `wevtutil.exe` (built-in Windows Event Log management).
  - PowerShell (`Set-AdminAuditLogConfig`, `Get-AdminAuditLogConfig`) for M365 Unified Audit Log.
  - Azure PowerShell / Azure CLI for diagnostic settings and Log Analytics connections.
  - Microsoft Sentinel / third-party SIEM (Splunk, etc.) for detection and alerting.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance (Windows)

```powershell
# Check high-level audit policy status on a Windows host
auditpol /get /category:* | Where-Object { $_ -match 'No Auditing' }
```

**What to Look For:**
- Categories showing `No Auditing` for critical areas (Logon, Account Logon, Object Access, Policy Change, Privilege Use, Directory Service Access, Process Creation).
- Baselines where advanced audit policy is expected but disabled.

**Version Note:** `auditpol` syntax is consistent from Server 2012 R2 onward; older systems may lack some subcategories.

**Command (Server 2016–2019):**
```powershell
# Check if the EventLog service is disabled or stopped
Get-Service -Name EventLog | Select-Object Name,Status,StartType
```

**Command (Server 2022+):**
```powershell
Get-Service -Name EventLog | Select-Object Name,Status,StartType

# Check for Autologger tampering (Security log)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" |
  Select-Object Start, Enabled
```

### Entra ID / M365 Logging Recon

```powershell
# Check Microsoft 365 Unified Audit Log ingestion
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled

# Entra ID sign-in & audit log export (Sentinel/Log Analytics)
Get-AzDiagnosticSetting -ResourceId "/providers/microsoft.aadiam/diagnosticSettings/azureaddiaglogs" 2>$null
```

**What to Look For:**
- `UnifiedAuditLogIngestionEnabled : False` indicates tenant-level Unified Audit Log disabled.
- Missing or disabled diagnostic settings for Entra ID, Key Vault, Storage, SQL, and other critical resources.

### Azure / Log Analytics Recon (CLI)

```bash
# List diagnostic settings on a key resource (example: Key Vault)
az monitor diagnostic-settings list \
  --resource /subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<kv-name>
```

**What to Look For:**
- No diagnostic settings at all.
- Diagnostic settings present but with all log categories disabled or no destination (Log Analytics / Event Hub / Storage) configured.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Disable Windows Event Logging on Endpoint / Server

**Supported Versions:** Windows 10/11; Windows Server 2016–2025.

#### Step 1: Disable Key Audit Categories Using `auditpol`
**Objective:** Turn off auditing for sensitive categories (e.g. Logon, Account Logon, Policy Change) to reduce visibility.

**Command (All supported versions):**
```powershell
# Disable auditing for Account Logon events (success and failure)
auditpol /set /category:"Account Logon" /success:disable /failure:disable

# Clear all audit policy (extreme case)
auditpol /clear /y
```

**Expected Output:**
- `The command was successfully executed.` messages.

**What This Means:**
- Subsequent authentication and policy change events will no longer generate Security log entries for those categories.

**OpSec & Evasion:**
- `auditpol` execution is itself logged (e.g. Event ID 4719 – System audit policy was changed) and may be detected by SIEM or EDR.
- Attackers may combine with log-clearing (Event ID 1102) and service tampering to further hide activity.

**Troubleshooting:**
- **Error:** `Access is denied.`
  - **Cause:** User is not elevated.
  - **Fix:** Run PowerShell or CMD as Administrator / use a privileged session.

**References & Proofs:**
- Microsoft documentation on `auditpol.exe` usage.
- MITRE ATT&CK T1562.002 examples of disabling event logging.

#### Step 2: Disable Windows EventLog Service and Channels
**Objective:** Stop or disable the Windows Event Log service and/or individual log channels.

**Command (Service stop – all versions):**
```powershell
Stop-Service -Name EventLog -Force

# Or configure service not to start automatically
sc.exe config EventLog start= disabled
```

**Command (Disable individual channels via `wevtutil`):**
```powershell
# Example: disable Microsoft-Windows-Security-Auditing channel
wevtutil sl Security /e:false
```

**Expected Output:**
- `wevtutil` returns success; Security log stops receiving new events.

**OpSec & Evasion:**
- Attempts may be recorded in Sysmon (if present) and in EDR telemetry even when native logs are disabled.
- Many security products directly protect the EventLog service and may block or alert.

**Troubleshooting:**
- **Error:** `Access is denied` or `The requested control is not valid for this service.`
  - **Cause:** Insufficient privileges or service protection.
  - **Fix:** Confirm Local Admin and check for EDR self-protection features.

**References & Proofs:**
- Atomic Red Team tests for T1562.002 (Disable Windows Event Logging).
- Splunk Security Content detection `Disable Logs Using WevtUtil`.

### METHOD 2 – Disable Microsoft 365 Unified Audit Logging

**Supported Versions:** All Microsoft 365 tenants with Exchange Online.

#### Step 1: Turn Off Unified Audit Log Ingestion
**Objective:** Stop tenant-wide ingestion of user and admin events into the Unified Audit Log.

**Command:**
```powershell
Connect-ExchangeOnline

# Disable Unified Audit Log ingestion
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false

# Verify
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

**Expected Output:**
- `UnifiedAuditLogIngestionEnabled : False`.

**What This Means:**
- New activities from Azure AD, Exchange, SharePoint, Teams and other workloads will not be written into the Unified Audit Log, breaking many SIEM and compliance workflows.

**OpSec & Evasion:**
- Operation is itself auditable if logs were active beforehand and exported to an external SIEM; once disabled, subsequent admin actions will not appear.

**Troubleshooting:**
- **Error:** `You must be assigned the Audit Logs role to enable or disable auditing.`
  - **Fix:** Grant appropriate Exchange Online RBAC or use an account in Compliance Management / Organization Management.

**References & Proofs:**
- Exchange Online `Set-AdminAuditLogConfig` documentation.
- Security blogs warning against disabling Unified Audit Log.

### METHOD 3 – Disable or Break Cloud Diagnostic and SIEM Connectors

**Supported Versions:** Entra ID, Azure subscriptions, Microsoft Sentinel, third-party SIEM.

#### Step 1: Remove or Modify Azure Diagnostic Settings
**Objective:** Prevent audit and sign-in logs from reaching Log Analytics, Event Hub, or external SIEM.

**Command (Azure CLI):**
```bash
# Remove diagnostic settings from Entra ID logs (example name)
az monitor diagnostic-settings delete \
  --name azureaddiaglogs \
  --resource /providers/microsoft.aadiam/diagnosticSettings/azureaddiaglogs
```

**Command (PowerShell – disable logs but keep setting):**
```powershell
$rg = "<rg>"
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name "<lawName>"

# Recreate setting with metrics only, no logs
disable-azdiagnosticsetting -Name 'azureaddiaglogs' # pseudo-example; actual implementation uses New-AzDiagnosticSetting with logs disabled
```

**Expected Output:**
- Diagnostic settings removed or recreated without relevant log categories.

**What This Means:**
- SIEM stops receiving Entra, Key Vault, Storage, or SQL logs; centralized monitoring is blind.

#### Step 2: Disable or Misconfigure Microsoft Sentinel Data Connectors
**Objective:** Break ingestion from M365 Defender, Entra, or other sources to Sentinel.

**Outline (Portal):**
1. Azure Portal → Microsoft Sentinel → Workspace → Data connectors.
2. Open a connector (for example: Microsoft 365 Defender, Azure AD). 
3. Turn off log types or disconnect the connector.

**OpSec & Evasion:**
- Sentinel Health table (`SentinelHealth`) and Defender/MDA activity logs can detect connector failures and configuration changes if monitored.

**References & Proofs:**
- Microsoft documentation on diagnostic settings and Sentinel health monitoring.
- Community blogs on detecting diagnostic setting changes with KQL.

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team
- **Atomic Test ID:** Multiple for T1562.002 (for example, `T1562.002-test1` through `test7`).
- **Test Name:** Disable Windows Event Logging.
- **Description:** Simulates disabling event logging on Windows hosts via `wevtutil`, `auditpol`, and service configuration.
- **Supported Versions:** Windows 10/11, Server 2016+.
- **Command:**
  ```powershell
  Invoke-AtomicTest T1562.002 -TestNumbers 1,2,3,4,5,6,7
  ```
- **Cleanup Command:**
  ```powershell
  Invoke-AtomicTest T1562.002 -TestNumbers 1,2,3,4,5,6,7 -Cleanup
  ```
**Reference:** Atomic Red Team GitHub – T1562.002.

## 7. TOOLS & COMMANDS REFERENCE

### `auditpol.exe`

**Supported Platforms:** Windows client and server.

**Usage:**
```powershell
# View all categories
auditpol /get /category:*

# Disable logon auditing
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
```

### `wevtutil.exe`

**Usage:**
```cmd
# Disable a specific channel
wevtutil sl Security /e:false

# Clear a log
wevtutil cl Security
```

### `Set-AdminAuditLogConfig` (Exchange Online)

**Usage:**
```powershell
Connect-ExchangeOnline
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false
```

### Azure CLI Diagnostic Settings

```bash
az monitor diagnostic-settings list --resource <resource-id>
az monitor diagnostic-settings delete --name <setting-name> --resource <resource-id>
```

## 8. SPLUNK DETECTION RULES

### Rule 1: Disable Event Logging via `wevtutil`
**Rule Configuration:**
- **Required Index:** `win*` or EDR index.
- **Required Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` or process telemetry.
- **Required Fields:** `process_name`, `process`, `process_path`, `command_line`.
- **Alert Threshold:** Any match (high fidelity).

**SPL Query:**
```spl
index=win* (sourcetype="*sysmon*" OR sourcetype="XmlWinEventLog:*")
| where process_name="wevtutil.exe" OR process="wevtutil.exe"
| search command_line="*sl*" command_line="*/e:false*" OR command_line="*cl security*"
| stats count values(command_line) by host, user, process_name, _time
```

**What This Detects:**
- Execution of `wevtutil.exe` with parameters used to disable or clear logs.

### False Positive Analysis
- **Legitimate Activity:** Rare administrative troubleshooting; should be approved change.
- **Tuning:**
  - Exclude known administrative jump hosts and service accounts by host/user.
  - Require additional context: concurrent privileged logon, script name, or change ticket ID in CMDB.

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Disable Windows Event Logs via `wevtutil` or `auditpol`

**Rule Configuration:**
- **Required Table:** `DeviceProcessEvents` (MDE) or `SecurityEvent` / `Sysmon` tables.
- **Alert Severity:** High.
- **Frequency:** Every 5 minutes, lookback 1 hour.

**KQL Query (MDE example):**
```kusto
DeviceProcessEvents
| where FileName in ("wevtutil.exe","auditpol.exe")
| where ProcessCommandLine has_any ("cl security", "/clear /y", "/set /category", " /e:false")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Manual Configuration Steps (Azure Portal):**
1. Azure Portal → Microsoft Sentinel → Workspace → Analytics.
2. Create a new Scheduled query rule.
3. Paste the KQL query, set frequency 5 minutes, lookback 1 hour.
4. Set Severity to High and enable incident creation.

### Query 2: Entra / Azure Diagnostic Settings Changed

**KQL (CloudAppEvents via M365 Defender connector):**
```kusto
CloudAppEvents
| where Application == "Microsoft Azure"
| where ActivityObjects[1].Name contains "microsoft.aadiam/diagnosticSettings"
| where ActionType in ("Write DiagnosticSettings","Delete DiagnosticSettings")
| extend Status = tostring(ActivityObjects[4].Value)
| where Status == "Succeeded"
| project TimeGenerated, User=UserId, ActionType, ActivityObjects
```

**What This Detects:**
- Successful write or delete of Entra ID diagnostic settings that can break log export.

## 10. WINDOWS EVENT LOG MONITORING

**Key Event IDs:**
- **4719** – System audit policy was changed.
- **1102** – The audit log was cleared.
- **1100/1101** – The event logging service has shut down / started.

**Manual Configuration Steps (Group Policy):**
1. Open `gpmc.msc`.
2. Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration.
3. Enable and configure:
   - Audit Policy Change.
   - Audit System Events.
   - Audit Logon/Logoff.
4. Set to Success and Failure.
5. Apply GPO and run `gpupdate /force`.

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Example Config Snippet (Registry change to disable channels):**
```xml
<RuleGroup name="EventLog Tampering" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">\Microsoft\Windows\CurrentVersion\WINEVT\Channels\</TargetObject>
    <TargetObject condition="ends with">\Enabled</TargetObject>
    <Details condition="is">DWORD (0x00000000)</Details>
  </RegistryEvent>
</RuleGroup>
```

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts
- **Alert Name:** Suspicious disablement of diagnostic settings / Missing diagnostic settings for critical resources.
- **Severity:** High.
- **Description:** Defender for Cloud raises recommendations when diagnostic settings are missing or disabled for key resources (Entra ID, Key Vault, SQL, Storage).

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Azure Portal → Microsoft Defender for Cloud → Environment settings.
2. Enable Defender plans for Servers, SQL, and relevant PaaS services.
3. Review Recommendations and enable policies for mandatory diagnostic settings.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Unified Audit Log Configuration Changes
```powershell
Search-UnifiedAuditLog -Operations Set-AdminAuditLogConfig -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
```
- **Operation:** `Set-AdminAuditLogConfig`.
- **Details:** Inspect the `AuditData` blob for changes to `UnifiedAuditLogIngestionEnabled`.

**Manual Steps:**
1. Purview → Audit → Search.
2. Filter on Activities: `Set-AdminAuditLogConfig`.
3. Filter on admin users and time range.

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Non-Bypassable Logging Baseline:**
  - Enforce advanced audit policy GPOs that cannot be disabled by local admins (enforced GPO, no local override).
  - Deploy Sysmon with a locked configuration.

- **Tenant-Level Protections:**
  - Restrict who can modify diagnostic settings, SIEM connectors, and Unified Audit Log configuration using least-privilege RBAC.
  - Implement Privileged Identity Management (PIM) with approval and just-in-time elevation for roles that can modify logging.

- **Immutable Offloading:**
  - Stream critical logs (Security, Sysmon, Entra Sign-In, Audit, M365) to immutable storage or external SIEM where attackers with tenant admin rights have no delete permission.

### Priority 2: HIGH

- Implement continuous health monitoring for SIEM connectors and diagnostic settings.
- Require change tickets and documented approvals for any logging configuration change.

### Access Control & Policy Hardening
- Lock down `Set-AdminAuditLogConfig` to a very small number of accounts.
- Limit Azure `Monitoring Contributor` and `Owner` assignments.

### Validation Command (Verify Fix)
```powershell
# Windows audit policy baseline present
auditpol /get /category:* | Where-Object { $_ -match 'No Auditing' }

# Unified Audit Log enabled
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- **Files/Registry:**
  - Registry keys under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-*` with `Start = 0` or `Enabled = 0`.
- **Network / Cloud:**
  - Sudden stop of log ingestion from specific subscriptions or tenants.

### Forensic Artifacts
- Windows `Security.evtx`, `System.evtx`, and Sysmon logs showing last events before shutdown or clearing.
- Cloud activity logs showing diagnostic setting changes, connector deletions, or Unified Audit Log configuration changes.

### Response Procedures
1. **Isolate:**
   - Isolate suspected hosts from the network.
   - Lock down admin accounts that performed logging changes.
2. **Collect Evidence:**
   - Export remaining Windows event logs (`wevtutil epl`) and EDR telemetry.
   - Export Entra, Azure Activity, and M365 audit logs from any external SIEM or archive.
3. **Remediate:**
   - Reapply hardened logging baselines (GPO, Sysmon, diagnostic settings templates).
   - Rotate credentials and revoke privileged sessions.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Phishing, Valid Accounts | Adversary obtains privileged credentials. |
| 2 | Privilege Escalation | Token abuse, misconfig | Attacker escalates to DA / Global Admin / Subscription Owner. |
| 3 | Current Step | **MISCONFIG-009 – Disabled Audit Logging** | Logging is disabled or broken to create a blind spot. |
| 4 | Persistence & Lateral Movement | Credential theft, AD/Entra abuse | Attacker moves laterally with low chance of detection. |
| 5 | Impact | Data exfiltration, ransomware | Data theft or destructive actions execute with limited forensic trace. |

## 17. REAL-WORLD EXAMPLES

### Example 1: APT Activity in Microsoft 365
- **Scenario:** APT actor gained access to a Microsoft 365 tenant and disabled Purview auditing for specific VIP mailboxes before exfiltrating email data, aligned with MITRE sub-technique T1562.008.
- **Impact:** Exfiltration of sensitive mailbox content with severely degraded audit trail.

### Example 2: Ransomware Group Disables Windows Event Logs
- **Scenario:** Ransomware operators used `wevtutil` and `auditpol` across compromised servers to disable and clear Windows event logs before encrypting data.
- **Impact:** Highly constrained ability of DFIR teams to reconstruct lateral movement, initial access vector, and scope of compromise.

---