# [EVADE-IMPAIR-004]: Event Log Clearing

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-004 |
| **MITRE ATT&CK v18.1** | [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (detection highly reliable; prevention via remote log forwarding) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows 10/11 (all), Server 2016-2025 |
| **Patched In** | Remote event forwarding to SIEM; Volume Shadow Copy (VSS) retention; Tamper protection on logs |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Event Logs (Security, System, Application) record all user and system activity including login attempts, process creation, privilege escalation, and malware execution. Clearing these logs is a post-compromise cleanup technique that destroys forensic evidence of the entire attack. Methods include using `wevtutil`, PowerShell `Clear-EventLog`, or direct file deletion from `C:\Windows\System32\winevt\logs\`. Event log clearing generates its own suspicious indicator (EventID 1102: "The audit log was cleared"), making it highly detectable but effective for destroying evidence when time permits.

**Attack Surface:** Event Log service, event log files (.evtx) stored on disk, registry entries for log configuration, and the Event Viewer management interface.

**Business Impact:** **Destruction of Forensic Evidence.** Clearing event logs prevents security teams from investigating the attack timeline, identifying lateral movement paths, discovering other compromised accounts, or determining what data was accessed. Organizations lose the ability to answer critical incident response questions: "What happened?" and "How long was the attacker present?"

**Technical Context:** Clearing a log is typically the **final step** in a post-compromise cleanup chain. By this time, attackers have already achieved their objectives (data exfiltration, persistence, lateral movement). The log clearing attempt is often the first indicator of compromise if logs are being remotely forwarded. Modern EDR and SIEM tools detect the clearing attempt (EventID 1102) and generate critical alerts.

### Operational Risk

- **Execution Risk:** Low-Medium (Requires admin for Security/System logs; can clear Application log as standard user).
- **Stealth:** Low (Clearing the log generates EventID 1102, one of the most suspicious events).
- **Reversibility:** No (Logs are permanently deleted unless backed up by VSS or remote SIEM).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1, 6.2 | Protect event logs; ensure audit logging is enabled and protected. |
| **DISA STIG** | WN10-AU-000025, WN10-AU-000030 | Protect and audit event log retention and integrity. |
| **CISA SCuBA** | SC.L1.1 | Detect and respond; maintain audit trail integrity. |
| **NIST 800-53** | AU-2 (Audit Events), AU-12 (Audit Generation), SI-4 (Monitoring) | Generate and protect audit records; detect suspicious activity. |
| **GDPR** | Art. 32, 33, 5(1)(f) | Integrity and confidentiality of personal data; accountability. |
| **DORA** | Art. 18, 19 | Incident reporting; breach notification. |
| **NIS2** | Art. 21, 22 | Detection capabilities; Incident management. |
| **ISO 27001** | A.12.4.1, A.12.4.3 | Event logging; Protection of log information. |
| **ISO 27005** | Risk Scenario | Destruction of audit evidence; Non-repudiation loss. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Administrator (to clear Security/System logs); standard user (to clear Application log).
- **Required Access:** Local console access or remote code execution on the endpoint.

**Supported Versions:**

- **Windows:** 10 (all), 11 (all), Server 2016, Server 2019, Server 2022, Server 2025
- **Tools:** wevtutil (all versions), PowerShell 5.0+, GUI Event Viewer (all versions)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Check event log sizes
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, FileSize

# Check Security log event count
(Get-WinEvent -LogName Security -MaxEvents 1).RecordCount

# Check if Event Log service is running
Get-Service EventLog | Select-Object Status, StartType

# Check if remote log forwarding is configured
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ErrorAction SilentlyContinue

# Check VSS (Volume Shadow Copy) for backup copies of logs
vssadmin list shadows /for=C:\
```

**What to Look For:**

- **RecordCount:** Number of events in each log; high counts mean more evidence available.
- **EventLog Service Status:** If `Stopped`, logs are not being recorded; if `Running`, logs are active.
- **Remote Forwarding:** If values present, logs are being forwarded to SIEM (clearing won't eliminate evidence).
- **VSS Snapshots:** If present, deleted logs may be recoverable from shadow copies.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Clear Event Logs via wevtutil (Command-Line)

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Clear Specific Event Log

**Objective:** Use wevtutil to clear a specific event log (Security, System, or Application).

**Command (Command Prompt or PowerShell):**

```cmd
# Clear Security Event Log
wevtutil cl security

# Clear System Event Log
wevtutil cl system

# Clear Application Event Log
wevtutil cl application
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- The specified event log is cleared (truncated to zero events).
- EventID 1102 (Audit log cleared) is generated in the Security log **before** it is cleared.

**OpSec & Evasion:**

- **Highly detectable:** EventID 1102 is one of the most suspicious events.
- If logs are forwarded to SIEM, clearing attempt is recorded on the SIEM server (evidence survives).
- Timeline shows attacker activity up to the point of clearing; everything after is unknown.

**Troubleshooting:**

- **Error:** "Access denied"
  - **Cause:** Not running as Administrator.
  - **Fix:** Run Command Prompt as Administrator.

**References:**

- [Microsoft Docs: wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

---

#### Step 2: Clear All Event Logs (Mass Clearing)

**Objective:** Clear all event logs in one command (more suspicious, but more thorough evidence destruction).

**Command (PowerShell - Admin Required):**

```powershell
# Clear all event logs
foreach ($log in (Get-WinEvent -ListLog *).LogName) {
    Clear-EventLog -LogName $log -Confirm:$false -ErrorAction SilentlyContinue
}
```

**Expected Output:**

```
(No output; all logs cleared)
```

**What This Means:**

- All event logs (Security, System, Application, custom logs) are cleared.
- Multiple EventID 1102 events are generated.

**OpSec & Evasion:**

- Multiple 1102 events in rapid succession is extremely suspicious.

**Troubleshooting:**

- **Error:** "Access denied on <specific log>"
  - **Cause:** Insufficient permissions for certain logs.
  - **Fix:** Run PowerShell as System/SYSTEM context using PsExec or similar.

---

### METHOD 2: Clear Event Logs via PowerShell Clear-EventLog

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Use Clear-EventLog Cmdlet

**Objective:** Use native PowerShell cmdlet to clear event logs.

**Command (PowerShell - Admin Required):**

```powershell
# Clear Security log
Clear-EventLog -LogName Security -Confirm:$false

# Clear System log
Clear-EventLog -LogName System -Confirm:$false

# Clear Application log
Clear-EventLog -LogName Application -Confirm:$false
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- Event log is cleared via PowerShell API.
- Generates EventID 1102 in Security log.

**OpSec & Evasion:**

- PowerShell execution itself may be logged (EventID 4688 process creation, EventID 4104 if Script Block Logging enabled).
- Multiple detection opportunities.

**Troubleshooting:**

- **Error:** "Log name not found"
  - **Cause:** Incorrect log name.
  - **Fix:** Use `Get-WinEvent -ListLog *` to list all available logs.

**References:**

- [Microsoft Docs: Clear-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)

---

### METHOD 3: Direct Event Log File Deletion

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Stop Event Log Service

**Objective:** Stop the Event Log service so log files can be deleted.

**Command (Command Prompt - Admin Required):**

```cmd
# Stop the Event Log service
net stop EventLog

# Alternative using sc.exe
sc stop EventLog
```

**Expected Output:**

```
The Event Log service is stopping.
The Event Log service has stopped successfully.
```

**What This Means:**

- The Event Log service is halted; logs cannot be written.
- Service stopping generates events (EventID 7034/7035) in System log **before** service stops.

**OpSec & Evasion:**

- Service stop is highly suspicious.
- System log may not be truncated if service stops before log write completes.

**Troubleshooting:**

- **Error:** "Service start pending"
  - **Cause:** Service is still running from previous instance.
  - **Fix:** Wait a moment or force kill: `taskkill /f /im svchost.exe` (dangerous; may crash system).

---

#### Step 2: Delete Event Log Files

**Objective:** Delete the physical .evtx files from disk.

**Command (Command Prompt - Admin Required):**

```cmd
# Delete event log files
del "C:\Windows\System32\winevt\logs\Security.evtx"
del "C:\Windows\System32\winevt\logs\System.evtx"
del "C:\Windows\System32\winevt\logs\Application.evtx"

# Delete PowerShell logs
del "C:\Windows\System32\winevt\logs\Microsoft-Windows-PowerShell*Operational.evtx"
```

**Expected Output:**

```
(No output on success; files deleted)
```

**What This Means:**

- The physical event log files are permanently deleted from disk.
- Very difficult to recover without forensic techniques.

**OpSec & Evasion:**

- File deletion is logged in filesystem (NTFS journal, USN journal) if properly configured.
- File deletion itself generates few events **while** Event Log service is stopped (logs not being written).

**Troubleshooting:**

- **Error:** "File in use"
  - **Cause:** Event Log service is still running.
  - **Fix:** Ensure Event Log service is stopped first.

---

#### Step 3: Restart Event Log Service

**Objective:** Restart Event Log service so system continues logging (covering tracks).

**Command (Command Prompt):**

```cmd
# Start the Event Log service
net start EventLog

# Alternative using sc.exe
sc start EventLog
```

**Expected Output:**

```
The Event Log service is starting.
The Event Log service has started successfully.
```

**What This Means:**

- Event Log service resumes; new events are logged to new (empty) log files.
- Attacker activity after restart is logged; activity before is destroyed.

---

### METHOD 4: GUI Event Viewer Manual Clearing

**Supported Versions:** All Windows versions

#### Step 1: Open Event Viewer and Clear Manually

**Objective:** Use GUI to clear event logs interactively (leaves GUI interaction artifacts in process logs).

**Steps:**

1. Press **Win + R**, type `eventvwr.msc`, press Enter
2. Expand **Windows Logs** (left panel)
3. Right-click **Security** → **Clear Log**
4. Confirm: **Clear**
5. Repeat for **System** and **Application** logs

**What This Means:**

- Event logs are cleared via GUI.
- eventvwr.msc process execution is logged (EventID 4688).

**OpSec & Evasion:**

- Process creation is logged; GUI usage is less suspicious than command-line (appears like normal admin work).

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Tests

**Test ID:** T1070.001 (Event Log Clearing variants)

**Supported Tests:**

1. **Test: Clear Security Event Log via wevtutil**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1070.001 -TestNumbers 1
     ```
   - **Cleanup:**
     ```powershell
     Invoke-AtomicTest T1070.001 -TestNumbers 1 -Cleanup
     ```

2. **Test: Clear Event Logs via PowerShell**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1070.001 -TestNumbers 2
     ```

3. **Test: Clear Event Log via Registry**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1070.001 -TestNumbers 3
     ```

**Reference:** [Atomic Red Team Library - T1070.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### Built-In Windows Tools

#### wevtutil (Windows Event Log Utility)

**Version:** All Windows versions
**Purpose:** Command-line event log management.
**Usage:**
```cmd
wevtutil cl security
wevtutil cl system
wevtutil cl application
```

**References:**

- [Microsoft Docs: wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

---

#### Clear-EventLog (PowerShell)

**Version:** PowerShell 5.0+
**Purpose:** PowerShell cmdlet for clearing event logs.
**Usage:**
```powershell
Clear-EventLog -LogName Security -Confirm:$false
```

**References:**

- [Microsoft Docs: Clear-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)

---

#### Event Viewer (eventvwr.msc)

**Version:** All Windows versions
**Purpose:** GUI for event log management.
**Usage:** `eventvwr.msc` (Right-click log → Clear Log)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Event Log Cleared (EventID 1102)

**Rule Configuration:**

- **Required Table:** SecurityEvent
- **Required Fields:** EventID, Computer, SubjectUserName, TimeGenerated
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 1 minute)
- **Applies To:** Windows 10/11, Server 2016+

**KQL Query:**

```kusto
// Detect clearing of event logs (EventID 1102)
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, SubjectUserName, EventID, Activity, Message
| summarize ClearCount = count() by Computer, SubjectUserName, bin(TimeGenerated, 5m)
| where ClearCount > 0
| sort by TimeGenerated desc
```

**What This Detects:**

- EventID 1102: "The audit log was cleared"
- Multiple clears in short time window (indicates post-compromise cleanup).

**Manual Configuration (Azure Portal):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Suspicious Event Log Clearing`
3. Severity: `Critical`
4. Paste KQL query above
5. Run every: `1 minute`
6. Alert threshold: `Count > 0`
7. Click **Review + create**

---

#### Query 2: Event Log Service Stopped

**Rule Configuration:**

- **Required Table:** SecurityEvent
- **Required Fields:** EventID, Computer, ProcessName
- **Alert Severity:** High

**KQL Query:**

```kusto
// Detect stopping of Event Log service
SecurityEvent
| where EventID in (7034, 7035)  // Service crashed/stopped
| where SubjectUserName contains "EventLog"
| project TimeGenerated, Computer, EventID, Activity, SubjectUserName
```

**What This Detects:**

- EventID 7034: Service unexpectedly terminated
- EventID 7035: Service stop/start request

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 1102 (Audit Log Cleared)**

- **Log Source:** Security
- **Trigger:** Any event log is cleared.
- **Filter:** EventID = 1102; SubjectUserName not in (trusted service accounts)
- **Applies To Versions:** All Windows versions

**Manual Configuration (Audit Clearing):**

1. Open **secpol.msc** (Local Security Policy)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System**
3. Enable: **Audit Security System Extension** (Success and Failure)
4. Run:
   ```powershell
   auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
   ```

---

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** wevtutil.exe, powershell.exe, or eventvwr.msc execution.
- **Filter:** EventID = 4688; ProcessName contains ("wevtutil", "powershell", "Clear-EventLog")

**Manual Configuration:**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Run `gpupdate /force`

---

**Event ID: 7034 / 7035 (Service Events)**

- **Log Source:** System
- **Trigger:** Event Log service is stopped.
- **Filter:** EventID in (7034, 7035); ServiceName = "EventLog"

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 11.0+

```xml
<Rule name="Event Log Clearing via wevtutil" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="endswith">wevtutil.exe</Image>
    <CommandLine condition="contains">cl</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="Event Log Clearing via PowerShell" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="contains">powershell.exe</Image>
    <CommandLine condition="contains">Clear-EventLog</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="Event Log Service Stopped" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="endswith">sc.exe</Image>
    <CommandLine condition="contains all">stop; EventLog</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="Suspicious Event Log File Deletion" groupRelation="or">
  <FileDelete onmatch="all">
    <TargetFilename condition="contains">\winevt\logs\</TargetFilename>
    <TargetFilename condition="endswith">.evtx</TargetFilename>
  </FileDelete>
</Rule>
```

**Manual Configuration:**

1. Download Sysmon
2. Create `sysmon-config.xml` with XML above
3. Install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Activity - Event Log Cleared"

- **Severity:** Critical
- **Description:** Defender detects attempt to clear Windows event logs via wevtutil, PowerShell, or service stop.
- **Applies To:** Devices with Defender for Endpoint
- **Remediation:** Immediate incident response; suspect post-compromise cleanup.

**Manual Configuration:**

1. **Azure Portal** → **Microsoft Defender for Cloud** → **Defender plans**
2. Enable **Defender for Servers**
3. Deploy MDE agent
4. Monitor **Security Alerts** for "Event Log Cleared" incidents

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Implement Centralized Remote Event Log Forwarding**

- **Objective:** Forward all event logs to remote SIEM so clearing local logs doesn't eliminate evidence.
- **Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - Windows Event Collector):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **Windows Components** → **Event Forwarding**
3. Find: **"Configure the Subscription Manager"**
4. Set to: **Enabled**
5. Specify SIEM server address:
   ```
   Server=https://your-siem-server:5985/wsman/SubscriptionManager/WEC,Refresh=60
   ```
6. Run `gpupdate /force`

**Manual Steps (PowerShell - Configure Forwarder):**

```powershell
# On domain-joined machines, create event subscription
New-EventLogSubscription -CollectorName YourCollector -SourceComputer "Domain Computers" -LogPath "Forwarded Events"
```

---

**2. Restrict Permissions on Event Log Files**

- **Objective:** Prevent deletion of event log files via NTFS permissions.
- **Applies To Versions:** Windows 10/11, Server 2016+

**Manual Steps (NTFS Permissions):**

```powershell
# Restrict access to event log directory
icacls "C:\Windows\System32\winevt\logs" /grant:r "BUILTIN\Administrators:F" /inheritance:r
icacls "C:\Windows\System32\winevt\logs" /grant:r "SYSTEM:F" /inheritance:r
icacls "C:\Windows\System32\winevt\logs" /grant:r "NETWORK SERVICE:R" /inheritance:r
icacls "C:\Windows\System32\winevt\logs" /grant:r "LOCAL SERVICE:R" /inheritance:r
```

---

**3. Enable Volume Shadow Copy (VSS) for Log Recovery**

- **Objective:** Maintain backup copies of deleted event logs for forensic recovery.
- **Applies To Versions:** All Windows versions

**Manual Steps (Configure VSS Schedule):**

1. Open **Disk Management** (diskmgmt.msc)
2. Right-click **C: drive** → **Properties** → **Shadow Copies**
3. Select **C:\ drive** → Click **Enable** → Configure schedule (e.g., daily)
4. Verify snapshots are created:
   ```powershell
   vssadmin list shadows /for=C:\
   ```

---

**4. Implement Audit Logging for Event Log Access**

- **Objective:** Log attempts to access or modify event log system.
- **Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - Audit Object Access):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Object Access** (Success and Failure)
4. Set SACL on event log directory:
   ```powershell
   icacls "C:\Windows\System32\winevt\logs" /setaudit "Everyone:(OA;CI;WA;;;S-1-1-0)"
   ```
5. Run `gpupdate /force`

---

#### Priority 2: HIGH

**5. Deploy EDR with Real-Time Monitoring**

- **Objective:** Detect and block event log clearing attempts in real-time.
- **Examples:** Microsoft Defender for Endpoint, CrowdStrike, SentinelOne.

**Manual Steps (Enable MDE):**

1. **Azure Portal** → **Microsoft Defender for Cloud** → **Defender plans**
2. Enable **Defender for Servers**
3. Configure alert rules for wevtutil.exe, Clear-EventLog, service stops
4. Set remediation action: **Isolate device** on detection

---

**6. Restrict Administrative Access**

- **Objective:** Limit who can execute wevtutil, PowerShell commands, or stop Event Log service.
- **Manual Steps (AppLocker):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
  3. Create rules:
     - Deny execution of `wevtutil.exe` for non-admin groups
     - Restrict PowerShell execution to trusted users

---

#### Validation Command

```powershell
# Check event log forwarding configuration
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"

# Check NTFS permissions on event log directory
icacls "C:\Windows\System32\winevt\logs"

# Check VSS snapshots
vssadmin list shadows /for=C:\

# Verify Event Log service is running and protected
Get-Service EventLog | Select-Object Status, StartType
```

**Expected Output (If Secure):**

```
Server=https://your-siem:5985/wsman/SubscriptionManager/WEC,Refresh=60
(NTFS permissions restricted)
(VSS snapshots present)
Status     : Running
StartType  : Automatic
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Process:** `wevtutil.exe`, `powershell.exe`, `sc.exe` with event log clearing parameters
- **Registry:** No value changes (event logs are files, not registry-stored)
- **Files:** Missing or zero-sized `.evtx` files in `C:\Windows\System32\winevt\logs\`
- **Event Log:** EventID 1102 (Audit log cleared); EventID 7034/7035 (service stop)

#### Forensic Artifacts

- **Disk:** 
  - USN Journal: Records of file deletions
  - NTFS MFT: Deleted file entries (recoverable with forensic tools)
  - VSS Snapshots: Previous versions of log files
- **Memory:** Process memory of wevtutil.exe or PowerShell (command history)
- **Cloud:** SIEM/Sentinel logs (if forwarding configured)

#### Response Procedures

1. **Isolate:**
   ```powershell
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Recover from VSS
   vssadmin list shadows /for=C:\
   # Use forensic tools to recover from shadow copy
   
   # Capture process memory
   procdump64.exe -ma powershell.exe C:\Evidence\powershell.dmp
   
   # Export registry for audit trail
   reg export HKLM C:\Evidence\HKLM.reg
   ```

3. **Remediate:**
   ```powershell
   # Restart Event Log service (recreates logs)
   Restart-Service -Name EventLog -Force
   
   # Re-enable event logging via Group Policy
   gpupdate /force
   ```

4. **Investigate:**
   - Determine **when** logs were cleared (before clearing, EventID 1102 shows timestamp)
   - Identify all activity **before** the clearing time (last recoverable events)
   - Cross-reference with **external logs** (firewall, network, SIEM, cloud logs)
   - Check for **other cleanup** (PowerShell history, Temp files, registry edits)
   - Escalate to forensics team for disk imaging and recovery

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-001] Tenant Discovery | Attacker gathers info on target. |
| **2** | **Execution** | [CA-DUMP-001] Mimikatz | Attacker dumping credentials (logged in Security log). |
| **3** | **Persistence** | [PERSIST-001] Registry Run Key | Attacker creates persistence (logged in System log). |
| **4** | **Defense Evasion** | **[EVADE-IMPAIR-004]** | **Attacker clears event logs (EventID 1102 generated, then Security log cleared).** |
| **5** | **Impact** | [DATA-EXF-001] Data Exfiltration | Attacker exfils data; no forensic evidence of earlier steps. |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: APT28 / Fancy Bear (2016)

- **Target:** Democratic National Convention (DNC), U.S. Government
- **Timeline:** 2016
- **Technique Status:** APT28 used `wevtutil cl System` and `wevtutil cl Security` to clear event logs after lateral movement.
- **Impact:** Destroyed forensic evidence of APT28's presence; investigation timeline was incomplete.
- **Reference:** [DHS Alert: Russian APT28 Campaign](https://www.cisa.gov/)

---

#### Example 2: NotPetya / ExPetr (2017)

- **Target:** Ukraine (global spread), financial institutions
- **Timeline:** June 2017
- **Technique Status:** NotPetya used `wevtutil` to clear event logs as part of post-compromise cleanup before deploying destructive wiper malware.
- **Impact:** Eliminated evidence of initial compromise; organizations couldn't reconstruct attack timeline.
- **Reference:** [Securelist: NotPetya Analysis](https://securelist.com/)

---

#### Example 3: Conti Ransomware Gang (2020-2023)

- **Target:** Critical Infrastructure, Healthcare, Finance
- **Timeline:** 2020-2023
- **Technique Status:** Conti affiliates routinely clear Security, System, and Application logs as final step before ransomware deployment.
- **Impact:** Dwell time extended (months); forensic evidence destroyed; impact assessment complicated.
- **Reference:** [CISA: Conti Ransomware Alerts](https://www.cisa.gov/conti)

---